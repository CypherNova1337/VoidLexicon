"""Tests for volume and egress detection.

Two things here are load-bearing and everything else supports them.

The first is that an unavailable measurement is *omitted*, not defaulted,
and that the claim shrinks to fit what was measured. NetFlow records no
directional byte split. Substituting a neutral 0.5 for the egress ratio is the
difference between finding four planted transfers and finding none; keeping
the *outbound* claim after omitting the component that grounds it is the same
error one level up, and it cost the CTU-13 infected host three queue
positions. Both are asserted below with numbers, because both fail silently
and the code that causes either looks reasonable.

The second is that a nightly backup is not a data breach. It is large,
outbound and scheduled, which is three of the four things exfiltration is, and
the corpus contains twelve of them precisely so that a regression which starts
reporting them is a failing test rather than a quiet flood.
"""

from __future__ import annotations

import numpy as np
import polars as pl
import pytest

from voidai.analyzers import AnalysisContext, EgressAnalyzer, EgressConfig, score_transfer
from voidai.analyzers.statistics import robust_deviation
from voidai.correlate import CorrelationConfig, build_queue
from voidai.eval.benchmark import run_egress_benchmark
from voidai.eval.synth import EgressCorpusGenerator
from voidai.ingest.schema import CONNECTION_SCHEMA, conform
from voidai.lexicon import (
    Artifact,
    Entity,
    EntityType,
    Evidence,
    Finding,
    Predicate,
    Severity,
)

HOUR = 3600.0
#: A plausible spread of per-destination outbound totals for one workstation:
#: browsing in the low hundreds of kilobytes, mail in the megabytes.
BASELINE = np.array([120_000.0, 150_000.0, 180_000.0, 210_000.0, 240_000.0, 5_000_000.0])


def _score(**overrides: object) -> object:
    """A strong transfer, with named fields overridden per test."""
    kwargs: dict[str, object] = {
        "orig_bytes": 500_000_000.0,
        "egress_ratio": 0.98,
        "host_baseline": BASELINE,
        "contacting_hosts": 1,
        "novelty_fraction": 0.7,
        "config": EgressConfig(),
        "flows": 12,
    }
    kwargs.update(overrides)
    return score_transfer(**kwargs)  # type: ignore[arg-type]


class TestScoreTransfer:
    def test_bulk_transfer_to_a_new_rare_destination_scores_high(self) -> None:
        score = _score()
        assert score is not None
        assert score.score >= EgressConfig().exfil_threshold

    def test_all_four_components_are_measured_when_available(self) -> None:
        score = _score()
        assert score is not None
        assert set(score.components) == {
            "egress_ratio",
            "volume_deviation",
            "destination_rarity",
            "novelty",
        }

    def test_inbound_transfer_does_not_score(self) -> None:
        """A software mirror moves the same bytes the other way."""
        score = _score(egress_ratio=0.02)
        assert score is not None
        assert score.components["egress_ratio"] == pytest.approx(0.0)
        assert score.score < EgressConfig().volume_threshold

    def test_popular_destination_does_not_score(self) -> None:
        """The estate-wide sync target. Volume and direction say exfiltration."""
        score = _score(contacting_hosts=200)
        assert score is not None
        assert score.score < EgressConfig().exfil_threshold

    def test_long_standing_destination_does_not_score(self) -> None:
        """The nightly backup: there since before the capture opened."""
        score = _score(novelty_fraction=0.005)
        assert score is not None
        assert score.score < EgressConfig().exfil_threshold

    def test_rarity_and_novelty_together_outweigh_volume_and_direction(self) -> None:
        """Rule 5, stated as a measurement.

        A backup is perfect on the two signals an average would let carry a
        detection alone. It has to lose anyway.
        """
        backup = _score(contacting_hosts=40, novelty_fraction=0.01)
        exfil = _score()
        assert backup is not None and exfil is not None
        assert backup.components["egress_ratio"] == exfil.components["egress_ratio"]
        assert backup.components["volume_deviation"] == exfil.components["volume_deviation"]
        assert backup.score < EgressConfig().volume_threshold < exfil.score

    def test_unmeasured_ratio_is_omitted_not_scored(self) -> None:
        score = _score(egress_ratio=None)
        assert score is not None
        assert "egress_ratio" not in score.components
        assert score.egress_ratio is None

    def test_omitting_the_ratio_renormalises_rather_than_penalising(self) -> None:
        """Rule 6 at the component level, which is the level it is famous for.

        A sensor that does not record direction must lose a signal, not
        acquire a negative one. So the score with the component omitted has to
        sit above the score a neutral 0.5 would have produced.
        """
        omitted = _score(egress_ratio=None)
        neutral = _score(egress_ratio=0.5)
        assert omitted is not None and neutral is not None
        assert omitted.score > neutral.score

    def test_unmeasured_novelty_is_omitted_not_scored(self) -> None:
        score = _score(novelty_fraction=None)
        assert score is not None
        assert "novelty" not in score.components

    def test_narrow_baseline_omits_the_deviation_component(self) -> None:
        """Two destinations are not a distribution."""
        score = _score(host_baseline=np.array([100.0, 200.0]))
        assert score is not None
        assert "volume_deviation" not in score.components
        assert score.volume_deviation is None

    def test_identical_baseline_omits_the_deviation_component(self) -> None:
        """MAD of zero cannot express a deviation, and zero is not the answer."""
        score = _score(host_baseline=np.full(8, 1_000.0))
        assert score is not None
        assert "volume_deviation" not in score.components

    def test_unmeasured_volume_returns_nothing(self) -> None:
        assert _score(orig_bytes=0.0) is None
        assert _score(flows=0) is None

    def test_basis_names_every_component_and_every_omission(self) -> None:
        score = _score(egress_ratio=None)
        assert score is not None
        for component in score.components:
            assert component in score.basis()
        assert "omitted (unmeasured): egress_ratio" in score.basis()


class TestRobustDeviation:
    def test_outlier_measures_many_deviations_above(self) -> None:
        assert (robust_deviation(5_000_000.0, BASELINE) or 0.0) > 10.0

    def test_typical_value_measures_near_zero(self) -> None:
        assert abs(robust_deviation(180_000.0, BASELINE) or 99.0) < 1.0

    def test_degenerate_baselines_return_none(self) -> None:
        assert robust_deviation(10.0, np.array([1.0, 2.0])) is None
        assert robust_deviation(10.0, np.full(6, 4.0)) is None


def _capture(rows: list[dict[str, object]]) -> pl.DataFrame:
    return conform(pl.DataFrame(rows), CONNECTION_SCHEMA)


def _synthetic_evidence(kind: str) -> Evidence:
    """Minimal Evidence, for the correlation tests that build Findings by hand."""
    return Evidence(
        kind=kind,
        summary="synthetic evidence",
        artifacts=[Artifact(source="conn.log", locator=f"line:{abs(hash(kind)) % 1000}")],
    )


def _flows(
    src: str,
    dst: str,
    count: int,
    orig: int,
    resp: int | None,
    start: float,
    step: float = HOUR,
) -> list[dict[str, object]]:
    return [
        {
            "ts": start + index * step,
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": 443,
            "proto": "tcp",
            "orig_bytes": orig,
            "resp_bytes": resp,
            "source_file": "conn.log",
            "source_line": index + 1,
        }
        for index in range(count)
    ]


def _workstation(src: str, start: float = 0.0) -> list[dict[str, object]]:
    """Enough ordinary destinations for a baseline and a full-day window."""
    rows: list[dict[str, object]] = []
    for index, volume in enumerate((120_000, 150_000, 180_000, 210_000, 240_000, 300_000)):
        rows += _flows(src, f"93.184.0.{index + 1}", 6, volume // 6, volume * 8, start, step=4 * HOUR)
    return rows


class TestNetFlowShapedTelemetry:
    """The known trap, asserted from both sides.

    NetFlow records total flow bytes as `orig_bytes` and has no responder
    figure at all, so `ingest/netflow.py` emits no `resp_bytes` column. The
    analyzer has to treat that as an absent measurement — the same way
    `beaconing` treats a missing payload column — and the tests below pin the
    two ways it could get that wrong: reading the column as zero, or
    substituting a neutral value for it.
    """

    def _corpus(self) -> pl.DataFrame:
        return EgressCorpusGenerator(seed=1337).generate(hours=24.0).connections

    def test_missing_column_omits_the_component(self) -> None:
        netflow = self._corpus().drop("resp_bytes")
        findings = EgressAnalyzer().analyze(AnalysisContext(connections=netflow))
        assert findings
        for finding in findings:
            volume = next(e for e in finding.evidence if e.kind == "egress_volume")
            assert volume.payload["egress_ratio"] is None
            assert "omitted (unmeasured): egress_ratio" in finding.basis

    def test_unpopulated_column_behaves_identically_to_a_missing_one(self) -> None:
        """A sensor writing `-` and a sensor with no such field say the same thing."""
        absent = EgressAnalyzer().analyze(
            AnalysisContext(connections=self._corpus().drop("resp_bytes"))
        )
        unpopulated = EgressAnalyzer().analyze(
            AnalysisContext(
                connections=self._corpus().with_columns(
                    pl.lit(None, dtype=pl.Int64).alias("resp_bytes")
                )
            )
        )
        assert [f.id for f in absent] == [f.id for f in unpopulated]

    def test_defaulting_the_ratio_would_lose_every_planted_transfer(self) -> None:
        """Why omission is not a stylistic preference.

        Substituting a neutral 0.5 — the obvious "reasonable" default — scores
        the ratio component at zero, and under a geometric mean that is enough
        to sink every finding in the capture. The contrast is asserted rather
        than described, because the failing version emits no error and looks
        like a quiet network.
        """
        corpus = EgressCorpusGenerator(seed=1337).generate(hours=24.0)
        planted = corpus.transfer_keys

        omitted = EgressAnalyzer().analyze(
            AnalysisContext(connections=corpus.connections.drop("resp_bytes"))
        )
        # `orig_bytes == resp_bytes` is what a defaulted 0.5 looks like.
        defaulted = EgressAnalyzer().analyze(
            AnalysisContext(
                connections=corpus.connections.with_columns(
                    pl.col("orig_bytes").alias("resp_bytes")
                )
            )
        )

        found = {(f.subject.value, f.object.value) for f in omitted}
        assert planted <= found, "omitting the component lost a planted transfer"
        assert not [f for f in defaulted if (f.subject.value, f.object.value) in planted]

    def test_netflow_shaped_telemetry_can_never_claim_exfiltration(self) -> None:
        """The regression CTU-13 caught, pinned from the measurement side.

        `exfiltrates_to` asserts an anomalous *outbound* volume. Direction is
        the one thing NetFlow does not record, so the predicate is unreachable
        on it — and unreachable is not the same as "scores too low to reach".
        The assertions below are deliberately built on a transfer that *does*
        clear the exfiltration threshold with the ratio omitted: the gate has
        to be on what was measured, not on the number that survived
        renormalising, or it will let the claim back in the moment the other
        three signals are strong enough.

        Scored the other way round, CTU-13 scenario 3 produced 176 critical
        outbound accusations across 35 hosts from telemetry with no direction
        in it, and the corroboration they earned moved the infected host from
        queue rank 2 to rank 5.
        """
        corpus = EgressCorpusGenerator(seed=1337).generate(hours=24.0)

        for label, frame in (
            ("column absent", corpus.connections.drop("resp_bytes")),
            (
                "column unpopulated",
                corpus.connections.with_columns(
                    pl.lit(None, dtype=pl.Int64).alias("resp_bytes")
                ),
            ),
        ):
            findings = EgressAnalyzer().analyze(AnalysisContext(connections=frame))
            assert findings, label
            assert not [
                f for f in findings if f.predicate is Predicate.EXFILTRATES_TO
            ], f"claimed outbound exfiltration with no direction recorded ({label})"
            assert not [
                f for f in findings if f.severity is Severity.CRITICAL
            ], f"a critical claim survived on ungrounded telemetry ({label})"

            # The gate is not the threshold doing the work by accident.
            strongest = max(findings, key=lambda f: f.confidence)
            assert strongest.confidence >= EgressConfig().exfil_threshold
            assert strongest.predicate is Predicate.TRANSFERS_ANOMALOUS_VOLUME

    def test_the_same_traffic_does_claim_exfiltration_when_direction_is_recorded(
        self,
    ) -> None:
        """Guards the test above against passing for the wrong reason.

        Same corpus, same transfers, `resp_bytes` present. The demotion has to
        be the missing measurement rather than a gate that quietly made the
        predicate unreachable everywhere.
        """
        corpus = EgressCorpusGenerator(seed=1337).generate(hours=24.0)
        findings = EgressAnalyzer().analyze(AnalysisContext(connections=corpus.connections))
        assert [f for f in findings if f.predicate is Predicate.EXFILTRATES_TO]

    def test_partially_populated_column_is_not_treated_as_measured(self) -> None:
        """A responder figure on a tenth of the flows describes that tenth."""
        rows = _workstation("10.0.0.5")
        rows += _flows("10.0.0.5", "45.83.220.17", 1, 400_000_000, 0, 18 * HOUR)
        rows += _flows("10.0.0.5", "45.83.220.17", 9, 20_000_000, None, 19 * HOUR)

        findings = EgressAnalyzer().analyze(AnalysisContext(connections=_capture(rows)))
        assert findings
        volume = next(e for e in findings[0].evidence if e.kind == "egress_volume")
        assert volume.payload["egress_ratio"] is None
        assert volume.payload["egress_ratio_flow_coverage"] == pytest.approx(0.1)


class TestSeededCorpus:
    """End-to-end, through a real `conn.log` and the production parser."""

    def test_every_planted_transfer_is_found(self) -> None:
        result = run_egress_benchmark(seed=1337, hours=24.0)
        assert result.detection.recall == pytest.approx(1.0), result.detection.missed_labels

    def test_the_only_false_positive_is_the_documented_one(self) -> None:
        """The lone-host backup, and nothing else.

        It is in the corpus on purpose: estate-wide rarity cannot defend
        against a large outbound destination that exactly one machine uses,
        and no amount of tuning changes that — it needs asset context VoidLexicon
        does not have. Pinned here so the *count* cannot grow unnoticed while
        the limitation is written up as a single known case.
        """
        result = run_egress_benchmark(seed=1337, hours=24.0)
        assert result.detection.false_positives == 1
        assert "lone-host-backup" in result.detection.false_positive_pairs[0]

    def test_no_finding_names_a_shared_backup_sync_or_mirror_target(self) -> None:
        corpus = EgressCorpusGenerator(seed=1337).generate(hours=24.0)
        findings = EgressAnalyzer().analyze(AnalysisContext(connections=corpus.connections))
        shared = {
            destination
            for (_, destination), label in corpus.decoys.items()
            if label != "lone-host-backup"
        }
        assert not [f for f in findings if f.object and f.object.value in shared]

    def test_browsing_does_not_produce_a_rare_destination_flood(self) -> None:
        """The predicted failure mode for this predicate.

        Every workstation reaches addresses nobody else in the estate does, so
        prevalence alone marks 72 of the corpus's destinations as rare. One
        finding each would be an alert flood arriving from inside the tool
        that exists to prevent them.
        """
        corpus = EgressCorpusGenerator(seed=1337).generate(hours=24.0)
        findings = EgressAnalyzer().analyze(AnalysisContext(connections=corpus.connections))
        rare = [f for f in findings if f.predicate is Predicate.CONTACTS_RARE_DESTINATION]
        assert len(rare) <= 2
        assert all(f.object and f.object.value.startswith("93.184.") is False for f in rare)

    def test_findings_are_reproducible(self) -> None:
        corpus = EgressCorpusGenerator(seed=1337).generate(hours=24.0)
        first = EgressAnalyzer().analyze(AnalysisContext(connections=corpus.connections))
        second = EgressAnalyzer().analyze(AnalysisContext(connections=corpus.connections))
        assert [f.id for f in first] == [f.id for f in second]


class TestBands:
    def test_a_source_emits_one_predicate_only(self) -> None:
        """Bands of one score are not independent behaviours.

        This host has three destinations that qualify under three different
        bands. Reporting all three would hand `voidai.correlate` two extra
        predicates on one host, and the corroboration multiplier would read
        one analyzer restating one measurement as three independent opinions
        — the failure `non_corroborating` exists to prevent for `precedes`.
        Only the strongest band survives, and the weaker destinations go
        unreported rather than being restated under a lesser verb.
        """
        rows = _workstation("10.0.0.5")
        rows += _flows("10.0.0.5", "45.83.220.17", 4, 200_000_000, 40_000, 18 * HOUR)
        rows += _flows("10.0.0.5", "185.220.101.9", 6, 3_000_000, 900_000, 9 * HOUR)
        rows += _flows("10.0.0.5", "179.43.160.8", 8, 90_000, 2_000, 16 * HOUR)

        findings = EgressAnalyzer().analyze(AnalysisContext(connections=_capture(rows)))
        assert findings
        assert {f.predicate for f in findings} == {Predicate.EXFILTRATES_TO}
        assert "179.43.160.8" not in {f.object.value for f in findings if f.object}

    def test_the_suppressed_band_would_otherwise_be_reported(self) -> None:
        """Guards the test above against becoming vacuous.

        Its fixture only proves anything while the weakest destination is one
        the analyzer *would* report if the source had nothing stronger. Run it
        on its own host and it is reported, so the suppression above is the
        band rule at work rather than a gate the traffic never cleared.
        """
        rows = _workstation("10.0.0.6")
        rows += _flows("10.0.0.6", "179.43.160.8", 8, 90_000, 2_000, 16 * HOUR)

        findings = EgressAnalyzer().analyze(AnalysisContext(connections=_capture(rows)))
        assert [f.predicate for f in findings] == [Predicate.CONTACTS_RARE_DESTINATION]

    def test_a_host_exfiltrating_twice_keeps_both_findings(self) -> None:
        rows = _workstation("10.0.0.5")
        rows += _flows("10.0.0.5", "45.83.220.17", 4, 200_000_000, 40_000, 18 * HOUR)
        rows += _flows("10.0.0.5", "141.98.11.4", 4, 150_000_000, 30_000, 16 * HOUR)

        findings = EgressAnalyzer().analyze(AnalysisContext(connections=_capture(rows)))
        destinations = {f.object.value for f in findings if f.object}
        assert {"45.83.220.17", "141.98.11.4"} <= destinations

    def test_volume_claim_requires_a_measured_baseline_deviation(self) -> None:
        """The predicate says the volume deviates from a baseline.

        Five hosts here reach three destinations each — too few for any of
        them to have a distribution, so `robust_deviation` returns None and
        the component is omitted. The remaining three signals still combine to
        0.64, comfortably inside the volume band's range, so nothing but the
        deviation requirement is keeping this quiet. A finding here would be
        asserting a deviation from a baseline that was never measured.
        """
        rows: list[dict[str, object]] = []
        for host in range(5):
            source = f"10.0.1.{host + 10}"
            rows += _flows(source, "93.184.0.1", 6, 40_000, 300_000, 0.0, step=4 * HOUR)
            rows += _flows(source, "93.184.0.2", 6, 50_000, 300_000, 0.0, step=4 * HOUR)
            rows += _flows(source, "203.0.113.9", 5, 2_000_000, 20_000, 12 * HOUR)

        findings = EgressAnalyzer().analyze(AnalysisContext(connections=_capture(rows)))
        assert findings == []

    def test_a_weaker_band_stays_at_its_severity_however_high_it_scores(self) -> None:
        """The severity cap, at the one point it can be observed.

        This upload is rare, new and almost entirely outbound, and scores
        above the critical threshold. It is also 112KB, which is below the
        floor for a volume claim — so the strongest thing sayable about it is
        that something went somewhere rare, and LOW is what that is worth. A
        score is not a severity: letting one band's arithmetic promote another
        band's claim would put a rare-destination note beside a measured
        exfiltration in the queue.
        """
        rows = _workstation("10.0.0.7")
        rows += _flows("10.0.0.7", "179.43.160.8", 8, 112_000, 2_000, 21 * HOUR, step=300.0)

        findings = EgressAnalyzer().analyze(AnalysisContext(connections=_capture(rows)))
        assert len(findings) == 1
        assert findings[0].predicate is Predicate.CONTACTS_RARE_DESTINATION
        assert findings[0].confidence >= EgressConfig().critical_threshold
        assert findings[0].severity is Severity.LOW

    def test_only_exfiltration_reaches_critical(self) -> None:
        corpus = EgressCorpusGenerator(seed=1337).generate(hours=24.0)
        findings = EgressAnalyzer().analyze(AnalysisContext(connections=corpus.connections))
        for finding in findings:
            if finding.severity is Severity.CRITICAL:
                assert finding.predicate is Predicate.EXFILTRATES_TO

    def test_rare_findings_are_capped_far_below_the_rest(self) -> None:
        config = EgressConfig()
        assert config.max_rare_findings * 4 <= config.max_findings

    def test_max_findings_is_honoured(self) -> None:
        rows: list[dict[str, object]] = []
        for host in range(6):
            source = f"10.0.0.{host + 10}"
            rows += _workstation(source)
            for index in range(4):
                rows += _flows(
                    source, f"45.83.{host}.{index}", 3, 200_000_000, 20_000, 18 * HOUR
                )

        findings = EgressAnalyzer(EgressConfig(max_findings=5)).analyze(
            AnalysisContext(connections=_capture(rows))
        )
        assert len(findings) <= 5


class TestContext:
    def test_empty_context_is_silent(self) -> None:
        assert EgressAnalyzer().analyze(AnalysisContext()) == []

    def test_a_sensor_without_byte_counts_is_silent(self) -> None:
        """Nothing to say is better than a score built from prevalence alone."""
        rows = _workstation("10.0.0.5")
        rows += _flows("10.0.0.5", "45.83.220.17", 4, 200_000_000, 40_000, 18 * HOUR)
        capture = _capture(rows).with_columns(pl.lit(None, dtype=pl.Int64).alias("orig_bytes"))
        assert EgressAnalyzer().analyze(AnalysisContext(connections=capture)) == []

    def test_every_finding_carries_a_locator_into_the_source(self) -> None:
        corpus = EgressCorpusGenerator(seed=1337).generate(hours=24.0)
        findings = EgressAnalyzer().analyze(AnalysisContext(connections=corpus.connections))
        assert findings
        for finding in findings:
            for evidence in finding.evidence:
                assert evidence.artifacts
                assert all(a.locator for a in evidence.artifacts)

    def test_short_capture_omits_novelty_rather_than_scoring_it(self) -> None:
        """Over ten minutes of capture, everything is new."""
        rows: list[dict[str, object]] = []
        for index, volume in enumerate((120_000, 150_000, 180_000, 210_000, 240_000, 300_000)):
            rows += _flows("10.0.0.5", f"93.184.0.{index + 1}", 4, volume, volume * 8, 0.0, step=60.0)
        rows += _flows("10.0.0.5", "45.83.220.17", 4, 200_000_000, 40_000, 400.0, step=60.0)

        findings = EgressAnalyzer().analyze(AnalysisContext(connections=_capture(rows)))
        assert findings
        profile = next(e for e in findings[0].evidence if e.kind == "destination_profile")
        assert profile.payload["novelty_fraction"] is None
        assert "novelty=" not in findings[0].basis
        assert "omitted (unmeasured): novelty" in findings[0].basis


class TestCorrelation:
    def test_a_rare_destination_alone_earns_no_corroboration_bonus(self) -> None:
        """Rule for this predicate, asserted where it takes effect.

        `contacts_rare_destination` is LOW, fires on one cheap signal, and
        every quiet corner of an estate produces one. It enriches an incident
        other evidence created; it may not create or promote one itself.
        """
        rows = _workstation("10.0.0.5")
        rows += _flows("10.0.0.5", "179.43.160.8", 8, 90_000, 2_000, 16 * HOUR)

        findings = EgressAnalyzer().analyze(AnalysisContext(connections=_capture(rows)))
        rare = [f for f in findings if f.predicate is Predicate.CONTACTS_RARE_DESTINATION]
        assert rare, "the fixture stopped exercising the predicate"

        queue = build_queue(rare)
        assert queue.incidents[0].corroborating_predicates == ()
        assert not queue.corroborated

    def test_beaconing_plus_volume_is_one_behaviour_not_two(self) -> None:
        """The CTU-13 scenario 3 regression, in miniature.

        `transfers_anomalous_volume` is what the analyzer says when it cannot
        say exfiltration — the direction was not recorded, or the signals did
        not reach the threshold. Partial evidence by construction, and partial
        evidence may be reported without being counted as a second opinion.

        Measured: letting it corroborate took scenario 3's infected host from
        queue rank 2 to rank 5 and corroborated incidents from 3 to 33, while
        contributing nothing to the true positive itself. The finding stays in
        the incident and still raises the combined confidence through the
        noisy-OR; it just stops multiplying the priority.
        """
        host = Entity(type=EntityType.IP, value="10.0.0.5")
        beacon = Finding(
            predicate=Predicate.BEACONS_TO,
            subject=host,
            object=Entity(type=EntityType.IP, value="45.83.220.17"),
            evidence=[_synthetic_evidence("interval_regularity")],
            confidence=0.90,
            basis="synthetic",
            analyzer="beaconing@test",
        )
        volume = Finding(
            predicate=Predicate.TRANSFERS_ANOMALOUS_VOLUME,
            subject=host,
            object=Entity(type=EntityType.IP, value="185.220.101.9"),
            evidence=[_synthetic_evidence("egress_volume")],
            confidence=0.85,
            basis="synthetic",
            analyzer="egress@test",
        )

        ranked = build_queue([beacon, volume]).incidents[0]
        assert ranked.corroborating_predicates == (Predicate.BEACONS_TO,)
        assert ranked.priority == pytest.approx(ranked.combined_confidence)
        assert "single behaviour" in ranked.rationale

        # Reported, and still contributing: two findings in the incident, and
        # a combined confidence above either one alone.
        assert len(ranked.incident.findings) == 2
        assert ranked.combined_confidence > max(beacon.confidence, volume.confidence)

    def test_exfiltration_does_still_corroborate(self) -> None:
        """Guards the test above against over-reaching.

        Only the demoted claim is barred from corroborating. `exfiltrates_to`
        rests on the full four signals including direction, and a host that
        beacons *and* exfiltrates has genuinely done two separate things.
        """
        host = Entity(type=EntityType.IP, value="10.0.0.5")
        beacon = Finding(
            predicate=Predicate.BEACONS_TO,
            subject=host,
            object=Entity(type=EntityType.IP, value="45.83.220.17"),
            evidence=[_synthetic_evidence("interval_regularity")],
            confidence=0.90,
            basis="synthetic",
            analyzer="beaconing@test",
        )
        exfil = Finding(
            predicate=Predicate.EXFILTRATES_TO,
            subject=host,
            object=Entity(type=EntityType.IP, value="185.220.101.9"),
            evidence=[_synthetic_evidence("egress_volume")],
            confidence=0.85,
            basis="synthetic",
            analyzer="egress@test",
        )

        ranked = build_queue([beacon, exfil]).incidents[0]
        assert len(ranked.corroborating_predicates) == 2
        assert ranked.priority > ranked.combined_confidence

    def test_the_partial_evidence_predicates_are_declared_non_corroborating(self) -> None:
        declared = CorrelationConfig().non_corroborating
        assert Predicate.CONTACTS_RARE_DESTINATION in declared
        assert Predicate.TRANSFERS_ANOMALOUS_VOLUME in declared
        assert Predicate.EXFILTRATES_TO not in declared
