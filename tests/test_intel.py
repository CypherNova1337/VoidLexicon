"""Tests for threat intel matching.

Three things here are load-bearing and the rest supports them.

**The score must not know about the traffic.** This is the one analyzer whose
inputs are a file rather than a measurement, and the tempting mistake is to
make it look like its neighbours by folding flow counts or destination rarity
into a geometric mean. A host that touched a known C2 once and a host that
touched it four thousand times have exactly the same intelligence behind them,
and `test_volume_does_not_move_the_score` fails if that stops being true.

**Missing provenance is not a default.** A feed that declares no confidence
has declared nothing, and an indicator with no date has an *unknown* age, not
a fresh one. The first scores low; the second is capped rather than decayed.
Both fail silently in the direction of over-confidence, which is why both are
asserted with numbers.

**Age is measured against the capture, not the clock.** Every ID in the
Lexicon is content-addressed, so an `age_days` derived from `datetime.now()`
would give the same input a different evidence ID every day and last week's
citations would resolve to nothing. `test_identity_is_reproducible` is the
guard, and it is not decorative — the wall-clock version of this analyzer
passes every other test in this file.
"""

from __future__ import annotations

import socket
from datetime import date, timedelta
from pathlib import Path

import polars as pl
import pytest
from pydantic import ValidationError

from voidai.analyzers import AnalysisContext, IntelConfig, ThreatIntelAnalyzer, score_match
from voidai.correlate import CorrelationConfig
from voidai.hunt import Dialect, queries_for
from voidai.ingest.ioc import (
    Feed,
    Indicator,
    IndicatorKind,
    IndicatorSet,
    classify,
    load_indicators,
    read_ioc_file,
)
from voidai.ingest.schema import CONNECTION_SCHEMA, DNS_SCHEMA, conform
from voidai.lexicon import Entity, EntityType, Finding, Predicate, Severity

DATA = Path(__file__).parent / "data"

#: 2018-04-04, the era of the CTU-13 captures. Fixed rather than derived from
#: the clock so that every age in this file is arithmetic, not weather.
CAPTURE_TS = 1_522_800_000.0
CAPTURE_DAY = date(2018, 4, 4)


def _feed(**overrides: object) -> Feed:
    kwargs: dict[str, object] = {
        "name": "test-feed",
        "path": "/feeds/test.ioc",
        "declared_confidence": 0.80,
    }
    kwargs.update(overrides)
    return Feed(**kwargs)  # type: ignore[arg-type]


def _indicator(value: str = "45.83.220.17", **overrides: object) -> Indicator:
    kind = classify(value)
    assert kind is not None
    kwargs: dict[str, object] = {
        "value": value,
        "kind": kind,
        "feed": _feed(),
        "added": CAPTURE_DAY - timedelta(days=10),
    }
    kwargs.update(overrides)
    return Indicator(**kwargs)  # type: ignore[arg-type]


def _set(*indicators: Indicator) -> IndicatorSet:
    out = IndicatorSet()
    for indicator in indicators:
        out.add(indicator)
    out.feeds = list({i.feed.path: i.feed for i in indicators}.values())
    return out


def _connections(rows: list[dict[str, object]]) -> pl.DataFrame:
    return conform(pl.DataFrame(rows), CONNECTION_SCHEMA)


def _conn(dst: str, count: int = 1, src: str = "10.0.0.5", start: int = 0) -> list[dict]:
    return [
        {
            "ts": CAPTURE_TS + start + index,
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": 443,
            "orig_bytes": 500,
            "resp_bytes": 500,
            "source_file": "conn.log",
            "source_line": start + index + 1,
        }
        for index in range(count)
    ]


def _dns(rows: list[tuple[str, str]]) -> pl.DataFrame:
    return conform(
        pl.DataFrame(
            [
                {
                    "ts": CAPTURE_TS + index,
                    "src_ip": "10.0.0.5",
                    "query": query,
                    "answers": answers,
                    "source_file": "dns.log",
                    "source_line": index + 1,
                }
                for index, (query, answers) in enumerate(rows)
            ]
        ),
        DNS_SCHEMA,
    )


class TestIocFormat:
    def test_the_documented_fixture_parses(self) -> None:
        indicators = load_indicators(DATA / "example.ioc")
        assert len(indicators) == 5
        assert indicators.counts() == {
            "ip": 1,
            "cidr": 1,
            "domain": 1,
            "url": 1,
            "file_hash": 1,
        }

    def test_the_header_configures_the_feed(self) -> None:
        feed, _, _ = read_ioc_file(DATA / "example.ioc")
        assert feed.name == "example-tracking"
        assert feed.declared_confidence == 0.80
        assert feed.updated == date(2018, 4, 1)
        assert feed.reference == "https://intel.example/report/0001"
        assert feed.tlp == "clear"

    def test_per_indicator_attributes_override_the_feed(self) -> None:
        _, indicators, _ = read_ioc_file(DATA / "example.ioc")
        by_value = {i.value: i for i in indicators}
        assert by_value["45.83.220.17"].added == date(2018, 3, 25)
        assert by_value["45.83.220.17"].note == "observed c2"

    def test_a_comment_after_the_first_indicator_cannot_redefine_provenance(
        self, tmp_path: Path
    ) -> None:
        """The header block ends at the first indicator, deliberately.

        Otherwise an operator annotating a block halfway down a file silently
        restates the confidence of everything above it.
        """
        path = tmp_path / "f.ioc"
        path.write_text("# confidence: 0.2\n10.0.0.1\n# confidence: 0.99\n10.0.0.2\n")
        feed, indicators, _ = read_ioc_file(path)
        assert feed.declared_confidence == 0.2
        assert {i.declared_confidence for i in indicators} == {0.2}

    def test_an_unreadable_line_is_rejected_and_reported_whole(self, tmp_path: Path) -> None:
        """One fat-fingered entry must not cost the other three hundred."""
        path = tmp_path / "f.ioc"
        path.write_text("10.0.0.1\nthis is not an indicator\n10.0.0.2\n")
        _, indicators, rejected = read_ioc_file(path)
        assert len(indicators) == 2
        assert [text for _, _, text in rejected] == ["this is not an indicator"]

    def test_a_missing_path_is_an_empty_set_not_an_error(self, tmp_path: Path) -> None:
        assert load_indicators(tmp_path / "absent").is_empty()

    def test_only_ioc_files_are_read(self, tmp_path: Path) -> None:
        """A directory of telemetry must not have the operator's notes parsed."""
        (tmp_path / "notes.txt").write_text("10.0.0.1\n")
        (tmp_path / "real.ioc").write_text("10.0.0.2\n")
        indicators = load_indicators(tmp_path)
        assert indicators.match_address("10.0.0.1") is None
        assert indicators.match_address("10.0.0.2") is not None

    def test_a_confidence_outside_the_scale_is_refused_not_clamped(self, tmp_path: Path) -> None:
        """A feed claiming 4.2 has told us its scale is not ours.

        Clamping to 1.0 would manufacture the provenance this module exists to
        preserve, so the declaration is discarded and the feed is treated as
        unprovenanced.
        """
        path = tmp_path / "f.ioc"
        path.write_text("# confidence: 4.2\n10.0.0.1\n")
        feed, _, _ = read_ioc_file(path)
        assert feed.declared_confidence is None
        assert not feed.provenanced


class TestClassification:
    @pytest.mark.parametrize(
        ("value", "kind"),
        [
            ("45.83.220.17", IndicatorKind.IP),
            ("2001:db8::1", IndicatorKind.IP),
            ("185.220.101.0/24", IndicatorKind.CIDR),
            ("c2.evil.example", IndicatorKind.DOMAIN),
            ("evil.example.", IndicatorKind.DOMAIN),
            ("d41d8cd98f00b204e9800998ecf8427e", IndicatorKind.FILE_HASH),
            ("http://drop.evil.example/gate.php", IndicatorKind.URL),
            ("drop.evil.example/gate.php", IndicatorKind.URL),
            ("localhost", None),
            ("", None),
        ],
    )
    def test_kinds_are_inferred_from_the_text(self, value: str, kind: IndicatorKind | None) -> None:
        assert classify(value) == kind

    def test_a_network_is_never_read_as_a_domain(self) -> None:
        """The failure this ordering prevents.

        `ip_address` rejects the `/24` form, so a network reaching the domain
        fallback becomes an indicator that can never match anything — a silent
        hole in an operator's coverage rather than an error.
        """
        assert classify("185.220.101.0/24") is IndicatorKind.CIDR

    def test_a_single_label_cannot_become_a_domain_indicator(self) -> None:
        """It would match a whole TLD on the parent walk."""
        assert classify("example") is None
        assert classify("com") is None


class TestMatching:
    def test_an_address_matches_exactly(self) -> None:
        indicators = _set(_indicator("45.83.220.17"))
        assert indicators.match_address("45.83.220.17") is not None
        assert indicators.match_address("45.83.220.18") is None

    def test_the_narrowest_network_wins(self) -> None:
        """An operator listing both meant the /28 as the more specific claim."""
        indicators = _set(_indicator("10.1.0.0/16"), _indicator("10.1.2.0/28"))
        match = indicators.match_address("10.1.2.3")
        assert match is not None
        assert match.value == "10.1.2.0/28"

    def test_a_parent_domain_catches_its_subdomains(self) -> None:
        indicators = _set(_indicator("evil.example"))
        match = indicators.match_domain("a.b.evil.example")
        assert match is not None and not match.exact
        assert match.indicator.value == "evil.example"

    def test_a_parent_domain_does_not_catch_a_lookalike(self) -> None:
        """`notevil.example` is not beneath `evil.example`.

        A substring test rather than a label-boundary walk gets this wrong,
        and gets it wrong in the direction of a confident false positive.
        """
        indicators = _set(_indicator("evil.example"))
        assert indicators.match_domain("notevil.example") is None

    def test_the_better_provenanced_duplicate_is_kept(self) -> None:
        """Two feeds naming one address is normal, not an error."""
        bulk = _indicator("45.83.220.17", feed=_feed(name="bulk", declared_confidence=None))
        precise = _indicator("45.83.220.17", feed=_feed(name="precise", declared_confidence=0.9))
        for order in ((bulk, precise), (precise, bulk)):
            match = _set(*order).match_address("45.83.220.17")
            assert match is not None
            assert match.feed.name == "precise"


class TestScoring:
    def test_confidence_comes_from_the_feed(self) -> None:
        score = score_match(_indicator(), CAPTURE_TS, IntelConfig())
        assert score is not None
        assert score.provenanced
        assert score.base_confidence == 0.80

    def test_an_unprovenanced_feed_scores_low(self) -> None:
        """Not a midpoint and not the feed's absent claim taken as agreement."""
        config = IntelConfig()
        anonymous = _indicator(feed=_feed(name="anon", declared_confidence=None))
        score = score_match(anonymous, CAPTURE_TS, config)
        assert score is not None
        assert score.base_confidence == config.unprovenanced_confidence
        assert score.confidence < config.medium_threshold

    def test_an_undated_indicator_is_capped_rather_than_assumed_fresh(self) -> None:
        config = IntelConfig()
        undated = score_match(_indicator(added=None), CAPTURE_TS, config)
        assert undated is not None
        assert undated.age_days is None
        assert undated.capped_for_unknown_age
        assert undated.confidence == config.max_confidence_without_age

    def test_an_undated_indicator_scores_below_a_fresh_dated_one(self) -> None:
        """The whole point of the cap.

        A substituted age of zero would score the undated indicator *higher*
        than a dated one a month old, rewarding the feed that recorded less.
        """
        config = IntelConfig()
        fresh = score_match(_indicator(added=CAPTURE_DAY - timedelta(days=30)), CAPTURE_TS, config)
        undated = score_match(_indicator(added=None), CAPTURE_TS, config)
        assert fresh is not None and undated is not None
        assert undated.confidence < fresh.confidence

    def test_age_decays_confidence_on_a_half_life(self) -> None:
        config = IntelConfig()
        aged = score_match(
            _indicator(added=CAPTURE_DAY - timedelta(days=int(config.half_life_days))),
            CAPTURE_TS,
            config,
        )
        assert aged is not None
        assert aged.confidence == pytest.approx(0.80 * 0.5, abs=1e-6)

    def test_older_is_always_weaker(self) -> None:
        config = IntelConfig()
        scores = [
            score_match(_indicator(added=CAPTURE_DAY - timedelta(days=days)), CAPTURE_TS, config)
            for days in (1, 30, 180, 400)
        ]
        confidences = [s.confidence for s in scores if s is not None]
        assert len(confidences) == 4
        assert confidences == sorted(confidences, reverse=True)

    def test_intel_older_than_the_hard_cut_is_not_reported_at_all(self) -> None:
        """Stale intel is worse than none.

        A 2019 indicator firing on a residential address reassigned since is a
        false positive with a citation attached, and a citation is what an
        analyst is least likely to re-check.

        The floor is disabled here on purpose. At default settings the decay
        alone puts a two-year-old indicator under `min_confidence`, so a test
        that simply asserts "ancient produces nothing" passes with
        `max_age_days` deleted — it names one mechanism and guards another.
        Removing the floor isolates the cut.
        """
        config = IntelConfig(min_confidence=0.0)
        ancient = _indicator(added=CAPTURE_DAY - timedelta(days=int(config.max_age_days) + 1))
        assert score_match(ancient, CAPTURE_TS, config) is None
        # And one day inside the cut still scores, so the boundary is the cut
        # rather than an accident of the arithmetic around it.
        inside = _indicator(added=CAPTURE_DAY - timedelta(days=int(config.max_age_days) - 1))
        assert score_match(inside, CAPTURE_TS, config) is not None

    def test_the_confidence_floor_drops_what_the_decay_has_hollowed_out(self) -> None:
        """The second mechanism, asserted separately from the first.

        Well inside `max_age_days`, decay alone can take a match below the
        floor. Reporting it would spend a queue position on a citation worth
        two percent.
        """
        config = IntelConfig(max_age_days=100_000.0)
        hollowed = _indicator(added=CAPTURE_DAY - timedelta(days=1200))
        assert score_match(hollowed, CAPTURE_TS, config) is None

    def test_an_indicator_added_after_the_capture_is_not_rewarded(self) -> None:
        """A feed refreshed between capture and analysis is the normal case.

        Clamped to zero rather than allowed negative: nothing is fresher than
        new, and a negative age would push the decay above 1.0 and inflate the
        feed's own declared confidence.
        """
        future = score_match(_indicator(added=CAPTURE_DAY + timedelta(days=90)), CAPTURE_TS, IntelConfig())
        assert future is not None
        assert future.age_days == 0.0
        assert future.confidence <= future.base_confidence

    def test_an_unknown_observation_time_is_an_unknown_age(self) -> None:
        score = score_match(_indicator(), None, IntelConfig())
        assert score is not None
        assert score.age_days is None
        assert score.capped_for_unknown_age

    def test_the_basis_states_both_factors(self) -> None:
        """An unexplained score is a guess, and this one has two inputs."""
        score = score_match(_indicator(), CAPTURE_TS, IntelConfig())
        assert score is not None
        assert "test-feed" in score.basis()
        assert "0.80" in score.basis()
        assert "day(s) before this traffic was observed" in score.basis()


class TestTheAnalyzer:
    def test_no_indicators_means_no_findings(self) -> None:
        ctx = AnalysisContext(connections=_connections(_conn("45.83.220.17", 5)))
        assert ThreatIntelAnalyzer().analyze(ctx) == []

    def test_an_empty_context_is_silent(self) -> None:
        ctx = AnalysisContext(indicators=load_indicators(DATA / "example.ioc"))
        assert ThreatIntelAnalyzer().analyze(ctx) == []

    def test_a_contacted_indicator_is_reported(self) -> None:
        ctx = AnalysisContext(
            connections=_connections(_conn("45.83.220.17", 5) + _conn("8.8.8.8", 40, start=100)),
            indicators=_set(_indicator("45.83.220.17")),
        )
        findings = ThreatIntelAnalyzer().analyze(ctx)
        assert [f.subject.value for f in findings] == ["45.83.220.17"]
        assert findings[0].predicate is Predicate.MATCHES_THREAT_INTEL

    def test_an_internal_source_address_is_matched_too(self) -> None:
        """An operator's list of known-compromised assets is the same file.

        Matching only destinations would silently ignore half of what an
        operator writes down.
        """
        ctx = AnalysisContext(
            connections=_connections(_conn("8.8.8.8", 3, src="10.0.0.66")),
            indicators=_set(_indicator("10.0.0.66")),
        )
        findings = ThreatIntelAnalyzer().analyze(ctx)
        assert [f.subject.value for f in findings] == ["10.0.0.66"]

    def test_the_direction_of_the_match_reaches_the_payload(self) -> None:
        """An indicator hit on a source is a different morning from one on a
        destination — a host of ours in someone's feed, rather than a host of
        ours having contacted one. The finding cannot say which otherwise,
        because the predicate is unary and the subject is the same either way.
        """
        outbound = AnalysisContext(
            connections=_connections(_conn("45.83.220.17", 3)),
            indicators=_set(_indicator("45.83.220.17")),
        )
        internal = AnalysisContext(
            connections=_connections(_conn("8.8.8.8", 3, src="10.0.0.66")),
            indicators=_set(_indicator("10.0.0.66")),
        )
        assert ThreatIntelAnalyzer().analyze(outbound)[0].evidence[0].payload[
            "observed_as"
        ] == ["dst"]
        assert ThreatIntelAnalyzer().analyze(internal)[0].evidence[0].payload[
            "observed_as"
        ] == ["src"]

    def test_volume_does_not_move_the_score(self) -> None:
        """The load-bearing one.

        A match is a join, not a measurement. One flow and four thousand flows
        carry the same intelligence, and letting VoidLexicon's own observation
        raise the score would report the capture as corroborating the feed.
        """
        indicators = _set(_indicator("45.83.220.17"), _indicator("203.0.113.9"))
        ctx = AnalysisContext(
            connections=_connections(
                _conn("45.83.220.17", 1) + _conn("203.0.113.9", 500, start=1000)
            ),
            indicators=indicators,
        )
        by_subject = {f.subject.value: f for f in ThreatIntelAnalyzer().analyze(ctx)}
        assert by_subject["45.83.220.17"].confidence == by_subject["203.0.113.9"].confidence

    def test_the_finding_is_unary(self) -> None:
        """`matches_threat_intel` says something about a subject alone."""
        ctx = AnalysisContext(
            connections=_connections(_conn("45.83.220.17", 3)),
            indicators=_set(_indicator("45.83.220.17")),
        )
        finding = ThreatIntelAnalyzer().analyze(ctx)[0]
        assert finding.object is None
        # And the grammar refuses to let it take one, so the shape is
        # enforced at construction rather than by this analyzer's good manners.
        with pytest.raises(ValidationError, match="unary"):
            Finding(
                predicate=Predicate.MATCHES_THREAT_INTEL,
                subject=finding.subject,
                object=Entity(type=EntityType.IP, value="10.0.0.5"),
                evidence=finding.evidence,
                confidence=0.5,
                basis="test",
                analyzer="test@0",
            )

    def test_severity_never_exceeds_medium(self) -> None:
        """A list membership is corroborating evidence, not a conclusion.

        A file an operator dropped into a directory must not be able to
        outrank VoidLexicon's own measurements.
        """
        certain = _indicator(feed=_feed(declared_confidence=1.0), added=CAPTURE_DAY)
        ctx = AnalysisContext(
            connections=_connections(_conn("45.83.220.17", 3)),
            indicators=_set(certain),
        )
        finding = ThreatIntelAnalyzer().analyze(ctx)[0]
        assert finding.confidence == 1.0
        assert finding.severity is Severity.MEDIUM

    def test_an_unprovenanced_match_is_low(self) -> None:
        ctx = AnalysisContext(
            connections=_connections(_conn("198.51.100.7", 3)),
            indicators=load_indicators(DATA / "unprovenanced.ioc"),
        )
        finding = ThreatIntelAnalyzer().analyze(ctx)[0]
        assert finding.severity is Severity.LOW

    def test_a_parent_domain_emits_one_finding_for_the_zone(self) -> None:
        """Not one per subdomain.

        A single wildcarded entry in a feed would otherwise fill the queue by
        itself — the alert flood this project exists to prevent, arriving from
        inside it.
        """
        ctx = AnalysisContext(
            dns=_dns([(f"host{index}.c2.evil.example", "") for index in range(40)]),
            indicators=_set(_indicator("c2.evil.example")),
        )
        findings = [
            f
            for f in ThreatIntelAnalyzer().analyze(ctx)
            if f.predicate is Predicate.MATCHES_THREAT_INTEL
        ]
        assert len(findings) == 1
        assert findings[0].subject.value == "c2.evil.example"
        payload = findings[0].evidence[0].payload
        assert payload["match"] == "parent_domain"
        assert payload["observed_value_count"] == 40
        assert len(payload["observed_values"]) <= IntelConfig().max_observed_samples

    def test_a_network_indicator_is_capped_but_counted(self) -> None:
        """A /16 in a feed can contain hundreds of observed addresses."""
        config = IntelConfig()
        rows: list[dict[str, object]] = []
        for index in range(60):
            rows += _conn(f"185.220.101.{index + 2}", 1, start=index)
        ctx = AnalysisContext(
            connections=_connections(rows),
            indicators=_set(_indicator("185.220.101.0/24")),
        )
        findings = ThreatIntelAnalyzer().analyze(ctx)
        matches = [f for f in findings if f.predicate is Predicate.MATCHES_THREAT_INTEL]
        assert len(matches) == config.max_per_indicator
        assert matches[0].evidence[0].payload["observed_value_count"] == 60
        assert matches[0].evidence[0].payload["match"] == "netblock"

    def test_findings_are_capped(self) -> None:
        config = IntelConfig(max_findings=5)
        indicators = _set(*[_indicator(f"203.0.113.{index}") for index in range(1, 40)])
        rows: list[dict[str, object]] = []
        for index in range(1, 40):
            rows += _conn(f"203.0.113.{index}", 1, start=index * 10)
        ctx = AnalysisContext(connections=_connections(rows), indicators=indicators)
        findings = ThreatIntelAnalyzer(config).analyze(ctx)
        matches = [f for f in findings if f.predicate is Predicate.MATCHES_THREAT_INTEL]
        assert len(matches) == 5

    def test_stale_intel_produces_nothing_even_when_contacted(self) -> None:
        ancient = _indicator(added=date(2009, 1, 1))
        ctx = AnalysisContext(
            connections=_connections(_conn("45.83.220.17", 20)),
            indicators=_set(ancient),
        )
        assert ThreatIntelAnalyzer().analyze(ctx) == []

    def test_a_resolved_answer_address_is_matched(self) -> None:
        """The address a name resolved to is telemetry the capture contains."""
        ctx = AnalysisContext(
            dns=_dns([("innocent.example", "45.83.220.17")]),
            indicators=_set(_indicator("45.83.220.17")),
        )
        subjects = {f.subject.value for f in ThreatIntelAnalyzer().analyze(ctx)}
        assert "45.83.220.17" in subjects

    def test_every_finding_carries_a_locator(self) -> None:
        """A Finding with no Artifact is rejected at construction."""
        ctx = AnalysisContext(
            connections=_connections(_conn("45.83.220.17", 4)),
            indicators=_set(_indicator("45.83.220.17")),
        )
        for finding in ThreatIntelAnalyzer().analyze(ctx):
            for evidence in finding.evidence:
                assert evidence.artifacts
                assert all(a.locator for a in evidence.artifacts)

    def test_the_payload_records_the_provenance_an_analyst_would_check(self) -> None:
        ctx = AnalysisContext(
            connections=_connections(_conn("45.83.220.17", 4)),
            indicators=_set(_indicator("45.83.220.17")),
        )
        payload = ThreatIntelAnalyzer().analyze(ctx)[0].evidence[0].payload
        assert payload["feed"] == "test-feed"
        assert payload["indicator"] == "45.83.220.17"
        assert payload["declared_confidence"] == 0.80
        assert payload["age_days"] == 10.0
        assert payload["indicator_added"] == "2018-03-25"


class TestIdentity:
    def test_identity_is_reproducible(self) -> None:
        """The same input produces the same IDs, which is what citations rest on.

        This one guards reproducibility *within* a run. It does not catch a
        wall-clock age — two runs a second apart agree about today — and
        pretending otherwise would make it the kind of test the engineering rule
        8 exists to prevent. `test_age_is_relative_to_the_capture_not_the_clock`
        below is the assertion that catches that, by requiring two captures
        ninety days apart to disagree by ninety days.
        """
        indicators = _set(_indicator("45.83.220.17"))
        ctx = AnalysisContext(
            connections=_connections(_conn("45.83.220.17", 6)), indicators=indicators
        )
        first = ThreatIntelAnalyzer().analyze(ctx)
        second = ThreatIntelAnalyzer().analyze(ctx)
        assert [f.id for f in first] == [f.id for f in second]
        assert [f.evidence[0].id for f in first] == [f.evidence[0].id for f in second]

    def test_age_is_relative_to_the_capture_not_the_clock(self) -> None:
        """The same indicator against two captures ages by the gap between them."""
        indicator = _indicator("45.83.220.17", added=date(2018, 1, 1))
        early = score_match(indicator, CAPTURE_TS, IntelConfig())
        late = score_match(indicator, CAPTURE_TS + 90 * 86400, IntelConfig())
        assert early is not None and late is not None
        assert late.age_days == early.age_days + 90


class TestSharedInfrastructure:
    def test_an_unflagged_name_on_a_flagged_address_is_linked(self) -> None:
        """The discovery worth having: what else sits on known-bad ground."""
        ctx = AnalysisContext(
            dns=_dns(
                [("known.evil.example", "45.83.220.17"), ("innocent.example", "45.83.220.17")]
            ),
            indicators=_set(_indicator("45.83.220.17")),
        )
        links = [
            f
            for f in ThreatIntelAnalyzer().analyze(ctx)
            if f.predicate is Predicate.SHARES_INFRASTRUCTURE_WITH
        ]
        assert {f.object.value for f in links if f.object} == {
            "known.evil.example",
            "innocent.example",
        }

    def test_two_values_caught_by_one_indicator_are_not_linked(self) -> None:
        """It would report the operator's own file back as a discovery.

        Five addresses inside one `/24` entry do share infrastructure — that
        is what the operator wrote down. Restating it is noise with a
        citation attached.
        """
        rows: list[dict[str, object]] = []
        for index in range(4):
            rows += _conn(f"185.220.101.{index + 2}", 1, start=index)
        ctx = AnalysisContext(
            connections=_connections(rows),
            indicators=_set(_indicator("185.220.101.0/24")),
        )
        links = [
            f
            for f in ThreatIntelAnalyzer().analyze(ctx)
            if f.predicate is Predicate.SHARES_INFRASTRUCTURE_WITH
        ]
        assert links == []

    def test_two_separately_flagged_addresses_in_one_block_are_linked(self) -> None:
        ctx = AnalysisContext(
            connections=_connections(
                _conn("203.0.113.4", 2) + _conn("203.0.113.9", 2, start=50)
            ),
            indicators=_set(_indicator("203.0.113.4"), _indicator("203.0.113.9")),
        )
        links = [
            f
            for f in ThreatIntelAnalyzer().analyze(ctx)
            if f.predicate is Predicate.SHARES_INFRASTRUCTURE_WITH
        ]
        assert len(links) == 1
        assert links[0].evidence[0].payload["link"] == "shared_netblock"

    def test_a_shared_hosting_address_is_not_infrastructure(self) -> None:
        """Ungated, this predicate describes CDNs at O(n²).

        The analyst learns that Akamai exists, and the finding cap is spent
        before anything useful reaches it.
        """
        config = IntelConfig(max_domains_per_address=5)
        ctx = AnalysisContext(
            dns=_dns(
                [("known.evil.example", "45.83.220.17")]
                + [(f"tenant{index}.example", "45.83.220.17") for index in range(40)]
            ),
            indicators=_set(_indicator("45.83.220.17")),
        )
        links = [
            f
            for f in ThreatIntelAnalyzer(config).analyze(ctx)
            if f.predicate is Predicate.SHARES_INFRASTRUCTURE_WITH
        ]
        assert links == []

    def test_a_link_needs_an_anchor(self) -> None:
        """Two unflagged names sharing an address is not a finding."""
        ctx = AnalysisContext(
            dns=_dns([("a.example", "198.51.100.20"), ("b.example", "198.51.100.20")]),
            indicators=_set(_indicator("45.83.220.17")),
        )
        assert ThreatIntelAnalyzer().analyze(ctx) == []

    def test_the_link_predicate_does_not_corroborate(self) -> None:
        """It describes the environment, not a second thing a host did."""
        assert Predicate.SHARES_INFRASTRUCTURE_WITH in CorrelationConfig().non_corroborating


class TestHuntPivot:
    def test_an_intel_match_generates_a_hunt(self) -> None:
        ctx = AnalysisContext(
            connections=_connections(_conn("45.83.220.17", 4)),
            indicators=_set(_indicator("45.83.220.17")),
        )
        finding = ThreatIntelAnalyzer().analyze(ctx)[0]
        queries = queries_for(finding, dialects=(Dialect.SIGMA,))
        assert queries
        assert "45.83.220.17" in queries[0].query
        assert queries[0].finding_id == finding.id


class TestOffline:
    def test_loading_indicators_opens_no_socket(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Rule 11, at the point most likely to tempt someone into a fetch.

        The whole cluster is one HTTP call away from being much easier, and
        this is the assertion that keeps it from being made.
        """

        def forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("intel loading reached for the network")

        for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
            monkeypatch.setattr(socket, name, forbidden)

        (tmp_path / "f.ioc").write_text("# confidence: 0.9\n45.83.220.17 added=2018-03-25\n")
        indicators = load_indicators(tmp_path)
        ctx = AnalysisContext(
            connections=_connections(_conn("45.83.220.17", 4)), indicators=indicators
        )
        assert ThreatIntelAnalyzer().analyze(ctx)

    def test_a_url_indicator_names_a_reference_but_fetches_nothing(self) -> None:
        """A feed header carrying a URL is documentation, not an instruction."""
        feed, _, _ = read_ioc_file(DATA / "example.ioc")
        assert feed.reference is not None
        assert feed.reference.startswith("http")


class TestInertIndicators:
    def test_hashes_and_urls_load_but_match_nothing_yet(self) -> None:
        """No HTTP or process telemetry parser exists until clusters 5 and 6.

        They are loaded anyway, because the alternative is a parser that
        misreads them as domains, and `voidai doctor` reports them as inert so
        an operator is told rather than left to assume.
        """
        indicators = load_indicators(DATA / "example.ioc")
        assert indicators.counts()["file_hash"] == 1
        assert indicators.counts()["url"] == 1
        ctx = AnalysisContext(
            connections=_connections(_conn("8.8.8.8", 4)),
            dns=_dns([("safe.example", "8.8.8.8")]),
            indicators=indicators,
        )
        assert ThreatIntelAnalyzer().analyze(ctx) == []
