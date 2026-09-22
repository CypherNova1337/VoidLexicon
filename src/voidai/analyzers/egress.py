"""Volume and egress: data leaving, in quantities the host does not normally send.

Exfiltration is the one stage of an intrusion that has to move bytes. The
channel can be TLS, the destination can be a rented VPS or a cloud bucket, and
the payload is opaque either way — but the volume is not, and neither is the
direction it travelled in.

Four measurements over each source→destination pair, combined with a weighted
geometric mean:

    egress ratio        share of the conversation's bytes that went *out*.
                        Browsing pulls; exfiltration pushes
    volume deviation    how far this destination sits above the host's own
                        distribution of per-destination volume, in robust
                        standard deviations
    destination rarity  how much of the estate talks to this destination
    novelty             how much of the host's observed window elapsed before
                        it first contacted this destination at all

The geometric mean is doing the same work it does in `beaconing.py`, against a
harder adversary. **A backup job and a cloud sync look exactly like
exfiltration on the first two signals**: high egress ratio, large volume, and
often a schedule as well. What separates them is that a backup target is
reached by much of the estate and has been reached since before the capture
began. `destination_rarity` and `novelty` carry 0.42 of the weight between
them for that reason, and an average — which would let sheer volume carry a
detection on its own — would report the nightly backup as a data breach on
night one.

The accepted cost is the mirror image: a transfer to a popular destination the
host has used since before the capture opened will not be claimed as
exfiltration here, however large it is. VoidLexicon sees one sensor's window, and
inside that window such traffic is the host's normal. That is a limit of the
observation, and it is stated on the finding rather than papered over — the
long-standing destination scores low on novelty, and the score says so.

## Direction is not always recorded, and absent is not zero

`ingest/netflow.py` records total flow bytes as `orig_bytes`, because a
NetFlow record carries no directional split. On NetFlow telemetry the egress
ratio is therefore **unavailable** — not zero, and not 0.5. The component is
omitted and the remaining weights renormalise over what was actually
measured, which is the same rule `payload_uniformity` follows in the beaconing
analyzer. Substituting a value here would invent the single most important
piece of evidence for the claim being made.

The consequence is recorded on every finding rather than hidden: the evidence
payload carries `egress_ratio: null` and the basis line says the component was
omitted.

**And the claim changes with it.** `exfiltrates_to` asserts an anomalous
*outbound* volume. With no direction observed, "outbound" is a word the
telemetry cannot support, so the predicate is unreachable on NetFlow no matter
what the remaining three signals score — the strongest available claim is
`transfers_anomalous_volume`, which asserts only that the volume between two
endpoints departs from a baseline, and which the deviation component does
ground. Dropping a measurement while keeping the claim it existed to justify
is the same mistake as substituting a value for it, made one level up where it
is harder to see.

That is not a hypothetical. Scored before this rule existed, CTU-13 scenario 3
produced 176 `exfiltrates_to` findings across 35 hosts at a median confidence
of 0.892 — every one a critical outbound accusation derived from telemetry
with no direction in it — and the corroboration they earned moved the infected
host from queue rank 2 to rank 5. `docs/benchmarks.md` §7 has the account.

## One predicate per source

The three predicates this analyzer claims are one measurement seen at three
strengths, not three independent observations. Which one a pair can support is
decided first by *what was measured* and only then by how high it scored:

    exfiltrates_to               (critical/high)  needs the egress ratio
    transfers_anomalous_volume   (medium)         needs the volume deviation
    contacts_rare_destination    (low)            prevalence alone

A source then emits findings in its **highest available** band only.
`voidai.correlate` multiplies an incident's priority by the number of distinct
predicates on the host, and a host that earned `exfiltrates_to` would
otherwise corroborate itself by restating the same score under a weaker verb —
the failure mode the `non_corroborating` set exists to prevent for `precedes`.
A host exfiltrating to two destinations still gets a finding for each, under
the one predicate.

`contacts_rare_destination` is additionally in `non_corroborating`, because it
fires on a single cheap signal and is LOW severity: it enriches an incident
that other evidence already created and can never raise a host's rank alone.
Its gates are correspondingly hard — a byte floor, a flow floor, a prevalence
ceiling, and a `max_findings` an order of magnitude tighter than the rest.

## Validation

Sensitivity and specificity are measured against a seeded synthetic corpus
(`EgressCorpusGenerator`) whose benign traffic includes the categories that
break volume detectors: a nightly backup, a cloud sync, and a software mirror.
**That is the synthetic half.** Real-capture figures from CTU-13 are pending —
see `docs/benchmarks.md`, which says so in the same sentence as every number
on this page.

No language model is involved at any point.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import numpy as np
import polars as pl

from voidai.analyzers.base import AnalysisContext, BaseAnalyzer
from voidai.analyzers.statistics import (
    destination_rarity,
    robust_deviation,
    saturating,
    weighted_geometric_mean,
)
from voidai.lexicon import Artifact, Evidence, Finding, Predicate, Severity

_WEIGHTS = {
    "egress_ratio": 0.30,
    "volume_deviation": 0.28,
    "destination_rarity": 0.24,
    "novelty": 0.18,
}

#: Columns without which this analyzer has nothing to measure. `orig_bytes` is
#: among them: a sensor that records no byte counts cannot be asked about
#: volume, and the honest response is silence rather than a score built from
#: rarity alone.
_REQUIRED = frozenset({"ts", "src_ip", "dst_ip", "orig_bytes"})


@dataclass(frozen=True)
class EgressConfig:
    """Tunables, set to favour precision over recall.

    Two of them — `min_bytes` and `rare_min_bytes` — are floors on how much
    data must move before this analyzer will say anything at all, and they are
    the difference between an exfiltration detector and a list of every
    conversation on the network. They are set from the shape of the problem
    rather than from a measurement, and are marked as such in
    `docs/benchmarks.md` until a real capture calibrates them.
    """

    #: Outbound bytes to one destination below which `exfiltrates_to` and
    #: `transfers_anomalous_volume` are not considered. Exfiltration that
    #: matters moves megabytes; a host that sent 40KB somewhere unusual is a
    #: question for `contacts_rare_destination` at LOW, if anything.
    min_bytes: int = 1_000_000

    #: Share of a pair's flows that must carry *both* byte counts before the
    #: egress ratio is treated as measured. A sensor that recorded the
    #: responder's bytes on a tenth of the flows gives a ratio describing that
    #: tenth, not the conversation.
    min_ratio_coverage: float = 0.5
    #: Egress ratio at which the component scores 0 and 1. A conversation that
    #: is evenly balanced says nothing; browsing sits well below 0.5 because
    #: pages are pulled, and a transfer out approaches 1.0.
    egress_ratio_floor: float = 0.50
    egress_ratio_ceiling: float = 0.90

    #: Destinations a host must have reached before its own volume
    #: distribution is a baseline rather than a coincidence.
    min_baseline_destinations: int = 5
    #: Modified z-score at which the deviation component is well-established.
    #: 3.5 is the conventional robust-outlier threshold, and lands at 0.63.
    strong_deviation: float = 3.5

    #: Observation window a host needs before "first seen late in the window"
    #: means anything at all. Over five minutes of capture everything is new,
    #: so below this the novelty component is omitted rather than scored.
    min_baseline_span_seconds: float = 3600.0

    #: Combined score at or above which the claim is `exfiltrates_to`.
    exfil_threshold: float = 0.70
    #: Score above which that finding is promoted from HIGH to CRITICAL.
    critical_threshold: float = 0.85
    #: Combined score at or above which the claim is
    #: `transfers_anomalous_volume`, given the deviation was measurable.
    volume_threshold: float = 0.45
    #: Deviation component below which the volume claim is not made. The
    #: predicate says the volume deviates from the host's baseline, so a
    #: finding that never measured the baseline would be asserting something
    #: it did not observe.
    min_volume_deviation: float = 0.50

    #: Gates on `contacts_rare_destination`, which is LOW severity, fires on
    #: one cheap signal, and over a real estate can emit thousands. Every
    #: workstation reaches a handful of addresses nobody else does, so
    #: prevalence and a byte floor together are not nearly enough: without the
    #: score threshold this band emits one finding per host per obscure
    #: website, at confidences around 0.03, which is the alert flood this
    #: project exists to prevent arriving from inside it.
    rare_min_bytes: int = 100_000
    rare_min_flows: int = 5
    #: Hosts contacting the destination, above which it is not rare.
    rare_max_hosts: int = 2
    rare_score_threshold: float = 0.30

    max_findings: int = 200
    #: Deliberately an order of magnitude below `max_findings`. See the
    #: module docstring: this predicate is enrichment, not a queue entry.
    max_rare_findings: int = 25
    artifact_samples: int = 5


#: Ordering of the bands, strongest first. Used to keep one source to one
#: predicate — see the module docstring.
_BANDS: dict[Predicate, int] = {
    Predicate.EXFILTRATES_TO: 2,
    Predicate.TRANSFERS_ANOMALOUS_VOLUME: 1,
    Predicate.CONTACTS_RARE_DESTINATION: 0,
}


@dataclass
class EgressScore:
    """The full measurement for one source→destination pair."""

    score: float
    components: dict[str, float]
    orig_bytes: float
    #: `None` when the sensor recorded no responder byte counts for this pair.
    resp_bytes: float | None
    egress_ratio: float | None
    ratio_coverage: float
    volume_deviation: float | None
    baseline_destinations: int
    baseline_median_bytes: float | None
    contacting_hosts: int
    novelty_fraction: float | None
    flows: int
    first_seen: float
    last_seen: float

    def basis(self) -> str:
        """A one-line, checkable justification for the confidence score."""
        parts = ", ".join(f"{k}={v:.2f}" for k, v in sorted(self.components.items()))
        omitted = [name for name in _WEIGHTS if name not in self.components]
        missing = f"; omitted (unmeasured): {', '.join(sorted(omitted))}" if omitted else ""
        return (
            f"weighted geometric mean of [{parts}] over {self.flows} flow(s) carrying "
            f"{self.orig_bytes:,.0f} bytes out to a destination reached by "
            f"{self.contacting_hosts} host(s) in this estate{missing}"
        )


def score_transfer(
    orig_bytes: float,
    egress_ratio: float | None,
    host_baseline: np.ndarray,
    contacting_hosts: int,
    novelty_fraction: float | None,
    config: EgressConfig,
    flows: int = 1,
    resp_bytes: float | None = None,
    ratio_coverage: float = 0.0,
    first_seen: float = 0.0,
    last_seen: float = 0.0,
) -> EgressScore | None:
    """Measure one source→destination pair. Returns None if it cannot qualify.

    Separated from the Polars and Lexicon plumbing for the same reason
    `score_pair` is: the mathematics can then be tested against hand-built
    inputs, including the ones where a measurement is missing.

    `egress_ratio` and `novelty_fraction` are `None` when the sensor could not
    supply them. `host_baseline` is the host's per-destination outbound byte
    totals, *including* this destination — excluding it would need a fresh
    median per pair and would inflate every deviation by removing the sample
    that is being judged.

    No volume floor is applied here. Which floor applies depends on which
    claim is being considered, and that is policy belonging to the analyzer
    rather than to the measurement.
    """
    if flows <= 0 or not np.isfinite(orig_bytes) or orig_bytes <= 0:
        return None

    components: dict[str, float] = {}

    if egress_ratio is not None:
        span = max(config.egress_ratio_ceiling - config.egress_ratio_floor, 1e-9)
        components["egress_ratio"] = float(
            np.clip((egress_ratio - config.egress_ratio_floor) / span, 0.0, 1.0)
        )

    deviation: float | None = None
    baseline_median: float | None = None
    if host_baseline.size >= config.min_baseline_destinations:
        deviation = robust_deviation(orig_bytes, host_baseline)
        if deviation is not None:
            baseline_median = float(np.median(host_baseline))
            components["volume_deviation"] = saturating(
                max(deviation, 0.0), config.strong_deviation
            )

    components["destination_rarity"] = destination_rarity(contacting_hosts)

    if novelty_fraction is not None:
        components["novelty"] = float(np.clip(novelty_fraction, 0.0, 1.0))

    return EgressScore(
        score=weighted_geometric_mean(components, _WEIGHTS),
        components=components,
        orig_bytes=float(orig_bytes),
        resp_bytes=resp_bytes,
        egress_ratio=egress_ratio,
        ratio_coverage=ratio_coverage,
        volume_deviation=deviation,
        baseline_destinations=int(host_baseline.size),
        baseline_median_bytes=baseline_median,
        contacting_hosts=contacting_hosts,
        novelty_fraction=novelty_fraction,
        flows=int(flows),
        first_seen=first_seen,
        last_seen=last_seen,
    )


class EgressAnalyzer(BaseAnalyzer):
    """Emits volume and egress findings for source→destination pairs."""

    name = "egress"
    version = "0.1.0"

    def __init__(self, config: EgressConfig | None = None) -> None:
        self.config = config or EgressConfig()

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        """Two streaming passes, neither materialising the capture.

        Pass one groups to one row per (source, destination) carrying only
        scalars — flow count, byte totals, first and last timestamp. Every
        measurement this analyzer makes is derived from those scalars or from
        small aggregations over the summary itself, so the expensive part of
        `beaconing.py` — gathering per-pair arrays — is never needed at all.

        Pass two runs after scoring and after the caps have been applied, and
        gathers artifact locators for the handful of pairs actually being
        reported. A semi-join restricts the scan to those pairs first, so the
        list columns hold a few hundred rows rather than the capture.
        """
        available = set(ctx.connection_scan().collect_schema().names())
        if not _REQUIRED.issubset(available):
            return []

        scan = ctx.connection_scan().drop_nulls(subset=["ts", "src_ip", "dst_ip"])
        summary = self._pair_summary(scan, available)
        if summary.is_empty():
            return []

        candidates = self._candidates(summary)
        if candidates.is_empty():
            return []

        baselines, windows = self._host_context(summary, candidates)

        scored: list[tuple[EgressScore, Predicate, dict[str, object]]] = []
        for row in candidates.iter_rows(named=True):
            source = str(row["src_ip"])
            score = score_transfer(
                float(row["orig_bytes"]),
                self._ratio(row),
                baselines[source],
                int(row["contacting_hosts"]),
                self._novelty(float(row["first_ts"]), windows[source]),
                self.config,
                flows=int(row["flows"]),
                resp_bytes=self._resp_bytes(row),
                ratio_coverage=self._ratio_coverage(row),
                first_seen=float(row["first_ts"]),
                last_seen=float(row["last_ts"]),
            )
            if score is None:
                continue
            predicate = self._band(score, row)
            if predicate is not None:
                scored.append((score, predicate, row))

        selected = self._select(scored)
        if not selected:
            return []

        artifacts = self._collect_artifacts(scan, selected, available)
        findings = [
            self._build_finding(score, predicate, row, artifacts, ctx)
            for score, predicate, row in selected
        ]
        return sorted(findings, key=lambda f: -f.confidence)

    # Pass 1: scalar summary per pair

    def _pair_summary(self, scan: pl.LazyFrame, available: set[str]) -> pl.DataFrame:
        """One row per (source, destination), carrying only scalars.

        Grouped without the destination port. Exfiltration is a claim about
        where the bytes went, not about which port carried them, and a host
        that spread one transfer across 443 and 8443 should be measured once.

        `orig_bytes` is summed null-skipping, so `measured_flows` — the count
        of flows that actually carried a figure — is aggregated alongside it.
        Polars sums an all-null column to 0, and a 0 here would be a sensor
        that records no byte counts masquerading as a silent host.
        """
        aggregations = [
            pl.len().alias("flows"),
            pl.col("orig_bytes").sum().alias("orig_bytes"),
            pl.col("orig_bytes").count().alias("measured_flows"),
            pl.col("ts").min().alias("first_ts"),
            pl.col("ts").max().alias("last_ts"),
        ]

        if "resp_bytes" in available:
            # Restricted to flows carrying *both* counts. Summing the two
            # columns independently would divide an originator total taken
            # over every flow by a responder total taken over a subset, and
            # report the sensor's gaps as outbound bias.
            both = pl.col("orig_bytes").is_not_null() & pl.col("resp_bytes").is_not_null()
            aggregations += [
                pl.col("orig_bytes").filter(both).sum().alias("paired_orig_bytes"),
                pl.col("resp_bytes").filter(both).sum().alias("paired_resp_bytes"),
                pl.col("orig_bytes").filter(both).len().alias("paired_flows"),
            ]

        summary = (
            scan.group_by(["src_ip", "dst_ip"])
            .agg(aggregations)
            .filter(pl.col("measured_flows") > 0)
            .collect(engine="streaming")
        )
        if summary.is_empty():
            return summary

        # Estate-wide prevalence, from the summary rather than a third scan:
        # it already holds one row per pair, so counting distinct sources per
        # destination is a small in-memory aggregation.
        prevalence = summary.group_by("dst_ip").agg(
            pl.col("src_ip").n_unique().alias("contacting_hosts")
        )
        return summary.join(prevalence, on="dst_ip", how="left")

    def _candidates(self, summary: pl.DataFrame) -> pl.DataFrame:
        """Pairs that could qualify under any band, on volume alone.

        The same gates the bands apply anyway, hoisted forward so that the
        Python loop below runs over the pairs that could be reported rather
        than over every conversation in the capture. On a capture with a
        million pairs that is the difference between a scoring pass measured
        in seconds and one measured in minutes.
        """
        config = self.config
        return summary.filter(
            (pl.col("orig_bytes") >= config.min_bytes)
            | (
                (pl.col("orig_bytes") >= config.rare_min_bytes)
                & (pl.col("flows") >= config.rare_min_flows)
                & (pl.col("contacting_hosts") <= config.rare_max_hosts)
            )
        )

    def _host_context(
        self, summary: pl.DataFrame, candidates: pl.DataFrame
    ) -> tuple[dict[str, np.ndarray], dict[str, tuple[float, float]]]:
        """Each candidate host's volume baseline and observation window.

        Built only for hosts owning a candidate, but from *all* of that host's
        pairs: the baseline a destination is judged against is everywhere else
        the host sent data, and the window is the whole time it was observed.
        """
        rows = (
            summary.join(candidates.select("src_ip").unique(), on="src_ip", how="semi")
            .group_by("src_ip")
            .agg(
                pl.col("orig_bytes").alias("baseline"),
                pl.col("first_ts").min().alias("host_first_ts"),
                pl.col("last_ts").max().alias("host_last_ts"),
            )
        )

        baselines: dict[str, np.ndarray] = {}
        windows: dict[str, tuple[float, float]] = {}
        for row in rows.iter_rows(named=True):
            source = str(row["src_ip"])
            baselines[source] = np.asarray(row["baseline"], dtype=np.float64)
            windows[source] = (float(row["host_first_ts"]), float(row["host_last_ts"]))
        return baselines, windows

    # Measurements that may be unavailable

    def _ratio(self, row: dict[str, object]) -> float | None:
        """Outbound share of the pair's bytes, or None if it was not recorded.

        None on three distinct grounds, all of them the same rule: the sensor
        has no `resp_bytes` column at all (NetFlow), it populated it on too
        few of this pair's flows to describe the conversation, or the
        conversation carried no bytes in either direction.
        """
        paired = row.get("paired_flows")
        if paired is None or int(paired) == 0:
            return None
        if self._ratio_coverage(row) < self.config.min_ratio_coverage:
            return None

        orig = float(row["paired_orig_bytes"] or 0.0)
        resp = float(row["paired_resp_bytes"] or 0.0)
        total = orig + resp
        if total <= 0:
            return None
        return orig / total

    def _ratio_coverage(self, row: dict[str, object]) -> float:
        paired = row.get("paired_flows")
        flows = int(row["flows"])
        if paired is None or flows <= 0:
            return 0.0
        return int(paired) / flows

    def _resp_bytes(self, row: dict[str, object]) -> float | None:
        paired = row.get("paired_flows")
        if paired is None or int(paired) == 0:
            return None
        return float(row["paired_resp_bytes"] or 0.0)

    def _novelty(self, first_ts: float, window: tuple[float, float]) -> float | None:
        """Share of the host's window that elapsed before this destination.

        A destination the host was already using when observation opened
        scores near zero, and that is a measurement rather than a missing one:
        over the only window available, the traffic is this host's normal.
        Under the geometric mean it drags hard, which is the intended
        behaviour and the reason a nightly backup does not read as a breach on
        night one.

        The genuinely unmeasurable case is a host observed too briefly for the
        ratio to carry information, and that returns None so the weight
        redistributes over the signals that were observed.
        """
        host_first, host_last = window
        span = host_last - host_first
        if span < self.config.min_baseline_span_seconds:
            return None
        return (first_ts - host_first) / span

    # Banding and caps

    def _band(self, score: EgressScore, row: dict[str, object]) -> Predicate | None:
        """Which claim, if any, this pair supports.

        Two questions in order, and the first one is not about the score.

        **Which signals were measured?** Each predicate names something, and a
        finding may not name what the sensor did not observe. `exfiltrates_to`
        asserts an anomalous *outbound* volume, so it requires the egress
        ratio; `transfers_anomalous_volume` asserts only that the volume
        between two endpoints departs from a baseline, so it requires the
        deviation. A sensor that recorded no direction can support the second
        claim and not the first, however high the score climbs.

        **Then, how high did it score?** Bands are thresholds on one score, so
        only one is ever returned: a pair supporting the strong claim does not
        additionally support the weak one.

        Reversing that order is what CTU-13 caught. Scoring first and letting
        the number pick the verb promoted 176 NetFlow pairs to a critical
        outbound claim on telemetry with no direction in it, and the
        corroboration those findings earned pushed the infected host down the
        queue. Omitting a component and then keeping the claim it existed to
        justify is the same error as defaulting the component, one level up.
        """
        config = self.config

        if score.orig_bytes >= config.min_bytes:
            measured_deviation = (
                score.components.get("volume_deviation", 0.0) >= config.min_volume_deviation
            )
            if "egress_ratio" in score.components and score.score >= config.exfil_threshold:
                return Predicate.EXFILTRATES_TO
            if score.score >= config.volume_threshold and measured_deviation:
                return Predicate.TRANSFERS_ANOMALOUS_VOLUME

        if (
            score.orig_bytes >= config.rare_min_bytes
            and score.flows >= config.rare_min_flows
            and score.contacting_hosts <= config.rare_max_hosts
            and score.score >= config.rare_score_threshold
        ):
            return Predicate.CONTACTS_RARE_DESTINATION

        return None

    def _select(
        self, scored: list[tuple[EgressScore, Predicate, dict[str, object]]]
    ) -> list[tuple[EgressScore, Predicate, dict[str, object]]]:
        """Keep each source's strongest band, then apply the caps.

        The band filter is what keeps this analyzer from corroborating itself
        in `voidai.correlate`; the caps are engineering rule 4. The rare
        band is capped separately and far more tightly, because it is the one
        that can run away over a large estate.
        """
        if not scored:
            return []

        best: dict[str, int] = {}
        for _, predicate, row in scored:
            source = str(row["src_ip"])
            best[source] = max(best.get(source, -1), _BANDS[predicate])

        kept = [
            item for item in scored if _BANDS[item[1]] == best[str(item[2]["src_ip"])]
        ]

        rare = sorted(
            (i for i in kept if i[1] is Predicate.CONTACTS_RARE_DESTINATION),
            key=lambda item: -item[0].score,
        )[: self.config.max_rare_findings]
        rest = sorted(
            (i for i in kept if i[1] is not Predicate.CONTACTS_RARE_DESTINATION),
            key=lambda item: -item[0].score,
        )[: self.config.max_findings]
        return rest + rare

    # Pass 2: artifact locators, reported pairs only

    def _collect_artifacts(
        self,
        scan: pl.LazyFrame,
        selected: list[tuple[EgressScore, Predicate, dict[str, object]]],
        available: set[str],
    ) -> dict[tuple[str, str], list[Artifact]]:
        """Gather source locators for the pairs being reported, and only those.

        Sampled by descending byte count rather than by position. An analyst
        checking an exfiltration finding wants the transfers that carried the
        volume, and the first five rows of a long conversation are usually its
        smallest.
        """
        if not {"source_file", "source_line"} <= available:
            return {}

        pairs = pl.DataFrame(
            {
                "src_ip": [str(row["src_ip"]) for _, _, row in selected],
                "dst_ip": [str(row["dst_ip"]) for _, _, row in selected],
            }
        )
        samples = self.config.artifact_samples
        by_volume = pl.col("orig_bytes")

        collected = (
            scan.join(pairs.lazy(), on=["src_ip", "dst_ip"], how="semi")
            .group_by(["src_ip", "dst_ip"])
            .agg(
                pl.col("source_file")
                .sort_by(by_volume, descending=True, nulls_last=True)
                .head(samples),
                pl.col("source_line")
                .sort_by(by_volume, descending=True, nulls_last=True)
                .head(samples),
                pl.col("ts").sort_by(by_volume, descending=True, nulls_last=True).head(samples),
                pl.col("orig_bytes")
                .sort_by(by_volume, descending=True, nulls_last=True)
                .head(samples),
            )
            .collect(engine="streaming")
        )

        out: dict[tuple[str, str], list[Artifact]] = {}
        for row in collected.iter_rows(named=True):
            files, lines = row["source_file"], row["source_line"]
            timestamps, volumes = row["ts"], row["orig_bytes"]
            artifacts: list[Artifact] = []
            for index in range(len(lines)):
                source = files[index] if index < len(files) and files[index] else "<unknown>"
                volume = volumes[index] if index < len(volumes) else None
                artifacts.append(
                    Artifact(
                        source=str(source),
                        locator=f"line:{lines[index]}",
                        observed_at=datetime.fromtimestamp(
                            float(timestamps[index]), tz=timezone.utc
                        ),
                        excerpt=(
                            f"{row['src_ip']} -> {row['dst_ip']} "
                            f"{'?' if volume is None else f'{int(volume)}'} bytes out"
                        ),
                    )
                )
            out[(str(row["src_ip"]), str(row["dst_ip"]))] = artifacts
        return out

    # Findings

    def _evidence(self, score: EgressScore, artifacts: list[Artifact]) -> list[Evidence]:
        """The measurement, with every unavailable figure explicitly null.

        `egress_ratio: null` in a payload is the whole point of the exercise.
        A reader of an `exfiltrates_to` finding derived from NetFlow can see
        that VoidLexicon measured how much left and how unusual the destination
        was, and never observed which direction the bytes travelled.
        """
        evidence = [
            Evidence(
                kind="egress_volume",
                summary=(
                    f"{score.orig_bytes:,.0f} bytes out over {score.flows} flow(s); "
                    + (
                        "direction not recorded by the sensor"
                        if score.egress_ratio is None
                        else f"{score.egress_ratio:.0%} of the conversation's bytes outbound"
                    )
                ),
                payload={
                    "orig_bytes": int(score.orig_bytes),
                    "resp_bytes": None if score.resp_bytes is None else int(score.resp_bytes),
                    "egress_ratio": (
                        None if score.egress_ratio is None else round(score.egress_ratio, 4)
                    ),
                    "egress_ratio_flow_coverage": round(score.ratio_coverage, 4),
                    "flows": score.flows,
                    "span_seconds": round(score.last_seen - score.first_seen, 1),
                },
                artifacts=artifacts,
            ),
            Evidence(
                kind="destination_profile",
                summary=(
                    f"destination reached by {score.contacting_hosts} host(s) estate-wide; "
                    + (
                        "novelty not measurable over this window"
                        if score.novelty_fraction is None
                        else f"first contacted {score.novelty_fraction:.0%} into the host's window"
                    )
                ),
                payload={
                    "contacting_hosts": score.contacting_hosts,
                    "novelty_fraction": (
                        None
                        if score.novelty_fraction is None
                        else round(score.novelty_fraction, 4)
                    ),
                    "baseline_destinations": score.baseline_destinations,
                },
                artifacts=artifacts,
            ),
        ]

        if score.volume_deviation is not None:
            evidence.append(
                Evidence(
                    kind="volume_deviation",
                    summary=(
                        f"{score.volume_deviation:.1f} robust standard deviations above this "
                        f"host's median of {score.baseline_median_bytes:,.0f} bytes "
                        f"across {score.baseline_destinations} destinations"
                    ),
                    payload={
                        "modified_z_score": round(score.volume_deviation, 3),
                        "baseline_median_bytes": (
                            None
                            if score.baseline_median_bytes is None
                            else int(score.baseline_median_bytes)
                        ),
                        "baseline_destinations": score.baseline_destinations,
                    },
                    artifacts=artifacts,
                )
            )
        return evidence

    def _severity(self, predicate: Predicate, score: EgressScore) -> Severity:
        """Severity per band.

        Only `exfiltrates_to` is allowed to reach CRITICAL, and only above its
        own threshold. The weaker bands are held at the Lexicon's default for
        their predicate: a volume anomaly is a lead, not a conclusion, and
        letting one climb would put this analyzer's opinion of a backup job
        alongside a measured command-and-control channel.
        """
        if predicate is Predicate.EXFILTRATES_TO:
            return (
                Severity.CRITICAL
                if score.score >= self.config.critical_threshold
                else Severity.HIGH
            )
        return predicate.spec.default_severity

    def _build_finding(
        self,
        score: EgressScore,
        predicate: Predicate,
        row: dict[str, object],
        artifacts: dict[tuple[str, str], list[Artifact]],
        ctx: AnalysisContext,
    ) -> Finding:
        source, destination = str(row["src_ip"]), str(row["dst_ip"])
        located = artifacts.get((source, destination)) or [
            Artifact(source="<aggregate>", locator=f"{source}->{destination}")
        ]
        return Finding(
            predicate=predicate,
            subject=ctx.actor(source),
            object=ctx.target(destination),
            evidence=[*self._evidence(score, located), *ctx.resolution_evidence(source)],
            confidence=round(score.score, 4),
            basis=score.basis(),
            severity=self._severity(predicate, score),
            analyzer=self.qualname,
            first_seen=datetime.fromtimestamp(score.first_seen, tz=timezone.utc),
            last_seen=datetime.fromtimestamp(score.last_seen, tz=timezone.utc),
        )
