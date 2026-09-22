"""Suricata alert triage.

A mid-sized sensor emits tens of thousands of alerts a day, and an analyst can
read a few dozen. Every deployed IDS is therefore already an alert-suppression
problem wearing a detection badge, and the usual response — tune the ruleset,
raise the severity floor — trades recall for silence.

This analyzer does something narrower and, in this architecture, more useful.
It does not try to decide which alerts are true. It reduces the flood to the
few worth *correlating*, and hands them to `voidai.correlate` as one more
opinion about a host.

That framing is why `TRIGGERED_SIGNATURE` carries a default severity of INFO
in the Lexicon. A signature firing is weak evidence on its own — most fire on
benign traffic — but a host that trips a rare high-severity rule *and* beacons
*and* sweeps a port is not ambiguous. The value of an alert here is almost
entirely as corroboration.

Three measurements per (source, signature):

    signature rarity   how many hosts in the estate trip this rule. A rule
                       firing for everyone describes the environment, not an
                       intrusion.
    stated severity    Suricata's own 1-3 rating, which is worth something
                       even though it is set by the rule author, not by you.
    category weight    "A Network Trojan was detected" and "Not Suspicious
                       Traffic" are not the same claim.

Deduplication is the first-order win and needs no scoring at all: an alert
repeated four thousand times is one fact about one host, and collapsing it is
most of the reduction.

No language model is involved at any point.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import polars as pl

from voidai.analyzers.base import AnalysisContext, BaseAnalyzer
from voidai.analyzers.statistics import destination_rarity, weighted_geometric_mean
from voidai.lexicon import Artifact, Entity, EntityType, Evidence, Finding, Predicate, Severity

_WEIGHTS = {
    "signature_rarity": 0.45,
    "stated_severity": 0.30,
    "category_weight": 0.25,
}

#: Suricata severity is 1 (highest) to 3 (lowest). Mapped rather than inverted
#: arithmetically so the scale stays explicit.
_SEVERITY_SCORE = {1: 1.0, 2: 0.6, 3: 0.3}
_DEFAULT_SEVERITY_SCORE = 0.4

#: Category weights, checked in order. Suricata writes a human-readable
#: description in EVE (`"Attempted Administrator Privilege Gain"`), while the
#: rule file carries the Snort classtype (`attempted-admin`). Both forms are
#: listed because both appear in the wild depending on the sensor.
#:
#: Order matters and is load-bearing: `"Not Suspicious Traffic"` contains the
#: substring `"suspicious"`, so a naive most-common-first ordering scores
#: Suricata's *noisiest* category as moderately suspicious. Negations are
#: therefore matched first, and `_NEGATIVE` exists so that invariant survives
#: someone appending to the list below.
_NEGATIVE: tuple[tuple[str, float], ...] = (
    ("not suspicious", 0.10),
    ("not-suspicious", 0.10),
    ("unknown traffic", 0.25),
)

_CATEGORY_WEIGHTS: tuple[tuple[str, float], ...] = (
    # Malware and control channels
    ("network trojan", 1.00),
    ("trojan-activity", 1.00),
    ("command and control", 1.00),
    ("malware", 1.00),
    ("crypto", 0.85),
    # Exploitation
    ("shellcode", 0.95),
    ("executable code was detected", 0.95),
    ("exploit", 0.95),
    ("administrator privilege gain", 0.90),
    ("attempted-admin", 0.90),
    ("successful-admin", 0.95),
    ("user privilege gain", 0.80),
    ("attempted-user", 0.80),
    ("web application attack", 0.85),
    ("web-application-attack", 0.85),
    ("sql injection", 0.85),
    # Credentials and data
    ("credential", 0.90),
    ("sensitive data", 0.75),
    # Reconnaissance and nuisance
    ("denial of service", 0.60),
    ("attempted-dos", 0.60),
    ("potentially bad traffic", 0.55),
    ("bad-unknown", 0.55),
    ("suspicious", 0.55),
    ("network scan", 0.50),
    ("network-scan", 0.50),
    ("scan", 0.50),
    # Policy and noise
    ("privacy violation", 0.35),
    ("policy", 0.30),
    ("misc attack", 0.50),
    ("misc activity", 0.25),
    ("misc-activity", 0.25),
    ("protocol", 0.25),
)

#: Applied when a category is absent or matches nothing. Mid-scale
#: deliberately: an unrecognised category is unknown, not exonerated.
_UNMATCHED_WEIGHT = 0.40


def category_weight(category: str | None) -> float:
    """Map a Suricata category string to a weight in [0, 1].

    Negations are tested before anything else, so a category that denies
    suspicion cannot be scored by the word it denies.
    """
    if not category:
        return _UNMATCHED_WEIGHT
    lowered = category.lower()

    for fragment, weight in _NEGATIVE:
        if fragment in lowered:
            return weight
    for fragment, weight in _CATEGORY_WEIGHTS:
        if fragment in lowered:
            return weight
    return _UNMATCHED_WEIGHT


@dataclass(frozen=True)
class AlertTriageConfig:
    """Tunables for reducing an alert stream to what is worth correlating."""

    #: Alerts from one source on one signature below this are ignored. A rule
    #: that fires once may still matter, but not enough to spend a finding on
    #: before anything corroborates it.
    min_alerts: int = 3
    #: Hosts tripping a signature above which it is treated as environmental.
    #: Fifty machines hitting the same rule is a policy, not an incident.
    environmental_host_count: int = 50

    score_threshold: float = 0.45
    high_threshold: float = 0.75

    max_findings: int = 200
    artifact_samples: int = 3


@dataclass
class AlertScore:
    """The measurement for one (source, signature) cluster."""

    score: float
    components: dict[str, float]
    alerts: int
    contacting_hosts: int
    stated_severity: int | None
    category: str | None
    first_seen: float
    last_seen: float

    def basis(self) -> str:
        parts = ", ".join(f"{k}={v:.2f}" for k, v in sorted(self.components.items()))
        return (
            f"weighted geometric mean of [{parts}] over {self.alerts} alerts; "
            f"signature seen on {self.contacting_hosts} host(s) in this estate, "
            f"stated severity {self.stated_severity}, category {self.category!r}"
        )


def score_alert_cluster(
    alerts: int,
    hosts_with_signature: int,
    stated_severity: int | None,
    category: str | None,
    config: AlertTriageConfig,
    first_seen: float = 0.0,
    last_seen: float = 0.0,
) -> AlertScore | None:
    """Score one source's alerts on one signature."""
    if alerts < config.min_alerts:
        return None

    # A rule tripped across the estate describes the environment. Reuse the
    # same prevalence curve the beaconing analyzer applies to destinations —
    # it is the same question about a different noun.
    rarity = destination_rarity(hosts_with_signature)
    if hosts_with_signature >= config.environmental_host_count:
        rarity = min(rarity, 0.05)

    components = {
        "signature_rarity": rarity,
        "stated_severity": _SEVERITY_SCORE.get(
            stated_severity if stated_severity is not None else -1,
            _DEFAULT_SEVERITY_SCORE,
        ),
        "category_weight": category_weight(category),
    }

    return AlertScore(
        score=weighted_geometric_mean(components, _WEIGHTS),
        components=components,
        alerts=alerts,
        contacting_hosts=hosts_with_signature,
        stated_severity=stated_severity,
        category=category,
        first_seen=first_seen,
        last_seen=last_seen,
    )


class AlertTriageAnalyzer(BaseAnalyzer):
    """Emits `TRIGGERED_SIGNATURE` findings for alerts worth correlating."""

    name = "alerts"
    version = "0.1.0"

    def __init__(self, config: AlertTriageConfig | None = None) -> None:
        self.config = config or AlertTriageConfig()

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        clusters = self._cluster(ctx.alert_scan())
        if clusters.is_empty():
            return []

        prevalence = self._signature_prevalence(clusters)

        scored: list[tuple[AlertScore, dict[str, object]]] = []
        for row in clusters.iter_rows(named=True):
            score = score_alert_cluster(
                int(row["alerts"]),
                prevalence.get(int(row["signature_id"] or 0), 1),
                int(row["severity"]) if row["severity"] is not None else None,
                str(row["category"]) if row["category"] is not None else None,
                self.config,
                first_seen=float(row["first_ts"]),
                last_seen=float(row["last_ts"]),
            )
            if score is not None and score.score >= self.config.score_threshold:
                scored.append((score, row))

        scored.sort(key=lambda item: (-item[0].score, -item[0].alerts))
        return [
            self._build_finding(score, row, ctx)
            for score, row in scored[: self.config.max_findings]
        ]

    def _cluster(self, scan: pl.LazyFrame) -> pl.DataFrame:
        """Collapse repeated alerts into one row per (source, signature).

        This is the reduction that matters most and costs least: an alert
        repeated four thousand times is one fact about one host.
        """
        available = set(scan.collect_schema().names())
        if not {"src_ip", "signature", "ts"} <= available:
            return pl.DataFrame()

        return (
            scan.drop_nulls(subset=["src_ip", "signature", "ts"])
            .group_by(["src_ip", "signature"])
            .agg(
                pl.len().alias("alerts"),
                pl.col("signature_id").first(),
                pl.col("category").first(),
                pl.col("severity").min(),  # most severe rating seen
                pl.col("dst_ip").n_unique().alias("distinct_targets"),
                pl.col("ts").min().alias("first_ts"),
                pl.col("ts").max().alias("last_ts"),
                pl.col("source_file").head(self.config.artifact_samples),
                pl.col("source_line").head(self.config.artifact_samples),
            )
            .collect(engine="streaming")
        )

    def _signature_prevalence(self, clusters: pl.DataFrame) -> dict[int, int]:
        """How many distinct hosts trip each signature.

        Derived from the clustered frame, which already holds one row per
        (source, signature), so this is a small in-memory aggregation.
        """
        if clusters.is_empty() or "signature_id" not in clusters.columns:
            return {}
        counts = (
            clusters.drop_nulls(subset=["signature_id"])
            .group_by("signature_id")
            .agg(pl.col("src_ip").n_unique().alias("hosts"))
        )
        return {
            int(sid): int(hosts)
            for sid, hosts in zip(
                counts["signature_id"].to_list(), counts["hosts"].to_list(), strict=True
            )
        }

    def _artifacts(self, row: dict[str, object], score: AlertScore) -> list[Artifact]:
        files, lines = row["source_file"], row["source_line"]
        artifacts = [
            Artifact(
                source=str(files[index]) if index < len(files) and files[index] else "<unknown>",
                locator=f"line:{lines[index]}",
                observed_at=datetime.fromtimestamp(score.first_seen, tz=timezone.utc),
                excerpt=f"{row['src_ip']} :: {row['signature']}",
            )
            for index in range(min(len(lines), self.config.artifact_samples))
        ]
        return artifacts or [
            Artifact(source="<aggregate>", locator=f"{row['src_ip']}:{row['signature_id']}")
        ]

    def _build_finding(
        self,
        score: AlertScore,
        row: dict[str, object],
        ctx: AnalysisContext,
    ) -> Finding:
        evidence = Evidence(
            kind="signature_cluster",
            summary=(
                f"{score.alerts} alerts for {row['signature']!r} "
                f"against {row['distinct_targets']} target(s); "
                f"signature seen on {score.contacting_hosts} host(s) estate-wide"
            ),
            payload={
                "signature": row["signature"],
                "signature_id": row["signature_id"],
                "category": score.category,
                "stated_severity": score.stated_severity,
                "alerts": score.alerts,
                "distinct_targets": row["distinct_targets"],
                "hosts_with_signature": score.contacting_hosts,
                "span_seconds": round(score.last_seen - score.first_seen, 1),
            },
            artifacts=self._artifacts(row, score),
        )

        return Finding(
            predicate=Predicate.TRIGGERED_SIGNATURE,
            subject=ctx.actor(str(row["src_ip"])),
            object=Entity(type=EntityType.SIGNATURE, value=str(row["signature"])),
            evidence=[evidence, *ctx.resolution_evidence(str(row["src_ip"]))],
            confidence=round(score.score, 4),
            basis=score.basis(),
            # Deliberately capped at MEDIUM. A signature firing is corroborating
            # evidence, not a conclusion, and letting it reach HIGH on its own
            # would put the ruleset's opinion above VoidLexicon's measurements.
            severity=(
                Severity.MEDIUM if score.score >= self.config.high_threshold else Severity.LOW
            ),
            analyzer=self.qualname,
            first_seen=datetime.fromtimestamp(score.first_seen, tz=timezone.utc),
            last_seen=datetime.fromtimestamp(score.last_seen, tz=timezone.utc),
        )
