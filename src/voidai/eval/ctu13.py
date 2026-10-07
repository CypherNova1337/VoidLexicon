"""Evaluation against the CTU-13 real-capture corpus.

CTU-13 is thirteen captures of real botnet traffic recorded on a university
network, with every flow labelled `Botnet`, `Normal`, or `Background`. It is
the closest thing the field has to ground truth for command-and-control
detection, and running against it is what separates a demo from a claim.

## Why the obvious metric is the wrong metric

The tempting evaluation is precision and recall against every `Botnet`-labelled
flow. That number would be meaningless here, and reporting it would be
dishonest in a direction that happens to flatter nobody.

A bot does far more than call home. The CTU-13 botnet labels cover spam runs,
ICMP floods, port scans, click fraud, and peer-to-peer chatter. A *beaconing*
detector is supposed to find the periodic check-in channel and ignore the
rest — flagging a spam burst as beaconing would be a bug, not a success. So
recall measured against all botnet traffic would punish the analyzer for being
correct, and its complement would reward a detector that simply alerted on
everything the infected host did.

Defining C2 as "the botnet traffic that looks periodic" and then measuring
whether we find periodic traffic is worse still: it is circular, and it would
score 1.000 by construction.

## What is measured instead

**Infected-host detection** — did the analyzer surface the compromised host at
all? This is the operational question a SOC actually asks, and it is derived
from the labels rather than from anything the detector computed.

**Pair precision** — of the source→destination pairs flagged as beaconing,
what fraction carry botnet labels? Non-circular, and directly interpretable:
it is the analyst's false-alarm rate. Scoped to `beacons_to` deliberately,
even though three analyzers now run: mixing predicates into one precision
figure would produce a number that changes whenever the analyzer mix changes
and means nothing on either side of the change.

**Alert burden** — findings per hour of capture. A detector with excellent
precision that emits four hundred alerts a day is still unusable, and this is
the number that says so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import polars as pl

from voidai.analyzers import (
    AnalysisContext,
    BeaconingAnalyzer,
    BeaconingConfig,
    EgressAnalyzer,
    EgressConfig,
    FanoutAnalyzer,
    FanoutConfig,
)
from voidai.correlate import IncidentQueue, build_queue
from voidai.ingest.netflow import LABEL_BOTNET, scan_labelled_netflow
from voidai.ingest.schema import CONNECTION_SCHEMA
from voidai.lexicon import Finding, Predicate
from voidai.telemetry import EnergyMeter, RunReceipt

#: Columns the analyzers need. Projecting early keeps the 1.4GB scenarios
#: inside a few hundred megabytes of working set.
_ANALYSIS_COLUMNS = [
    "ts",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "proto",
    "duration",
    "orig_bytes",
    "orig_pkts",
    "conn_state",
    "source_file",
    "source_line",
]


@dataclass(frozen=True)
class Scenario:
    """One CTU-13 capture and its published provenance."""

    key: str
    filename: str
    malware: str
    duration_hours: float
    #: The compromised hosts the CTU-13 authors document for this capture.
    #: Scoring counts a host as infected only when it is documented here *and*
    #: the labels confirm it — see `_infected`. Never an input to detection.
    #: Empty for a capture this module does not recognise, which then falls
    #: back to the labels alone.
    documented_infected: tuple[str, ...] = ()

    @property
    def url(self) -> str:
        return f"https://mcfp.felk.cvut.cz/publicDatasets/{self.key}/{self.filename}"


SCENARIOS: dict[str, Scenario] = {
    "scenario03": Scenario(
        key="CTU-Malware-Capture-Botnet-44",
        filename="capture20110812.pcap.netflow.labeled",
        malware="Rbot",
        duration_hours=66.85,
        documented_infected=("147.32.84.165",),
    ),
    "scenario06": Scenario(
        key="CTU-Malware-Capture-Botnet-47",
        filename="capture20110816.pcap.netflow.labeled",
        malware="Menti",
        duration_hours=2.18,
        documented_infected=("147.32.84.165",),
    ),
}


@dataclass
class RealCaptureResult:
    """Outcome of running the analyzers against one real capture."""

    scenario: Scenario
    findings: list[Finding]
    receipt: RunReceipt

    flow_count: int = 0
    span_hours: float = 0.0
    infected_hosts: set[str] = field(default_factory=set)
    #: Every source of a botnet-labelled flow. Reported for context, not
    #: scored: in this dialect it includes every server that answered the bot.
    label_sources: set[str] = field(default_factory=set)
    botnet_pairs: set[tuple[str, str]] = field(default_factory=set)
    flagged_pairs: list[tuple[str, str]] = field(default_factory=list)
    queue: IncidentQueue = field(default_factory=IncidentQueue)

    @property
    def best_infected_rank(self) -> int | None:
        """Best queue position held by a host the labels call compromised.

        The measure that actually matters. A true positive at rank 2 gets
        worked; the same true positive at rank 358 does not.
        """
        ranks = [
            rank
            for host in self.infected_hosts
            if (rank := self.queue.rank_of(host)) is not None
        ]
        return min(ranks) if ranks else None

    @property
    def true_positive_pairs(self) -> list[tuple[str, str]]:
        return [p for p in self.flagged_pairs if p in self.botnet_pairs]

    @property
    def pair_precision(self) -> float:
        """Fraction of flagged pairs that carry botnet labels."""
        if not self.flagged_pairs:
            return 1.0
        return len(self.true_positive_pairs) / len(self.flagged_pairs)

    @property
    def beaconing_findings(self) -> list[Finding]:
        """Beaconing findings only, highest confidence first.

        Several measures on this page are named after the beaconing channel
        and must be computed from beaconing findings alone, however many
        analyzers ran. See `c2_beaconing_confidence`.
        """
        beacons = [f for f in self.findings if f.predicate is Predicate.BEACONS_TO]
        return sorted(beacons, key=lambda f: -f.confidence)

    @property
    def c2_beaconing_confidence(self) -> float | None:
        """Strongest *beaconing* finding on a labelled botnet pair.

        Scoped to `beacons_to` deliberately. Selected across every predicate
        instead, this reported a `contacts_rare_destination` finding at 0.983
        on scenario 3 in place of the C2 beacon at 0.958 — a row labelled "c2
        confidence" carrying a number about something else, and no longer
        comparable with the figure the same row published before a third
        analyzer existed. A measure named after one behaviour is computed from
        that behaviour.

        The strongest finding of any kind on a labelled pair is worth knowing
        too, and has its own name: `strongest_labelled_finding`.
        """
        return next(
            (f.confidence for f in self.beaconing_findings if self._pair(f) in self.botnet_pairs),
            None,
        )

    @property
    def c2_beaconing_rank(self) -> int | None:
        """Where that finding sits among all beaconing findings, 1-based."""
        confidence = self.c2_beaconing_confidence
        if confidence is None:
            return None
        return [f.confidence for f in self.beaconing_findings].index(confidence) + 1

    @property
    def strongest_labelled_finding(self) -> Finding | None:
        """Highest-confidence finding of *any* predicate on a labelled pair.

        Reported under its own name rather than folded into the C2 row, so
        that a strong finding of another kind is visible without being
        mistaken for a measurement of the command-and-control channel.
        """
        labelled = [f for f in self.findings if self._pair(f) in self.botnet_pairs]
        return max(labelled, key=lambda f: f.confidence, default=None)

    @staticmethod
    def _pair(finding: Finding) -> tuple[str, str]:
        """A finding's endpoints, in the shape the label set is keyed by."""
        return (finding.subject.value, finding.object.value if finding.object else "")

    @property
    def flagged_infected_hosts(self) -> set[str]:
        return {src for src, _ in self.flagged_pairs} & self.infected_hosts

    @property
    def infected_host_detected(self) -> bool:
        """Did any finding name a host the labels identify as compromised?"""
        return bool(self.flagged_infected_hosts)

    @property
    def findings_per_hour(self) -> float:
        return len(self.findings) / self.span_hours if self.span_hours > 0 else 0.0


def _ground_truth(path: Path) -> tuple[set[str], set[tuple[str, str]]]:
    """Derive infected hosts and botnet pairs from the label column alone.

    Read in a separate pass from the analysis frame so that the labels are
    never present in the data the analyzer sees. Segregating them by
    construction is stronger than remembering to drop a column.
    """
    labelled = (
        scan_labelled_netflow(path)
        .filter(pl.col("label") == LABEL_BOTNET)
        .select("src_ip", "dst_ip")
        .unique()
        .collect(engine="streaming")
    )
    pairs = {(row["src_ip"], row["dst_ip"]) for row in labelled.iter_rows(named=True)}
    return {src for src, _ in pairs}, pairs


def _infected(scenario: Scenario, label_sources: set[str]) -> set[str]:
    """Which hosts to score as compromised.

    This dialect's label says a flow belongs to the botnet's traffic, not which
    end of it is the bot: a server answering the bot carries `Botnet` as surely
    as the bot's own request does. Read as "every source of a labelled flow is
    infected", scenario 3 has 3,347 infected hosts, a DNS server among them,
    for a capture its authors document as having one bot. The first NetFlow
    parser hid this by accident — server endpoints are short, short endpoints
    are padded with an extra tab, and padded rows lost their labels.

    So a host counts as infected when the authors document it *and* the labels
    confirm it. A documented host the labels never confirm is not counted,
    which surfaces a wrong file or a broken parse as "not detected" rather than
    as a pass. A capture with nothing documented falls back to the labels.
    """
    if not scenario.documented_infected:
        return set(label_sources)
    return set(scenario.documented_infected) & label_sources


def evaluate(
    path: str | Path,
    scenario: Scenario,
    config: BeaconingConfig | None = None,
) -> RealCaptureResult:
    """Run the beaconing analyzer against a real capture and score it."""
    path = Path(path)
    label_sources, botnet_pairs = _ground_truth(path)
    infected_hosts = _infected(scenario, label_sources)

    receipt = RunReceipt()
    with EnergyMeter() as meter:
        # Handed to the analyzer lazily. Collecting here would materialise the
        # whole capture — 7.2GB on the 66-hour scenario — before any filtering
        # had a chance to run.
        scan = scan_labelled_netflow(path).select(_ANALYSIS_COLUMNS)

        # Belt and braces: the analyzer must not be able to see ground truth
        # even if a future refactor changes the projection above.
        columns = set(scan.collect_schema().names())
        assert "label" not in columns, "ground truth leaked into analysis frame"
        assert columns <= set(CONNECTION_SCHEMA)

        extent = scan.select(
            pl.len().alias("records"),
            pl.col("ts").min().alias("first_ts"),
            pl.col("ts").max().alias("last_ts"),
        ).collect(engine="streaming")

        records = int(extent["records"][0]) if extent.height else 0
        ctx = AnalysisContext(connections=scan, known_record_count=records)

        findings = BeaconingAnalyzer(config).analyze(ctx)
        cap = config.max_findings if config else FanoutConfig().max_findings
        findings += FanoutAnalyzer(FanoutConfig(max_findings=cap)).analyze(ctx)
        # NetFlow carries no directional byte split, so `_ANALYSIS_COLUMNS`
        # has no `resp_bytes` for the egress analyzer to read. It measures
        # volume, prevalence and novelty and omits the ratio component
        # entirely — which is the behaviour this corpus is here to exercise,
        # not a degradation to work around.
        findings += EgressAnalyzer(EgressConfig(max_findings=cap)).analyze(ctx)
        queue = build_queue(findings)

    receipt.records_ingested = records
    receipt.findings_emitted = len(findings)
    receipt.finalize(meter.reading)

    span_hours = (
        (extent["last_ts"][0] - extent["first_ts"][0]) / 3600.0
        if records and extent["first_ts"][0] is not None
        else 0.0
    )

    return RealCaptureResult(
        scenario=scenario,
        findings=findings,
        receipt=receipt,
        flow_count=records,
        span_hours=float(span_hours),
        infected_hosts=infected_hosts,
        label_sources=label_sources,
        botnet_pairs=botnet_pairs,
        queue=queue,
        flagged_pairs=[
            (f.subject.value, f.object.value if f.object else "")
            for f in findings
            if f.predicate is Predicate.BEACONS_TO
        ],
    )
