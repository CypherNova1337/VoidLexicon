"""Tests for the real-capture scoring layer.

The property under test is that a measure named after one behaviour is
computed from that behaviour. It is not an abstract concern: when a third
analyzer was added, the "c2 confidence" row silently began reporting a
`contacts_rare_destination` finding at 0.983 on CTU-13 scenario 3 in place of
the C2 beacon at 0.958. Nothing errored. The row kept its name, the number
went up, and it stopped being comparable with every figure the same row had
published before.

These tests need no capture. `RealCaptureResult` is a scoring object over a
list of findings and a label set, so the interesting cases can be built by
hand — including the one that actually happened.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from voidai.eval.ctu13 import SCENARIOS, RealCaptureResult, evaluate
from voidai.lexicon import (
    Artifact,
    Entity,
    EntityType,
    Evidence,
    Finding,
    Predicate,
)
from voidai.telemetry import RunReceipt

#: The scenario 3 command-and-control channel and its documented victim.
INFECTED = "147.32.84.165"
C2 = "38.229.70.20"


def _finding(
    predicate: Predicate,
    source: str,
    target: str,
    confidence: float,
    target_type: EntityType = EntityType.IP,
) -> Finding:
    return Finding(
        predicate=predicate,
        subject=Entity(type=EntityType.IP, value=source),
        object=Entity(type=target_type, value=target),
        evidence=[
            Evidence(
                kind="synthetic",
                summary="synthetic evidence",
                artifacts=[Artifact(source="capture.netflow.labeled", locator="line:1")],
            )
        ],
        confidence=confidence,
        basis="synthetic",
        analyzer="test@0.0.0",
    )


def _result(findings: list[Finding]) -> RealCaptureResult:
    return RealCaptureResult(
        scenario=SCENARIOS["scenario03"],
        findings=findings,
        receipt=RunReceipt(),
        infected_hosts={INFECTED},
        botnet_pairs={(INFECTED, C2)},
        flagged_pairs=[
            (f.subject.value, f.object.value if f.object else "")
            for f in findings
            if f.predicate is Predicate.BEACONS_TO
        ],
    )


class TestC2Confidence:
    def test_a_stronger_finding_of_another_kind_cannot_become_the_c2_confidence(
        self,
    ) -> None:
        """The regression this module exists for, with the measured numbers.

        Both findings name the labelled C2 pair, and the rare-destination one
        scores higher. The row is named after the beaconing channel, so 0.958
        is the only answer it may give.
        """
        beacon = _finding(Predicate.BEACONS_TO, INFECTED, C2, 0.958)
        rare = _finding(Predicate.CONTACTS_RARE_DESTINATION, INFECTED, C2, 0.983)

        result = _result([rare, beacon])
        assert result.c2_beaconing_confidence == 0.958

    def test_the_stronger_finding_is_still_reported_under_its_own_name(self) -> None:
        """Scoped, not discarded. It was worth knowing, just not under that name."""
        beacon = _finding(Predicate.BEACONS_TO, INFECTED, C2, 0.958)
        rare = _finding(Predicate.CONTACTS_RARE_DESTINATION, INFECTED, C2, 0.983)

        strongest = _result([rare, beacon]).strongest_labelled_finding
        assert strongest is not None
        assert strongest.confidence == 0.983
        assert strongest.predicate is Predicate.CONTACTS_RARE_DESTINATION

    def test_the_rank_counts_beaconing_findings_only(self) -> None:
        """A denominator of "all findings" moves whenever the analyzer mix does.

        Three beaconing findings and four of other kinds. The C2 beacon is
        second-strongest of the beacons, and that is the rank — the other four
        are not competing for a position in this ordering.
        """
        findings = [
            _finding(Predicate.BEACONS_TO, "10.0.0.1", "8.8.8.8", 0.970),
            _finding(Predicate.BEACONS_TO, INFECTED, C2, 0.958),
            _finding(Predicate.BEACONS_TO, "10.0.0.2", "9.9.9.9", 0.800),
            _finding(Predicate.CONTACTS_RARE_DESTINATION, INFECTED, C2, 0.983),
            _finding(Predicate.EXFILTRATES_TO, "10.0.0.3", "1.2.3.4", 0.990),
            _finding(Predicate.TRANSFERS_ANOMALOUS_VOLUME, "10.0.0.4", "1.2.3.5", 0.975),
            _finding(Predicate.SCANS, "10.0.0.5", "445", 0.960, EntityType.PORT),
        ]

        result = _result(findings)
        assert len(result.beaconing_findings) == 3
        assert result.c2_beaconing_rank == 2

    def test_an_unlabelled_beacon_is_not_the_c2(self) -> None:
        beacon = _finding(Predicate.BEACONS_TO, "10.0.0.1", "8.8.8.8", 0.990)
        result = _result([beacon])
        assert result.c2_beaconing_confidence is None
        assert result.c2_beaconing_rank is None

    def test_no_findings_at_all_reports_nothing_rather_than_zero(self) -> None:
        result = _result([])
        assert result.c2_beaconing_confidence is None
        assert result.c2_beaconing_rank is None
        assert result.strongest_labelled_finding is None

    def test_a_unary_finding_does_not_break_pair_matching(self) -> None:
        """`matches_threat_intel` takes no object. Nothing here may assume one."""
        intel = Finding(
            predicate=Predicate.MATCHES_THREAT_INTEL,
            subject=Entity(type=EntityType.IP, value=C2),
            evidence=[
                Evidence(
                    kind="synthetic",
                    summary="synthetic evidence",
                    artifacts=[Artifact(source="ioc.txt", locator="line:1")],
                )
            ],
            confidence=0.99,
            basis="synthetic",
            analyzer="test@0.0.0",
        )
        beacon = _finding(Predicate.BEACONS_TO, INFECTED, C2, 0.958)

        result = _result([intel, beacon])
        assert result.c2_beaconing_confidence == 0.958
        assert result.strongest_labelled_finding is beacon


_HEADER = (
    "Date flow start         Durat   Prot    Src IP Addr:Port"
    "                Dst IP Addr:Port\tFlags   Tos     Packets Bytes   Flows   Label Labels\n"
)


def _row(ts: str, src: str, dst: str, size: int, label: str) -> str:
    return f"{ts}\t0.512\tTCP\t{src}\t->\t{dst}\tPA_\t0\t4\t{size}\t1\t{label}\n"


@pytest.fixture
def tiny_capture(tmp_path: Path) -> Path:
    """A labelled capture that actually produces a beaconing finding.

    120 check-ins at 60s over two hours, which clears the beaconing analyzer's
    minimum count and its one-hour minimum span. A shorter capture parses and
    scores fine and finds nothing, which would make every assertion below
    vacuously true — the failure mode engineering rule 8 exists to prevent.
    """
    rows = [
        _row(
            f"2011-08-16 {10 + minute // 60:02d}:{minute % 60:02d}:00.000",
            f"{INFECTED}:1027",
            f"{C2}:5678",
            4096,
            "Botnet",
        )
        for minute in range(120)
    ]
    # A second beaconing pair, deliberately raggeder so it scores lower. Two
    # findings tied at the same confidence would let `c2_beaconing_rank`
    # report 1 by accident rather than because the C2 leads.
    jitter = [0, 4, 9, 2, 7, 3, 8, 5]
    rows += [
        _row(
            f"2011-08-16 {10 + minute // 60:02d}:{minute % 60:02d}:"
            f"{jitter[minute % len(jitter)]:02d}.000",
            "147.32.84.59:52431",
            "93.184.216.34:443",
            8192,
            "Normal",
        )
        for minute in range(120)
    ]
    path = tmp_path / "capture20110816.pcap.netflow.labeled"
    path.write_text(_HEADER + "".join(rows))
    return path


class TestHarnessEndToEnd:
    """The scoring path over a real file, through the real parser.

    The measures above are pure functions over a findings list, which is what
    makes them testable — but it also means they can be right while the code
    calling them is not. Three analyzers run here against NetFlow, which is
    the sensor with no `resp_bytes` column, so the harness is exercised in the
    configuration the real captures use.
    """

    def test_the_c2_channel_is_found_and_reported_under_its_own_measure(
        self, tiny_capture: Path
    ) -> None:
        result = evaluate(tiny_capture, SCENARIOS["scenario06"])

        assert result.flow_count > 0
        assert result.infected_hosts == {INFECTED}
        assert result.infected_host_detected

        # Not `is not None` — a None here would pass every downstream
        # assertion by being absent rather than by being right.
        confidence = result.c2_beaconing_confidence
        assert confidence is not None and confidence > 0.0

        # More than one beacon, at distinct confidences, so rank 1 is the C2
        # leading rather than a tie resolving in its favour.
        scores = [f.confidence for f in result.beaconing_findings]
        assert len(scores) > 1 and len(set(scores)) == len(scores)
        assert result.c2_beaconing_rank == 1
        assert confidence == max(scores)

    def test_the_strongest_labelled_finding_is_reachable(self, tiny_capture: Path) -> None:
        result = evaluate(tiny_capture, SCENARIOS["scenario06"])
        strongest = result.strongest_labelled_finding
        assert strongest is not None
        assert (strongest.subject.value, strongest.object.value) in result.botnet_pairs

    def test_ground_truth_never_reaches_the_analyzers(self, tiny_capture: Path) -> None:
        """Asserted inside `evaluate`; this is the test that runs the assertion."""
        assert evaluate(tiny_capture, SCENARIOS["scenario06"]).botnet_pairs == {(INFECTED, C2)}


#: Verbatim from scenario 6: a DNS server answering the bot. Labelled `Botnet`
#: because it is the botnet's traffic — the label does not say which end is
#: the bot — and padded after the source, as short endpoints are.
_SERVER_REPLY = (
    "2011-08-16 10:02:08.871\t0.000\tUDP\t147.32.80.9:53\t\t->\t147.32.84.165:1025\tINT"
    "\t0\t1\t427\t1\tBotnet\n"
)
_DNS_SERVER = "147.32.80.9"


class TestInfectedHosts:
    """A host is infected when the authors document it and the labels agree.

    Read as "every source of a labelled flow", scenario 3 has 3,347 infected
    hosts — a DNS server among them — for a capture documented as having one
    bot. The first parser hid that by accident: padded rows lost their labels,
    and server endpoints are the short ones that get padded.
    """

    @pytest.fixture
    def capture_with_reply(self, tiny_capture: Path) -> Path:
        tiny_capture.write_text(tiny_capture.read_text() + _SERVER_REPLY)
        return tiny_capture

    def test_a_server_that_answered_the_bot_is_not_infected(
        self, capture_with_reply: Path
    ) -> None:
        result = evaluate(capture_with_reply, SCENARIOS["scenario06"])
        assert _DNS_SERVER in result.label_sources, "the reply must parse with its label"
        assert result.infected_hosts == {INFECTED}
        assert _DNS_SERVER not in result.flagged_infected_hosts

    def test_an_undocumented_capture_falls_back_to_the_labels(
        self, capture_with_reply: Path
    ) -> None:
        from voidai.eval.ctu13 import Scenario

        unknown = Scenario(key="unknown", filename="x", malware="unknown", duration_hours=0.0)
        result = evaluate(capture_with_reply, unknown)
        assert result.infected_hosts == result.label_sources
        assert {INFECTED, _DNS_SERVER} <= result.infected_hosts

    def test_a_documented_host_the_labels_never_confirm_is_not_counted(self) -> None:
        """A wrong file or a broken parse must read as "not detected", never as
        a pass on the strength of the documentation alone."""
        from voidai.eval.ctu13 import _infected

        assert _infected(SCENARIOS["scenario06"], {"10.9.9.9"}) == set()
        assert _infected(SCENARIOS["scenario06"], {INFECTED, _DNS_SERVER}) == {INFECTED}

    def test_the_report_names_only_the_bot_and_says_how_it_counted(
        self, capture_with_reply: Path
    ) -> None:
        """Through the command an operator runs. Before, the "infected host"
        row listed the DNS server beside the bot."""
        from typer.testing import CliRunner

        from voidai.cli import app

        result = CliRunner().invoke(app, ["bench", "--real", str(capture_with_reply)])
        assert result.exit_code == 0, result.output
        detected = next(ln for ln in result.output.splitlines() if "infected host" in ln)
        assert INFECTED in detected
        assert _DNS_SERVER not in detected
        # The table wraps at the runner's 80 columns; read it as prose.
        prose = " ".join(result.output.replace("│", " ").split())
        assert "1 documented infected host (2 sources carry the label)" in prose

    def test_both_scenarios_name_their_bot(self) -> None:
        """The default is empty, so an unrecognised capture is never scored
        against a host it does not contain; the known ones say so explicitly."""
        for key in ("scenario03", "scenario06"):
            assert SCENARIOS[key].documented_infected == (INFECTED,)
