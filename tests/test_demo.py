"""The demo capture, end to end.

`voidai demo` is the first thing anyone evaluating this project will run, so
it is tested like a feature rather than left as a script. The assertions below
are the claims the demo makes out loud: five real formats, several behaviours
on one host, and that host at the top of the queue.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from voidai.analyzers import DEFAULT_ANALYZERS, AnalysisContext
from voidai.correlate import build_queue
from voidai.eval.synth import build_demo_capture
from voidai.ingest import (
    load_alerts,
    load_connections,
    load_dns,
    load_passivedns,
    load_processes,
    load_ssl,
)
from voidai.ingest.inventory import load_inventory
from voidai.lexicon import Finding

PATIENT_ZERO = "10.0.1.14"
#: The same machine, as the endpoint agent names it. Sysmon records a computer
#: name and no address; the capture ships one line of asset inventory to say
#: that these are one machine, and the queue carries one row for it as a
#: result — see `docs/benchmarks.md` section 11½.
PATIENT_ZERO_HOST = "FINANCE-WS04"


@pytest.fixture(scope="module")
def capture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_demo_capture(tmp_path_factory.mktemp("demo"))


@pytest.fixture(scope="module")
def queue(capture: Path):  # type: ignore[no-untyped-def]
    # Sources chosen the way `cli._detect` chooses them: dns.log where it
    # exists, passivedns as the fallback. A fixture that read the fallback
    # while the CLI read the primary would be testing a capture the product
    # never analyses.
    ctx = AnalysisContext(
        connections=load_connections(capture),
        dns=load_dns(capture),
        alerts=load_alerts(capture),
        ssl=load_ssl(capture),
        processes=load_processes(capture),
        # The capture ships an `assets.inv`, and `_detect` reads it. A fixture
        # that skipped it would analyse a capture the product never sees.
        inventory=load_inventory(capture),
    )
    findings: list[Finding] = []
    for analyzer in DEFAULT_ANALYZERS:
        findings += analyzer().analyze(ctx)
    return build_queue(findings)


class TestDemoCapture:
    def test_writes_all_five_formats(self, capture: Path) -> None:
        names = {p.name for p in capture.iterdir()}
        assert {
            "conn.log",
            "dns.log",
            "capture.passivedns",
            "ssl.log",
            "eve.json",
            "sysmon.jsonl",
            "assets.inv",
        } <= names

    def test_the_shipped_inventory_is_one_dated_mapping(self, capture: Path) -> None:
        """One line, and dated. A partial inventory is the honest demo — the
        coverage figure it produces is under 1% and that is the point."""
        inventory = load_inventory(capture)
        assert len(inventory) == 1
        mapping = inventory.by_address[PATIENT_ZERO]
        assert mapping.hostname == PATIENT_ZERO_HOST
        assert mapping.stated is not None

    def test_every_file_parses_through_a_production_parser(self, capture: Path) -> None:
        """The demo must not bypass the parsers it is demonstrating."""
        assert load_connections(capture).height > 10_000
        assert load_dns(capture).height > 1_000
        assert load_passivedns(capture).height > 1_000
        assert load_ssl(capture).height > 100
        assert load_alerts(capture).height > 1_000
        assert load_processes(capture).height > 1_000


class TestDemoDetection:
    def test_patient_zero_ranks_first(self, queue) -> None:  # type: ignore[no-untyped-def]
        """And by its hostname, because the inventory named it.

        `ip:10.0.1.14` is no longer a subject at all: the address resolved, so
        every finding measured from it asserts the machine rather than the
        address it happened to hold.
        """
        assert queue.rank_of(PATIENT_ZERO_HOST) == 1
        assert queue.rank_of(PATIENT_ZERO) is None

    def test_every_independent_behaviour_corroborates(self, queue) -> None:  # type: ignore[no-untyped-def]
        top = queue.incidents[0]
        behaviours = {p.value for p in top.corroborating_predicates}
        assert behaviours == {
            "beacons_to",
            "scans",
            "tunnels_dns_over",
            "triggered_signature",
            "resolves_algorithmic_domain",
            "executes_rare_process",
            "exhibits_anomalous_lineage",
        }

    def test_the_rare_fingerprint_is_reported_but_does_not_corroborate(self, queue) -> None:  # type: ignore[no-untyped-def]
        """Patient zero presents a TLS client nothing else in the estate runs.

        It belongs in the incident an analyst reads, and it raises the
        combined confidence through the noisy-OR. What it may not do is
        multiply the priority: the fingerprint is a property of the same
        channel the beaconing finding already scored.
        """
        top = queue.incidents[0]
        predicates = {f.predicate.value for f in top.incident.findings}
        assert "presents_rare_tls_fingerprint" in predicates
        assert "presents_rare_tls_fingerprint" not in {
            p.value for p in top.corroborating_predicates
        }

    def test_priority_clears_the_field(self, queue) -> None:  # type: ignore[no-untyped-def]
        """Corroboration must be visible, not a hair's breadth.

        Measured against the highest-ranked incident that is not the
        compromised machine, which since the inventory landed is simply the
        second row.
        """
        top = queue.incidents[0]
        others = [
            r
            for r in queue.incidents
            if r.subject.value not in (PATIENT_ZERO, PATIENT_ZERO_HOST)
        ]
        assert top.priority > others[0].priority * 2

    def test_alert_flood_is_suppressed(self, queue) -> None:  # type: ignore[no-untyped-def]
        """55 hosts trip policy rules thousands of times and reach no incident."""
        noisy = [r for r in queue.incidents if r.subject.value != PATIENT_ZERO_HOST]
        assert all(
            "triggered_signature" not in {p.value for p in r.corroborating_predicates}
            for r in noisy
        )

    def test_the_endpoint_and_the_network_land_on_one_machine(self, queue) -> None:  # type: ignore[no-untyped-def]
        """The payoff cluster 5 was ranked for and did not collect.

        The endpoint agent sees a binary the estate has never run and an Office
        application spawning a shell. The network sensors see a beacon, a port
        sweep, a DNS tunnel, a generated domain and two rare signatures. Sysmon
        records a computer name and no address, so until one line of a file
        said they were the same machine these were two incidents that did not
        corroborate each other, ranked 2.50 and 1.50.

        Seven corroborating behaviours on one subject is that line working.
        Asserted here rather than left to the queue, so that a change which
        splits them again is a failing test rather than a quieter demo.
        """
        assert queue.rank_of(PATIENT_ZERO) is None
        top = queue.incidents[0]
        assert top.subject.value == PATIENT_ZERO_HOST
        assert len(top.corroborating_predicates) == 7

    def test_every_renamed_finding_cites_the_line_that_renamed_it(self, queue) -> None:  # type: ignore[no-untyped-def]
        """A wrong mapping attaches a beacon to an innocent machine with a
        clean chain of custody. The chain therefore carries the mapping."""
        top = queue.incidents[0]
        network = [
            f
            for f in top.incident.findings
            if f.predicate.value in {"beacons_to", "scans", "tunnels_dns_over"}
        ]
        assert network
        for finding in network:
            cited = [e for e in finding.evidence if e.kind == "asset_inventory"]
            assert len(cited) == 1, finding.sentence()
            assert cited[0].payload["address"] == PATIENT_ZERO
            assert cited[0].payload["staleness"] == "current"
            assert cited[0].artifacts[0].source.endswith("assets.inv")

    def test_a_sysmon_finding_cites_nothing_it_did_not_use(self, queue) -> None:  # type: ignore[no-untyped-def]
        """`host.py` names the machine from Sysmon's computer name and never
        resolves an address, so it must not carry the inventory's citation."""
        top = queue.incidents[0]
        host_findings = [
            f
            for f in top.incident.findings
            if f.predicate.value in {"executes_rare_process", "exhibits_anomalous_lineage"}
        ]
        assert host_findings
        assert not [e for f in host_findings for e in f.evidence if e.kind == "asset_inventory"]

    def test_the_host_estate_is_large_enough_to_be_measured(self, capture: Path) -> None:
        """The demo must demonstrate the detector, not the gate.

        `tests/data/real.sysmon.jsonl.gz` already demonstrates the gate, on
        real telemetry. A demo estate below the floor would emit nothing and
        look like a broken analyzer.
        """
        from voidai.analyzers.host import HostConfig, estate_baseline, host_summary

        baseline = estate_baseline(host_summary(load_processes(capture)))
        assert baseline.gate(HostConfig()) is None

    def test_every_finding_is_evidenced(self, queue) -> None:  # type: ignore[no-untyped-def]
        for ranked in queue.incidents:
            for finding in ranked.incident.findings:
                assert finding.evidence
                assert all(e.artifacts for e in finding.evidence)


class TestTheCommandItself:
    """The pipeline is tested above; this tests that the command runs it.

    Every assertion above reaches the analyzers directly, which is the right
    way to test detection and the wrong way to notice that `voidai demo` no
    longer starts. It did not, for the length of one commit: `demo` invokes
    `run` as a Python function, `run` is a typer command, and an argument left
    out of that call arrives as an `OptionInfo` rather than as its default —
    so adding one option to `run` broke a different command entirely, with a
    type error naming neither of them.
    """

    def test_demo_runs_end_to_end(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from voidai import cli

        result = CliRunner().invoke(cli.app, ["demo", "--keep", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert "incident(s)" in result.output

    @pytest.mark.parametrize("command", ["run", "hunt"])
    def test_the_pipeline_commands_accept_an_intel_path(
        self, command: str, capture: Path, tmp_path: Path
    ) -> None:
        """`--intel` reaches the analyzer from both commands that detect.

        They share `_detect`, and a wiring mistake in one of them is invisible
        from the other.
        """
        from typer.testing import CliRunner

        from voidai import cli

        (tmp_path / "operator.ioc").write_text(
            f"# name: demo-fixture\n# confidence: 0.9\n# updated: 2025-06-01\n{PATIENT_ZERO}\n"
        )
        args = [command, str(capture), "--intel", str(tmp_path), "--no-receipt"]
        if command == "run":
            args.append("--no-llm")
        result = CliRunner().invoke(cli.app, args)
        assert result.exit_code == 0, result.output

    @pytest.mark.parametrize("command", ["run", "hunt"])
    def test_the_pipeline_commands_accept_an_inventory_path(
        self, command: str, capture: Path, tmp_path: Path
    ) -> None:
        """`--inventory` reaches the join from both commands that detect.

        Same reasoning as `--intel` above: they share `_detect`, and a wiring
        mistake in one is invisible from the other.
        """
        from typer.testing import CliRunner

        from voidai import cli

        (tmp_path / "operator.inv").write_text(
            f"# name: demo-fixture\n# updated: 2025-06-01\n{PATIENT_ZERO}  FINANCE-WS04\n"
        )
        args = [command, str(capture), "--inventory", str(tmp_path), "--no-receipt"]
        if command == "run":
            args.append("--no-llm")
        result = CliRunner().invoke(cli.app, args)
        assert result.exit_code == 0, result.output

    def test_every_queued_incident_states_a_reason(self, capture: Path) -> None:
        """No queue row may carry a priority and a blank Behaviours cell.

        The cell was built only from corroborating predicates. Five of the
        eighteen predicates no longer corroborate, so an incident whose
        findings are all of that kind — a lone rare TLS fingerprint — rendered
        with a severity, a priority and no stated reason. An analyst cannot
        triage a row that will not say why it is there.
        """
        from voidai.analyzers import DEFAULT_ANALYZERS, AnalysisContext
        from voidai.cli import _behaviours_cell
        from voidai.correlate import build_queue
        from voidai.ingest.suricata import load_alerts
        from voidai.ingest.sysmon import load_processes
        from voidai.ingest.zeek import load_connections, load_dns, load_ssl

        ctx = AnalysisContext(
            connections=load_connections(capture),
            dns=load_dns(capture),
            alerts=load_alerts(capture),
            ssl=load_ssl(capture),
            processes=load_processes(capture),
        )
        findings = []
        for analyzer in DEFAULT_ANALYZERS:
            findings += analyzer().analyze(ctx)

        queue = build_queue(findings)
        assert queue.incidents, "the demo capture must produce incidents"
        blank = [
            r.subject.value for r in queue.incidents if not _behaviours_cell(r).strip()
        ]
        assert not blank, f"incidents listed with no reason: {blank}"

    def test_a_wholly_non_corroborating_incident_still_states_a_reason(self) -> None:
        """The specific case, built directly rather than hoped for in a corpus."""
        from voidai.cli import _behaviours_cell
        from voidai.correlate import build_queue
        from voidai.lexicon import (
            Artifact,
            Entity,
            EntityType,
            Evidence,
            Finding,
            Predicate,
        )

        finding = Finding(
            predicate=Predicate.PRESENTS_RARE_TLS_FINGERPRINT,
            subject=Entity(type=EntityType.IP, value="10.0.3.52"),
            object=Entity(type=EntityType.TLS_FINGERPRINT, value="a" * 32),
            evidence=[
                Evidence(
                    kind="ja3_rarity",
                    summary="synthetic",
                    artifacts=[Artifact(source="ssl.log", locator="line:1")],
                )
            ],
            confidence=0.83,
            basis="synthetic",
            analyzer="test@0",
        )
        ranked = build_queue([finding]).incidents[0]
        assert not ranked.corroborating_predicates, "fixture must be non-corroborating"
        assert "presents_rare_tls_fingerprint" in _behaviours_cell(ranked)

    @pytest.mark.parametrize("width", [80, 100])
    def test_the_queue_keeps_every_column(
        self, capture: Path, width: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A long Behaviours cell wraps; it does not squeeze the other columns out.

        With no column allowed to wrap, the demo's top incident drew #,
        Severity, Prio and Findings at zero width and cut its subject to
        `host:FINANC…`, at every width up to 140 columns.
        """
        import io

        from rich.console import Console
        from typer.testing import CliRunner

        from voidai import cli

        screen = Console(file=io.StringIO(), width=width, record=True)
        monkeypatch.setattr(cli, "console", screen)
        result = CliRunner().invoke(cli.app, ["run", str(capture), "--no-llm", "--no-receipt"])
        assert result.exit_code == 0, result.output

        lines = screen.export_text().splitlines()
        header = next(line for line in lines if "Behaviours" in line)
        for column in ("#", "Severity", "Prio", "Subject", "Findings"):
            assert f" {column} " in header, header
        top = next(line for line in lines if line.startswith("│ 1 │"))
        assert f"host:{PATIENT_ZERO_HOST} " in top, top


class TestDoctorTellsTheTruth:
    """A diagnostic that disagrees with the command it diagnoses is worse
    than no diagnostic — the operator acts on it and is wrong.
    """

    def test_doctor_reports_the_inventory_run_will_actually_apply(
        self, capture: Path
    ) -> None:
        """`_detect` auto-discovers `.inv` beside the telemetry; doctor must too.

        Before this, `doctor --telemetry <dir>` printed "none given" for a
        directory whose inventory `run` was about to load and apply.
        """
        from typer.testing import CliRunner

        from voidai import cli

        assert list(capture.glob("*.inv")), "fixture must ship an inventory"
        doctor = CliRunner().invoke(cli.app, ["doctor", "--telemetry", str(capture)])
        assert doctor.exit_code == 0, doctor.output
        assert "none given" not in _inventory_line(doctor.output)
        assert "mapping(s) applied" in _inventory_line(doctor.output)

    def test_doctor_without_a_telemetry_path_still_says_none_given(self) -> None:
        """The fallback must not invent an inventory that was never named."""
        from typer.testing import CliRunner

        from voidai import cli

        out = CliRunner().invoke(cli.app, ["doctor"]).output
        assert "none given" in _inventory_line(out)

    def test_a_rejected_line_cannot_carry_control_characters_to_the_terminal(
        self, capture: Path, tmp_path: Path
    ) -> None:
        """Rejected lines are printed as written, so an operator can fix them.

        That makes this the one display fed directly from a file someone was
        told to check *because* it looked wrong. An ANSI escape can blank the
        screen or hide which line was actually rejected.
        """
        from typer.testing import CliRunner

        from voidai import cli

        for name in ("conn.log", "sysmon.jsonl"):
            source = capture / name
            if source.exists():
                (tmp_path / name).write_bytes(source.read_bytes())
        (tmp_path / "evil.inv").write_text(
            "# name: probe\n\x1b[2J\x1b[31mHIJACKED\x1b[0m not-an-address\n\x00\x07\n"
        )

        out = CliRunner().invoke(cli.app, ["doctor", "--telemetry", str(tmp_path)]).output
        assert "\x1b[2J" not in out, "an escape sequence reached the terminal"
        assert "\x00" not in out, "a NUL reached the terminal"
        assert "\x07" not in out, "a bell reached the terminal"
        assert "rejected" in out, "the rejection must still be reported"

    def test_the_sanitiser_keeps_the_text_an_operator_needs(self) -> None:
        """Stripping must remove the weapon, not the message.

        A row that reports "1 line rejected" and shows nothing of the line is
        as useless as no row at all — the operator still cannot find it. Tested
        on the function rather than through the CLI, because at an 80-column
        terminal the table truncates the line for reasons that have nothing to
        do with sanitising it.
        """
        from voidai.cli import _safe

        cleaned = _safe("\x1b[2J\x1b[31mHIJACKED\x1b[0m 10.0.0.1\x00\x07")
        assert "HIJACKED" in cleaned
        assert "10.0.0.1" in cleaned
        for bad in ("\x1b", "\x00", "\x07"):
            assert bad not in cleaned

    def test_the_sanitiser_also_neutralises_markup(self) -> None:
        """Control characters are the new half; markup was already handled."""
        from voidai.cli import _safe

        assert "[/dim]" not in _safe("x[/dim]y") or "\\" in _safe("x[/dim]y")

    def test_why_there_is_no_narrative_reaches_the_operator_verbatim(
        self, capture: Path, tmp_path: Path
    ) -> None:
        """Both reasons the backend can give carry brackets, and both are
        actionable only if exact: the install hint names the `.[llm]` extra,
        and the 'not found' message names the `--model` path to compare
        against what was meant. Rendered as markup, `[llm]` is consumed as a
        tag — leaving `pip install -e '.'`, which installs nothing missing —
        and the path displayed is not the path passed.

        Asserted against whichever reason this environment actually produces,
        so the test cannot pass by never reaching the branch.
        """
        from typer.testing import CliRunner

        from voidai import cli
        from voidai.reason.backend import default_backend

        typed = str(tmp_path / "[bold red]weights[/].gguf")
        reason = default_backend(typed).reason
        assert "[" in reason, "neither reason carries markup; this test has gone stale"

        out = CliRunner().invoke(cli.app, ["run", str(capture), "--model", typed]).output
        collapsed = " ".join(out.split())
        assert " ".join(reason.split()) in collapsed, (
            f"the renderer altered the reason before the operator saw it: {reason!r}"
        )


def _inventory_line(output: str) -> str:
    return next((ln for ln in output.splitlines() if "inventory" in ln.lower()), "")
