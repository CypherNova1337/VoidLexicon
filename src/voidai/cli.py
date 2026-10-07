"""Command-line interface.

The operator surface is deliberately small and deliberately textual. A SOC
analyst at 3am wants a ranked list and a way to pull the evidence behind any
line of it, not a dashboard.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import polars as pl
import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from voidai import __version__
from voidai.analyzers import DEFAULT_ANALYZERS, AnalysisContext, HostConfig, TlsDgaConfig
from voidai.analyzers.host import estate_baseline, host_summary
from voidai.correlate import IncidentQueue, build_queue
from voidai.hunt import Dialect, queries_for_incident
from voidai.ingest.inventory import (
    INVENTORY_SUFFIX,
    CaptureWindow,
    Coverage,
    Inventory,
    load_inventory,
)
from voidai.ingest.ioc import IOC_SUFFIX, load_indicators
from voidai.ingest.passivedns import load_passivedns
from voidai.ingest.suricata import load_alerts
from voidai.ingest.sysmon import load_processes
from voidai.ingest.zeek import load_connections, load_dns, load_ssl
from voidai.lexicon import GRAMMAR, EntityType, Finding, Severity
from voidai.reason import Reasoner, ReasoningConfig, ReasoningResult, default_backend
from voidai.telemetry import EnergyMeter, RunReceipt, detect_platform

if TYPE_CHECKING:  # the benchmark harness is imported lazily, at use
    from voidai.eval.benchmark import DetectionScore

app = typer.Typer(
    name="voidai",
    help="Local-first, evidence-bound agent runtime for cyber defence.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _safe(text: str) -> str:
    """Prepare a string that came out of a file for terminal display.

    `escape()` alone is not enough. It neutralises rich's markup, which is why
    the evidence chain uses it, but it passes control characters through
    untouched — and the rows that report a *rejected* line print that line as
    written, so an operator can fix it. Whatever was in the file therefore
    reaches the terminal, and a NUL, a backspace or an ANSI escape sequence can
    blank the screen, hide text, or misrepresent which line was rejected.

    Third occurrence of one pattern. The evidence chain escapes markup because
    a log-derived component list was being swallowed by the parser;
    `hunt.queries` strips non-printables before interpolating an indicator into
    a query someone will paste into a console. This is the same rule for the
    same reason, applied to the diagnostic that reads the most hostile input in
    the tool: a file the operator was told to check *because* it looked wrong.
    """
    return escape("".join(character for character in text if character.isprintable()))


def _severity_text(severity: Severity | None) -> Text:
    severity = severity or Severity.INFO
    return Text(severity.value.upper(), style=_SEVERITY_STYLE[severity])


def _render_findings(findings: list[Finding]) -> None:
    if not findings:
        console.print("\n[green]No findings.[/green] Nothing in this telemetry met threshold.\n")
        return

    table = Table(title=f"{len(findings)} finding(s)", title_justify="left", expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Conf", justify="right", no_wrap=True)
    table.add_column("Proposition")
    table.add_column("ATT&CK", no_wrap=True)

    for finding in findings:
        table.add_row(
            _severity_text(finding.severity),
            f"{finding.confidence:.2f}",
            escape(finding.sentence()),
            escape(", ".join(finding.attack_techniques)) or "—",
        )
    console.print()
    console.print(table)


def _render_evidence(findings: list[Finding]) -> None:
    """Print the chain of custody for each finding.

    Every dynamic string here is escaped. Evidence text is derived from log
    data, and log data contains brackets — an attacker-controlled User-Agent
    or a component list like [regularity=1.00] would otherwise be swallowed by
    the console's markup parser. Silently mangled evidence is worse than no
    evidence, and this is the one display where that is least acceptable.
    """
    console.print("\n[bold]Evidence chain[/bold]")
    for finding in findings:
        console.print(f"\n  [bold]{finding.id}[/bold]  {escape(finding.sentence())}")
        console.print(f"  [dim]basis:[/dim] {escape(finding.basis)}")
        for evidence in finding.evidence:
            console.print(f"    [cyan]{evidence.id}[/cyan]  {escape(evidence.summary)}")
            for artifact in evidence.artifacts[:3]:
                location = escape(f"{artifact.source}:{artifact.locator}")
                console.print(f"      [dim]{location}[/dim]")
            if len(evidence.artifacts) > 3:
                console.print(f"      [dim]… and {len(evidence.artifacts) - 3} more[/dim]")


def _behaviours_cell(ranked: object) -> str:
    """The Behaviours column: what this host did, and which of it corroborates.

    Corroborating predicates are highlighted when there is more than one,
    because that conjunction is what moves an incident up the queue. The rest
    are listed dimmed rather than dropped.

    Dropping them was a real defect. Five of eighteen predicates are now
    non-corroborating, and an incident whose findings are *all* of that kind —
    a lone rare TLS fingerprint, say — rendered with a priority, a severity and
    a blank reason. A queue row that cannot say why it is there is the one
    thing this tool must never print.
    """
    corroborating = tuple(ranked.corroborating_predicates)  # type: ignore[attr-defined]
    present = {f.predicate for f in ranked.incident.findings}  # type: ignore[attr-defined]
    supporting = sorted(p.value for p in present - set(corroborating))

    lead = ", ".join(p.value for p in corroborating)
    if len(corroborating) > 1:
        lead = f"[bold yellow]{escape(lead)}[/bold yellow]"
    elif lead:
        lead = escape(lead)

    if not supporting:
        return lead
    trailing = f"[dim]{escape(', '.join(supporting))}[/dim]"
    return f"{lead}, {trailing}" if lead else trailing


def _render_queue(queue: IncidentQueue, limit: int = 20) -> None:
    """Print the analyst-facing queue, highest priority first.

    Incidents rather than findings, because a host is the unit a responder
    works in, and because ranking by corroboration is what separates a
    compromised machine from a merely periodic one.
    """
    if not len(queue):
        console.print("\n[green]No incidents.[/green] Nothing met threshold.\n")
        return

    table = Table(
        title=f"{len(queue)} incident(s) · {len(queue.corroborated)} corroborated",
        title_justify="left",
        expand=True,
    )
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Prio", justify="right", no_wrap=True)
    table.add_column("Subject", no_wrap=True)
    table.add_column("Behaviours", no_wrap=True)
    table.add_column("Findings", justify="right", no_wrap=True)

    for position, ranked in enumerate(queue.top(limit), start=1):
        table.add_row(
            str(position),
            _severity_text(ranked.incident.severity),
            f"{ranked.priority:.2f}",
            escape(str(ranked.subject)),
            _behaviours_cell(ranked),
            str(len(ranked.incident.findings)),
        )

    console.print()
    console.print(table)
    if len(queue) > limit:
        console.print(f"[dim]… {len(queue) - limit} lower-priority incidents not shown[/dim]")

    corroborated = queue.corroborated
    if corroborated:
        console.print("\n[bold]Corroborated — more than one independent behaviour[/bold]")
        for ranked in corroborated[:5]:
            console.print(f"\n  [bold]{escape(str(ranked.subject))}[/bold]")
            console.print(f"  [dim]{escape(ranked.rationale)}[/dim]")
            for finding in ranked.incident.findings[:4]:
                console.print(
                    f"    {finding.confidence:.2f}  {escape(finding.sentence())}"
                )


def _render_reasoning(results: list[ReasoningResult]) -> None:
    """Print the language layer's output, with struck claims shown as struck.

    Struck claims are displayed rather than hidden. An analyst evaluating
    whether to trust this tool needs to see what it refused to say, and a
    silent filter would deny them that.
    """
    for result in results:
        console.print(f"\n[bold]{escape(result.incident.title)}[/bold]")

        if result.report.narrative:
            console.print(f"  {escape(result.report.narrative)}")
        elif result.report.narrative_struck:
            console.print(
                "  [red]narrative struck[/red] [dim]— named an entity the evidence "
                "does not contain[/dim]"
            )

        for claim in result.report.verified:
            console.print(f"  [green]✓[/green] {escape(claim.text)}")
            console.print(f"      [dim]cites {', '.join(claim.cites)}[/dim]")
        for claim in result.report.struck:
            console.print(f"  [red]✗[/red] [strike]{escape(claim.text)}[/strike]")
            console.print(f"      [red dim]struck: {escape(claim.rejection_reason or '')}[/red dim]")

        if result.report.actions:
            console.print("  [dim]suggested next steps:[/dim]")
            for action in result.report.actions:
                console.print(f"    → {escape(action)}")


def _render_receipt(receipt: RunReceipt) -> None:
    energy = receipt.energy
    table = Table(title="Run receipt", title_justify="left", show_header=False, expand=False)
    table.add_column(style="dim")
    table.add_column()

    if energy:
        marker = "measured" if energy.is_measured else "estimated"
        style = "green" if energy.is_measured else "yellow"
        table.add_row(
            "energy",
            f"[{style}]{receipt.total_joules:.2f} J[/{style}] "
            f"total, [{style}]{marker}[/{style}]",
        )
        table.add_row("method", escape(energy.method))
        table.add_row(
            "detection", f"{energy.wall_seconds:.2f} s wall / {energy.cpu_seconds:.2f} s cpu"
        )
        if receipt.reasoning:
            table.add_row(
                "reasoning",
                f"{receipt.reasoning.wall_seconds:.2f} s wall · "
                f"{receipt.reasoning.joules:.0f} J ({receipt.tokens.total} tokens)",
            )

    if receipt.inventory is not None:
        # Coverage, not a mapping count: an inventory
        # covering 3% of an estate is a rounding error dressed as an
        # improvement, and the count on its own cannot say which this is.
        table.add_row("inventory", escape(receipt.inventory.summary()))

    table.add_row("memory", f"{receipt.peak_rss_mb:.0f} MB peak")
    table.add_row(
        "tokens",
        f"{receipt.tokens.total} ({receipt.tokens.model or 'no model used'})"
        + (f", {receipt.claims_struck} claim(s) struck" if receipt.claims_struck else ""),
    )
    table.add_row(
        "work",
        f"{receipt.records_ingested:,} records → {receipt.findings_emitted} findings "
        f"({receipt.records_per_second:,.0f} rec/s)",
    )
    table.add_row("host", f"{receipt.host} · {receipt.machine} · {receipt.cores} cores")
    console.print()
    console.print(table)


def _observed_addresses(ctx: AnalysisContext) -> set[str]:
    """Every distinct source address the capture contains.

    The denominator for inventory coverage, and it is the source side only
    because that is the side `actor()` is ever asked to name. Counting
    destinations too would divide by the internet and report a coverage of
    nought point nothing for a complete inventory.

    One streaming pass per source, taken only when an inventory is loaded.
    """
    addresses: set[str] = set()
    for scan in (ctx.connection_scan(), ctx.dns_scan(), ctx.alert_scan(), ctx.ssl_scan()):
        column = scan.select(pl.col("src_ip").unique()).collect(engine="streaming")
        if column.height:
            addresses.update(str(value) for value in column.to_series() if value)
    return addresses


def _inventory_coverage(ctx: AnalysisContext) -> Coverage | None:
    """What the loaded inventory reached, or `None` if none was loaded."""
    if ctx.inventory.is_empty():
        return None
    return ctx.inventory.coverage(ctx.capture, _observed_addresses(ctx))


def _detect(
    path: Path,
    intel: Path | None = None,
    inventory: Path | None = None,
) -> tuple[AnalysisContext, list[Finding], IncidentQueue]:
    """Ingest, analyse and rank. The whole model-free pipeline, in one place.

    Shared by `run` and `hunt` so the two cannot drift into analysing the same
    directory differently.
    """
    connections = load_connections(path)
    # Zeek dns.log if present, else passivedns from a Stratosphere-style
    # capture. Either yields real query names; neither is required.
    dns = load_dns(path)
    if dns.is_empty():
        dns = load_passivedns(path)
    alerts = load_alerts(path)
    # TLS sessions, for the fingerprint half of the tlsdga analyzer. Usually
    # empty, and empty in two different ways — no ssl.log, or an ssl.log
    # written without the JA3 package. `voidai doctor --telemetry` tells them
    # apart; the analyzer is silent for either.
    ssl = load_ssl(path)
    # Windows process creations, as JSON lines. Empty for every network-only
    # capture, which is all of them in this project's corpora — and empty here
    # means the two host predicates are silent rather than degraded.
    processes = load_processes(path)
    # Indicators are read from files and never retrieved. Absent by default:
    # `*.ioc` alongside the telemetry, or wherever `--intel` points.
    indicators = load_indicators(intel or path)
    # Asset mappings, on the same terms: `*.inv` alongside the telemetry or
    # wherever `--inventory` points, read and never derived. Applying it is
    # `AnalysisContext`'s job rather than this function's, so that `voidai
    # bench` — which builds its own context and never calls `_detect` — joins
    # identically and produces the same content-addressed IDs.
    assets = load_inventory(inventory or path)
    ctx = AnalysisContext(
        connections=connections,
        dns=dns,
        alerts=alerts,
        ssl=ssl,
        processes=processes,
        indicators=indicators,
        inventory=assets,
    )

    # Driven from DEFAULT_ANALYZERS so `voidai doctor` cannot report a set
    # that differs from the one actually run, and so adding an analyzer is a
    # one-line change in one place.
    findings: list[Finding] = []
    for analyzer in DEFAULT_ANALYZERS:
        findings += analyzer().analyze(ctx)

    return ctx, findings, build_queue(findings)


@app.command()
def run(
    path: Path = typer.Argument(..., help="Directory of Zeek logs to analyse."),
    no_llm: bool = typer.Option(
        False, "--no-llm", help="Skip the language layer. Detection is unaffected."
    ),
    evidence: bool = typer.Option(
        False, "--evidence", help="Print the full evidence chain for every finding."
    ),
    receipt: bool = typer.Option(True, "--receipt/--no-receipt", help="Print the run receipt."),
    model: Path | None = typer.Option(
        None, "--model", help="GGUF model for the narrative layer. Detection runs without it."
    ),
    explain: int = typer.Option(
        3, "--explain", help="Incidents to narrate, highest priority first."
    ),
    intel: Path | None = typer.Option(
        None,
        "--intel",
        help=f"Directory or file of local {IOC_SUFFIX} indicators. Read, never fetched.",
    ),
    inventory: Path | None = typer.Option(
        None,
        "--inventory",
        help=f"Directory or file of {INVENTORY_SUFFIX} asset mappings. Read, never derived.",
    ),
) -> None:
    """Run the detection pipeline over a directory of telemetry."""
    if not path.exists():
        console.print(f"[red]No such path:[/red] {path}")
        raise typer.Exit(code=2)

    run_receipt = RunReceipt()

    with EnergyMeter() as meter:
        ctx, findings, queue = _detect(path, intel, inventory)

    run_receipt.records_ingested = ctx.record_count()
    run_receipt.findings_emitted = len(findings)
    run_receipt.inventory = _inventory_coverage(ctx)
    run_receipt.finalize(meter.reading)

    if run_receipt.records_ingested == 0:
        console.print(f"[yellow]No parseable telemetry found under[/yellow] {path}")
        raise typer.Exit(code=1)

    _render_queue(queue)
    if evidence:
        _render_evidence(findings)

    if no_llm:
        console.print(
            "\n[dim]--no-llm: detection only. The findings above are complete; "
            "only the narrative is absent.[/dim]"
        )
    else:
        reasoner = Reasoner(
            backend=default_backend(model),
            config=ReasoningConfig(max_incidents=explain),
        )
        if not reasoner.available():
            # The reason carries the `--model` path the operator typed, and
            # `.[llm]` in the install hint. Both are eaten as markup unescaped:
            # the hint becomes a command that does not install anything, and a
            # "not found" message names a path that is not the one passed.
            console.print(
                f"\n[dim]No narrative: {_safe(reasoner.backend.reason)}. "
                "Detection is unaffected.[/dim]"
            )
        else:
            with EnergyMeter() as reasoning_meter:
                results = reasoner.explain_queue(queue.incidents, run_receipt.tokens)
            run_receipt.claims_struck = sum(r.strike_count for r in results)
            run_receipt.reasoning = reasoning_meter.reading
            console.print("\n[bold]Analysis[/bold]")
            _render_reasoning(results)

    if receipt:
        _render_receipt(run_receipt)



def _accuracy_table(title: str, detection: DetectionScore) -> Table:
    """Render one corpus's score.

    Misses and false alarms are printed by name rather than counted. A
    benchmark that reports "1 FP" and stops has told the reader the least
    useful half of the result; which decoy it fell for is the half that says
    what to fix.
    """
    table = Table(title=title, title_justify="left", show_header=False)
    table.add_column(style="dim")
    table.add_column()
    table.add_row("precision", f"{detection.precision:.3f}")
    table.add_row("recall", f"{detection.recall:.3f}")
    table.add_row("f1", f"{detection.f1:.3f}")
    table.add_row(
        "confusion",
        f"{detection.true_positives} TP · {detection.false_positives} FP "
        f"· {detection.false_negatives} FN",
    )
    if detection.missed_labels:
        table.add_row("missed", escape(", ".join(detection.missed_labels)))
    if detection.false_positive_pairs:
        table.add_row("false alarms", escape(", ".join(detection.false_positive_pairs[:5])))
    return table


def _bench_real(path: Path, limit: int) -> None:
    """Score against a labelled real capture — currently the CTU-13 dialect.

    Reported separately from the synthetic benchmark and never averaged with
    it. See docs/benchmarks.md for why pair precision reads near zero here and
    what it does and does not mean.
    """
    from voidai.analyzers.beaconing import BeaconingConfig
    from voidai.eval.ctu13 import SCENARIOS, Scenario, evaluate

    scenario = next(
        (s for key, s in SCENARIOS.items() if key in path.name or s.filename == path.name),
        Scenario(key="unknown", filename=path.name, malware="unknown", duration_hours=0.0),
    )

    console.print(f"[dim]Scoring {path.name} ({scenario.malware})…[/dim]")
    result = evaluate(path, scenario, config=BeaconingConfig(max_findings=limit))

    detected = result.true_positive_pairs

    table = Table(title="Real capture", title_justify="left", show_header=False)
    table.add_column(style="dim")
    table.add_column()
    table.add_row("capture", f"{escape(path.name)} · {scenario.malware}")
    table.add_row("volume", f"{result.flow_count:,} flows over {result.span_hours:.2f}h")
    table.add_row(
        "infected host",
        (
            f"[green]detected[/green] — {', '.join(sorted(result.flagged_infected_hosts))}"
            if result.infected_host_detected
            else "[red]not detected[/red]"
        ),
    )
    # Named after the beaconing channel, so computed from beaconing findings
    # alone — see `RealCaptureResult.c2_beaconing_confidence` for what
    # selecting across every predicate reported instead.
    c2 = result.c2_beaconing_confidence
    if c2 is not None:
        table.add_row(
            "c2 confidence",
            f"{c2:.3f} (beaconing rank {result.c2_beaconing_rank} "
            f"of {len(result.beaconing_findings)})",
        )
    strongest = result.strongest_labelled_finding
    if strongest is not None and strongest.confidence != c2:
        table.add_row(
            "strongest on a labelled pair",
            f"{strongest.confidence:.3f} · {escape(strongest.predicate.value)}",
        )
    rank = result.best_infected_rank
    table.add_row(
        "queue position",
        (
            f"[green]rank {rank} of {len(result.queue)}[/green]"
            if rank is not None and rank <= 5
            else f"rank {rank} of {len(result.queue)}"
            if rank is not None
            else "[red]absent from queue[/red]"
        ),
    )
    table.add_row(
        "alert burden",
        f"{len(result.findings)} findings → {len(result.queue)} incidents, "
        f"{len(result.queue.corroborated)} corroborated",
    )
    table.add_row("pair precision", f"{result.pair_precision:.4f} ({len(detected)} on labelled pairs)")
    table.add_row(
        "ground truth",
        f"{len(result.botnet_pairs):,} botnet pairs · {len(result.infected_hosts)} infected hosts",
    )
    console.print()
    console.print(table)
    console.print(
        "\n[dim]'Background' in CTU-13 means unlabelled, not benign, so pair precision is a "
        "lower bound rather than an estimate. See docs/benchmarks.md.[/dim]"
    )
    _render_queue(result.queue, limit=10)
    _render_receipt(result.receipt)


@app.command()
def bench(
    seed: int = typer.Option(1337, help="Corpus seed. Same seed, same corpus, forever."),
    hours: float = typer.Option(24.0, help="Hours of synthetic telemetry to generate."),
    real: Path | None = typer.Option(
        None, "--real", help="Score against a labelled real capture instead (CTU-13 format)."
    ),
    limit: int = typer.Option(100_000, help="Cap on findings emitted, highest-scoring first."),
) -> None:
    """Score the analyzers against a labelled corpus, and meter the run."""
    from voidai.eval.benchmark import (
        run_benchmark,
        run_dga_benchmark,
        run_egress_benchmark,
        run_host_benchmark,
        run_tls_benchmark,
    )

    if real is not None:
        if not real.is_file():
            console.print(f"[red]No such capture:[/red] {real}")
            raise typer.Exit(code=2)
        _bench_real(real, limit)
        return

    console.print(f"[dim]Generating {hours:g}h corpus (seed {seed})…[/dim]")
    result = run_benchmark(seed=seed, hours=hours)

    console.print()
    console.print(_accuracy_table("Detection accuracy — beaconing", result.detection))
    _render_findings(result.findings)
    _render_receipt(result.receipt)

    # A second corpus with its own decoys and its own ground truth. Scored and
    # printed separately rather than merged: one number covering two analyzers
    # measuring different behaviours would describe neither.
    console.print(f"\n[dim]Generating {hours:g}h transfer corpus (seed {seed})…[/dim]")
    egress = run_egress_benchmark(seed=seed, hours=hours)

    console.print()
    console.print(_accuracy_table("Detection accuracy — volume and egress", egress.detection))
    _render_findings(egress.findings)
    _render_receipt(egress.receipt)

    # A third and fourth corpus, for the two halves of the tlsdga analyzer.
    # They are printed separately from each other as well as from the two
    # above: DGA specificity has a real corpus behind it and TLS fingerprint
    # rarity has none, so one merged figure could not be honestly labelled.
    console.print(f"\n[dim]Generating {hours:g}h domain-generation corpus (seed {seed})…[/dim]")
    dga = run_dga_benchmark(seed=seed, hours=hours)
    console.print()
    console.print(_accuracy_table("Detection accuracy — domain generation", dga.detection))
    _render_findings(dga.findings)
    console.print(
        "[dim]Scored per family, not per domain. Recall is 3 of 4 because a "
        "dictionary-concatenation family is planted and is a known miss — see "
        "analyzers/ngrams.py. Specificity against real traffic is measured "
        "separately, on tests/data/real.passivedns.[/dim]"
    )
    _render_receipt(dga.receipt)

    console.print(f"\n[dim]Generating TLS fingerprint corpus (seed {seed})…[/dim]")
    tls = run_tls_benchmark(seed=seed)
    console.print()
    console.print(_accuracy_table("Detection accuracy — TLS fingerprints", tls.detection))
    _render_findings(tls.findings)
    console.print(
        "[dim]Synthetic on both sides: no openly-licensed ssl.log corpus carrying "
        "JA3 was reachable, so this measures the arithmetic and not the detector.[/dim]"
    )
    _render_receipt(tls.receipt)

    # A fifth corpus, and the one whose accuracy figure means the least on its
    # own. The host analyzer's real result is a *refusal* — on the only
    # openly-licensed corpus available it declines to score at all, because
    # four hosts is not an estate. See `docs/benchmarks.md` section 11 and
    # `tests/test_host.py::TestTheGate`.
    console.print(f"\n[dim]Generating {hours:g}h host telemetry corpus (seed {seed})…[/dim]")
    host = run_host_benchmark(seed=seed, hours=hours)
    console.print()
    console.print(_accuracy_table("Detection accuracy — host and endpoint", host.detection))
    _render_findings(host.findings)
    console.print(
        "[dim]Synthetic sensitivity, and the one false positive is planted: a "
        "legitimate installer in a user's Downloads folder, run once. It is "
        "indistinguishable from a dropped payload by everything measured here, "
        "so it is counted rather than tuned away. Real telemetry contributes a "
        "gate result and no detection rate — the largest openly-licensed corpus "
        "is four hosts, and the analyzer correctly declines to score it.[/dim]"
    )
    _render_receipt(host.receipt)


_HUNT_SUFFIX = {
    Dialect.SIGMA: "yml",
    Dialect.KQL: "kql",
    Dialect.SPL: "spl",
    Dialect.ZEEK: "sh",
}


@app.command()
def hunt(
    path: Path = typer.Argument(..., help="Directory of telemetry to analyse."),
    dialect: Dialect = typer.Option(
        Dialect.SIGMA, "--dialect", "-d", help="Query language to emit."
    ),
    top: int = typer.Option(3, "--top", help="Incidents to generate hunts for, highest first."),
    out: Path | None = typer.Option(
        None, "--out", help="Write each query to a file in this directory instead of stdout."
    ),
    receipt: bool = typer.Option(True, "--receipt/--no-receipt", help="Print the run receipt."),
    intel: Path | None = typer.Option(
        None,
        "--intel",
        help=f"Directory or file of local {IOC_SUFFIX} indicators. Read, never fetched.",
    ),
    inventory: Path | None = typer.Option(
        None,
        "--inventory",
        help=f"Directory or file of {INVENTORY_SUFFIX} asset mappings. Read, never derived.",
    ),
) -> None:
    """Turn ranked incidents into queries you can run in a SIEM.

    VoidLexicon sees one sensor's window; the SIEM holds the estate's history. So
    the generated queries do not re-find the traffic that produced a finding —
    you already have that. They pivot on the *indicator* and exclude the host
    already known, which makes every row they return new information.

    No model is involved. A typed proposition already carries the predicate,
    the entity types and the measured values, so the transformation is
    templating rather than interpretation.
    """
    if not path.exists():
        console.print(f"[red]No such path:[/red] {path}")
        raise typer.Exit(code=2)

    run_receipt = RunReceipt()
    with EnergyMeter() as meter:
        ctx, findings, queue = _detect(path, intel, inventory)
    run_receipt.records_ingested = ctx.record_count()
    run_receipt.findings_emitted = len(findings)
    run_receipt.inventory = _inventory_coverage(ctx)
    run_receipt.finalize(meter.reading)

    if run_receipt.records_ingested == 0:
        console.print(f"[yellow]No parseable telemetry found under[/yellow] {path}")
        raise typer.Exit(code=1)

    if out is not None:
        out.mkdir(parents=True, exist_ok=True)

    written = 0
    for ranked in queue.incidents[:top]:
        queries = queries_for_incident(ranked.incident, dialects=(dialect,))
        if not queries:
            continue

        console.print(
            f"\n[bold]{escape(str(ranked.subject))}[/bold] "
            f"[dim]priority {ranked.priority:.2f} · {len(queries)} "
            f"{'hunt' if len(queries) == 1 else 'hunts'}[/dim]"
        )
        for query in queries:
            console.print(f"\n[cyan]{escape(query.title)}[/cyan]")
            console.print(f"[dim]{escape(query.rationale)}[/dim]")
            if out is None:
                # Verbatim, or not at all. markup=False because the query is
                # built from log-derived values; soft_wrap=True because
                # wrapping a YAML rule at terminal width breaks its
                # indentation, and a hunt an analyst cannot paste is worse
                # than no hunt — it looks correct and does not run.
                console.print()
                console.print(query.query, markup=False, highlight=False, soft_wrap=True)
            else:
                target = out / f"{query.finding_id}.{_HUNT_SUFFIX[dialect]}"
                target.write_text(query.query + "\n", encoding="utf-8")
                console.print(f"[dim]→ {escape(str(target))}[/dim]")
                written += 1

    if written:
        console.print(f"\n[green]{written}[/green] queries written to {escape(str(out))}")
    elif not any(queries_for_incident(r.incident) for r in queue.incidents[:top]):
        console.print(
            "\n[yellow]No hunts generated.[/yellow] The top-ranked incidents carry no "
            "pivotable indicator — nothing a SIEM has a field for.\n"
        )

    console.print(
        "\n[dim]These are hypotheses to run, not verdicts. Every query names the "
        "finding it came from.[/dim]"
    )

    if receipt:
        _render_receipt(run_receipt)


@app.command()
def lexicon() -> None:
    """Print the complete grammar: everything VoidLexicon is able to say."""
    # Not expanded: on a narrow terminal `expand` steals width from the
    # fixed columns to feed the description and collapses the predicate name
    # to nothing. Sizing to content and letting the description wrap keeps
    # the table readable at any width.
    table = Table(title="The Lexicon", title_justify="left")
    table.add_column("Predicate", no_wrap=True, style="bold")
    table.add_column("Subject", no_wrap=True)
    table.add_column("Object", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Meaning", min_width=30)

    def render_types(types: frozenset[EntityType] | None) -> str:
        """Collapse a universal type set to 'any' rather than listing all ten.

        Without this, the one relational predicate that accepts every entity
        type forces both type columns wide enough to squeeze everything else
        off the terminal.
        """
        if types is None:
            return "—"
        if set(types) == set(EntityType):
            return "any"
        return "|".join(sorted(t.value for t in types))

    for predicate, spec in GRAMMAR.items():
        table.add_row(
            predicate.value,
            render_types(spec.subject_types),
            "—" if spec.is_unary() else render_types(spec.object_types),
            _severity_text(spec.default_severity),
            escape(spec.description),
        )

    console.print()
    console.print(table)
    console.print(
        f"\n[dim]{len(GRAMMAR)} predicates. An assertion outside this set has no "
        "representation and cannot reach an analyst.[/dim]\n"
    )


@app.command()
def demo(
    keep: Path | None = typer.Option(
        None, "--keep", help="Write the generated capture here instead of a temp directory."
    ),
    model: Path | None = typer.Option(
        None, "--model", help="GGUF model for the narrative layer."
    ),
    explain: int = typer.Option(2, "--explain", help="Incidents to narrate."),
) -> None:
    """Generate a complete capture and run the full pipeline over it.

    Real files in real sensor formats — Zeek conn, dns and ssl logs,
    passivedns, Suricata EVE, Sysmon process events and an asset inventory —
    so the production parsers are exercised rather than bypassed. One machine
    beacons, sweeps a port, tunnels over DNS, resolves generated domains, runs
    a TLS client and a binary nothing else runs, and launches shells from an
    unusual parent, each hidden in benign traffic of its kind. Nothing in the
    data marks it out.
    """
    import tempfile

    from voidai.eval.synth import build_demo_capture

    directory = Path(keep) if keep else Path(tempfile.mkdtemp(prefix="voidai-demo-"))
    console.print(f"[dim]Generating capture in {escape(str(directory))}…[/dim]")
    build_demo_capture(directory)

    for name in sorted(p.name for p in directory.iterdir()):
        size = (directory / name).stat().st_size / 1024
        console.print(f"  [dim]{escape(name):26s} {size:8.0f} KB[/dim]")

    console.print(
        "\n[dim]One host in this capture beacons, sweeps a port, tunnels DNS and "
        "trips two rare signatures. Nothing labels it.[/dim]"
    )
    # Every parameter of `run` is passed explicitly, including the ones this
    # command has no opinion about. `run` is a typer command, so an argument
    # left out here arrives as an `OptionInfo` rather than as its default, and
    # fails somewhere further down with a type error that names neither
    # command. `tests/test_demo.py` invokes this through the CLI so the next
    # option added to `run` is caught here rather than by a user.
    run(
        path=directory,
        no_llm=model is None,
        evidence=False,
        receipt=True,
        model=model,
        explain=explain,
        intel=None,
        inventory=None,
    )


def _inventory_row(table: Table, inventory: Path | None, telemetry: Path | None) -> None:
    """Report what an inventory path actually loaded, and how far it reaches.

    Two numbers, because either alone misleads. A mapping count says nothing
    about whether the estate in front of you is covered, and a coverage
    percentage says nothing about how many statements were thrown away for
    being too old to trust. Either number alone misleads, so both are shown.
    """
    if inventory is None:
        table.add_row(
            "inventory",
            f"[dim]none given — pass --inventory to check {INVENTORY_SUFFIX} files[/dim]",
        )
        return

    if not inventory.exists():
        table.add_row("inventory", f"[red]not found:[/red] {escape(str(inventory))}")
        return

    assets = load_inventory(inventory)
    if assets.is_empty():
        table.add_row(
            "inventory",
            f"[yellow]no mappings[/yellow] — "
            f"{len(assets.registers)} {INVENTORY_SUFFIX} file(s) read",
        )
        _inventory_rejects(table, assets)
        return

    # Age is judged against the capture, never the clock, so without telemetry
    # to date there is no window and every mapping is reported unjudged rather
    # than judged against today. Saying so is the point: the same inventory
    # can be current for one capture and expired for another.
    window = CaptureWindow()
    observed: set[str] = set()
    if telemetry is not None and telemetry.exists():
        ctx = AnalysisContext(
            connections=load_connections(telemetry),
            dns=load_dns(telemetry),
            alerts=load_alerts(telemetry),
            ssl=load_ssl(telemetry),
            inventory=assets,
        )
        window, observed = ctx.capture, _observed_addresses(ctx)

    coverage = assets.coverage(window, observed)
    table.add_row("inventory", f"[green]{escape(coverage.summary())}[/green]")
    if telemetry is None:
        table.add_row(
            "",
            "[dim]coverage and staleness need a capture to measure against: pass --telemetry[/dim]",
        )

    # With no window there is nothing to judge against, and listing every
    # mapping as "unknown window" would repeat the line above once per row.
    flagged = assets.flagged(window) if window.known else []
    for mapping, state in flagged[:5]:
        colour = "red" if state == "expired" else "yellow"
        table.add_row(
            "",
            f"[{colour}]{escape(state.replace('_', ' '))}[/{colour}] "
            f"[dim]{_safe(mapping.address)} -> {_safe(mapping.hostname)}, "
            f"{_safe(mapping.register.name)}[/dim]",
        )
    _inventory_rejects(table, assets)


def _inventory_rejects(table: Table, assets: Inventory) -> None:
    """Show the first unparseable line, as written.

    One fat-fingered entry must not cost the other three hundred and
    ninety-nine, and an operator cannot fix a line they are not shown.
    """
    if not assets.rejected:
        return
    path, number, text = assets.rejected[0]
    table.add_row(
        "",
        f"[yellow]{len(assets.rejected)} line(s) rejected[/yellow] "
        f"[dim]— first at {_safe(path)}:{number}: {_safe(text)}[/dim]",
    )


def _intel_row(table: Table, intel: Path | None) -> None:
    """Report what an IOC path actually loaded.

    Written for the failure an operator cannot see: a file in the wrong place,
    a file whose lines were all rejected, or a file full of hashes and URLs
    that nothing in this repository can match yet. Each of those looks
    identical to "no intel configured" from the outside, and each has a
    different fix.
    """
    if intel is None:
        table.add_row("intel", f"[dim]none given — pass --intel to check {IOC_SUFFIX} files[/dim]")
        return

    if not intel.exists():
        table.add_row("intel", f"[red]not found:[/red] {escape(str(intel))}")
        return

    indicators = load_indicators(intel)
    if indicators.is_empty():
        table.add_row(
            "intel",
            f"[yellow]no indicators[/yellow] — {len(indicators.feeds)} {IOC_SUFFIX} file(s) read",
        )
    else:
        counts = ", ".join(f"{count} {kind}" for kind, count in indicators.counts().items() if count)
        table.add_row(
            "intel",
            f"[green]{len(indicators)} indicator(s)[/green] from "
            f"{len(indicators.feeds)} feed(s) — {escape(counts)}",
        )

    unprovenanced = [feed.name for feed in indicators.feeds if not feed.provenanced]
    if unprovenanced:
        table.add_row(
            "",
            "[dim]no declared confidence: "
            + escape(", ".join(sorted(unprovenanced)[:4]))
            + " — matches score low by design[/dim]",
        )

    inert = indicators.counts()["url"] + indicators.counts()["file_hash"]
    if inert:
        table.add_row(
            "",
            f"[dim]{inert} url/hash indicator(s) loaded but inert: no HTTP or process "
            "telemetry parser exists yet[/dim]",
        )

    if indicators.rejected:
        first = indicators.rejected[0]
        table.add_row(
            "",
            f"[yellow]{len(indicators.rejected)} line(s) rejected[/yellow] — "
            f"e.g. {_safe(Path(first[0]).name)}:{first[1]} {_safe(first[2][:40])}",
        )


def _tls_row(table: Table, telemetry: Path | None) -> None:
    """Report whether TLS fingerprints are actually available.

    Written for the known failure: `ja3` is
    produced by a Zeek *package*, not by the core script, so a sensor without
    it writes an `ssl.log` with every column except the one that matters. From
    outside, that is indistinguishable from having no TLS telemetry at all —
    and the two have completely different fixes. One needs a sensor
    configuration change; the other needs a sensor.
    """
    if telemetry is None:
        table.add_row("tls", "[dim]none given — pass --telemetry to check an ssl.log[/dim]")
        return

    if not telemetry.exists():
        table.add_row("tls", f"[red]not found:[/red] {escape(str(telemetry))}")
        return

    sessions = load_ssl(telemetry)
    if sessions.is_empty():
        table.add_row("tls", "[dim]no ssl.log found — TLS fingerprinting inactive[/dim]")
        return

    fingerprints = sessions["ja3"].drop_nulls()
    fingerprints = fingerprints.filter(fingerprints.str.strip_chars() != "")
    if fingerprints.is_empty():
        table.add_row(
            "tls",
            f"[yellow]{sessions.height} session(s), no JA3[/yellow] — "
            "load the JA3 Zeek package",
        )
        table.add_row(
            "",
            "[dim]ssl.log is being written but carries no client fingerprint, so "
            "presents_rare_tls_fingerprint cannot be measured[/dim]",
        )
        return

    hosts = sessions["src_ip"].drop_nulls().n_unique()
    table.add_row(
        "tls",
        f"[green]{sessions.height} session(s)[/green] — "
        f"{fingerprints.n_unique()} distinct JA3 across {hosts} host(s)",
    )
    if hosts < TlsDgaConfig().min_estate_hosts:
        table.add_row(
            "",
            f"[dim]below the {TlsDgaConfig().min_estate_hosts}-host floor: rarity needs an "
            "estate, so no fingerprint finding will be emitted[/dim]",
        )


def _host_row(table: Table, telemetry: Path | None) -> None:
    """Report whether the estate can support a prevalence claim.

    The same shape as `_tls_row`, for the same reason and a worse version of
    it. Host telemetry has *three* states an operator cannot tell apart from
    outside: no process log at all, a process log from an estate too small to
    measure rarity over, and a healthy estate on which nothing was found. All
    three print no findings.

    The middle one is the trap this cluster exists around. Every "rare
    process" signal degenerates on a small estate, where everything is rare
    exactly once, so the analyzer declines rather than emitting a perfect
    rarity score for every binary ever run — and an operator who cannot see
    that is being told "clean" when they are being told "not measured".
    """
    if telemetry is None:
        table.add_row("host", "[dim]none given — pass --telemetry to check a Sysmon log[/dim]")
        return

    if not telemetry.exists():
        table.add_row("host", f"[red]not found:[/red] {escape(str(telemetry))}")
        return

    events = load_processes(telemetry)
    if events.is_empty():
        table.add_row("host", "[dim]no Sysmon JSON lines found — host analysis inactive[/dim]")
        return

    baseline = estate_baseline(host_summary(events))
    reason = baseline.gate(HostConfig())
    if reason is None:
        table.add_row("host", f"[green]{escape(baseline.summary())}[/green]")
        return

    table.add_row("host", f"[yellow]{escape(baseline.summary())}[/yellow]")
    table.add_row(
        "",
        f"[dim]no host finding will be emitted: {escape(reason)}[/dim]",
    )


@app.command()
def doctor(
    model: Path | None = typer.Option(None, "--model", help="GGUF model to check for."),
    intel: Path | None = typer.Option(
        None, "--intel", help=f"Directory or file of local {IOC_SUFFIX} indicators to check."
    ),
    inventory: Path | None = typer.Option(
        None,
        "--inventory",
        help=f"Directory or file of {INVENTORY_SUFFIX} asset mappings to check.",
    ),
    telemetry: Path | None = typer.Option(
        None,
        "--telemetry",
        help="Directory of logs to check for TLS fingerprints and host telemetry.",
    ),
) -> None:
    """Pre-flight check: platform, energy source, optional components.

    Written for bring-up on new hardware. The question that matters on a Pi is
    whether energy will be *measured* or *estimated*, and this answers it
    before a benchmark is run rather than after.
    """
    from voidai.telemetry.power import (
        EstimatedSource,
        HwmonSource,
        RaplSource,
        best_available_source,
    )

    table = Table(title="VoidLexicon pre-flight", title_justify="left", show_header=False)
    table.add_column(style="dim")
    table.add_column()

    profile = detect_platform()
    table.add_row("version", __version__)
    table.add_row("platform", escape(profile.name))
    table.add_row("machine", f"{os.uname().machine} · {os.cpu_count() or 1} cores")

    source = best_available_source()
    measured = not isinstance(source, EstimatedSource)
    table.add_row(
        "energy",
        f"[green]measured[/green] — {escape(source.method)}"
        if measured
        else f"[yellow]estimated[/yellow] — {escape(source.method)}",
    )
    if not measured:
        table.add_row(
            "",
            "[dim]RAPL: "
            + ("present but unreadable" if Path("/sys/class/powercap").is_dir() else "absent")
            + f"; hwmon power rails: {len(HwmonSource.available())} found"
            + f"; RAPL domains: {len(RaplSource.available())}[/dim]",
        )
        table.add_row("", "[dim]see docs/deployment.md to wire a shunt for real figures[/dim]")

    try:
        import llama_cpp

        table.add_row("llama-cpp", f"[green]installed[/green] ({llama_cpp.__version__})")
    except ImportError:
        table.add_row("llama-cpp", "[yellow]absent[/yellow] — narrative layer disabled")

    if model is not None:
        size = model.stat().st_size / 1e9 if model.is_file() else 0.0
        table.add_row(
            "model",
            f"[green]{escape(model.name)}[/green] ({size:.1f} GB)"
            if model.is_file()
            else f"[red]not found:[/red] {escape(str(model))}",
        )
    else:
        table.add_row("model", "[dim]none given — pass --model to check one[/dim]")

    # Fall back to the telemetry directory when no explicit path was given,
    # because `_detect` does exactly that — `load_indicators(intel or path)`.
    # Without this, `doctor --telemetry <dir>` reported "none given" for a
    # directory whose `.inv` file `run` was about to load and apply, which is
    # a diagnostic command lying about the system it is diagnosing.
    _intel_row(table, intel or telemetry)
    _inventory_row(table, inventory or telemetry, telemetry)
    _tls_row(table, telemetry)
    _host_row(table, telemetry)

    table.add_row("analyzers", ", ".join(a.name for a in DEFAULT_ANALYZERS))
    table.add_row("predicates", f"{len(GRAMMAR)} in the Lexicon")

    console.print()
    console.print(table)
    console.print(
        "\n[dim]Energy reads 'estimated' unless a real counter is present. An estimate "
        "is never reported as a measurement.[/dim]\n"
    )


@app.command()
def version() -> None:
    """Print version and detected platform."""
    profile = detect_platform()
    console.print(f"voidai {__version__}")
    console.print(f"[dim]platform:[/dim] {profile.citation}")


if __name__ == "__main__":  # pragma: no cover
    app()
