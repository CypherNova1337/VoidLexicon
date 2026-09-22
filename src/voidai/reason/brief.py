"""The evidence brief: the only thing a language model is ever shown.

This module is the enforcement point for the project's central architectural
claim. The model does not receive logs, packets, or flow records. It receives
a compressed, token-budgeted summary of propositions the deterministic layer
has *already grounded*, each tagged with the Finding ID that authorises it.

Three consequences follow, and all three are the point:

**It runs on a Pi.** A brief for a fully-loaded incident is a few hundred
tokens. Feeding raw telemetry to a 4B model at four tokens per second is not
slow, it is impossible; feeding it a brief takes seconds.

**It cannot invent a finding.** Nothing in the brief is open-ended. The model
is shown a closed list of grounded propositions and asked to rank, connect and
explain them. A proposition it was not shown has no ID, and a claim citing no
valid ID is struck by `voidai.reason.verifier` before an analyst sees it.

**It cannot leak.** Raw log content never enters the prompt, so nothing in the
capture can reach the model's context — which matters for a tool that may be
pointed at traffic its operator is not cleared to read in full.

The budget is enforced by construction rather than by truncating a finished
string: sections are emitted in priority order and stop when the budget is
spent, so a brief is always syntactically whole.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from voidai.correlate import RankedIncident
from voidai.lexicon import Evidence, Finding

#: Rough characters-per-token for the tokenisers used by the small open models
#: this targets. Deliberately conservative: over-estimating token count makes
#: the brief shorter than the budget, never longer.
_CHARS_PER_TOKEN = 3.5


def estimate_tokens(text: str) -> int:
    """Cheap token estimate that needs no tokeniser loaded.

    The real count comes back from the backend after the call and is what the
    receipt reports. This is only used to decide what fits.
    """
    return int(len(text) / _CHARS_PER_TOKEN) + 1


@dataclass
class BriefSection:
    """One block of the brief, with the cost of including it."""

    text: str
    tokens: int

    @classmethod
    def of(cls, text: str) -> BriefSection:
        return cls(text=text, tokens=estimate_tokens(text))


@dataclass
class EvidenceBrief:
    """A token-budgeted, fully-grounded summary of one incident."""

    incident_id: str
    subject: str
    text: str
    estimated_tokens: int
    #: Every Finding ID quoted in the brief. The verifier treats this as the
    #: complete set of things a claim is permitted to cite.
    citable_ids: frozenset[str] = field(default_factory=frozenset)
    truncated: bool = False

    def __str__(self) -> str:
        return self.text


def _summarise_evidence(evidence: Evidence) -> str:
    """One line per evidence object: the measured numbers, not prose."""
    return f"      - {evidence.summary}"


def _describe_finding(finding: Finding, include_evidence: bool) -> str:
    """Render one finding, including what its predicate actually means.

    The meaning comes from the Lexicon's own grammar rather than from a
    hand-written gloss. Without it a small model has no idea that "beacons to"
    is bad news: Qwen2.5-1.5B described a 0.98-confidence beacon as "likely a
    legitimate communication" on the first run. The predicate description is
    already defined, already authoritative, and costs a dozen tokens.

    ATT&CK technique IDs are deliberately *excluded*. Shown T1071, T1573 and
    T1008, Qwen2.5-1.5B rendered them as "reconnaissance, credential
    harvesting, and monitoring" — they are Application Layer Protocol,
    Encrypted Channel and Fallback Channels. A bare code the model
    half-remembers is an invitation to confabulate, and the verifier cannot
    catch it because a wrong gloss is neither a fabricated entity nor a bad
    citation. The IDs stay on the Finding, where an analyst reads them; they
    have no business in a prompt.
    """
    lines = [
        f"  [{finding.id}] {finding.sentence()}",
        f"      meaning: {finding.predicate.spec.description}",
        f"      confidence {finding.confidence:.2f} ({finding.severity.value})",
    ]
    if include_evidence:
        lines.extend(_summarise_evidence(e) for e in finding.evidence)
    return "\n".join(lines)


def build_brief(
    ranked: RankedIncident,
    token_budget: int = 700,
    max_findings: int = 12,
) -> EvidenceBrief:
    """Compress one ranked incident into a brief the model may be shown.

    Findings are emitted strongest-first, with their evidence lines included
    while budget allows and dropped before the findings themselves are. Losing
    a supporting measurement costs the model detail; losing a whole finding
    costs it a fact, so facts are protected first.
    """
    incident = ranked.incident
    # The incident's own order, not a fresh sort by confidence. A `precedes`
    # finding inherits the confidence of the observation it orders, so sorting
    # on confidence alone lets VoidLexicon's own bookkeeping tie with the evidence
    # and take a slot from it under the cap. The correlator has already put
    # measured findings first and the derived chain last, in sequence.
    findings = incident.findings[:max_findings]

    header = BriefSection.of(
        "\n".join(
            [
                f"SUBJECT: {ranked.subject}",
                # The priority number, not the arithmetic behind it. The
                # rationale string names the scoring method, and a small model
                # repeats internal notation as though it described the host:
                # shown "noisy-OR of [...]", Qwen2.5-1.5B wrote "the host is a
                # noisy-OR beacon". The rationale is for the analyst's audit
                # trail, which is where it stays.
                f"PRIORITY: {ranked.priority:.2f}",
                f"BEHAVIOURS: {', '.join(p.value for p in ranked.corroborating_predicates)}",
                "",
                "GROUNDED FINDINGS (cite these IDs and no others):",
            ]
        )
    )

    spent = header.tokens
    body: list[str] = []
    citable: set[str] = set()
    truncated = False

    # Two passes: every finding headline first, then evidence detail for as
    # many as the remaining budget allows.
    with_evidence: list[str] = []
    for finding in findings:
        block = BriefSection.of(_describe_finding(finding, include_evidence=False))
        if spent + block.tokens > token_budget:
            truncated = True
            break
        spent += block.tokens
        body.append(block.text)
        citable.add(finding.id)
        with_evidence.append(finding.id)

    detail: list[str] = []
    for finding in findings:
        if finding.id not in citable:
            continue
        lines = "\n".join(_summarise_evidence(e) for e in finding.evidence)
        block = BriefSection.of(lines)
        if not lines or spent + block.tokens > token_budget:
            truncated = True
            break
        spent += block.tokens
        detail.append(f"  [{finding.id}] measurements:\n{lines}")

    parts = [header.text, *body]
    if detail:
        parts.extend(["", "MEASUREMENTS:", *detail])
    if truncated:
        parts.append("\n(brief truncated at token budget; findings above are complete)")

    text = "\n".join(parts)
    return EvidenceBrief(
        incident_id=incident.id,
        subject=str(ranked.subject),
        text=text,
        estimated_tokens=estimate_tokens(text),
        citable_ids=frozenset(citable),
        truncated=truncated,
    )
