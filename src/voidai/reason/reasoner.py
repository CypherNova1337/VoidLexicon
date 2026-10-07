"""The reasoning stage: brief in, verified commentary out.

This is the only place in VoidLexicon where a language model runs, and it is
deliberately the smallest stage in the pipeline. It cannot detect anything, it
cannot author a Finding, and it cannot reach an analyst without passing the
verifier.

What it contributes is the part statistics genuinely cannot: a sentence
explaining why six measurements about one host add up to a story, and an
ordered list of what to check next. That is worth having. It is not worth
trusting, which is why nothing here is trusted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from voidai.correlate import RankedIncident
from voidai.lexicon import Incident
from voidai.reason.backend import (
    NARRATIVE_CHAR_LIMIT,
    SYSTEM_PROMPT,
    USER_TEMPLATE,
    ReasoningBackend,
    UnavailableBackend,
)
from voidai.reason.brief import EvidenceBrief, build_brief
from voidai.reason.verifier import VerificationReport, verify
from voidai.telemetry import TokenUsage

_SENTENCE_END = re.compile(r"[.!?](?=\s|$)")


def _drop_unfinished_sentence(narrative: str) -> str:
    """Remove the fragment a narrative is left with when it hits its length bound.

    The grammar stops the model at `NARRATIVE_CHAR_LIMIT` characters wherever it
    happens to be, which is usually mid-word — "part of a larger, pre". That
    fragment says nothing and reads as a defect, so it is cut back to the last
    complete sentence. Applied only to a narrative that reached the bound: one
    that ended on its own is left exactly as written, full stop or not.

    When the bound fell inside the first sentence there is nothing complete to
    keep, so the text stays and an ellipsis marks where it was stopped.
    """
    if len(narrative) < NARRATIVE_CHAR_LIMIT:
        return narrative
    ends = list(_SENTENCE_END.finditer(narrative))
    if not ends:
        return narrative.rstrip() + "…"
    return narrative[: ends[-1].end()]


@dataclass
class ReasoningConfig:
    """Budgets. All of them exist because the target is a CPU, not a cluster."""

    #: Incidents to narrate, highest priority first. Narrating a queue of 200
    #: on a Pi would take an hour and tell an analyst nothing they could not
    #: read from the ranking.
    max_incidents: int = 5
    #: Tokens allowed in one brief.
    prompt_token_budget: int = 700
    #: Tokens allowed in one response.
    max_response_tokens: int = 640
    #: Findings quoted per brief.
    max_findings_per_brief: int = 12


@dataclass
class ReasoningResult:
    """One narrated incident, with everything needed to audit the narration."""

    incident: Incident
    brief: EvidenceBrief
    report: VerificationReport
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def strike_count(self) -> int:
        return self.report.strike_count


@dataclass
class Reasoner:
    """Runs the language layer over a ranked queue."""

    backend: ReasoningBackend = field(default_factory=lambda: UnavailableBackend("none configured"))
    config: ReasoningConfig = field(default_factory=ReasoningConfig)

    def available(self) -> bool:
        return self.backend.available()

    def explain(self, ranked: RankedIncident) -> ReasoningResult:
        """Narrate one incident and verify every sentence of the result."""
        brief = build_brief(
            ranked,
            token_budget=self.config.prompt_token_budget,
            max_findings=self.config.max_findings_per_brief,
        )

        completion = self.backend.complete(
            SYSTEM_PROMPT,
            USER_TEMPLATE.format(brief=brief.text),
            max_tokens=self.config.max_response_tokens,
        )
        payload = completion.parse()

        report = verify(
            narrative=str(payload.get("narrative", "")),
            raw_claims=list(payload.get("claims", []) or []),
            actions=[str(a) for a in (payload.get("actions", []) or [])],
            findings=ranked.incident.findings,
            citable_ids=brief.citable_ids,
        )
        # Trimmed after verification, never before: an invented address in the
        # fragment must still strike the narrative, not be cut away unseen.
        report.narrative = _drop_unfinished_sentence(report.narrative)

        # Only verified commentary is attached to the Incident. The struck
        # claims stay on the report for audit, not on the record.
        incident = ranked.incident
        incident.narrative = report.narrative or None
        incident.claims = report.claims
        incident.recommended_actions = report.actions

        return ReasoningResult(
            incident=incident,
            brief=brief,
            report=report,
            prompt_tokens=completion.prompt_tokens,
            completion_tokens=completion.completion_tokens,
        )

    def explain_queue(
        self,
        ranked_incidents: list[RankedIncident],
        usage: TokenUsage | None = None,
    ) -> list[ReasoningResult]:
        """Narrate the top of the queue, recording token cost as it goes.

        Returns an empty list when no backend is available. That is not an
        error: detection has already produced its full result, and the run
        continues without commentary.
        """
        if not self.available():
            return []

        results: list[ReasoningResult] = []
        for ranked in ranked_incidents[: self.config.max_incidents]:
            result = self.explain(ranked)
            results.append(result)
            if usage is not None:
                usage.add(result.prompt_tokens, result.completion_tokens)
                usage.model = self.backend.name
        return results
