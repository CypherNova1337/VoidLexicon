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

from dataclasses import dataclass, field

from voidai.correlate import RankedIncident
from voidai.lexicon import Incident
from voidai.reason.backend import (
    SYSTEM_PROMPT,
    USER_TEMPLATE,
    ReasoningBackend,
    UnavailableBackend,
)
from voidai.reason.brief import EvidenceBrief, build_brief
from voidai.reason.verifier import VerificationReport, verify
from voidai.telemetry import TokenUsage


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
