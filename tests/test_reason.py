"""Tests for the language layer.

The verifier tests are the important ones. A model that fabricates is not a
hypothetical: the responses used below are shaped after what Qwen2.5-1.5B
actually produced during development, including a narrative that called a
0.98-confidence beacon "likely legitimate" and one that wandered into naming
addresses the capture never contained.

`ScriptedBackend` replays fixed responses so all of this is deterministic and
needs no 1GB model file on disk.
"""

from __future__ import annotations

import json

import pytest

from voidai.correlate import build_queue, correlate
from voidai.lexicon import (
    Artifact,
    Entity,
    EntityType,
    Evidence,
    Finding,
    Predicate,
)
from voidai.reason import (
    Reasoner,
    ReasoningConfig,
    ScriptedBackend,
    UnavailableBackend,
    build_brief,
    estimate_tokens,
    verify,
)
from voidai.reason.verifier import StrikeReason


def beacon(host: str = "10.0.0.5", target: str = "203.0.113.7", confidence: float = 0.9) -> Finding:
    return Finding(
        predicate=Predicate.BEACONS_TO,
        subject=Entity(type=EntityType.IP, value=host),
        object=Entity(type=EntityType.IP, value=target),
        evidence=[
            Evidence(
                kind="interval_regularity",
                summary="240 connections at 60.0s intervals",
                payload={"period_seconds": 60.0},
                artifacts=[Artifact(source="conn.log", locator="line:42")],
            )
        ],
        confidence=confidence,
        basis="synthetic",
        analyzer="beaconing@test",
    )


def scan(host: str = "10.0.0.5", port: int = 25, confidence: float = 0.9) -> Finding:
    return Finding(
        predicate=Predicate.SCANS,
        subject=Entity(type=EntityType.IP, value=host),
        object=Entity(type=EntityType.PORT, value=str(port)),
        evidence=[
            Evidence(
                kind="destination_fanout",
                summary="1573 distinct destinations on port 25",
                payload={"destinations": 1573, "port": port},
                artifacts=[Artifact(source="conn.log", locator="line:77")],
            )
        ],
        confidence=confidence,
        basis="synthetic",
        analyzer="fanout@test",
    )


def response(narrative: str = "A host is beaconing.", claims=None, actions=None) -> str:
    return json.dumps(
        {
            "narrative": narrative,
            "claims": claims if claims is not None else [],
            "actions": actions if actions is not None else [],
        }
    )


class TestEvidenceBrief:
    def test_contains_no_raw_log_content(self) -> None:
        """The central architectural claim, asserted rather than assumed."""
        ranked = correlate([beacon(), scan()])[0]
        brief = build_brief(ranked)
        # Artifact locators identify where evidence lives; their contents must
        # not be pasted into the prompt.
        assert "conn.log" not in brief.text
        assert "line:42" not in brief.text

    def test_quotes_every_finding_id(self) -> None:
        findings = [beacon(), scan()]
        brief = build_brief(correlate(findings)[0])
        for finding in findings:
            assert finding.id in brief.text
            assert finding.id in brief.citable_ids

    def test_includes_predicate_meaning(self) -> None:
        """Without it a small model does not know a beacon is bad news."""
        brief = build_brief(correlate([beacon()])[0])
        assert Predicate.BEACONS_TO.spec.description in brief.text

    def test_is_small(self) -> None:
        """A brief must fit a CPU-bound model's budget with room to answer."""
        brief = build_brief(correlate([beacon(), scan()])[0])
        assert brief.estimated_tokens < 400

    def test_respects_the_token_budget(self) -> None:
        findings = [beacon(target=f"203.0.113.{i}", confidence=0.8) for i in range(1, 40)]
        brief = build_brief(correlate(findings)[0], token_budget=200)
        assert brief.estimated_tokens <= 260  # budget plus the truncation notice
        assert brief.truncated

    def test_truncation_keeps_the_brief_whole(self) -> None:
        findings = [beacon(target=f"203.0.113.{i}") for i in range(1, 40)]
        brief = build_brief(correlate(findings)[0], token_budget=200)
        assert "GROUNDED FINDINGS" in brief.text
        # Every ID still quoted must be citable, and vice versa.
        for finding_id in brief.citable_ids:
            assert finding_id in brief.text

    def test_citable_set_matches_what_was_shown(self) -> None:
        findings = [beacon(target=f"203.0.113.{i}") for i in range(1, 40)]
        brief = build_brief(correlate(findings)[0], token_budget=200)
        shown = {f.id for f in findings if f.id in brief.text}
        assert brief.citable_ids == frozenset(shown)

    def test_estimate_tokens_is_monotonic(self) -> None:
        assert estimate_tokens("") < estimate_tokens("a" * 100) < estimate_tokens("a" * 1000)


    def test_attack_codes_are_withheld_from_the_prompt(self) -> None:
        """A bare technique ID invites the model to invent its meaning.

        Qwen2.5-1.5B rendered T1071/T1573/T1008 as "reconnaissance, credential
        harvesting, and monitoring". They are Application Layer Protocol,
        Encrypted Channel and Fallback Channels. The verifier cannot catch a
        wrong gloss, so the codes do not go in the prompt at all.
        """
        finding = beacon()
        assert finding.attack_techniques  # the finding carries them
        brief = build_brief(correlate([finding])[0])
        for technique in finding.attack_techniques:
            assert technique not in brief.text


    def test_scoring_notation_is_withheld_from_the_prompt(self) -> None:
        """Internal vocabulary gets parroted as though it described the host.

        Shown the rationale string "noisy-OR of [...]", Qwen2.5-1.5B asserted
        that "the host is a noisy-OR beacon". The brief carries the priority
        number; the arithmetic stays in the audit trail.
        """
        ranked = correlate([beacon(), scan()])[0]
        assert "noisy-OR" in ranked.rationale
        assert "noisy-OR" not in build_brief(ranked).text


class TestVerifier:
    def test_accepts_a_grounded_claim(self) -> None:
        finding = beacon()
        report = verify(
            narrative="",
            raw_claims=[{"text": "The host beacons on a schedule.", "cites": [finding.id]}],
            actions=[],
            findings=[finding],
            citable_ids=frozenset({finding.id}),
        )
        assert len(report.verified) == 1
        assert report.strike_count == 0

    def test_strikes_a_claim_with_no_citation(self) -> None:
        finding = beacon()
        report = verify("", [{"text": "This host is compromised.", "cites": []}], [], [finding],
                        frozenset({finding.id}))
        assert report.strike_count == 1
        assert report.struck[0].rejection_reason == StrikeReason.NO_CITATION

    def test_strikes_an_unresolvable_citation(self) -> None:
        """The most common small-model failure: a plausible, invented ID."""
        finding = beacon()
        report = verify(
            "",
            [{"text": "The host beacons.", "cites": ["fnd_0000000000000000"]}],
            [],
            [finding],
            frozenset({finding.id}),
        )
        assert report.strike_count == 1
        assert StrikeReason.UNRESOLVED_CITATION in (report.struck[0].rejection_reason or "")

    def test_strikes_a_citation_from_another_incident(self) -> None:
        """Citing a real finding the brief did not show is still unresolved."""
        shown, unshown = beacon(), beacon(host="10.0.0.9", target="198.51.100.4")
        report = verify(
            "",
            [{"text": "Two hosts are beaconing.", "cites": [shown.id, unshown.id]}],
            [],
            [shown, unshown],
            frozenset({shown.id}),  # only one was in the brief
        )
        assert report.strike_count == 1

    def test_strikes_a_fabricated_address(self) -> None:
        """The dangerous case: an invented IP reads exactly like a real one."""
        finding = beacon()
        report = verify(
            "",
            [{"text": "The host also contacted 198.51.100.99.", "cites": [finding.id]}],
            [],
            [finding],
            frozenset({finding.id}),
        )
        assert report.strike_count == 1
        assert "198.51.100.99" in (report.struck[0].rejection_reason or "")

    def test_strikes_a_fabricated_port(self) -> None:
        finding = beacon()
        report = verify(
            "",
            [{"text": "Traffic was seen on port 4444.", "cites": [finding.id]}],
            [],
            [finding],
            frozenset({finding.id}),
        )
        assert report.strike_count == 1

    def test_accepts_an_address_the_evidence_contains(self) -> None:
        finding = beacon(target="203.0.113.7")
        report = verify(
            "",
            [{"text": "The host beacons to 203.0.113.7.", "cites": [finding.id]}],
            [],
            [finding],
            frozenset({finding.id}),
        )
        assert len(report.verified) == 1

    def test_accepts_a_port_the_evidence_contains(self) -> None:
        finding = scan(port=25)
        report = verify(
            "",
            [{"text": "The host sweeps port 25.", "cites": [finding.id]}],
            [],
            [finding],
            frozenset({finding.id}),
        )
        assert len(report.verified) == 1

    def test_strikes_a_narrative_naming_an_unseen_address(self) -> None:
        finding = beacon(target="203.0.113.7")
        report = verify(
            "The host exfiltrated data to 198.51.100.200.",
            [],
            [],
            [finding],
            frozenset({finding.id}),
        )
        assert report.narrative_struck
        assert report.narrative == ""

    def test_keeps_a_narrative_that_stays_grounded(self) -> None:
        finding = beacon(target="203.0.113.7")
        text = "The host contacts 203.0.113.7 on a fixed schedule."
        report = verify(text, [], [], [finding], frozenset({finding.id}))
        assert report.narrative == text
        assert not report.narrative_struck

    def test_struck_claims_are_kept_for_audit(self) -> None:
        """An analyst needs to see what the tool refused to say."""
        finding = beacon()
        report = verify("", [{"text": "Invented.", "cites": []}], [], [finding],
                        frozenset({finding.id}))
        assert len(report.claims) == 1
        assert report.claims[0].verified is False
        assert report.claims[0].text == "Invented."

    def test_strike_rate(self) -> None:
        finding = beacon()
        report = verify(
            "",
            [
                {"text": "Grounded.", "cites": [finding.id]},
                {"text": "Ungrounded.", "cites": []},
            ],
            [],
            [finding],
            frozenset({finding.id}),
        )
        assert report.strike_rate == pytest.approx(0.5)

    def test_empty_claims(self) -> None:
        report = verify("", [], [], [beacon()], frozenset())
        assert report.claims == []
        assert report.strike_rate == 0.0


class TestReasoner:
    def test_no_backend_yields_no_results(self) -> None:
        """--no-llm and a missing model are the same path, and neither errors."""
        reasoner = Reasoner(backend=UnavailableBackend("none"))
        queue = build_queue([beacon()])
        assert reasoner.explain_queue(queue.incidents) == []
        assert not reasoner.available()

    def test_attaches_only_verified_commentary(self) -> None:
        finding = beacon()
        backend = ScriptedBackend(
            [
                response(
                    narrative="The host beacons on a schedule.",
                    claims=[
                        {"text": "It beacons.", "cites": [finding.id]},
                        {"text": "It also reached 198.51.100.99.", "cites": [finding.id]},
                    ],
                    actions=["Check the destination."],
                )
            ]
        )
        result = Reasoner(backend=backend).explain_queue(build_queue([finding]).incidents)[0]

        assert len(result.report.verified) == 1
        assert result.strike_count == 1
        # The Incident carries every claim for audit, but only verified ones
        # are reported as true.
        assert len(result.incident.verified_claims()) == 1

    def test_malformed_json_does_not_abort_the_run(self) -> None:
        backend = ScriptedBackend(["this is not json at all"])
        result = Reasoner(backend=backend).explain_queue(build_queue([beacon()]).incidents)[0]
        assert result.report.claims == []
        assert result.incident.narrative is None

    def test_respects_max_incidents(self) -> None:
        findings = [beacon(host=f"10.0.0.{i}") for i in range(1, 12)]
        backend = ScriptedBackend([response() for _ in range(11)])
        reasoner = Reasoner(backend=backend, config=ReasoningConfig(max_incidents=3))
        assert len(reasoner.explain_queue(build_queue(findings).incidents)) == 3

    def test_records_token_usage(self) -> None:
        from voidai.telemetry import TokenUsage

        usage = TokenUsage()
        backend = ScriptedBackend([response()])
        Reasoner(backend=backend).explain_queue(build_queue([beacon()]).incidents, usage)
        assert usage.total > 0
        assert usage.invocations == 1

    @staticmethod
    def _narrate(narrative: str) -> str | None:
        backend = ScriptedBackend([response(narrative=narrative)])
        result = Reasoner(backend=backend).explain_queue(build_queue([beacon()]).incidents)[0]
        return result.incident.narrative

    def test_a_narrative_cut_by_its_bound_ends_on_a_complete_sentence(self) -> None:
        """The grammar stops the model at the bound wherever it is, which on
        Qwen2.5-1.5B produced "part of a larger, pre" in the demo. The fragment
        goes; every complete sentence before it stays. The decimal in the
        fragment must not be mistaken for a sentence end."""
        from voidai.reason.backend import NARRATIVE_CHAR_LIMIT

        kept = "The host beacons on a schedule. It checks in every minute."
        fragment = " It reached the destination at 0.98 confidence and is part of a larger, pre"
        cut = (kept + fragment + " padding" * 80)[:NARRATIVE_CHAR_LIMIT]
        assert len(cut) == NARRATIVE_CHAR_LIMIT

        assert self._narrate(cut) == kept

    def test_a_narrative_that_ended_on_its_own_is_left_as_written(self) -> None:
        """Only the bound triggers the trim. A short narrative with no closing
        full stop is complete, and cutting it back would delete a sentence."""
        written = "The host beacons on a schedule. It should be isolated"
        assert self._narrate(written) == written

    def test_a_bound_inside_the_first_sentence_is_marked_not_emptied(self) -> None:
        """With no complete sentence to fall back to, emptying the narrative
        would lose all of it. The text stays, and an ellipsis shows it was
        stopped rather than finished."""
        from voidai.reason.backend import NARRATIVE_CHAR_LIMIT

        run_on = ("the host beacons and scans and resolves " * 20)[:NARRATIVE_CHAR_LIMIT]
        narrated = self._narrate(run_on)
        assert narrated is not None
        assert narrated.endswith("…")
        assert narrated[:-1] == run_on.rstrip()

    def test_an_invented_address_in_the_fragment_still_strikes_the_narrative(self) -> None:
        """Trimming must not launder a fabrication. If the cut-off fragment
        names an address the evidence does not, the narrative is struck as it
        would have been — the trim runs after the verifier, not before it."""
        from voidai.reason.backend import NARRATIVE_CHAR_LIMIT

        kept = "The host beacons on a schedule."
        fragment = " It also reached 198.51.100.99 and then"
        cut = (kept + fragment + " padding" * 80)[:NARRATIVE_CHAR_LIMIT]

        backend = ScriptedBackend([response(narrative=cut)])
        result = Reasoner(backend=backend).explain_queue(build_queue([beacon()]).incidents)[0]
        assert result.report.narrative_struck
        assert result.incident.narrative is None

    def test_the_trim_threshold_is_the_grammar_bound(self) -> None:
        """The constant and the grammar are two statements of one number. If
        the grammar's bound moves alone, every narrative cut by it is missed."""
        from voidai.reason.backend import NARRATIVE_CHAR_LIMIT, RESPONSE_GRAMMAR

        rule = next(ln for ln in RESPONSE_GRAMMAR.splitlines() if ln.startswith("narrative ::="))
        assert f"char{{1,{NARRATIVE_CHAR_LIMIT}}}" in rule

    def test_model_never_receives_raw_logs(self) -> None:
        """Asserted on the prompt actually sent, not on the brief in isolation."""
        backend = ScriptedBackend([response()])
        Reasoner(backend=backend).explain_queue(build_queue([beacon(), scan()]).incidents)
        _system, user = backend.calls[0]
        assert "conn.log" not in user
        assert "line:42" not in user
