"""Tests for correlation and incident ranking.

The property under test is the one that took the CTU-13 true positive from
rank 358 of 395 to rank 1 of 133: a host exhibiting two independent
suspicious behaviours must outrank a host exhibiting one, even when the
single behaviour scores higher in isolation.

Two mechanisms below exist to add to an incident without adding to its score,
and most of their tests are about the second half of that sentence.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from voidai.correlate import CorrelationConfig, build_queue, correlate
from voidai.lexicon import (
    Artifact,
    Entity,
    EntityType,
    Evidence,
    Finding,
    Predicate,
    Severity,
)

#: Fixed so a finding's timestamps are the capture's, never the clock's. Two
#: runs a day apart must produce identical content-addressed ids.
T0 = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


def _evidence(kind: str = "interval_regularity", source: str = "conn.log") -> Evidence:
    # The locator is derived with a *stable* digest rather than `hash()`,
    # which Python salts per process. Finding ids are content-addressed, so a
    # salted locator gives one fixture a different id in every run — and any
    # test about reproducible ids then only ever compares a run with itself.
    digest = hashlib.sha256(kind.encode()).hexdigest()[:8]
    return Evidence(
        kind=kind,
        summary="synthetic evidence",
        artifacts=[Artifact(source=source, locator=f"line:{digest}")],
    )


def _at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def beacon(
    host: str,
    target: str,
    confidence: float,
    at: float | None = None,
    source: str = "conn.log",
) -> Finding:
    return Finding(
        predicate=Predicate.BEACONS_TO,
        subject=Entity(type=EntityType.IP, value=host),
        object=Entity(type=EntityType.IP, value=target),
        evidence=[_evidence(source=source)],
        confidence=confidence,
        basis="synthetic",
        analyzer="beaconing@test",
        first_seen=None if at is None else _at(at),
    )


def scan(
    host: str,
    port: int,
    confidence: float,
    at: float | None = None,
    source: str = "conn.log",
) -> Finding:
    return Finding(
        predicate=Predicate.SCANS,
        subject=Entity(type=EntityType.IP, value=host),
        object=Entity(type=EntityType.PORT, value=str(port)),
        evidence=[_evidence("destination_fanout", source=source)],
        confidence=confidence,
        basis="synthetic",
        analyzer="fanout@test",
        first_seen=None if at is None else _at(at),
    )


def tunnel(
    host: str,
    zone: str,
    confidence: float,
    at: float | None = None,
    source: str = "dns.log",
) -> Finding:
    return Finding(
        predicate=Predicate.TUNNELS_DNS_OVER,
        subject=Entity(type=EntityType.IP, value=host),
        object=Entity(type=EntityType.DOMAIN, value=zone),
        evidence=[_evidence("query_volume", source=source)],
        confidence=confidence,
        basis="synthetic",
        analyzer="dnstunnel@test",
        first_seen=None if at is None else _at(at),
    )


def intel(indicator: str, confidence: float, at: float | None = None) -> Finding:
    """A `matches_threat_intel` finding: unary, subject is the *indicator*."""
    return Finding(
        predicate=Predicate.MATCHES_THREAT_INTEL,
        subject=Entity(type=EntityType.IP, value=indicator),
        evidence=[_evidence("intel_match")],
        confidence=confidence,
        basis="synthetic",
        analyzer="intel@test",
        first_seen=None if at is None else _at(at),
    )


def orderings(ranked: object) -> list[Finding]:
    return [
        f
        for f in ranked.incident.findings  # type: ignore[attr-defined]
        if f.predicate is Predicate.PRECEDES
    ]


class TestCorroboration:
    def test_two_behaviours_outrank_one_stronger_one(self) -> None:
        """The CTU-13 result in miniature.

        The compromised host beacons at 0.75 — weaker than the 0.99 monitoring
        agent it was buried under — but it also sweeps port 25.
        """
        queue = build_queue(
            [
                beacon("10.0.0.9", "198.51.100.1", 0.99),  # a monitoring agent
                beacon("10.0.0.5", "203.0.113.7", 0.75),  # the compromised host
                scan("10.0.0.5", 25, 0.90),
            ]
        )
        assert queue.rank_of("10.0.0.5") == 1
        assert queue.rank_of("10.0.0.9") == 2

    def test_single_behaviour_gets_no_multiplier(self) -> None:
        ranked = correlate([beacon("10.0.0.5", "203.0.113.7", 0.80)])[0]
        assert ranked.priority == pytest.approx(0.80)
        assert "no corroboration" in ranked.rationale

    def test_multiplier_grows_with_distinct_behaviours(self) -> None:
        one = correlate([beacon("10.0.0.5", "203.0.113.7", 0.8)])[0]
        two = correlate([beacon("10.0.0.5", "203.0.113.7", 0.8), scan("10.0.0.5", 25, 0.8)])[0]
        assert two.priority > one.priority * 1.4

    def test_multiplier_is_capped(self) -> None:
        config = CorrelationConfig(max_corroboration_multiplier=1.5)
        ranked = correlate(
            [
                beacon("10.0.0.5", "203.0.113.7", 0.9),
                scan("10.0.0.5", 25, 0.9),
                scan("10.0.0.5", 22, 0.9),
            ],
            config,
        )[0]
        assert ranked.priority <= 1.0 * 1.5

    def test_repeated_findings_of_one_kind_are_not_corroboration(self) -> None:
        """Twenty views of one behaviour are not twenty independent opinions.

        Without this, a chatty analyzer could manufacture certainty simply by
        emitting more findings about the same thing.
        """
        many = [beacon("10.0.0.5", f"203.0.113.{i}", 0.8) for i in range(1, 21)]
        ranked = correlate(many)[0]
        assert len(ranked.corroborating_predicates) == 1
        assert ranked.priority == pytest.approx(0.8)

    def test_strongest_finding_per_predicate_is_used(self) -> None:
        ranked = correlate(
            [beacon("10.0.0.5", "203.0.113.1", 0.4), beacon("10.0.0.5", "203.0.113.2", 0.9)]
        )[0]
        assert ranked.combined_confidence == pytest.approx(0.9)


class TestIncidentFormation:
    def test_groups_by_subject(self) -> None:
        queue = build_queue(
            [
                beacon("10.0.0.5", "203.0.113.1", 0.8),
                beacon("10.0.0.5", "203.0.113.2", 0.9),
                beacon("10.0.0.6", "203.0.113.3", 0.7),
            ]
        )
        assert len(queue) == 2
        assert len(queue.incidents[0].incident.findings) == 2

    def test_shared_destinations_do_not_merge_hosts(self) -> None:
        """Joining through destinations collapses an estate into one incident."""
        queue = build_queue(
            [beacon(f"10.0.0.{i}", "203.0.113.1", 0.8) for i in range(1, 20)]
        )
        assert len(queue) == 19

    def test_incident_takes_highest_finding_severity(self) -> None:
        ranked = correlate([beacon("10.0.0.5", "203.0.113.1", 0.95)])[0]
        assert ranked.incident.severity is Severity.HIGH

    def test_findings_are_ordered_by_confidence(self) -> None:
        ranked = correlate(
            [beacon("10.0.0.5", "203.0.113.1", 0.4), beacon("10.0.0.5", "203.0.113.2", 0.9)]
        )[0]
        confidences = [f.confidence for f in ranked.incident.findings]
        assert confidences == sorted(confidences, reverse=True)

    def test_empty_input(self) -> None:
        assert correlate([]) == []
        assert len(build_queue([])) == 0


class TestQueue:
    def test_ordering_is_deterministic(self) -> None:
        findings = [beacon(f"10.0.0.{i}", "203.0.113.1", 0.8) for i in range(1, 30)]
        first = [r.subject.value for r in build_queue(findings).incidents]
        second = [r.subject.value for r in build_queue(list(reversed(findings))).incidents]
        assert first == second

    def test_rank_of_absent_subject(self) -> None:
        queue = build_queue([beacon("10.0.0.5", "203.0.113.1", 0.8)])
        assert queue.rank_of("10.0.0.99") is None

    def test_corroborated_subset(self) -> None:
        queue = build_queue(
            [
                beacon("10.0.0.5", "203.0.113.1", 0.8),
                scan("10.0.0.5", 25, 0.8),
                beacon("10.0.0.6", "203.0.113.2", 0.9),
            ]
        )
        assert [r.subject.value for r in queue.corroborated] == ["10.0.0.5"]

    def test_top_respects_the_limit(self) -> None:
        queue = build_queue([beacon(f"10.0.0.{i}", "203.0.113.1", 0.8) for i in range(1, 10)])
        assert len(queue.top(3)) == 3

    def test_rationale_is_auditable(self) -> None:
        """A priority an analyst cannot check is one they cannot trust."""
        ranked = correlate([beacon("10.0.0.5", "203.0.113.1", 0.75), scan("10.0.0.5", 25, 0.9)])[0]
        assert "beacons_to=0.75" in ranked.rationale
        assert "scans=0.90" in ranked.rationale
        assert "corroborate" in ranked.rationale

    def test_severity_counts(self) -> None:
        queue = build_queue(
            [beacon("10.0.0.5", "203.0.113.1", 0.8), scan("10.0.0.6", 25, 0.6)]
        )
        counts = queue.severity_counts()
        assert sum(counts.values()) == 2


class TestTemporalOrdering:
    """`precedes`: turning an incident's set of findings into a sequence.

    Most of these are about what it must *not* do. Ordering is VoidLexicon
    reasoning about findings already inside the incident, so every path by
    which it could feed back into that incident's own score is a bug.
    """

    def test_adjacent_behaviours_are_ordered(self) -> None:
        ranked = correlate(
            [scan("10.0.0.5", 22, 0.9, at=0), beacon("10.0.0.5", "203.0.113.7", 0.8, at=3600)]
        )[0]
        (edge,) = orderings(ranked)
        assert edge.subject.value == "22"
        assert edge.object is not None and edge.object.value == "203.0.113.7"
        assert edge.sentence() == "port:22 precedes ip:203.0.113.7"

    def test_the_chain_runs_over_behaviours_not_findings(self) -> None:
        """Twenty beacons are one behaviour, so there is nothing to order.

        Chaining findings rather than behaviours would emit nineteen edges
        saying a host beaconed before it beaconed.
        """
        many = [
            beacon("10.0.0.5", f"203.0.113.{i}", 0.8, at=i * 3600) for i in range(1, 21)
        ]
        assert orderings(correlate(many)[0]) == []

    def test_three_behaviours_produce_two_chained_edges(self) -> None:
        ranked = correlate(
            [
                beacon("10.0.0.5", "203.0.113.7", 0.9, at=7200),
                scan("10.0.0.5", 22, 0.9, at=0),
                tunnel("10.0.0.5", "evil.example", 0.9, at=14400, source="conn.log"),
            ]
        )[0]
        edges = orderings(ranked)
        assert [(e.subject.value, e.object.value) for e in edges] == [  # type: ignore[union-attr]
            ("22", "203.0.113.7"),
            ("203.0.113.7", "evil.example"),
        ]

    def test_no_order_below_the_same_clock_floor(self) -> None:
        """Half a second apart in one log is not an ordering worth asserting."""
        ranked = correlate(
            [scan("10.0.0.5", 22, 0.9, at=0), beacon("10.0.0.5", "203.0.113.7", 0.9, at=0.5)]
        )[0]
        assert orderings(ranked) == []

    def test_separate_sources_need_a_larger_separation(self) -> None:
        """The trap: two log sources on one host can be seconds or hours apart.

        Sixty seconds is ample within one sensor's own log and meaningless
        across two, so the same separation is asserted in one case and
        declined in the other. Both halves are here because a test that only
        checked the permissive half would pass with the whole distinction
        deleted.
        """
        one_sensor = correlate(
            [
                scan("10.0.0.5", 22, 0.9, at=0, source="conn.log"),
                beacon("10.0.0.5", "203.0.113.7", 0.9, at=60, source="conn.log"),
            ]
        )[0]
        assert len(orderings(one_sensor)) == 1

        two_sensors = correlate(
            [
                scan("10.0.0.5", 22, 0.9, at=0, source="conn.log"),
                tunnel("10.0.0.5", "evil.example", 0.9, at=60, source="dns.log"),
            ]
        )[0]
        assert orderings(two_sensors) == []

    def test_a_wide_enough_separation_crosses_sources(self) -> None:
        ranked = correlate(
            [
                scan("10.0.0.5", 22, 0.9, at=0, source="conn.log"),
                tunnel("10.0.0.5", "evil.example", 0.9, at=7200, source="dns.log"),
            ]
        )[0]
        (edge,) = orderings(ranked)
        assert edge.evidence[0].payload["shared_clock"] is False
        assert edge.evidence[0].payload["sources"] == ["conn.log", "dns.log"]

    def test_the_separation_is_recorded_for_the_reader(self) -> None:
        """A reader has to be able to judge the order, not just be told it."""
        ranked = correlate(
            [scan("10.0.0.5", 22, 0.9, at=0), beacon("10.0.0.5", "203.0.113.7", 0.9, at=3600)]
        )[0]
        payload = orderings(ranked)[0].evidence[0].payload
        assert payload["separation_seconds"] == 3600.0
        assert payload["min_separation_seconds"] == 1.0
        assert payload["shared_clock"] is True
        assert payload["earlier_predicate"] == "scans"
        assert payload["later_predicate"] == "beacons_to"

    def test_a_finding_with_no_timestamp_is_not_ordered(self) -> None:
        """Rule 6: with no time, the verb `precedes` is unsayable.

        Not placed at the start of the window, not placed at the end. Left
        out, exactly as a missing component is omitted rather than defaulted.
        """
        ranked = correlate(
            [scan("10.0.0.5", 22, 0.9, at=None), beacon("10.0.0.5", "203.0.113.7", 0.9, at=3600)]
        )[0]
        assert orderings(ranked) == []

    def test_no_entity_precedes_itself(self) -> None:
        """Two behaviours pivoting on one address have no ordering to state.

        The common case, and the reason this is not hypothetical: a host
        beacons to an address, and that address is in the operator's feed. The
        hit attaches here, and both behaviours pivot on the same entity, so
        the only proposition available is "203.0.113.7 precedes 203.0.113.7".
        The ordering is real and the Lexicon has no way to say it that a
        reader would not misread, so nothing is said.

        Written as a two-behaviour incident on purpose. The three-behaviour
        version of this test passes with the guard deleted, because no
        *adjacent* pair in it happens to share a pivot — an assertion that
        holds for a reason other than the one it names guards nothing.
        """
        ranked = correlate(
            [
                beacon("10.0.0.5", "203.0.113.7", 0.9, at=0),
                intel("203.0.113.7", 0.9, at=3600),
            ]
        )[0]
        assert {f.predicate for f in ranked.incident.findings} == {
            Predicate.BEACONS_TO,
            Predicate.MATCHES_THREAT_INTEL,
        }
        assert orderings(ranked) == []

    def test_confidence_is_bounded_by_the_weaker_finding(self) -> None:
        """An ordering cannot be better founded than what it orders."""
        ranked = correlate(
            [scan("10.0.0.5", 22, 0.91, at=0), beacon("10.0.0.5", "203.0.113.7", 0.42, at=3600)]
        )[0]
        assert orderings(ranked)[0].confidence == pytest.approx(0.42)

    def test_ordering_does_not_change_the_priority(self) -> None:
        """The whole point, and the bug this cluster was warned about.

        `precedes` is derived from findings already inside the incident, so
        any route by which it reaches the score is the incident inflating
        itself by describing its own contents. Both routes are checked: the
        corroboration multiplier and the noisy-OR.
        """
        findings = [
            beacon("10.0.0.5", "203.0.113.7", 0.9, at=0),
            scan("10.0.0.5", 22, 0.8, at=3600),
            tunnel("10.0.0.5", "evil.example", 0.7, at=7200, source="conn.log"),
        ]
        with_order = correlate(findings)[0]
        without = correlate(findings, CorrelationConfig(order_behaviours=False))[0]

        assert len(orderings(with_order)) == 2
        assert with_order.priority == pytest.approx(without.priority)
        assert with_order.combined_confidence == pytest.approx(without.combined_confidence)
        assert with_order.corroborating_predicates == without.corroborating_predicates
        assert Predicate.PRECEDES not in with_order.corroborating_predicates
        assert "precedes" not in with_order.rationale

    def test_more_ordering_cannot_climb_the_queue(self) -> None:
        """A host with four behaviours earns three edges; none of them count.

        The failure mode stated as a ranking: if ordering fed the noisy-OR,
        the host with more behaviours to order would outrank a stronger one
        for describing itself more thoroughly.
        """
        chatty = [
            beacon("10.0.0.5", "203.0.113.7", 0.6, at=0),
            scan("10.0.0.5", 22, 0.6, at=3600),
        ]
        quiet = [beacon("10.0.0.9", "198.51.100.1", 0.99, at=0)]
        ordered = correlate(chatty)[0]
        assert len(orderings(ordered)) == 1
        assert ordered.priority == pytest.approx(
            correlate(chatty, CorrelationConfig(order_behaviours=False))[0].priority
        )
        assert correlate(chatty + quiet)[0].subject.value == "10.0.0.5"

    def test_derived_findings_sort_after_measured_ones(self) -> None:
        """An ordering inherits a confidence and must not float above evidence."""
        ranked = correlate(
            [scan("10.0.0.5", 22, 0.99, at=0), beacon("10.0.0.5", "203.0.113.7", 0.99, at=3600)]
        )[0]
        predicates = [f.predicate for f in ranked.incident.findings]
        assert predicates[-1] is Predicate.PRECEDES
        assert Predicate.PRECEDES not in predicates[:-1]

    def test_the_edge_cites_both_sides(self) -> None:
        """Chain of custody: an ordering rests on two moments, and names both."""
        ranked = correlate(
            [
                scan("10.0.0.5", 22, 0.9, at=0, source="conn.log"),
                tunnel("10.0.0.5", "evil.example", 0.9, at=7200, source="dns.log"),
            ]
        )[0]
        edge = orderings(ranked)[0]
        assert {a.source for a in edge.evidence[0].artifacts} == {"conn.log", "dns.log"}
        measured = {f.id for f in ranked.incident.findings if f.predicate is not Predicate.PRECEDES}
        payload = edge.evidence[0].payload
        assert payload["earlier_finding"] in measured
        assert payload["later_finding"] in measured

    def test_derived_findings_stay_last_at_the_epoch(self) -> None:
        """The measured/derived split must not rest on timestamps being large.

        Derived findings carry their start time as a sort key and measured
        ones sort at zero, so on any ordinary capture the split falls out of
        the times alone and the explicit flag looks redundant. It is not: a
        sensor with an unset clock writes 1970, and then every key collides at
        zero and only the flag keeps VoidLexicon's bookkeeping below the evidence.
        Found by deleting the flag and watching nothing fail.
        """
        epoch = (datetime(1970, 1, 1, tzinfo=timezone.utc) - T0).total_seconds()
        ranked = correlate(
            [
                scan("10.0.0.5", 22, 0.9, at=epoch),
                beacon("10.0.0.5", "203.0.113.7", 0.9, at=epoch + 3600),
            ]
        )[0]
        assert len(orderings(ranked)) == 1
        assert ranked.incident.findings[-1].predicate is Predicate.PRECEDES

    def test_the_chain_is_stored_in_the_order_it_describes(self) -> None:
        """A sequence a reader has to reassemble is not a sequence.

        Every edge in a run of equally-confident behaviours ties on
        confidence, so sorting the derived block that way scrambled the chain
        and left the order recoverable only from the payloads. Caught by the
        test above failing under two of six hash seeds and passing under the
        rest — the arrangement had fallen through to the finding id.
        """
        # Confidences chosen so the two chain orders disagree. The edges
        # inherit min(0.7, 0.9) = 0.7 and min(0.9, 0.8) = 0.8, so sorting the
        # derived block by confidence puts the *second* edge first. Equal
        # confidences would let this pass on a lucky finding-id tie-break,
        # which is how the scrambling survived its first test.
        ranked = correlate(
            [
                scan("10.0.0.5", 22, 0.7, at=0),
                beacon("10.0.0.5", "203.0.113.7", 0.9, at=7200),
                tunnel("10.0.0.5", "evil.example", 0.8, at=14400, source="conn.log"),
            ]
        )[0]
        edges = orderings(ranked)
        assert [e.confidence for e in edges] == [pytest.approx(0.7), pytest.approx(0.8)]
        starts = [e.evidence[0].payload["earlier_first_seen"] for e in edges]
        assert starts == sorted(starts)
        assert [f.predicate for f in ranked.incident.findings][-2:] == [
            Predicate.PRECEDES,
            Predicate.PRECEDES,
        ]

    def test_ordering_is_reproducible(self) -> None:
        """Rule 12: two runs over one set produce identical ids.

        The timestamps come from the capture, never from the clock, so this
        holds tomorrow as well as twice in a row.
        """
        findings = [
            beacon("10.0.0.5", "203.0.113.7", 0.9, at=0),
            scan("10.0.0.5", 22, 0.9, at=3600),
            tunnel("10.0.0.5", "evil.example", 0.9, at=7200, source="conn.log"),
        ]
        first = [f.id for f in correlate(findings)[0].incident.findings]
        second = [f.id for f in correlate(list(reversed(findings)))[0].incident.findings]
        assert first == second


class TestUnaryAttachment:
    """An intel hit joins the host that reached the indicator.

    `matches_threat_intel` is unary and its subject is the indicator, so
    grouping by subject alone files it under the address. A host that beacons
    *and* touches a known-bad address then reads as two incidents — the
    conjunction the ranking exists to surface.
    """

    def test_the_hit_joins_the_host_that_reached_it(self) -> None:
        queue = build_queue(
            [beacon("10.0.0.5", "45.83.220.17", 0.9), intel("45.83.220.17", 0.8)]
        )
        assert len(queue) == 1
        ranked = queue.incidents[0]
        assert ranked.subject.value == "10.0.0.5"
        assert Predicate.MATCHES_THREAT_INTEL in {f.predicate for f in ranked.incident.findings}

    def test_the_proposition_is_not_rewritten(self) -> None:
        """The finding moves; the sentence does not.

        Re-subjecting it to the host would make it false — a host does not
        appear in a feed.
        """
        queue = build_queue(
            [beacon("10.0.0.5", "45.83.220.17", 0.9), intel("45.83.220.17", 0.8)]
        )
        hit = next(
            f
            for f in queue.incidents[0].incident.findings
            if f.predicate is Predicate.MATCHES_THREAT_INTEL
        )
        assert hit.subject.value == "45.83.220.17"
        assert hit.object is None

    def test_the_indicator_does_not_also_stand_alone(self) -> None:
        queue = build_queue(
            [beacon("10.0.0.5", "45.83.220.17", 0.9), intel("45.83.220.17", 0.8)]
        )
        assert queue.rank_of("45.83.220.17") is None

    def test_it_attaches_to_every_incident_naming_the_indicator(self) -> None:
        """Several hosts may have reached it, and each analyst needs to see it."""
        queue = build_queue(
            [
                beacon("10.0.0.5", "45.83.220.17", 0.9),
                beacon("10.0.0.6", "45.83.220.17", 0.8),
                beacon("10.0.0.7", "198.51.100.1", 0.7),
                intel("45.83.220.17", 0.8),
            ]
        )
        carrying = {
            r.subject.value
            for r in queue.incidents
            if any(f.predicate is Predicate.MATCHES_THREAT_INTEL for f in r.incident.findings)
        }
        assert carrying == {"10.0.0.5", "10.0.0.6"}

    def test_an_unattached_indicator_keeps_its_own_incident(self) -> None:
        """Seen in traffic with nothing else against it: still worth reporting."""
        queue = build_queue([beacon("10.0.0.5", "198.51.100.1", 0.9), intel("45.83.220.17", 0.8)])
        assert queue.rank_of("45.83.220.17") == 2

    def test_an_indicator_that_is_also_an_actor_keeps_its_incident(self) -> None:
        """Dropping the group would delete the beaconing finding with it.

        A group is dropped only when nothing anchors it. Here the address is
        both an indicator and a host doing something in this estate, so its
        incident survives — and keeps the hit, which is a fact about it.
        """
        queue = build_queue(
            [
                beacon("10.0.0.5", "45.83.220.17", 0.9),
                beacon("45.83.220.17", "198.51.100.1", 0.7),
                intel("45.83.220.17", 0.8),
            ]
        )
        own = next(r for r in queue.incidents if r.subject.value == "45.83.220.17")
        assert {f.predicate for f in own.incident.findings} == {
            Predicate.BEACONS_TO,
            Predicate.MATCHES_THREAT_INTEL,
        }

    def test_the_incident_is_named_for_its_host_not_the_indicator(self) -> None:
        """The attached finding has a different subject and must not rename it.

        `RankedIncident.subject` used to be the first finding's subject with
        the findings sorted by confidence, so a strong hit renamed the host's
        incident after an address in someone else's country.
        """
        queue = build_queue(
            [beacon("10.0.0.5", "45.83.220.17", 0.60), intel("45.83.220.17", 0.99)]
        )
        ranked = queue.incidents[0]
        assert ranked.subject.value == "10.0.0.5"
        assert ranked.incident.title == "Beacons To — 10.0.0.5"
        assert queue.rank_of("10.0.0.5") == 1

    def test_a_hit_does_not_corroborate(self) -> None:
        """Not a second thing the host did — better information about the first.

        The multiplier counts independent behaviours of a host. An intel match
        is complete evidence of exactly what it claims, so this is not rule 6;
        it is what corroboration means here.
        """
        ranked = correlate([beacon("10.0.0.5", "45.83.220.17", 0.9), intel("45.83.220.17", 0.8)])[0]
        assert ranked.corroborating_predicates == (Predicate.BEACONS_TO,)
        assert "no corroboration" in ranked.rationale

    def test_a_hit_still_raises_combined_confidence(self) -> None:
        """Confirmatory evidence belongs in the noisy-OR, and lands there."""
        alone = correlate([beacon("10.0.0.5", "45.83.220.17", 0.9)])[0]
        with_hit = correlate(
            [beacon("10.0.0.5", "45.83.220.17", 0.9), intel("45.83.220.17", 0.8)]
        )[0]
        assert with_hit.combined_confidence > alone.combined_confidence
        assert with_hit.combined_confidence == pytest.approx(1 - 0.1 * 0.2)

    def test_a_bad_feed_cannot_flood_the_queue(self) -> None:
        """The failure mode that settles it.

        A stale or over-broad feed matching every destination in the estate
        would, if it corroborated, multiply the priority of every host that
        touched anything in it — turning one bad file into a queue of
        corroborated incidents.
        """
        findings: list[Finding] = []
        for i in range(1, 51):
            findings.append(beacon(f"10.0.0.{i}", f"45.83.220.{i}", 0.7))
            findings.append(intel(f"45.83.220.{i}", 0.9))
        queue = build_queue(findings)
        assert len(queue) == 50
        assert queue.corroborated == []

    def test_attachment_can_be_turned_off(self) -> None:
        queue = build_queue(
            [beacon("10.0.0.5", "45.83.220.17", 0.9), intel("45.83.220.17", 0.8)],
            CorrelationConfig(attach_unary=False),
        )
        assert len(queue) == 2
        assert queue.rank_of("45.83.220.17") == 2


class TestTheLadderIsEnforced:
    """The two config sets encode three rungs; the nesting must hold.

    `non_evidential` sitting outside `non_corroborating` would mean a finding
    that raises the corroboration multiplier while contributing nothing to the
    confidence that is supposed to justify it. Coherent today only because one
    person held both facts in mind at once.
    """

    def test_the_default_config_is_coherent(self) -> None:
        config = CorrelationConfig()
        assert config.non_evidential <= config.non_corroborating

    def test_an_inverted_ladder_is_rejected_at_construction(self) -> None:
        with pytest.raises(ValueError, match="subset of non_corroborating"):
            CorrelationConfig(
                non_corroborating=frozenset(),
                non_evidential=frozenset({Predicate.PRECEDES}),
            )

    def test_the_error_names_the_offending_predicate(self) -> None:
        """A rejection an author cannot act on is a rejection they will bypass."""
        with pytest.raises(ValueError, match="precedes"):
            CorrelationConfig(
                non_corroborating=frozenset({Predicate.SHARES_INFRASTRUCTURE_WITH}),
                non_evidential=frozenset({Predicate.PRECEDES}),
            )
