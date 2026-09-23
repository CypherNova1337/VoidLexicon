"""Correlation: findings into incidents, and incidents into an ordered queue.

## The problem this exists to solve

The beaconing analyzer finds the command-and-control channel in both CTU-13
scenarios tested. It also emits 395 findings on a two-hour capture, with the
true positive at rank 358. Detected and invisible are the same thing to an
analyst working a queue.

The instinct is to tighten the detector. That is wrong, and the data says so:
the high-scoring findings VoidLexicon cannot rank below the C2 are *genuinely*
beacon-like — perfectly regular, uniform payload, single-host destinations.
They are monitoring agents, backup jobs and keep-alives. No refinement of a
periodicity measure separates them, because on the axis of periodicity they
are not different.

## What actually separates a compromised host

It does more than one suspicious thing.

The CTU-13 scenario 6 host beacons every 33 seconds *and* mails 1,573 distinct
destinations on port 25 — rank 1 of 143,546 (host, port) pairs for fan-out.
Scenario 3's beacons *and* sweeps 26,702 hosts on port 22. Neither the
beaconing nor the fan-out signal is decisive alone: plenty of hosts beacon
benignly, and a busy workstation reaches more web servers than the spam bot
reached mail servers. Their conjunction is decisive, and no amount of tuning
either analyzer in isolation would find it.

So ranking belongs here, not in the analyzers. A `Finding` answers "how
beacon-like is this traffic?" An `Incident` answers "how much should an
analyst care about this host?" Conflating those two questions is what buried
the true positive at rank 358.

## How incidents are formed

By subject. Every finding about one host becomes one incident, because "what
is this host doing?" is the unit a responder actually works in.

Findings are deliberately *not* joined through shared destinations. Doing so
collapses the whole estate into a single component the moment two hosts touch
one popular address — and on a university network they do, immediately.

There is one edge, and it runs the other way. A *unary* predicate says
something about a subject alone, and `matches_threat_intel` is unary with the
indicator as its subject — so grouping by subject alone puts an intel hit in
its own incident rather than in the one for the host that reached the address.
A host that beacons *and* touches a known-bad address then reads as two
incidents, which is precisely the conjunction this module exists to surface.
So incident formation follows an edge from a finding's **object** to a unary
finding's **subject**: the intel hit joins the host, and the proposition is
left alone. `_attach_unary` has the full account.

## Ordering what an incident contains

Grouping produces a *set* of findings, and a set cannot be narrated. Once the
membership of an incident is settled, `_order_behaviours` walks its distinct
behaviours in observed order and emits `precedes` between adjacent ones, so
the language layer can say "swept a port, then beaconed, then transferred"
rather than listing three things that happened to the same machine.

Those edges are VoidLexicon's own reasoning about findings already in the incident,
not new observations of the host, and they are kept out of the arithmetic
entirely — see `CorrelationConfig.non_evidential`.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import datetime, timezone

from voidai.lexicon import (
    Artifact,
    Entity,
    Evidence,
    Finding,
    Incident,
    Predicate,
    Severity,
)

#: Named in the `analyzer` field of every finding this module mints, so a
#: derived proposition is traceable to the component that derived it — the
#: same chain-of-custody rule every analyzer follows.
CORRELATOR = "correlate.incidents@1"


@dataclass(frozen=True)
class CorrelationConfig:
    """Tunables for incident formation and priority."""

    #: Multiplier applied per additional independent predicate. Two distinct
    #: categories of suspicious behaviour on one host score 1.5x, three 2.0x.
    corroboration_bonus: float = 0.5
    #: Cap on the corroboration multiplier, so a host with many weak findings
    #: cannot climb past one with strong, genuinely independent evidence.
    max_corroboration_multiplier: float = 2.5

    #: Predicates that contribute evidence but do not count as an independent
    #: behaviour. A finding here still raises its host's combined confidence
    #: through the noisy-OR and still appears in the incident an analyst
    #: reads; what it may not do is multiply the priority, because a
    #: multiplier is a claim that two *separate* things were seen.
    #:
    #: Three reasons put a predicate in this set, and all three are the same
    #: rule at different levels — see engineering rule 6.
    #:
    #: `shares_infrastructure_with` and `precedes` describe the environment,
    #: or VoidLexicon's own reasoning about two observations. They are bookkeeping,
    #: and a pair of bookkeeping entries is not two opinions.
    #:
    #: `contacts_rare_destination` is a real observation about the host, but
    #: it rests on a single cheap signal — estate-wide prevalence — and every
    #: host that talks to anything unusual earns one.
    #:
    #: `transfers_anomalous_volume` is the claim the egress analyzer makes
    #: when it *cannot* make the stronger one: either the sensor recorded no
    #: direction, or the four signals did not reach the exfiltration
    #: threshold. Partial evidence, by construction. Measured on CTU-13
    #: scenario 3: letting it corroborate moved the infected host from queue
    #: rank 2 to rank 5 and took corroborated incidents from 3 to 33, while
    #: contributing nothing to the true positive — which had no volume
    #: finding at all. On scenario 6 the bot's incident keeps its volume
    #: finding and still ranks 1, which is the shape wanted: evidence
    #: retained, false promotion removed.
    #:
    #: `presents_rare_tls_fingerprint` is the one member that is *not* here
    #: for partial evidence. A rare JA3 is complete evidence of exactly what
    #: it claims. It is excluded because of what corroboration counts:
    #: independent **behaviours of a host**. An implant beaconing over TLS
    #: earns a beaconing finding and a rare-fingerprint finding from the same
    #: connection — one behaviour measured twice, and multiplying a host's
    #: priority for it would reward the analyzer for looking at the traffic
    #: twice. It is also a single prevalence signal, which is the reason
    #: `contacts_rare_destination` sits here. Confirmatory evidence still
    #: raises the incident's combined confidence through the noisy-OR, which
    #: is where confirmation belongs.
    #:
    #: `resolves_algorithmic_domain` is deliberately **not** in this set. A
    #: host running a domain generation algorithm is doing a second thing,
    #: not describing the first one differently, and the conjunction of a DGA
    #: and a beacon is exactly what the multiplier exists to surface.
    #:
    #: `matches_threat_intel` is the newest member and the reason is neither
    #: rule 6 nor a doubt about the feed. An intel match is *complete*
    #: evidence of exactly what it claims — the address is in a file the
    #: operator supplied — and the confidence already carries the feed's own
    #: declared strength and the indicator's age. It is excluded because of
    #: what the multiplier counts: independent **behaviours of a host**, on
    #: the argument that a machine doing several unrelated suspicious things
    #: is more likely compromised than one doing a single thing. An intel hit
    #: is not a second thing the host did. It is better information about the
    #: first thing, and confirmatory evidence belongs in the noisy-OR — where
    #: it still lands — and not in a count of behaviours.
    #:
    #: The failure mode that settles it: a feed that is stale, over-broad or
    #: simply wrong would otherwise become a queue-flooding weapon, doubling
    #: the priority of every host that touched anything in it. If intel hits
    #: later prove too weak in the queue, the lever is the finding's own
    #: confidence, not the behaviour count.
    non_corroborating: frozenset[Predicate] = frozenset(
        {
            Predicate.SHARES_INFRASTRUCTURE_WITH,
            Predicate.PRECEDES,
            Predicate.CONTACTS_RARE_DESTINATION,
            Predicate.TRANSFERS_ANOMALOUS_VOLUME,
            Predicate.PRESENTS_RARE_TLS_FINGERPRINT,
            Predicate.MATCHES_THREAT_INTEL,
        }
    )

    #: Predicates that contribute *nothing* to the arithmetic: neither a
    #: multiplier nor a term in the noisy-OR. Strictly narrower than
    #: `non_corroborating` above, and for a different reason.
    #:
    #: Everything in `non_corroborating` is still an observation about the
    #: world that VoidLexicon did not derive from its own output, so raising the
    #: incident's combined confidence with it is sound. `precedes` is not.
    #: The correlator mints it from findings that are *already inside the
    #: incident*, so admitting it to the noisy-OR would let an incident raise
    #: its own confidence by describing its own contents — a closed loop, and
    #: the more one behaviour is measured the tighter it winds. Five
    #: behaviours produce four `precedes` edges, each inheriting the
    #: confidence of a finding already counted.
    #:
    #: The original warning named the corroboration count,
    #: and `precedes` was already kept out of that. The same circularity runs
    #: through the noisy-OR, which is the half that had no guard — and it is
    #: the same argument `docs/benchmarks.md` §8 makes for keeping observed
    #: volume out of an intel score: VoidLexicon's own observation may not be
    #: reported as though it corroborated the thing it was derived from.
    #:
    #: This is not a discount on the claim. A `precedes` finding is asserted
    #: with the confidence of the weaker observation it orders and appears in
    #: the incident an analyst reads. Excluding it says only that an ordering
    #: is not evidence of compromise.
    non_evidential: frozenset[Predicate] = frozenset({Predicate.PRECEDES})

    def __post_init__(self) -> None:
        """Enforce the ladder the two sets encode between them.

        They are not two spellings of "does not count". They are three rungs:

          *corroborating* — an independent behaviour of the subject. Counts
            toward the multiplier and the noisy-OR. The default.
          *supporting* — a real observation, but not a second thing the subject
            did. `non_corroborating` only: noisy-OR, no multiplier.
          *derived* — not an observation at all, minted by the correlator from
            findings already counted. Both sets: neither term.

        Membership of the inner set without the outer would mean a finding that
        raises the multiplier while contributing no confidence — a predicate
        counted as an independent behaviour on the strength of evidence the
        arithmetic refuses to look at. Nothing enforced this until the ladder
        had a second rung to fall off, so it is enforced here rather than left
        to whoever adds the third.
        """
        stray = self.non_evidential - self.non_corroborating
        if stray:
            names = ", ".join(sorted(p.value for p in stray))
            raise ValueError(
                f"non_evidential must be a subset of non_corroborating; {names} "
                "would count toward the corroboration multiplier while "
                "contributing nothing to the confidence that justifies it"
            )

    #: Follow the object → unary-subject edge when forming incidents, so an
    #: intel hit joins the host that reached the address. See `_attach_unary`.
    attach_unary: bool = True

    #: Emit `precedes` between adjacent behaviours in an incident.
    order_behaviours: bool = True

    #: Separation, in seconds, below which two observations are not ordered.
    #:
    #: Timestamps come from sensors that disagree. Two log sources on one host
    #: can be seconds or hours apart, so how much separation is meaningful
    #: depends on whether the two observations share a clock — and that is
    #: checkable: every Evidence names its Artifacts, and every Artifact names
    #: its `source`. Two findings drawn from one source were written by one
    #: sensor and ordered by one clock, and a second is real. Across sources
    #: nothing is guaranteed, so the floor is five minutes and anything closer
    #: goes unsaid rather than being asserted and hedged.
    same_clock_min_separation_seconds: float = 1.0
    cross_clock_min_separation_seconds: float = 300.0


@dataclass
class RankedIncident:
    """An incident with the arithmetic behind its position in the queue."""

    incident: Incident
    #: The entity this incident is *about* — the host a responder works.
    #:
    #: Carried explicitly rather than read back off the findings. It used to
    #: be `findings[0].subject` with the findings sorted by confidence, which
    #: held only while every finding in an incident shared a subject. Unary
    #: attachment ends that: a `matches_threat_intel` finding keeps the
    #: indicator as its subject, so the first finding of a host's incident can
    #: be a proposition about an address in Bulgaria. The queue row, the hunt
    #: pivots, `rank_of` and the model brief all read this.
    subject: Entity
    priority: float
    combined_confidence: float
    corroborating_predicates: tuple[Predicate, ...]
    rationale: str


def _noisy_or(confidences: list[float]) -> float:
    """Combine independent evidence: the chance at least one is real.

    Standard noisy-OR. Two independent findings at 0.7 and 0.6 combine to
    0.88, because for both to be wrong each must independently be wrong.

    Applied to the strongest finding *per predicate* rather than to every
    finding. Twenty beaconing findings on one host are twenty views of the
    same behaviour, not twenty independent reasons to believe it — treating
    them as independent would let a chatty analyzer manufacture certainty.
    """
    survival = 1.0
    for confidence in confidences:
        survival *= 1.0 - min(max(confidence, 0.0), 1.0)
    return 1.0 - survival


def correlate(
    findings: list[Finding],
    config: CorrelationConfig | None = None,
) -> list[RankedIncident]:
    """Group findings by subject and order the result by priority.

    Three steps, in this order, because each needs the one before it settled:

    1. Group by subject. "What is this host doing?" is the unit a responder
       works in.
    2. Attach unary findings across the object → subject edge, so an intel hit
       joins the host that reached the indicator rather than standing alone.
    3. Order each incident's behaviours and emit `precedes` between adjacent
       ones. Membership has to be final first: an incident that gains an intel
       hit in step 2 has a different sequence to narrate.

    Deterministic, like everything upstream of the language layer: the same
    findings produce the same incidents in the same order.
    """
    config = config or CorrelationConfig()
    if not findings:
        return []

    by_subject: dict[str, list[Finding]] = {}
    subjects: dict[str, Entity] = {}
    for finding in findings:
        by_subject.setdefault(finding.subject.id, []).append(finding)
        subjects.setdefault(finding.subject.id, finding.subject)

    if config.attach_unary:
        by_subject = _attach_unary(by_subject, config)

    ranked = [
        _rank(subjects[key], subject_findings, config)
        for key, subject_findings in by_subject.items()
    ]
    # Ties broken by severity then subject id, so ordering is total and stable
    # across runs rather than dependent on dictionary insertion.
    ranked.sort(
        key=lambda r: (
            -r.priority,
            -(r.incident.severity.rank),
            r.incident.id,
        )
    )
    return ranked


def _rank(
    subject: Entity,
    findings: list[Finding],
    config: CorrelationConfig,
) -> RankedIncident:
    """Score one subject's findings into a priority."""
    if config.order_behaviours:
        findings = findings + _order_behaviours(findings, config)

    strongest: dict[Predicate, float] = {}
    for finding in findings:
        # Derived predicates never reach the arithmetic at all — not the
        # multiplier and not the noisy-OR. See `non_evidential`.
        if finding.predicate in config.non_evidential:
            continue
        current = strongest.get(finding.predicate, 0.0)
        strongest[finding.predicate] = max(current, finding.confidence)

    combined = _noisy_or(list(strongest.values()))

    corroborating = tuple(
        sorted(
            (p for p in strongest if p not in config.non_corroborating),
            key=lambda p: p.value,
        )
    )
    multiplier = min(
        1.0 + config.corroboration_bonus * max(len(corroborating) - 1, 0),
        config.max_corroboration_multiplier,
    )
    priority = combined * multiplier

    ordered = sorted(findings, key=lambda f: _finding_order(f, config))
    incident = Incident(
        findings=ordered,
        score=round(priority, 4),
        title=_title(subject, ordered, config),
    )

    return RankedIncident(
        incident=incident,
        subject=subject,
        priority=priority,
        combined_confidence=combined,
        corroborating_predicates=corroborating,
        rationale=_rationale(strongest, combined, multiplier, corroborating),
    )


def _finding_order(
    finding: Finding,
    config: CorrelationConfig,
) -> tuple[bool, float, float, str]:
    """Measured findings first by confidence, then derived ones in time order.

    Three terms, each earning its place.

    **Measured before derived.** A `precedes` finding inherits the confidence
    of the observation it orders, so on confidence alone it ties with the
    strongest thing in the incident and floats to the top of a display that
    shows four findings out of eleven — putting VoidLexicon's bookkeeping above the
    evidence. The language layer protects facts first when it runs out of
    budget, and an ordering is not a fact about the host.

    **Derived findings in the order they describe.** Sorting the chain by
    confidence scrambles it: every edge in a run of equally-confident
    behaviours ties, and the sequence has to be reassembled from the payloads
    by whoever reads it. The point of the predicate is that a reader can
    follow the incident in order, so the stored order *is* the sequence.
    Measured findings keep a sort time of zero and are unaffected.

    **A trailing finding id.** Ties on confidence are not rare — a generated
    domain family mints hundreds of names at an identical 1.0 — and with no
    total order the arrangement decides a content-addressed incident id.
    Reproducibility is a promise this project makes on its front page
    (engineering rule 12).
    """
    derived = finding.predicate in config.non_evidential
    when = (
        _utc(finding.first_seen).timestamp()
        if derived and finding.first_seen is not None
        else 0.0
    )
    return (derived, when, -finding.confidence, finding.id)


def _title(subject: Entity, findings: list[Finding], config: CorrelationConfig) -> str:
    """Name the incident after its subject and its most serious behaviour.

    Set here rather than left to `Incident._derive_title`, which counts
    distinct finding subjects and renders "2 hosts" when it finds more than
    one. That was right while an incident was one subject's findings; an
    attached intel finding keeps the indicator as its subject and would rename
    a host's incident on the strength of a proposition about an address.

    Derived findings are excluded from the choice of verb: an incident is not
    titled after its own bookkeeping.
    """
    measured = [f for f in findings if f.predicate not in config.non_evidential] or findings
    top = max(
        measured,
        key=lambda f: (f.severity.rank if f.severity else 0, f.confidence, f.id),
    )
    return f"{top.predicate.value.replace('_', ' ').title()} — {subject.value}"


def _attach_unary(
    by_subject: dict[str, list[Finding]],
    config: CorrelationConfig,
) -> dict[str, list[Finding]]:
    """Follow the object → unary-subject edge, so an intel hit joins its host.

    A unary predicate says something about a subject alone. `matches_threat_intel`
    is the one in service, and its subject is the *indicator*: the address or
    name that appeared in the operator's feed. Grouping by subject therefore
    files it under the address, and a host that beacons to a known-bad address
    reads as two incidents — the conjunction the corroboration multiplier
    exists to surface, and the single most actionable fact this system can
    produce, invisible.

    Four decisions, all settled before this was built rather than here:

    **Attach; do not re-subject.** `matches_threat_intel(ip:45.83.220.17)` is
    a true and well-formed proposition about the address. Rewriting it to take
    the host as subject would make it false — a host does not appear in a
    feed. So the finding moves and the sentence does not.

    **Attach to every incident naming the indicator.** Several hosts may have
    reached it, and each one's analyst needs to see it. This is the one place
    a finding legitimately appears in more than one incident.

    **A finding that attached anywhere does not also stand alone.** One that
    attached nowhere keeps its own incident: an indicator seen in traffic with
    no other finding against it is still worth reporting, just not worth
    promoting. And a group is dropped only when *nothing* anchors it — if the
    indicator is also an actor in this estate, with findings of its own, that
    incident survives and keeps the intel finding too, because it is a fact
    about that machine.

    **It does not corroborate.** `MATCHES_THREAT_INTEL` is in
    `non_corroborating`, and the reason is not partial evidence — see the
    comment there.
    """
    # Which incidents name each entity as the *object* of something. Only
    # non-unary findings have objects, so this is the whole of the edge.
    named_by: dict[str, set[str]] = {}
    for key, group in by_subject.items():
        for finding in group:
            if finding.object is not None:
                named_by.setdefault(finding.object.id, set()).add(key)

    attached: set[str] = set()
    additions: dict[str, list[Finding]] = {}
    for key, group in by_subject.items():
        for finding in group:
            if not finding.predicate.spec.is_unary():
                continue
            # Never to its own group: it is already there.
            targets = named_by.get(finding.subject.id, set()) - {key}
            if not targets:
                continue
            attached.add(finding.id)
            for target in sorted(targets):
                additions.setdefault(target, []).append(finding)

    result: dict[str, list[Finding]] = {}
    for key, group in by_subject.items():
        # An anchor is a finding that did not find a home elsewhere. A group
        # with none is an indicator whose every finding attached, and it no
        # longer stands alone.
        if not any(finding.id not in attached for finding in group):
            continue
        result[key] = group + additions.get(key, [])
    return result


def _order_behaviours(findings: list[Finding], config: CorrelationConfig) -> list[Finding]:
    """Emit `precedes` between adjacent behaviours, so a set becomes a sequence.

    One node per *behaviour*, not per finding. Twenty beaconing findings on
    one host are twenty views of one behaviour — the same reason the noisy-OR
    takes the strongest finding per predicate — and chaining them would emit
    nineteen edges saying a host beaconed before it beaconed. Each predicate
    is represented by its earliest finding, and adjacent representatives are
    linked.

    That is also the answer to rule 4. The chain is bounded by the vocabulary
    at seventeen edges per incident, whatever the traffic volume, so there is
    no `max_findings` to set: a busier capture cannot make it longer.

    A finding with no `first_seen` is dropped from the chain rather than
    placed at an assumed time. Ordering is the whole of what this predicate
    asserts, so with no timestamp the verb is unsayable — rule 6, and the same
    shape as `exfiltrates_to` on direction-blind NetFlow.
    """
    representatives: dict[Predicate, Finding] = {}
    for finding in findings:
        if finding.first_seen is None or finding.predicate in config.non_evidential:
            continue
        current = representatives.get(finding.predicate)
        if current is None or _earliest_key(finding) < _earliest_key(current):
            representatives[finding.predicate] = finding

    ordered = sorted(
        representatives.values(),
        # The predicate value breaks a timestamp tie, so two behaviours first
        # seen in the same second always chain the same way (rule 12).
        key=lambda f: (_utc(f.first_seen), f.predicate.value),
    )

    edges: list[Finding] = []
    for earlier, later in itertools.pairwise(ordered):
        edge = _precedes(earlier, later, config)
        if edge is not None:
            edges.append(edge)
    return edges


def _earliest_key(finding: Finding) -> tuple[datetime, float, str]:
    return (_utc(finding.first_seen), -finding.confidence, finding.id)


def _utc(moment: datetime | None) -> datetime:
    """Normalise to an aware UTC datetime so two findings can be subtracted.

    Every analyzer in the tree builds these with `tz=timezone.utc`, but a
    Finding is a public model and a naive timestamp would otherwise raise
    mid-run. A naive value is read as UTC, which is what the ingest layer
    means by a bare epoch anyway.
    """
    assert moment is not None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def _sources(finding: Finding) -> set[str]:
    return {a.source for e in finding.evidence for a in e.artifacts}


def _precedes(
    earlier: Finding,
    later: Finding,
    config: CorrelationConfig,
) -> Finding | None:
    """Assert that one behaviour was observed before another, or say nothing.

    Two reasons to decline. The separation may be inside the disagreement
    between the sensors that recorded it — see the thresholds on
    `CorrelationConfig` — in which case the order was not measured and is not
    claimed. Or both behaviours may pivot on the same entity, which makes the
    proposition an entity preceding itself; there is a real ordering there,
    but the Lexicon has no way to say it that a reader would not misread.

    Confidence is the *weaker* of the two findings ordered. An ordering claim
    cannot be better founded than the observations it orders: if the later
    behaviour is a 0.4 guess, "this came before that" is a 0.4 claim about a
    guess. It is not 1.0 — nobody measured a certainty — and it is not a
    geometric mean of invented components, which is the mistake the intel
    cluster names. The number never reaches a priority in any case; `precedes`
    is `non_evidential`.
    """
    # The entity that distinguishes a finding: its object, or its subject when
    # it has none. The same rule `hunt.queries.pivot_entities` uses, and for
    # the same reason — a unary finding carries its indicator on the subject.
    first = earlier.object if earlier.object is not None else earlier.subject
    second = later.object if later.object is not None else later.subject
    if first.id == second.id:
        return None

    separation = (_utc(later.first_seen) - _utc(earlier.first_seen)).total_seconds()
    sources = sorted(_sources(earlier) | _sources(later))
    shared_clock = len(sources) == 1
    floor = (
        config.same_clock_min_separation_seconds
        if shared_clock
        else config.cross_clock_min_separation_seconds
    )
    if separation < floor:
        return None

    clock = (
        f"one sensor ({sources[0]})"
        if shared_clock
        else f"separate sources ({', '.join(sources)})"
    )
    confidence = min(earlier.confidence, later.confidence)

    evidence = Evidence(
        kind="temporal_order",
        summary=(
            f"{earlier.predicate.value} first observed {separation:.1f} s before "
            f"{later.predicate.value}, from {clock}"
        ),
        payload={
            "earlier_finding": earlier.id,
            "earlier_predicate": earlier.predicate.value,
            "earlier_first_seen": _utc(earlier.first_seen).isoformat(),
            "later_finding": later.id,
            "later_predicate": later.predicate.value,
            "later_first_seen": _utc(later.first_seen).isoformat(),
            # The separation and the floor it cleared, so a reader can judge
            # the order for themselves rather than take it on trust. The
            # design calls for exactly this: sensors disagree, and how much
            # they may disagree is the reader's call as much as ours.
            "separation_seconds": round(separation, 1),
            "min_separation_seconds": floor,
            "shared_clock": shared_clock,
            "sources": sources,
        },
        artifacts=_edge_artifacts(earlier, later),
    )

    return Finding(
        predicate=Predicate.PRECEDES,
        subject=first,
        object=second,
        evidence=[evidence],
        confidence=confidence,
        basis=(
            f"{earlier.predicate.value} first observed {separation:.1f} s before "
            f"{later.predicate.value}, above the {floor:.0f} s floor for {clock}; "
            f"confidence bounded by the weaker of the two findings ordered "
            f"({confidence:.2f})"
        ),
        analyzer=CORRELATOR,
        first_seen=_utc(earlier.first_seen),
        last_seen=_utc(later.first_seen),
    )


def _edge_artifacts(earlier: Finding, later: Finding) -> list[Artifact]:
    """One artifact from each side: where the two timestamps came from.

    Not every artifact behind both findings. An ordering rests on two moments,
    and a beaconing finding can carry thousands of flow records that say
    nothing further about which came first.
    """
    artifacts: list[Artifact] = []
    seen: set[str] = set()
    for finding in (earlier, later):
        for evidence in finding.evidence:
            for artifact in evidence.artifacts:
                if artifact.id not in seen:
                    seen.add(artifact.id)
                    artifacts.append(artifact)
                break
            break
    return artifacts


def _rationale(
    strongest: dict[Predicate, float],
    combined: float,
    multiplier: float,
    corroborating: tuple[Predicate, ...],
) -> str:
    """Explain the priority in one checkable line.

    Same rule as a Finding's `basis`: a score an analyst cannot audit is a
    score they have no reason to trust.
    """
    parts = ", ".join(
        f"{predicate.value}={confidence:.2f}"
        for predicate, confidence in sorted(strongest.items(), key=lambda kv: kv[0].value)
    )
    if len(corroborating) > 1:
        corroboration = (
            f"; {len(corroborating)} independent behaviours corroborate "
            f"(x{multiplier:.1f})"
        )
    else:
        corroboration = "; single behaviour, no corroboration"
    return f"noisy-OR of [{parts}] = {combined:.3f}{corroboration}"


@dataclass
class IncidentQueue:
    """The analyst-facing result of a run."""

    incidents: list[RankedIncident] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.incidents)

    def top(self, count: int) -> list[RankedIncident]:
        return self.incidents[:count]

    def rank_of(self, subject_value: str) -> int | None:
        """1-based position of a subject, or None if absent.

        The measure that matters for the benchmark: a true positive at rank 3
        gets worked, and the same true positive at rank 358 does not.
        """
        for position, ranked in enumerate(self.incidents, start=1):
            if ranked.subject.value == subject_value:
                return position
        return None

    @property
    def corroborated(self) -> list[RankedIncident]:
        return [r for r in self.incidents if len(r.corroborating_predicates) > 1]

    def severity_counts(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {}
        for ranked in self.incidents:
            counts[ranked.incident.severity] = counts.get(ranked.incident.severity, 0) + 1
        return counts


def build_queue(
    findings: list[Finding],
    config: CorrelationConfig | None = None,
) -> IncidentQueue:
    return IncidentQueue(incidents=correlate(findings, config))
