"""Threat intel: the join, and what a join is allowed to claim.

Every other analyzer in this package measures something. This one does not.
It asks whether an address, a name or a hash the estate touched appears in a
list the operator put on disk, and a list membership is *binary* — the value
is in the file or it is not.

That difference decides the whole design, and getting it wrong is the obvious
trap. There is a weighted geometric mean in `beaconing.py`, in `egress.py`,
in `fanout.py` and in `alerts.py`, and the temptation is to manufacture one
here so this analyzer looks like its neighbours: score the match on how many
flows carried it, how rare the destination is, how long the conversation ran.
Every one of those numbers is real, and not one of them is evidence about
whether the indicator is *true*. A host that contacted a known C2 once and a
host that contacted it four thousand times have the same intelligence backing
them. Letting volume raise the score would be reporting VoidLexicon's own
observation as though it corroborated the feed's claim, which is the same
circularity `precedes` is kept out of the corroboration count to prevent.

## So where does confidence come from

From properties of the *feed*, and only from those:

    declared confidence   what the feed says it knows. Absent → unprovenanced,
                          which scores low. Not a default, not a midpoint
    age                   how stale the indicator was **at the moment the
                          traffic was seen**, decayed on a half-life

Nothing about the observation enters the number. The observation decides
*whether* there is a finding; the feed decides how much it is worth.

## Stale intel is worse than none

An indicator from 2019 firing on a residential address reassigned three years
ago is a false positive with a citation attached, and a citation is the thing
an analyst is least likely to re-check. Age is therefore not advisory
metadata: it is a multiplier, on a half-life, with a hard cut beyond
`max_age_days`. A 0.85-confidence indicator two years old lands at 0.07 and is
dropped by the confidence floor before it can be written down.

Age is measured against the capture's own timestamps rather than against the
clock. Two reasons, and the second is the load-bearing one:

*It is the right question.* What matters is how stale the indicator was when
the traffic happened, not how stale it is now that someone is reading.

*Identity must be reproducible.* Every ID in the Lexicon is content-addressed
(`lexicon/ids.py`), so `age_days` in an evidence payload derived from
`datetime.now()` would give the same run a different evidence ID every day,
and last week's citations would resolve to nothing.

## Provenance that is missing is not provenance that is zero

`docs/engineering-rules.md` rule 6, applied to a component that is not a statistic. A
feed that declares no confidence has not declared low confidence — it has
declared nothing — and the honest reading is that the claim cannot be a strong
one. So an unprovenanced feed scores at `unprovenanced_confidence`, and an
indicator whose age is *unknown* has its confidence **capped** at
`max_confidence_without_age` rather than multiplied by an invented decay. A
cap says "this cannot be asserted strongly". A substituted age would say "this
is fresh", which nobody measured.

Severity is capped at MEDIUM for the same reason `alerts.py` caps its own: a
list membership is corroborating evidence, not a conclusion, and a file an
operator dropped in a directory must not be able to outrank VoidLexicon's
measurements.

## `shares_infrastructure_with`

The graph half. Two names resolving to one address, or two flagged addresses
inside one netblock, are linked — and the link is emitted **only when one end
is already an intel match**. Ungated, this predicate is an O(n²) description
of shared hosting: every pair of domains behind one CDN address becomes a
finding, and the analyst learns that Akamai exists. Anchored to an indicator
it answers the question actually worth asking — *what else in this capture
sits on the infrastructure we already know is bad* — and stays bounded by the
number of matches rather than by the size of the capture.

It is INFO severity and already carries a seat in
`CorrelationConfig.non_corroborating`: it describes the environment, not a
second thing the host did.

## What is not matched

URL and file-hash indicators are parsed, indexed and counted, and nothing in
this repository can match them yet — there is no HTTP log parser and no
process telemetry until the host and inventory work landed. They are loaded anyway,
because the alternative is a parser that misreads them as domains, and
`voidai doctor` reports them as inert so an operator is told rather than left
to assume.

## Validation

Synthetic, and labelled as such wherever a number from it appears. The
correctness question here is integration — does a documented file format
reach a grammatical finding with its provenance intact — and a fixture with a
handful of indicators answers it. There is no detection rate to measure: the
detection was performed by whoever wrote the feed.

No language model is involved at any point. Nothing here opens a socket.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import TypeVar

import networkx as nx
import polars as pl

from voidai.analyzers.base import AnalysisContext, BaseAnalyzer
from voidai.ingest.ioc import DomainMatch, Indicator, IndicatorKind, IndicatorSet
from voidai.lexicon import Artifact, Entity, EntityType, Evidence, Finding, Predicate, Severity

_ENTITY_TYPE = {
    IndicatorKind.IP: EntityType.IP,
    # A network is not an entity in the Lexicon, and inventing one would be a
    # grammar change. The subject of a CIDR match is the address that was
    # actually observed; the block is recorded as the reason in the payload.
    IndicatorKind.CIDR: EntityType.IP,
    IndicatorKind.DOMAIN: EntityType.DOMAIN,
    IndicatorKind.URL: EntityType.URL,
    IndicatorKind.FILE_HASH: EntityType.FILE_HASH,
}

#: What `_fold` resolves a value into — an `Indicator` for addresses, a
#: `DomainMatch` for names. The fold does not care which; it only needs to know
#: that `None` means "no indicator caught this", so the value can be dropped
#: before a Python object is built for it.
_MatchT = TypeVar("_MatchT")


@dataclass(frozen=True)
class IntelConfig:
    """Tunables. Every one of them is about provenance, not about traffic."""

    #: Confidence for a match against a feed that declared none. Low, and
    #: deliberately below `medium_threshold`, so an unprovenanced list can
    #: enrich an incident but cannot raise one to MEDIUM on its own.
    unprovenanced_confidence: float = 0.25
    #: Ceiling on a match whose indicator carries no date. A cap, not a
    #: substituted age: it says the claim cannot be made strongly, where a
    #: default age would say the indicator is fresh.
    max_confidence_without_age: float = 0.35

    #: Days over which a dated indicator loses half its confidence. Six months
    #: is set from the shape of the problem — the observed half-life of a
    #: rented C2 address is far shorter, and of a malware hash far longer —
    #: and is marked as unmeasured in `docs/benchmarks.md`.
    half_life_days: float = 180.0
    #: Age beyond which an indicator is not reported at all, whatever it
    #: declares. The decay alone would push it under the floor; the explicit
    #: cut exists so the rule can be read off the configuration.
    max_age_days: float = 730.0

    #: Confidence below which a match is dropped rather than written down.
    min_confidence: float = 0.10
    #: Confidence at or above which the finding is MEDIUM rather than LOW.
    #: Never higher: see the module docstring.
    medium_threshold: float = 0.50

    #: Cap on `matches_threat_intel` findings, over all indicators.
    #: `max_infrastructure_findings` caps the link predicate separately, so
    #: the two bands cannot crowd each other out — the analyzer's own ceiling
    #: is the sum.
    max_findings: int = 200
    #: Observations reported for one indicator. A `/16` in a feed can contain
    #: hundreds of observed addresses, and an analyst needs the largest few
    #: plus the true count, not one finding per address.
    max_per_indicator: int = 10
    #: Observed values named in the evidence payload of one finding.
    max_observed_samples: int = 5
    artifact_samples: int = 3

    #: Domains on one address, above which shared resolution is hosting rather
    #: than infrastructure. Five is generous for a dedicated host and far
    #: below what a CDN address carries.
    max_domains_per_address: int = 5
    #: Prefix length at which two flagged addresses count as one netblock.
    netblock_prefix: int = 24
    max_infrastructure_findings: int = 50


@dataclass
class IntelScore:
    """What one match is worth, and why.

    `components` holds the two inputs rather than weighted scores, because
    there is no weighting: the confidence is a product of a declared value and
    a decay, and an analyst checking it should see both factors.
    """

    confidence: float
    indicator: Indicator
    #: Days between the indicator being recorded and the traffic being seen.
    #: `None` means the indicator carried no date at all.
    age_days: float | None
    provenanced: bool
    base_confidence: float
    decay: float | None
    capped_for_unknown_age: bool

    def basis(self) -> str:
        feed = self.indicator.feed
        if self.provenanced:
            source = f"feed {feed.name!r} declares confidence {self.base_confidence:.2f}"
        else:
            source = (
                f"feed {feed.name!r} declares no confidence; unprovenanced "
                f"indicators score {self.base_confidence:.2f}"
            )
        if self.age_days is None:
            age = (
                "indicator carries no date, so freshness is unmeasured and the "
                f"confidence is capped at {self.confidence:.2f}"
                if self.capped_for_unknown_age
                else "indicator carries no date, so no decay was applied"
            )
        else:
            age = (
                f"recorded {self.age_days:.0f} day(s) before this traffic was "
                f"observed (x{self.decay:.2f} on a half-life)"
            )
        return f"{source}; {age}. No property of the observed traffic enters this score."


def score_match(
    indicator: Indicator,
    observed_at: float | None,
    config: IntelConfig,
) -> IntelScore | None:
    """Score one indicator match from the feed's provenance alone.

    `observed_at` is an epoch timestamp from the capture, not the clock — the
    age that matters is the indicator's age when the traffic happened, and a
    wall-clock reading would make every evidence ID change daily.

    Returns `None` when the indicator is too old to report or the resulting
    confidence falls under the floor.
    """
    declared = indicator.declared_confidence
    provenanced = declared is not None
    base = declared if declared is not None else config.unprovenanced_confidence

    age_days = _age_in_days(indicator.added, observed_at)
    if age_days is not None and age_days > config.max_age_days:
        return None

    if age_days is None:
        decay = None
        confidence = min(base, config.max_confidence_without_age)
        capped = confidence < base
    else:
        decay = 0.5 ** (age_days / config.half_life_days)
        confidence = base * decay
        capped = False

    if confidence < config.min_confidence:
        return None

    return IntelScore(
        confidence=confidence,
        indicator=indicator,
        age_days=age_days,
        provenanced=provenanced,
        base_confidence=base,
        decay=decay,
        capped_for_unknown_age=capped,
    )


def _age_in_days(added: date | None, observed_at: float | None) -> float | None:
    """Days from the indicator being recorded to the traffic being observed.

    `None` when either end is unknown. Negative ages — an indicator added
    after the capture, which happens whenever a feed is refreshed between the
    capture and the analysis — are clamped to zero rather than rewarded: an
    indicator cannot be fresher than new.
    """
    if added is None or observed_at is None:
        return None
    observed = datetime.fromtimestamp(observed_at, tz=timezone.utc).date()
    return max(0.0, float((observed - added).days))


@dataclass(frozen=True)
class _Observation:
    """One value the capture contained, and the scalars describing it."""

    value: str
    events: int
    peers: int
    first_ts: float
    last_ts: float
    #: Where the value was seen: as a connection or alert destination (`dst`),
    #: as a source (`src`), as a DNS answer (`answer`), or as a queried name
    #: (`query`). Carried into the payload because it is the first thing an
    #: analyst needs from a match and the finding cannot otherwise say it: an
    #: indicator hit on `src` is a host of ours in someone's feed, which is a
    #: different morning from a host of ours having contacted one.
    roles: tuple[str, ...]


class ThreatIntelAnalyzer(BaseAnalyzer):
    """Emits `matches_threat_intel` and `shares_infrastructure_with`."""

    name = "intel"
    version = "0.1.0"

    def __init__(self, config: IntelConfig | None = None) -> None:
        self.config = config or IntelConfig()

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        """Two passes, neither materialising the capture.

        Pass one reduces each telemetry source to one row per distinct value
        with scalars only — event count, distinct peers, first and last
        timestamp. The join then runs in Python over those distinct values,
        which number in the hundreds of thousands at worst where the flows
        number in the tens of millions.

        Pass two gathers artifact locators by semi-joining the scan against
        the handful of values actually being reported.
        """
        indicators = ctx.indicators
        if indicators is None or indicators.is_empty():
            return []

        matched_addresses = self._match_addresses(ctx, indicators)
        matched_domains = self._match_domains(ctx, indicators)
        if not matched_addresses and not matched_domains:
            return []

        artifacts = self._collect_artifacts(ctx, matched_addresses, matched_domains)

        findings = self._intel_findings(matched_addresses, matched_domains, artifacts)
        findings.sort(key=lambda f: (-f.confidence, f.subject.value))
        findings = findings[: self.config.max_findings]

        findings += self._infrastructure_findings(
            ctx, matched_addresses, matched_domains, artifacts
        )
        return findings

    # Pass 1: distinct observed values, scalars only

    def _address_frames(self, ctx: AnalysisContext) -> list[pl.DataFrame]:
        """Per-source summaries of every distinct address in the capture.

        Sources are read in both directions. An operator's indicator list is
        not only external infrastructure — a list of known-compromised
        internal assets is the same file — so matching destinations alone
        would silently ignore half of what an operator writes down.
        """
        frames: list[pl.DataFrame] = []
        for scan in (ctx.connection_scan(), ctx.alert_scan()):
            available = set(scan.collect_schema().names())
            for column, peer, role in (("dst_ip", "src_ip", "dst"), ("src_ip", "dst_ip", "src")):
                if not {column, peer, "ts"} <= available:
                    continue
                frames.append(self._value_summary(scan, column, peer, role))

        answers = self._dns_answer_addresses(ctx)
        if answers is not None:
            frames.append(answers)
        return frames

    def _domain_frames(self, ctx: AnalysisContext) -> list[pl.DataFrame]:
        """A summary of every distinct name queried, from DNS."""
        scan = ctx.dns_scan()
        available = set(scan.collect_schema().names())
        if not {"query", "ts"} <= available:
            return []
        peer = "src_ip" if "src_ip" in available else "query"
        return [self._value_summary(scan, "query", peer, "query")]

    def _value_summary(
        self,
        scan: pl.LazyFrame,
        column: str,
        peer: str,
        role: str,
    ) -> pl.DataFrame:
        """One row per distinct value, carrying only scalars.

        No list columns and no arrays: the locators needed to cite a match are
        gathered in pass two, for the few values actually reported.
        """
        return (
            scan.drop_nulls(subset=[column, "ts"])
            .group_by(column)
            .agg(
                pl.len().alias("events"),
                pl.col(peer).n_unique().alias("peers"),
                pl.col("ts").min().alias("first_ts"),
                pl.col("ts").max().alias("last_ts"),
            )
            .rename({column: "value"})
            .with_columns(pl.lit(role).alias("role"))
            .collect(engine="streaming")
        )

    def _dns_answer_addresses(self, ctx: AnalysisContext) -> pl.DataFrame | None:
        """Addresses a name resolved to, from the joined `answers` column.

        `answers` is stored flat and semicolon-joined for cheap columnar work,
        so it is split and exploded here. A CNAME chain puts names in the same
        column as addresses; the non-address entries simply match nothing.
        """
        scan = ctx.dns_scan()
        available = set(scan.collect_schema().names())
        if not {"answers", "ts", "query"} <= available:
            return None

        exploded = (
            scan.drop_nulls(subset=["answers", "ts"])
            .with_columns(pl.col("answers").str.split(";").alias("answer"))
            # Pinned rather than left to the default, which changes in Polars
            # 2.0. A record with no answers must drop out, not become a null
            # row that later filters count as an observation.
            .explode("answer", empty_as_null=True)
            .with_columns(pl.col("answer").str.strip_chars())
            .filter(pl.col("answer").str.len_chars() > 0)
        )
        return self._value_summary(exploded, "answer", "query", "answer")

    @staticmethod
    def _fold(
        frames: list[pl.DataFrame],
        resolve: Callable[[str], _MatchT | None],
    ) -> list[tuple[_MatchT, _Observation]]:
        """Fold per-source summaries into one entry per *matched* value.

        The join runs inside the fold rather than after it, and that is a
        memory decision rather than a stylistic one. A capture with 200,000
        distinct destinations against a feed of 700 indicators would otherwise
        build 200,000 Python objects in order to discard all but a few hundred:
        measured at 48.5 MB of Python allocation against 0.1 MB for the same
        work filtered here.

        That is the part this code controls. The dominant cost of the pass is
        the streaming `group_by` above it — 254 MB on a three-million-flow
        frame at this cardinality, the same figure `egress.py` pays for the
        same operation — and no arrangement of this loop changes it. Rule 2
        holds only while each analyzer individually behaves, so the part that
        *is* controllable is kept bounded by the match count rather than by
        the size of the capture.
        """
        merged: dict[str, tuple[_MatchT, _Observation]] = {}
        for frame in frames:
            if frame.is_empty():
                continue
            for row in frame.iter_rows(named=True):
                value = str(row["value"]).strip()
                if not value:
                    continue
                existing = merged.get(value)
                if existing is None:
                    match = resolve(value)
                    if match is None:
                        continue
                    merged[value] = (
                        match,
                        _Observation(
                            value=value,
                            events=int(row["events"]),
                            peers=int(row["peers"]),
                            first_ts=float(row["first_ts"]),
                            last_ts=float(row["last_ts"]),
                            roles=(str(row["role"]),),
                        ),
                    )
                    continue
                match, observation = existing
                merged[value] = (
                    match,
                    _Observation(
                        value=value,
                        events=observation.events + int(row["events"]),
                        peers=max(observation.peers, int(row["peers"])),
                        first_ts=min(observation.first_ts, float(row["first_ts"])),
                        last_ts=max(observation.last_ts, float(row["last_ts"])),
                        roles=tuple(sorted(set(observation.roles) | {str(row["role"])})),
                    ),
                )
        return list(merged.values())

    # The join

    # The join

    def _match_addresses(
        self,
        ctx: AnalysisContext,
        indicators: IndicatorSet,
    ) -> dict[str, list[tuple[_Observation, IntelScore]]]:
        """Group address matches by the indicator that caught them.

        Keyed by indicator rather than by address so that a network indicator
        producing two hundred observed addresses becomes one capped finding
        set carrying a true count, instead of two hundred findings.
        """
        grouped: dict[str, list[tuple[_Observation, IntelScore]]] = {}
        for indicator, observation in self._fold(
            self._address_frames(ctx), indicators.match_address
        ):
            score = score_match(indicator, observation.first_ts, self.config)
            if score is None:
                continue
            grouped.setdefault(_indicator_key(indicator), []).append((observation, score))
        return grouped

    def _match_domains(
        self,
        ctx: AnalysisContext,
        indicators: IndicatorSet,
    ) -> dict[str, tuple[DomainMatch, list[tuple[_Observation, IntelScore]]]]:
        """Group name matches by indicator, keeping exact and parent apart.

        A parent-domain indicator catching forty subdomains is one fact about
        one zone. Collapsing it here is what stops a single wildcarded entry
        in a feed from filling the queue by itself.
        """
        grouped: dict[str, tuple[DomainMatch, list[tuple[_Observation, IntelScore]]]] = {}
        for match, observation in self._fold(
            self._domain_frames(ctx), indicators.match_domain
        ):
            score = score_match(match.indicator, observation.first_ts, self.config)
            if score is None:
                continue
            key = _indicator_key(match.indicator)
            if key not in grouped:
                grouped[key] = (match, [])
            grouped[key][1].append((observation, score))
        return grouped

    # Pass 2: locators    # Pass 2: locators, for reported values only

    def _collect_artifacts(
        self,
        ctx: AnalysisContext,
        addresses: dict[str, list[tuple[_Observation, IntelScore]]],
        domains: dict[str, tuple[DomainMatch, list[tuple[_Observation, IntelScore]]]],
    ) -> dict[str, list[Artifact]]:
        """Gather source locators for the values being reported, and only those.

        Every source is restricted by a semi-join against the reported values
        before any row-level column is touched, so the list columns hold a few
        hundred rows rather than the capture.
        """
        wanted_addresses = {
            observation.value
            for entries in addresses.values()
            for observation, _ in entries
        }
        wanted_domains = {
            observation.value
            for _, entries in domains.values()
            for observation, _ in entries
        }
        collected: dict[str, list[Artifact]] = {}

        for scan, columns in (
            (ctx.connection_scan(), ("dst_ip", "src_ip")),
            (ctx.alert_scan(), ("dst_ip", "src_ip")),
            (ctx.dns_scan(), ("query",)),
        ):
            available = set(scan.collect_schema().names())
            for column in columns:
                wanted = wanted_domains if column == "query" else wanted_addresses
                self._gather(scan, available, column, wanted, collected)

        return collected

    def _gather(
        self,
        scan: pl.LazyFrame,
        available: set[str],
        column: str,
        wanted: set[str],
        into: dict[str, list[Artifact]],
    ) -> None:
        if not wanted or not {column, "ts"} <= available:
            return
        if not {"source_file", "source_line"} <= available:
            return

        keys = pl.LazyFrame({column: sorted(wanted)}, schema={column: pl.Utf8})
        rows = (
            scan.drop_nulls(subset=[column, "ts"])
            .join(keys, on=column, how="semi")
            .group_by(column)
            .agg(
                pl.col("source_file").head(self.config.artifact_samples),
                pl.col("source_line").head(self.config.artifact_samples),
                pl.col("ts").head(self.config.artifact_samples),
            )
            .collect(engine="streaming")
        )

        for row in rows.iter_rows(named=True):
            value = str(row[column])
            bucket = into.setdefault(value, [])
            if len(bucket) >= self.config.artifact_samples:
                continue
            files, lines, stamps = row["source_file"], row["source_line"], row["ts"]
            for index in range(min(len(lines), self.config.artifact_samples)):
                bucket.append(
                    Artifact(
                        source=str(files[index]) if files[index] else "<unknown>",
                        locator=f"line:{lines[index]}",
                        observed_at=datetime.fromtimestamp(float(stamps[index]), tz=timezone.utc),
                        excerpt=f"{column}={value}",
                    )
                )

    def _artifacts_for(self, value: str, collected: dict[str, list[Artifact]]) -> list[Artifact]:
        """Locators for one value, or an aggregate pointer if none survived.

        A Finding with no Artifact is rejected at construction, and a source
        without `source_file` columns is a real deployment rather than a bug —
        so the fallback names the aggregation instead of dropping the finding.
        """
        found = collected.get(value)
        if found:
            return found[: self.config.artifact_samples]
        return [Artifact(source="<aggregate>", locator=f"value:{value}")]

    # Findings

    def _intel_findings(
        self,
        addresses: dict[str, list[tuple[_Observation, IntelScore]]],
        domains: dict[str, tuple[DomainMatch, list[tuple[_Observation, IntelScore]]]],
        artifacts: dict[str, list[Artifact]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for entries in addresses.values():
            # Largest first: an analyst checking a network indicator wants the
            # addresses that carried the traffic, not the first ones sorted.
            ranked = sorted(entries, key=lambda pair: (-pair[0].events, pair[0].value))
            for observation, score in ranked[: self.config.max_per_indicator]:
                findings.append(
                    self._build_finding(
                        subject=Entity(
                            type=_ENTITY_TYPE[score.indicator.kind], value=observation.value
                        ),
                        score=score,
                        observations=[observation],
                        total_observed=len(entries),
                        exact=score.indicator.kind is IndicatorKind.IP,
                        artifacts=self._artifacts_for(observation.value, artifacts),
                    )
                )

        for match, entries in domains.values():
            ranked = sorted(entries, key=lambda pair: (-pair[0].events, pair[0].value))
            score = ranked[0][1]
            if match.exact:
                observation = ranked[0][0]
                subject = Entity(type=EntityType.DOMAIN, value=observation.value)
                cited = [observation]
            else:
                # One finding about the zone, not one per subdomain beneath it.
                subject = Entity(type=EntityType.DOMAIN, value=match.indicator.value)
                cited = [observation for observation, _ in ranked]
            findings.append(
                self._build_finding(
                    subject=subject,
                    score=score,
                    observations=cited,
                    total_observed=len(entries),
                    exact=match.exact,
                    artifacts=self._artifacts_for(cited[0].value, artifacts),
                )
            )

        return findings

    def _build_finding(
        self,
        subject: Entity,
        score: IntelScore,
        observations: list[_Observation],
        total_observed: int,
        exact: bool,
        artifacts: list[Artifact],
    ) -> Finding:
        indicator = score.indicator
        feed = indicator.feed
        first_seen = min(o.first_ts for o in observations)
        last_seen = max(o.last_ts for o in observations)
        events = sum(o.events for o in observations)
        peers = max(o.peers for o in observations)
        samples = [o.value for o in observations][: self.config.max_observed_samples]

        roles = tuple(sorted({role for observation in observations for role in observation.roles}))
        evidence = Evidence(
            kind="intel_match",
            summary=(
                f"{subject.type.value} {subject.value} "
                f"{'is' if exact else 'matches'} indicator {indicator.value!r} "
                f"from feed {feed.name!r}; observed as {'/'.join(roles)} "
                f"on {events} record(s) across {peers} peer(s)"
            ),
            payload={
                "indicator": indicator.value,
                "indicator_kind": indicator.kind.value,
                "match": "exact" if exact else _inexact_kind(indicator.kind),
                "feed": feed.name,
                "feed_path": feed.path,
                "feed_reference": feed.reference,
                "feed_tlp": feed.tlp,
                "declared_confidence": indicator.declared_confidence,
                "provenanced": score.provenanced,
                "indicator_added": indicator.added.isoformat() if indicator.added else None,
                # Days between the indicator being recorded and this traffic.
                # Null means the feed dated nothing — which is why the
                # confidence above is capped rather than decayed.
                "age_days": score.age_days,
                "age_decay": round(score.decay, 4) if score.decay is not None else None,
                "note": indicator.note,
                "observed_values": samples,
                "observed_value_count": total_observed,
                "observed_as": list(roles),
                "records": events,
                "distinct_peers": peers,
                "span_seconds": round(last_seen - first_seen, 1),
                "indicator_source": f"{indicator.source_file}:{indicator.source_line}",
            },
            artifacts=artifacts,
        )

        return Finding(
            predicate=Predicate.MATCHES_THREAT_INTEL,
            subject=subject,
            evidence=[evidence],
            confidence=round(score.confidence, 4),
            basis=score.basis(),
            # Capped at MEDIUM on purpose. A list membership is corroborating
            # evidence, not a conclusion, and a file dropped into a directory
            # must not outrank a measurement.
            severity=(
                Severity.MEDIUM
                if score.confidence >= self.config.medium_threshold
                else Severity.LOW
            ),
            analyzer=self.qualname,
            first_seen=datetime.fromtimestamp(first_seen, tz=timezone.utc),
            last_seen=datetime.fromtimestamp(last_seen, tz=timezone.utc),
        )

    # The graph half

    def _infrastructure_findings(
        self,
        ctx: AnalysisContext,
        addresses: dict[str, list[tuple[_Observation, IntelScore]]],
        domains: dict[str, tuple[DomainMatch, list[tuple[_Observation, IntelScore]]]],
        artifacts: dict[str, list[Artifact]],
    ) -> list[Finding]:
        """Link what the capture shows to what the feed already flagged.

        Two rules keep this from restating the operator's own file back to
        them, and both were written after reading the output without them.

        *Anchored.* An edge is emitted only where one end is an intel match.
        Ungated, this predicate is an O(n²) description of shared hosting:
        every pair of names behind one CDN address becomes a finding and the
        analyst learns that CDNs exist.

        *Cross-indicator.* Two values matched by the **same** indicator are
        never linked to each other. Five addresses inside one `/24` entry do
        share infrastructure — that is what the operator wrote down — and
        reporting it back as a discovery is noise with a citation. The link
        worth having is the one that crosses: an unflagged name on a flagged
        address, or two addresses flagged by different entries that turn out
        to sit in one block.
        """
        flagged_addresses = {
            observation.value: (score, key)
            for key, entries in addresses.items()
            for observation, score in entries
        }
        flagged_domains: dict[str, tuple[IntelScore, str]] = {}
        for key, (_, entries) in domains.items():
            for observation, score in entries:
                flagged_domains[observation.value] = (score, key)
        if not flagged_addresses and not flagged_domains:
            return []

        graph = nx.Graph()
        for address, names in self._shared_resolutions(ctx).items():
            self._link_resolution(graph, address, names, flagged_addresses, flagged_domains)
        self._link_netblocks(graph, flagged_addresses)

        findings = [
            self._build_link_finding(left, right, data, artifacts)
            for left, right, data in graph.edges(data=True)
        ]
        findings.sort(
            key=lambda f: (-f.confidence, f.subject.value, f.object.value if f.object else "")
        )
        return findings[: self.config.max_infrastructure_findings]

    def _link_resolution(
        self,
        graph: nx.Graph,
        address: str,
        names: list[str],
        flagged_addresses: dict[str, tuple[IntelScore, str]],
        flagged_domains: dict[str, tuple[IntelScore, str]],
    ) -> None:
        """Edges through one address that several names resolve to.

        A flagged *address* anchors the link itself — the claim is that these
        names sit on known-bad infrastructure, and the address is the
        infrastructure, so it is the subject rather than an arbitrary one of
        the names. Otherwise a flagged *name* anchors, and one anchor is taken
        per indicator so that two subdomains of one flagged zone do not each
        emit an edge to the same neighbour.
        """
        anchored_address = flagged_addresses.get(address)
        if anchored_address is not None:
            score, key = anchored_address
            for name in names:
                if flagged_domains.get(name, (None, None))[1] == key:
                    continue
                graph.add_edge(
                    address,
                    name,
                    reason="shared_resolution",
                    via=address,
                    breadth=len(names),
                    anchor=address,
                    anchor_type=EntityType.IP,
                    other_type=EntityType.DOMAIN,
                    score=score,
                )
            return

        anchors: dict[str, str] = {}
        for name in names:
            flagged = flagged_domains.get(name)
            if flagged is not None:
                anchors.setdefault(flagged[1], name)

        for key, anchor in anchors.items():
            for name in names:
                if name == anchor or flagged_domains.get(name, (None, None))[1] == key:
                    continue
                graph.add_edge(
                    anchor,
                    name,
                    reason="shared_resolution",
                    via=address,
                    breadth=len(names),
                    anchor=anchor,
                    anchor_type=EntityType.DOMAIN,
                    other_type=EntityType.DOMAIN,
                    score=flagged_domains[anchor][0],
                )

    def _link_netblocks(
        self,
        graph: nx.Graph,
        flagged: dict[str, tuple[IntelScore, str]],
    ) -> None:
        """Flagged addresses sharing a netblock, where the indicators differ.

        Bounded by the number of matches rather than by the capture, and
        restricted to pairs caught by *different* entries: a block of five
        addresses all matched by one `/24` line is that line, not a finding.
        """
        blocks: dict[str, list[str]] = {}
        for address in flagged:
            try:
                network = ipaddress.ip_network(
                    f"{address}/{self.config.netblock_prefix}", strict=False
                )
            except ValueError:
                continue
            if network.version != 4:
                # The prefix length is an IPv4 convention. Applying /24 to
                # IPv6 would group unrelated allocations.
                continue
            blocks.setdefault(str(network), []).append(address)

        for prefix, members in blocks.items():
            ordered = sorted(members, key=ipaddress.ip_address)
            # One anchor per indicator, lowest address first, so a block holds
            # at most one edge per pair of distinct entries.
            anchors: dict[str, str] = {}
            for address in ordered:
                anchors.setdefault(flagged[address][1], address)
            for key, anchor in anchors.items():
                for address in ordered:
                    if flagged[address][1] == key:
                        continue
                    graph.add_edge(
                        anchor,
                        address,
                        reason="shared_netblock",
                        via=prefix,
                        breadth=2,
                        anchor=anchor,
                        anchor_type=EntityType.IP,
                        other_type=EntityType.IP,
                        score=flagged[anchor][0],
                    )

    def _shared_resolutions(self, ctx: AnalysisContext) -> dict[str, list[str]]:
        """Addresses reached by more than one name, from observed DNS answers.

        Two passes for the same reason as everywhere else: the first counts
        distinct names per address and keeps only the addresses narrow enough
        to mean something, the second collects names for those addresses
        alone. Collecting the lists first would build one per address in the
        capture, the majority of them CDN entries about to be discarded.
        """
        scan = ctx.dns_scan()
        available = set(scan.collect_schema().names())
        if not {"answers", "query"} <= available:
            return {}

        exploded = (
            scan.drop_nulls(subset=["answers", "query"])
            .with_columns(pl.col("answers").str.split(";").alias("answer"))
            # Pinned rather than left to the default, which changes in Polars
            # 2.0. A record with no answers must drop out, not become a null
            # row that later filters count as an observation.
            .explode("answer", empty_as_null=True)
            .with_columns(pl.col("answer").str.strip_chars())
            .filter(pl.col("answer").str.len_chars() > 0)
        )

        breadth = (
            exploded.group_by("answer")
            .agg(pl.col("query").n_unique().alias("names"))
            .filter(
                (pl.col("names") >= 2) & (pl.col("names") <= self.config.max_domains_per_address)
            )
            .collect(engine="streaming")
        )
        if breadth.is_empty():
            return {}

        collected = (
            exploded.join(breadth.lazy().select("answer"), on="answer", how="semi")
            .group_by("answer")
            .agg(pl.col("query").unique().alias("names"))
            .collect(engine="streaming")
        )

        out: dict[str, list[str]] = {}
        for row in collected.iter_rows(named=True):
            address = str(row["answer"])
            if not _is_address(address):
                continue
            names = sorted({str(name).rstrip(".").casefold() for name in row["names"]})
            if 2 <= len(names) <= self.config.max_domains_per_address:
                out[address] = names
        return out

    def _build_link_finding(
        self,
        left: str,
        right: str,
        data: dict[str, object],
        artifacts: dict[str, list[Artifact]],
    ) -> Finding:
        anchor = str(data["anchor"])
        subject_type = data["anchor_type"]
        object_type = data["other_type"]
        other = right if anchor == left else left
        reason = str(data["reason"])
        via = str(data["via"])
        breadth = int(data["breadth"])  # type: ignore[call-overload]
        score = data.get("score")

        if reason == "shared_resolution":
            # Exclusivity is the whole claim: two names on one address is
            # infrastructure, five is a hosting provider. The confidence says
            # which of those was observed, and nothing else.
            confidence = min(0.95, 2.0 / breadth)
            summary = (
                f"{other} resolves to {anchor}, which is itself an indicator match"
                if anchor == via
                else f"{anchor} and {other} both resolve to {via}"
            )
        else:
            # A shared /24 is weaker than a shared address and is scored as
            # such: a hint about an actor's rented range, not a fact about one
            # machine.
            confidence = 0.50
            summary = f"{anchor} and {other} are separately flagged and sit inside {via}"

        indicator = score.indicator if isinstance(score, IntelScore) else None
        evidence = Evidence(
            kind="shared_infrastructure",
            summary=summary,
            payload={
                "link": reason,
                "via": via,
                "entities_on_link": breadth,
                "anchor_indicator": indicator.value if indicator else None,
                "anchor_feed": indicator.feed.name if indicator else None,
                "anchor_confidence": (
                    round(score.confidence, 4) if isinstance(score, IntelScore) else None
                ),
            },
            artifacts=(
                self._artifacts_for(anchor, artifacts)
                if anchor in artifacts
                else self._artifacts_for(str(other), artifacts)
            ),
        )

        return Finding(
            predicate=Predicate.SHARES_INFRASTRUCTURE_WITH,
            subject=Entity(type=subject_type, value=anchor),  # type: ignore[arg-type]
            object=Entity(type=object_type, value=str(other)),  # type: ignore[arg-type]
            evidence=[evidence],
            confidence=round(confidence, 4),
            basis=(
                f"observed link via {via}, shared by {breadth} entities, and the two "
                "ends were caught by different indicators; anchored on an intel match. "
                "Describes infrastructure, not a second behaviour by any host"
            ),
            analyzer=self.qualname,
        )


def _indicator_key(indicator: Indicator) -> str:
    """Identity of an indicator across feeds, for grouping matches."""
    return f"{indicator.kind.value}:{indicator.value}"


def _inexact_kind(kind: IndicatorKind) -> str:
    return "netblock" if kind is IndicatorKind.CIDR else "parent_domain"


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
