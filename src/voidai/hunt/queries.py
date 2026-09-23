"""Hunt query generation: a Finding becomes something you can run elsewhere.

This module is the Lexicon's argument made concrete.

A finding written as prose — "host 10.0.1.14 looks like it might be beaconing
to 45.83.220.17" — cannot be mechanically turned into a detection rule.
Something has to read it and decide what the indicator was, what field it
belongs in, and what the query should ask. That is a job for a person, or for
a model that will occasionally get it wrong.

A finding written as a *typed proposition* can be transformed by templating,
because every part an author would otherwise have to infer is already
explicit: the predicate says what kind of claim it is, the subject and object
carry declared entity types, and the evidence payload carries the measured
values. No model is involved and none is needed.

## These are hunts, not re-detections

The obvious generated query — "find the traffic that produced this finding" —
is useless, because you already have it. A hunt pivots on the *indicator* and
asks who else touched it, with the known subject excluded so the answer is new
information:

    beacons_to(ip:10.0.1.14, ip:45.83.220.17)
      → which other hosts contacted 45.83.220.17?

That question is the reason to hand a finding to a SIEM at all. VoidLexicon sees
one sensor's window; the SIEM sees the estate's history.

## Escaping

Entity values come from logs, and logs contain whatever an attacker put in
them. Every value interpolated into a query is escaped for its dialect, and
non-printable characters are stripped before that. A generated hunt query is a
string an analyst will paste into a console holding production credentials,
and treating it as trusted because *we* generated it would be exactly
backwards — we generated it *from attacker-controlled input*.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import Enum

from voidai.lexicon import Entity, EntityType, Finding, Incident, Predicate, Severity

#: Namespace for deriving a stable Sigma rule UUID from a finding ID. Sigma
#: requires a UUID in the `id` field, and VoidLexicon IDs are content-addressed —
#: so a v5 derivation keeps the rule ID reproducible across runs too.
_SIGMA_NAMESPACE = uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")


class Dialect(str, Enum):
    """Query languages VoidLexicon can emit."""

    SIGMA = "sigma"
    KQL = "kql"
    SPL = "spl"
    ZEEK = "zeek"


#: Which telemetry class a pivot lives in. Determines the table, index or log
#: file a generated query reads from.
_TELEMETRY: dict[str, str] = {
    "dst": "connection",
    "dst_port": "connection",
    "domain": "dns",
    "signature": "alert",
    "ja3": "tls",
    "image": "process",
}

#: Field names per dialect, indexed by what the value *means* rather than by
#: where it came from. Keeps the templates below free of vendor detail.
_FIELDS: dict[Dialect, dict[str, str]] = {
    Dialect.SIGMA: {
        "image": "Image",
        "host": "Computer",
        "src": "src_ip",
        "dst": "dst_ip",
        "dst_port": "dst_port",
        "domain": "query",
        "signature": "signature",
        "ja3": "ja3",
    },
    Dialect.KQL: {
        "image": "FolderPath",
        "host": "DeviceName",
        "src": "SourceIP",
        "dst": "DestinationIP",
        "dst_port": "DestinationPort",
        "domain": "QueryName",
        "signature": "AlertName",
        "ja3": "Ja3Hash",
    },
    Dialect.SPL: {
        "image": "Image",
        "host": "host",
        "src": "src_ip",
        "dst": "dest_ip",
        "dst_port": "dest_port",
        "domain": "query",
        "signature": "signature",
        "ja3": "ssl_ja3",
    },
    Dialect.ZEEK: {
        # No process telemetry: zeek-cut reads Zeek logs and Zeek does not
        # write one. The entries exist so the table stays total; a process
        # pivot never reaches this dialect — see `_Pivot.dialects`.
        "image": "image",
        "host": "host",
        "src": "id.orig_h",
        "dst": "id.resp_h",
        "dst_port": "id.resp_p",
        "domain": "query",
        "signature": "note",
        "ja3": "ja3",
    },
}

#: Where each dialect looks for a telemetry class. These are the conventional
#: defaults, not a claim about any particular deployment — an analyst will
#: retarget the table or index, and everything below it still holds.
_SOURCES: dict[Dialect, dict[str, str]] = {
    Dialect.SIGMA: {
        "connection": "  category: network_connection",
        "dns": "  category: dns_query",
        "alert": "  product: suricata\n  service: alert",
        "tls": "  category: network_connection\n  service: tls",
        "process": "  category: process_creation\n  product: windows",
    },
    Dialect.KQL: {
        "connection": "NetworkEvents",
        "dns": "DnsEvents",
        "alert": "SecurityAlert",
        "tls": "TlsEvents",
        "process": "DeviceProcessEvents",
    },
    Dialect.SPL: {
        "connection": "index=network",
        "dns": "index=dns",
        "alert": "index=ids",
        "tls": "index=tls",
        "process": "index=sysmon EventCode=1",
    },
    Dialect.ZEEK: {
        "connection": "conn.log",
        "dns": "dns.log",
        "alert": "notice.log",
        "tls": "ssl.log",
        "process": "<none>",
    },
}

#: Sigma spells the lowest level "informational"; the Lexicon spells it "info".
_SIGMA_LEVEL: dict[Severity, str] = {
    Severity.INFO: "informational",
    Severity.LOW: "low",
    Severity.MEDIUM: "medium",
    Severity.HIGH: "high",
    Severity.CRITICAL: "critical",
}


def _printable(value: str) -> str:
    """Strip characters that have no place in an indicator.

    A hostname, address, port or signature name is printable text. Anything
    else in one arrived from a crafted log line, and its only possible effect
    on a generated query is to break out of a quoted string or garble the
    console the query is pasted into.
    """
    return "".join(character for character in value if character.isprintable())


def escape(value: str, dialect: Dialect) -> str:
    """Escape a log-derived value for the dialect's quoted value slot.

    The result is the *inner* text: the caller supplies the surrounding
    quotes. For Zeek that slot is a shell single-quoted `awk -v` assignment,
    which needs both shell and awk escaping — awk applies backslash
    processing to `-v` values, so backslashes are doubled first.
    """
    cleaned = _printable(value)

    if dialect is Dialect.ZEEK:
        # awk -v expands escape sequences in the assigned value.
        for_awk = cleaned.replace("\\", "\\\\")
        # …and the assignment sits inside a shell single-quoted token.
        return for_awk.replace("'", "'\\''")

    # Sigma (YAML double-quoted), KQL and SPL all use double-quoted strings
    # with backslash escapes.
    quoted = cleaned.replace("\\", "\\\\").replace('"', '\\"')

    if dialect is Dialect.SPL:
        # Splunk treats `*` as a wildcard even inside quotes. An indicator
        # containing one would silently widen the hunt rather than break it,
        # which is the harder failure to notice.
        quoted = quoted.replace("*", "\\*")

    return quoted


@dataclass(frozen=True)
class HuntQuery:
    """One runnable query, with the finding that justifies it."""

    dialect: Dialect
    title: str
    query: str
    #: The indicator being pivoted on, as an analyst would describe it.
    pivot: str
    #: Provenance. A query with no finding behind it has no business here.
    finding_id: str
    rationale: str

    def __str__(self) -> str:
        return self.query


@dataclass(frozen=True)
class _Pivot:
    """What to hunt for, extracted from a finding before any templating."""

    field: str
    value: str
    exclude_src: str | None
    title: str
    rationale: str
    #: How the value should be compared. A tunnelling zone must be matched as
    #: a *suffix*: the indicator is `tunnel.example.com`, but no query is ever
    #: for that name — every one is `<encoded-chunk>.tunnel.example.com`. An
    #: equality test on the zone apex would return nothing, forever, and look
    #: like a clean estate.
    match: str = "exact"
    #: What a suffix match is a suffix *of*. A tunnelling zone is a DNS suffix
    #: and takes a dot; an image name is a path suffix and takes a separator.
    #: Without it, `Image: "powershell.exe"` compares a basename against a
    #: column holding `C:\\Windows\\System32\\…\\powershell.exe` and
    #: matches nothing, forever, while looking like a clean estate.
    suffix_separator: str = "."
    #: Which column names the entity a hunt groups and excludes by. Network
    #: telemetry answers "which other addresses"; process telemetry answers
    #: "which other machines", and those are different columns.
    subject_field: str = "src"
    #: Dialects this pivot can be rendered in, or None for all of them. Only
    #: process pivots restrict it: `zeek-cut` reads Zeek logs, Zeek writes no
    #: process log, and a pipeline over a file that does not exist returns
    #: nothing forever while looking like a clean estate — the same reason
    #: `matches_threat_intel` declines to pivot on a hash.
    dialects: tuple[Dialect, ...] | None = None

    @property
    def numeric(self) -> bool:
        """Whether the value belongs in a numeric field unquoted.

        A port compared as the string "445" silently fails to match a numeric
        column in every dialect here.
        """
        return self.field == "dst_port" and self.value.isdigit()

    @property
    def comparand(self) -> str:
        """The literal to compare against, including any suffix separator."""
        return f"{self.suffix_separator}{self.value}" if self.match == "suffix" else self.value


def _pivot_for(finding: Finding) -> _Pivot | None:
    """Decide what indicator a finding offers, and what to ask about it.

    Returns None for findings carrying no pivotable indicator. A relational
    predicate like `precedes` describes VoidLexicon's own reasoning about two
    observations rather than a value a SIEM can look up, and inventing a
    query for it would be inventing an indicator.
    """
    subject, target = finding.subject, finding.object

    if finding.predicate is Predicate.MATCHES_THREAT_INTEL:
        # The one unary predicate that carries an indicator. Its *subject* is
        # the indicator — the address or name that appeared in the operator's
        # feed — so the pivot comes from the subject rather than the object,
        # and nothing is excluded: the question is which hosts touched it, and
        # every one of them is the answer.
        if subject.type is EntityType.IP:
            field_name = "dst"
        elif subject.type is EntityType.DOMAIN:
            field_name = "domain"
        else:
            # A hash or a URL. Neither is a field in the log sources this
            # generator templates against, and a query for one would return
            # nothing forever while looking like a clean estate.
            return None
        return _Pivot(
            field=field_name,
            value=subject.value,
            exclude_src=None,
            title=f"Every host touching {subject.value}",
            rationale=(
                "The indicator came from a feed, not from this capture, so "
                "the estate's history is the measurement that matters. Any "
                "host that reached it is in the same position as the one "
                "already found."
            ),
        )

    if target is None:
        return None

    source = subject.value if subject.type in (EntityType.HOST, EntityType.IP) else None

    if finding.predicate in (
        Predicate.BEACONS_TO,
        Predicate.EXFILTRATES_TO,
        Predicate.CONTACTS_RARE_DESTINATION,
        Predicate.TRANSFERS_ANOMALOUS_VOLUME,
    ):
        return _Pivot(
            field="domain" if target.type is EntityType.DOMAIN else "dst",
            value=target.value,
            exclude_src=source,
            title=f"Other hosts contacting {target.value}",
            rationale=(
                "One host was measured communicating with this destination. If "
                "the estate holds others, the intrusion is wider than this "
                "capture shows."
            ),
        )

    if finding.predicate is Predicate.TUNNELS_DNS_OVER:
        return _Pivot(
            field="domain",
            value=target.value,
            exclude_src=source,
            title=f"Other hosts resolving under {target.value}",
            match="suffix",
            rationale=(
                "A tunnelling zone is attacker infrastructure. Any other host "
                "querying it is a candidate for the same implant."
            ),
        )

    if finding.predicate is Predicate.RESOLVES_ALGORITHMIC_DOMAIN:
        return _Pivot(
            field="domain",
            value=target.value,
            exclude_src=source,
            title=f"Other hosts resolving {target.value}",
            rationale=(
                "Algorithmically generated domains are computed from a shared "
                "seed, so a second host resolving the same one is running the "
                "same generator."
            ),
        )

    if finding.predicate is Predicate.SCANS and target.type is EntityType.PORT:
        return _Pivot(
            field="dst_port",
            value=target.value,
            exclude_src=source,
            title=f"Other hosts sweeping port {target.value}",
            rationale=(
                "Horizontal sweeps on a single port are how a worm moves. "
                "Finding a second source is finding the next victim."
            ),
        )

    if finding.predicate is Predicate.PRESENTS_RARE_TLS_FINGERPRINT:
        return _Pivot(
            field="ja3",
            value=target.value,
            exclude_src=source,
            title=f"Other hosts presenting JA3 {target.value}",
            rationale=(
                "A JA3 hash identifies a TLS client build, not a destination. "
                "A second host presenting the same rare one is running the "
                "same software — which is the question the estate's history "
                "answers and this capture cannot."
            ),
        )

    if finding.predicate in (
        Predicate.EXECUTES_RARE_PROCESS,
        Predicate.EXHIBITS_ANOMALOUS_LINEAGE,
    ):
        # The pivot is the image name, and the question is which *other
        # machines* ran it — so the subject column is the hostname rather than
        # a source address, and the known host is excluded so the answer is
        # new information. `matches_threat_intel`'s rationale applies here in
        # reverse: VoidLexicon measured rarity over one capture's window, and the
        # estate's history is what says whether that rarity is real.
        #
        # No `zeek` dialect. Zeek writes no process log, and a zeek-cut
        # pipeline over a file that does not exist returns nothing forever.
        return _Pivot(
            field="image",
            value=target.value,
            exclude_src=subject.value if subject.type is EntityType.HOST else None,
            match="suffix",
            suffix_separator="\\",
            subject_field="host",
            dialects=(Dialect.SIGMA, Dialect.KQL, Dialect.SPL),
            title=f"Other hosts executing {target.value}",
            rationale=(
                "Rarity was measured over this capture's window. Whether the "
                "image is rare in the estate's history, or merely rare in what "
                "was captured, is the question this answers — and a second "
                "machine running it is a second machine to look at."
            ),
        )

    if finding.predicate is Predicate.TRIGGERED_SIGNATURE:
        return _Pivot(
            field="signature",
            value=target.value,
            exclude_src=source,
            title=f"Other hosts tripping {target.value}",
            rationale=(
                "The signature was rare in this window. Its history across the "
                "estate says whether that rarity is real or an artefact of how "
                "little was captured."
            ),
        )

    return None


def _sigma(pivot: _Pivot, finding: Finding) -> str:
    fields = _FIELDS[Dialect.SIGMA]
    field = fields[pivot.field]
    value = escape(pivot.comparand, Dialect.SIGMA)
    title = escape(pivot.title, Dialect.SIGMA)
    source = escape(pivot.exclude_src, Dialect.SIGMA) if pivot.exclude_src else None
    rule_id = uuid.uuid5(_SIGMA_NAMESPACE, finding.id)

    if pivot.match == "suffix":
        selection = f"    {field}|endswith: \"{value}\""
    elif pivot.numeric:
        selection = f"    {field}: {value}"
    else:
        selection = f'    {field}: "{value}"'

    if source:
        condition = (
            f"  filter_known:\n"
            f'    {fields[pivot.subject_field]}: "{source}"\n'
            f"  condition: selection and not filter_known"
        )
    else:
        condition = "  condition: selection"

    tags = "".join(f"  - attack.{technique.lower()}\n" for technique in finding.attack_techniques)
    level = _SIGMA_LEVEL[finding.severity or Severity.MEDIUM]

    return (
        f'title: "{title}"\n'
        f"id: {rule_id}\n"
        f"status: experimental\n"
        f"description: |\n"
        f"  Hunt generated by VoidLexicon from finding {finding.id}.\n"
        f"  {pivot.rationale}\n"
        f"references:\n"
        f"  - voidai://finding/{finding.id}\n"
        f"{'tags:' + chr(10) + tags if tags else ''}"
        f"logsource:\n{_SOURCES[Dialect.SIGMA][_TELEMETRY[pivot.field]]}\n"
        f"detection:\n"
        f"  selection:\n"
        f"{selection}\n"
        f"{condition}\n"
        f"level: {level}"
    )


def _kql(pivot: _Pivot, finding: Finding) -> str:
    fields = _FIELDS[Dialect.KQL]
    field = fields[pivot.field]
    value = escape(pivot.comparand, Dialect.KQL)
    source = escape(pivot.exclude_src, Dialect.KQL) if pivot.exclude_src else None
    table = _SOURCES[Dialect.KQL][_TELEMETRY[pivot.field]]

    if pivot.match == "suffix":
        predicate = f'{field} endswith "{value}"'
    elif pivot.numeric:
        predicate = f"{field} == {value}"
    else:
        predicate = f'{field} == "{value}"'

    exclusion = f'\n| where {fields[pivot.subject_field]} != "{source}"' if source else ""
    return (
        f"// {_printable(pivot.title)} — VoidLexicon finding {finding.id}\n"
        f"{table}\n"
        f"| where {predicate}{exclusion}\n"
        f"| summarize Events = count(), FirstSeen = min(TimeGenerated), "
        f'LastSeen = max(TimeGenerated) by {fields[pivot.subject_field]}\n'
        f"| order by Events desc"
    )


def _spl(pivot: _Pivot, finding: Finding) -> str:
    fields = _FIELDS[Dialect.SPL]
    field = fields[pivot.field]
    value = escape(pivot.comparand, Dialect.SPL)
    source = escape(pivot.exclude_src, Dialect.SPL) if pivot.exclude_src else None
    index = _SOURCES[Dialect.SPL][_TELEMETRY[pivot.field]]

    if pivot.match == "suffix":
        # The leading `*` is ours, added after escaping, so it stays a wildcard.
        term = f'{field}="*{value}"'
    elif pivot.numeric:
        term = f"{field}={value}"
    else:
        term = f'{field}="{value}"'

    exclusion = f' {fields[pivot.subject_field]}!="{source}"' if source else ""
    return (
        f"``` {_printable(pivot.title)} — VoidLexicon finding {finding.id} ```\n"
        f"{index} {term}{exclusion}\n"
        f"| stats count AS events, min(_time) AS first_seen, max(_time) AS last_seen "
        f'BY {fields[pivot.subject_field]}\n'
        f"| sort - events"
    )


def _zeek(pivot: _Pivot, finding: Finding) -> str:
    """A zeek-cut pipeline against archived logs, for estates with no SIEM.

    The indicator is passed through `awk -v` rather than spliced into the awk
    program, so the value can never be read as code no matter what a log line
    contained.
    """
    fields = _FIELDS[Dialect.ZEEK]
    field = fields[pivot.field]
    value = escape(pivot.comparand, Dialect.ZEEK)
    source = escape(pivot.exclude_src, Dialect.ZEEK) if pivot.exclude_src else None
    log = _SOURCES[Dialect.ZEEK][_TELEMETRY[pivot.field]]

    assignments = f"-v want='{value}'"
    if pivot.match == "suffix":
        # substr rather than a regex: the indicator would have to be escaped
        # for regex syntax too, and a dot in a domain would quietly become
        # "any character".
        condition = "length($2) > length(want) && substr($2, length($2) - length(want) + 1) == want"
    else:
        condition = "$2 == want"
    if source:
        assignments += f" -v known='{source}'"
        condition += " && $1 != known"

    # -F'\t' is not optional: zeek-cut emits tab-separated columns, and a
    # signature name contains spaces. Under awk's default whitespace
    # separator, `ET TROJAN Beacon` becomes three fields and $2 is "TROJAN".
    return (
        f"# {_printable(pivot.title)} — VoidLexicon finding {finding.id}\n"
        f'cat {log} | zeek-cut {fields[pivot.subject_field]} {field} \\\n'
        f"  | awk -F'\\t' {assignments} '{condition} {{ print $1 }}' \\\n"
        f"  | sort | uniq -c | sort -rn"
    )


_RENDERERS = {
    Dialect.SIGMA: _sigma,
    Dialect.KQL: _kql,
    Dialect.SPL: _spl,
    Dialect.ZEEK: _zeek,
}


def queries_for(
    finding: Finding,
    dialects: tuple[Dialect, ...] | None = None,
) -> list[HuntQuery]:
    """Generate hunt queries for one finding, in each requested dialect.

    Returns an empty list when the finding offers no pivotable indicator.
    """
    pivot = _pivot_for(finding)
    if pivot is None:
        return []

    wanted = dialects or tuple(Dialect)
    if pivot.dialects is not None:
        wanted = tuple(d for d in wanted if d in pivot.dialects)

    return [
        HuntQuery(
            dialect=dialect,
            title=_printable(pivot.title),
            query=_RENDERERS[dialect](pivot, finding),
            pivot=f"{pivot.field}={_printable(pivot.value)}",
            finding_id=finding.id,
            rationale=pivot.rationale,
        )
        for dialect in wanted
    ]


def queries_for_incident(
    incident: Incident,
    dialects: tuple[Dialect, ...] | None = None,
) -> list[HuntQuery]:
    """Generate hunt queries for every pivotable finding in an incident.

    Deduplicated by pivot: two findings naming the same destination are two
    views of one indicator, and produce one hunt rather than two identical
    ones. Highest-confidence finding first, so the surviving query is the one
    with the strongest provenance.
    """
    seen: set[tuple[str, Dialect]] = set()
    out: list[HuntQuery] = []
    for finding in sorted(incident.findings, key=lambda f: -f.confidence):
        for query in queries_for(finding, dialects):
            key = (query.pivot, query.dialect)
            if key in seen:
                continue
            seen.add(key)
            out.append(query)
    return out


def pivot_entities(incident: Incident) -> list[Entity]:
    """The indicators an incident offers for hunting, in confidence order."""
    entities: list[Entity] = []
    seen: set[str] = set()
    for finding in sorted(incident.findings, key=lambda f: -f.confidence):
        if _pivot_for(finding) is None:
            continue
        # Unary predicates carry their indicator on the subject; everything
        # else carries it on the object.
        entity = finding.object if finding.object is not None else finding.subject
        if entity.id in seen:
            continue
        seen.add(entity.id)
        entities.append(entity)
    return entities
