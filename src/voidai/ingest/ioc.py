"""Local indicator-of-compromise files.

Threat intelligence enters VoidLexicon exactly one way: as files an operator has
already placed on disk. Nothing here retrieves a feed, resolves a name, or
opens a socket. That is not a limitation waiting to be lifted — it is the same
commitment as the rest of the runtime, and the test suite severs sockets and
asserts the pipeline still completes.

## The format

Newline-delimited text, one indicator per line, with an optional metadata
header. It was chosen because an operator can write one with `cat`, diff it in
review, and grep it during an incident, and because every feed vendor already
exports to it.

    # name: internal-c2-tracking
    # confidence: 0.85
    # updated: 2026-08-14
    # reference: https://intel.example/report/4417

    45.83.220.17        added=2026-07-02
    185.220.101.0/24    added=2026-06-11  note=hosting range
    c2.evil.example     added=2026-07-02
    d41d8cd98f00b204e9800998ecf8427e

`# key: value` lines *before the first indicator* configure the feed. After
that point a `#` line is a comment, so an operator annotating a block halfway
down a file cannot silently redefine the provenance of everything above it.

Per-indicator attributes follow the value as `key=value` tokens. Three are
read — `added`, `confidence`, `note` — and anything else is retained verbatim
in `attributes`, so a field this parser did not anticipate survives into the
evidence payload instead of being dropped.

## Why provenance is a field and not a nicety

*Stale intel is worse than none.* An indicator from 2019
firing on a residential address reassigned three years ago is a false positive
with a confident citation attached — and a citation is the thing an analyst is
least likely to re-check.

So the two fields that decide what a match is worth — how much the feed claims
to know, and when the indicator was recorded — are parsed, carried on every
`Indicator`, and consumed by `voidai.analyzers.intel`. A file declaring
neither is still loaded and still matched; what it cannot do is produce a
confident finding. An indicator with no provenance gets low confidence, not a
default.

## Type inference

The kind of each indicator is inferred from its own text, never from the
filename or a per-file declaration, because mixed files are the norm once a
feed has been exported by hand. Inference runs from least ambiguous to most,
and reaches "domain" only once every stricter form is ruled out. A line that
is not a plausible indicator of any kind is skipped and counted in `rejected`,
so a file the operator believes is loaded and is not can be reported rather
than silently half-read.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from pathlib import Path

#: Files read by `load_indicators`. One extension, deliberately: a directory
#: of telemetry should not have the operator's `.txt` notes parsed as intel.
IOC_SUFFIX = ".ioc"

_HEADER = re.compile(r"^#\s*([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.+?)\s*$")
_ATTRIBUTE = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*)=(.*)$")

#: MD5, SHA-1, SHA-256, SHA-512. Tested before anything else, because a
#: 32-character hex string is a hash and is never a domain.
_HASH_LENGTHS = frozenset({32, 40, 64, 128})
_HEX = re.compile(r"^[0-9a-fA-F]+$")

_URL_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

#: One hostname label, RFC-1123: alphanumeric with internal hyphens.
_LABEL = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

_DATE_FORMATS = (
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%d/%m/%Y",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
)


class IndicatorKind(str, Enum):
    """What an indicator is, and therefore what it can be matched against."""

    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"


def parse_date(text: str) -> date | None:
    """Read a date in any of the formats a hand-exported feed uses.

    Returns `None` rather than raising, and rather than guessing. A date this
    parser cannot read is an *unknown* date, and the analyzer treats unknown
    and old differently — see `voidai.analyzers.intel`.
    """
    cleaned = text.strip()
    if not cleaned:
        return None
    # Trailing zone designators are common in exported feeds and carry no
    # information at this resolution.
    cleaned = cleaned.rstrip("Zz").strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(cleaned, fmt).date()
        except ValueError:
            continue
    return None


def _parse_confidence(text: str) -> float | None:
    """Read a declared confidence as a fraction in [0, 1].

    Accepts `0.85` and `85%`, because feeds write both. A value outside the
    range is rejected outright rather than clamped: a feed claiming 4.2 has
    told us its scale is not ours, and inventing a reading of it would be
    manufacturing the provenance this module exists to preserve.
    """
    cleaned = text.strip().rstrip("%")
    scale = 100.0 if text.strip().endswith("%") else 1.0
    try:
        value = float(cleaned) / scale
    except ValueError:
        return None
    return value if 0.0 <= value <= 1.0 else None


def classify(value: str) -> IndicatorKind | None:
    """Infer what an indicator is from its own text.

    Ordered from least ambiguous to most. `None` means the text is not a
    plausible indicator of any kind this module understands.
    """
    text = value.strip()
    if not text:
        return None

    if _URL_SCHEME.match(text):
        return IndicatorKind.URL

    if len(text) in _HASH_LENGTHS and _HEX.match(text):
        return IndicatorKind.FILE_HASH

    # A CIDR is tested before a bare address: `ip_address` rejects the `/24`
    # form, so a network reaching the domain fallback would become an
    # indicator that can never match anything.
    if "/" in text:
        try:
            ipaddress.ip_network(text, strict=False)
            return IndicatorKind.CIDR
        except ValueError:
            # Not a network, but it has a path separator — a URL missing its
            # scheme, which is how most feeds write one.
            return IndicatorKind.URL if "." in text.split("/", 1)[0] else None

    try:
        ipaddress.ip_address(text)
        return IndicatorKind.IP
    except ValueError:
        pass

    hostname = text.rstrip(".")
    labels = hostname.split(".")
    if len(labels) >= 2 and all(_LABEL.match(label) for label in labels):
        return IndicatorKind.DOMAIN

    return None


def normalise(value: str, kind: IndicatorKind) -> str:
    """Canonical form, so that two spellings of one indicator are one entry."""
    text = value.strip()
    if kind is IndicatorKind.DOMAIN:
        return text.rstrip(".").casefold()
    if kind is IndicatorKind.FILE_HASH:
        return text.casefold()
    if kind is IndicatorKind.IP:
        # Compressed IPv6 and the same address written long-hand are one host.
        return str(ipaddress.ip_address(text))
    if kind is IndicatorKind.CIDR:
        return str(ipaddress.ip_network(text, strict=False))
    return text


@dataclass(frozen=True)
class Feed:
    """One IOC file and what it declares about itself."""

    name: str
    path: str
    #: The feed's own confidence in its contents, if it stated one. `None`
    #: means unprovenanced, which the analyzer scores as such.
    declared_confidence: float | None = None
    #: When the feed was last refreshed. Used as the fallback age for an
    #: indicator carrying no `added=` of its own.
    updated: date | None = None
    reference: str | None = None
    tlp: str | None = None
    #: Header keys this module does not interpret, kept for the receipt.
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def provenanced(self) -> bool:
        """Whether the feed said anything about how much to trust it."""
        return self.declared_confidence is not None


@dataclass(frozen=True)
class Indicator:
    """One entry in one feed, with everything needed to score a match."""

    value: str
    kind: IndicatorKind
    feed: Feed
    #: When this indicator was recorded, from `added=` or the feed's
    #: `updated:`. `None` is an *unknown* age, never an implied recent one.
    added: date | None = None
    #: A per-indicator override of the feed's declared confidence.
    confidence: float | None = None
    note: str | None = None
    attributes: dict[str, str] = field(default_factory=dict)
    source_file: str = ""
    source_line: int = 0

    @property
    def declared_confidence(self) -> float | None:
        """The confidence claimed for this entry, most specific first."""
        if self.confidence is not None:
            return self.confidence
        return self.feed.declared_confidence

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
        if self.kind is not IndicatorKind.CIDR:
            return None
        return ipaddress.ip_network(self.value, strict=False)


@dataclass(frozen=True)
class DomainMatch:
    """A domain observation resolved against the indicator set.

    `exact` records whether the observed name *is* the indicator or merely
    sits beneath it. The analyzer reports the two differently, because a
    finding naming a zone and a finding naming a host are different claims.
    """

    indicator: Indicator
    exact: bool


class IndicatorSet:
    """Indicators from every loaded feed, indexed for lookup.

    Lookup is by exact value for addresses, hashes and URLs, and by walking
    parent domains for names — an indicator for `evil.example` is intended to
    catch `c2.evil.example`, and every feed in the world is written on that
    assumption. Networks are the one linear scan, and they are matched only
    against the *distinct* addresses a capture actually contains rather than
    against its flows.
    """

    def __init__(self) -> None:
        self.feeds: list[Feed] = []
        self.by_ip: dict[str, Indicator] = {}
        self.by_domain: dict[str, Indicator] = {}
        self.by_hash: dict[str, Indicator] = {}
        self.by_url: dict[str, Indicator] = {}
        self.networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, Indicator]] = []
        #: Networks grouped by (version, prefix length), so that matching one
        #: address costs one masking operation per *distinct prefix length* in
        #: the set rather than a scan of every network in it. A capture with
        #: 250,000 distinct addresses against a feed carrying a few hundred
        #: ranges is the difference between a lookup pass measured in seconds
        #: and one measured in minutes, on the hardware this targets.
        self._by_prefix: dict[tuple[int, int], dict[str, Indicator]] = {}
        #: Lines that were not a plausible indicator, as (file, line, text).
        self.rejected: list[tuple[str, int, str]] = []

    def __len__(self) -> int:
        return (
            len(self.by_ip)
            + len(self.by_domain)
            + len(self.by_hash)
            + len(self.by_url)
            + len(self.networks)
        )

    def is_empty(self) -> bool:
        return len(self) == 0

    def counts(self) -> dict[str, int]:
        """Indicators by kind. What `voidai doctor` prints."""
        return {
            IndicatorKind.IP.value: len(self.by_ip),
            IndicatorKind.CIDR.value: len(self.networks),
            IndicatorKind.DOMAIN.value: len(self.by_domain),
            IndicatorKind.URL.value: len(self.by_url),
            IndicatorKind.FILE_HASH.value: len(self.by_hash),
        }

    def add(self, indicator: Indicator) -> None:
        """Index one indicator, keeping the better-provenanced duplicate.

        Two feeds naming the same address is the normal case, not an error.
        The entry retained is the one that can support the stronger claim —
        higher declared confidence, then more recently added — so that a
        precise indicator is not shadowed by a bulk list that happened to load
        first.
        """
        if indicator.kind is IndicatorKind.CIDR:
            network = indicator.network
            assert network is not None  # kind is CIDR
            table = self._by_prefix.setdefault((network.version, network.prefixlen), {})
            key = str(network)
            existing = table.get(key)
            if existing is None:
                table[key] = indicator
                self.networks.append((network, indicator))
            elif _outranks(indicator, existing):
                table[key] = indicator
                self.networks = [(n, indicator if n == network else i) for n, i in self.networks]
            return

        index = {
            IndicatorKind.IP: self.by_ip,
            IndicatorKind.DOMAIN: self.by_domain,
            IndicatorKind.FILE_HASH: self.by_hash,
            IndicatorKind.URL: self.by_url,
        }[indicator.kind]

        existing = index.get(indicator.value)
        if existing is None or _outranks(indicator, existing):
            index[indicator.value] = indicator

    def match_address(self, address: str) -> Indicator | None:
        """An exact address indicator, else the narrowest network holding it.

        Narrowest first: an operator who lists both a /16 and a /28 inside it
        meant the /28 to be the more specific statement, and reporting the
        block that says least about the address would waste the better one.
        """
        try:
            canonical = str(ipaddress.ip_address(address.strip()))
        except ValueError:
            return None

        exact = self.by_ip.get(canonical)
        if exact is not None:
            return exact
        if not self.networks:
            return None

        version = ipaddress.ip_address(canonical).version
        best: Indicator | None = None
        best_prefix = -1
        for (net_version, prefix), table in self._by_prefix.items():
            if net_version != version or prefix <= best_prefix:
                continue
            supernet = str(ipaddress.ip_network(f"{canonical}/{prefix}", strict=False))
            indicator = table.get(supernet)
            if indicator is not None:
                best, best_prefix = indicator, prefix
        return best

    def match_domain(self, name: str) -> DomainMatch | None:
        """The most specific indicator matching a queried name.

        Walks the name's parents, so `a.b.evil.example` is caught by an
        indicator for `evil.example` and reported as a non-exact match against
        that zone. A single-label indicator would match a whole TLD, so
        `classify` refuses to produce one.
        """
        if not self.by_domain:
            return None

        hostname = name.strip().rstrip(".").casefold()
        if not hostname:
            return None

        exact = self.by_domain.get(hostname)
        if exact is not None:
            return DomainMatch(indicator=exact, exact=True)

        labels = hostname.split(".")
        for start in range(1, len(labels) - 1):
            parent = ".".join(labels[start:])
            indicator = self.by_domain.get(parent)
            if indicator is not None:
                return DomainMatch(indicator=indicator, exact=False)
        return None

    def match_hash(self, digest: str) -> Indicator | None:
        return self.by_hash.get(digest.strip().casefold())


def _outranks(candidate: Indicator, incumbent: Indicator) -> bool:
    """Whether a duplicate should replace the entry already indexed."""
    new_confidence = candidate.declared_confidence
    old_confidence = incumbent.declared_confidence
    if (new_confidence is None) != (old_confidence is None):
        return old_confidence is None
    if (
        new_confidence is not None
        and old_confidence is not None
        and new_confidence != old_confidence
    ):
        return new_confidence > old_confidence
    if (candidate.added is None) != (incumbent.added is None):
        return incumbent.added is None
    if candidate.added is not None and incumbent.added is not None:
        return candidate.added > incumbent.added
    return False


def read_ioc_file(path: str | Path) -> tuple[Feed, list[Indicator], list[tuple[str, int, str]]]:
    """Parse one `.ioc` file into its feed, its indicators and its rejects.

    Never raises on content. A malformed line is a rejected line, because an
    operator who fat-fingered one entry of four hundred should get the other
    three hundred and ninety-nine and a report of the one, not a stack trace
    in the middle of an incident.
    """
    path = Path(path)
    header: dict[str, str] = {}
    rows: list[tuple[str, int, dict[str, str], str]] = []
    rejected: list[tuple[str, int, str]] = []
    in_header = True

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return Feed(name=path.stem, path=str(path)), [], []

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            match = _HEADER.match(line)
            if in_header and match:
                header[match.group(1).lower()] = match.group(2)
            continue

        in_header = False
        tokens = line.split()
        value, attributes = tokens[0], {}
        for token in tokens[1:]:
            attribute = _ATTRIBUTE.match(token)
            if attribute:
                attributes[attribute.group(1).lower()] = attribute.group(2)
            else:
                # A bare trailing word continues the previous `note=`, which is
                # how a human writes one. Anything before a note is discarded.
                if "note" in attributes:
                    attributes["note"] = f"{attributes['note']} {token}".strip()
        rows.append((value, number, attributes, line))

    feed = _feed_from_header(path, header)
    indicators: list[Indicator] = []
    for value, number, attributes, raw_line in rows:
        kind = classify(value)
        if kind is None:
            # The whole line, not the token that failed: an operator reading
            # the report needs to recognise what they wrote.
            rejected.append((str(path), number, raw_line))
            continue
        indicators.append(
            Indicator(
                value=normalise(value, kind),
                kind=kind,
                feed=feed,
                added=parse_date(attributes.get("added") or attributes.get("first_seen") or "")
                or feed.updated,
                confidence=_parse_confidence(attributes.get("confidence", "")),
                note=attributes.get("note"),
                attributes={
                    key: val
                    for key, val in attributes.items()
                    if key not in {"added", "first_seen", "confidence", "note"}
                },
                source_file=str(path),
                source_line=number,
            )
        )

    return feed, indicators, rejected


def _feed_from_header(path: Path, header: dict[str, str]) -> Feed:
    known = {"name", "confidence", "updated", "reference", "source", "tlp"}
    return Feed(
        name=header.get("name") or path.stem,
        path=str(path),
        declared_confidence=_parse_confidence(header.get("confidence", "")),
        updated=parse_date(header.get("updated") or header.get("date") or ""),
        reference=header.get("reference") or header.get("source"),
        tlp=header.get("tlp"),
        metadata={key: value for key, value in header.items() if key not in known},
    )


def load_indicators(source: str | Path) -> IndicatorSet:
    """Load every `.ioc` file under a directory, or one file directly.

    Reads from disk and from nowhere else. A missing path yields an empty set
    rather than an error: intel is optional, and a run without it is a run
    with four analyzers instead of five, not a failed one.
    """
    path = Path(source)
    indicators = IndicatorSet()

    if path.is_file():
        paths = [path]
    elif path.is_dir():
        paths = sorted(p for p in path.rglob(f"*{IOC_SUFFIX}") if p.is_file())
    else:
        return indicators

    for ioc_path in paths:
        feed, entries, rejected = read_ioc_file(ioc_path)
        indicators.feeds.append(feed)
        indicators.rejected.extend(rejected)
        for entry in entries:
            indicators.add(entry)

    return indicators
