# The asset inventory file format

An inventory answers one question: which machine held this address. VoidLexicon
reads it from a file an operator has placed on disk. It does not query DHCP,
resolve names, consult a CMDB over the network, or infer the answer from the
traffic in front of it — the same commitment as `docs/ioc.md`, for the same
reason, and asserted by the same test suite.

The inference ban is worth stating separately from the network ban, because
the tempting shortcut here is not an HTTP call. It is deriving mappings from
observed data — a DHCP log, a reverse lookup, "this address always talks to
that name". Every one of those is a different piece of work with a different
failure mode, and none of them is this one. An inventory is a statement an
operator makes and stands behind.

---

## Why this file exists

Network sensors see addresses. Endpoint agents see computer names. Sysmon
event ID 1 records `FINANCE-WS04` and no address; Zeek's `conn.log` records
`10.0.1.14` and no name. Without something to join them, one compromised
machine reaches the analyst as two incidents that do not corroborate each
other, and the corroboration is the whole ranking signal.

One line of inventory is the join:

```
10.0.1.14   FINANCE-WS04   stated=2025-06-11
```

On the demo capture that line takes patient zero from two rows carrying five
and two behaviours to one row carrying seven, and the queue from ten incidents
to nine. Nothing else in the pipeline changes.

---

## Where the files go

Anywhere `voidai run` can see them, exactly as with `.ioc`:

```bash
# Alongside the telemetry — anything ending .inv, at any depth
voidai run /captures/2018-04-04/

# Or kept separately and pointed at
voidai run /captures/2018-04-04/ --inventory /etc/voidai/assets/

# One file works too
voidai run /captures/2018-04-04/ --inventory /etc/voidai/assets/corp.inv
```

Only `*.inv` is read, so a directory of telemetry cannot have the operator's
`hosts.txt` parsed as an asset register.

Check what actually loaded, and how far it reaches, before trusting it:

```bash
voidai doctor --inventory /etc/voidai/assets/ --telemetry /captures/2018-04-04/
```

`doctor` reports how many mappings loaded, how many were applied, how many
were dropped as too old, what fraction of the addresses in the capture they
resolved, every mapping whose date is worth a second look, and the first line
it could not parse. Coverage and staleness need the telemetry as well as the
inventory, because both are measured against the capture rather than against
today — pass `--telemetry` or they are reported as unmeasured.

---

## The format

Newline-delimited text, one mapping per line, with an optional metadata
header. Deliberately the same shape as an `.ioc` file: an operator who can
write one can write the other, and both can be produced with `cat`, diffed in
review and grepped during an incident.

```
# name: corp-asset-register
# source: netbox export, finance floor
# updated: 2025-06-11
# reference: https://netbox.internal/dcim/devices/
# tlp: amber

10.0.1.14    FINANCE-WS04    stated=2025-06-11  note=static lease, finance floor
10.0.1.20    HR-WS02
10.0.2.31    BUILD-SRV01     stated=2024-02-09
```

### The header

`# key: value` lines **before the first mapping** configure the register.
After that point a `#` line is an ordinary comment — so an operator annotating
a block halfway down a file cannot silently restate the provenance of
everything above it.

| Key | Meaning |
|---|---|
| `name` | Register name, as it appears in evidence. Defaults to the filename. |
| `updated` | When the register was last reconciled. Fallback date for undated mappings. |
| `reference` | Where the inventory came from. Recorded, never fetched. |
| `tlp` | Handling marking, carried into the evidence payload. |

Anything else in the header is kept verbatim and carried through rather than
discarded.

### Mapping lines

An address, then a hostname, then optional `key=value` attributes:

| Attribute | Meaning |
|---|---|
| `stated` (or `first_seen`) | When this mapping was asserted. Overrides the register's `updated`. |
| `note` | Free text, carried into the evidence payload. |

Dates are read in the formats `docs/ioc.md` lists. A date that cannot be read
is an **unknown** date, not a guessed one.

The address must parse as IPv4 or IPv6 — no CIDR, and no prefix walk at lookup
time. `10.0.1.0/24 -> FINANCE` would name a floor, and a finding asserting
that a beacon came from an entire subnet is worse than one that admits it
knows only the address.

The hostname may be a single label. Unlike an IOC domain, `FINANCE-WS04` on
its own is exactly what an asset register contains, and it names one machine
rather than a whole TLD. Underscores are tolerated because NetBIOS names reach
registers with underscores in them.

A line that is not a plausible mapping — one token, an unparseable address, a
hostname that is really a second address — is skipped, counted, and reported
by `voidai doctor` with the line as written. One fat-fingered entry must not
cost the other three hundred and ninety-nine.

---

## Why every mapping carries a date

**A wrong mapping is worse than none.** An inventory naming the wrong machine
attaches a beacon to an innocent host with full confidence and a clean chain
of custody — and a citation is the thing an analyst is least likely to
re-check. This is the one failure this project cannot tolerate.

DHCP is what makes that failure ordinary rather than exotic. An address is not
a machine; it is a lease. A lease that turned over between the statement and
the capture points at somebody else's laptop, and the finding will not look
any less confident for it.

So a mapping is judged by *when it was stated, relative to the traffic it is
being applied to*:

| Situation | Result |
|---|---|
| Stated within 90 days of the capture | Applied, unremarked |
| Stated more than 90 days before | Applied, flagged `stale`, with its age |
| Stated more than 730 days before | **Not applied at all**, reported as dropped |
| Stated *after* the capture ended | Applied, flagged `stated_after_capture` |
| No date at all | Applied, flagged `undated` |

The 730-day floor is the same horizon `docs/ioc.md` puts on an indicator, for
the same reason: past some age a record does not describe a weaker version of
this estate, it describes a different one.

**The fourth row is the sharp one.** An inventory exported last week says
nothing reliable about who held that address six months ago, and it is the
case that will pass unexamined — a *fresh* file feels like the safe kind, and
a reader checking provenance will see a recent date and stop. It resolves
silently and confidently in exactly the direction nobody questions. So a
mapping stated after the traffic it is naming carries the flag too, and the
number of days is in the payload for an analyst to weigh.

### Age is measured against the capture, not the clock

The question is how stale the mapping was **when the traffic happened**, not
how stale it is now that someone is reading. It is also what keeps identity
reproducible: every ID in the Lexicon is content-addressed, so an age derived
from `datetime.now()` would give the same run a different evidence ID every
day, and last week's citations would resolve to nothing.

A capture VoidLexicon cannot date — no timestamped records at all — has no window,
and every mapping in it is reported as unjudged rather than judged against
today.

### Nothing about the traffic enters any of this

An address seen four thousand times and an address seen once resolve
identically. A mapping is not corroborated by the volume of what the machine
did, and a busy host does not get a more confident name than a quiet one. The
moment observation strengthened a mapping, the inventory would be inferring
mappings from data, which is the thing this file exists to avoid.

---

## What the join actually does

`AnalysisContext.actor()` names the subject of a finding, and already prefers
a hostname when it has one. The inventory is what gives it one. The resolution
happens at the **finding** layer and nowhere else: a finding that names
`host:FINANCE-WS04` is a more accurate assertion than one naming the address,
and its evidence still cites the `conn.log` lines it was measured from.

Nothing resolves at the incident layer. Incidents attach, findings assert, and
a second resolution step in the correlator would undo that rule from the other
side.

Every renamed finding carries the mapping in its own chain of custody, as an
`asset_inventory` evidence object:

```
ev_40e77cfeeadfa8  10.0.1.14 is FINANCE-WS04, per corp-asset-register
                   (stated 2025-06-11, 4d before the capture)
    /captures/2018-04-04/assets.inv:line:6
```

The artifact is the file and the line, so an analyst can open the statement
and read it as the operator wrote it. The payload carries the address, the
hostname, the register, the date stated, the capture start, the age in days,
and the staleness verdict — everything needed to decide whether to believe the
name, at the point where the name is used.

A finding that did not resolve carries no such evidence, and its ID is
byte-identical to what it would have been with no inventory file present. A
finding whose subject came from host telemetry rather than from an address —
`host:FINANCE-WS04 executes_rare_process`, asserted from Sysmon's computer
name — never resolves anything and so never picks one up either; its identity
does not move because a file appeared on disk beside the capture.

---

## Coverage is a number you need

An inventory covering 3% of an estate is a rounding error dressed as an
improvement, and a mapping count cannot tell you which you have. So both
`voidai doctor` and the run receipt report the fraction:

```
inventory   1 of 1 mapping(s) applied — resolved 1 of 109 observed address(es) (0.9%)
```

The denominator is the distinct **source** addresses the capture contains,
because that is the side `actor()` is ever asked to name. Counting
destinations would divide by the internet and report nearly nothing for a
complete inventory.

---

## Duplicates across registers

Two registers naming one address is normal once an estate has more than one
source of truth. The mapping retained is the more recently stated; a dated
statement beats an undated one; and two statements genuinely indistinguishable
by date fall back to the file path and line they were written on.

That last tiebreaker is not decoration. Without it the winner would depend on
directory iteration order, and a finding's subject — and therefore its
content-addressed ID — would differ between two runs over one capture. Rule 12
of `docs/engineering-rules.md` applies to a join as much as to a top-N.

---

## What is deliberately not here

**Any derivation.** No DHCP lease parsing, no reverse DNS, no inference from
traffic patterns. Each is a real feature and each has a failure mode this
format does not: a derived mapping is a measurement with an error bar, and it
would need to be scored, aged and doubted like every other measurement rather
than read.

**Subnets and wildcards.** See above: a subject an analyst cannot act on is
worse than an honest address.

**Time-ranged mappings.** An address that held two machines during one capture
is a real case and this format cannot express it; today the more recent
statement wins for the whole window. The right fix is a `from=`/`until=` pair
scoped per mapping, and it is not here because a half-implemented one — where
the ranges are read but the analyzers still resolve once per run — would look
like it worked.

**Any retrieval at all.** Engineering rule 11, asserted by
`tests/test_offline.py`.
