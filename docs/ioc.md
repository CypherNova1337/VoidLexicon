# The IOC file format

VoidLexicon reads threat intelligence from files an operator has placed on disk. It
does not fetch feeds, resolve names, or open a socket for any purpose at
runtime — the test suite severs sockets and asserts the pipeline still
completes. If an indicator is to be matched, a file containing it has to be on
the machine already.

That constraint is the reason this format exists rather than a MISP client.

---

## Where the files go

Anywhere `voidai run` can see them:

```bash
# Alongside the telemetry — anything ending .ioc, at any depth
voidai run /captures/2018-04-04/

# Or kept separately and pointed at
voidai run /captures/2018-04-04/ --intel /etc/voidai/intel/

# One file works too
voidai run /captures/2018-04-04/ --intel /etc/voidai/intel/tracked.ioc
```

Only `*.ioc` is read. A directory of telemetry should not have the operator's
`notes.txt` parsed as intelligence, so the extension is the opt-in.

Check what actually loaded before trusting it:

```bash
voidai doctor --intel /etc/voidai/intel/
```

`doctor` reports the indicator count by kind, names any feed that declared no
confidence, counts indicators that are loaded but inert, and shows the first
line it could not parse. Each of those looks identical to "no intel
configured" from the outside and each has a different fix.

---

## The format

Newline-delimited text, one indicator per line, with an optional metadata
header.

```
# name: internal-c2-tracking
# confidence: 0.85
# updated: 2026-08-14
# reference: https://intel.example/report/4417
# tlp: amber

45.83.220.17        added=2026-07-02  note=observed c2 for cluster 9
185.220.101.0/24    added=2026-06-11  note=rented hosting range
c2.evil.example     added=2026-07-02
d41d8cd98f00b204e9800998ecf8427e
http://drop.evil.example/gate.php
```

An operator can write one of these with `cat`, diff it in review, and grep it
during an incident. Every feed vendor can already export to it.

### The header

`# key: value` lines **before the first indicator** configure the feed. After
that point a `#` line is an ordinary comment — so an operator annotating a
block halfway down a file cannot silently restate the provenance of
everything above it.

| Key | Meaning |
|---|---|
| `name` | Feed name, as it appears in findings. Defaults to the filename. |
| `confidence` | What the feed claims to know, `0.0`–`1.0` or `85%`. |
| `updated` | When the feed was last refreshed. Fallback age for undated entries. |
| `reference` | Where the intelligence came from. Recorded, never fetched. |
| `tlp` | Handling marking, carried into the evidence payload. |

Anything else in the header is kept verbatim and carried through rather than
discarded.

A `confidence` outside `0.0`–`1.0` is **refused, not clamped**. A feed
claiming `4.2` has told us its scale is not ours, and inventing a reading of
it would manufacture exactly the provenance this format exists to preserve.
The feed is treated as unprovenanced instead.

### Indicator lines

The value, then optional `key=value` attributes:

| Attribute | Meaning |
|---|---|
| `added` (or `first_seen`) | When this entry was recorded. Overrides the feed's `updated`. |
| `confidence` | Overrides the feed's declared confidence for this entry. |
| `note` | Free text, carried into the evidence payload. |

Dates are read as `YYYY-MM-DD`, `YYYY/MM/DD`, `DD/MM/YYYY`, or either with a
time appended. A date that cannot be read is an **unknown** date, not a
guessed one — see below, because unknown and old are treated differently.

Unrecognised attributes are kept rather than dropped, so a field this parser
did not anticipate still reaches the evidence payload.

### What each line is inferred to be

From the text itself, never from the filename, because mixed files are the
norm once a feed has been exported by hand:

| Kind | Recognised as | Matched against |
|---|---|---|
| `ip` | An IPv4 or IPv6 address | Connection and alert addresses, and DNS answers |
| `cidr` | An address with a prefix, e.g. `185.220.101.0/24` | The same, by containment |
| `domain` | Two or more hostname labels | DNS query names, and every name beneath it |
| `file_hash` | 32, 40, 64 or 128 hex characters | *Nothing yet — see below* |
| `url` | A scheme, or a host with a path | *Nothing yet — see below* |

A line that is not a plausible indicator of any kind is skipped, counted, and
reported by `voidai doctor` with the line as written. One fat-fingered entry
must not cost the other three hundred and ninety-nine.

A **single label** cannot become a domain indicator. `com` on its own would
match every name beneath a whole TLD on the parent walk, so it is rejected.

---

## How a match is scored

Not by a weighted geometric mean. Every other analyzer in VoidLexicon measures
something and combines the measurements; this one performs a **join**, and a
list membership is binary — the value is in the file or it is not.

So the confidence comes from properties of the *feed*, and from nothing else:

```
confidence = declared confidence  x  age decay
```

A host that contacted a known C2 once and a host that contacted it four
thousand times have the same intelligence behind them. Nothing about the
observed traffic enters the score, and a test fails if that stops being true.

### Provenance that is absent is not provenance that is zero

| Situation | Result |
|---|---|
| Feed declares a confidence | That value is the base |
| Feed declares none | Base is `0.25` — low, and below the MEDIUM threshold |
| Indicator has a date | Base decays on a 180-day half-life |
| Indicator has no date | Confidence is **capped** at `0.35`, not decayed |

The cap in the last row is the point. A missing date is an *unknown* age, and
substituting zero would score an undated indicator **higher** than a dated one
a month old — rewarding the feed that recorded less. A cap says the claim
cannot be made strongly, which is what was actually established.

### Age is measured against the capture, not the clock

The question that matters is how stale the indicator was **when the traffic
happened**, not how stale it is now that someone is reading. It is also what
keeps identity reproducible: every ID in the Lexicon is content-addressed, so
an age derived from `datetime.now()` would give the same run a different
evidence ID every day and last week's citations would resolve to nothing.

### Stale intel is worse than none

An indicator from 2019 firing on a residential address reassigned three years
ago is a false positive with a citation attached — and a citation is the thing
an analyst is least likely to re-check. Two mechanisms drop those:

- Nothing older than **730 days** is reported, whatever it declares.
- Anything decaying below **0.10** confidence is dropped.

At default settings a well-provenanced indicator two years old lands at 0.07
and is gone before it can be written down.

### Severity is capped at MEDIUM

A list membership is corroborating evidence, not a conclusion. A file dropped
into a directory must not be able to outrank VoidLexicon's own measurements, which
is the same rule `alerts.py` applies to a signature firing.

---

## Loaded but inert

URL and file-hash indicators parse, index, and count — and nothing in this
repository can match them yet. There is no HTTP log parser and no process
telemetry until the host and inventory work landed.

They are loaded anyway, because the alternative is a parser that misreads them
as domains and produces indicators that can never match. `voidai doctor`
reports them as inert so an operator is told rather than left to assume.

---

## Duplicates across feeds

Two feeds naming the same address is the normal case, not an error. The entry
retained is the one that can support the stronger claim: higher declared
confidence first, then more recently added. A precise indicator is not
shadowed by a bulk list that happened to load first.

---

## What is deliberately not here

**MISP and STIX.** Both are worth having and neither is hard; a newline list
is what an operator can produce in every environment, including the ones where
this runs, so it came first.

**Any retrieval at all.** No fetch, no refresh, no "update on start". Rule 11
engineering rule, asserted by `tests/test_offline.py`. This is the work
most likely to tempt someone into an HTTP call, and the whole architecture
rests on the call not being made.
