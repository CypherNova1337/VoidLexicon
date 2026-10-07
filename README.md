<div align="center">

# VoidLexicon

**A local-first, evidence-bound agent runtime for cyber defence.**

*Runs on a $80 board. Cites every claim. Tells you what it cost.*

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Arch](https://img.shields.io/badge/arch-aarch64%20%7C%20x86__64-lightgrey.svg)](docs/deployment.md)

</div>

---

> *"The limits of my language mean the limits of my world."*
> — Ludwig Wittgenstein

VoidLexicon takes that sentence literally.

Most security AI is a language model holding a log file, asked politely not to
make things up. It makes things up anyway, because nothing in its architecture
prevents it. The model's world is unbounded, so its claims are too.

VoidLexicon inverts this. At its centre is the **Lexicon** — a closed, typed
vocabulary of propositions the system is permitted to assert, and a grammar
governing which nouns each verb accepts. An assertion outside the Lexicon is
not "low confidence." It is **unsayable**: it has no representation, so it
cannot reach an analyst. Every proposition that *is* sayable must carry a chain
of custody down to a specific byte range in a specific source file.

The result is a defensive AI that cannot hallucinate a finding, because
findings are not something it is able to author freely.

---

## The architectural bet

```
   telemetry ──▶  Ingest  ──▶  Analyzers  ──▶  Correlate  ──▶  Reason  ──▶  Propose
                 (parsers)    (statistics,     (per-host      (small      (analyst
                              no model)         incidents,     model)      approves)
                                                ranked)
                                        │
                    Lexicon ────────────┴──────── binds every stage
                                        │
                    Receipt ── joules · tokens · seconds · watts
```

**The language model never sees a raw log.**

Detection is done by deterministic parsers and vectorised statistics. The model
receives only a compressed, token-budgeted *evidence brief* — a few hundred
tokens of already-grounded findings — and does the three things it is genuinely
good at: ranking competing hypotheses, narrating a correlation, and
recommending an analyst's next step. Its output is constrained to a Lexicon
schema and then passed through a **claim verifier** that strikes any sentence
whose cited evidence IDs do not resolve.

Measured, on the top-ranked CTU-13 incident with Qwen2.5-1.5B at 4-bit on four
CPU threads: a **256-token brief**, 188 tokens of response, 28.9 seconds, and
**zero struck claims**. Detection ran at 332,759 records/second in the same
run — the two stages are metered separately, because folding a model's writing
time into detection throughput would understate it by two orders of magnitude.

It is also why detection quality is identical with the model switched off:

```console
$ voidai run ./capture --no-llm
```

You lose the narrative. You do not lose a single finding. **Detection was never
the model's job.**

---

## What it does today

| Agent | Method | Status |
|---|---|---|
| **C2 Beaconing Analyzer** | Six-signal ensemble: interval regularity, schedule-floor tightness, payload uniformity, adaptive-bin autocorrelation, coverage, estate-wide destination rarity — over burst-coalesced arrivals | **working** |
| **Fan-out / Scan Detector** | Destination breadth against revisit rate, per port | **working** |
| **Volume & Egress Analyzer** | Egress ratio, robust volume deviation against the host's own baseline, estate-wide destination rarity, destination novelty | **working** ³ |
| **Correlation & ranking** | Findings → per-host incidents, ordered by noisy-OR across independent behaviours; unary findings attach to the host that reached the indicator | **working** |
| **Temporal ordering** | `precedes` between adjacent behaviours in an incident, gated on whether the two observations share a sensor clock | **working** ⁷ |
| **Language layer** | Token-budgeted evidence brief → grammar-constrained small model → claim verifier | **working** |
| **DNS Tunnelling Detector** | Label entropy, subdomain cardinality, query length, qtype skew | **working** ¹ |
| **PassiveDNS / Zeek DNS / EVE ingest** | Real query names and Suricata alerts | **working** |
| **Suricata Alert Triage** | Deduplication, estate-wide signature rarity, category weighting | **working** ² |
| **Threat Intel Matcher** | Local IOC files joined to addresses, netblocks and DNS names; confidence from feed provenance and indicator age, never from traffic volume | **working** ⁴ |
| **DGA Detector** | Per-family NXDOMAIN rate, bigram improbability against an embedded English character model, digit and consonant structure | **working** ⁵ |
| **Rare Process & Lineage Analyzer** | Estate-wide image prevalence, a graded prior over where a binary lives, and parent→child edges scored as conditional breadth over a directed lineage graph | **working** ⁸ |
| **Sysmon JSON-lines ingest** | Windows process creations from any collector's newline-delimited JSON. No EVTX dissector, no new dependency | **working** |
| **TLS Fingerprint Rarity** | Estate-wide JA3 prevalence, weighted by how much estate the rarity was measured over | **working** ⁶ |
| **Zeek ssl.log ingest** | TLS sessions and JA3/JA3S client fingerprints | **working** |
| **Hunt Query Generator** | Ranked incident → Sigma / KQL / SPL / Zeek, by templating, no model | **working** |
| **Web Attack Detector** | Signature + statistical hybrid over access logs | planned |

¹ Split validation, reported separately. **False positives are measured on
real traffic**: zero findings across 3,655 real DNS records from 18 hosts —
Akamai chains, update services, telemetry, certificate status lookups. **True
positives are synthetic**, since no labelled tunnelling corpus was reachable.
So the analyzer is *known* not to fire on real benign DNS, and *believed* to
fire on real tunnels. The difference is recorded rather than blurred.

² Synthetic validation. The Stratosphere captures carry NetFlow and
passivedns but no EVE output, so no real alert stream was reachable.

³ **Accuracy synthetic, ranking real.** Against a seeded corpus whose benign
traffic is a nightly backup, a cloud sync and a software mirror — large,
outbound and scheduled, which is three of the four things exfiltration is — it
finds 4 of 4 planted transfers with one false positive, on a backup target
only one machine uses. CTU-13 returned no precision figure but two design
corrections, both about the same thing: **a claim is bounded by what was
measured.** A verb whose defining signal is missing is unsayable, so
`exfiltrates_to` — an *outbound* claim — is unreachable on NetFlow, which
records no direction; and a finding resting on partial evidence may be
reported but may not corroborate. Missing either cost the infected host three
queue positions and took corroborated incidents from 3 to 33. The synthetic
corpus could not have found either, because its traffic always has direction.
See [`docs/benchmarks.md`](docs/benchmarks.md) §7.

⁴ **Synthetic, and there is no detection rate to measure.** A match is a join,
not a measurement: the detection was performed by whoever wrote the feed, and
the only question worth scoring is whether the join is correct and whether
what it claims is bounded by what the file said. So confidence comes from the
feed's declared confidence and the indicator's age — **never** from how much
traffic was seen, since one contact with a known C2 and four thousand carry
the same intelligence. An undated indicator is *capped* rather than assumed
fresh, because substituting a zero age would score it higher than a dated one
a month old and reward the feed that recorded less. Nothing is fetched at
runtime, ever: IOC sets are files the operator places on disk, and
`tests/test_offline.py` severs sockets and asserts the pipeline still
completes. Format and scoring in [`docs/ioc.md`](docs/ioc.md);
[`docs/benchmarks.md`](docs/benchmarks.md) §8 for what is and is not measured.

⁵ **Specificity real, sensitivity synthetic.** Zero findings across the real
passivedns corpus — and measured *without* its heaviest component, since that
capture records no `rcode`, which makes the result conservative rather than
optimistic. The closest real name is `crwdcntrl.net` at 0.546 against a 0.65
threshold, a margin pinned by a test. True positives are synthetic: 3 of 4
planted families, the fourth a **dictionary generator counted as a miss**
rather than dropped from the denominator, because a family built from
concatenated words is more English than English and this model cannot see it.
Public DGA feeds exist but none was vendored — nothing is fetched, and no
redistribution licence was verified.

The component the plan called for is not in the list above, and that is the
result worth reading: **Shannon entropy does not work at this length.** A
second-level label is 6 to 20 characters, where per-character entropy is
bounded by `log2(len)` and so measures length rather than randomness — real
labels average 0.855 of their maximum against 0.893 for random strings, and
0.807 for hex, which scores an encoded family as *more natural* than
`googleapis`. It was measured, and removed.
[`docs/benchmarks.md`](docs/benchmarks.md) §9.

⁶ **Synthetic on both sides.** No openly-licensed `ssl.log` corpus carrying
JA3 was reachable, so this measures the arithmetic and not the detector: 2 of
2 planted implants, no false positive, against decoys that are the two ways a
prevalence measure goes wrong — a fingerprint seen once, and one shared by two
hosts. Its threshold was set after watching a decoy fire on a corpus written
by the same hand as the detector; the rule it encodes — that two hosts need a
larger estate to be unusual than one does — is the part to trust. JA3 comes
from a Zeek package rather than the core script, so the column is often absent
and `voidai doctor --telemetry` reports which of the three states a capture is
in. A rare fingerprint is reported but **does not corroborate**: an implant
beaconing over TLS earns a beaconing finding and a fingerprint finding from
the same connection, which is one behaviour measured twice.

⁷ **Nothing measured, by construction — it is a rewrite of what an incident
contains, not a detector.** `precedes` claims no new observation: it orders
findings the analyzers already produced, so there is no detection rate to
score and no corpus that could supply one. What is checkable is that it never
reaches a score. An ordering is derived from findings *inside* the incident,
so letting it count would be the incident inflating itself by describing its
own contents — which is the same circularity that keeps observed volume out of
an intel score. It is excluded from both the corroboration multiplier and the
noisy-OR, and measured against the old correlator over 250 incidents that is
exactly nil: **zero priorities changed and zero ranks moved.**

The gate is what the design turns on. Two log sources on one host can be
seconds or hours apart, and which it is depends on whether they share a
sensor — so the floor is one second within a single source and five minutes
across two, read off the `source` each Artifact already names. Below the floor
nothing is said rather than said and hedged. On `voidai demo` that leaves a
single edge out of a possible five, because the generator plants every
behaviour in the same second; the demo capture has no sequence to narrate, and
the analyzer declines to invent one.

Alongside it, `matches_threat_intel` — unary, with the *indicator* as its
subject — now attaches to the incident of every host that reached the
indicator, instead of forming an incident of its own. The proposition is left
untouched, because rewriting it to take the host as subject would make it
false: a host does not appear in a feed. It **does not corroborate**, and not
for want of evidence — a match is complete evidence of exactly what it claims.
The multiplier counts independent *behaviours of a host*, and an intel hit is
not a second thing the host did; it is better information about the first
thing. Letting it count would hand a stale or over-broad feed the power to
multiply the priority of every host that touched anything in it.
[`docs/benchmarks.md`](docs/benchmarks.md) §10.

⁸ **Synthetic sensitivity, and a real *refusal* rather than a real
detection.** This is the first result here shaped that way, and it is the one
worth reading. A real, openly-licensed, correctly-formatted corpus of Windows
attack telemetry is committed — OTRF Security-Datasets, MIT, licence verified
by fetching it, 447 process creations from the APT29 ATT&CK Evaluations
emulation — and it contains a genuine true positive. **The analyzer declines
to score it.** Four hosts over half an hour is not an estate: 74% of the
images in that capture are seen on exactly one machine, `lsass.exe`,
`explorer.exe`, `csrss.exe` and `winlogon.exe` among them, so a rarity measure
over it ranks `lsass.exe` identically with the attacker's payload. Reporting
the payload would mean reporting `lsass.exe`.

Both verbs are *estate-relative* — the Lexicon says "rare across the observed
estate" and "inconsistent with normal system behaviour" — so estate prevalence
is not a component of these scores, it is the signal that **defines** them.
With it unavailable the verb is unsayable, and unlike the volume analyzer
there is no weaker predicate to fall back to. So the analyzer gates and emits
nothing, and `voidai doctor --telemetry` prints which floor was missed, because
"declined" and "found nothing" look identical from outside.

Synthetic: 6 of 6 planted executions across two shapes that cannot see each
other — three novel binaries found by rarity, three *entirely ordinary*
binaries in an impossible relationship (`winword.exe → cmd.exe →
powershell.exe`) found by lineage. One false positive, a legitimate installer
in a user's Downloads folder, which is planted and **stays**: every threshold
that removes it also removes a staging tool in `C:\Users\Public`.

The component the plan called for is missing again, and again it was measured
rather than argued: **command-line entropy does not work**, for a different
reason than §9's. The encodings attackers actually use are *less* entropic
than ordinary command lines — base64 of UTF-16LE is half null bytes — and the
7,106-character payload in that capture sits at the **38th percentile** of its
own corpus, below a routine `SearchProtocolHost.exe` invocation.
[`docs/benchmarks.md`](docs/benchmarks.md) §11.

### Measured, on real malware traffic

Validated against [CTU-13](https://www.stratosphereips.org/datasets-ctu13) —
real botnet captures on a university network, with per-flow ground truth.

| | CTU-13 #3 (Rbot, 66.8h) | CTU-13 #6 (Menti, 2.15h) |
|---|---|---|
| Flows | 10,159,384 | 1,605,474 |
| **Infected host, queue rank** | **2 of 275** | **1 of 176** |
| Findings → incidents | 2253 → 275 | 596 → 176 |
| Corroborated incidents | 3 | 1 |
| Throughput | 114k rec/s | 105k rec/s |
| Peak RSS | 2.7 GB | 0.6 GB |

Re-measured in October 2026 after a parser correction. These files pad a short
field with an extra tab so their columns line up on screen, and the first
parser read them positionally: 29% of scenario 6's rows and 41% of scenario
3's were misread, and earlier versions of this table were measured on them.
Read correctly, the two rows that matter held — the infected host is still
rank 2 and rank 1, and corroborated incidents are still 3 and 1. Throughput
fell, partly because the parser now normalises each line before splitting it,
and partly because traffic that had collapsed onto one false destination is
now spread across real ones.

Reproduce with `voidai bench` and `voidai bench --real <capture>`.

**Ranking is the whole game.** Beaconing alone puts the scenario 6 C2 at rank
376 of 415 — detected and invisible are the same thing to an analyst working a
queue. The fix was not a better periodicity measure: the findings outranking
it were *genuinely* beacon-like monitoring agents and backup jobs. What
separates a compromised host is that it does several suspicious things at
once. A second analyzer plus correlation by corroboration moved it to rank 1.

[`docs/benchmarks.md`](docs/benchmarks.md) has the full account, including the
real bugs that only real captures exposed — among them a beaconing signal that
turned out to be measuring an artifact of our own synthetic generator, a
textbook flow-orientation rule that silently deleted the one true positive in
a capture, and the padded columns above.

---

## What the typed vocabulary buys you

The Lexicon's payoff is not philosophical. A finding written as prose cannot
be mechanically turned into a detection rule — something has to read it and
decide what the indicator was and which field it belongs in. A finding written
as a *typed proposition* already carries all of that, so the transformation is
templating:

```console
$ voidai hunt ./capture --dialect sigma
```

```yaml
title: "Other hosts resolving under tunnel-example.com"
id: 871b23d0-a11b-5608-9751-55334a102e9a
description: |
  Hunt generated by VoidLexicon from finding fnd_dfd6fdc69e7d7afb.
  A tunnelling zone is attacker infrastructure. Any other host querying it is
  a candidate for the same implant.
logsource:
  category: dns_query
detection:
  selection:
    query|endswith: ".tunnel-example.com"
  filter_known:
    src_ip: "10.0.1.14"
  condition: selection and not filter_known
level: critical
```

**No model is involved in generating that**, and none is needed. Four dialects
are emitted — Sigma, KQL, SPL, and a `zeek-cut` pipeline for estates with no
SIEM at all.

Two details in that rule are the whole point of the exercise:

**It excludes the host you already know about.** A query that re-finds the
traffic which produced the finding returns nothing you don't have. VoidLexicon sees
one sensor's window; the SIEM holds the estate's history, and the only useful
question to ask it is *who else*.

**It matches the zone as a suffix.** Every tunnelled query is
`<encoded-chunk>.tunnel-example.com` and none is the apex — so an equality
test would return nothing, forever, and read as a clean estate. That failure
is invisible in review, so the Zeek pipelines are *executed* in the test suite
against logs with known contents and their output compared to the answer.

The same tests paste attacker-controlled values into every dialect: quotes,
backslashes, a Splunk wildcard, and a shell break-out attempt. Indicator
values come out of logs, a generated query gets pasted into a console holding
production credentials, and treating that string as trusted because *we*
generated it would be exactly backwards.

---

## Design commitments

These are constraints on the codebase, enforced in review and in tests — not
aspirations.

**Nothing leaves the machine.** No telemetry, no API calls, no model
downloads at runtime, no update checks. VoidLexicon runs correctly with the network
interface down, and the test suite asserts it.

**Every dependency installs on a Pi.** No CUDA, no compiler toolchain, no
wheel that lacks an `aarch64` build. The language layer is an *optional extra*;
the core is six libraries.

**"Fits on a Pi" is measured, not asserted.** `tools/envelope.py` runs the
pipeline inside a cgroup whose memory limit and swap are pinned together — the
mechanism a board with no swap enforces. It corrected this README: the 66-hour
capture was documented as needing more than a 4GB board, and in fact completes
inside a 2,200 MB ceiling, peaking near 2.1 GB, which leaves a 4GB board
roughly 1.5 GB spare. Held to 3 GB and a **single** core it takes six minutes
and still returns the infected host at **rank 2 — the unconstrained result**.
`voidai demo` completes inside 192 MB. This is not an ARM test and is not
offered as one; see [`docs/deployment.md`](docs/deployment.md).

**Small by construction.** The target model tier is 1.5B–4B parameters at
4-bit quantisation. If a finding requires a larger model, the correct fix is a
better analyzer, not a bigger model.

**Semi-autonomous, always.** VoidLexicon proposes; a human disposes. It has no
capability to block an IP, kill a process, or modify a rule. Actions are
emitted as reviewed recommendations, and there is no execution path — by
absence, not by policy toggle.

**Self-accounting.** Every run prints an itemised receipt: joules, tokens,
wall time, peak RSS. Energy is labelled `measured` when it comes from a real
counter (RAPL, INA3221) and `estimated` when it comes from a platform model.
An estimate is never dressed up as a measurement.

---

## Try it

```bash
voidai demo
```

Generates a capture in five real sensor formats — Zeek `conn.log`, Zeek
`ssl.log`, passivedns, Suricata EVE, Sysmon JSON lines — plus a one-line asset
inventory, runs the full pipeline, and puts the compromised host at the top of
the queue. One host beacons, sweeps a port, tunnels DNS, resolves
algorithmically generated domains, trips two rare signatures, runs a binary the
estate has never run and lets an Office application spawn a shell; nothing in
the data labels it. Under a second, no model, no GPU, no network.

```
 #  Severity  Prio  Subject                    Behaviours                                          Findings
 1  CRITICAL  2.50  host:FINANCE-WS04          beacons_to, executes_rare_process, exhibits_anom…        13
 2  MEDIUM    0.98  host:WS019.contoso.local   executes_rare_process                                      1
 3  CRITICAL  0.89  ip:10.0.1.23               tunnels_dns_over                                           1
 4  HIGH      0.87  ip:10.0.1.17               beacons_to                                                 1
 5  HIGH      0.85  ip:10.0.1.13               beacons_to                                                 1
```

```
inventory   1 of 1 mapping(s) applied — resolved 1 of 109 observed address(es) (0.9%)
```

**Row 1 is one machine because one line of a file says so.** Sysmon records a
computer name and no address, so the network sensors and the endpoint agent
describe `10.0.1.14` and `FINANCE-WS04` with nothing to join them; until this
release the queue carried them as two incidents, ranked 2.50 and 1.50, neither
corroborating the other. The capture now ships `assets.inv` with a single
mapping, and the queue goes from ten incidents to nine with patient zero
carrying seven corroborating behaviours instead of five and two. Every renamed
finding cites the file and line that renamed it, along with how old that
statement was when the traffic ran — see [docs/inventory.md](docs/inventory.md),
because a mapping that is wrong attaches a beacon to an innocent machine with a
clean chain of custody.

The coverage figure is the second number that matters, and it is not
flattering: one line names one address out of a hundred and nine the capture
contains. That is the honest reading of a one-line inventory, and it is
reported next to the mapping count precisely so an inventory covering 3% of an
estate cannot be mistaken for one that covers it.

Row 2 is the planted false positive — a legitimate installer, run once, from a
user's Downloads folder — left in rather than tuned away. It was rank 3 before
the inventory and it is rank 2 now, still above four genuine detections. That
is the argument for the inventory stated more plainly than any figure above:
the join did not make it a better false positive, it removed the duplicate row
that was hiding how highly it already ranked.

## Installation

```bash
git clone https://github.com/CypherNova1337/VoidLexicon
cd VoidLexicon
python3 -m venv .venv && source .venv/bin/activate

pip install -e .            # core: detection, correlation, receipts
pip install -e ".[llm]"     # optional: the narrative layer
pip install -e ".[tui]"     # optional: the operator console
```

Core install pulls six runtime dependencies and needs no compiler.

## Usage

```bash
voidai run ./zeek-logs/                 # detection pipeline over a log directory
voidai run ./zeek-logs/ --model m.gguf   # add the narrative layer
voidai run ./zeek-logs/ --no-llm        # detection only; findings are unchanged
voidai run ./zeek-logs/ --evidence      # print the full evidence chain per finding
voidai run ./zeek-logs/ --intel ./ioc/  # match local IOC files; read from disk, never fetched
voidai run ./zeek-logs/ --inventory ./assets/  # name hosts from an asset inventory; read, never derived
voidai hunt ./zeek-logs/                # ranked incidents → Sigma rules
voidai hunt ./zeek-logs/ -d kql         # …or KQL, SPL, or a zeek-cut pipeline
voidai hunt ./zeek-logs/ --out ./rules  # write one file per query
voidai bench                            # seeded synthetic accuracy + energy benchmark
voidai bench --real <capture>           # score against a labelled real capture
voidai demo                             # generate a capture and run everything
voidai lexicon                          # print the complete grammar
voidai doctor                           # pre-flight: platform, energy source, model
voidai doctor --intel ./ioc/            # …and what the IOC files actually loaded
voidai doctor --inventory ./assets/     # …and how much of the estate the inventory covers
voidai doctor --telemetry ./logs/       # …and whether the estate can support a rarity claim
voidai version                          # version and detected power profile
```

Every command prints a run receipt unless given `--no-receipt`.

## Documentation

- **[`docs/proposal.md`](docs/proposal.md)** — the project proposal: problem,
  architecture, results, and what real data changed
- [`docs/benchmarks.md`](docs/benchmarks.md) — measured accuracy, energy, and
  what real captures changed about the design
- [`docs/ioc.md`](docs/ioc.md) — the local IOC file format, and why a match is
  scored from the feed's provenance rather than from the traffic
- [`docs/inventory.md`](docs/inventory.md) — the asset inventory file format,
  and why a mapping is judged against the capture's date rather than today's
- [`docs/models.md`](docs/models.md) — supported open-weight models, and what a
  1.5B model got wrong before the prompt was fixed
- [`docs/deployment.md`](docs/deployment.md) — Pi 5, Jetson and x86, including
  how to get *measured* rather than estimated energy

## Licence

Apache-2.0. See [LICENSE](LICENSE).
