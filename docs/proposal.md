# VoidLexicon — Project Proposal

**A local-first, evidence-bound agent runtime for cyber defence.**

Runs on hardware an individual owns. Cites every claim to a byte range in a
source file. Prints what it cost to run.

```bash
git clone https://github.com/CypherNova1337/VoidLexicon && cd VoidLexicon
python3 -m venv .venv && source .venv/bin/activate && pip install -e .
voidai demo
```

That command generates a capture in three real sensor formats, runs the full
pipeline, and puts the compromised host at the top of the queue. It takes
under a second and needs no model, no GPU, and no network.

---

## 1. The problem

Security AI is mostly a language model holding a log file, asked politely not
to make things up. It makes things up anyway, because nothing in the
architecture prevents it — and in this domain a confident fabrication is worse
than silence. An invented IP address in an incident report reads exactly like
a real one, and an analyst who finds one invention stops trusting the other
ninety-nine findings, correctly.

The second problem is quieter and kills more deployments. Detectors that work
produce more alerts than anyone can read. During development, VoidLexicon's own
beaconing analyzer found the command-and-control channel in a real botnet
capture and buried it at **rank 358 of 395**. Detected and invisible are the
same thing to an analyst working a queue.

## 2. The central idea

> *"The limits of my language mean the limits of my world."*

At the centre of VoidLexicon is the **Lexicon**: a closed, typed vocabulary of
propositions the system is permitted to assert, and a grammar governing which
nouns each verb accepts. Eighteen predicates, each with declared subject and
object types, a description, a default severity and ATT&CK mapping.

An assertion outside the Lexicon is not "low confidence". It is **unsayable** —
it has no representation, so it cannot reach an analyst. And every proposition
that *is* sayable must carry a chain of custody:

```
Artifact  →  Evidence  →  Finding  →  Incident  →  Claim
(a line in  (a measured  (a grounded (correlated  (language-layer
 a file)     observation) assertion)  cluster)     commentary)
```

Nothing may skip a link. A `Finding` with no `Evidence` is rejected at
construction; a `Claim` citing an unknown `Finding` is struck by the verifier.
Both are enforced by the type system, not by convention — a provenance rule
that lives in a style guide is a provenance rule that is already broken.

Identifiers are content-addressed, so re-running an investigation reproduces
the same IDs. Citations in last month's report still resolve.

## 3. Architecture

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

**The language model never sees a raw log.** Detection is deterministic
statistics. The model receives only a token-budgeted *evidence brief* — a few
hundred tokens of already-grounded findings — and does the three things it is
genuinely good at: narrating a correlation, ranking hypotheses, and suggesting
a next step. Its output is grammar-constrained and then verified.

This is what lets it run on a CPU. It is also why detection quality is
identical with the model switched off.

### Four analyzers, no model in any of them

| Analyzer | Method |
|---|---|
| **Beaconing** | Interval regularity, schedule-floor tightness, payload uniformity, adaptive-bin autocorrelation, coverage, estate-wide destination rarity — over burst-coalesced arrivals |
| **Fan-out** | Destination breadth against revisit rate, per port |
| **DNS tunnelling** | Label entropy, subdomain cardinality, query length, qtype skew |
| **Alert triage** | Deduplication, estate-wide signature rarity, category weighting |

Every one combines its signals with a **weighted geometric mean** rather than
an average. An average lets one strong signal carry a detection alone — which
is exactly how a periodic software updater gets reported as C2. A geometric
mean requires every dimension to hold up.

### Correlation is where ranking lives

A `Finding` answers *"how beacon-like is this traffic?"*. An `Incident` answers
*"how much should an analyst care about this host?"*. Conflating those two
questions is what buried the true positive at rank 358.

Findings are grouped by subject and ordered by noisy-OR over the strongest
finding **per predicate**, times a corroboration bonus. Per-predicate
deliberately: twenty beaconing findings on one host are twenty views of one
behaviour, not twenty independent reasons to believe it.

### The typed vocabulary earns its keep at the exit

A finding written as prose cannot be mechanically turned into a detection
rule; something has to read it and decide what the indicator was and which
field it belongs in. A typed proposition already carries the predicate, the
declared entity types and the measured values, so `voidai hunt` transforms it
into Sigma, KQL, SPL or a `zeek-cut` pipeline by **templating, with no model
in the path**.

The generated hunts pivot on the *indicator* and exclude the subject already
known — VoidLexicon sees one sensor's window, the SIEM holds the estate's history,
and the only useful question to ask it is *who else*. A DNS zone is matched as
a suffix rather than for equality, because every tunnelled query is
`<chunk>.zone` and none is the apex: the equality test parses, runs, returns
nothing forever, and reads as a clean estate. Because that failure is
invisible in review, the Zeek pipelines are executed in the test suite against
logs with known contents and their output compared against the answer, with
attacker-crafted indicator values included.

## 4. Results

### On real malware traffic — CTU-13

Thirteen captures of real botnet traffic on a university network, per-flow
ground truth, CC-BY.

| | Scenario 3 (Rbot, 66.8h) | Scenario 6 (Menti, 2.15h) |
|---|---|---|
| Flows analysed | 12,689,947 | 1,916,655 |
| **Infected host, queue rank** | **2 of 247** | **1 of 160** |
| Findings → incidents | 1589 → 247 | 512 → 160 |
| Throughput | 207k rec/s | 180k rec/s |
| Peak memory | 2.6 GB | 0.6 GB |

Three network analyzers. The rank held at 2 and 1 when the third was added,
against larger queues; peak memory did not move, because analyzers run
sequentially and release.

Ranking is the whole story. Beaconing alone put scenario 6's C2 at rank 358 of
395. The fix was not a better periodicity measure — the findings outranking it
were *genuinely* beacon-like monitoring agents and backup jobs. What separates
a compromised host is that it does several suspicious things at once.

### DNS tunnelling — real specificity

Across **3,655 real DNS records from 18 hosts** — Akamai CNAME chains, update
services, telemetry, certificate status lookups — the analyzer emits
**nothing**. Only one zone even passed the volume gates, scoring 0.065 against
a 0.62 threshold. That is the half no generator can honestly test.

### Inside a Pi's resource envelope

A claim that something "runs on a $80 board" is worth nothing unless the board's
limits were actually applied. `tools/envelope.py` runs the pipeline inside a
cgroup whose memory limit and swap are pinned to the same value — the mechanism
a board with no swap enforces — so the answer is measured rather than believed.

It corrected this project's own documentation. The 66-hour capture was recorded
as needing more than a 4GB Pi could give. Bisected against a hard ceiling it is
OOM-killed at 2,400 MB, *flaky* at exactly 2,500 MB, and completes reliably from
2,600 MB, settling at a 2,545 MB peak. A 4GB board clears that with roughly
1.1 GB spare.

The load-bearing result is the combined envelope: 12.7M flows held to 3 GB and a
**single** 2.1GHz core complete in 166 seconds and return the infected host at
**rank 2 of 214 — identical to the unconstrained run** at the time it was
measured, with two analyzers. Constraining the board
changes how long the answer takes, not what the answer is. The whole pipeline
including Qwen2.5-1.5B peaks at 2,072 MB, and `voidai demo` runs in 512 MB.

This is not an ARM test, and is not presented as one. Memory ceilings and core
counts are reproduced exactly by the kernel; the instruction set is x86-64 and
cannot be. That distinction is the point of reporting it this way.

### The language layer

Qwen2.5-1.5B at 4-bit, four CPU threads: a **256-token brief**, 188 tokens of
response, 28.9 seconds, **zero struck claims**. Detection ran at 332,759
records/second in the same run — the two stages are metered separately.

### Test suite

738 tests. Includes one that severs sockets and asserts the whole pipeline
still completes, backing the offline claim rather than merely stating it, and
a set that *executes* generated hunt queries against logs with known contents
— because a query that parses but matches nothing looks exactly like a clean
estate.

## 5. Against the eleven principles

| Principle | How |
|---|---|
| **1. Independent, local** | No API, no cloud, no account. Runs with the interface down. |
| **2. Lightweight** | CPU-only detection; every run prints joules. 0.71 s and 20 J for a 74,000-record capture. |
| **3. Open-source models** | Qwen2.5 (Apache-2.0) measured; the backend is model-agnostic GGUF. |
| **4. Your data is yours** | Nothing leaves the machine; asserted by test. The model never sees a raw log, so telemetry cannot reach a prompt. |
| **5. Small is beautiful** | 1.5B–4B target. The architecture is what makes it sufficient: the model reads a few hundred tokens, never gigabytes. |
| **6. Curated data** | Every corpus is labelled, seeded and documented. The Lexicon is itself a curated vocabulary. |
| **7. Semi-autonomous** | VoidLexicon proposes; a human disposes. There is **no code path** that blocks an address or kills a process — enforced by absence, not a policy toggle. |
| **8. Agile** | Adding an analyzer is one line in a registry; a test asserts the CLI cannot drift from it. |
| **9. ARM** | Pure Python, no compiled core, no CUDA. `aarch64` is a first-class target with a deployment guide. |
| **10. Neural networks are one way** | **The strongest alignment.** Detection uses no neural network at all — robust statistics, Otsu thresholding, entropy, graph correlation. Even the SIEM hunt queries are generated by templating a typed proposition, not by asking a model to write one. The model is confined to language. |
| **11. Secure** | No network, no execution path, no privileged access. Detection runs unprivileged. |

Principle 10 deserves emphasis because it shaped everything. A language model
is a poor detector and an excellent explainer, and VoidLexicon is built on that
division. Every accuracy number above was produced without a neural network in
the loop.

## 6. What is not done

Stated plainly, because a proposal that only lists strengths is not worth
reading.

**Energy is estimated, not measured.** No RAPL access and no ARM hardware yet.
Every figure is labelled `estimated`, and an estimate is never dressed up as a
measurement. A Pi 5 with an INA219 shunt closes this; the wiring recipe is in
`deployment.md`.

**Two analyzers are validated only synthetically.** DNS tunnelling
*sensitivity* and alert triage. Their specificity and reduction behaviour are
measured, but no real corpus carrying tunnels or EVE output was reachable.
Said clearly wherever those analyzers appear.

**Corroboration is shallow on real data.** CTU-13 carries neither DNS names
nor alerts, so on real captures the corroboration signal is only two-valued.
That is a data problem, not a code one.

**Never run on ARM.** The instruction set is the one Pi property that cannot
be imposed on an x86 VM, and it is the remaining risk: different wheels,
128-bit NEON instead of 256-bit AVX2, a different allocator profile. Memory
and core count *have* now been measured against a hard kernel-enforced ceiling
(§4), so what is left untested is architecture alone rather than "the Pi".

## 7. What real data changed

The most useful thing in this project is the list of things that were wrong
until real traffic proved them wrong. All four were invisible against
synthetic data, because synthetic data was built on the same assumptions as
the detector.

**A signal measuring our own generator.** Interval symmetry via Bowley
skewness scored ~1.0 on every synthetic implant — because the generator
applied symmetric jitter by construction. Real C2 is heavily *right*-skewed:
the Menti channel scores +0.948, its tail being missed check-ins at two, three
and five times the base period. The measure was penalising its own best
evidence. Replaced with a hard-floor test: a timer cannot fire early, a person
has no such constraint.

**One check-in is not one record.** NetFlow splits connections, so a 33-second
beacon arrived as 384 records with a *median interval of 0.15 seconds*. Every
statistic measured record framing. Now detected as log-space bimodality via
Otsu's method and coalesced before measurement.

**The textbook rule deletes real C2.** "The server has the lower port" is
wrong: the scenario 6 bot sources from ports 1027–4985 to a controller on
5678. Under that rule the genuine channel is classified as a reply and
deleted, taking the capture's only true positive with it.

**A negation matched by the word it negates.** `"Not Suspicious Traffic"`
scored 0.55 because the substring `"suspicious"` matched first — Suricata's
noisiest category read as moderately suspicious, enough to flood the queue by
itself.

## 8. Reproducing everything

```bash
voidai demo                              # full pipeline, one command
voidai bench                             # seeded synthetic benchmark
voidai bench --real <capture>            # CTU-13, fetch instructions in benchmarks.md
voidai hunt <capture> --dialect sigma    # incidents to SIEM queries
voidai lexicon                           # the complete grammar
voidai doctor                            # platform, energy source, model
pytest                                   # 738 tests
```

- [`benchmarks.md`](benchmarks.md) — every number above, and how it was measured
- [`deployment.md`](deployment.md) — Pi 5, Jetson, x86; measured energy wiring
- [`models.md`](models.md) — supported models, and what a 1.5B model got wrong

## 9. Licence

Apache-2.0. Corpora are CC-BY from Stratosphere IPS, cited where used and not
vendored except for one attributed 400-record test fixture.
