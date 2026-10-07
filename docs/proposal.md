# VoidLexicon — Project Proposal

**A local-first, evidence-bound agent runtime for cyber defence.**
*Entry for the Hackers-Arise Wittgenstein AI Tournament.*

Runs on hardware an individual owns. Cites every claim to a line in a source
file. Prints what it cost to run.

```bash
git clone https://github.com/CypherNova1337/VoidLexicon && cd VoidLexicon
python3 -m venv .venv && source .venv/bin/activate && pip install -e .
voidai demo        # the command-line tool is `voidai`
```

That writes a capture in real sensor formats, runs the whole pipeline and puts
the compromised host at the top of the queue, with no model, no GPU and no
network. Detection itself takes about half a second.

## 1. The problem

Security AI is mostly a language model holding a log file, asked politely not
to make things up. It makes things up anyway, because nothing in the
architecture prevents it — and in this domain a confident fabrication is worse
than silence. An invented IP address reads exactly like a real one, and an
analyst who finds one invention stops trusting the other ninety-nine findings.

The second problem kills more deployments. Detectors that work produce more
alerts than anyone can read. During development, VoidLexicon's own beaconing
analyzer found the command-and-control channel in a real botnet capture and
buried it at **rank 358 of 395**. Detected and invisible are the same thing to
an analyst working a queue.

## 2. The central idea

> *"The limits of my language mean the limits of my world."*
> — Ludwig Wittgenstein, *Tractatus Logico-Philosophicus*, 5.6

At the centre is the **Lexicon**: a closed, typed vocabulary of eighteen
propositions the system is permitted to assert, with a grammar fixing which
nouns each verb accepts. An assertion outside it is not "low confidence". It is
**unsayable** — it has no representation, so it cannot reach an analyst. Every
proposition that *is* sayable carries a chain of custody:

```
Artifact  →  Evidence  →  Finding  →  Incident  →  Claim
(a line in  (a measured  (a grounded (correlated  (language-layer
 a file)     observation) assertion)  cluster)     commentary)
```

A `Finding` with no `Evidence` is rejected at construction; a `Claim` citing an
unknown `Finding` is struck by the verifier. Both are enforced by the type
system, not by convention. Identifiers are content-addressed, so re-running an
investigation reproduces the same IDs and last month's citations still resolve.

The same rule governs measurement. Where a verb's defining signal cannot be
measured, the verb is not scored low — it is not said. NetFlow records no
direction, so on NetFlow the egress analyzer may not assert *exfiltration*.
Four hosts cannot define "rare", so on a four-host estate the host analyzer
emits nothing and says why.

## 3. Architecture

```
telemetry ─▶ Ingest ─▶ Analyzers ─▶ Correlate ─▶ Reason ─▶ Propose
                       (statistics,  (per-host    (small    (analyst
                        no model)     incidents)   model)    approves)
                  Lexicon binds every stage · Receipt meters every run
```

**The language model never sees a raw log.** Detection is deterministic
statistics. The model receives a few hundred tokens of already-grounded
findings and does what it is genuinely good at — narrating a correlation and
suggesting a next step — under a grammar, with every citation verified. That is
why it runs on a CPU, and why detection is identical with the model off.

| Analyzer | Method |
|---|---|
| **Beaconing** | Interval regularity, schedule-floor tightness, payload uniformity, autocorrelation, coverage, destination rarity — over burst-coalesced arrivals |
| **Fan-out** | Destination breadth against revisit rate, per port |
| **Volume and egress** | Egress ratio, volume against the host's own baseline, destination rarity, novelty |
| **DNS tunnelling** | Label entropy, subdomain cardinality, query length, qtype skew |
| **Alert triage** | Deduplication, estate-wide signature rarity, category weighting |
| **Threat intel** | Exact-match join against operator-supplied indicator files |
| **TLS and DGA** | JA3 rarity; NXDOMAIN rate, character improbability and structure of domains |
| **Host** | Estate-relative process rarity and parent→child lineage, from Sysmon |

Seven combine their signals with a **weighted geometric mean**, never an
average: an average lets one strong signal carry a detection alone, which is
how a software updater gets reported as C2 or a nightly backup as exfiltration.
Threat intel is the deliberate exception — a list match is scored only on what
the feed declares, because letting volume raise it would report VoidLexicon's
own observation as corroboration of the feed.

**Correlation is where ranking lives.** Findings are grouped per host and
ordered by noisy-OR over the strongest finding *per predicate*, times a
corroboration bonus: twenty beaconing findings are twenty views of one
behaviour, not twenty reasons. An operator-written asset inventory joins the
address the sensor saw to the hostname the endpoint agent wrote, so one machine
is one incident.

**The typed vocabulary pays off at the exit.** `voidai hunt` turns a finding
into Sigma, KQL, SPL or a `zeek-cut` pipeline by templating, with no model in
the path, pivoting on the indicator to ask the SIEM *who else*. The generated
shell is executed in the test suite against hostile input.

## 4. Results

**Real botnet traffic — CTU-13** (CC-BY, per-flow ground truth):

| | Scenario 3 (Rbot, 66.8h) | Scenario 6 (Menti, 2.15h) |
|---|---|---|
| Flows analysed | 12,689,947 | 1,916,655 |
| **Infected host, queue rank** | **2 of 247** | **1 of 160** |
| Findings → incidents | 1589 → 247 | 512 → 160 |
| Throughput · peak memory | 207k rec/s · 2.7 GB | 180k rec/s · 0.6 GB |

Ranking is the whole story. Beaconing alone put scenario 6's C2 at 358 of 395;
the findings above it were *genuinely* beacon-like monitoring agents. What
separates a compromised host is that it does several suspicious things at once.

**Real specificity.** Across 3,655 real DNS records from 18 hosts, the
tunnelling analyzer emits nothing.

**Inside a Pi's envelope, measured.** `tools/envelope.py` runs the pipeline in
a cgroup with memory and swap pinned to one value — what a swapless board
enforces. The 66-hour capture is killed at 2,200 MB and completes from
2,400 MB with all eight analyzers — no higher than with four, because analyzers
run one at a time and release. A 4GB board clears it with ~1.1 GB spare. `voidai demo` completes inside 192 MB. This is not
an ARM test — the kernel reproduces memory and cores exactly; the instruction
set cannot be.

**The language layer.** Qwen2.5-1.5B at 4-bit on four CPU threads: 256-token
brief, 188-token response, 28.9 s, **zero struck claims**.

**739 tests**, including one that severs sockets and asserts the pipeline still
completes.

## 5. Against the eleven principles

| Principle | How |
|---|---|
| **1. Independent, local** | No API, no cloud, no account. Runs with the interface down. |
| **2. Lightweight** | CPU-only detection; every run prints joules — ~0.5 s and ~15 J (estimated) for 79,300 records. |
| **3. Open-source models** | Qwen2.5 (Apache-2.0) measured; any GGUF model loads. |
| **4. Your data is yours** | Nothing leaves the machine, asserted by test. The model never sees a raw log. |
| **5. Small is beautiful** | 1.5B–4B target; the model reads hundreds of tokens, never gigabytes. |
| **6. Curated data** | Every corpus labelled, seeded and documented. The Lexicon is itself curated. |
| **7. Semi-autonomous** | It proposes; a human disposes. No code path blocks an address or kills a process. |
| **8. Agile** | A new analyzer is one file and one registry line; the last four arrived this way. |
| **9. ARM** | Pure Python, no compiled core, no CUDA; deployment guide for the Pi 5. |
| **10. Neural networks are one way** | Detection uses none — robust statistics, entropy, graph correlation. The model is confined to language. |
| **11. Secure** | No network, no execution path, no privileged access. |

Principle 10 shaped everything: a language model is a poor detector and an
excellent explainer. Every accuracy number above was produced without one.

## 6. What is not done

**Energy is estimated, not measured** — no RAPL or ARM hardware yet, and every
figure says so. A Pi 5 with an INA219 shunt closes it.

**Sensitivity is mostly synthetic.** Beaconing and fan-out are ranked on real
botnet traffic, and DNS tunnelling, DGA and host telemetry have real
*specificity* results. But no openly-licensed capture with labelled tunnels,
exfiltration, EVE alerts, JA3 or DGA traffic was reachable, so the remaining
sensitivity figures come from synthetic data written by the same hand as the
detectors. Threat intel has never fired on a real feed. Each is labelled where
it appears.

**Corroboration is shallow on real data**: CTU-13 has no DNS names, alerts or
TLS, so only three analyzers can fire on it.

**Never run on ARM**, and **four predicates are declared but not built**:
`establishes_persistence`, `authentication_anomaly`, `attacks_web_endpoint`,
`enumerates_web_paths`.

## 7. What real data changed

The most useful thing in this project is the list of assumptions that were
wrong until real traffic proved them wrong — each invisible on synthetic data,
because the generator shared the detector's assumptions. A symmetry measure
that scored our own generator's jitter rather than C2; a beacon arriving as 384
NetFlow records with a 0.15-second median interval; the textbook "server has
the lower port" rule, which deletes scenario 6's only true positive; and
`"Not Suspicious Traffic"` matching the word it negates. Each is written up in
[`benchmarks.md`](benchmarks.md) with the measurement that exposed it.

## 8. Reproducing everything

```bash
voidai demo · voidai bench · voidai bench --real <capture> · voidai hunt <capture>
voidai lexicon · voidai doctor · pytest
```

Every number here is in [`benchmarks.md`](benchmarks.md) with how it was
measured; deployment and models in [`deployment.md`](deployment.md) and
[`models.md`](models.md). Apache-2.0. Corpora are CC-BY from Stratosphere IPS,
cited where used.
