# Benchmarks

Synthetic corpora and real captures, reported separately and never averaged
together. A synthetic corpus proves the mathematics; a real capture proves —
or disproves — the product. Where they disagree, the real capture wins.

Which analyzers have a real half is not uniform, and every section says which
it has. Beaconing has both. DNS tunnelling has real specificity and synthetic
sensitivity, and section 5 splits them. Alert triage and volume-and-egress
are synthetic on both halves, and sections 6 and 7 say so before they say
anything else.

Everything here is reproducible:

```bash
voidai bench                              # synthetic, seeded: beaconing, then egress
voidai bench --real data/ctu13/<file>     # CTU-13, after fetching a capture
```

> **Correction, 7 October 2026 — every CTU-13 figure.** The CTU-13 files pad
> a short field with an extra tab so their columns line up on screen, and the
> NetFlow parser read them positionally. 29% of scenario 6's rows and 41% of
> scenario 3's were misread. Every misread row had a number read as its label,
> which cost scenario 6 43% of its botnet labels, and about half had the
> direction arrow read as their destination as well. Polars up to 1.33
> accepted the files silently; Polars 2.0 refuses them, which is how it was
> found. Sections 2 and 4 are re-measured on the corrected parse, as are the
> memory and CPU figures in `deployment.md`, and the two results that matter
> held — the infected host at rank 2 of 275
> and rank 1 of 176, against 247 and 160 before, with corroborated incidents
> still 3 and 1. Correct labels then exposed a second defect: they mark the
> botnet's traffic, not which end is the bot, so scoring "every source of a
> labelled flow" as infected counted 3,347 hosts on scenario 3. Infected hosts
> are now the ones the CTU-13 authors document, confirmed by the labels.
>
> CTU-13 figures in section 3 and sections 5 to 11 are left as they were
> measured, on the misparsed rows, because they record what each change did at
> the time and their comparisons are internally consistent. Their absolute
> values are superseded by section 2.

---

## 1. Synthetic corpus — beaconing (seed 1337, 24h)

Six planted implants hidden among browsing traffic, a monitoring agent, a
software update checker, and NTP.

`voidai bench` scores this corpus and then generates a second one for the
volume-and-egress analyzer — different traffic, different decoys, different
ground truth. The two are printed as separate tables and never combined; one
number covering two analyzers measuring different behaviours would describe
neither. Section 7 has the second.

```
precision 1.000 · recall 0.833 · f1 0.909      (5 TP · 0 FP · 1 FN)
55,983 records → 5 findings in 0.24s           (230,000+ rec/s, x86_64, 4 cores)
```

| Implant | Period | Jitter | Model | Score | Found |
|---|---|---|---|---|---|
| textbook-60s | 60s | 0% | symmetric | 0.982 | yes |
| jittered-5m | 300s | 10% | symmetric | 0.874 | yes |
| jittered-15m | 900s | 25% | symmetric | 0.718 | **no** |
| low-and-slow-30m | 1800s | 50% | symmetric | 0.753 | yes |
| scheduled-33s-menti-like | 33s | 18% | scheduled | 0.852 | yes |
| scheduled-10m | 600s | 30% | scheduled | 0.800 | yes |

The single miss scores 0.718 against a 0.72 threshold. It is left as a miss
deliberately — see "Alert burden" below, where the real captures show the
false-positive rate, not sensitivity, is the binding constraint.

**A synthetic benchmark measures the generator as much as the detector.**
Section 3 is a worked example of that going wrong.

---

## 2. Real captures: CTU-13

[CTU-13](https://www.stratosphereips.org/datasets-ctu13) is thirteen captures
of real botnet traffic on a university network, every flow labelled `Botnet`,
`Normal`, or `Background`. Licence: CC-BY.

Measured with all three network analyzers running — beaconing, fan-out, and
volume-and-egress — on the corrected parse, 7 October 2026: `voidai bench
--real` on a four-core x86-64 VM, Polars 2.0.

| | Scenario 3 | Scenario 6 |
|---|---|---|
| Malware | Rbot | Menti |
| Duration | 66.8h | 2.15h |
| Flows analysed | 10,159,384 | 1,605,474 |
| **Infected host detected** | **yes** | **yes** |
| C2 beaconing confidence | **0.958** | 0.749 |
| C2 rank among beaconing findings | 216 / 1359 | 376 / 415 |
| **Infected host queue rank** | **2 / 275** | **1 / 176** |
| Findings → incidents | 2253 → 275 | 596 → 176 |
| Corroborated incidents | 3 | 1 |
| Beaconing pair precision | 0.0007 | 0.0024 |
| Throughput | 113,996 rec/s | 104,551 rec/s |
| Peak RSS | 2,746 MB | 625 MB |

The infected host is `147.32.84.165`, the bot the CTU-13 authors document for
both captures, and the rank is its own — measured directly, not inferred from
the labels. On scenario 3 the one host above it is `147.32.84.229`, the
campus gateway section 12 describes, now tied with it on priority.

**What the correction changed.** Flows analysed fall — 12.7M to 10.2M and 1.92M
to 1.61M — mostly because a row misread with the arrow as its destination had
no destination port, so flow orientation could not recognise it as the reply
half of a conversation; read correctly, those replies are dropped. Findings
rise, 1589 → 2253 and 512 → 596, as traffic that had collapsed onto a single
false destination, `->`, spreads back across real ones. Throughput is lower,
partly for the same reason and partly because the parser now normalises every
line before splitting it. Peak memory rises 84 MB on scenario 3 and falls
7 MB on scenario 6. The ranks held, and corroborated incidents are unchanged.

The rest of this section was measured before the correction, on the misparsed
rows; its comparisons are between figures taken the same way.

**What the third analyzer changed, and what it did not.** Findings rise by
about 20% on scenario 3 (1328 → 1589) and 29% on scenario 6 (397 → 512), and
throughput falls by roughly 8% and 18% as a third pass runs. Memory is flat:
peak RSS is inside 10 MB of the two-analyzer figure on both captures, which is
rule 2 holding — peak is `max(analyzers)`, not `sum(analyzers)`, because they
run sequentially and release.

The two rows that matter are the two that did not move. **The infected host
holds rank 2 and rank 1**, against larger queues than before — 247 and 160
incidents rather than 214 and 133. And **corroborated incidents stay at 3 and
1**, exactly where two analyzers had them, while a third analyzer emits
findings across the estate. That is what `non_corroborating` is for, and it is
emphatically not what the first two versions of the egress analyzer did: they
took corroboration to 33 and 16 and pushed the scenario 3 true positive to
rank 5. Section 7 has that story.

Two rows are scoped rather than re-measured, and are named for it. "C2
beaconing confidence" and "C2 rank among beaconing findings" are computed from
`beacons_to` findings alone, so they are unchanged by construction — the
beaconing analyzer itself is untouched. Selected across every predicate, as
they briefly were, scenario 3's C2 row reported a `contacts_rare_destination`
finding at 0.983 instead of the beacon at 0.958: a row keeping its name while
measuring something else, and losing comparability with every figure it had
published before. `voidai bench --real` now reports the strongest finding of
any kind on a labelled pair under its own separate row.

Scenario 3's C2 channel (`147.32.84.165 → 38.229.70.20`) is found at 0.958
confidence — genuinely strong. Scenario 6's Menti channel
(`147.32.84.165 → 91.212.135.158:5678`) is found at 0.749, near the threshold.

### Why beaconing "precision" is near zero, and why that number is not what it looks like

Two things make the raw figure misleading in *both* directions, so it is
reported as-is and explained rather than massaged.

**`Background` means unlabelled, not benign.** The CTU-13 authors labelled
only traffic they could attribute. A flagged pair labelled `Background` is
unverified, not confirmed wrong. Pair precision is therefore a hard lower
bound on real precision, not an estimate of it.

**Most botnet traffic is not beaconing.** The `Botnet` label covers spam runs,
ICMP floods, scanning, and click fraud. Scenario 6 is overwhelmingly spam —
port 25 to 1,106 distinct mail servers. A beaconing detector *should* ignore
all of it, so recall against all botnet-labelled flows would punish the
analyzer for being correct. Defining C2 as "the botnet traffic that looks
periodic" and then measuring whether periodic traffic is found would score
1.000 by construction and mean nothing.

So the honest measures are: was the compromised host surfaced (yes, in both),
and how much noise came with it.

### Alert burden, and how it was fixed

The first version of this page reported the real problem: 184 findings/hour on
scenario 6, with the true positive at **rank 358 of 395**. Detected and
invisible are the same thing to an analyst working a queue.

The instinct is to tighten the detector. That is wrong, and the data says so.
The high-scoring findings that outranked the C2 are *genuinely* beacon-like —
perfectly regular, uniform payload, single-host destinations. They are
monitoring agents, backup jobs and keep-alives. No refinement of a periodicity
measure separates them, because on the axis of periodicity they are not
different.

**What separates a compromised host is that it does more than one suspicious
thing.** The scenario 6 host beacons every 33 seconds *and* mails 1,573
distinct destinations on port 25 — rank 1 of 143,546 (host, port) pairs for
fan-out. Scenario 3's beacons *and* sweeps 26,702 hosts on port 22, where
seven of the top ten fan-out pairs in the whole capture are infected hosts.

So a second analyzer was added (`fanout`, the `SCANS` predicate) and ranking
moved out of the analyzers into `voidai.correlate`. A `Finding` answers "how
beacon-like is this traffic?"; an `Incident` answers "how much should an
analyst care about this host?" Conflating those two questions is what buried
the true positive.

| | scenario 3 | scenario 6 |
|---|---|---|
| Before — C2 finding rank | 204 / 1277 | 358 / 395 |
| **After — infected host queue rank** | **2 / 214** | **1 / 133** |
| Findings → incidents | 1328 → 214 | 397 → 133 |
| Corroborated incidents | 3 | 1 |

This table is the one-analyzer to two-analyzer transition and its numbers are
that measurement, not the current one — a third analyzer has since been added
and the table at the top of this section carries the figures with all three.
The rank and the corroboration count are the same in both.

Adding the second analyzer costs about 25% in wall time (223k rec/s against
310k for beaconing alone) and nothing in memory.

On scenario 3 the three corroborated incidents are, in order: a resolver or
gateway reaching 162,612 destinations, **the actual bot**, and a BitTorrent
client on port 6881. An analyst triaging three incidents finds it immediately.

Ranking is by noisy-OR over the strongest finding *per predicate*, multiplied
by a corroboration bonus. Per-predicate deliberately: twenty beaconing
findings on one host are twenty views of one behaviour, not twenty independent
reasons to believe it, and treating them as independent would let a chatty
analyzer manufacture certainty.

The remaining noise is still genuinely periodic benign traffic — SNMP polling
on port 161, internal monitoring, backups, P2P. It is no longer *ranked above
the intrusion*, which was the operational problem. Suppressing it outright
needs environment context: an asset inventory, a business-hours model, a
baseline.

---

## 3. What the real captures changed

Every item here was invisible against synthetic data and was caught only by
running on real traffic. This is the argument for doing it early.

### One check-in is not one record — burst coalescing

NetFlow emits a record per direction and splits long connections at the
active timeout. The Menti C2 beacons every 33 seconds but appears as 384
records whose **median interval is 0.15 seconds**. Every interval statistic
downstream measured record framing rather than the beacon, and the channel was
rejected outright by the minimum-period gate.

Interval distributions like this are strongly bimodal in log space. VoidLexicon now
detects that with Otsu's method and coalesces bursts before measuring
anything, recovering 183 check-ins at 33.3s. Unimodal series — well-formed
connection logs — are left untouched.

Otsu rather than "largest gap between sorted intervals": a handful of
intermediate values bridge the valley in real captures, and the simpler rule
fails silently on exactly the traffic it exists to fix. That was the first
implementation, and it did fail.

### Real beacons are right-skewed — the symmetry measure was backwards

The original ensemble scored interval *symmetry* via Bowley skewness, on the
reasoning that jitter is applied evenly and human traffic skews right.

The Menti channel has Bowley **+0.948**: q1=33.0s, q2=33.3s, q3=42.4s, with a
tail running to 2x, 3x and 5x the base period as check-ins are missed. Strong
right skew is a *hallmark* of a real beacon. The measure was penalising its
own best evidence.

It scored ~1.0 on every synthetic implant because the generator applied
`uniform(±jitter)` — symmetric by construction. **The component was measuring
an artifact of the generator.**

It is replaced by `schedule_floor_dispersion`, `(q2-q1)/q2`, which asks
whether the distribution has a hard *floor*. A process on a timer cannot fire
early but can easily fire late; a person has neither constraint. Measured
across traffic types, browsing lands at 0.59 and every beacon shape at 0.00
to 0.33.

The generator now also emits hard-floor, right-tailed implants alongside the
symmetric ones, so neither shape can be over-fitted again.

### The obvious flow-orientation rule deletes real C2

Bidirectional NetFlow lists both halves of every conversation. The reply half
becomes a pair whose "destination port" is the client's ephemeral port, and
since a client holds that port for the life of the conversation, those replies
form textbook-looking beacons. On scenario 6 they manufactured tens of false
detections on ports like 49375.

The textbook fix — "the server is the endpoint with the lower port" — is
wrong. The scenario 6 bot sources from ports **1027–4985**, the Windows XP
ephemeral range, to a controller on **5678**. Under that rule the genuine C2
channel is classified as a reply and silently deleted, taking the capture's
only true positive with it. Measured, not theorised: findings dropped 618 →
309 and detection went from yes to no.

VoidLexicon drops a record only when its destination port is ≥32768 *and* the
source port is lower. Findings fell to 395 and the C2 survived. A real service
listening above 32768 and contacted from a lower port still produces spurious
pairs; that is the accepted cost of never discarding a real channel.

### Memory did not survive contact with 12.7M flows

Scenario 3 originally peaked at **7,165 MB** — more than the Pi 5 target has
in total. The cause was materialising the whole capture before grouping: the
per-pair arrays of timestamps and byte counts hold every record in the file.

Now split into two streaming passes:

  **Pass 1** groups to one row per (src, dst, port) carrying only scalars — a
  count and a first/last timestamp. Enough to decide which pairs could
  possibly qualify, cheap enough to stream.

  **Pass 2** re-scans, semi-joins to the survivors, and gathers full arrays
  for those alone.

On scenario 3, pass 1 yields 1,123,519 pairs, of which **15,737 (1.4%)**
survive the count-and-span gate. Pass 2 therefore collects a fortieth of what
the single-pass version held.

| | before | after |
|---|---|---|
| Peak RSS | 7,165 MB | **2,653 MB** |
| Wall time | 46.5s | **40.8s** |
| Throughput | 272,649 rec/s | 310,801 rec/s |
| Findings | 1277 | 1277 (identical) |

Faster despite reading twice, because nothing large is ever materialised.
Findings are byte-identical, asserted by a test rather than assumed.

**What remains.** 2,653 MB is Polars' hash state for the pass-1 `group_by`
over 1.12M distinct keys — the summary frame it produces is only 53 MB. Thread
count barely moves it (2,042 MB at one thread against 2,093 MB at four, for a
4x speed difference), so it is inherent to the aggregation rather than to
parallelism.

**Does that fit a 4GB board?** This document previously said no, reasoning
from the peak-RSS figure. Measured against a hard cgroup ceiling with swap
pinned to match — see `tools/envelope.py` and `deployment.md` — the answer is
yes: OOM-killed at 2,400 MB, flaky at exactly 2,500 MB, reliable from 2,600 MB,
and comfortable in the 3,696 MB a 4GB Pi has left after the OS. The estimate
was pessimistic by about one board class.

Splitting pass 1 into time windows and merging partial summaries would still
lower the peak — counts sum and min/max combine, so the merge is exact — but
CSV has no random access, so windowing means either re-parsing per window or
moving to a batched reader. A Pi deployment would realistically process hourly
or daily windows anyway, which is the same benefit arriving from the
operational direction rather than as a requirement.

### Parsing was 21x slower than it needed to be

The first NetFlow parser looped in Python: 37k flows/s, which turns scenario 3
into a ten-minute wait on a desktop and something far worse on a Pi. Rewritten
as vectorised Polars expressions it runs at 790k flows/s with identical
output.

---

## 4. The language layer

Qwen2.5-1.5B-Instruct Q4_K_M, 4 CPU threads, x86_64, on the CTU-13 scenario 6
top-ranked incident — the documented bot, rank 1 of 176 — re-measured on the
corrected parse, 8 October 2026, with the model already loaded:

| | |
|---|---|
| Evidence brief | 489 tokens (4 findings, 7 measurements) |
| Prompt / completion | 887 / 286 tokens |
| Wall time | 25.2 s (~11 tok/s) |
| Claims struck | 0 |
| Detection throughput, same run | 103,166 rec/s |

The brief is larger than the 256 tokens first recorded because the incident
now carries four findings rather than two. Detection and reasoning are metered
separately. Folding them together divides detection throughput by the time a
model spent writing prose — the first version of the receipt reported 781
rec/s for a stage that runs at over 100,000.

Four things the model got wrong, all fixed by changing what it is *shown*
rather than by prompting harder — full detail in
[`models.md`](models.md):

- Called a 0.98-confidence beacon "likely a legitimate communication". It did
  not know what the predicate meant; the Lexicon's own description now goes in
  the brief.
- Glossed T1071/T1573/T1008 as "reconnaissance, credential harvesting, and
  monitoring". Those are Application Layer Protocol, Encrypted Channel and
  Fallback Channels. Technique codes were removed from the prompt.
- Wrote "the host is a noisy-OR beacon", having parroted the ranking
  rationale. The brief now carries the priority number, not the arithmetic.
- Produced a 900-character narrative, exhausted its token budget, and was cut
  off mid-claim leaving unparseable JSON. The grammar now bounds every string
  and list, and caps whitespace.

The pattern: **show the model only what it can reason about.** Raw logs,
technique codes and scoring notation are all things a small model repeats
without understanding.

The verifier catches uncited claims, citations that do not resolve against the
brief, and claims naming addresses or ports absent from the cited evidence. It
cannot catch a well-cited claim that is simply wrong — which is why all four
fixes above are about grounding rather than filtering.

---

## 5. DNS tunnelling — real specificity, synthetic sensitivity

Validation here is split, and the halves are reported separately because they
rest on different evidence.

**False positives: measured on real traffic.** The Stratosphere malware
captures ship `passivedns` logs alongside their NetFlow, and those carry real
query names. Across **3,655 records from 18 hosts** — Akamai CNAME chains,
Mozilla update services, Google notification endpoints, OneNote CDN, telemetry
and certificate status lookups — the analyzer emits **nothing**. Only one zone
even passed the volume gates (`google.com`, scoring 0.065 against a 0.62
threshold).

This is the half that decides whether the analyzer is deployable, and it is
the half no generator can honestly test: real DNS is stranger than anything
worth writing by hand. A 400-record excerpt is committed as
`tests/data/real.passivedns` (CC-BY, Stratosphere IPS) so the result is
regression-tested rather than reported once.

**True positives: synthetic only.** No labelled DNS-tunnelling corpus was
reachable, so sensitivity is measured against traffic modelled on published
tool behaviour. That distinction is not blurred: the analyzer is *known* not
to fire on real benign DNS, and *believed* to fire on real tunnels.

The generator is adversarial: benign traffic includes a content delivery
network minting 300 subdomains per host, hex-encoded reputation lookups, and
DNSBL queries — the categories that break entropy detectors.

| Zone | Queries | Entropy (bits/char) | Score |
|---|---|---|---|
| `tunnel-example.com` (iodine-like, TXT) | 600 | 4.55 | **0.911** |
| `exfil-example.org` (chunked labels) | 380 | 4.57 | **0.891** |
| `c2-example.net` (dnscat2-like, A only) | 450 | 4.35 | **0.783** |
| `reputation-example.net` (hex hashes) | 250 | 3.87 | 0.569 |
| `akamaiedge.net` (CDN) | 300 | 3.39 | 0.268 |
| `blocklist-example.org` (DNSBL) | 200 | 3.03 | 0.080 |

3 of 3 tunnels found, no false positives, at a 0.62 threshold — and zero
findings across the real traffic above.

**The margin on reputation lookups is thin — 0.05.** Hex encoding tops out at
4.0 bits/char against base32's 5.0, and that gap is the only thing separating
a hash-lookup service from a tunnel. The threshold is deliberately *not*
widened to make the number look better: with no real corpus, tuning it would
mean calibrating against a generator written by the same hand as the
detector, which is precisely the error section 3 documents. The margin is
pinned by a test instead, so a regression is visible.

Two consequences follow honestly: a tunnel that encodes in hex would likely be
missed, and a reputation service using longer or denser encodings could false
positive. Both wait on real data.

---

## 6. Alert triage

A mid-sized sensor emits tens of thousands of alerts a day and an analyst
reads a few dozen, so every deployed IDS is already an alert-suppression
problem. This analyzer does not try to decide which alerts are true. It
reduces the flood to the few worth *correlating* and hands them on as one more
opinion about a host — which is why `TRIGGERED_SIGNATURE` is capped at MEDIUM
severity and never reaches HIGH on its own. A ruleset's opinion should not
outrank VoidLexicon's own measurements.

On a synthetic stream shaped like a real one — 60 hosts tripping policy and
scan rules thousands of times, one host tripping two rare severe rules, and
3,000 non-alert flow events mixed in:

```
14,534 EVE events → 11,534 alerts parsed → 2 findings
both on the compromised host; the 60-host estate-wide noise entirely suppressed
```

A 5,767:1 reduction with the intrusion intact. Volume alone does not raise a
score: ten thousand copies of one alert is one fact, and a test pins that.

**Synthetic only.** The Stratosphere captures carry NetFlow and passivedns but
no EVE output, so no real alert stream was reachable.

Three bugs the tests caught before this shipped, all in the category table:

- `"Not Suspicious Traffic"` scored **0.55**. The substring `"suspicious"`
  matched before `"not suspicious"`, so Suricata's *noisiest* category was
  being read as moderately suspicious — the exact inverse of intent, and
  enough to flood the queue on its own. Negations are now matched first, in a
  separate table, so the invariant survives someone appending to the list.
- `"Attempted Administrator Privilege Gain"` scored **0.40**, the unmatched
  default. The table was written with Snort classtype names
  (`attempted-admin`) but EVE emits human-readable descriptions, so roughly
  half the entries matched nothing. Both forms are now listed.
- One malformed line discarded an entire file. Log rotation truncates the
  final record mid-write routinely, so `read_eve` now falls back to a
  line-by-line salvage when the bulk reader rejects a file.

---

## 7. Volume and egress — synthetic accuracy, real-capture ranking

Two halves, resting on different evidence, and they are not the halves section
5 splits.

**Accuracy is synthetic.** Every precision, recall and score below is measured
against a generator, and describes traffic built to the same beliefs as the
detector. There is no real precision figure for this analyzer.

**Ranking behaviour is real.** CTU-13 has been run against it, and what it
returned was not an accuracy number — it was two design errors and the
measurements that fixed them, under "What CTU-13 changed" onward. Both
captures are now restored with the analyzer running: scenario 3's infected
host at rank 2 of 247, scenario 6's at rank 1 of 160.

The analyzer claims three predicates that are one measurement seen at three
strengths: `exfiltrates_to` (critical/high), `transfers_anomalous_volume`
(medium), and `contacts_rare_destination` (low). Which one a pair can support
is decided first by *which signals the sensor actually supplied* and only then
by how high the combined score reached — see "What CTU-13 changed" for why
that order is not an implementation detail. Four signals, combined the same
way beaconing combines its six:

| Component | Measure | Weight |
|---|---|---|
| `egress_ratio` | share of the conversation's bytes that went out | 0.30 |
| `volume_deviation` | modified z-score against the host's own per-destination distribution | 0.28 |
| `destination_rarity` | estate-wide prevalence, the same curve beaconing uses | 0.24 |
| `novelty` | share of the host's window elapsed before it first reached this destination | 0.18 |

### The corpus

`EgressCorpusGenerator`, seeded, separate from the beaconing corpus in section
1 — adding traffic to that one would have invalidated results this document
calls reproducible. Twelve hosts, 12,251 flows over 24 hours, 125 distinct
source→destination pairs.

The benign traffic is not filler. Three of its four categories are
indistinguishable from exfiltration on volume and direction alone:

| Benign category | Per host | Direction | Why it is hard |
|---|---|---|---|
| Nightly backup | ~2.1 GB in 24 flows | 99.8% outbound | Large, outbound, scheduled — three of the four things exfiltration is |
| Cloud sync | ~310 MB in 140 flows | 99% outbound | Same, reached by the whole estate |
| Software mirror | ~2.4 GB in 20 flows | 99.8% **inbound** | Same volume, travelling the other way |
| Browsing | 6 destinations, ~150 KB each | inbound-heavy | Every host reaches addresses nobody else does |

Plus one deliberate trap, described below.

### Result

```
precision 0.800 · recall 1.000 · f1 0.889      (4 TP · 1 FP · 0 FN)
12,251 records → 5 findings in 0.06s           (189,000 rec/s, x86_64, 4 cores)
```

| Planted transfer | Volume | Flows | Appears at | Predicate | Score |
|---|---|---|---|---|---|
| `bulk-single-archive` | 800 MB | 3 | 70% in | `exfiltrates_to` | **0.946** |
| `slow-and-small` | 12 MB | 40 | 55% in | `exfiltrates_to` | **0.899** |
| `staged-chunked` | 600 MB | 120 | 40% in | `exfiltrates_to` | **0.851** |
| `trickle-upload` | 600 KB | 25 | 62% in | `contacts_rare_destination` | **0.704** |

The last one is 600 KB, below the megabyte floor for a volume claim, so the
strongest thing sayable about it is that something went somewhere rare — and
that is what it says, at LOW. It counts as found because it was found; scoring
it a miss would penalise the analyzer for not overstating what it measured.

And the decoys, scored with the thresholds removed so the separation is
visible rather than inferred from silence:

| Benign category | Instances | Median score | Threshold it had to clear |
|---|---|---|---|
| Software mirror | 12 | 0.098 | 0.45 |
| Cloud sync | 12 | 0.340 | 0.45 |
| Nightly backup | 12 | 0.360 | 0.45 |
| Lone-host backup | 1 | **0.485** | 0.45 — **fires** |

Thirty-six of the thirty-seven hard decoys are silent, and the 72 browsing
destinations with them. The nightly backups clear the highest bar in the
corpus on volume and direction and still land at 0.36, because a backup target
is reached by the whole estate and was already in use when the sensor started
recording. That is rule 5 doing its job: under an arithmetic mean the backups
would score 0.65 and flood the queue.

### The one false positive is the one that cannot be fixed here

`10.0.2.13 → 10.0.2.61`, at 0.485 against a 0.45 threshold. It is a backup
target used by exactly one machine, and it is in the corpus on purpose.

Estate-wide rarity scores it 1.0 because the score is right: one host, one
destination, nobody else. Novelty is what holds it to MEDIUM rather than
CRITICAL — the destination has been in use since the capture opened — but
nothing available to this analyzer can take it to zero, because nothing in the
telemetry says "backup server". This is the gap section 10 already records as
open: **the estate has no identity.** An asset inventory demotes it in one
step, and `AnalysisContext.ip_to_host` exists for exactly that. Section 11½
supplies the parser that fills it; naming a backup target is then a line an
operator writes, not a change to this analyzer.

The margin is 0.035, which is thin. It is not widened by moving the threshold:
with no real corpus, tuning it would mean calibrating against a generator
written by the same hand as the detector — the error section 3 documents. A
test pins the false-positive *count* at one instead, so a regression that
starts reporting backups is a failing test rather than a quiet flood.

### NetFlow has no direction, and the obvious default deletes every detection

This is the trap this predicate carries, and it is worth the space because the
failing version emits no error and reads as a quiet network.

`ingest/netflow.py` records total flow bytes as `orig_bytes` — a NetFlow
record carries no directional split — so there is no `resp_bytes` column at
all. The egress ratio is *unavailable*, which is not zero and not 0.5. Run
against the same corpus with the responder column removed:

| Telemetry | Ratio handling | Planted transfers found | Top score | Strongest claim |
|---|---|---|---|---|
| Zeek `conn.log` | measured | **4 of 4** | 0.946 | `exfiltrates_to`, CRITICAL |
| NetFlow-shaped | **omitted**, weights renormalise | **4 of 4** | 0.923 | `transfers_anomalous_volume`, MEDIUM |
| NetFlow-shaped | defaulted to 0.5 ("neutral") | **0 of 4** | — | — |
| NetFlow-shaped | defaulted to 1.0 ("it's all we have") | 4 of 4 | 0.946 | `exfiltrates_to`, CRITICAL |

Omitting the component costs 0.02 to 0.06 of score as the remaining weights
redistribute, and finds everything. Substituting a neutral 0.5 scores the
component at zero, and under a geometric mean that is enough to sink every
finding in the capture — **detection goes to nothing, silently.**

The fourth row is the more instructive one. Defaulting to 1.0 produces results
identical to the sensor that actually measured direction, so it would pass
every test in this table and look like the right answer. It is not: it asserts
that every byte went outbound on telemetry that never observed a direction,
and the first capture where that is false is the one where it invents an
exfiltration. A default that happens to look right is more dangerous than one
that looks wrong. The component is omitted, the evidence payload carries
`egress_ratio: null`, and the basis line on every affected finding names the
omission.

The last column is the part that took a real capture to get right. Less
telemetry produces a *weaker claim*, not the same claim with a worse number:
the same transfers that are called exfiltration on Zeek are called an
anomalous volume on NetFlow, and the lone-host backup falls further still,
out of the volume band into `contacts_rare_destination` at LOW.

### What is not measured

**Thresholds.** `min_bytes` (1 MB), `rare_min_bytes` (100 KB),
`exfil_threshold` (0.70), `volume_threshold` (0.45) and
`rare_score_threshold` (0.30) are set from the shape of the problem, not from
a measurement.

`min_bytes` is the one CTU-13 has something to say about, and what it says is
*leave it alone* — the real command-and-control transfer it catches is smaller
than the noise it would have to exclude, and scores lower too. "Why the byte
floor is not the lever" below has the numbers. It also means what `min_bytes`
counts differs by sensor: originator bytes on Zeek, whole-flow bytes on
NetFlow. That is a property of the telemetry, recorded so a reader knows what
the floor means on theirs.

**Alert burden on a real estate.** `contacts_rare_destination` is the
predicate flagged from the start as a flood waiting to happen, and the corpus
proves the flood is real: without its score threshold, prevalence alone marks
72 browsing destinations as rare and the analyzer emits one finding each at
confidences around 0.03. Gated, it emits one. Whether that holds on a
university network with a hundred thousand destinations is not something
twelve synthetic hosts can answer. It is also in
`CorrelationConfig.non_corroborating`, so however many it emits, it can
enrich an incident other evidence created but never create or promote one.

**Precision and recall on a real capture.** CTU-13 gives queue ranks and
corroboration counts for this analyzer, reported below, but not a precision
figure: `Background` in CTU-13 means unlabelled rather than benign, and the
label set covers spam, scanning and click fraud rather than transfers, so
there is nothing to score a volume detector's false-alarm rate against. The
one real true positive it has — scenario 6's Menti channel, at 2.16 MB — is a
single data point, not a recall measurement.

### What CTU-13 changed: omitting a component is not enough if you keep the claim

The analyzer's first version scored four signals, omitted any it could not
measure, and then picked its predicate from the resulting number:
`exfiltrates_to` above 0.70, `transfers_anomalous_volume` above 0.45. That
passed every synthetic test on this page, including all of the omission tests
in the table above.

Run against CTU-13 scenario 3, it regressed the thing the whole project is
ranked on:

| | before this analyzer | with it, predicate by score | change |
|---|---|---|---|
| **Infected host queue rank** | **2 / 214** | **5 / 247** | **worse** |
| Corroborated incidents | 3 | 33 | 11x |

Scenario 6 held rank 1. The cause was **176 `exfiltrates_to` findings across
35 hosts, median confidence 0.892, every one of them CRITICAL** — and every
one of them a claim about *outbound* volume made on NetFlow, which does not
record a direction.

The omission logic was right and did exactly what it was written to do: the
egress ratio was dropped, the weights renormalised across volume deviation,
destination rarity and novelty, and those three still reached 0.892 on real
traffic. What was wrong was that the analyzer then kept the verb the omitted
component existed to justify. `exfiltrates_to` is defined in the Lexicon as
"transfers an anomalous outbound volume"; `transfers_anomalous_volume` as
"byte volume between subject and target deviates from its own baseline". With
no direction observed, only the second sentence is grounded — and the first
was being asserted at CRITICAL, 176 times, each one adding a distinct
predicate to a host and multiplying its priority.

**This is rule 6 one level up.** "Absent is not zero" was written as a rule
about arithmetic: do not substitute a value for a measurement you do not have.
It is really a rule about claims. A component dropped from a score, and a
claim left standing that the component was the only evidence for, are the same
error — and the second is harder to see, because the arithmetic looks
scrupulous right up to the point where the verb is chosen. The rule
6 now says so in three levels rather than one, because there turned out to be
a third.

The fix is that the predicate is now a function of **which signals were
measured**, and only then of the score. `exfiltrates_to` requires the egress
ratio; `transfers_anomalous_volume` requires the volume deviation. On NetFlow
the critical claim is unreachable at any score, and a test asserts that using
a transfer that *does* clear the exfiltration threshold with the ratio
omitted — so the gate cannot quietly become the threshold doing the work.

**The synthetic corpus could not have caught this.** Its traffic is Zeek-
shaped and carries `resp_bytes` on every flow, so the ratio is always
measured, the exfiltration claim is always grounded, and the bug is invisible
by construction. The corpus can be run with the column dropped — the table
above does exactly that — but that only tests whether the *score* survives
omission, which it did. Nothing in a corpus that always has direction can ask
whether a claim about direction should still be made without it. That question
only exists once a real sensor that cannot supply it is in the picture, which
is the argument for running on real captures early, restated for the fourth
time on this page.

### And the predicate fix alone did not restore the rank

It was not expected to. Demoting the verb changes what is claimed and at what
severity; it does not change how many pairs are reported, what confidence they
carry, or how many *distinct predicates* a host ends up with — and queue
priority is a noisy-OR over the strongest finding per predicate, multiplied by
the count of distinct behaviours. A host that was corroborating with
`exfiltrates_to` corroborates identically with `transfers_anomalous_volume`.
Re-run, scenario 3 stayed at rank 5.

The third level of rule 6 is what moved it. `transfers_anomalous_volume` is,
by construction, the claim the analyzer makes when it *cannot* make the
stronger one — the direction was not recorded, or the four signals did not
reach the exfiltration threshold. Partial evidence, every time. Partial
evidence may be reported; it may not be counted as an independent behaviour.
So the predicate joins `CorrelationConfig.non_corroborating`, where it still
contributes to the incident's combined confidence through the noisy-OR and
still appears in front of the analyst, but no longer multiplies a priority.

| | before this analyzer | predicate by score | + predicate grounded | + volume non-corroborating |
|---|---|---|---|---|
| **Scenario 3 — infected host rank** | **2 / 214** | 5 / 247 | 5 / 247 | **2 / 247** |
| Scenario 3 — corroborated incidents | 3 | 33 | 33 | **3** |
| **Scenario 6 — infected host rank** | **1 / 133** | 1 | 1 | **1 / 160** |
| Scenario 6 — corroborated incidents | 1 | 16 | 16 | **1** |

Scenario 6's rank is given without a denominator in the two middle columns;
the incident count was not recorded for those runs and is not filled in from
the column beside it.

Both captures are restored, with a third analyzer running and its findings
kept. The scenario 6 bot's incident still carries its
`transfers_anomalous_volume` finding: evidence retained, false promotion
removed. That is the outcome to want from this rule — not silence, but a
finding that informs without inflating.

### Why the byte floor is not the lever, and will not be moved

The obvious response to 176 findings is to raise `min_bytes`. Three
measurements say not to.

**The scenario 6 volume finding sits on the real Menti command-and-control
channel, at 2.16 MB.** It is the only real-world true positive this analyzer
has. A 10 MB floor — the size that would have suppressed most of scenario 3's
noise — discards it.

**Scenario 3's infected host has no volume finding at all.** So on that
capture the floor is being tuned entirely against traffic that contains no
true positive to protect.

**And confidence does not separate them either.** Scenario 3's noise scores a
median of **0.851**. The scenario 6 true positive scores **0.487**. The noise
outranks the real detection by a wide margin on the very number a threshold
would sort by. There is no value of `min_bytes`, and no value of
`volume_threshold`, that keeps the true positive and drops the noise, because
on both axes the noise is on the wrong side of it.

This is the same lesson the alert-burden section reached from the other
direction: when a detector's own axis cannot separate signal from noise, the
answer is not a tighter threshold on that axis. It is to stop letting the
finding carry more weight than its evidence supports.

**`orig_bytes` does mean different things on different sensors, and that is
recorded rather than tuned around.** On Zeek it is the originator's bytes; on
NetFlow it is the whole flow's total in both directions, because that is the
only figure the format carries and `ingest/netflow.py` says so in a comment.
The same `min_bytes` constant is therefore a lower bar on NetFlow than on
Zeek. That is a real property of the telemetry, documented here so a reader
knows what the floor means on their sensor — not a defect to be corrected by
picking a number that suits one capture.

---

## 8. Threat intel — integration, not detection

**Synthetic, and there is no detection rate to measure.** That is not a gap
waiting to be filled by a better corpus. The detection was performed by
whoever wrote the feed; what this analyzer does is join a file to a capture,
and the only question worth scoring is whether the join is correct and whether
what it claims is bounded by what the file actually said. A fixture with a
handful of indicators answers that, and a labelled corpus would not answer it
better.

So the numbers below are counts and behaviours, not precision and recall, and
nothing in this section should be read as a measured detection rate.

```
5 indicators (1 ip, 1 cidr, 1 domain, 1 url, 1 hash) → 63 tests
3,000,000 flows over 200,000 destinations → 838k rec/s
```

### What the join is not

Every other analyzer here measures something and combines the measurements
with a weighted geometric mean. The obvious move is to do the same, so this
one looks like its neighbours: score the match on flow count, on destination
rarity, on how long the conversation ran.

All three numbers are real and none of them is evidence about whether the
indicator is *true*. A host that contacted a known C2 once and a host that
contacted it four thousand times have exactly the same intelligence behind
them. Folding volume into the score would report VoidLexicon's own observation as
though it corroborated the feed — the same circularity that keeps `precedes`
out of the corroboration count.

Confidence therefore comes from the feed alone: its declared confidence,
decayed by how stale the indicator was when the traffic was seen.
`test_volume_does_not_move_the_score` fails if that stops being true.

### Missing provenance, and the version of rule 6 that has no weights

Rule 6 says a component that is unavailable is omitted and the remaining
weights renormalise. There are no weights here, so the rule had to be
re-derived for a product of two factors, and it lands in two different places:

**A feed that declares no confidence** has not declared low confidence. It has
declared nothing, and the honest reading is that the claim cannot be strong —
so it scores at `0.25`, below the MEDIUM threshold, and can enrich an incident
without raising one on its own.

**An indicator with no date** has an *unknown* age, not a fresh one. This is
the one that bites, because the obvious handling is a decay of 1.0, and it
fails in the flattering direction: an undated indicator would score **higher
than a dated one a month old**, rewarding the feed that recorded less. The
confidence is therefore **capped** at `0.35` rather than multiplied by an
invented decay. A cap states that the claim cannot be made strongly; a
substituted age would state that the indicator is fresh, which nobody
measured.

### Age is measured against the capture, and that is not a detail

An indicator from 2019 firing on a residential address reassigned three years
ago is a false positive with a citation attached, and a citation is the thing
an analyst is least likely to re-check. Two mechanisms drop those: a hard cut
at 730 days, and a confidence floor at 0.10 that a 180-day half-life reaches
well before it.

The age is measured from the indicator's date to **the capture's own
timestamps**, never from the clock. Both reasons matter and the second is
load-bearing:

- It is the right question. What matters is how stale the intelligence was
  when the traffic happened.
- Every ID in the Lexicon is content-addressed. An `age_days` derived from
  `datetime.now()` would give the same input a different evidence ID every
  day, and every citation in an archived report would stop resolving.

The wall-clock version of this analyzer passes a test asserting that two runs
produce identical IDs — they are seconds apart and agree about today. The
assertion that catches it requires two captures ninety days apart to disagree
by ninety days.

### Two flood mechanisms, both found by reading the output

Neither was predicted; both were obvious once the findings were printed.

**A parent-domain indicator emitted one finding per subdomain.** One
wildcarded entry in a feed against forty observed names is forty findings
about one fact. They now collapse to a single finding naming the zone, with
the observed names and their true count in the payload.

**`shares_infrastructure_with` reported the operator's own file back to them.**
Five addresses inside one `/24` entry were linked to each other pairwise as
shared infrastructure. They do share infrastructure — that is what the
operator wrote down — and restating it is noise with a citation attached. The
predicate now requires the two ends to have been caught by *different*
indicators, and requires one end to be an intel match at all. Ungated it is an
O(n²) description of shared hosting, and the analyst learns that CDNs exist.

### Cost

The pass is two streaming aggregations and a dictionary lookup per distinct
value, with locators gathered by semi-join for the handful of values actually
reported. On three million flows across 200,000 distinct destinations against
a 700-indicator feed it runs at 838k rec/s.

Peak memory is dominated by the streaming `group_by` — 254 MB at that
cardinality, the same figure `egress.py` pays for the same operation. The part
this analyzer controls is the Python side, and it is kept bounded by the match
count rather than by the capture: filtering during the fold rather than after
it is 0.1 MB of Python allocation against 48.5 MB for the same work.

### What is not measured

- **Any real detection rate.** By construction, as above.
- **The half-life.** 180 days is set from the shape of the problem, not from
  data. The observed lifetime of a rented C2 address is far shorter and of a
  malware hash far longer, and a single half-life for both is a compromise
  nothing here has calibrated.
- **The unprovenanced floor and the undated cap.** `0.25` and `0.35` are
  ordered correctly with respect to the MEDIUM threshold and to each other,
  which is the property that matters; the values themselves are judgement.
- **URL and file-hash indicators**, which load and match nothing. No HTTP log
  parser and no process telemetry exist until clusters 5 and 6.

### One thing this cluster surfaced that belongs to the correlator

`matches_threat_intel` is unary and its subject is the **indicator** — the
address or name that appeared in the feed. Correlation groups findings by
subject, so an intel hit on a destination forms its own incident rather than
joining the incident for the host that contacted it:

```
 1  CRITICAL  0.98  ip:10.0.1.14      beacons_to             1
 2  MEDIUM    0.89  ip:10.0.0.50      matches_threat_intel   1
```

That is honest and it is useful — a fresh, well-provenanced hit lands near the
top of the queue on its own merits, and the payload names the hosts that
touched it. But the host does not get the corroboration bump that the whole
ranking mechanism exists to produce, and a host that beacons *and* contacts a
known-bad address is exactly the conjunction the noisy-OR was built to
surface.

Fixing it means changing how incidents are formed, which is cross-cutting:
correlation behaviour affects every analyzer, and rule 6's third
level says a finding resting on external assertion must not corroborate in the
way a measurement does. Cluster 4 is also correlator-side work. It is recorded
here, and left for that discussion, rather than settled unilaterally inside
this branch.

---

## 9. TLS and DGA — real specificity, synthetic sensitivity

Validation is split three ways here and the parts are reported separately,
because they rest on different evidence and averaging them would produce a
number whose provenance nobody could state.

| | Evidence | Result |
|---|---|---|
| DGA — false positives | **real** (`tests/data/real.passivedns`) | 0 findings, ceiling 0.546 against a 0.65 threshold |
| DGA — true positives | synthetic (`DgaCorpusGenerator`) | 3 of 4 families, 0 false positives |
| TLS fingerprints | synthetic, both sides | 2 of 2 clients, 0 false positives |

**Was a real corpus available?** For the DGA half, only for specificity.
Public DGA feeds exist — netlab 360 and Bambenek both publish one — but
nothing is fetched at runtime or at test time and no redistribution licence
was verified, so none was vendored and sensitivity is synthetic. For TLS
fingerprint rarity, no openly-licensed `ssl.log` corpus carrying JA3 was
reachable at all, so **both** halves of that measurement are synthetic and it
measures the arithmetic rather than the detector. That answer was established
before the code was written, because deciding
it afterwards is how a synthetic result quietly gets written up as a real one.

### Entropy does not work at this length, and that is the cluster's main finding

The design specified four components, weighted
`nxdomain_rate` 0.34, `label_entropy` 0.26, `bigram_improbability` 0.24,
`structure` 0.16. The entropy component was measured and dropped.

Per-character Shannon entropy is bounded by `log2(len)`. The DNS tunnelling
analyzer measures 40-to-60-character encoded subdomains, where that bound is
far away and entropy separates base32 payload from English cleanly — section 5
is the record of it working. A second-level label is 6 to 20 characters, and
there the bound dominates. Measured over the 41 real registered labels of
eight characters or more in the fixture, against random strings of matched
length:

| population | entropy ratio, mean | bigram improbability, median | p90 |
|---|---|---|---|
| real registered labels | 0.855 | 0.145 | 0.467 |
| random alphabetic | 0.893 | 0.667 | 0.831 |
| random hexadecimal | 0.807 | 0.941 | 1.000 |
| dictionary concatenation | 0.869 | 0.065 | 0.167 |

Four points of separation on entropy, and **inverted on the hex families**: a
16-character hex string draws from a 16-character alphabet and so scores as
*more* natural than `googleapis`. An entropy component would have penalised
precisely the family the replacement catches best. It was removed rather than
down-weighted, and its weight went to the character model.

That is the same shape of correction cluster 1 made to rule 6 and cluster 2
made to it again: the plan was written from reasoning and the measurement
disagreed with it.

### The character model, and why a word list rather than a frequency table

The design called for "a small embedded table of real domain bigrams".
Writing one directly would mean inventing 1,369 letter-pair probabilities from
memory and presenting three significant figures of them as measured.
`analyzers/ngrams.py` embeds **1,233 ordinary English words** instead and
computes the bigram counts from them at import. The word list is a datum that
can be read and checked by eye; the table follows from it by arithmetic.

Brand names are excluded from the list on purpose — `google`, `akamai`,
`mozilla`, `microsoft`, `crwdcntrl` — because the fixture those labels come
from is the corpus the model's specificity is measured against, and fitting
the model to it would turn a measurement into a tautology. A test asserts the
exclusion so it survives future edits to the list.

**Dictionary generators defeat it, by construction.** A family that
concatenates words scores a median 0.065 against a real-label median of 0.145:
more English than English, because it is. One is planted in the corpus and
counted as a **miss** rather than excluded from the denominator, which is why
recall reads 0.750 rather than 1.000. Catching those needs a word-boundary
model and is a separate piece of work.

### The synthetic corpus cannot set the threshold; the real fixture can

Every threshold between 0.35 and 0.85 finds all three detectable families in
`DgaCorpusGenerator` and fires on none of its decoys. The corpus says only
that the answer lies in a wide band — which is worth stating plainly, because
a benchmark that cannot distinguish two candidate settings has not validated
either of them.

The binding constraint is real traffic. Scored without `nxdomain_rate`, which
`passivedns` cannot supply:

| real label | score |
|---|---|
| `crwdcntrl.net` | 0.546 |
| `msftncsi.com` | 0.519 |
| `office365.com` | 0.405 |
| `wgg4ggefwg.ru` | 0.384 |
| `netdna-cdn.com` | 0.355 |

Labels shorter than six characters are not scored at all, and that gate is
what those five rows depend on. At five, `ml314.com` scores 1.000,
`gvt2.com` 0.827 and `fbcdn.net` 0.784 — real abbreviations whose four
bigrams are genuinely improbable English, and which no threshold separates
from a generated name. The cliff is between five and six and it is sheer:
from six upward the ceiling is 0.546 whatever the gate, so six is taken
rather than a rounder eight, which would score 43 of the fixture's registered
labels instead of 68 and buy nothing.

The threshold is 0.65, leaving a margin of **0.104** — comparable to the 0.05
section 5 reports for DNS tunnelling, and pinned by a test so that a change
eroding it shows up in a diff.

Two things about that table are worth more than the margin. **The real decoys
are 0.2 harder than the synthetic ones written to imitate them**: the
consonant-heavy abbreviations in `DgaCorpusGenerator` top out at 0.337 while
`crwdcntrl` reaches 0.546. The generator is less adversarial than reality, as
generators are. And **`wgg4ggefwg.ru` is not obviously benign** — the fixture
comes from a Stratosphere malware capture, so "false positive" there means
unlabelled rather than known-good, the same caveat CTU-13's "background"
carries in section 2. It scores 0.384 and is missed either way, because its
digit lowers the structure component.

### The fixture is one host, so this is a weaker specificity result than section 5's

Section 5 reports 3,655 records from 18 hosts for DNS tunnelling. The
committed excerpt is 400 records from **one** host, and of its 81 distinct
registered labels only 41 are eight characters or more and therefore scored at
all. Two families qualify — 44 labels under `.com`, 30 under `.net` — so the
analyzer is silent because it scored the traffic and stayed under threshold,
not because a gate hid it. That is the right shape of result, over a smaller
sample than one would like.

### rcode is missing, the component goes, and the predicate survives — unlike cluster 1

`passivedns` records no response code, so the heaviest component is
unavailable on the corpus that measures specificity. The component is omitted,
the weights renormalise, and the payload carries `nxdomain_rate: null`.

The interesting part is the *second* level of rule 6, where this cluster
differs from cluster 1. There, the missing `resp_bytes` was the word
"outbound" in `exfiltrates_to`, so the verb became unsayable and the analyzer
had to fall back to a weaker one. Here the verb is
`resolves_algorithmic_domain`, which the Lexicon defines as a domain "whose
structure is consistent with algorithmic generation" — and structure is
exactly what the character model measures. `rcode` is the strongest evidence
for the claim; it is not the claim. So the predicate stands, the confidence
falls out of the renormalisation, and the false-positive rate is reported
separately for the two telemetry shapes instead of averaged.

Getting this right is not a matter of applying the rule harder. It is a
matter of reading what the verb asserts, one predicate at a time.

### The family is not pre-filtered, and that costs recall on purpose

`nxdomain_rate` needs a group. The group is `(source, public suffix)` — every
registered domain one host resolved under `.biz`, or under `.com` — and it is
deliberately **not** narrowed to the names that already look generated.
Selecting a family by the property being measured would let any host
manufacture a perfect NXDOMAIN rate out of its handful of typos.

The cost is paid knowingly and is visible in the corpus: one planted family
generates under `.com` on a host that also browses the web, so its NXDOMAIN
rate is diluted to 71% against the 99% of the families that generate under a
suffix their host does not otherwise use. It is still found. A quieter
generator hiding under a heavily-browsed suffix would not be.

### Two things the analyzer does that are not scoring decisions

**Exemplars are chosen by resolution first, score second.** A generation family
is a few hundred names that failed and one that worked, and the one that
worked is the C2. It is no stranger-looking than the rest — in the corpus it
scores 0.934, 0.876 and 0.811 while family members reach 1.000 — so a
score-ordered report would omit the only actionable name in the set. All three
detectable families report theirs.

**The exemplar sort needed a total order, and finding that out was luck.**
A generated family produces hundreds of names scoring an identical 1.0, and
only three are reported. Without a tiebreaker the choice fell to whatever
order `group_by` returned, which Polars does not promise to keep stable — so
two runs over the same capture emitted different exemplars and therefore
different content-addressed finding IDs. Every archived report and every
benchmark comparison in this project rests on that not happening. It was
caught by printing the findings twice and noticing the names had changed, not
by a test; the test came after.

### TLS: a prevalence claim, kept as one

A JA3 hash identifies a TLS client build. The claim is that this one is rare
in this environment, and no geometric mean of loosely-related quantities is
assembled to make it resemble the behavioural analyzers — the mistake
`intel.py` was warned against. Two components: `fingerprint_rarity` from
estate-wide prevalence, and `estate_support`, because rarity needs an estate
and on a three-host capture every fingerprint is rare.

Result on the synthetic corpus — 768 sessions, 45 hosts, three shared browser
builds — is 2 of 2 planted implants at 0.833, no false positive. The two
decoys are the two ways a prevalence measure goes wrong, and both are
suppressed: a fingerprint seen exactly **once** (a truncated handshake, not a
client the host runs) and one shared by **two** hosts (a minority browser
build) at 0.665.

That second one is the honest edge. Two hosts of forty-five is unremarkable;
two of five hundred is not, and `estate_support` encodes exactly that, so the
same fingerprint clears the threshold at 0.794 on a 500-host estate. **The
threshold was set after watching the decoy fire, on a corpus written by the
same hand as the detector.** The rule it encodes should be trusted; the number
should not, until a real `ssl.log` corpus exists.

**A rare fingerprint does not corroborate.** It is in
`CorrelationConfig.non_corroborating`, and not for rule 6's reason — a rare
JA3 is complete evidence of exactly what it claims. The reason is cluster 4's:
the multiplier counts independent *behaviours of a host*, and an implant
beaconing over TLS earns a beaconing finding and a fingerprint finding from
the same connection. That is one behaviour measured twice. `voidai demo`
exercises the distinction — patient zero's fingerprint appears in its incident
and is absent from its behaviour count.

`resolves_algorithmic_domain` is deliberately not in that set: a host running
a generation algorithm is doing a second thing, not restating the first.

### JA3 is missing more often than it is present

It comes from a Zeek package, not the core script, so a stock sensor writes an
`ssl.log` with every column except the one that matters — which from outside
is indistinguishable from having no TLS telemetry at all, and has a completely
different fix. `voidai doctor --telemetry <dir>` reports which of the three
states a capture is in, and the analyzer is silent for the two that cannot
support a claim.

The sharper version of that failure is a **partially** populated column: a
package loaded late, handshakes the sensor could not parse. If null
fingerprints were grouped rather than dropped, the few hosts missing one would
form a group of their own — and being few, that group is *rare*, so the
analyzer would report the sensor's own blind spot as a rare TLS client on
exactly the hosts it knows least about. Dropping the whole column does not
expose this; one host missing it does, and that is the test.

### CTU-13 is unaffected, and that is asserted rather than assumed

Section 2's real-capture figures were measured before this analyzer existed.
CTU-13 is NetFlow: connections, no query names, no TLS sessions. This analyzer
has no connection-derived signal, so it contributes exactly zero findings
there and the ranks, queue depths and corroboration counts in section 2 stand
unchanged. A test pins it, because "it probably does nothing on that shape" is
how a benchmark quietly stops being comparable to its own history.

### Cost

Peak RSS on the demo capture is 262 MB with this analyzer and 261 MB without
it, which is rule 2 behaving as advertised — analyzers run sequentially and
release. On a 1.1M-record, 9,800-host DNS frame the analyzer peaks at 673 MB
and runs at **60k records/second**, against the 180–207k the beaconing
analyzer reaches on CTU-13.

That gap is structural rather than a defect: beaconing evaluates Python once
per *candidate pair*, and this evaluates it once per distinct
(host, registered domain) — 332,700 scored labels on that frame. Three
attempts at it are worth recording, because the first was the obvious one and
was wrong:

  * replacing the per-row `map_elements` suffix reduction with a Polars
    expression: 32k → 34k records/second. Noise. The interpreter call per row
    was not the bottleneck. The expression was kept anyway, because it is the
    right shape for a streaming pass.
  * replacing scalar `np.clip` with a comparison: NumPy dispatches through
    `_wrapfunc` on every call, free on an array and ruinous on a scalar in a
    loop running once per component per label.
  * caching the character model per label: an estate resolves the same few
    thousand registered domains from hundreds of hosts.

The last two together took it from 32k to 60k. What remains is diffuse, and
the largest single item is the same scalar `np.clip`, in
`statistics.weighted_geometric_mean` — shared by every analyzer here, so worth
more than this cluster, and not taken as part of it.

### What is not measured

**No real DGA sensitivity.** Nothing was fetched and nothing was vendored, so
every true positive is synthetic. A licensed feed on disk would close it.

**No real TLS anything.** Both halves synthetic.

**Whether the character model holds outside English.** The word list is
English, so a German or Turkish second-level label reads as improbable.
`nxdomain_rate` is what carries a family in that case, and on `passivedns`
there is nothing to carry it — so the fixture's clean result may not transfer
to an estate that resolves a lot of non-English names. This is the limitation
most likely to produce a surprise in the field.

**Server breadth is the obvious next TLS component and is not used.** A rare
client reaching two servers looks different from one reaching two hundred, and
in the synthetic corpus the implants reach 2 while the minority browser build
reaches 11. Adding it on that evidence would be calibrating against a
difference this generator was written with, and the predicate claims rarity
rather than breadth. It waits on a real corpus.

---

## 10. Temporal ordering and unary attachment

Two changes to `correlate/incidents.py`, neither of which detects anything.
The first orders the findings inside an incident; the second changes which
incident a finding lands in. Both are cross-cutting — every analyzer feeds
this module — so most of what follows is about what they are *not* allowed to
move.

```
0 new parsers · 0 new dependencies · 0 new telemetry · 26 tests
```

### There is no accuracy figure here, and there could not be

`precedes` claims no observation of its own. It reads findings the analyzers
already produced and asserts that one was seen before another, so there is no
detection to score and no corpus that would supply a number. The intel
attachment is the same shape: the join was already validated in section 8, and
what changed is which incident it joins.

So the measurements below are all of the *negative* kind — what did not move —
and that is the honest form for this cluster rather than a shortfall in it.

### The circularity, and the half of it that had no guard

An incident's priority is a noisy-OR across the strongest finding per
predicate, multiplied by a count of independent behaviours. The
warning for this cluster names the multiplier: `precedes` must not count
toward corroboration, or every incident inflates its own ranking by describing
itself. It was already in `non_corroborating`, so that half was covered before
the work started.

The other half was not. `non_corroborating` stops the multiplier and
deliberately *does not* stop the noisy-OR — its docstring says so, because
everything else in that set is a real observation about the world and raising
combined confidence with one is sound. `precedes` is not a real observation.
The correlator mints it from findings already inside the incident, so
admitting it to the noisy-OR is the same closed loop on the other side of the
arithmetic, and it tightens as behaviours are added: five behaviours produce
four edges, each inheriting the confidence of a finding already counted.

This is the argument section 8 already made for keeping observed volume out of
an intel score — VoidLexicon's own observation may not be reported as though it
corroborated the thing it was derived from — arriving from a different
direction. It needed a second, narrower set, `non_evidential`, whose members
contribute neither a multiplier nor a term:

| | `non_corroborating` | `non_evidential` |
|---|---|---|
| Multiplies priority | no | no |
| Enters the noisy-OR | **yes** | no |
| Appears in the incident | yes | yes |
| Why | not a *separate* behaviour | not an observation at all |

Measured against the previous correlator over a 250-incident set: **zero
priorities changed and zero ranks moved.** With the exclusion removed, the
same set moves. That is the whole result for the ordering half.

### Ranks move only where priorities tie, and only on a corpus that forces ties

Adding a finding to an incident changes its content-addressed id, and the
queue's final tiebreak among equal priorities is that id. So an incident that
gains an edge can trade places with one it was tied with. How often that
happens is a property of the corpus, not of the change:

| Corpus | Incidents in a priority tie | Ranks moved |
|---|---|---|
| Confidences on five discrete values | 249 of 250 | 40 |
| Confidences continuous, as analyzers emit them | 7 of 250 | **0** |

Real analyzers produce continuous floats and real captures therefore tie
rarely, so the exposure is confined to the tail. It was worth measuring rather
than assuming, because the first corpus written to test it was the discrete
one and it reported a 16% reshuffle that does not exist on real traffic.

The tiebreak was left as it is. Rule 12 names the subject as the stable key
and the queue uses the incident id instead, which is stable run-to-run but not
across a change of contents — with zero measured movement, swapping it would
have been a behaviour change bought with nothing.

### Sensors disagree, and whether they disagree is checkable

The trap, stated plainly: two log sources on one host can be seconds
or hours apart, so require a minimum separation before asserting order. A
single floor has to be set for the worst case, which is hours, and then
nothing inside one log gets ordered either.

It does not have to be one floor. Every Evidence names its Artifacts and every
Artifact names its `source`, so whether two findings share a clock is already
in the data. Two findings drawn from one source were written by one sensor,
and a second between them is real. Across two sources nothing is guaranteed:

| | Floor | Reasoning |
|---|---|---|
| One source | 1 s | One sensor, one clock, one log's own order |
| Two or more | 300 s | Independent clocks; "seconds or hours" apart |

Below the floor nothing is emitted, rather than an ordering emitted with a
hedge attached. The separation, the floor it cleared, the shared-clock verdict
and both source names go in the evidence payload, so a reader can disagree
with the judgement rather than take it.

### What the demo corpus could not validate

`voidai demo` puts five behaviours on one host and produces **one** edge. Not
a bug: the generator plants every behaviour at the first second of the
capture, so six of the seven representative findings share a timestamp exactly
and there is no order to measure. The one edge that survives is a DNS
tunnelling finding 50 s before a DGA finding, both from `dns.log` — one
sensor, one clock.

That is the right outcome and a poor demonstration, and the fix is not in this
module. A generator that staggers its planted behaviours would exercise the
chain; writing one *here* would be building a corpus to flatter the feature
it is supposed to test, which section 9 already paid for once.

### Attaching a unary finding without re-subjecting it

`matches_threat_intel` is unary and its subject is the indicator, so incident
formation by subject filed an intel hit under the address rather than under
the host that reached it. Incident formation now follows an edge from a
finding's *object* to a unary finding's *subject*. Four consequences, all
settled before the work began:

- **The proposition is untouched.** `matches_threat_intel(ip:45.83.220.17)` is
  true about the address. Re-subjecting it to the host would make it false.
- **It attaches to every incident naming the indicator**, since several hosts
  may have reached it and each one's analyst needs to see it.
- **A finding that attached anywhere does not also stand alone**; one that
  attached nowhere keeps its own incident. A group is dropped only when
  nothing anchors it — an indicator that is *also* an actor in this estate
  keeps its incident, and the hit stays in it too.
- **It does not corroborate.** Not rule 6: a match is complete evidence of
  exactly what it claims. The multiplier counts independent behaviours of a
  host, and an intel hit is not a second thing the host did — it is better
  information about the first thing. Confirmatory evidence belongs in the
  noisy-OR, where it still lands. The failure mode that settles it is a feed
  that is stale, over-broad or wrong: letting it corroborate would multiply
  the priority of every host that touched anything in it, and section 8 built
  age decay because that worry is real.

The lever, if intel hits later prove too weak in the queue, is the finding's
own confidence and not the behaviour count.

### What it cost, for whoever takes the next one

**A property carried on a `@property` broke the moment a finding could have a
different subject.** `RankedIncident.subject` read `findings[0].subject` with
findings sorted by confidence, which was correct while every finding in an
incident shared a subject. Attachment ends that: a hit stronger than the
host's own findings renamed the incident after an address in another country,
and the queue row, `rank_of`, the hunt pivots and the model brief all read
that one attribute. `Incident._derive_title` had the same assumption from the
other side and rendered "2 hosts". Both were found by printing the queue, not
by the type checker — the types were all still correct.

**Two tests passed for a reason other than the one they named, and both were
found by breaking the code rather than by reading it.** The first asserted
that no entity precedes itself, using a three-behaviour incident in which no
*adjacent* pair happened to share a pivot; it passed with the guard deleted.
The second asserted the chain is stored in the order it describes, using three
equally-confident behaviours, so it fell through to a finding-id tiebreak and
passed under four of six hash seeds. Rule 8 says to break the fix and confirm
the test fails; doing it to eleven guards found these two, and nothing else
would have.

**`hash()` in a test fixture defeats a test about reproducible ids.** The
locator in `tests/test_correlate.py` was `abs(hash(kind)) % 1000`, and Python
salts string hashing per process — so every fixture finding had a different
content-addressed id in every run, and a determinism test could only ever
compare a run with itself. The same shape as section 8's wall-clock `age_days`:
the assertion looks like it covers reproducibility and covers nothing.

**The sequence has to be stored in sequence.** Derived findings were first
sorted with the rest by confidence, and edges inherit the confidence of what
they order — so a run of equally-strong behaviours produced a chain in
arbitrary order that a reader had to reassemble from the payloads, which
defeats the point of the predicate. They are now stored last and in time
order. The flag that keeps them last looks redundant next to the time key and
is not: a sensor with an unset clock writes 1970, every key collides at zero,
and only the flag holds.

---

## 11. Host and endpoint — a real corpus, and a refusal to score it

The first half of the host cluster: `executes_rare_process` and
`exhibits_anomalous_lineage`, one analyzer, one parser, one baseline.
`establishes_persistence` and `authentication_anomaly` are deliberately not
built — see below for why that split and not another.

**The headline is not the accuracy figure.** It is that a real, openly
licensed, correctly formatted corpus of Windows attack telemetry exists, is
now committed, contains a genuine true positive, and the analyzer **declines
to score it** — correctly, because four hosts is not an estate. That is a
harder result to claim by accident than "no false positives observed", and it
is the one worth reading.

| | Synthetic estate | Real corpus (`tests/data/real.sysmon.jsonl.gz`) |
|---|---|---|
| Hosts | 40 | **4** |
| Process creations | 3,388 | 446 |
| Distinct images | 26 | 107 |
| Images on exactly one host | 23% | **74%** |
| Findings | 7 | **0 — gated** |
| Precision / recall | 0.857 / 1.000 | not measurable |

Reproduce with `voidai bench` (fifth table) and
`voidai doctor --telemetry <dir>`.

### The trap, and the answer

The constraint is *rarity needs an estate.* Every "rare process"
signal degenerates on a single host, where everything is rare exactly once.

The answer turns on what each verb *asserts*. The Lexicon already says:
`executes_rare_process` is "runs a process rare across the observed estate",
and `exhibits_anomalous_lineage` is "a parent/child relationship inconsistent
with normal system behaviour" — where the only thing this analyzer knows about
normal is what the estate did. Estate prevalence is therefore not a
*component* of these scores. It is the signal that **defines** them.

That is rule 6's second level, and the answer is the one cluster 1 reached for
`exfiltrates_to` on direction-blind NetFlow: if the defining signal is
unavailable, the verb is unsayable. **Gate and emit nothing.**

Unlike cluster 1 there is no weaker predicate to fall back to. `exfiltrates_to`
could degrade to `transfers_anomalous_volume` because the grammar already had
one; there is no `executes_process_from_unusual_path`, and minting one is a
Lexicon change — cross-cutting work, deferred rather than approved, and noted
here as a candidate so the next cluster does not rediscover the gap.

### Three gates, and the one that was measured rather than chosen

```
min_baseline_hosts   5      distinct hosts reporting process telemetry
min_executions       200    total process creations
max_singleton_share  0.50   share of images seen on exactly one host
```

The first two are ordinary floors. The third is the one that matters, and it
is the first gate in this project set by measurement instead of judgement.

Host count alone passes an estate that is wide but **shallow** — thirty
machines observed for twenty seconds each — where every image is still a
singleton and every rarity score is still 1.0. The share of single-host images
detects that directly, because it asks whether the baseline has converged
rather than how many machines are in it.

The real corpus is what set it. Its distribution:

```
images on 1 host   79      images on 3 hosts   2
images on 2 hosts  18      images on 4 hosts   8      (107 distinct)
```

**74% of images are seen on exactly one host, and they include `lsass.exe`,
`explorer.exe`, `csrss.exe`, `smss.exe`, `winlogon.exe` and `spoolsv.exe`.**
Every one of those runs on every Windows machine ever built. They are
"rare" here because the capture is half an hour long and its four hosts are
unevenly instrumented — SCRANTON contributes 359 of the 446 executions,
UTICA contributes 9.

So a rarity measure over this capture ranks `lsass.exe` identically with the
APT29 day-1 payload, which is present in the file:

```
explorer.exe → C:\ProgramData\victim\‮cod.3aka3.scr   "…\‮cod.3aka3.scr" /S
```

Reporting the payload here would mean reporting `lsass.exe` too. The analyzer
reports neither, and `tests/test_host.py::TestTheGate` asserts both halves of
that: **zero findings, and 447 records parsed.** The pairing is the point —
"the analyzer declined" and "the parser returned nothing" look identical from
outside, and only one of them is correct.

The capture fails two gates independently: four hosts against a floor of five,
and 74% against a ceiling of 50%. Lowering the host floor to four does not
unlock it, which is asserted rather than assumed.

### So: synthetic sensitivity, real specificity, and rule 7 in one sentence

**Sensitivity is synthetic. The real corpus contributes a gate result and no
detection rate.** Not for want of a corpus — the format is right and the
licence is verified — but for want of an estate. The largest openly-licensed
Windows attack corpus available is four hosts over half an hour, which is
below this cluster's own floor.

### What was checked, and what was rejected

**`OTRF/Security-Datasets` — MIT, Copyright (c) 2021 Open Threat Research
Forge.** Verified by fetching `LICENSE`, not by reputation. Ships JSON lines
with `EventID`, `Hostname`, `UtcTime`, `Image`, `CommandLine`, `ParentImage`
and `ProcessGuid` at the top level, so **no EVTX parser and no new
dependency** — engineering rule 9 satisfied without an extra.

Committed as `tests/data/real.sysmon.jsonl.gz`: every event-ID-1 record from
`compound/apt29/day1`, verbatim except the `Message` field, which is a
human-readable rendering of the structured fields already present and was
503 KB of the original 1,316 KB. 66 KB gzipped, against `real.passivedns`'s
52 KB. Attribution is carried **in-band** in a comment header, the way
`real.passivedns` carries its CC-BY line — a licence recorded only in a
document is a licence that goes missing the first time the file is copied.

**`sbousseaden/EVTX-ATTACK-SAMPLES` — GPL-3.0**, verified the same way. Not
vendored, for two independent reasons: GPL-3.0 data in an Apache-2.0
repository is a licence conflict not worth taking on for a fixture, and the
samples are `.evtx` binaries needing the parser rule 9 puts behind an extra.
Either reason alone would have been enough.

### Command-line entropy was measured and removed

The design asked for command-line length **and entropy**. Entropy is not in
the score, and the reason is not section 9's.

Section 9 found entropy fails on 6-to-20-character domain labels because at
that length it measures length. Command lines are hundreds of characters, so
that objection does not apply — and it fails anyway, for a different reason:
**the encodings attackers actually use are less entropic than ordinary command
lines.** Base64 of UTF-16LE text is half null bytes, and null bytes are
extremely predictable.

Measured over the real corpus's 446 command lines:

| | Length | Entropy | Percentile |
|---|---|---|---|
| The Empire base64 payload | 7,106 | 4.44 | **38th** |
| `SearchProtocolHost.exe Global\UsGthr…` | 308 | 5.22 | 96th |
| Corpus median | 55 | 4.44 | 50th |

Sixty-two percent of the command lines in a capture of a live intrusion score
*higher* than its largest encoded payload. A component that ranks the attack
below the median is not a weak component; it is a wrong one.

**Length alone does separate it** — 7,106 against a 99th percentile of 308 —
but only against the image's own baseline. Scored against a global constant it
is a constant drag: a typical 55-character line scores 0.09 on any saturating
curve wide enough to distinguish 7,106, so every finding in the estate is
multiplied down by roughly the same amount and the threshold simply moves.
That is not a signal, it is a units change.

So the command line is carried in the **evidence payload**, where an analyst
reads it first, and not in the arithmetic. A per-image length deviation —
`powershell.exe` normally 90 characters, this instance 7,106, through the
existing `robust_deviation` — is the candidate replacement and is left for
whoever needs it, unbuilt rather than guessed at.

`executes_rare_process` therefore scores three components, not four:

| Component | Measure | Weight |
|---|---|---|
| `image_prevalence` | hosts running it, through `destination_rarity` | 0.50 |
| `path_anomaly` | graded prior over where the binary lives | 0.34 |
| `execution_prevalence` | how few times it ran estate-wide | 0.16 |

### The lineage measurement had to be rewritten, and why

The first version scored an edge on the raw number of hosts showing it, plus
`-log2 P(child | parent)` from the estate's lineage graph. It found every
planted implant. It also swallowed the other predicate whole: **all seven
findings came back as lineage and `executes_rare_process` was structurally
unreachable.**

The reason is arithmetic rather than tuning. `hosts(edge) ≤ hosts(child)`
always, so a binary the estate has never run *always* has an edge the estate
has never seen. Raw edge rarity cannot distinguish an anomalous relationship
from a novel participant, because a novel participant guarantees one.

The conditional frequency did not save it either, and failed in the opposite
direction. `winword.exe` in the corpus has spawned exactly one process, so
`P(cmd.exe | winword.exe)` is 1.0 — surprisal zero — and the strongest
lineage signal available annihilated the clearest true positive in the corpus.
Both measures were reading the sample size.

What works is **conditional breadth on both ends**:

| Component | Measure | Weight |
|---|---|---|
| `parent_breadth` | `1 − hosts(edge)/hosts(parent)` | 0.38 |
| `child_breadth` | `1 − hosts(edge)/hosts(child)` | 0.38 |
| `child_surprisal` | `-log2 P(child\|parent)`, omitted below 20 samples | 0.24 |

Dividing by how widespread each end is separates the two cases completely, and
the corpus's own decoys show it:

```
winword.exe → cmd.exe        1 host of 40.  winword on 40, cmd on 40.
                             parent_breadth 0.98, child_breadth 0.98   → 0.98
cmd.exe → msbuild.exe        1 host of 40.  cmd on 40, msbuild on 1.
                             parent_breadth 0.98, child_breadth 0.00   → 0.15
```

Both edges are on exactly one host out of forty. The developer's `msbuild.exe`
runs on one machine and is spawned by `cmd.exe` on that machine every single
time, so its parentage is entirely typical *of msbuild*, and the measure says
so. The same arithmetic rejects `cmd.exe → psexec64.exe`, an administrator's
tool whose only parent anywhere is `cmd.exe`.

It also makes the two predicates disjoint by construction rather than by
filter, which is what fixes the swallowing: a novel child scores zero on
`child_breadth` because `hosts(edge) = hosts(child) = 1`.

### Subsumption, and where it had to live

Even with the breadths conditional, one process creation can satisfy both
predicates when a novel binary reaches a second host. Reported as two
findings it becomes **two independent behaviours of the host**, and the
corroboration multiplier promotes the incident for one event observed twice —
the argument that keeps `presents_rare_tls_fingerprint` out of the count.

So a `(host, image)` that earned `executes_rare_process` cannot also earn
`exhibits_anomalous_lineage`.

**Rare-process wins, and not because it is more severe** — lineage is the HIGH
one. It wins because it names what is actually unusual: a binary the estate
has never run trivially arrives on an edge the estate has never seen, so the
lineage sentence is true and adds nothing. The reverse does not hold, which is
the whole of why `winword.exe → cmd.exe` is a finding at all.

**It has to be in the analyzer, not in `correlate/incidents.py`.** The
correlator sees two findings about one host and cannot know they describe a
single execution. The analyzer that produced both knows exactly. Nothing in
the correlator changed for this cluster.

The bug this hid, found by breaking the fix (rule 8): the subsumption was
originally computed from the **capped** rare-process list, so every novel
binary the per-host ceiling dropped came back under the other predicate. The
cap was bounding the display and quietly widening the behaviour count. Both
predicates are now scored in full before either is capped, and
`test_a_capped_rare_finding_does_not_reappear_as_lineage` guards it.

### Corroboration: `executes_rare_process` does corroborate

Two prevalence predicates are already excluded from the multiplier, so the
question had to be asked. The test that settles it is not "is it prevalence":

1. **Is it a behaviour of the subject, or a property of something else?**
2. **Does it rest on more than one cheap signal?**

`contacts_rare_destination` is a behaviour but fires on a single cheap signal
at LOW severity — excluded for flood risk. `presents_rare_tls_fingerprint` is
one signal and is really a property of the client's TLS library, not a thing
the host chose to do. `matches_threat_intel` is a property of the destination.
`shares_infrastructure_with` is a property of the environment. `precedes` is
derived.

`executes_rare_process` passes both. Running an unfamiliar binary out of a
user-writable directory is unambiguously a thing the host *did*, and it is a
geometric mean of three signals at MEDIUM. A host that beacons **and** does
that is genuinely two behaviours, which is what the multiplier is for. And
after subsumption, a standing-alone rare-process finding means "rare, and the
lineage looked normal" — a real and separate claim.

Recorded here because the "is it prevalence" reading would have excluded it
and been wrong, and the next cluster faces the same question.

**The number attached to it**, so the question is not settled by argument
alone: on the synthetic estate, 7 findings across 5 hosts produce **1
corroborated incident**. On `voidai demo`, host telemetry adds **1**
corroborated incident and 2 queue rows. On CTU-13 it adds nothing, because
there is no host telemetry there. If it floods on a real estate that is
measurable and revisitable, the same way egress was.

### Synthetic accuracy, and the false positive that stays

```
6 TP · 1 FP · 0 FN     precision 0.857   recall 1.000   f1 0.923
3,388 records · 40 hosts · 8h · 7 findings · 196 MB peak
```

Six plants, in two shapes that cannot see each other:

- **Three novel binaries** — a dropped executable in a user temp directory, a
  service binary masquerading under `ProgramData`, a staging tool in
  `C:\Users\Public`. Found by rarity.
- **Three ordinary binaries in an impossible relationship** —
  `winword.exe → cmd.exe → powershell.exe` and
  `outlook.exe → powershell.exe`. Every image runs on all forty machines.
  Found by lineage, and **invisible to rarity by construction.**

Each plant is scored only against the predicate it was planted for. Counting
each against both would report a 50% miss rate for a detector behaving exactly
as specified — the shape section 9 avoided by counting a dictionary generator
as a miss and *saying so* rather than dropping it from the denominator.

Three decoys are rejected: the developer toolchain and the administrator's
tool described above, and a rare-but-ordinary lineage.

**The one false positive is planted and stays.** A legitimate 7-Zip installer
in a user's Downloads folder, run once: rare image, writable path, single
execution. It is indistinguishable from a dropped payload by everything this
analyzer measures, and every threshold that removes it also removes the
staging tool in `C:\Users\Public`. Section 7's backup target, on a different
axis. Moving a threshold until the corpus looks clean is fitting to the
corpus, and the corpus was written by the same hand as the detector.

It costs a queue position on the demo, and that is reported rather than
hidden: at priority 0.98 it takes rank 3, above two genuine single-behaviour
beaconing incidents at 0.87 and 0.85. A single strong rarity finding
outranking a single strong periodicity finding is the arithmetic working as
designed — neither corroborates, and 0.98 is a higher confidence than 0.87 —
but it is the first time a *planted* false positive has ranked above a *real*
detection anywhere in this document, and it is the strongest argument on this
page for the asset inventory in section 12. An inventory that knew
`WS019` was a developer workstation would not demote it; one that knew the
installer's hash was signed would. Neither exists.

### Cost

```
1,946,000 process creations · 300 hosts · 706 MB frame
0.81 s · 2.4M rec/s · peak RSS 192 MB above the frame
```

Rule 3 holds and is the reason. Pass one groups the capture to one row per
(host, parent image, image) — 24,000 rows for two million executions, because
its height is the number of distinct lineage *relationships* rather than the
number of events — and pass two gathers arrays only for triples that could
still reach a threshold. On the estate above that is a few hundred rows.
`test_pass_two_gathers_a_small_fraction_of_the_capture` asserts the ratio
directly rather than measuring RSS, because the row count is the property that
decides the memory and an RSS assertion is flaky.

Rule 2 holds too: the analyzer runs eighth and releases, so the run's peak is
unchanged. The demo's peak RSS is 269 MB with host telemetry in the capture.

The bounded ancestry walk is the one place this cluster spends passes rather
than memory. Each level of the climb is a scan filtered to the GUIDs the level
below asked for, up to `max_chain_depth` of them, and the rows held are
bounded by candidates × depth. A process-creation log is dense in distinct
*subjects* rather than in records — two million executions here against
CTU-13's 12.7 million flows — so trading four cheap scans for a flat memory
profile is the right way round on this telemetry, and it is the opposite of
the trade `beaconing` makes.

### CTU-13 is a no-op by construction

NetFlow and passivedns carry no process telemetry. `ctx.processes` is empty on
every scenario, both predicates return before the gate is even reached, and
scenario 3 rank 2 of 247 with 3 corroborated and scenario 6 rank 1 of 160 with
1 corroborated cannot move.

That is asserted rather than assumed —
`test_a_network_only_capture_is_silent` builds a connection-only context and
requires an empty result. If a re-measurement moves a rank, something reached
the queue that this test says cannot, and the finding is the bug rather than
the number.

### What it cost, for whoever takes the next one

**Two of fifteen tests passed for a reason other than the one they named**,
and rule 8 is what found them. A cycle test on the ancestry walk asserted only
that the walk *terminates* — which the depth bound guarantees on its own, so
it passed with the cycle guard removed. What the guard actually buys is the
chain's **content**: without it a two-node cycle reports `a → b → a → b`, an
ancestry that never happened, in an evidence payload an analyst is meant to
trust. The second was a truncated-chain test standing in for the `nulls_equal`
join guard while containing no null parent at all; the real exposure is a
process whose parent started before the capture window, which is the shape of
the first execution on a host the sensor started watching mid-intrusion.

**A size-preserving mutation leaves stale bytecode.** Breaking `start=1` to
`start=0` and reverting it produced a `.pyc` whose cache key — mtime and size
— was unchanged, so the *next* run imported the mutant and a passing test
failed for no visible reason. Anyone repeating the rule 8 exercise should run
the mutants with `-B`.

**The rule 12 shuffle earns its place here more than anywhere.** Ties are not
an edge case in this telemetry, they are the norm: every singleton image sits
at an identical prevalence of 1.0 and every one-off execution at an identical
execution prevalence, so four of the seven synthetic findings score 0.980
exactly. Running the same frame twice would not have caught a `group_by`
ordering leaking into the cap; shuffling the input rows does, and it caught
nothing only because the tiebreak was written first.

**Host telemetry and network telemetry do not join, and that is now visible.**
Sysmon event ID 1 records a computer name and no address, so the demo's
compromised machine appears in the queue **twice** — `ip:10.0.1.14` for
everything the network sensors saw, and `host:FINANCE-WS04` for what the
endpoint agent saw. The corroboration payoff promised for this
cluster is therefore only half collected: two host behaviours corroborate each
other, and neither corroborates the five network behaviours on the same
machine.

Closing it needs an asset inventory mapping addresses to hostnames.
`AnalysisContext.ip_to_host` is already shaped for exactly that and nothing
populates it — the same gap section 12 names for demoting a gateway, arriving
from a second direction. It is one small parser and it is deliberately not in
this branch.

*Since collected.* Section 11½ ships that parser, and the split above closes:
one row, seven behaviours, on the same capture.

**`networkx` earned its place, in two ways, after eight commits of being a
dependency one analyzer used for connected components.** The estate's observed
lineage is a directed graph and the conditional frequency comes off its
out-strength; the per-host process tree, built from `ProcessGuid` and
`ParentProcessGuid`, is a second one, walked for ordered ancestry with a
visited set. `explorer → winword → cmd` and `explorer → cmd` are different
things for a responder to read.

**Chain surprisal is reported and not scored, after three attempts.** The mean
edge anomaly along an ancestry dilutes the one edge that matters with the
ordinary ones above it — `explorer → winword` is on every host, and averaging
it with a 0.98 gives 0.49. The maximum restates `parent_breadth` exactly. A
count of unusual edges scores a genuine single-step anomaly at zero. A
component that restates another is the double-count this analyzer already
exists to prevent, so the chain stays in the evidence payload, the basis line
and the summary — where it does real work for a reader — until there is a
measurement of it that is not a restatement.

**The shipper's clock is not the sensor's clock, and the gap is not small.**
`@timestamp` is when the collector received a record; `UtcTime` is when the
process started. On the committed corpus they differ by a **median of 34
seconds and a maximum of 84**, and 366 of 446 records differ by more than one
second — which is the correlator's floor for ordering two behaviours from a
single source. Taking `@timestamp` would not have blurred an ordering. It
would have invented one, in the predicate cluster 4 built specifically to
avoid that.

---

## 11½. The asset inventory — a join, not a detector

**Nothing here is detected and nothing here is scored.** Rule 7 applies to
this section in its strongest form: the input is a file an operator wrote, the
output is a subject named more precisely, and there is no ground truth to be
right or wrong about. The correctness questions are whether the join picks the
right mapping, whether it degrades honestly when the file is stale or partial,
and whether it changes nothing at all when there is no file. `voidai bench`
reports no accuracy figure for it because it has none to report.

### What one line did to the demo capture

The capture now ships `assets.inv` carrying a single mapping,
`10.0.1.14 -> FINANCE-WS04`, dated four days before the traffic starts:

| | Before | After |
|---|---|---|
| Patient zero | two rows: `ip:10.0.1.14` with 5 behaviours, `host:FINANCE-WS04` with 2 | one row: `host:FINANCE-WS04` with **7** |
| Priority | 2.50 and 1.50 | 2.50 |
| Findings on that row | 10 and 3 | 13 |
| Incidents in the queue | 10 | 9 |
| Corroborated incidents | 2 | 1 |

The seven are `beacons_to`, `scans`, `tunnels_dns_over`,
`resolves_algorithmic_domain`, `triggered_signature`, `executes_rare_process`
and `exhibits_anomalous_lineage` — network and host evidence corroborating on
one machine, which is what section 11 was ranked highest for and did not get.

Corroborated incidents falling from two to one is the join working, not a
regression: the two rows that each corroborated internally were one machine,
and merging them leaves one corroborated incident rather than two.

### The false positive moved up, and stays

`host:WS019.contoso.local` — a legitimate installer, run once, from a user's
Downloads folder — was rank 3 and is now rank 2, above four genuine
detections. It has not been tuned away and it has not got worse. Removing the
duplicate row above it simply stopped hiding how highly it already ranked,
which is a more useful thing for this page to say than a queue that reads
tidily.

### Coverage, which is the number that is not flattering

```
inventory   1 of 1 mapping(s) applied — resolved 1 of 109 observed address(es) (0.9%)
```

One line names one address out of the hundred and nine the capture contains.
The receipt and `voidai doctor` both report the fraction rather than the
mapping count alone, because an inventory covering 3% of an estate is a
rounding error dressed as an improvement and a count cannot tell the two
apart.

### No inventory, no change — asserted rather than assumed

The CTU-13 captures ship no `.inv` file, so this cluster must be a no-op on
them. That is not left to inspection: `tests/test_inventory.py` asserts that
findings produced with an empty inventory, with an inventory naming no address
in the capture, and with none at all are **byte-identical by
content-addressed ID** to those produced before this module existed, and that
an inventory which renames one host leaves every other finding's ID untouched.
Scenario 3 (rank 2 of 247, 3 corroborated) and scenario 6 (rank 1 of 160, 1
corroborated) are therefore expected to reproduce exactly; if either moves,
the join has reached something it should not have.

Findings whose subject came from host telemetry rather than from an address —
`host:FINANCE-WS04 executes_rare_process`, asserted from Sysmon's computer
name — never resolve anything, never cite the inventory, and keep their IDs
whether or not a file is present. That is structural: those call sites do not
call `actor()`, so they cannot call `resolution_evidence()` either. A test
asserts it anyway, because it is a property worth pinning rather than a
workaround worth remembering.

### What a resolved finding now carries

```
ev_40e77cfeeadfa8  10.0.1.14 is FINANCE-WS04, per corp-asset-register
                   (stated 2025-06-11, 4d before the capture)
    /captures/demo/assets.inv:line:6
```

The mapping is a link in the chain of custody, not a lookup performed off to
one side. Its payload carries the address, the hostname, the register, the
date stated, the capture's start, the age in days and a staleness verdict, and
its artifact is the file and line an analyst can open. A mapping older than
730 days is not applied at all; one older than 90 days is applied and flagged;
one stated *after* the capture is applied and flagged too, which is the case
most likely to pass unexamined because a recent file reads as the safe kind.
`docs/inventory.md` states the ladder in full.

---

## 12. What is still open

**Corroboration is broad but shallow on real data.** Seven analyzers now
exist, and multi-way corroboration ranks correctly on synthetic traffic —
`voidai demo` puts patient zero at priority 2.50 against a runner-up at 0.89,
on five independent behaviours. But CTU-13 carries neither DNS query names nor
alerts nor TLS, so on the real captures the signal is still only two-valued.
Closing that needs a capture with network, DNS, TLS and alert telemetry
together — which is a data problem, not a code one.

**Nothing has ordered a real sequence yet.** `precedes` works and is tested,
but the only capture available to exercise it plants every behaviour in the
same second — section 10 — so on `voidai demo` it emits one edge out of five
and on CTU-13 there are two behaviours to order rather than five. Whether an
ordered narrative actually helps an analyst is unanswered, and answering it
needs a capture where a compromised host does several things hours apart. A
data problem, like the one below it.

**An intel hit still cannot be measured against a real feed.** Attachment
means a hit now joins the host that reached the indicator rather than standing
alone — section 10 — which closes the correlator-side half of the item that
stood here. What it does to a queue at scale is still unmeasured: CTU-13 runs
three analyzers and no IOC file, so no real capture in this repository has ever
produced an intel finding. The behaviour under a large, imperfect feed is
reasoned about and guarded by a flood test, not observed.

**Volume and egress has no real accuracy figure, and may not get one here.**
CTU-13 gives it queue ranks and corroboration counts — section 7 — but not a
precision number: the corpus labels spam, scanning and click fraud rather than
transfers, so there is nothing to score a volume detector against. Its one
real true positive is scenario 6's Menti channel at 2.16 MB. Closing that
needs a capture with labelled exfiltration in it, which is a data problem
rather than a code one.

**The estate has no identity, and it now costs a detection rather than only a
false positive.** VoidLexicon does not know which of its hosts is a mail relay, a
resolver, or a domain controller. `147.32.84.229` ranks first on scenario 3
because it reaches 162,612 destinations, which is exactly what a gateway does.
The volume analyzer meets the same wall from the other side: its single false
positive is a backup target that exactly one machine uses, which no signal
available to it can distinguish from a private drop box.

Section 11 adds a third face of the same gap and the most expensive one.
Sysmon records a computer name and no address, so a machine with both network
and host telemetry produces **two incidents** — `ip:10.0.1.14` and
`host:FINANCE-WS04` on `voidai demo` — and the conjunction this cluster was
built to surface is split in half before the correlator sees it. An asset
inventory would demote the gateway, demote the backup target and join those
two rows, all in one step. `AnalysisContext.ip_to_host` is already shaped for
it and nothing populates it; it is one small parser and the highest-value one
left on this list.

*Now written — section 11½.* The third face is closed: patient zero is one row
carrying seven behaviours. The first two are not, and the reason is worth
stating, because it is the same reason in both cases and it is not a missing
feature. Demoting a gateway and demoting a backup target need an operator to
say which machines those are; the parser reads such a statement and nothing in
this repository will invent one. An inventory covering 0.9% of the demo estate
demonstrates the join and closes none of the ranking gaps on its own, which is
why coverage is now reported next to the mapping count.

**The DGA character model has never seen a non-English estate.** Its word
list is English, so a German or Turkish second-level label reads as
improbable, and on telemetry without `rcode` there is no second component to
carry the family. Section 9 states it as the limitation most likely to
produce a surprise in the field, and closing it needs traffic from an estate
that resolves a lot of non-English names rather than a code change.

**No real corpus for either half of cluster 3's sensitivity.** Public DGA
feeds exist but were not vendored — nothing is fetched, and no redistribution
licence was verified. No openly-licensed `ssl.log` carrying JA3 was reachable
at all, so TLS fingerprint rarity is synthetic on both sides and its threshold
was set against a corpus written by the same hand as the detector. Both are
data problems.

**Host telemetry has no real sensitivity figure, and the reason is an estate
rather than a corpus.** Section 11 has a real, MIT-licensed, correctly
formatted corpus of Windows attack telemetry with a genuine true positive in
it, and the analyzer correctly refuses to score it: four hosts over half an
hour, with 74% of images seen on exactly one machine. Closing it needs a
labelled capture from an estate of tens of machines, which is a data problem
and a harder one than the others on this list — public corpora are built to
demonstrate a technique, and one host is enough for that.

**Two host predicates remain unclaimed.** `establishes_persistence` and
`authentication_anomaly` are declared in the Lexicon and deliberately not
built. Neither shares the parser or the baseline
that made the first two one unit of work.

**A per-image command-line baseline is unbuilt.** Section 11 measured entropy
and removed it, and left length out because a global constant makes it a
constant drag. Length against the *image's own* distribution — through the
existing `robust_deviation` — is the measurement that would work, and it is
guessed at nowhere.

**Memory headroom on the largest capture.** Re-measured on the corrected
parse, scenario 3 peaks at 2,746 MB unconstrained and completes inside a
2,200 MB hard cgroup ceiling, so a 4GB board clears it with roughly 1.5 GB
spare. That is a wider margin than the 1.1 GB measured on the misparsed rows,
but nothing enforces it as analyzers are added. Windowing pass 1 would lower it
further.

---

## 13. Energy

Every figure on this page was produced on x86_64 with **estimated** energy —
this container exposes no RAPL counters, and the fallback profile deliberately
overstates draw (15 W idle + 12 W/active-core). Those numbers are indicative
only and are labelled as such in every receipt.

Measured energy requires either RAPL access or an ARM board with INA rails.
Pending real hardware, no energy claim in this project should be treated as
verified.

---

## 14. Reproducing

```bash
# Synthetic — no download required. Prints five tables against five separate
# corpora: beaconing (section 1), volume-and-egress (section 7), domain
# generation and TLS fingerprints (both section 9), host and endpoint
# (section 11). Never averaged: they measure different behaviours against
# different decoys, and their evidence is not of the same kind.
voidai bench

# Threat intel: section 8. No corpus to download — the fixture is committed.
voidai doctor --intel tests/data/example.ioc

# TLS fingerprints: whether a capture can support section 9's second half.
# Host telemetry: whether its estate can support section 11's predicates at
# all, and the reason in full if it cannot. Both from the same flag.
voidai doctor --telemetry ./capture

# Section 11's real corpus is committed; this is the refusal, reproduced.
python -c "from voidai.analyzers import HostAnalyzer, AnalysisContext; \
from voidai.ingest.sysmon import read_sysmon; \
e = read_sysmon('tests/data/real.sysmon.jsonl.gz'); \
print(e.height, 'records ->', HostAnalyzer().analyze(AnalysisContext(processes=e)))"

# CTU-13 scenario 6 (245MB) and scenario 3 (1.4GB)
mkdir -p data/ctu13 && cd data/ctu13
curl -O https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/capture20110816.pcap.netflow.labeled
curl -O https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-44/capture20110812.pcap.netflow.labeled
```

Captures are not committed — they total 1.7GB and are freely redistributable
from the source above under CC-BY.
