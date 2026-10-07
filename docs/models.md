# Models

The language layer is an **optional extra**. VoidLexicon detects, correlates and
ranks with it uninstalled, and `voidai run --no-llm` is a first-class path
rather than a degraded one. What you lose without a model is the narrative and
the suggested next steps. You do not lose a single finding.

## Installing

```bash
pip install -e ".[llm]"
```

`llama-cpp-python` builds from source where no wheel exists for your platform.
It needs `cmake` and a C++ compiler, and takes a few minutes.

## Fetching a model

Any GGUF chat model llama.cpp can load will work. The target tier is **1.5B–4B
parameters at 4-bit quantisation** — small enough to run on hardware an
individual owns.

```bash
mkdir -p models && cd models
curl -LO https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf
```

```bash
voidai run ./zeek-logs/ --model models/qwen2.5-1.5b-instruct-q4_k_m.gguf
```

Weights are never committed and never downloaded at runtime. VoidLexicon has no
code path that fetches a model; you place the file, or there is no model.

| Model | Size (Q4_K_M) | Licence | Notes |
|---|---|---|---|
| **Qwen2.5-1.5B-Instruct** | 1.1 GB | Apache-2.0 | Measured below. Fits a 4GB Pi. |
| Qwen2.5-3B-Instruct | 2.0 GB | Qwen licence | Better prose; check licence terms. |
| Llama-3.2-3B-Instruct | 2.0 GB | Llama licence | Widely available. |
| SmolLM2-1.7B-Instruct | 1.1 GB | Apache-2.0 | Alternative at the same tier. |

Apache-2.0 models are listed first deliberately: the tournament requires an
open-source base, and a permissive licence makes that unambiguous.

## Measured behaviour

Qwen2.5-1.5B-Instruct Q4_K_M, 4 CPU threads, x86_64, on the CTU-13 scenario 6
top-ranked incident:

```
brief            256 tokens        (2 findings, 3 measurements)
prompt           605 tokens
completion       188 tokens
wall            28.9 s             (~7-11 tok/s)
claims struck      0
```

Detection throughput is unaffected — 332,759 records/second — because the two
stages are metered separately. The receipt reports them on separate lines for
exactly that reason.

## What a 1.5B model gets wrong, and what was done about it

None of the following are hypothetical. Each is what this model actually
produced during development, and each was fixed by changing what it is shown
rather than by asking it more nicely.

**It did not know a beacon was bad.** Given `beacons_to` at 0.98 confidence,
it wrote "likely a legitimate communication". Fixed by putting the Lexicon's
own predicate description in the brief. The definition already existed and is
already authoritative; it costs a dozen tokens.

**It invented meanings for ATT&CK codes.** Shown T1071, T1573 and T1008, it
glossed them as "reconnaissance, credential harvesting, and monitoring". They
are Application Layer Protocol, Encrypted Channel, and Fallback Channels. The
codes were removed from the prompt. They remain on the Finding, where an
analyst reads them.

**It parroted internal notation.** Shown the ranking rationale `noisy-OR of
[...]`, it asserted "the host is a noisy-OR beacon". The brief now carries the
priority number; the arithmetic stays in the audit trail.

**It wrote one enormous paragraph and ran out of budget.** A 900-character
narrative followed by truncation mid-claim, leaving JSON that would not parse.
Fixed in the grammar: every string is length-bounded, every list is
count-bounded, and whitespace is capped at a single optional space so the
model cannot spend its budget on indentation.

The pattern behind all four: **show the model only what it can reason about.**
Raw logs, technique codes and scoring notation are all things it will repeat
without understanding.

## What the verifier catches, and what it cannot

Catches: claims with no citation, citations that do not resolve to a finding
the brief actually showed, and claims naming an address, domain or port absent
from the cited evidence. That last one matters most — an invented IP address
in an incident report reads exactly like a real one.

Does not catch: a claim that is well-cited, names nothing invented, and is
still wrong. "Likely legitimate" about a real beacon cites correctly and
fabricates nothing. Only better grounding fixes that class, which is why the
three fixes above are about the prompt rather than the filter.

A measured instance that is not yet fixed. On `voidai demo`'s
false-positive incident — a single `executes_rare_process` finding at 0.98 —
Qwen2.5-1.5B calls that confidence "low" on **3 of 8 seeds**, once as a
verified claim, because its citation is real. The obvious suspect was the
brief printing `confidence 0.98 (medium)`, with the predicate's severity where
an adjective for the number would sit. Relabelled as `severity medium`, the
same eight seeds gave **2 of 8**, and different seeds misread — noise, not a
fix — so the change was not kept. In the two full demo runs made, the
top-ranked incident did not show it; two runs is not a measurement of that.

Struck claims are shown to the analyst, not silently dropped. Someone deciding
whether to trust this tool needs to see what it refused to say, and the strike
count appears on every receipt as a standing measure of confabulation.
