# Deployment

VoidLexicon is architecture-agnostic: pure Python, no compiled extensions in the
core, and no dependency that lacks an `aarch64` wheel. It runs the same way on
x86_64 and on ARM.

Start with:

```bash
voidai doctor
```

which reports the platform, whether energy will be **measured** or
**estimated**, and whether the optional narrative layer is present — before
you run a benchmark rather than after.

---

## Raspberry Pi 5

The reference target. **4GB is enough**, including for the largest capture in
this repository — measured, not assumed; see the memory section below.

```bash
sudo apt install -y python3-venv python3-dev
git clone https://github.com/CypherNova1337/VoidLexicon && cd VoidLexicon
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
voidai doctor
```

The core install needs no compiler. `pip install -e ".[llm]"` does —
`llama-cpp-python` builds from source on ARM and takes several minutes.

### Memory — measured against a board's ceiling, not estimated

An earlier version of this document claimed the 66-hour capture did not fit a
4GB Pi. That was a guess from a peak-RSS figure, and it was wrong. `tools/envelope.py`
puts the workload inside a cgroup with a hard memory limit and swap pinned to
the same value — the same mechanism a board with no swap enforces — so the
question can be answered by running it:

```bash
sudo python3 tools/envelope.py --board pi5-4gb --reserve-mb 400 -- \
    voidai bench --real data/ctu13/botnet-44-scenario03.netflow.labeled
```

**What each workload actually needs** (peak charge, and the smallest ceiling
it survives):

| Workload | Records | Peak | Smallest ceiling that completes |
|---|---|---|---|
| `voidai demo` | 79,300 | 221–246 MB | **192 MB** |
| `pytest` (738 tests) | — | 324–332 MB | **384 MB** |
| CTU-13 scenario 6 | 1.6M | 525–542 MB | **512 MB** |
| CTU-13 scenario 3 | 10.2M | 2,077–2,133 MB | **2.0 GB** |
| Detection + Qwen2.5-1.5B q4\_k\_m | 74,157 | 2,072 MB | ~2.5 GB |

The first two rows were re-measured after the analyzer count doubled; the
demo capture itself grew from 74,157 records to 79,300 when `ssl.log` and
`sysmon.jsonl` were added to it, which is why the earlier figures read low on
records and high on ceiling. The two CTU-13 rows were re-measured on 7–8
October 2026, after the NetFlow parser was corrected — the correction at the
top of [`benchmarks.md`](benchmarks.md) says what was wrong — and the earlier
figures, 768 MB and 2.6 GB, were measured on misparsed rows. The model row is
carried forward from the smaller demo capture it was measured on.

A ceiling below the peak is not a contradiction. `voidai demo` completes at
192 MB and at 224 MB, but at both the reported peak *equals the ceiling
exactly*: the kernel is reclaiming page cache to keep the process under the
limit, and the number stops describing the working set. Only from 256 MB does
the peak float free at ~240 MB, which is the real figure. Below 192 MB it is
OOM-killed on every run. Scenario 6 at 512 MB and scenario 3 at 2,000 MB
behave the same way. Take the floor as the point of failure and the peak as
the requirement — they answer different questions.

**Where the 66-hour capture actually breaks**, bisected against a hard ceiling
on the corrected parse, all eight analyzers:

| Ceiling | Outcome |
|---|---|
| 1,600–1,800 MB | OOM-killed |
| 2,000 MB | completes, pinned at the ceiling — running at the wall |
| 2,200 MB | completes, peak 2,097 MB |
| 2,400 MB | completes, peak 2,103 MB |
| 2,600 MB | completes, peak 2,077 MB |
| 3,696 MB (4GB board less 400 MB for the OS) | completes, peak 2,133 MB |

Every run that completes ranks the infected host second of 275, the
unconstrained result. The run at 2,000 MB is the useful one: it is what
"running at the wall" looks like, and it is why the recommendation is not the
bare floor. **2.4 GB of free memory is the recommendation** — the capture
completes with room from 2.2 GB and is killed by 1.8 GB — and a 4GB Pi 5
clears it, peaking at 2.1 GB with about 1.5 GB to spare.

Two earlier bisections put the boundary in a 2.4–2.6 GB band, a ceiling the
capture now clears with room. Both were measured on the misparsed rows, which
analysed 12.7M flows rather than 10.2M with 41% of the capture misread, so
their absolute numbers are superseded. The comparison between them still
stands, because both sides were measured the same way: doubling the analyzer
count from four to eight did not raise the floor. That is rule 2 — peak memory
is set by the hungriest analyzer, not by how many there are.

Windowing is still what a real deployment does — hourly or daily batches, not
three days of telemetry at once — but it is now a convenience, not a
requirement:

```bash
for log in /var/log/zeek/*/conn.*.log.gz; do voidai run "$(dirname "$log")"; done
```

### CPU — a curve, because a quota is not a Cortex-A76

The same harness caps CPU with a CFS quota. A quota can make a core slower but
cannot give it a different microarchitecture, so no single setting *is* a Pi.
What it produces instead is a scaling curve that real hardware can be located
on with one run. Measured on CTU-13 scenario 6, 1.6M flows on the corrected
parse, memory unconstrained; detection time is the receipt's, excluding start-up
and the ground-truth pass:

| CPU quota | Detection | Throughput |
|---|---|---|
| 400% (4 cores) | 15.3 s | 105k rec/s |
| 300% | 19.1 s | 84k rec/s |
| 200% | 27.3 s | 59k rec/s |
| 100% (1 core) | 50.3 s | 32k rec/s |
| 50% | 109.1 s | 15k rec/s |

Four cores return 3.3× the throughput of one, so the pipeline parallelises at
about 82% efficiency. Every row ranks the infected host first of 176. The
curve measured on the misparsed rows showed two to three times this
throughput, partly because the parser now normalises every line before
splitting it, and partly because 14% of the rows had collapsed onto one false
destination and cost almost nothing to analyse.

The load-bearing result is the combined envelope. The 10.2M-flow capture, held
to 3 GB and a *single* core, completes in about **six minutes** — 330 s of
detection at 31k records per second — and returns the infected host at
**queue rank 2 of 275, identical to the unconstrained run**. Constraining the
board changes how long the answer takes, not what the answer is:

| Envelope | Wall | Infected host |
|---|---|---|
| Unconstrained — four cores, no ceiling | 102 s | rank 2 of 275 |
| 3,696 MB (4GB board), four cores | 99 s | rank 2 of 275 |
| 2,000 MB, at the wall | 101 s | rank 2 of 275 |
| 3,000 MB, one core (two runs) | 368–379 s | rank 2 of 275 |

Wall is the whole command, including the separate pass that reads ground
truth. The runs this table replaces were measured on the misparsed rows, with
two analyzers, at 166 s on one core.

### What this harness does not prove

It runs on x86-64. **It is not an ARM test.** aarch64 has different wheels,
128-bit NEON rather than 256-bit AVX2, and a different allocator profile.
Memory ceilings and core counts are reproduced by the kernel's own accounting
and are therefore evidence; the instruction set is not reproduced at all, and
anything that would only fail on ARM passes here. The architecture question
stays open until it runs on the board.

### Getting *measured* energy

The Pi 5 has no on-board power telemetry, so out of the box VoidLexicon reports
`estimated` from a published power profile. To get a real number, put a
current-sense breakout on the 5V rail. An INA219 or INA260 is the usual
choice and costs a few pounds.

```bash
sudo raspi-config nonint do_i2c 0          # enable I2C
sudo modprobe ina2xx
echo ina219 0x40 | sudo tee /sys/bus/i2c/devices/i2c-1/new_device
```

That creates an hwmon device exposing `power1_input` in microwatts.
`voidai doctor` should then report `measured`, and every receipt switches from
`estimated` to `measured` automatically — VoidLexicon discovers hwmon power rails
without configuration.

Verify by hand first:

```bash
cat /sys/class/hwmon/hwmon*/power1_input     # microwatts
```

Without a shunt the figures remain honest but indicative, and are labelled as
such everywhere they appear.

---

## NVIDIA Jetson (Orin Nano / NX / AGX)

Jetson modules expose INA3221 rails through hwmon already, so energy is
**measured** with no extra hardware. `voidai doctor` will confirm it.

Detection is CPU-only and does not use CUDA. Building
`llama-cpp-python` with CUDA support is possible and will speed up the
narrative layer considerably, but is not required and is not the tier this
project argues for.

---

## x86_64

Intel and AMD expose RAPL energy counters through `powercap`. Since
CVE-2020-8694 these are root-readable only on most distributions:

```bash
sudo chmod -R a+r /sys/class/powercap/intel-rapl
```

Do that and VoidLexicon reports `measured` on ordinary hardware. Note that RAPL
covers the CPU package, not the whole board — it understates system draw,
which is the safe direction for a project claiming efficiency.

Many virtual machines and containers expose no counters at all. This is the
case in CI, where every figure is correctly labelled `estimated`.

---

## Running against real telemetry

```bash
voidai run /var/log/zeek/current/          # Zeek conn.log and dns.log
voidai run ./capture/ --evidence           # with the full chain of custody
voidai run ./capture/ --model models/qwen2.5-1.5b-instruct-q4_k_m.gguf
```

Supported inputs — everything `voidai run` reads from the directory it is
given:

| Source | Files | Analyzers fed |
|---|---|---|
| Zeek `conn.log` | TSV or JSON, rotated `.gz` accepted | beaconing, fan-out, volume and egress |
| Zeek `dns.log`, or passivedns | `dns.log`, else `*.passivedns` | DNS tunnelling, DGA |
| Zeek `ssl.log` | JA3 fingerprints need Zeek's JA3 package | TLS fingerprint rarity |
| Suricata EVE | `eve*.json`, `*.eve.json`, `alerts*.json` | alert triage |
| Sysmon process events | `sysmon*.json[l]`, `*.sysmon.json[l]`, `.gz` accepted | host |
| Threat intel | `*.ioc`, or `--intel <path>` | threat intel |
| Asset inventory | `*.inv`, or `--inventory <path>` | joins addresses to hostnames |

Labelled NetFlow in the CTU-13 dialect is read by `voidai bench --real`, for
scoring against ground truth, and not by `voidai run`.

VoidLexicon reads logs. It does not capture traffic, and needs no privileged
network access — point it at a sensor's output directory.

## Operating notes

**No network access is required or used.** VoidLexicon runs with the interface
down; the test suite severs sockets and asserts the pipeline still completes.
There are no update checks, no telemetry, and no runtime model downloads.

**It cannot act.** There is no code path that blocks an address, kills a
process or edits a rule. Recommendations are text. This is enforced by
absence, not by a configuration flag.

**Nothing needs root** except reading energy counters. Detection runs
unprivileged.

## Sizing

Measured on x86_64, 4 cores, on the corrected parse. ARM will be slower per
core; the shape holds.

| Capture | Flows | Detection | Peak RSS |
|---|---|---|---|
| 2 hours | 1.6M | 15 s | 0.6 GB |
| 66 hours | 10.2M | 89 s | 2.7 GB |

Detection runs at roughly 105,000–115,000 records/second on labelled NetFlow,
and about 160,000 on the demo's Zeek logs. The narrative layer adds
about 30 seconds per incident narrated on a 1.5B model at 4-bit — it is
metered separately on the receipt for that reason, and `--explain N` bounds
how many incidents are narrated.
