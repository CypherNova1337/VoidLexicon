# Engineering rules

Thirteen constraints the detection code is written against. None of them is a
style preference and none was decided in advance — each one is a bug that
happened in this repository, generalised so it cannot happen again in a
different place.

They are cited by name from the code that obeys them, because a rule recorded
only in a document is a rule that gets rediscovered the expensive way. Where a
rule names a measurement, that measurement is in
[`benchmarks.md`](benchmarks.md).

---

**1 · Add analyzers, never a second tool.** A new analyzer is one file in
`src/voidai/analyzers/` plus one line in `DEFAULT_ANALYZERS`. It then inherits the
Lexicon, chain of custody, correlation, ranking, run receipt, hunt-query generation,
CLI and language layer unchanged. A separate tool inherits none of it and has to be
merged later.

**2 · Peak memory is `max(analyzers)`, not `sum(analyzers)`.** Measured: the four
existing analyzers run together peak at 521 MB, against 1,035 MB if it were
additive, because they run sequentially and release. Adding analyzers is therefore
close to free on the constraint that decides whether this runs on a Pi. That holds
only while each analyzer individually behaves — see rule 3.

**3 · Two passes, always.** Pass one computes scalars per group and stays streaming.
Pass two collects full arrays for candidates only, via a semi-join. Copy
`_pair_summary` and `_collect_series` from `beaconing.py`. An analyzer that
materialises a capture will be the one that breaks the 4 GB board.

**4 · Cap what you emit.** `max_findings` exists on every analyzer for a reason.
Findings from all analyzers accumulate into one list, and a low-severity predicate
over a large estate can emit thousands. The project exists to *prevent* alert
floods; do not add one.

**5 · Weighted geometric mean, never an average.** An average lets one strong
signal carry a detection alone — that is how a software updater gets reported as
C2. Absent components renormalise the remaining weights.

**6 · A claim is bounded by what was measured, not by what the survivors
score.** Three separate bugs here came from partial evidence producing a
whole-strength assertion. It applies at three levels, and getting one right
does not get the others right.

*The component.* If a field is unavailable, omit it and let the weights
renormalise. Never substitute a value — not zero, not a midpoint, not the
value that happens to reproduce the right answer.

*The predicate.* If the signal that defines a verb is unavailable, that verb
is unsayable. `exfiltrates_to` means "anomalous outbound volume"; with no
directional bytes, emit `transfers_anomalous_volume`, which claims only what
was seen.

*The corroboration.* A finding resting on partial evidence may be reported,
but must not count as an independent behaviour. Put it in
`CorrelationConfig.non_corroborating`. Measured on CTU-13: letting a
direction-blind volume finding corroborate moved the infected host from rank 2
to rank 5 and took corroborated incidents from 3 to 33, while contributing no
evidence on the true positive at all.

**7 · Say which half of your validation is synthetic.** Synthetic data validates
your assumptions, not your detector — you built both from the same beliefs. If only
specificity is measured on real traffic, the docs say exactly that, in the same
sentence as the result.

**8 · Test the intent, not the implementation.** After writing a regression test,
break the fix and confirm the test fails. There was a test here named
`test_all_zero_values_are_not_treated_as_regular` that asserted the exact opposite
of its own name and guarded nothing for weeks.

**9 · No new core dependency.** Six, no compiler, every one has an `aarch64` wheel.
Anything needing a dissector or a build step goes behind an extra, like `[llm]` and
`[tui]` already do.

**10 · No execution path.** VoidLexicon proposes; a human disposes. Never add code that
blocks an address, kills a process or edits a rule. Enforced by absence.

**11 · No network at runtime.** Not for intel feeds, not for enrichment, not for
model downloads. The test suite severs sockets and asserts the pipeline still
completes.

**12 · A top-N over equal scores needs a total order.** Ranking, capping and
sampling all pick a few items out of many, and ties are not rare — a generated
domain family produces hundreds of names scoring an identical 1.0. With no
tiebreaker, `group_by` ordering decides which ones are reported, so two runs
over one capture return different findings and therefore different
content-addressed IDs. Reproducibility is a promise this project makes on its
front page: citations in last month's report still resolve. Sort by score *and*
by a stable key — the subject and object values will do — everywhere a limit is
applied.

Printing the findings twice and diffing finds it, but weakly: the same input in
the same order can hide an ordering that depends on the input. Shuffle the row
order of the input frame and assert the output is identical — that is what
catches a `group_by` whose result order leaks into a top-N.

**13 · Say why a row is in the queue.** Every incident the operator sees must
name what put it there. Five predicates no longer corroborate, and a display
built only from corroborating ones printed a severity, a priority and a blank
reason for any incident made entirely of the rest. An analyst cannot triage a
row that will not say why it exists.
