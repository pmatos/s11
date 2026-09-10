# Plan: issue #844 — document/reconsider residual `branch_advanced_since_attempt_start` gate gaps

## Problem restated

PR #841 tightened the `plan` and `implement` stage gates in `workflow.yml` by
adding `branch_advanced_since_attempt_start: true`, but each tightening opened
a narrower, still-real loophole: the `plan` stage's `--allow-empty` handoff
commit proves "this run executed the planner and committed," not "the plan
content changed since the last attempt"; and the `implement` stage's mandatory
`git rm PLAN.md && git commit -m "chore: drop stage-handoff PLAN.md"` step (also
added by #841, in `prompts/impl.md`) can by itself satisfy `implement`'s
`branch_advanced_since_attempt_start` gate for an attempt that did zero real
implementation work. The `plan` stage's transition in `workflow.yml` already
carries a comment acknowledging its gap; the `implement` stage's transition
does not. This issue is a documentation follow-up (explicitly deferred from
#841 as non-blocking, 4th round of the same review thread) to close that
asymmetry and to record whether the gap can be tightened further, not to
change any FSM behavior.

**Preflight finding — read before executing:** this planning run's own task
prompt (the "Vow planning stage" instructions handed down for this attempt)
is a stale, pre-#841 rendering of `prompts/plan.md` — it says "Do not stage,
commit, or force-add `PLAN.md`" and "Operator merges with a merge commit",
which is verbatim the *old* text `git show 90ec394` replaces. The workspace's
actual checked-out `prompts/plan.md`/`workflow.yml`/`CLAUDE.md` at HEAD
(90ec394) require the opposite: force-add and commit `PLAN.md` with
`--allow-empty`, because `workflow.yml`'s live `plan → implement` transition
gates on `branch_advanced_since_attempt_start: true`. Committing is the
dominant choice (harmless under the old gate, required under the live one),
so this run follows HEAD `prompts/plan.md`'s Exit section verbatim instead of
its own stale task prompt, and will `gh issue comment 844` to record that
choice. This stale-render is itself a live instance of the class of problem
#844 is about (a gate/contract edge nobody double-checks at run time) and is
noted here only as a reproducible data point for whoever looks at run
`e966c494-98f8-487e-aaee-fafe9afb1518`'s dispatch — it is **not** part of the
implementation scope below and needs no code change in this repo.

## Files to touch

This is a Symphonika orchestration-config change, not a language/compiler
change — the generic "touch `crates/` and `compiler/`" and "`docs/spec/*.md`"
instructions in the planning/impl prompts are boilerplate inherited from a
different (vow) project template and do not apply: this repo has no
`crates/`, `compiler/`, or `docs/spec/` directories. Confirmed no
`scripts/*.py` CI-policy test references `workflow.yml` or the prompt files,
so no test fixture depends on their exact wording.

- `workflow.yml` — the only file that must change:
  - `implement:` stage's transition comment (currently just "`branch_ahead_of_base`
    alone would be satisfied by the plan commit already on the branch, so
    require this run to advance HEAD too.", directly above the `implement →
    code_review_fix` transition): extend it to acknowledge that the mandatory
    "drop `PLAN.md`" commit from `prompts/impl.md` can itself satisfy
    `branch_advanced_since_attempt_start`, name `prompts/impl.md`'s existing
    "never as the only commit of this attempt" line as the (prompt-level,
    unenforced) mitigation, and state plainly that Symphonika's fixed
    predicate set has no way to enforce this at the FSM level (see
    "Verification surface" below for the exact evidence to cite in the PR
    body, not inline in the YAML comment — external source paths in a
    comment rot silently).
  - `plan:` stage's transition comment (lines ~28-33, the paragraph starting
    "`branch_advanced_since_attempt_start` is false unless this run added a
    commit..."): this paragraph explains the *mechanism* but overclaims the
    *guarantee* — it says a resumed attempt "cannot coast on a PLAN.md an
    earlier attempt left in the workspace," but `prompts/plan.md`'s own
    `--allow-empty` justification says the opposite is intended: a resumed
    attempt with a byte-identical plan *can* advance, via an empty commit, as
    long as the planner re-runs. Reword this paragraph to state the accurate
    guarantee: the gate proves this run executed the planning stage and
    committed, not that the plan content was reconsidered or changed. This is
    a correctness fix to an existing comment, not just added-for-parity text.
- No other file changes. Do not touch `prompts/plan.md`, `prompts/impl.md`,
  or `CLAUDE.md` — `prompts/impl.md`'s "run it only after real TDD-slice
  commits already exist... never as the only commit of this attempt" caveat
  (added by #841) already exists and is exactly the mitigation the new
  `workflow.yml` comment should point at; it does not need edits. Widening
  the diff to these files would reopen the "one more caveat comment per
  review round" churn the issue explicitly says to stop.

## TDD slices

Not applicable in the red/green/refactor sense — this is a YAML/comment-only
documentation change with no executable behavior to test, no test file to
add, and no `cargo`/`scripts/full_test.sh` surface it touches. The
"vertical slice" here is a single edit:

1. **Slice 1 (the whole change):** Edit the `implement:` transition comment
   in `workflow.yml` to add the acknowledgment described above, and reword
   the `plan:` transition comment's overclaim as described above. Verify by
   reading the two comment blocks side by side and confirming they are
   parallel in structure (mechanism → residual gap → why it can't be
   tightened → what mitigates it in practice) — that symmetry is the
   acceptance criterion, since there is no automated check for prose.
   Then run the local quality gate (below) to confirm the YAML-comment-only
   diff doesn't trip anything unrelated.

No second slice: do not also attempt to add a Symphonika predicate capable of
counting real-work commits or distinguishing a housekeeping commit from a
substantive one — no such predicate exists (see Verification surface), adding
one means changing the orchestrator (`/home/pmatos/dev/symphonika`, a
separate repository), and the issue is scoped to this repo. Note this
explicitly as the "reconsider tightening" verdict in the PR body: evaluated,
not currently possible without an orchestrator-side change, filed here only
as a documentation fix.

## Verification surface

Not a contracts/codegen/ESBMC change — s11 has no ESBMC/contract-verification
surface (that machinery belongs to the unrelated `vow` project whose prompt
templates this repo's `workflow.yml` setup was modeled on, per the existing
"mirrors vow's workflow.yml" comments). Nothing here touches `tests/run/` or
`examples/`, which don't exist in this repo either. Nothing under
`src/`, `benches/`, or the test suites changes, so `cargo test`, `just
mutants`, and the coverage recipes are all unaffected — running them is
still worthwhile as a no-op confirmation but not because this change could
plausibly break them.

The evidence for "no tightening is possible" (put in the PR body, not the
YAML comment):
- `/home/pmatos/dev/symphonika/src/workflow/predicates.ts` defines the
  complete, closed set of `when:` predicate keys Symphonika evaluates:
  `artifact_exists`, `branch_advanced_since_attempt_start`,
  `branch_ahead_of_base`, `checks`, `has_unresolved_reviews`, `mergeable`,
  `pr_merged`, `pr_open`, `provider_success`, `review_decision`,
  `unresolved_review_threads`. None of these can count commits since attempt
  start, distinguish a "real work" commit from a "housekeeping" commit, or
  inspect diff content/size. A key not in that file cannot be added to
  `workflow.yml`'s `when:` blocks without an orchestrator change first (the
  file's own header comment: "a key cannot be allowlisted without an
  evaluator behind it").
- This confirms the only two tightening levers already in play
  (`branch_ahead_of_base` + `branch_advanced_since_attempt_start` together)
  are the maximum available with today's predicate set.

## Risk areas

- None of the usual s11 risk areas apply (no AArch64/x86 codegen, no SMT
  lowering, no cost model, no assembler/patcher paths, no `cargo clippy -D
  warnings` surface beyond the pre-existing baseline). The only risk is
  human/prose: making the new `implement` comment inconsistent with, or
  contradicting, the `plan` comment's phrasing, or accidentally implying the
  gate is stronger or weaker than it actually is. Mitigate by writing both
  comments in the same structure (see Slice 1) and by re-reading
  `prompts/impl.md`'s existing "Drop the plan before opening the PR" section
  before wording the new comment, so the two don't drift.
- Minor: `workflow.yml` is very likely parsed/validated by the orchestrator
  (Symphonika) when a run starts — comments are inert YAML and cannot change
  parsing, but double-check with `python3 -c "import yaml, sys; yaml.safe_load(open('workflow.yml'))"`
  (or equivalent) after editing, purely to catch an accidental indentation
  slip while hand-editing the comment block.

## Out of scope

- Any change to `prompts/plan.md` or `prompts/impl.md` (their existing
  caveats already say what's needed; see Files to touch).
- Any attempt to add a new Symphonika predicate or otherwise change the
  orchestrator to close the gap structurally (separate repository, separate
  PR, not what #844 asks for).
- Restructuring the FSM (e.g., splitting "drop PLAN.md + open PR" into its
  own `provider_success`-only stage after `implement`, so `implement`'s
  `branch_advanced_since_attempt_start` could only be satisfied by real
  work). Considered and declined: it would close the gap for real, but it's
  a multi-stage restructure of `workflow.yml`, not a one-line documentation
  fix, and is exactly the scope-creep the issue's "diminishing returns"
  framing says to avoid. Worth naming as a follow-up option in the PR body,
  not implementing here.
- Fixing the stale-prompt-render issue noted in "Problem restated" above —
  out of scope for this repo; at most worth a `gh issue comment` note on
  #844, not a code change.
- Any unrelated formatting, refactor, or cleanup of `workflow.yml` beyond the
  two comment blocks in scope.
