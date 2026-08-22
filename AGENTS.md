# gspwn Orchestrator Contract

You are the orchestrator of an agentic fuzzing workflow targeting the NVIDIA
GPU kernel driver (Track K) and NVIDIA Container Toolkit (Track U).

## Ground rules

- All state lives in `state/pipeline.json` and `artifacts/`. Never hold
  pipeline state in conversation.
- The orchestrator coordinates and does no phase work. Dispatch one subagent
  per phase using the prompt file in `agents/<phase>.md`.
- Subagents reason, tools act. Phase work goes through `tools/*.py` /
  `tools/*.sh`, never hand-typed command sequences.
- All state changes go through `tools/pipeline_ctl.py`. Never hand-edit
  `state/pipeline.json`. The tool validates, locks, and writes atomically,
  and parallel subagents will otherwise lose each other's updates.
- Phases run in dependency order (below). `describe`, `seeds`, `harness` may
  run in parallel with each other after `build`.
- After any interruption (session restart, kernel panic, reboot, or a context
  compaction):
  1. `sudo python3 tools/crashlog_ctl.py harvest`
  2. `python3 tools/pipeline_ctl.py brief`
  3. resume at the phase it reports

  That sequence needs no memory of the previous session. The state file is
  the orchestrator's memory, and `brief` renders it: where the pipeline is,
  what is blocked, what the crash registry holds, what the findings say to
  target, and the tail of `knowledge/`. It is derived at read time, so it
  cannot be stale. A copy of it goes out of date the moment the pipeline
  moves, so re-run it and do not trust a handed-over copy. When
  `gspwn-orchestrator.service` is installed it performs steps 1 and 2 and
  launches an agent, so this sequence runs without a human. See
  `tools/orchestrator_ctl.py`.
- Record each learning as it happens. `knowledge/learnings.md` and
  `knowledge/mistakes.md` are committed and outlive the box, the campaign and
  this session. They are the only thing a rebuilt machine starts with. Append
  through `tools/knowledge_ctl.py note`, never by hand, and never at the end
  of a round from memory, because by then the detail that mattered is gone.
  A learning is about the target, and a mistake is about us. Both are read by
  the next agent doing this job, so generalise. It will not have this
  session's context.

## Configuration

Every cap, budget, duration and threshold that changes what the campaign does
or concludes lives in `config/campaign.yaml`, including the ones that decide
research outcomes: the plateau rule, the dedup depths, and what counts as a
reliable reproduction. No further input is required once these are set. What
values still fixed in code are limited to internal safety floors, which are
not decisions about the target. Before the first campaign, confirm what actually
took effect:

```
python3 tools/gspwn_config.py
```

It prints the effective configuration and the resulting stopping rules, and
exits non-zero on a bad value. An unknown key is an error, so a misspelled key
fails loudly and does not leave the default in force. If it exits non-zero,
stop and report. Do not proceed on defaults.

The loop's primary termination is completion, `exercised + accounted-for =
764`, which is measured and not configured. Three declared stopping rules bound
an unattended run that does not converge: `loop.max_total_run_hours`,
`loop.max_rounds` (a backstop, default 10, and a campaign reaching it has
failed to converge), and `loop.campaign_hours` (each campaign
self-stops after this long). They bound the search duration. Spend is not
bounded by them, because this repo has no view of what the instance costs and
does not guess. Watch real money in the AWS console.

Run-hours are recorded in `state/spend.json`, a ledger keyed by run id. It is
machine-global on purpose. It does not follow `GSPWN_STATE` as
`pipeline.json` does, so a run with its own state file still counts against
the one cap. If the ledger goes missing while rounds still record hours, every
command that reads it refuses, and none of them treats the cap as untouched.
Clear that with `pipeline_ctl.py spend-init`, which rebuilds the ledger from
the state file and never lowers recorded hours.

## State commands

| Need | Command |
|---|---|
| Create the state file (once, provision) | `python3 tools/pipeline_ctl.py init` |
| Recover after a panic or a compaction | `python3 tools/pipeline_ctl.py brief` |
| See where the pipeline stands | `python3 tools/pipeline_ctl.py show` |
| Which phase to run next | `python3 tools/pipeline_ctl.py next` |
| Advance / block a phase | `python3 tools/pipeline_ctl.py set-phase <phase> <status> --notes "..."` |
| Inspect the crash registry | `python3 tools/pipeline_ctl.py crash-list [--status S] [--track K\|U]` |
| Fix a triage decision | `python3 tools/pipeline_ctl.py crash-set <id> --duplicate-of <id>` |
| Record disclosure status | `python3 tools/pipeline_ctl.py crash-set <id> --disclosure pending` |
| Attach rca's research record | `python3 tools/pipeline_ctl.py finding-set <id> --json -` |
| What the findings say to target | `python3 tools/pipeline_ctl.py finding-list` |
| Attach rca's impact record | `python3 tools/pipeline_ctl.py impact-set <id> --json -` |
| What the report can argue | `python3 tools/pipeline_ctl.py impact-list` |
| Check registry integrity | `python3 tools/pipeline_ctl.py validate` |
| Record a fact about the target | `python3 tools/knowledge_ctl.py note --kind learning --phase <p> "..."` |
| Record a process error to avoid | `python3 tools/knowledge_ctl.py note --kind mistake --phase <p> "..."` |
| Read the knowledge files | `python3 tools/knowledge_ctl.py show [--kind K] [--phase P]` |
| Round history + loop budget | `python3 tools/pipeline_ctl.py round-show` |
| Rebuild a lost spend ledger | `python3 tools/pipeline_ctl.py spend-init` |
| Attach a run to this round | `python3 tools/pipeline_ctl.py round-add-run --run-id <id>` |
| This round's input worklist | `python3 tools/pipeline_ctl.py worklist` |
| Round 1's input worklist (patch history) | read `surface/worklist-round1.md`, which is committed. Regenerate with `python3 tools/cve_patch_map.py worklist` only after a driver-version change |
| Surface coverage, three-stage | `python3 tools/surface_cov.py report --run-id <run-id>` |
| Whether the surface is accounted for | `python3 tools/coverage_ctl.py completion --run-id <run-id>` |
| Record a reason against an unreachable target | `python3 tools/pipeline_ctl.py surface-account --json -` |
| Undo an accounting written in error | `python3 tools/pipeline_ctl.py surface-unaccount --variant <name>` (`--key <key>` for a row whose target no inventory holds) |
| Read the completion ledger | `python3 tools/pipeline_ctl.py surface-ledger` |
| Add the surface column to a run that predates it | `sudo python3 tools/coverage_ctl.py migrate-csv --run-id <run-id>`, with the sampler timer stopped, because it rewrites the CSV |
| Close a round | `python3 tools/pipeline_ctl.py round-end --from-run <run-id> [--from-run ...]` (measures the outcome) |
| Continue or stop the loop | `python3 tools/pipeline_ctl.py round-decide` |
| Open the next round | `python3 tools/pipeline_ctl.py round-advance` |

Phase statuses: `pending`, `in_progress`, `done`, `blocked`, `failed`. Mark a
phase `in_progress` on dispatch, and `done` only once the gate evidence has
been seen directly. Never mark it done on the subagent's assertion alone.

Before trusting the tools after any change to them, run
`python3 tools/selftest.py` (offline, no hardware needed). After editing
`tools/ioctl_map.json` or regenerating `descriptions/`, run
`python3 tools/regression_check.py all`, which is the local form of the five
artefact checks CI runs: `coverage`, `names`, `pins`, `derived` and `pages`.
`derived` catches a regeneration that stopped before `object_graph.py chains`
or `ctrl_rank.py rank`, and `pages` catches one that stopped before
`tools/refgen.py`. `agents/describe.md` step 1 carries the regeneration
sequence that satisfies all five, and it is the authority on the order.

## Phase order and gates

Advance only when the gate holds. On gate failure, consult the phase's
agent file error-handling section. After one agent retry, run
`python3 tools/pipeline_ctl.py set-phase <phase> blocked --notes "<why>"`
and stop. A blocked phase is a stopping point. Do not skip ahead to a later
phase to keep making progress.

| Phase | Agent file | Gate to advance |
|---|---|---|
| provision | agents/provision.md | the gate section of `agents/provision.md` holds this phase's full evidence list, and it is the authority. The main items are manifest.json written, `crashlog_ctl.py verify` prints READY, the test panic harvested, a clean `orchestrator_ctl.py preflight`, and a `surface_verify.py check --no-running` verdict. A failing preflight is a blocked gate, and so is exit 3 or exit 4 from that check |
| build | agents/build.md | booted into the instrumented kernel, KASAN state matches the rung in manifest, and `nvidia-smi` works |
| describe | agents/describe.md | `surface_verify.py check` exits 0, meaning two or more version sources agree; Syzlang compiles; smoke run reaches driver (dmesg evidence); `regression_check.py pins` exits 0 and the `NV_ESC_IOCTL_XFER_CMD` `cmd` constraint set is quoted; `surface_cov.py modelled` still reports 764/764, which is a regression check and not evidence of work done; `surface_cov.py gaps --stage corpus` names fewer targets with `--run-id <smoke run id>` than it does over `artifacts/seeds`, which is the round's starting position, and that delta is the phase's measured output; audit sample logged. Where the phase regenerated the surface artefacts, `regression_check.py all` exits 0 over all five checks and the reference pages are committed with them |
| seeds | agents/seeds.md | `artifacts/seeds/chain-*.syz` exist, `trace2seed.py chains` exits 0, and its account line is reported with all three of its numbers: commands emitted, commands dropped before emission, commands with no chain. The three close on the whole control surface and no round emits all 531, because 17 reach no chain by construction, so this clause is a regression check on the artefacts and not evidence of work done. Also: every syscall name in the seed bank is declared by a description (`regression_check.py names` exits 0); seeds parse under syz-manager; the per-item report names for every `[finding ...]`, `[history ...]` and `[surface]` item whether a seed establishes its precondition |
| harness | agents/harness.md | Track U harnesses build and produce coverage under `artifacts/runs/<id>/u/<harness>/`, `harnesses/TARGETS.md` lists every harness with its reachability justification and its `{input}` replay command, `track_u.targets` in `config/campaign.yaml` names every harness directory, and `run_all.sh` runs `replay_crashes.sh` at harvest. A harness that failed to build is named with the number of inputs its failure leaves unreplayed |
| fuzz | agents/fuzz.md | both systemd units active and coverage increases within the smoke window, then the campaign window has elapsed (`campaign_ctl.py wait --run-id <id>`). The smoke window only says the campaign started. Everything after this phase measures the run, so advancing on the smoke window measures the first half hour of a 24-hour campaign |
| triage | agents/triage.md | every raw crash registered unique/duplicate/flagged, and the flagged queue is empty (`crash-list --status flagged` returns nothing). For Track U, the `replay_crashes.sh` summary line beside the registry count, because a raw input registers nothing until the replay writes its `.sanlog`, and zero registered crashes over zero replayed inputs is an unrun replay. The replayed-and-clean count is reported separately as a verdict |
| rca | agents/rca.md | `artifacts/rca/<id>.md` complete for every unique crash selected for PoC, with its count of `[UNVERIFIED]` claims, because the eval phase samples from exactly that set; each also has a research record (`finding-list`), which steers the next round, and an impact record (`impact-list`), which lets the report argue a severity |
| poc | agents/poc.md | every unique crash has repro rate + classification in pipeline.json, the PoC README paths are named, and every reliable/flaky Track K crash has a recorded profile-check outcome |
| eval | agents/eval.md | the gate section of `agents/eval.md` holds this phase's full evidence list, and it is the authority. The main items are `artifacts/eval/` holding the coverage series, findings table, round progression, rca-audit.md and version-persistence.md (an explicit `skipped: <why>` counts) for every run in this round; the three-stage surface report with the corpus path it was measured against; the completion counts with their exit status; and a statement of whether the completion claim was made and which of its six evidence items was missing where it was not |
| refine | agents/refine.md | the gate section of `agents/refine.md` holds this phase's full evidence list, and it is the authority. The main items are gaps.md + worklist.md written, every item tagged `[surface]`, `[finding crash-NNNN]` or `[history CVE-YYYY-NNNNN]`; round outcome recorded via `round-end`; every target the round will not reach accounted for via `surface-account` |
| report | agents/report.md | report + PSIRT packages exist, and disclosure status is recorded |

## The improvement loop

`provision` and `build` run once for the machine,
`describe` through `refine` run once per round, and `report` runs once after
the loop stops.

```
provision → build → ┌─ describe / seeds / harness → fuzz → triage
                    │        ↑                              ↓
                    │        └── refine ← eval ← poc ← rca ──┘
                    │              │
                    └── continue ──┘   (stop) → report
```

Each round: fuzz a fresh or carried corpus, triage what it found, measure
coverage on both tracks, then `refine` writes
`artifacts/eval/<run-id>/worklist.md` and records it with
`round-end --worklist <path>`. `round-advance` carries that path into the new
round, where `describe` and `seeds` read it back with `pipeline_ctl.py
worklist`.

Three signals steer the next round, and they are not interchangeable.
Surface names the commands nothing has reached: `tools/surface_cov.py gaps`
lists them against the driver's own enumerated 764, and it is the primary
unexplored-surface signal because it is the only one that names a call. The
edge curve `refine` derives from the run says whether the fuzzer is still
finding new code inside the calls it already makes. It steers the stop
decision and the holes inside commands already reached, and it names no call,
so it carries no worklist tag. Findings say where the bugs *have been*: `rca`
records a research record per analysed crash
(`finding-set`), naming the subsystem, the bug class, the calls involved, the
state they needed, and the adjacent calls that share the same object, lock or
teardown path. History says where NVIDIA has already shipped a kernel-mode fix:
`tools/cve_patch_map.py worklist` classifies 61 kernel-mode CVEs, resolves 53
of them to a release tag pair, and ranks 270 changed functions, 27 of which
reach a named ioctl target. History is the only one of the three available
before a campaign has run, so it steers round 1, which previously had only the
structural priority order in describe step 4. A history item ranks a place
where the vendor found a bug, and it is not evidence that a bug remains there.
`refine` merges all
three into one worklist with every item tagged `[surface]`,
`[finding crash-NNNN]` or `[history CVE-YYYY-NNNNN]`.

History items decay, and the other two do not. A `[history ...]` item is
carried into the next round only while it is still unmodelled or unexercised,
which `python3 tools/surface_cov.py gaps --run-id <run-id>` answers
mechanically: `--stage model` for unmodelled, `--stage corpus` for unexercised.
Once an item is modelled and the corpus exercises it, it is spent and drops
out, whether or not it produced a finding, and an item that produced one
re-enters under its own `[finding crash-NNNN]` tag. Without the rule the same
items reappear in every round for the life of the campaign. The refine gate
asks for the dropped items by name, and this rule settles whether that list is
right.

Without the second signal the loop only ever widens the surface and never
returns to a place that already yielded. An `rca_done` crash with no research
record is an integrity problem `validate` reports for exactly that reason,
because the analysis happened and nothing was recorded from it.

The loop reads two curves and one ledger. The edge curve says whether the
fuzzer is still finding code. The surface curve says whether it is still
reaching commands it had not reached, over a denominator the driver enumerates
itself. The completion ledger says which of the remaining targets carry a
written reason.

| Edge curve | Surface curve | Ledger | Reading |
|---|---|---|---|
| flat | climbing | any | Not a plateau, because the round is still reaching new commands |
| flat | flat | open | The corpus is stuck on a resource-chain problem, and the campaign is unfinished |
| flat | flat | closed | Complete, and nothing is left to fuzz |

Completion is `exercised + accounted-for = 764` and no percentage threshold
decides it. It is the campaign's primary termination and it sits in the hard
non-overridable set alongside the run-hour budget, because a campaign with
nothing left to fuzz has no work an override could authorise.

`loop.max_rounds` is a backstop against a runaway loop and no longer the
expected termination. A campaign that reaches it has failed to converge, and
`round-decide` says so in the stop reason. The default is 10.

The per-subsystem rollup in `finding-list` measures where the loop has been
paying off.

A reproducer is not yet a vulnerability. It proves a crash condition, which is
a bug report. The weakness class and what the fault hands an attacker make it
a vulnerability, and those have two halves recorded by two phases. `rca`
records the impact record (`impact-set`): the primitive, which field the
corruption lands on, whether the freed allocation can be reclaimed with
attacker data, and what the attacker influences. `poc` answers who can reach
it with an experiment. It re-runs the reproducer under the threat model's
capability set. `report` joins them into an argued severity.

The record stops at the primitive and carries no weaponization.
`undetermined` is a valid outcome and costs nothing as long as
`undetermined_reason` says what blocked the analysis, because a fault that
disappears into GSP firmware genuinely cannot be followed further. A
conclusion the evidence does not support is not acceptable. `impact-list` closes
with how many records can carry a severity and names the ones that cannot, and
`validate` reports the same. An `rca_done` crash with no impact record is an
integrity problem for the same reason as a missing research record. The report
would carry a reproducer with no severity behind it.

Ask `python3 tools/pipeline_ctl.py next` what to do. It returns a phase, or
`wait`, or `decide`, or `advance-round`, or `complete`. `wait` means a
campaign in this round is still inside its window. Block on
`campaign_ctl.py wait --run-id <id>`, and do not run the next phase against a
run that is not finished. The loop transition is:

```
python3 tools/pipeline_ctl.py round-decide     # completion, caps, plateau -> continue|stop
python3 tools/pipeline_ctl.py round-advance    # only if the decision was continue
```

Stop conditions, in the order the tool applies them. Completion is measured
and not configured. The rest come from `loop:` in config/campaign.yaml, and
they are the spend ceiling, so never raise them mid-loop to keep a campaign
alive.

- the surface is accounted for: `exercised + accounted-for = 764`, where every
  target in the accounted-for set carries a written reason saying it cannot be
  reached. A row written as `deliberately-deferred` records a reachable target
  put aside, so it is counted separately as `deferred` and does not close one.
  This is the primary completion condition, and no
  percentage threshold enters it. It bounds Track K alone, because Track U has
  no enumerable denominator and its stop stays on its edge curve
- `max_total_run_hours` spent across all campaigns
- `max_rounds` reached, which is a backstop and not a convergence
- coverage plateaued (`stop_on_plateau`)
- coverage verdict `unknown`, where a missing or broken sampler stops the loop
  and authorises no further blind campaign

A plateau verdict is not a stop on its own. It is a stop only when read with
the surface number and the ledger. A plateau with the surface accounted for is
completion. A plateau with unreached targets carrying no reason is evidence
about the descriptions or the resource chains, and the loop continues. A
plateau at low surface coverage means the descriptions or the resource chains
are wrong, and the driver is not exhausted. A corpus that drifts onto the 236
GSP-routed control commands raises executions and never edges, which looks the
same as a plateau, so read
`python3 tools/surface_cov.py report --run-id <run-id>` before believing one.
`NV_ESC_IOCTL_XFER_CMD` re-enters the dispatch switch with a caller-supplied
command number, which is the one path that could produce that drift by
construction. `syzlang_gen.py emit` pins the inner command in all 31 typed
wrappers, and `python3 tools/regression_check.py pins` checks that in CI.

`round-decide` computes this. A completion, budget or round-cap stop cannot be
overridden, and the tool refuses. Overriding a plateau or `unknown` stop
requires `--decision continue --reason "..."`.

A completion stop rests on the ledger, and the verdict is recomputed from it on
every `round-end`. A target closed by a row that should not have been written
is reopened by removing the row
(`python3 tools/pipeline_ctl.py surface-unaccount --variant <name>`) and
running `round-end` again. That is no override of the stop. The stop goes away
because the ledger it was computed from changed.

The numbers those conditions read are measured. Each campaign self-stops after
`loop.campaign_hours` (a deadline on disk, enforced by
`gspwn-deadline@<run-id>.timer`, which `install-k`/`install-u` install, so it
survives the panics this pipeline expects), and
`round-end --from-run <run-id>` derives the coverage verdict, edge counts,
run-hours and new-crash count from the run's `coverage.csv` and the registry.
Do not hand-type those values. The cap is measured against `run_hours`, and a
run that ended after three hours must not bill the configured twenty-four.

Run isolation is mandatory. Every campaign gets its own `--run-id` and workdir
via `campaign_ctl.py`. Runs that share a workdir share
an evolved corpus, so neither run's coverage numbers describe what that run
actually did.

## Dispatching

For each phase, spawn a subagent whose prompt is: the full contents of
`agents/<phase>.md`, plus the current contents of `config/machine.yaml`,
`config/campaign.yaml`, and the paths of any artifacts it needs. Tell it to
write its outputs to the artifact paths the contract defines and to return
a one-paragraph summary plus gate evidence.

In round 1, `describe` and `seeds` need `surface/worklist-round1.md`
named explicitly. `pipeline_ctl.py worklist` exits non-zero by design that
round, because refine has recorded nothing yet.

Subagents are isolated and hand off paths and no transcripts, so the gate
evidence they return is a claim about files on disk. Check the artifacts
exist and say what the subagent reports before marking a phase `done`. A
phase whose evidence could not be confirmed is `blocked`.

Background subagents are allowed for `fuzz` (long-running monitor) and for
parallel `describe`/`seeds`/`harness`. Resume timed-out subagents, and do not
restart them.

## Kernel panics

Kernel panics are expected. The fuzzer runs under systemd and survives the
session. After a reboot, harvest crash logs, correlate with new registry
entries via triage, and resume.
