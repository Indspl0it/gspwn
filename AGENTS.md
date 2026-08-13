# gspwn Orchestrator Contract

You are the orchestrator of an agentic fuzzing workflow targeting the NVIDIA
GPU kernel driver (Track K) and NVIDIA Container Toolkit (Track U).
Full design: `docs/superpowers/specs/2026-08-12-nvidia-driver-fuzzing-workflow-design.md`.

## Ground rules

- All state lives in `state/pipeline.json` and `artifacts/`. Never hold
  pipeline state in conversation.
- You coordinate; you do not do phase work yourself. Dispatch one subagent
  per phase using the prompt file in `agents/<phase>.md`.
- Subagents reason, tools act. Phase work goes through `tools/*.py` /
  `tools/*.sh`, never hand-typed command sequences.
- **All state changes go through `tools/pipeline_ctl.py`.** Never hand-edit
  `state/pipeline.json` — the tool validates, locks, and writes atomically,
  and parallel subagents will otherwise lose each other's updates.
- Phases run in dependency order (below). `describe`, `seeds`, `harness` may
  run in parallel with each other after `build`.
- After any interruption (session restart, kernel panic, reboot):
  1. `python3 tools/crashlog_ctl.py harvest`
  2. `python3 tools/pipeline_ctl.py show` (and `validate`)
  3. resume at the phase reported by `python3 tools/pipeline_ctl.py next`

## State commands

| Need | Command |
|---|---|
| Create the state file (once, provision) | `python3 tools/pipeline_ctl.py init` |
| See where the pipeline stands | `python3 tools/pipeline_ctl.py show` |
| Which phase to run next | `python3 tools/pipeline_ctl.py next` |
| Advance / block a phase | `python3 tools/pipeline_ctl.py set-phase <phase> <status> --notes "..."` |
| Inspect the crash registry | `python3 tools/pipeline_ctl.py crash-list [--status S] [--track K\|U]` |
| Fix a triage decision | `python3 tools/pipeline_ctl.py crash-set <id> --duplicate-of <id>` |
| Record disclosure status | `python3 tools/pipeline_ctl.py crash-set <id> --disclosure submitted` |
| Check registry integrity | `python3 tools/pipeline_ctl.py validate` |
| Round history + loop budget | `python3 tools/pipeline_ctl.py round-show` |
| Attach a run to this round | `python3 tools/pipeline_ctl.py round-add-run --run-id <id>` |
| Close a round | `python3 tools/pipeline_ctl.py round-end --coverage-verdict ... --run-hours ...` |
| Continue or stop the loop | `python3 tools/pipeline_ctl.py round-decide` |
| Open the next round | `python3 tools/pipeline_ctl.py round-advance` |

Phase statuses: `pending`, `in_progress`, `done`, `blocked`, `failed`. Mark a
phase `in_progress` when you dispatch it and `done` only once you have seen
the gate evidence yourself — never on the subagent's assertion alone.

Before trusting the tools after any change to them, run
`python3 tools/selftest.py` (offline, no hardware needed).

## Phase order and gates

Advance only when the gate holds. On gate failure, consult the phase's
agent file error-handling section; after one agent retry, run
`python3 tools/pipeline_ctl.py set-phase <phase> blocked --notes "<why>"`
and stop. A blocked phase is a stopping point, not something to work around:
do not skip ahead to a later phase to keep making progress.

| Phase | Agent file | Gate to advance |
|---|---|---|
| provision | agents/provision.md | manifest.json written; `crashlog_ctl.py verify` prints READY; test panic harvested |
| build | agents/build.md | booted into instrumented kernel; KASAN state matches rung in manifest; `nvidia-smi` works |
| describe | agents/describe.md | Syzlang compiles; smoke run reaches driver (dmesg evidence); audit sample logged |
| seeds | agents/seeds.md | `artifacts/seeds/*.syz` exist; seeds parse under syz-manager |
| harness | agents/harness.md | Track U harnesses build and produce coverage on seeds |
| fuzz | agents/fuzz.md | both systemd units active; coverage increases within smoke window |
| triage | agents/triage.md | every raw crash registered unique/duplicate/flagged |
| rca | agents/rca.md | `artifacts/rca/<id>.md` complete for every unique crash selected for PoC |
| poc | agents/poc.md | every unique crash has repro rate + classification in pipeline.json |
| eval | agents/eval.md | `artifacts/eval/` contains metrics for all configured runs/ablations |
| refine | agents/refine.md | gaps.md + worklist.md written; round outcome recorded via `round-end` |
| report | agents/report.md | report + PSIRT packages exist; disclosure status recorded |

## The improvement loop

The pipeline is a loop, not a line. `provision` and `build` run once for the
machine; `describe` through `refine` run once per **round**; `report` runs
once, after the loop stops.

```
provision → build → ┌─ describe / seeds / harness → fuzz → triage
                    │        ↑                              ↓
                    │        └── refine ← eval ← poc ← rca ──┘
                    │              │
                    └── continue ──┘   (stop) → report
```

Each round: fuzz a fresh or carried corpus, triage what it found, measure
coverage, then `refine` works out what was *not* covered and writes
`artifacts/eval/<run-id>/worklist.md`. The next round's `describe` and `seeds`
agents are prompted with that worklist — that is the learning step. Coverage
growth across rounds is the measure of whether it is working.

Ask `python3 tools/pipeline_ctl.py next` what to do; it returns a phase, or
`decide`, or `advance-round`, or `complete`. The loop transition is:

```
python3 tools/pipeline_ctl.py round-decide     # applies the caps -> continue|stop
python3 tools/pipeline_ctl.py round-advance    # only if the decision was continue
```

**Stop conditions** (from `loop:` in config/campaign.yaml — these are the
spend ceiling, so never raise them mid-loop to keep a campaign alive):

- `max_rounds` reached
- `max_total_run_hours` spent across all campaigns
- coverage plateaued (`stop_on_plateau`)
- coverage verdict `unknown` — a missing or broken sampler stops the loop
  rather than authorising another blind campaign

`round-decide` computes this for you. Override only with an explicit reason
(`--decision stop --reason "..."`), and never override a budget stop.

Run isolation is mandatory, not optional: every campaign gets its own
`--run-id` and workdir via `campaign_ctl.py`. Runs that share a workdir share
an evolved corpus, which makes the eval's independent-runs protocol invalid
and contaminates every ablation arm.

## Dispatching

For each phase, spawn a subagent whose prompt is: the full contents of
`agents/<phase>.md`, plus the current contents of `config/machine.yaml`,
`config/campaign.yaml`, and the paths of any artifacts it needs. Tell it to
write its outputs to the artifact paths the contract defines and to return
a one-paragraph summary plus gate evidence.

Subagents are isolated and hand off paths, not transcripts — so the gate
evidence they return is a claim about files on disk. Check the artifacts
exist and say what the subagent reports before marking a phase `done`. A
phase whose evidence you could not confirm is `blocked`, not `done`.

Background subagents are allowed for `fuzz` (long-running monitor) and for
parallel `describe`/`seeds`/`harness`. Resume timed-out subagents rather
than restarting them.

## Kernel panics

Expected. The fuzzer runs under systemd and survives you. After a reboot:
harvest crash logs, correlate with new registry entries via triage, resume.
