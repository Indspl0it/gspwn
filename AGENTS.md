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
- Phases run in dependency order (below). `describe`, `seeds`, `harness` may
  run in parallel with each other after `build`.
- After any interruption (session restart, kernel panic, reboot): read
  `state/pipeline.json`, run `python3 tools/crashlog_ctl.py harvest`, then
  resume at the first phase not marked `done`.

## Phase order and gates

Advance only when the gate holds. On gate failure, consult the phase's
agent file error-handling section; after one agent retry, mark the phase
`blocked` in pipeline.json and stop.

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
| report | agents/report.md | report + PSIRT packages exist; disclosure status recorded |

## Dispatching

For each phase, spawn a subagent whose prompt is: the full contents of
`agents/<phase>.md`, plus the current contents of `config/machine.yaml`,
`config/campaign.yaml`, and the paths of any artifacts it needs. Tell it to
write its outputs to the artifact paths the contract defines and to return
a one-paragraph summary plus gate evidence.

Background subagents are allowed for `fuzz` (long-running monitor) and for
parallel `describe`/`seeds`/`harness`. Resume timed-out subagents rather
than restarting them.

## Kernel panics

Expected. The fuzzer runs under systemd and survives you. After a reboot:
harvest crash logs, correlate with new registry entries via triage, resume.
