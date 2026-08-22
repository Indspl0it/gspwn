---
title: Architecture overview
description: The five layers, the four state stores, the round loop, and the mechanisms that carry a campaign across a kernel panic.
---

gspwn drives a fuzzing campaign against the NVIDIA GPU kernel driver (Track K)
and the NVIDIA Container Toolkit (Track U) with no human at the console. It is
built in five layers: systemd units, one orchestrating agent, twelve sub-agents,
deterministic tools, and four state stores. Track K fuzzing panics the machine
as a normal part of its work, so no layer holds durable state in a process.

## Layers

| Layer | Components | Property the layer provides |
|---|---|---|
| Supervision | `gspwn-orchestrator.service`, `gspwn-k.service`, `gspwn-u.service`, `gspwn-deadline@<run-id>.timer`, `gspwn-coverage.timer` | Fuzzing, coverage sampling and deadline enforcement outlive the agent session and return after a reboot |
| Orchestration | One agent executing the contract in `AGENTS.md` | A single serialised walk of the phase state machine: ask `pipeline_ctl.py next`, dispatch, confirm the gate evidence on disk, record the result |
| Sub-agents | The twelve files in `agents/`, one per phase | Isolation. A dispatch carries the sub-agent's contract plus `config/machine.yaml` and `config/campaign.yaml`, and returns artifact paths plus a summary |
| Tools | `tools/*.py`, `tools/*.sh` | The only writers. Validation, locking, atomic writes, and refusal of operations whose output would be a wrong number |
| State | `state/pipeline.json`, `state/spend.json`, `artifacts/`, `knowledge/` | Durable position and evidence. A restarted agent needs nothing from the session it replaced |

The orchestrator holds no pipeline state in conversation. `state/pipeline.json`
is never hand-edited: `pipeline_ctl.py` validates the change, takes an exclusive
lock, and writes atomically. Sub-agents hand off paths, so the orchestrator
confirms each artifact on disk before marking a phase `done`. A phase whose
evidence cannot be confirmed is marked `blocked`, which stops the pipeline.

```mermaid
flowchart TB
  subgraph SD["systemd"]
    ORCH["gspwn-orchestrator.service<br/>Restart=always, breaker"]
    K["gspwn-k.service<br/>syz-manager"]
    U["gspwn-u.service<br/>harness container"]
    DL["gspwn-deadline@run.timer"]
    COV["gspwn-coverage.timer"]
  end

  ORCH -->|"dispatches, one per phase"| SA["sub-agents<br/>agents/*.md"]
  SA -->|"invokes"| T["tools/*.py<br/>the only writers"]
  ORCH -->|"next, brief, set-phase"| T

  T -->|"atomic write under flock"| PJ[("state/pipeline.json<br/>execution position")]
  T -->|"idempotent per run id"| SJ[("state/spend.json<br/>run-hour ledger")]
  T -->|"writes and reads"| AR[("artifacts/<br/>evidence")]
  T -->|"atomic append"| KN[("knowledge/<br/>committed facts")]

  K -->|"crashes, corpus"| AR
  U -->|"crashes, fuzzer_stats"| AR
  COV -->|"one row per interval"| AR
  DL -->|"stops and disables at the deadline"| K
  DL --> U
  DL -->|"bills"| SJ
```

## State stores

| Store | Holds | Lifetime | Committed |
|---|---|---|---|
| `state/pipeline.json` | Execution position: phases, the crash registry, rounds | This campaign | No |
| `state/spend.json` | Run-hours billed per run id | This machine | No |
| `artifacts/` | Evidence: coverage, crashes, reproducers, reports | This campaign | No |
| `knowledge/` | ABI and process facts | Every campaign, every machine | Yes, to a public repository |

A fact belongs to exactly one store. Execution position written into
`knowledge/` is published to a public repository and then drifts. Knowledge
written into `state/pipeline.json` is lost when the box is rebuilt.

`state/spend.json` is machine-global. `GSPWN_STATE` redirects
`state/pipeline.json` so a side run keeps its own registry. The ledger does
not follow it, so that run still counts against `loop.max_total_run_hours`.

Three locks cover these stores. `state/.pipeline.lock` follows `GSPWN_STATE` and
sits beside the file it protects. `state/spend.json.lock` and `state/repro.lock`
do not follow it. One lock covering both the state file and the ledger deadlocks
when `round-end` bills a run inside its own state transaction. See
[Durability](/gspwn/architecture/durability/).

## The round loop

`provision` and `build` run once per machine. The nine round phases run once per
round. `report` runs once, after the loop stops. A round inherits two things:
the work list, which `refine` writes and `round-advance` hands to the next
round's `describe` and `seeds`, and the corpus, which
`campaign_ctl.py install-k --corpus carry --from-run` packs into the next
campaign.

```mermaid
flowchart TB
  PR["provision<br/>machine facts, crash capture,<br/>syzkaller built"] --> BU["build<br/>instrumented kernel,<br/>rung ladder 1 to 3"]

  BU --> DE["describe<br/>syzlang for the ioctl surface"]
  BU --> SE["seeds<br/>trace2seed.py on a real CUDA workload"]
  BU --> HA["harness<br/>libFuzzer and AFL++ targets, Track U"]

  DE --> FZ["fuzz<br/>both units live, campaign bounded by<br/>loop.campaign_hours"]
  SE --> FZ
  HA --> FZ

  FZ --> TR["triage<br/>crash_parse.py, flagged queue emptied"]
  TR --> RC["rca<br/>research record and impact record<br/>per unique crash"]
  RC --> PO["poc<br/>repro_ctl.py verify, profile check"]
  PO --> EV["eval<br/>coverage series, findings table,<br/>round progression"]
  EV --> RF["refine<br/>gaps.md and worklist.md<br/>surface-account writes the completion ledger"]
  RF --> RE["round-end --from-run<br/>verdict, edges, run-hours, new crashes<br/>derived from coverage.csv and the registry"]

  RE --> DEC{"round-decide<br/>applies surface completion,<br/>loop.max_rounds, loop.max_total_run_hours,<br/>plateau and unknown, in that order"}
  DEC -->|continue| ADV["round-advance<br/>round phases reset to pending,<br/>setup and crash registry kept"]
  DEC -->|stop| REP["report<br/>write-up and PSIRT packages"]

  ADV -.->|"worklist_in"| DE
  ADV -.->|"worklist_in"| SE
  ADV -.->|"corpus carry --from-run"| FZ
```

Solid edges are dependency order. Dashed edges are the only state a new round
inherits. `describe`, `seeds` and `harness` may run in parallel after `build`.
Every phase from `triage` onward measures the campaign, so
`pipeline_ctl.py next` returns `wait` while a run is inside its window, and
`round-end` refuses to measure a live campaign.

Entry conditions, carried state and termination for all ten loops are in
[Loops](/gspwn/architecture/loops/).

## Crash resilience

The kernel dies, the agent dies with it, and the campaign resumes with no memory
of the session that started it.

| Mechanism | Implementation | Failure it prevents |
|---|---|---|
| Durable position | `state/pipeline.json`, rendered by `pipeline_ctl.py brief`, which derives its output at read time | A resumed agent cannot locate the pipeline and restarts phases that already ran |
| Crash evidence capture | `crashlog_ctl.py harvest` copies every pstore record and every new `/var/crash` dump into `artifacts/`, then unlinks the pstore records. It runs before the orchestrator launches an agent | pstore is fixed-size and frees a record only on unlink, so the next panic has nowhere to write and later findings are lost |
| Atomic write path | Temp file in the target directory, `flush`, `fsync` of the file, `os.replace`, `fsync` of the parent directory | A panic mid-write truncates the state file and the next read fails to parse it |
| Exclusive transactions | An `flock` held across the whole read-modify-write cycle | Parallel `describe`, `seeds` and `harness` sub-agents overwrite each other's updates |
| Process supervision | `gspwn-orchestrator.service`, `Restart=always`, `RestartSec=60` | The pipeline stops at the first panic and waits for a human to log in |
| Circuit breaker | Same-boot starts and reboots counted separately inside `orchestrator.window_min`, against `orchestrator.max_same_boot_starts` and `orchestrator.max_reboots`. A trip records the block and exits 78, which systemd does not restart | A crash-looping agent restarts forever with no token ceiling. Separate counters keep expected panic reboots from tripping the same limit |
| Launch cap | `orchestrator.max_agent_hours` kills the process group of a launch that exceeds it | A stalled agent holds the pipeline open while the instance bills |
| Deadline on disk | `artifacts/runs/<run-id>/deadline` holds one absolute epoch second, `fsync`ed at install. `gspwn-deadline@<run-id>.timer` rechecks it every `loop.deadline_check_min` and after each boot. A lost file is reconstructed from the install event in the state file | A one-shot timer dies with the machine and the campaign runs past its window unbounded |
| Stop plus disable | Deadline enforcement runs `systemctl stop` and `systemctl disable` on both fuzz units | An enabled `Restart=always` unit resumes fuzzing at the next boot, after the campaign was stopped |
| Idempotent billing | `record_run_hours` overwrites the entry for a run id | A `round-end` retried after an interruption bills the campaign twice against `loop.max_total_run_hours` |
| Verification progress | `repro_ctl.py verify` persists `crash.repro_progress` with the boot id before and after every run | A reproducer that panics the box loses the run it was executing, and the boot-id evidence for whether that run was a hit |

### Resume sequence

```mermaid
sequenceDiagram
  autonumber
  participant K as kernel
  participant PS as pstore / kdump
  participant SD as systemd
  participant OC as orchestrator_ctl.py run
  participant T as tools
  participant ST as state/pipeline.json

  K->>PS: KASAN report and panic record persisted
  K->>SD: the box goes down and reboots
  SD->>SD: gspwn-k and gspwn-u return, Restart=always
  SD->>SD: gspwn-deadline@<run-id>.timer returns, OnBootSec
  SD->>OC: start the unit, Restart=always RestartSec=60
  OC->>OC: breaker check against orchestrator.window_min
  OC->>ST: is the pipeline drivable?
  ST-->>OC: blocked, complete or unreadable state exits 78
  OC->>T: crashlog_ctl.py harvest, as root
  T->>PS: copy every record out, then unlink it
  T->>ST: recovered crashes reach the registry at triage
  OC->>T: pipeline_ctl.py brief
  T->>ST: read
  ST-->>OC: position, crash registry, findings, knowledge tail
  OC->>OC: launch an agent, bounded by orchestrator.max_agent_hours
```

A harvest failure warns and does not stop the launch. A blocked phase, a
complete pipeline or an unreadable state file exits 78, and systemd leaves the
unit stopped until `orchestrator_ctl.py reset`.

### Manual recovery

Three commands restore the position after a panic, a reboot, a session restart
or a compacted context:

```
sudo python3 tools/crashlog_ctl.py harvest
python3 tools/pipeline_ctl.py brief
python3 tools/pipeline_ctl.py next
```

`brief` is derived from the state file at read time, so a stored copy of it goes
out of date as soon as the pipeline moves. `gspwn-orchestrator.service` runs the
first two commands and launches an agent.

## Enforcement points

| Property | Enforced by |
|---|---|
| A campaign ends on time | A deadline file plus a per-run systemd timer, which survives reboots and needs no follow-up command |
| The run-hour budget is not overshot | A machine-global ledger, checked at every campaign install and at every round decision |
| A round is measured over its whole campaign | `next` returning `wait`, and `round-end` refusing a live campaign |
| A dead GPU is not reported as a plateau | The GPU status recorded in every Track K coverage sample |
| A campaign stops on measured completion and not on a round count | The completion ledger, read by `round-decide` before `loop.max_rounds`, which is a backstop |
| An unattended agent cannot loop forever | A circuit breaker on starts, a wall-clock cap on one launch, and an exit code systemd will not restart |
| Crash evidence survives a panic | pstore and kdump, harvested before anything else on resume |
| A write survives a panic mid-write | A temporary file, `fsync`, an atomic rename, and an `fsync` of the directory |

## Refusal conditions

Each condition causes the named command to exit non-zero without producing a
result. The shared failure class is a broken measurement path that returns a
well-formed wrong number.

| Condition | Tool and command | Behaviour | Rationale |
|---|---|---|---|
| The `gpu` column of a Track K sample holds any value other than `ok` | `coverage_ctl.py plateau` | Reports the verdict as `unknown`, which `round-decide` treats as a stop | A card off the bus leaves syz-manager executing against nothing. The edge count stops moving and the curve matches a saturated run. Track U records `n/a` and is not gated on GPU health |
| `dmesg` is unreadable, which under `kernel.dmesg_restrict=1` appears as empty output | `repro_ctl.py verify`, Track K | Exits before any run is scored | An empty ring buffer scores every run `clean`, giving a real bug a repro rate of 0.0 and the classification unreproducible |
| `systemctl is-active gspwn-k` returns `active` or `activating` | `repro_ctl.py verify`, Track K | Exits before any run is scored | A Track K run counts as a reproduction partly because the box went down during it. A live fuzzer panics the box by design, and each such panic lands as a hit on the rate that gates disclosure |
| Effective uid is not 0 | `crashlog_ctl.py harvest`, `setup` and `prune` | Exits with the sudo remediation and names `orchestrator_ctl.py preflight` | `/sys/fs/pstore` and `/var/crash` are root-only. A non-root harvest reads nothing while reporting that it found nothing, and the unattended post-panic path records success while the evidence stays on the machine |
| `state/spend.json` is absent while rounds still record run-hours | `campaign_ctl.py install-k` and `install-u`, and every `pipeline_ctl.py` command that reads the ledger | Raises `SpendLedgerMissing`, refuses the operation, and names `pipeline_ctl.py spend-init` | A missing ledger read as zero spent removes `loop.max_total_run_hours` from an unattended run. `spend-init` rebuilds the ledger from the state file and never lowers recorded hours |
| A run attached to this round is still inside its campaign window | `pipeline_ctl.py round-end` | Refuses to measure the round | The coverage verdict, edge counts, new-crash count and billed hours would describe whichever part of the run had happened by then |
| A key in `config/campaign.yaml` is absent from the schema | `gspwn_config.py`, and every tool that loads the configuration | Raises `ConfigError` naming the offending key and the valid keys at that level, then exits non-zero | A misspelled cap leaves the default value in force, so a limit keyed in to bound the run has no effect |

## See also

- [Execution model](/gspwn/architecture/execution-model/): invocation to exit.
- [Loops](/gspwn/architecture/loops/): every loop in the system.
- [Durability](/gspwn/architecture/durability/): the write path.
