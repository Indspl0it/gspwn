---
title: Loops
description: All ten loops in the system, each with its entry condition, iteration body, exit condition, bound and owner.
---

Ten loops run in gspwn. The agent-owned ones nest four deep at their deepest,
along the chain L6, L1, L2 and then whichever loop the running phase carries.
Each loop states a bound, because an unterminated loop on a machine billed by
the hour spends without limit.

## Nesting

```mermaid
flowchart TB
  L6["L6 supervision<br/>systemd restarts the agent"]
  L1["L1 round<br/>describe .. refine, then decide"]
  L2["L2 phase-gate<br/>next, dispatch, confirm, record"]
  L9["L9 rung ladder<br/>inside the build phase"]
  L8["L8 wait<br/>inside the fuzz phase"]
  L4["L4 deadline<br/>a systemd timer, running alongside"]
  L3["L3 syzkaller inner<br/>owned by syz-manager, running alongside"]
  L5["L5 sampling<br/>a systemd timer, running alongside"]
  L10["L10 flagged queue<br/>inside the triage phase"]
  L7["L7 verify<br/>inside the poc phase"]

  L6 --> L1 --> L2
  L2 --> L9
  L2 --> L8 --> L4
  L2 --> L3
  L2 --> L5
  L2 --> L10
  L2 --> L7
```

L3, L4 and L5 run under systemd and outlive any agent session.

| Loop | Owner | Bound |
|---|---|---|
| L1 round | `pipeline_ctl.py` | Surface completion, then `loop.max_rounds`, then `loop.max_total_run_hours` |
| L2 phase-gate | The orchestrator | Twelve phases; a `blocked` phase stops the orchestrator |
| L3 syzkaller inner | syz-manager | The campaign deadline, enforced by L4 |
| L4 deadline | systemd | Fires every `loop.deadline_check_min`; disables itself after enforcement |
| L5 sampling | systemd | Fires every `loop.coverage_sample_min`; skips once the window elapses |
| L6 supervision | systemd and the breaker | `orchestrator.max_same_boot_starts`, `orchestrator.max_reboots`, `orchestrator.max_agent_hours` |
| L7 verify | `repro_ctl.py` | `poc.default_runs` counted runs, `poc.void_retry_factor` attempts per still-needed run |
| L8 wait | The `fuzz` sub-agent | The deadline file |
| L9 rung ladder | The `build` sub-agent | Three rungs |
| L10 flagged queue | The `triage` sub-agent | The count of `flagged` registry entries |

## L1: the round loop

| Property | Value |
|---|---|
| Entry | `build` is `done` and the current round has no recorded decision |
| Iteration body | The nine round phases in dependency order, then `round-end`, then `round-decide` |
| State carried | The corpus, through `install-k --corpus carry --from-run`; the work list, through `round.worklist_in` |
| Exit | `round-decide` returns `stop` |
| Bound | Surface completion, `loop.max_rounds` and `loop.max_total_run_hours`, all three non-overridable |

```mermaid
flowchart TB
  A["round-advance<br/>round phases reset to pending"] --> B["describe / seeds / harness<br/>read worklist_in"]
  B --> C["fuzz<br/>campaign bounded by loop.campaign_hours"]
  C --> D["triage"]
  D --> E["rca<br/>finding-set, impact-set"]
  E --> F["poc"]
  F --> G["eval"]
  G --> H["refine<br/>writes worklist.md"]
  H --> I["round-end --from-run --worklist"]
  I --> J{"round-decide"}
  J -->|"surface complete"| S0["stop"]
  J -->|"round cap reached"| S1["stop"]
  J -->|"run-hour budget spent"| S2["stop"]
  J -->|"both curves flat"| S3["stop"]
  J -->|"coverage verdict unknown"| S4["stop"]
  J -->|"edge or surface curve climbing"| A
  S0 --> R["report"]
  S1 --> R
  S2 --> R
  S3 --> R
  S4 --> R
```

| Stop condition | Source | `--decision continue` accepted |
|---|---|---|
| Surface complete | `surface_stop_reason()` against the completion ledger | No |
| Round cap reached | `hard_cap_reason()` against `loop.max_rounds` | No |
| Run-hour budget spent | `hard_cap_reason()` against `loop.max_total_run_hours` | No |
| Coverage plateaued | `round.coverage_verdict` with `loop.stop_on_plateau` set | Yes, with `--reason` |
| Coverage verdict unknown | `round.coverage_verdict` | Yes, with `--reason` |

`hard_cap_reason()` checks completion first, so a campaign finishing on its
last permitted round records why it finished. `loop.max_rounds` is 10 and is a
backstop against a runaway loop. A campaign that reaches it has failed to
converge, and its stop reason says so and points at the completion ledger.
`loop.max_total_run_hours` at 5000 is the spend ceiling. See
[Coverage and plateau](/gspwn/architecture/coverage-and-plateau/) for the
two-curve decision table.

`round-advance` requires every round phase `done` and a recorded `round-end`. A
phase marked `blocked` fails that check, so a blocked gate cannot be carried
into a new round behind a fresh set of phase records.

The work list is the loop's carried state, and round 1 has no predecessor round
to produce one. `tools/cve_patch_map.py worklist` fills that position from
NVIDIA's published kernel-mode CVEs, the one steering signal available before
any campaign has run. It classifies 61 kernel-mode CVEs, resolves 53 of them to
a release tag pair and ranks 270 changed functions, 27 of which reach a named
ioctl target. The committed `surface/worklist-round1.md` carries 31 items: 22
in its describe section, 4 in its seeds section, and 5 targets recorded as
outside the tenant surface so that a later round does not rediscover them. A
`[history CVE-YYYY-NNNNN]` item ranks a place where the vendor found a bug and
is no evidence that a bug remains there. See
[Historical targeting](/gspwn/architecture/historical-targeting/).

`describe`, `seeds` and `harness` are declared parallel after the build phase
in `PARALLEL_AFTER_BUILD`, in round 1 as in every later round. `seeds` reads
`tools/ioctl_map.json`, which is committed and pre-populated, so it takes no
input from the describe phase and the three run concurrently.

## L2: the phase-gate loop

| Property | Value |
|---|---|
| Entry | Any phase is not `done` |
| Iteration body | Ask `next`, mark `in_progress`, dispatch the sub-agent, confirm the evidence on disk, record `done` or `blocked` |
| State carried | The phase records in `state/pipeline.json` |
| Exit | `next` returns `complete`, or a phase is recorded `blocked` and the orchestrator stops at it |
| Bound | Twelve phases per pipeline; a `blocked` phase stops the orchestrator before the next dispatch |

```mermaid
flowchart TB
  N["pipeline_ctl.py next"] --> K{"what came back?"}
  K -->|"a phase name"| M["set-phase PHASE in_progress"]
  K -->|"wait"| W["campaign_ctl.py wait --run-id ID"]
  K -->|"decide"| DEC["round-decide"]
  K -->|"advance-round"| ADV["round-advance"]
  K -->|"complete"| DONE(["pipeline complete"])
  M --> DIS["dispatch the sub-agent:<br/>agents/PHASE.md + both config files<br/>+ artifact paths"]
  DIS --> EV["sub-agent returns a summary<br/>and a claim about files"]
  EV --> CHK{"do the artifacts exist,<br/>and say what was claimed?"}
  CHK -->|yes| OK["set-phase PHASE done"]
  CHK -->|no| BAD["set-phase PHASE blocked --notes"]
  OK --> N
  W --> N
  ADV --> N
  DEC --> N
  BAD --> STOP(["stop: a blocked gate is<br/>not something to work around"])
```

The confirmation step reads the filesystem. See
[Execution model](/gspwn/architecture/execution-model/).

## L3: the syzkaller inner loop

| Property | Value |
|---|---|
| Entry | `gspwn-k.service` starts |
| Iteration body | Pick a corpus program, mutate it, execute it, read the KCOV trace, keep it when it covered new edges |
| State carried | `workdir/corpus.db` and the crash directories |
| Exit | The unit is stopped. No condition inside the loop ends it |
| Bound | External. L4 stops and disables the unit at the deadline |

```mermaid
flowchart TB
  P["pick a corpus program"] --> MU["mutate"]
  MU --> EX["execute against a modelled node:<br/>nvidiactl, nvidiaN, nvidia-uvm, nvidia-uvm-tools,<br/>nvidia-modeset, dri/card, dri/renderD"]
  EX --> KC["read the KCOV trace"]
  KC --> NEW{"new edges?"}
  NEW -->|yes| ADD["add to the corpus, minimise"]
  NEW -->|no| DIS["discard"]
  ADD --> P
  DIS --> P
  EX -->|"the kernel faulted"| CR["write workdir/crashes/&lt;hash&gt;/<br/>description, report&lt;N&gt;, log&lt;N&gt;, repro.prog"]
  CR --> P
  EX -->|"the machine panicked"| RS["systemd restarts after RestartSec=30<br/>syzkaller replays its corpus"]
  RS --> P
```

The pipeline does not modify this loop. The outer loop supplies what syzkaller
cannot produce for itself: models for ioctls it has no description for, and
valid object-chain seeds. One iteration is drawn in
[Execution model](/gspwn/architecture/execution-model/).

A replay climbs the reported count back towards its previous high-water mark
and records no new coverage, which the coverage model absorbs with a running
maximum on the y axis.

## L4: the deadline loop

| Property | Value |
|---|---|
| Entry | `install-k` or `install-u` enables `gspwn-deadline@<run-id>.timer` |
| Iteration body | Read or reconstruct the deadline, compare it against the clock, stop and disable the fuzz units once it has passed |
| State carried | `artifacts/runs/<run-id>/deadline`, one absolute epoch second |
| Exit | Enforcement completes and the timer disables itself |
| Bound | Fires every `loop.deadline_check_min` and after each boot, through `OnBootSec` |

```mermaid
flowchart TB
  T["timer fires every<br/>loop.deadline_check_min"] --> RD{"deadline file present?"}
  RD -->|yes| CMP{"has it passed?"}
  RD -->|no| RC{"reconstructible from<br/>the install record?"}
  RC -->|yes| CMP
  RC -->|no| UN{"units still fuzzing<br/>for this run?"}
  UN -->|no| NOP["nothing to enforce, exit 0"]
  UN -->|yes| FORCE["nothing bounds this campaign's spend:<br/>stop it now"]
  CMP -->|no| LEFT["report the hours left, exit 0"]
  CMP -->|yes| STOP["systemctl stop AND disable<br/>gspwn-k, gspwn-u"]
  FORCE --> STOP
  STOP --> OKQ{"every stop succeeded?"}
  OKQ -->|no| RETRY["record no stop; exit 1<br/>the timer retries"]
  OKQ -->|yes| BILL["record the stops, bill the run,<br/>disable this run's own timer"]
  LEFT --> T
  NOP --> T
  RETRY --> T
```

An enabled `Restart=always` unit resumes at the next boot, and this pipeline
reboots by design, so the disable step is required alongside the stop.

`loop.deadline_check_min` is separate from `loop.coverage_sample_min`, so
raising the sampling interval does not delay every campaign stop past the
window it enforces.

## L5: the sampling loop

| Property | Value |
|---|---|
| Entry | `coverage_ctl.py install-timer` enables `gspwn-coverage.timer` |
| Iteration body | One invocation per track: collect that track's counters, probe the GPU, read free disk, measure the surface when it is due, append one row |
| State carried | `artifacts/runs/<id>/coverage.csv` and `coverage-u.csv` |
| Exit | `coverage_ctl.py remove-timer` |
| Bound | Fires every `loop.coverage_sample_min`. The append is skipped once the campaign window has elapsed, absent `--force` |

The timer carries one `ExecStart` line per track and each is a separate
invocation against its own CSV. A sample handles one track and never both.

```mermaid
flowchart TB
  T["timer fires every<br/>loop.coverage_sample_min<br/>once per track"] --> REG{"run registered<br/>in the state file?"}
  REG -->|no| REF["refuse: a typo would create a<br/>root-owned run directory"]
  REG -->|yes| FIN{"campaign window<br/>elapsed?"}
  FIN -->|"yes, and no --force"| SKIP["skip: do not pad the sample count<br/>long after fuzzing stopped"]
  FIN -->|no| TRK{"which track?"}
  TRK -->|K| CK["try the JSON endpoints,<br/>then the dashboard HTML,<br/>then corpus.db size"]
  TRK -->|U| CU["sum fuzzer_stats<br/>across artifacts/runs/&lt;id&gt;/u/*"]
  CK --> GK["probe the GPU"]
  CU --> GU["record the GPU column<br/>as not applicable"]
  GK --> DISK["read free space"]
  GU --> DISK
  DISK --> SD{"Track K, surface not skipped,<br/>and the last surface sample older<br/>than coverage.surface_sample_min?"}
  SD -->|yes| SURF["unpack the run's corpus.db<br/>and count enumerated targets"]
  SD -->|no| APP
  SURF --> APP["append one row under the header<br/>the file already carries"]
  APP --> WARN{"unhealthy GPU, low disk,<br/>or an unreachable source?"}
  WARN -->|yes| W["print a warning; exit 1 if unreachable"]
  WARN -->|no| T
  W --> T
  SKIP --> T
  REF --> T
```

Both `ExecStart` lines carry a `-` prefix, so a failure sampling one track
leaves the other track's sample intact. The GPU probe is bounded by
`coverage.gpu_probe_timeout_sec`, default 20 seconds, which covers a hung
driver as well as a dead one.

The surface measurement runs on its own coarser cadence, because it unpacks the
run's `corpus.db` and rescans every program in it where the other columns come
from one HTTP fetch. The Track U line skips it: those harnesses produce no
syzlang programs. A sample that skips the measurement records an empty
`surface` value, which the curve drops.

## L6: the supervision loop

| Property | Value |
|---|---|
| Entry | `gspwn-orchestrator.service` is enabled and started |
| Iteration body | Breaker check, session resolve, harvest, launch the agent, wait for exit or kill on stall |
| State carried | `state/orchestrator.json`: the start history, the blocked record, the session id |
| Exit | Exit 78, which systemd does not restart |
| Bound | `orchestrator.max_same_boot_starts` (5) and `orchestrator.max_reboots` (10) inside `orchestrator.window_min` (60). `orchestrator.max_agent_hours` per launch, 0 in the shipped configuration and therefore off |

```mermaid
flowchart TB
  S["systemd starts the unit<br/>Restart=always, RestartSec=60"] --> CMD{"orchestrator.command set?"}
  CMD -->|no| X1["exit 78"]
  CMD -->|yes| LK["take the breaker lock,<br/>record this start"]
  LK --> BRK{"same-boot starts or reboots<br/>over the limit in window_min?"}
  BRK -->|yes| BLK["record blocked; exit 78"]
  BRK -->|no| SESS["resolve the session:<br/>fresh or resume<br/>stored BEFORE launching"]
  SESS --> PIPE{"pipeline drivable?"}
  PIPE -->|"a phase is blocked"| X2["exit 78"]
  PIPE -->|"complete"| X3["exit 78"]
  PIPE -->|"state file unreadable"| X4["exit 78"]
  PIPE -->|yes| HAR["crashlog_ctl.py harvest<br/>failure warns, does not stop"]
  HAR --> LAUNCH["launch the agent,<br/>bounded by max_agent_hours<br/>when it is non-zero"]
  LAUNCH --> WAIT{"exited, or stalled?"}
  WAIT -->|exited| RES{"was this a resume<br/>that exited non-zero?"}
  WAIT -->|stalled| KILL["kill the process group:<br/>SIGTERM, then SIGKILL"]
  RES -->|yes| CLR["clear the session id<br/>so the next start is clean"]
  RES -->|no| RET["return the agent's code"]
  KILL --> RET
  CLR --> RET
  RET --> S
  BLK --> STOPPED(["stopped until<br/>orchestrator_ctl.py reset"])
  X1 --> STOPPED
  X2 --> STOPPED
  X3 --> STOPPED
  X4 --> STOPPED
```

Same-boot starts and reboots are counted separately. Track K panics the box by
design, so one shared limit would trip on a healthy campaign.

The session id is stored before the launch. See
[Durability](/gspwn/architecture/durability/).

## L7: the verify loop

| Property | Value |
|---|---|
| Entry | `repro_ctl.py verify` acquires `state/repro.lock` |
| Iteration body | Persist progress, run the reproducer, score the verdict, persist progress |
| State carried | `crash.repro_progress` in the state file, with the boot id and an `in_flight` flag |
| Exit | The counted-run target is reached, or the attempt cap is hit |
| Bound | `poc.default_runs` counted runs; `poc.void_retry_factor` attempts per still-needed counted run, plus a fixed slack |

```mermaid
flowchart TB
  K0{"track K and the fuzzer unit is active?"} -->|"yes, without --allow-live-campaign"| REFUSE["refuse: every panic the fuzzer<br/>causes would score as a hit"]
  K0 -->|no| L["acquire state/repro.lock<br/>non-blocking: a second session exits"]
  L --> REC{"a run left in_flight?"}
  REC -->|yes| RESOLVE["resolve it: same boot -> void;<br/>new boot + matching log -> hit;<br/>new boot + other crash -> void;<br/>new boot + no logs -> weak hit (K only)"]
  REC -->|no| CHK
  RESOLVE --> CHK{"counted runs &lt; --runs?"}
  CHK -->|no| RATE["rate = hits / counted"]
  CHK -->|yes| CAP{"attempts &gt;= the cap?"}
  CAP -->|yes| GIVE["give up: too many void runs"]
  CAP -->|no| MARK["runs_done += 1, in_flight = true<br/>persist"]
  MARK --> RUN["run the reproducer"]
  RUN --> SCORE{"verdict"}
  SCORE -->|hit| H["hits += 1"]
  SCORE -->|void| V["inconclusive += 1<br/>does NOT advance the count"]
  SCORE -->|clean| C["counted, not a hit"]
  H --> PER["persist"]
  V --> PER
  C --> PER
  PER --> CHK
  GIVE --> ANY{"any run counted?"}
  ANY -->|no| EX1["exit 1: 0 counted runs,<br/>no rate recorded"]
  ANY -->|yes| RATE
  RATE --> CLS["reliable / flaky / unreproducible<br/>recorded with the counted-run count"]
```

| Verdict | Advances the counted-run total | Counts as a hit |
|---|---|---|
| hit | Yes | Yes |
| clean | Yes | No |
| void | No | No |

Void runs leave the count unchanged, so the attempt cap bounds the loop. A
persistently wrapping dmesg ring would otherwise iterate without end.

A rate at or above `poc.reliable_threshold` classifies the crash `reliable`.
Any rate above zero below it classifies it `flaky`. A rate of zero classifies
it `unreproducible`.

## L8: the wait loop

| Property | Value |
|---|---|
| Entry | The `fuzz` phase calls `campaign_ctl.py wait --run-id <id>` |
| Iteration body | Re-read the deadline, print a heartbeat, sleep for the lesser of the poll interval and the time left |
| State carried | The deadline file, which this loop does not own |
| Exit | The deadline has passed |
| Bound | The absolute epoch second in `artifacts/runs/<run-id>/deadline` |

```mermaid
flowchart TB
  S["wait --run-id ID"] --> D{"deadline recoverable?"}
  D -->|no| ERR["exit: install the campaign first,<br/>which starts the clock"]
  D -->|yes| RE["re-read the deadline<br/>a --replace install moves it"]
  RE --> LEFT{"time left?"}
  LEFT -->|"no"| OUT["window has elapsed"]
  LEFT -->|"yes, --check given"| CH["print the hours left; exit 1"]
  LEFT -->|"yes"| HB["print a heartbeat"]
  HB --> SL["sleep min(poll_min, time left)"]
  SL --> RE
  OUT --> ACT{"units still active<br/>past the deadline?"}
  ACT -->|yes| ENF["enforce it here:<br/>run check-deadline"]
  ACT -->|no| DONE(["return 0"])
  ENF --> DONE
```

The deadline is re-read on every iteration, so a `--replace` install that moves
it takes effect without restarting the wait. The heartbeat distinguishes a
process blocking for a day from a hung one. A wait interrupted by a panic
resumes against the same deadline when the command is re-run after the reboot.

The wait enforces the deadline itself when the units are still active past it,
because the timer may never have been installed. Waiting out a window and then
measuring a campaign that is still running produces the same wrong number the
timer exists to prevent.

## L9: the rung ladder

| Property | Value |
|---|---|
| Entry | The `build` phase starts, at rung 1 |
| Iteration body | Build, install, reboot, check the gate |
| State carried | `instrumentation_rung` in `config/machine.yaml` and in `artifacts/builds/manifest.json` |
| Exit | The first rung whose gate passes, or all three failing |
| Bound | Three rungs |

```mermaid
flowchart TB
  R1["RUNG=1<br/>KASAN+KCOV kernel, KASAN+KCOV modules"] --> G1{"gate: booted into it,<br/>KASAN matches, the nvidia modules<br/>are loaded, nvidia-smi works"}
  G1 -->|pass| DONE1["record rung 1, stop"]
  G1 -->|"fail on a stripped CFLAGS"| RETRY["patch conftest.sh,<br/>retry once per rung"]
  RETRY --> G1
  G1 -->|fail| H1["harvest crash logs,<br/>write rung-1-failed.md"]
  H1 --> R2["RUNG=2 SKIP_KERNEL=1<br/>KCOV-only modules"]
  R2 --> G2{"same four-condition gate,<br/>KASAN state matching this rung"}
  G2 -->|pass| DONE2["record rung 2, stop"]
  G2 -->|fail| H2["harvest, write rung-2-failed.md"]
  H2 --> R3["RUNG=3 SKIP_KERNEL=1<br/>uninstrumented modules"]
  R3 --> G3{"same four-condition gate,<br/>KASAN state matching this rung"}
  G3 -->|pass| DONE3["record rung 3, stop"]
  G3 -->|fail| BLOCK["write FAILED.md,<br/>mark the phase blocked"]
```

`SKIP_KERNEL=1` on rungs 2 and 3 bounds the ladder's cost. Only the module
CFLAGS differ between rungs. The kernel image is identical, and rebuilding it
per rung spends hours of billed machine time producing the same image.

The rung reached bounds what the oracles report. See
[Scope and oracle](/gspwn/architecture/scope-and-oracle/).

## L10: the flagged-queue loop

| Property | Value |
|---|---|
| Entry | `crash_parse.py` registered at least one `flagged` entry |
| Iteration body | Read both reports, decide duplicate or distinct, record the decision with `crash-set` |
| State carried | The crash registry in `state/pipeline.json` |
| Exit | `crash-list --status flagged` returns nothing |
| Bound | The count of `flagged` entries, which no iteration increases |

The queue is durable and survives the session that produced it. The
commands are in
[Results and triage](/gspwn/guides/results-and-triage/), and the flagging rules
are in [Crash identity](/gspwn/architecture/crash-identity/).

## The campaign lifecycle

L4, L5 and L8 all act on this state machine.

```mermaid
stateDiagram-v2
  [*] --> installed: install-k / install-u<br/>budget checked, deadline written,<br/>per-run timer enabled
  installed --> running: start k / start u
  running --> panicked: the kernel dies
  panicked --> rebooted: systemd comes back
  rebooted --> running: Restart=always;<br/>syzkaller replays its corpus
  running --> elapsed: the deadline passes
  elapsed --> stopped: check-deadline stops AND<br/>disables both units
  stopped --> billed: measured hours recorded<br/>to state/spend.json
  billed --> measured: round-end --from-run derives<br/>the verdict, edges and crash count
  measured --> [*]
  running --> retired: a --replace install of another run
  retired --> [*]: units disabled,<br/>deadline timer retired
```

| Transition | Trigger | Durable record |
|---|---|---|
| `installed` | `campaign_ctl.py install-k` or `install-u` | The install event in `state/pipeline.json`, the deadline file, the per-run timer |
| `running` | `campaign_ctl.py start k` or `start u` | The systemd unit state |
| `panicked` to `rebooted` to `running` | A kernel fault, then `Restart=always` | Nothing in-process. The corpus and the deadline file carry the run |
| `stopped` | `check-deadline` stops and disables both units | The stop record in the state file |
| `billed` | `measured_run_hours()` over the run's coverage samples | `state/spend.json`, keyed by run id |
| `measured` | `pipeline_ctl.py round-end --from-run` | The round record |
| `retired` | A `--replace` install of another run | The previous run's units disabled and its timer retired |

This pipeline traverses the `rebooted` to `running` edge most often. Every
mechanism on the diagram survives it, because each is either a file on disk or
a systemd unit carrying `OnBootSec`.

## See also

- [Execution model](/gspwn/architecture/execution-model/)
- [Coverage and plateau](/gspwn/architecture/coverage-and-plateau/)
- [Spend accounting](/gspwn/architecture/spend-accounting/)
- [Durability](/gspwn/architecture/durability/)
