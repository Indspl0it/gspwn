---
title: Configuration
description: A walkthrough of the eight campaign.yaml sections and machine.yaml, in the order a researcher sets them.
---

Every cap, budget, duration and threshold that changes what a campaign does or
concludes lives in `config/campaign.yaml`. `config/machine.yaml` records what
the machine is. Nothing else is keyed in.

The numbered sections follow the order the values are usually set in.
[Configuration keys](/gspwn/reference/configuration/) is the exhaustive table.

## Validating the configuration

```
python3 tools/gspwn_config.py
```

It prints the effective configuration, then the behaviour that configuration
produces, and exits non-zero on a bad value. Run it after every edit. An
unknown key is an error, so a misspelled key fails here and its default never
stays silently in force.

## Precedence

```
built-in defaults  ->  config/campaign.yaml (or $GSPWN_CONFIG)  ->  a per-command flag
```

Omitting a key applies its default. Omitting the whole file applies every
default. A top-level scalar or list in place of a mapping is a malformed
configuration and is refused.

## 1. `loop`: the stopping rules

Set these first. They bound an unattended run, and they are the spend ceiling.

```yaml
loop:
  max_rounds: 10
  max_total_run_hours: 216
  campaign_hours: 24
```

`max_rounds` is a backstop against a runaway loop. Surface completion is the
primary stop and `hard_cap_reason()` checks it first, so a campaign that
reaches this cap has failed to converge and its stop reason says so.
`max_total_run_hours` is the spend ceiling, checked against the spend ledger
and counting every campaign in every round. `campaign_hours` sets the duration
of each campaign before its deadline timer stops it.

A completion, budget or round-cap stop cannot be overridden. `round-decide`
recomputes all three and refuses `--decision continue`.

```yaml
  stop_on_plateau: true
  plateau_window_min: 240
  plateau_min_growth: 0.02
  coverage_sample_min: 10
```

`stop_on_plateau` decides whether a plateau verdict ends the loop.
`coverage_sample_min` is the sampler interval, and it sets the resolution of
every curve the round is measured on. `plateau_window_min` and
`plateau_min_growth` apply only to runs whose coverage source reports no
execution count. Otherwise the verdict comes from the fitted discovery curve
under `coverage`.

```yaml
  corpus_policy: carry
  promote_seeds: true
```

`carry` builds each round on the last one's corpus, and `fresh` starts empty.
`promote_seeds: false` freezes the seed bank, and `corpus_ctl.py promote`
refuses while it is false.

```yaml
  deadline_check_min: 2
  min_free_disk_gb: 20
```

`deadline_check_min` is the cadence of the per-run deadline timer, deliberately
separate from `coverage_sample_min`: raising the sampling interval must not
delay every campaign stop past the window it enforces. `min_free_disk_gb` is
the free-space floor below which the tools warn, and `0` disables the check.

## 2. `track_k`: the Track K campaign

```yaml
track_k:
  enabled_syscalls:
    - "openat$nvidia*"
    - "mmap$nvidia*"
    - "ioctl$NV_*"
    - "ioctl$UVM_*"
  sandbox: "namespace"
  procs: 2
  memory_max: "12G"
  http: "127.0.0.1:56744"
  smoke_window_minutes: 30
```

`enabled_syscalls` is scope. See
[Scope and targets](/gspwn/guides/scope-and-targets/). `sandbox` is syzkaller's
own value, one of `none`, `setuid`, `namespace` or `android`; a name syzkaller
does not know makes syz-manager exit at startup.

`procs` is the number of parallel executor processes and `memory_max` is the
systemd `MemoryMax` on the syz-manager unit. Both trade throughput against the
machine's RAM budget.

`http` is syz-manager's stats endpoint, and the coverage sampler reads its
address from this key, the single place the endpoint is configured. A malformed
value records the whole campaign as `unreachable`. `smoke_window_minutes`
bounds the early-abort check only, and has no effect on the phase gate.

## 3. `track_u`: the Track U campaign

```yaml
track_u:
  docker_image: "aflplusplus/aflplusplus:latest"
  memory_max: "8G"
  targets: []
```

`docker_image` is the image the Track U unit runs, and it is where the
harnesses are built. `targets` is written by the `harness` phase and read by
the `fuzz` phase, and nothing validates that the names correspond to real
harnesses.

## 4. `coverage`: the two curves

These keys determine the campaign's stopping rule. The first six govern the
edge curve, and the three `surface_` keys plus `unpack_timeout_sec` govern the
second one.

```yaml
coverage:
  plateau_new_edges: 50
  horizon_hours: 24
  model_min_r2: 0.90
  min_fit_samples: 8
  fit_tail_fraction: 0.5
  beta_tolerance: 0.05
  gpu_probe_timeout_sec: 20
  surface_sample_min: 60
  surface_min_samples: 5
  unpack_timeout_sec: 300
```

The edge verdict is an extrapolation from a fitted species-accumulation curve. It
answers how many new edges another campaign is expected to find, in the units
of the quantity being predicted.

`plateau_new_edges` is the threshold: below that many expected new edges, the
run has plateaued. `horizon_hours` sets how far ahead the extrapolation reaches and matches
`loop.campaign_hours` by default, since that is the unit of spend the decision
authorises. A mismatch between them makes the verdict answer a different
question than the next campaign asks, and `gspwn_config.py` prints a note when
they differ.

`model_min_r2` is the fit quality below which no extrapolation is reported and
the verdict is `unknown`. `min_fit_samples` sets the number of points needed
before extrapolating. `fit_tail_fraction` is the share of the run's
**executions** the fit covers: fitting the whole run lets the early steep phase
dominate, so a run that rose steeply and then flattened would still report a
high exponent. `beta_tolerance` is the slack above a discovery exponent of 1
before the series is judged not to be an accumulation curve.

`gpu_probe_timeout_sec` bounds `nvidia-smi` before the driver is called wedged.
Track K only, because Track U samples record the GPU column as not applicable.

`surface_sample_min` sets the minutes between surface samples. The
measurement unpacks the run's `corpus.db` and rescans every program in it,
where every other column comes from one HTTP fetch, so it runs on a coarser
cadence. Raise it on a long campaign against a slow volume. Lowering it to `0`
measures the surface on every coverage sample.

`surface_min_samples` is the floor below which the surface curve's shape is not
read, and it moves with the cadence: at 240 minutes a floor of 5 buys most of a
day before the curve says anything. Its minimum is 2, because one sample has
nothing to be compared against.

`unpack_timeout_sec` bounds one `syz-db unpack`. The value it guards grows
through a campaign as the corpus does, and a limit set too low makes a large
healthy corpus report its surface as unmeasurable, which reads as
`surface_verdict=unknown` and blocks the completion stop.

Full derivation: [Coverage and plateau](/gspwn/architecture/coverage-and-plateau/).

## 5. `poc`: reproduction thresholds

```yaml
poc:
  repro_timeout_sec: 120
  reliable_threshold: 0.8
  default_runs: 10
  void_retry_factor: 2
```

`reliable_threshold` is the boundary between a `reliable` and a `flaky`
classification, and a disclosure package is built on that label.
`repro_timeout_sec` bounds how long one run may take before it counts as a
hang, and a hang is a hit only for a crash whose title is hang-class. `default_runs` is the
counted-run target when `--runs` is absent. `void_retry_factor` bounds how many
attempts a still-needed counted run may consume, so a persistently wrapping
dmesg ring cannot loop forever.

## 6. `triage`: dedup depth

```yaml
triage:
  stack_hash_frames: 3
  signature_frames: 5
  frameless_signature_lines: 5
  frameless_signature_chars: 300
```

These decide whether two reports are the same bug, which decides what reaches
`rca` and what the next round targets.

`stack_hash_frames` sets the number of top frames hashed for the secondary
dedup key: fewer merges distinct bugs sharing a caller, more splits one bug whose
stack varies by an inlined frame. `signature_frames` sets the number of frames a
reproduction must match to count as the same crash.

The two `frameless_*` keys govern the fallback identity for a report with no
usable stack at all, a lone `BUG: unable to handle ...` or a trace-less panic.
They bound the prologue wording only, because the faulting function from the
RIP line is always part of the identity and neither knob can drop it.

:::danger[Change dedup depth between campaigns, never during one]
Already registered hashes are not recomputed. Across a mid-campaign change one
bug can register twice and two bugs can merge into one that never reaches
`rca`. The settings in force at the first registration are stamped into
`state/pipeline.json`, and `pipeline_ctl.py validate` reports it when they move
underneath the registry.
:::

## 7. `orchestrator`: the unattended supervisor

```yaml
orchestrator:
  command: ""
  resume_command: ""
  session_transcript_glob: ""
  max_session_mb: 6
  max_resumes: 40
  window_min: 60
  max_same_boot_starts: 5
  max_reboots: 10
  max_agent_hours: 0
  resume_anchor: >-
    ...
```

`command` is the headless agent invocation the supervisor launches. It is empty
on purpose: the repository works with any `AGENTS.md`-aware coding agent and
does not guess which one is installed. `orchestrator_ctl.py install` refuses
until it is set.

`resume_command` carries the previous session across a restart. Empty keeps
every start fresh, which is always correct for the pipeline's position, because
the state file records that position. Setting it also carries the previous
session's reasoning across a panic.

The circuit breaker counts same-boot restarts and reboots separately, against
`max_same_boot_starts` and `max_reboots` within `window_min`. Kernel fuzzing
panics the machine by design, so reboots are expected. Repeated agent restarts
within one boot indicate that nothing is progressing.

Session rotation is primarily by transcript size, `max_session_mb`, measured
through `session_transcript_glob`. `max_resumes` is the backstop for when the
transcript cannot be measured, and the tool reports each fall back to it.

Full behaviour: [Unattended operation](/gspwn/guides/unattended-operation/).

## 8. `agent`: brief content limits

```yaml
agent:
  brief_knowledge_entries: 3
  brief_knowledge_line_chars: 100
  brief_max_problems: 5
  crash_title_chars: 70
```

`pipeline_ctl.py brief` is the resume anchor: after a panic it is the entire
input a fresh context receives. How much it carries is a tuning knob for the
agent's effectiveness. A low value makes the agent re-derive what an earlier
round already settled. A high value spends the context the anchor exists to
conserve.

`crash_title_chars` truncates titles in `crash-list`. Kernel report titles put
the distinguishing part at the end often enough that cutting too early makes
two different bugs look like one line of output.

## 9. `config/machine.yaml`

Filled in by the `provision` sub-agent and pasted into every sub-agent's prompt
by the orchestrator. No tool reads it.

```yaml
distro: ""
environment: ""
gpu_model: ""
secure_boot: ""
kernel_version: ""
driver_branch: ""
gsp_firmware: ""
syzkaller_commit: ""
instrumentation_rung: 0
paths:
  workdir: "artifacts"
```

`environment` is `ec2` or `baremetal`, which decides the crash-capture path.
`instrumentation_rung` is 0 until `build` chooses one, then 1, 2 or 3.

## Cross-field rules

Five conditions are checked across keys. Each one refuses the whole
configuration.

| Rule | Reason |
|---|---|
| `loop.corpus_policy` is `fresh` or `carry` | `campaign_ctl.py install-k` accepts no other value |
| `loop.campaign_hours` does not exceed `loop.max_total_run_hours` | No round could finish inside the budget |
| `orchestrator.max_agent_hours`, when non-zero, exceeds `loop.campaign_hours` | The `fuzz` phase waits out the whole campaign window inside one agent launch, so a shorter timeout kills every healthy agent at the same point in every round |
| `loop.plateau_window_min` covers at least three `loop.coverage_sample_min` intervals | The plateau test needs three samples in the window, and would otherwise always report `unknown`, which stops the loop |
| With `orchestrator.resume_command` set, it and `orchestrator.command` both contain `{session}`, `orchestrator.session_transcript_glob` contains it when set, and `orchestrator.resume_anchor` contains no apostrophe or double quote | The session id is substituted into each invocation, and the anchor is substituted into an already quoted shell command line |

## See also

- [Configuration keys](/gspwn/reference/configuration/): every value, type,
  accepted range, default and consumer.
- [Throughput against depth](/gspwn/guides/tuning-throughput-vs-depth/):
  which knobs change how fast a campaign runs and which change what it
  concludes.
