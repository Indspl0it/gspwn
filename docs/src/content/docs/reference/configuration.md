---
title: Configuration keys
description: Every configurable value, with its type, accepted values, default, command-line override and consumer.
---

Fifty-two keys in `config/campaign.yaml`, and eleven in `config/machine.yaml`.

## Table columns

Each `config/campaign.yaml` table below carries these seven columns. The
`machine.yaml` table carries six of them and omits Override, because no
validator and no per-invocation flag reads that file.

| Column | Contents |
|---|---|
| Key | Section-qualified, as it is written in prose and in error messages |
| Effect | The behaviour that changes when the value changes |
| Type | `integer`, `number`, `boolean`, `string`, `list of strings`, or a named format |
| Accepted values | The validator's exact bound, or the closed set |
| Default | The built-in default in `DEFAULTS` in `tools/gspwn_config.py`, which applies when the key is absent |
| Override | The per-invocation flag or environment variable that wins over the configured value for one run. An empty cell means the key has no such override and a config edit is the only way to change it |
| Read by | The tool function that reads the key. `sub-agent context only` means no tool reads it: the orchestrator pastes the value into a sub-agent's prompt, and behaviour follows from what that sub-agent does with it |

:::note[Shipped values against built-in defaults]
`config/campaign.yaml` sets two keys away from their built-in defaults:
`track_k.enabled_syscalls` to eight patterns, where the default is an empty
list, and `track_u.targets` to the six harness names `fuzz_ldcache`,
`fuzz_path_resolve`, `fuzz_dsl_evaluate`, `fuzz_options_parse`,
`fuzz_imex_channels` and `fuzz_path_join`, where the default is also an empty
list. Every other shipped value matches its default.
`python3 tools/gspwn_config.py` prints what is in force.
:::

## track_k

The Track K campaign: syzkaller against the instrumented kernel.

| Key | Effect | Type | Accepted values | Default | Override | Read by |
|---|---|---|---|---|---|---|
| `track_k.enabled_syscalls` | The syscall set syz-manager is allowed to generate. Written into the run's `syz-manager.cfg` as `enable_syscalls`. An empty list enables everything syzkaller knows | list of strings | Non-empty strings. A bare scalar reaches syz-manager as a one-character list | `[]` | | `campaign_ctl.cmd_gen_config` |
| `track_k.sandbox` | syzkaller's sandbox mode, which decides the capability set executed programs hold | string | `none`, `setuid`, `namespace`, `android` | `namespace` | | `campaign_ctl.cmd_gen_config` |
| `track_k.procs` | Parallel executor processes per syz-manager. Raises executions per hour and RAM use together | integer | `> 0` | `2` | | `campaign_ctl.cmd_gen_config` |
| `track_k.memory_max` | The systemd `MemoryMax` on `gspwn-k.service`. A syz-manager killed by the cgroup limit restarts, which shows in the curve as a counter reset | systemd byte spec | A number with an optional `K`, `M`, `G` or `T` suffix, or `infinity`. `GB` is not a valid suffix and makes the unit unloadable | `12G` | | `campaign_ctl.cmd_install_k` |
| `track_k.http` | syz-manager's stats endpoint. The coverage sampler derives its address from this key | `host:port` | `host:port`, or a full `http://` URL | `127.0.0.1:56744` | `coverage_ctl.py sample --url`, `coverage_ctl.py install-timer --url` | `campaign_ctl.cmd_gen_config`, `gspwn_config.manager_url` |
| `track_k.smoke_window_minutes` | How long the early-abort check runs. Coverage must increase inside it. The `fuzz` gate is separate | integer | `> 0` | `30` | | sub-agent context only (`fuzz`) |

## track_u

The Track U campaign: harnesses against the NVIDIA Container Toolkit.

| Key | Effect | Type | Accepted values | Default | Override | Read by |
|---|---|---|---|---|---|---|
| `track_u.docker_image` | The image `gspwn-u.service` runs, which is where the harnesses are built and executed | string | Non-empty | `aflplusplus/aflplusplus:v5.02c` | | `campaign_ctl.cmd_install_u` |
| `track_u.memory_max` | The container memory limit and the systemd `MemoryMax` on `gspwn-u.service` | systemd byte spec | As `track_k.memory_max` | `8G` | | `campaign_ctl.cmd_install_u` |
| `track_u.targets` | The harness directory names the `harness` phase produced. Nothing validates that they correspond to real harnesses | list of strings | Non-empty strings | `[]` | | sub-agent context only (`fuzz`) |

## loop

The stopping rules and the round-level policy.

| Key | Effect | Type | Accepted values | Default | Override | Read by |
|---|---|---|---|---|---|---|
| `loop.max_rounds` | The backstop on rounds. Surface completion is the primary stop and is checked first, so a campaign that reaches this cap has failed to converge. A round-cap stop cannot be overridden | integer | `> 0` | `10` | | `pipeline_state.hard_cap_reason` |
| `loop.max_total_run_hours` | The run-hour budget across every campaign, checked against `state/spend.json`. A budget stop cannot be overridden | number | `> 0`, and at least `loop.campaign_hours` | `5000` | | `pipeline_state.hard_cap_reason`, `campaign_ctl.check_budget` |
| `loop.campaign_hours` | How long each campaign runs before its deadline timer stops and disables the units | number | `> 0`, and not above `loop.max_total_run_hours` | `1000` | `campaign_ctl.py install-k --hours`, `campaign_ctl.py install-u --hours` | `campaign_ctl.cmd_install_k`, `campaign_ctl.cmd_install_u` |
| `loop.stop_on_plateau` | Whether a `plateaued` coverage verdict ends the loop | boolean | `true` or `false`, unquoted. A quoted string is truthy and silently keeps the default behaviour | `true` | | `pipeline_state.loop_decision` |
| `loop.plateau_window_min` | The trailing window the fallback growth test measures over, for runs whose coverage source reports no execution count | integer | `> 0`, and at least three `loop.coverage_sample_min` intervals | `240` | `coverage_ctl.py plateau --window-min` | `coverage_ctl.cmd_plateau`, `pipeline_ctl._derive_run` |
| `loop.plateau_min_growth` | The fractional edge growth below which such a run has plateaued. Unused when execution counts are available | number | `0 < v < 1`. `0` would silently disable the plateau stop | `0.02` | `coverage_ctl.py plateau --min-growth` | `coverage_ctl._legacy_window_verdict` |
| `loop.coverage_sample_min` | The coverage sampler's interval, which sets the resolution of every curve a round is measured on | integer | `> 0` | `10` | `coverage_ctl.py install-timer --interval-min` | `coverage_ctl.cmd_install_timer` |
| `loop.corpus_policy` | The default corpus policy for a campaign install. `carry` builds each round on the last; `fresh` starts empty | string | `fresh` or `carry` | `carry` | `campaign_ctl.py install-k --corpus` | `campaign_ctl.cmd_install_k` |
| `loop.promote_seeds` | Whether a finished run's corpus may be promoted into the persistent seed bank. `false` freezes the bank and `promote` refuses | boolean | `true` or `false`, unquoted | `true` | | `corpus_ctl.cmd_promote` |
| `loop.deadline_check_min` | How often the per-run deadline timer asks whether the window is up, and the default heartbeat interval for `wait` | integer | `> 0` | `2` | `campaign_ctl.py wait --poll-min` | `campaign_ctl.install_deadline_timer`, `campaign_ctl.cmd_wait` |
| `loop.min_free_disk_gb` | The free-space floor below which the tools warn. Kernel dumps, the corpus, the coverage CSVs and the agent transcript share one filesystem | number | `>= 0`. `0` disables the check | `20` | | `coverage_ctl.disk_warning`, `orchestrator_ctl.cmd_preflight` |

## orchestrator

The unattended supervisor and its circuit breaker.

| Key | Effect | Type | Accepted values | Default | Override | Read by |
|---|---|---|---|---|---|---|
| `orchestrator.command` | The headless agent invocation the supervisor launches. Empty on purpose: the repository does not guess which coding-agent CLI is installed, and `install` refuses until it is set | string | Any string. Must contain `{session}` when `resume_command` is set | `(none)` | `orchestrator_ctl.py install --command`, `orchestrator_ctl.py run --command` | `orchestrator_ctl.cmd_run`, `orchestrator_ctl.cmd_install` |
| `orchestrator.resume_command` | The invocation for a restart that reuses the previous session, with `{session}` and `{anchor}` substituted. Empty keeps every start fresh | string | Any string. Must contain `{session}` when non-empty | `(none)` | | `orchestrator_ctl.resolve_session` |
| `orchestrator.max_session_mb` | The transcript size at which a session rotates. Size is the rotation rule because size drives auto-compaction | number | `>= 0`. `0` disables the size check | `6` | | `orchestrator_ctl.resolve_session` |
| `orchestrator.session_transcript_glob` | Where the agent's transcript lives, with `{session}` substituted. Empty means the size check cannot run and the tool says so | glob with `{session}` | Any glob containing `{session}`, or empty | `(none)` | | `orchestrator_ctl.transcript_bytes` |
| `orchestrator.max_resumes` | The backstop rotation rule for when the transcript cannot be measured at all | integer | `> 0` | `40` | | `orchestrator_ctl.resolve_session` |
| `orchestrator.window_min` | The window both breaker limits are counted within | integer | `> 0` | `60` | | `orchestrator_ctl.check` |
| `orchestrator.max_same_boot_starts` | Agent starts on one boot within the window before the breaker trips. Repeated starts inside the window indicate that the pipeline is making no progress | integer | `> 0` | `5` | | `orchestrator_ctl.check` |
| `orchestrator.max_reboots` | Distinct boots within the window before the breaker trips. Counted separately because kernel fuzzing panics the box by design | integer | `> 0` | `10` | | `orchestrator_ctl.check` |
| `orchestrator.max_agent_hours` | The wall-clock headroom one agent launch gets beyond the work it waits on, killed by process group. It bounds a stalled launch; the breaker counts starts. `orchestrator_ctl.launch_hours` adds `loop.campaign_hours` for the `fuzz` launch and for no other | number or string | `> 0`, or the string `"unbounded"` to run with no per-launch bound. A number may not exceed `loop.campaign_hours` | `24` | | `orchestrator_ctl.launch_agent` |
| `orchestrator.resume_anchor` | The paragraph substituted for `{anchor}`, telling a resumed agent that its last turn predates the interruption and that `brief` is authoritative | string | Non-empty, containing no apostrophe and no double quote | A paragraph pointing the agent at `pipeline_ctl.py brief` | | `orchestrator_ctl.render_command` |

## agent

The content the tools put in front of the agent.

| Key | Effect | Type | Accepted values | Default | Override | Read by |
|---|---|---|---|---|---|---|
| `agent.brief_knowledge_entries` | Knowledge entries `brief` shows per file. After a panic `brief` is the whole of what a fresh context knows | integer | `> 0` | `3` | `pipeline_ctl.py brief --last` | `pipeline_ctl.cmd_brief` |
| `agent.brief_knowledge_line_chars` | How much of each entry's first line `brief` prints. `knowledge_ctl.py show` always has the full text | integer | `> 0` | `100` | | `pipeline_ctl.cmd_brief` |
| `agent.brief_max_problems` | Integrity problems `brief` lists before deferring to `validate` | integer | `> 0` | `5` | | `pipeline_ctl.cmd_brief` |
| `agent.crash_title_chars` | Crash title width in `crash-list`. Kernel report titles carry the distinguishing part at the end often enough that cutting early makes two bugs share one line | integer | `> 0` | `70` | | `pipeline_ctl.cmd_crash_list` |

## coverage

Seven keys govern the edge curve, whose asymptote is unknown and has to be
extrapolated: `plateau_new_edges`, `horizon_hours`, `model_min_r2`,
`min_fit_samples`, `fit_tail_fraction`, `beta_tolerance` and, for the GPU state
a plateau claim requires, `gpu_probe_timeout_sec`. The remaining three,
`surface_sample_min`, `surface_min_samples` and `unpack_timeout_sec`, govern
the surface curve, whose denominator is counted at 852, and the completion rule
over it sets no percentage threshold.

| Key | Effect | Type | Accepted values | Default | Override | Read by |
|---|---|---|---|---|---|---|
| `coverage.plateau_new_edges` | Expected new edges over one more campaign, below which the run has plateaued. Set it to what would justify another campaign of machine time | integer | `> 0` | `50` | | `coverage_ctl.plateau_verdict` |
| `coverage.horizon_hours` | How far ahead the fitted curve is extrapolated. Matching `loop.campaign_hours` scopes the verdict to exactly one further campaign | number | `> 0` | `1000` | `coverage_ctl.py plateau --horizon-hours` | `coverage_ctl.plateau_verdict` |
| `coverage.model_min_r2` | The fit quality below which no extrapolation is reported and the verdict is `unknown` | number | `0 < v < 1`. `0` would accept any curve and extrapolate from noise | `0.90` | | `coverage_ctl.plateau_verdict` |
| `coverage.min_fit_samples` | Points required inside the fitted tail before extrapolating at all | integer | `>= 3`. A least-squares fit of two points is exact and says nothing about the curve | `8` | | `coverage_ctl.plateau_verdict` |
| `coverage.fit_tail_fraction` | The share of the run's executions the fit covers. Fitting the whole run lets the early steep phase dominate | number | `(0, 1]`, where `1.0` fits the whole run | `0.5` | | `coverage_ctl.fit_tail` |
| `coverage.beta_tolerance` | Slack above a discovery exponent of 1 before the series is judged not to be an accumulation curve | number | `0 <= v < 1` | `0.05` | | `coverage_ctl.plateau_verdict` |
| `coverage.gpu_probe_timeout_sec` | How long to wait for `nvidia-smi` before recording the driver as wedged. A dead GPU fails fast. A hung GPU blocks until this timeout expires | integer | `> 0` | `20` | | `coverage_ctl.gpu_health` |
| `coverage.surface_sample_min` | Minutes between surface samples. The measurement unpacks the run's `corpus.db` and rescans every program, so it runs on a coarser cadence than the other columns. `0` measures it on every coverage sample | integer | `>= 0` | `60` | `GSPWN_SURFACE_SAMPLE_MIN` | `coverage_ctl.surface_sample_min` |
| `coverage.surface_min_samples` | Surface samples required before the second curve's shape is read | integer | `>= 2`. One sample has nothing to be compared against, so the curve would read flat from its first measurement and a still-climbing surface would stop the loop | `5` | `GSPWN_SURFACE_MIN_SAMPLES` | `coverage_ctl.surface_growth` |
| `coverage.unpack_timeout_sec` | Ceiling on one `syz-db unpack` of a run's corpus. Too low and a large healthy corpus reports its surface as unmeasurable, which reads as `surface_verdict=unknown` and blocks the completion stop | integer | `> 0` | `300` | `GSPWN_UNPACK_TIMEOUT_SEC` | `surface_cov.unpack_run_corpus` |

A non-integer value in any of the three environment overrides is refused by
name, so a typo is never read as the configured value.

## poc

The criteria for a reproduction. A disclosure package rests on a `reliable`
classification.

| Key | Effect | Type | Accepted values | Default | Override | Read by |
|---|---|---|---|---|---|---|
| `poc.repro_timeout_sec` | Seconds one reproducer run may take before it counts as a hang. A hang is a hit only for a hang-class crash title | integer | `> 0` | `120` | | `repro_ctl._prepare_k`, `repro_ctl._prepare_u` |
| `poc.reliable_threshold` | The hit rate at or above which a crash is `reliable`. A lower non-zero rate makes it `flaky`. Both are reportable, and the label travels into the report | number | `(0, 1]` | `0.8` | | `repro_ctl._verify_session` |
| `poc.default_runs` | Counted runs `verify` aims for when `--runs` is absent | integer | `> 0` | `10` | `repro_ctl.py verify --runs` | `repro_ctl` argument default |
| `poc.void_retry_factor` | Attempts allowed per still-needed counted run, so a persistently wrapping dmesg ring cannot loop forever. A small fixed slack is added on top | integer | `> 0` | `2` | | `repro_ctl._verify_session` |

## triage

Dedup depth, which decides whether two reports are the same bug and so what
reaches `rca`.

| Key | Effect | Type | Accepted values | Default | Override | Read by |
|---|---|---|---|---|---|---|
| `triage.stack_hash_frames` | Top frames hashed for the secondary dedup key. Fewer merges distinct bugs sharing a caller; more splits one bug whose stack varies by an inlined frame | integer | `> 0` | `3` | | `crash_parse.stack_hash` |
| `triage.signature_frames` | Frames a reproduction must match to count as the same crash | integer | `> 0` | `5` | | `repro_ctl.crash_signature` |
| `triage.frameless_signature_lines` | Report lines forming the fallback signature for a report with no usable stack. Later lines of a trace-less report are usually register dumps | integer | `> 0` | `5` | | `crash_parse.block_signature` |
| `triage.frameless_signature_chars` | How much of that normalised wording is hashed | integer | `>= 32`. Below that the hash covers little more than the report's first few words, and unrelated trace-less panics sharing a prologue would merge | `300` | | `crash_parse.block_signature` |

:::danger[Change dedup depth between campaigns, never during one]
Already registered hashes are not recomputed. The settings in force at the
first registration are stamped into `state/pipeline.json`, and
`pipeline_ctl.py validate` reports the drift.
:::

## machine.yaml

Written by the `provision` phase and pasted into every sub-agent's prompt by
the orchestrator. No tool reads this file, and no validator checks it, so it
carries no accepted-value bound and no override.

| Key | Effect | Type | Accepted values | Default | Read by |
|---|---|---|---|---|---|
| `distro` | The distribution id from `/etc/os-release`, which decides package names | string | Free text, such as `debian` or `kali` | `(none)` | sub-agent context only |
| `environment` | Which crash-capture path applies. `crashlog_ctl.py --env auto` detects the same thing at run time | string | `ec2` or `baremetal` | `(none)` | sub-agent context only |
| `gpu_model` | The card under test, from `nvidia-smi --query-gpu=name` | string | Free text | `(none)` | sub-agent context only |
| `secure_boot` | Whether unsigned out-of-tree modules can load, from `mokutil --sb-state`. Bare metal only | string | `enabled` or `disabled` | `(none)` | sub-agent context only |
| `kernel_version` | The instrumented kernel the `build` phase produced | string | Free text | `(none)` | sub-agent context only |
| `driver_branch` | The `open-gpu-kernel-modules` branch or commit under test, cited in the report as an affected version | string | Free text | `(none)` | sub-agent context only |
| `container_toolkit_version` | The pinned `nvidia-container-toolkit` version the Track U harnesses are built against | string | Free text, such as `1.20.0-1` | `(none)` | sub-agent context only |
| `gsp_firmware` | The GSP firmware version from `nvidia-smi -q`, also written into the build manifest | string | Free text | `(none)` | sub-agent context only |
| `syzkaller_commit` | The pinned syzkaller build, which decides the stats endpoint shape the sampler must handle | string | Free text | `(none)` | sub-agent context only |
| `instrumentation_rung` | Which rung of the degradation ladder the build settled on, which bounds what coverage and KASAN can report | integer | `0` undecided, `1` full KASAN and KCOV, `2` KCOV-only modules, `3` uninstrumented modules | `0` | sub-agent context only |
| `paths.workdir` | The repository-relative artifacts root | string | A repository-relative path | `artifacts` | sub-agent context only |

## Checks that span more than one key

Seven conditions are checked outside the per-key bounds above. Each refuses the
whole configuration.

- `loop.corpus_policy` is `fresh` or `carry`. This refuses a campaign install
  with a policy no code path implements.
- `loop.campaign_hours` does not exceed `loop.max_total_run_hours`. Without it
  a loop spends the whole ceiling on run 1 and stops, because no round could
  finish inside the budget.
- `orchestrator.max_agent_hours`, when it is a number, does not exceed
  `loop.campaign_hours`. A bound longer than a whole campaign fires only after
  the campaign has ended, so it bounds nothing. The `fuzz` launch is the only
  long one and already gets `loop.campaign_hours` added on top of this value.
  `"unbounded"` is the way to run with no bound.
- `loop.plateau_window_min` is at least three `loop.coverage_sample_min`
  intervals. Below that the plateau test never has enough samples, always
  reports `unknown`, and stops the loop.
- `orchestrator.command`, `orchestrator.resume_command` and
  `orchestrator.session_transcript_glob` are strings. A value YAML parsed as
  something else otherwise reaches `subprocess` as whatever it parsed into.
- `orchestrator.session_transcript_glob`, when non-empty, contains
  `{session}`. Without it the size check matches every session's transcript
  and rotates on some other run's history.
- When `orchestrator.resume_command` is set, both it and
  `orchestrator.command` contain `{session}`. Without it a restart silently
  opens a new session while the resume counter believes otherwise.

`orchestrator.resume_anchor` is checked as a per-key bound, not here: it must
contain no apostrophe and no double quote, because it is substituted into a
shell command line the operator has already quoted.

Validation collects every failure before raising, so one run reports the whole
list:

```
error: invalid configuration in config/campaign.yaml:
  - track_k.procs = 0 must be a positive integer
  - loop.plateau_min_growth = 40 must be a fraction between 0 and 1 exclusive (0.02 = 2%; 0 would silently disable the plateau stop)
  - loop.campaign_hours (6000) exceeds loop.max_total_run_hours (5000) — no round could finish inside the budget
```

## Precedence

Three sources supply a value, and the first that carries one decides it.

1. A per-command flag, or the environment variable named in the Override
   column.
2. `config/campaign.yaml`, or the file named by `$GSPWN_CONFIG`.
3. Built-in defaults.

Rank 1 wins, and it applies to one invocation only. A config edit is the
durable change.

## Loading

Seven conditions decide what a load does with the configuration file.

| Condition | Result |
|---|---|
| The file is absent | Every default is in force |
| The file is empty | Every default is in force |
| A top-level scalar or list stands in place of a mapping | Refused |
| A section holds a scalar where a mapping is expected | Refused, naming the section |
| A key is unknown | Refused, naming the section and listing the keys it accepts |
| The file is not valid YAML | Refused, quoting the parser's own message |
| PyYAML is not installed | Refused, naming the package |

```
error: unknown key(s) in loop: loop.max_round. Valid keys here: campaign_hours, corpus_policy, coverage_sample_min, deadline_check_min, max_rounds, max_total_run_hours, min_free_disk_gb, plateau_min_growth, plateau_window_min, promote_seeds, stop_on_plateau
```

```
error: PyYAML is required to read config/campaign.yaml (apt install python3-yaml)
```

`gspwn_config.load` re-reads and re-validates on every call. `gspwn_config.cached`
memoises on the file's path, modification time and size, so an edit between runs
is picked up while crash dedup asking for its frame count once per report block
does not re-parse the file thousands of times per harvest.

`GSPWN_CONFIG` names a different configuration file for one invocation. It is
read once, when `tools/gspwn_config.py` is imported, so it has to be set in the
environment of the command itself.

## Verifying the effective configuration

```
python3 tools/gspwn_config.py
```

Exit code 0 means the configuration is usable. Exit code 1 names the key, the
value and the rule it broke. The command prints the whole effective
configuration as JSON, then one line per group of settings:

```
effective configuration (/path/to/gspwn/config/campaign.yaml):
{
  "agent": {
    "brief_knowledge_entries": 3,
    ...
  }
}

stopping rules: at most 10 round(s) x campaigns of 1000 h, total <= 5000 run-hours
orchestrator: command unset (supervisor not installable); breaker blocks at 5 same-boot start(s) or 10 reboot(s) per 60 min
session resume: off — every restart starts a fresh session
brief carries: 3 knowledge entr(ies) per file at 100 chars, 5 integrity problem(s)
dedup: 3 stack frame(s) hashed, 5 frame(s) matched on repro; with no stack at all, 5 report line(s) cut to 300 chars
plateau: fit the last 50% of executions (>= 8 samples, R2 >= 0.90); plateaued when another 1000 h is expected to find < 50 new edge(s)
surface curve: sampled every 60 min, shape read from >= 5 sample(s), corpus unpack capped at 300s
repro: 10 run(s) by default, 120s per run, reliable at >= 80%
guards: deadline checked every 2 min, agent launch capped at 24 h (fuzz: 1024 h), warn below 20 GB free
```

A tenth line is printed when `coverage.horizon_hours` and
`loop.campaign_hours` differ, because the verdict then answers a different
question from the one the next campaign asks. At the shipped values both are
1000, so it stays silent.

## See also

- [Throughput against depth](/gspwn/guides/tuning-throughput-vs-depth/): which
  of these change conclusions and which change only speed.
