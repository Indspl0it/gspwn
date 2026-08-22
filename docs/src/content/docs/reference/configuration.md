---
title: Configuration keys
description: Every configurable value, with its type, accepted values, default and consumer.
---

Fifty-nine keys, across `config/campaign.yaml` and `config/machine.yaml`.

## Table columns

Every key table below carries these six columns.

| Column | Contents |
|---|---|
| Key | Section-qualified, as it is written in prose and in error messages |
| Effect | The behaviour that changes when the value changes |
| Type | `integer`, `number`, `boolean`, `string`, `list of strings`, or a named format |
| Accepted values | The validator's exact bound, or the closed set |
| Default | The built-in default, which applies when the key is absent |
| Read by | The tool function that reads the key. `sub-agent context only` means no tool reads it: the orchestrator pastes the value into a sub-agent's prompt, and behaviour follows from what that sub-agent does with it |

:::note[Shipped values against built-in defaults]
`config/campaign.yaml` sets `track_k.enabled_syscalls` to four patterns, where
the built-in default is an empty list. Every other shipped value matches its
default. `python3 tools/gspwn_config.py` prints what is in force.
:::

## track_k

The Track K campaign: syzkaller against the instrumented kernel.

| Key | Effect | Type | Accepted values | Default | Read by |
|---|---|---|---|---|---|
| `track_k.enabled_syscalls` | The syscall set syz-manager is allowed to generate. Written into the run's `syz-manager.cfg` as `enable_syscalls`. An empty list enables everything syzkaller knows | list of strings | Non-empty strings. A bare scalar reaches syz-manager as a one-character list | `[]` | `campaign_ctl.cmd_gen_config` |
| `track_k.sandbox` | syzkaller's sandbox mode, which decides the capability set executed programs hold | string | `none`, `setuid`, `namespace`, `android` | `namespace` | `campaign_ctl.cmd_gen_config` |
| `track_k.procs` | Parallel executor processes per syz-manager. Raises executions per hour and RAM use together | integer | `> 0` | `2` | `campaign_ctl.cmd_gen_config` |
| `track_k.memory_max` | The systemd `MemoryMax` on `gspwn-k.service`. A syz-manager killed by the cgroup limit restarts, which shows in the curve as a counter reset | systemd byte spec | A number with an optional `K`, `M`, `G` or `T` suffix, or `infinity`. `GB` is not a valid suffix and makes the unit unloadable | `12G` | `campaign_ctl.cmd_install_k` |
| `track_k.http` | syz-manager's stats endpoint. The coverage sampler derives its address from this key | `host:port` | `host:port`, or a full `http://` URL | `127.0.0.1:56744` | `campaign_ctl.cmd_gen_config`, `gspwn_config.manager_url` |
| `track_k.smoke_window_minutes` | How long the early-abort check runs. Coverage must increase inside it. The `fuzz` gate is separate | integer | `> 0` | `30` | sub-agent context only (`fuzz`) |

## track_u

The Track U campaign: harnesses against the NVIDIA Container Toolkit.

| Key | Effect | Type | Accepted values | Default | Read by |
|---|---|---|---|---|---|
| `track_u.docker_image` | The image `gspwn-u.service` runs, which is where the harnesses are built and executed | string | Non-empty | `aflplusplus/aflplusplus:latest` | `campaign_ctl.cmd_install_u` |
| `track_u.memory_max` | The container memory limit and the systemd `MemoryMax` on `gspwn-u.service` | systemd byte spec | As `track_k.memory_max` | `8G` | `campaign_ctl.cmd_install_u` |
| `track_u.targets` | The harness directory names the `harness` phase produced. Nothing validates that they correspond to real harnesses | list of strings | Non-empty strings | `[]` | sub-agent context only (`fuzz`) |

## loop

The stopping rules and the round-level policy.

| Key | Effect | Type | Accepted values | Default | Read by |
|---|---|---|---|---|---|
| `loop.max_rounds` | The backstop on rounds. Surface completion is the primary stop and is checked first, so a campaign that reaches this cap has failed to converge. A round-cap stop cannot be overridden | integer | `> 0` | `10` | `pipeline_state.hard_cap_reason` |
| `loop.max_total_run_hours` | The run-hour budget across every campaign, checked against `state/spend.json`. A budget stop cannot be overridden | number | `> 0`, and at least `loop.campaign_hours` | `216` | `pipeline_state.hard_cap_reason`, `campaign_ctl.check_budget` |
| `loop.campaign_hours` | How long each campaign runs before its deadline timer stops and disables the units | number | `> 0`, and not above `loop.max_total_run_hours` | `24` | `campaign_ctl.cmd_install_k`, `campaign_ctl.cmd_install_u` |
| `loop.stop_on_plateau` | Whether a `plateaued` coverage verdict ends the loop | boolean | `true` or `false`, unquoted. A quoted string is truthy and silently keeps the default behaviour | `true` | `pipeline_state.loop_decision` |
| `loop.plateau_window_min` | The trailing window the fallback growth test measures over, for runs whose coverage source reports no execution count | integer | `> 0`, and at least three `loop.coverage_sample_min` intervals | `240` | `coverage_ctl.cmd_plateau`, `pipeline_ctl._derive_run` |
| `loop.plateau_min_growth` | The fractional edge growth below which such a run has plateaued. Unused when execution counts are available | number | `0 < v < 1`. `0` would silently disable the plateau stop | `0.02` | `coverage_ctl._legacy_window_verdict` |
| `loop.coverage_sample_min` | The coverage sampler's interval, which sets the resolution of every curve a round is measured on | integer | `> 0` | `10` | `coverage_ctl.cmd_install_timer` |
| `loop.corpus_policy` | The default corpus policy for a campaign install. `carry` builds each round on the last; `fresh` starts empty | string | `fresh` or `carry` | `carry` | `campaign_ctl.cmd_install_k` |
| `loop.promote_seeds` | Whether a finished run's corpus may be promoted into the persistent seed bank. `false` freezes the bank and `promote` refuses | boolean | `true` or `false`, unquoted | `true` | `corpus_ctl.cmd_promote` |
| `loop.deadline_check_min` | How often the per-run deadline timer asks whether the window is up, and the default heartbeat interval for `wait` | integer | `> 0` | `2` | `campaign_ctl.install_deadline_timer`, `campaign_ctl.cmd_wait` |
| `loop.min_free_disk_gb` | The free-space floor below which the tools warn. Kernel dumps, the corpus, the coverage CSVs and the agent transcript share one filesystem | number | `>= 0`. `0` disables the check | `20` | `coverage_ctl.disk_warning`, `orchestrator_ctl.cmd_preflight` |

## orchestrator

The unattended supervisor and its circuit breaker.

| Key | Effect | Type | Accepted values | Default | Read by |
|---|---|---|---|---|---|
| `orchestrator.command` | The headless agent invocation the supervisor launches. Empty on purpose: the repository does not guess which coding-agent CLI is installed, and `install` refuses until it is set | string | Any string. Must contain `{session}` when `resume_command` is set | `(none)` | `orchestrator_ctl.cmd_run`, `orchestrator_ctl.cmd_install` |
| `orchestrator.resume_command` | The invocation for a restart that reuses the previous session, with `{session}` and `{anchor}` substituted. Empty keeps every start fresh | string | Any string. Must contain `{session}` when non-empty | `(none)` | `orchestrator_ctl.resolve_session` |
| `orchestrator.max_session_mb` | The transcript size at which a session rotates. Size is the rotation rule because size drives auto-compaction | number | `>= 0`. `0` disables the size check | `6` | `orchestrator_ctl.resolve_session` |
| `orchestrator.session_transcript_glob` | Where the agent's transcript lives, with `{session}` substituted. Empty means the size check cannot run and the tool says so | glob with `{session}` | Any glob containing `{session}`, or empty | `(none)` | `orchestrator_ctl.transcript_bytes` |
| `orchestrator.max_resumes` | The backstop rotation rule for when the transcript cannot be measured at all | integer | `> 0` | `40` | `orchestrator_ctl.resolve_session` |
| `orchestrator.window_min` | The window both breaker limits are counted within | integer | `> 0` | `60` | `orchestrator_ctl.check` |
| `orchestrator.max_same_boot_starts` | Agent starts on one boot within the window before the breaker trips. Repeated starts inside the window indicate that the pipeline is making no progress | integer | `> 0` | `5` | `orchestrator_ctl.check` |
| `orchestrator.max_reboots` | Distinct boots within the window before the breaker trips. Counted separately because kernel fuzzing panics the box by design | integer | `> 0` | `10` | `orchestrator_ctl.check` |
| `orchestrator.max_agent_hours` | The wall-clock ceiling on one agent launch, killed by process group. It bounds a stalled launch; the breaker counts starts | number | `>= 0`. `0` disables it. When non-zero it must exceed `loop.campaign_hours` | `0` | `orchestrator_ctl.launch_agent` |
| `orchestrator.resume_anchor` | The paragraph substituted for `{anchor}`, telling a resumed agent that its last turn predates the interruption and that `brief` is authoritative | string | Non-empty, containing no apostrophe and no double quote | A paragraph pointing the agent at `pipeline_ctl.py brief` | `orchestrator_ctl.render_command` |

## agent

The content the tools put in front of the agent.

| Key | Effect | Type | Accepted values | Default | Read by |
|---|---|---|---|---|---|
| `agent.brief_knowledge_entries` | Knowledge entries `brief` shows per file. After a panic `brief` is the whole of what a fresh context knows | integer | `> 0` | `3` | `pipeline_ctl.cmd_brief` |
| `agent.brief_knowledge_line_chars` | How much of each entry's first line `brief` prints. `knowledge_ctl.py show` always has the full text | integer | `> 0` | `100` | `pipeline_ctl.cmd_brief` |
| `agent.brief_max_problems` | Integrity problems `brief` lists before deferring to `validate` | integer | `> 0` | `5` | `pipeline_ctl.cmd_brief` |
| `agent.crash_title_chars` | Crash title width in `crash-list`. Kernel report titles carry the distinguishing part at the end often enough that cutting early makes two bugs share one line | integer | `> 0` | `70` | `pipeline_ctl.cmd_crash_list` |

## coverage

How the two curves are read. The campaign's stopping rule rests on these
numbers. The first six govern the edge curve, whose asymptote is unknown and
has to be extrapolated. The last three govern the surface curve, whose
denominator is counted at 764, and the completion rule over it invents no
percentage threshold.

| Key | Effect | Type | Accepted values | Default | Read by |
|---|---|---|---|---|---|
| `coverage.plateau_new_edges` | Expected new edges over one more campaign, below which the run has plateaued. Set it to what would justify another campaign of machine time | integer | `> 0` | `50` | `coverage_ctl.plateau_verdict` |
| `coverage.horizon_hours` | How far ahead the fitted curve is extrapolated. Matching `loop.campaign_hours` scopes the verdict to exactly one further campaign | number | `> 0` | `24` | `coverage_ctl.plateau_verdict` |
| `coverage.model_min_r2` | The fit quality below which no extrapolation is reported and the verdict is `unknown` | number | `0 < v < 1`. `0` would accept any curve and extrapolate from noise | `0.90` | `coverage_ctl.plateau_verdict` |
| `coverage.min_fit_samples` | Points required inside the fitted tail before extrapolating at all | integer | `>= 3`. A least-squares fit of two points is exact and says nothing about the curve | `8` | `coverage_ctl.plateau_verdict` |
| `coverage.fit_tail_fraction` | The share of the run's **executions** the fit covers. Fitting the whole run lets the early steep phase dominate | number | `(0, 1]`, where `1.0` fits the whole run | `0.5` | `coverage_ctl.fit_tail` |
| `coverage.beta_tolerance` | Slack above a discovery exponent of 1 before the series is judged not to be an accumulation curve | number | `0 <= v < 1` | `0.05` | `coverage_ctl.plateau_verdict` |
| `coverage.gpu_probe_timeout_sec` | How long to wait for `nvidia-smi` before recording the driver as wedged. A dead GPU fails fast. A hung GPU blocks until this timeout expires | integer | `> 0` | `20` | `coverage_ctl.gpu_health` |
| `coverage.surface_sample_min` | Minutes between surface samples. The measurement unpacks the run's `corpus.db` and rescans every program, so it runs on a coarser cadence than the other columns. `0` measures it on every coverage sample | integer | `>= 0` | `60` | `coverage_ctl.surface_sample_min` |
| `coverage.surface_min_samples` | Surface samples required before the second curve's shape is read | integer | `>= 2`. One sample has nothing to be compared against, so the curve would read flat from its first measurement and a still-climbing surface would stop the loop | `5` | `coverage_ctl.surface_growth` |
| `coverage.unpack_timeout_sec` | Ceiling on one `syz-db unpack` of a run's corpus. Too low and a large healthy corpus reports its surface as unmeasurable, which reads as `surface_verdict=unknown` and blocks the completion stop | integer | `> 0` | `300` | `surface_cov.unpack_run_corpus` |

## poc

The criteria for a reproduction. A disclosure package is built on a `reliable`
classification.

| Key | Effect | Type | Accepted values | Default | Read by |
|---|---|---|---|---|---|
| `poc.repro_timeout_sec` | Seconds one reproducer run may take before it counts as a hang. A hang is a hit only for a hang-class crash title | integer | `> 0` | `120` | `repro_ctl._prepare_k`, `repro_ctl._prepare_u` |
| `poc.reliable_threshold` | The hit rate at or above which a crash is `reliable`. A lower non-zero rate makes it `flaky`. Both are reportable, and the label travels into the report | number | `(0, 1]` | `0.8` | `repro_ctl._verify_session` |
| `poc.default_runs` | Counted runs `verify` aims for when `--runs` is absent | integer | `> 0` | `10` | `repro_ctl` argument default |
| `poc.void_retry_factor` | Attempts allowed per still-needed counted run, so a persistently wrapping dmesg ring cannot loop forever. A small fixed slack is added on top | integer | `> 0` | `2` | `repro_ctl._verify_session` |

## triage

Dedup depth. These decide whether two reports are the same bug, which decides
what reaches `rca`.

| Key | Effect | Type | Accepted values | Default | Read by |
|---|---|---|---|---|---|
| `triage.stack_hash_frames` | Top frames hashed for the secondary dedup key. Fewer merges distinct bugs sharing a caller; more splits one bug whose stack varies by an inlined frame | integer | `> 0` | `3` | `crash_parse.stack_hash` |
| `triage.signature_frames` | Frames a reproduction must match to count as the same crash | integer | `> 0` | `5` | `repro_ctl.crash_signature` |
| `triage.frameless_signature_lines` | Report lines forming the fallback signature for a report with no usable stack. Later lines of a trace-less report are usually register dumps | integer | `> 0` | `5` | `crash_parse.block_signature` |
| `triage.frameless_signature_chars` | How much of that normalised wording is hashed | integer | `>= 32`. Below that the hash covers little more than the report's first few words, and unrelated trace-less panics sharing a prologue would merge | `300` | `crash_parse.block_signature` |

:::danger[Change dedup depth between campaigns, never during one]
Already registered hashes are not recomputed. The settings in force at the
first registration are stamped into `state/pipeline.json`, and
`pipeline_ctl.py validate` reports the drift.
:::

## machine.yaml

Written by the `provision` phase and pasted into every sub-agent's prompt by
the orchestrator. No tool reads this file, and no validator checks it.

| Key | Effect | Type | Accepted values | Default | Read by |
|---|---|---|---|---|---|
| `distro` | The distribution id from `/etc/os-release`, which decides package names | string | Free text, e.g. `debian`, `kali` | `(none)` | sub-agent context only |
| `environment` | Which crash-capture path applies. `crashlog_ctl.py --env auto` detects the same thing at run time | string | `ec2` or `baremetal` | `(none)` | sub-agent context only |
| `gpu_model` | The card under test, from `nvidia-smi --query-gpu=name` | string | Free text | `(none)` | sub-agent context only |
| `secure_boot` | Whether unsigned out-of-tree modules can load, from `mokutil --sb-state`. Bare metal only | string | `enabled` or `disabled` | `(none)` | sub-agent context only |
| `kernel_version` | The instrumented kernel the `build` phase produced | string | Free text | `(none)` | sub-agent context only |
| `driver_branch` | The `open-gpu-kernel-modules` branch or commit under test, cited in the report as an affected version | string | Free text | `(none)` | sub-agent context only |
| `gsp_firmware` | The GSP firmware version from `nvidia-smi -q`, also written into the build manifest | string | Free text | `(none)` | sub-agent context only |
| `syzkaller_commit` | The pinned syzkaller build, which decides the stats endpoint shape the sampler must handle | string | Free text | `(none)` | sub-agent context only |
| `instrumentation_rung` | Which rung of the degradation ladder the build settled on, which bounds what coverage and KASAN can report | integer | `0` undecided, `1` full KASAN and KCOV, `2` KCOV-only modules, `3` uninstrumented modules | `0` | sub-agent context only |
| `paths.workdir` | The repository-relative artifacts root | string | A repository-relative path | `artifacts` | sub-agent context only |

## Cross-field rules

Five conditions are checked across keys. Each refuses the whole configuration.

| Rule | Condition | Failure prevented |
|---|---|---|
| 1 | `loop.corpus_policy` is `fresh` or `carry` | A campaign install with a policy no code path implements |
| 2 | `loop.campaign_hours` does not exceed `loop.max_total_run_hours` | A loop that spends the whole ceiling on run 1 and stops, because no round could finish inside the budget |
| 3 | `orchestrator.max_agent_hours`, when non-zero, exceeds `loop.campaign_hours` | Every healthy agent being killed at the same point in every round, because the `fuzz` phase waits out the whole campaign window inside one launch |
| 4 | `loop.plateau_window_min` is at least three `loop.coverage_sample_min` intervals | A plateau test that never has enough samples and always reports `unknown`, which stops the loop |
| 5 | When `orchestrator.resume_command` is set, both it and `orchestrator.command` contain `{session}`; `orchestrator.session_transcript_glob` contains it when non-empty; `orchestrator.resume_anchor` contains no apostrophe or double quote | A restart that silently opens a new session while the resume counter believes otherwise, a size check that measures some other run's transcript, and a quote that ends the operator's shell quoting |

## Precedence

| Rank | Source |
|---|---|
| 1 | A per-command flag |
| 2 | `config/campaign.yaml`, or the file named by `$GSPWN_CONFIG` |
| 3 | Built-in defaults |

Rank 1 wins. An empty configuration file leaves every default in force. A
top-level scalar or list in place of a mapping is refused.

An unknown key is an error. A misspelled key fails at load time, and the error
names the section and lists the keys that section accepts:

```
error: unknown key(s) in loop: loop.max_round. Valid keys here: campaign_hours, coverage_sample_min, corpus_policy, deadline_check_min, max_rounds, max_total_run_hours, min_free_disk_gb, plateau_min_growth, plateau_window_min, promote_seeds, stop_on_plateau
```

## Verifying the effective configuration

```
python3 tools/gspwn_config.py
```

Exit code 0 means the configuration is usable. Non-zero names the key, the
value and the rule it broke.

```
effective configuration (/path/to/gspwn/config/campaign.yaml):
{
  "agent": {
    "brief_knowledge_entries": 3,
    ...
  }
}

stopping rules: at most 3 round(s) x campaigns of 24 h, total <= 216 run-hours
orchestrator: command unset (supervisor not installable); breaker blocks at 5 same-boot start(s) or 10 reboot(s) per 60 min
session resume: off — every restart starts a fresh session
brief carries: 3 knowledge entr(ies) per file at 100 chars, 5 integrity problem(s)
dedup: 3 stack frame(s) hashed, 5 frame(s) matched on repro; with no stack at all, 5 report line(s) cut to 300 chars
plateau: fit the last 50% of executions (>= 8 samples, R2 >= 0.90); plateaued when another 24 h is expected to find < 50 new edge(s)
repro: 10 run(s) by default, 120s per run, reliable at >= 80%
guards: deadline checked every 2 min, agent launch capped at no limit, warn below 20 GB free
```

## Environment overrides

| Variable | Effect |
|---|---|
| `GSPWN_CONFIG` | Names a different configuration file. See [Environment variables](/gspwn/reference/environment/) |

## See also

- [Configuration](/gspwn/guides/configuration/): the same keys as a
  walkthrough.
- [Throughput against depth](/gspwn/guides/tuning-throughput-vs-depth/): which
  of these change conclusions and which change only speed.
