---
title: gspwn_config.py
description: Reading and validating the effective configuration.
---

The single source of truth for every tunable. Every tool reads its values from
here, so a value cannot drift between the configuration file and the code that
uses it.

## Synopsis

```
python3 tools/gspwn_config.py
```

No subcommands and no flags. Root is never required. It prints the effective
configuration, then the behaviour that configuration produces.

```
effective configuration (/path/to/gspwn/config/campaign.yaml):
{ ... }

stopping rules: at most 3 round(s) x campaigns of 24 h, total <= 216 run-hours
orchestrator: command unset (supervisor not installable); breaker blocks at 5 same-boot start(s) or 10 reboot(s) per 60 min
session resume: off — every restart starts a fresh session
brief carries: 3 knowledge entr(ies) per file at 100 chars, 5 integrity problem(s)
dedup: 3 stack frame(s) hashed, 5 frame(s) matched on repro; with no stack at all, 5 report line(s) cut to 300 chars
plateau: fit the last 50% of executions (>= 8 samples, R2 >= 0.90); plateaued when another 24 h is expected to find < 50 new edge(s)
repro: 10 run(s) by default, 120s per run, reliable at >= 80%
guards: deadline checked every 2 min, agent launch capped at no limit, warn below 20 GB free
```

## Configuration file

`config/campaign.yaml`, or the file named by `GSPWN_CONFIG`.

| Condition | Result |
|---|---|
| The file is absent | Every default is in force |
| The file is empty | Every default is in force |
| A top-level scalar or list stands in place of a mapping | Refused |
| PyYAML is missing | Reported as a message naming the package |

```
error: PyYAML is required to read config/campaign.yaml (apt install python3-yaml)
```

## Unknown keys

```
error: unknown key(s) in loop: loop.max_round. Valid keys here: campaign_hours, coverage_sample_min, corpus_policy, deadline_check_min, max_rounds, max_total_run_hours, min_free_disk_gb, plateau_min_growth, plateau_window_min, promote_seeds, stop_on_plateau
```

A misspelled key fails loudly, so the default cannot stay silently in force.

## Aggregated validation errors

Validation collects every failure before raising, so one run reports the whole
list:

```
error: invalid configuration in config/campaign.yaml:
  - track_k.procs = 0 must be a positive integer
  - loop.plateau_min_growth = 40 must be a fraction between 0 and 1 exclusive (0.02 = 2%; 0 would silently disable the plateau stop)
  - loop.campaign_hours (240) exceeds loop.max_total_run_hours (216) — no round could finish inside the budget
```

## The horizon note

```
  note: horizon 48 h differs from loop.campaign_hours 24 h, so the verdict answers a different question than the one the next campaign asks
```

Printed when `coverage.horizon_hours` and `loop.campaign_hours` differ. It is a
note, and the configuration remains valid: the mismatch is legitimate when the
extrapolation deliberately asks about a different span.

## Module API

| Function | Returns |
|---|---|
| `load(path=None)` | The whole effective configuration, validated. Raises `ConfigError` |
| `cached(path=None)` | The same, memoised until the file changes on disk |
| `loop()`, `agent()`, `triage()`, `coverage()`, `poc()` | One section each |
| `manager_url()` | The syz-manager base URL derived from `track_k.http` |
| `validate(cfg)` | The configuration, or raises `ConfigError` listing every problem |

`load` re-reads and re-validates. `cached` memoises on the file's path,
modification time and size, so an edit between runs is picked up. Crash dedup
asks for its frame count once per report block, and the memo keeps that from
re-parsing the file thousands of times per harvest.

`manager_url` is derived here and read by the sampler, so a port change in the
configuration cannot leave the sampler polling a stale address and recording
the whole campaign as unreachable.

## Tool behaviour on a broken configuration

| Tool | Behaviour |
|---|---|
| `pipeline_ctl.py` loop caps and agent settings | Exits. This loop spends machine time unattended, and a guessed cap is unacceptable |
| `pipeline_ctl.py validate` dedup drift check | Skips the drift check and still reports on the registry |
| `coverage_ctl.py` plateau tunables | Falls back to the shipped defaults, because several other tools call the verdict path |
| `repro_ctl.py` reproduction tunables | Falls back to the shipped defaults, so verification still runs on a box whose configuration is mid-edit |
| `orchestrator_ctl.py` resume anchor | Falls back to the module default, because this runs on the post-panic recovery path |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The configuration is usable |
| 1 | A value was rejected. The message names the key, the value and the rule |

## Files

| Path | Contents |
|---|---|
| `config/campaign.yaml` | The configuration file, or the path in `GSPWN_CONFIG` |

## See also

- [Configuration keys](/gspwn/reference/configuration/)
- [Configuration](/gspwn/guides/configuration/)
