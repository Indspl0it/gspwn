---
title: Quickstart
description: Verify a gspwn checkout on a machine with no GPU, in four commands.
sidebar:
  order: 4
---

Every command here runs offline: no GPU, no kernel build, no root, no network.
Run them after [Installation](/gspwn/getting-started/installation/) and before
a machine is committed to a campaign.

## 1. Verify the tools

```
python3 tools/selftest.py
```

The suite exercises the state machine, the configuration validator, the crash
dedup, the coverage model, the spend ledger and the systemd unit generation. It
prints `OK` and exits 0 when everything passes. On a failure it prints the
failing case and exits non-zero.

`AGENTS.md` requires this run after any change to the tools, and
`.github/workflows/selftest.yml` runs it on every push and pull request.

## 2. Check the shipped configuration

```
python3 tools/gspwn_config.py
```

It prints the effective configuration as JSON, then the behaviour that
configuration produces:

```
stopping rules: at most 3 round(s) x campaigns of 24 h, total <= 216 run-hours
orchestrator: command unset (supervisor not installable); breaker blocks at 5 same-boot start(s) or 10 reboot(s) per 60 min
session resume: off — every restart starts a fresh session
brief carries: 3 knowledge entr(ies) per file at 100 chars, 5 integrity problem(s)
dedup: 3 stack frame(s) hashed, 5 frame(s) matched on repro; with no stack at all, 5 report line(s) cut to 300 chars
plateau: fit the last 50% of executions (>= 8 samples, R2 >= 0.90); plateaued when another 24 h is expected to find < 50 new edge(s)
repro: 10 run(s) by default, 120s per run, reliable at >= 80%
guards: deadline checked every 2 min, agent launch capped at no limit, warn below 20 GB free
```

Exit code 0 means the configuration is usable. Non-zero means a value was
rejected, and the message names the key, the value and the rule it broke. An
unknown key is an error, so a misspelled key fails here and never leaves its
default silently in force.

Full key list: [Configuration keys](/gspwn/reference/configuration/).

## 3. Create a state file

```
python3 tools/pipeline_ctl.py init
python3 tools/pipeline_ctl.py show
```

`show` prints the phase table, the position in the loop and the crash summary:

```
pipeline: /path/to/gspwn/state/pipeline.json
round 1 of max 3 (0.0 run-hours of 216 used)
  . provision  pending
  . build      pending
  . describe   pending
  . seeds      pending
  . harness    pending
  . fuzz       pending
  . triage     pending
  . rca        pending
  . poc        pending
  . eval       pending
  . refine     pending
  . report     pending
next: run phase provision
crashes: none registered
```

The leading mark on each row is the phase status.

| Mark | Status |
|---|---|
| `.` | pending |
| `>` | in progress |
| `+` | done |
| `!` | blocked or failed |

## 4. Query the next phase

```
python3 tools/pipeline_ctl.py next
```

```
provision
```

`next` prints a phase name, or `wait`, `decide`, `advance-round` or
`complete`. The orchestrator reads it at the top of every cycle. The value is
derived from the state file, so it cannot disagree with the recorded state.

## State file validation

```
python3 tools/pipeline_ctl.py validate
```

```
state is consistent
```

`validate` reports integrity problems and exits 1 when it finds any: a phase
marked done ahead of its dependency, a duplicate with no link to a surviving
entry, a crash analysed by `rca` with no research record, an impact record
whose consequence outruns its primitive, or dedup settings that moved
underneath the registry's stored hashes.

## Session recovery

```
python3 tools/pipeline_ctl.py brief
```

`brief` is the derived handoff: the pipeline position, the blocked phases, the
contents of the crash registry, the targets the findings name, and the tail of
`knowledge/`. On a fresh state file the output is short:

```
# gspwn brief — generated 2026-08-15T15:31:31+00:00
Derived from state/pipeline.json at read time. Re-run it rather than trusting a copy;
nothing here is authoritative once the state file moves on.

## Where the pipeline is
round 1 of max 3, 0.0 of 216 run-hours spent
next action: run phase provision (see agents/provision.md)

## Crashes
none registered

## Findings (what steers the next round)
none recorded — the loop can only steer on coverage

## Impact (what the report can argue)
none assessed — the report would carry reproducers with no argued severity
```

`brief` is computed at read time and cannot be stale. A stored copy goes out of
date the moment the pipeline moves, so re-run the command at each handoff.

## Scratch state file

`GSPWN_STATE` redirects the state file, which allows experiments that leave a
real campaign's registry untouched:

```
GSPWN_STATE=/tmp/scratch/pipeline.json python3 tools/pipeline_ctl.py init
```

The spend ledger does not follow `GSPWN_STATE`. A run with its own state file
still bills the one machine-global budget. See
[Environment variables](/gspwn/reference/environment/).

## Next

- [Your first campaign](/gspwn/getting-started/first-campaign/) runs round 1 on
  real hardware.
- [Command line overview](/gspwn/reference/cli/) lists every tool.
