---
title: pipeline_ctl.py
description: Every subcommand and flag of the pipeline state machine driver.
---

Drives `state/pipeline.json`. Every write is atomic, locked and validated.

## Synopsis

```
python3 tools/pipeline_ctl.py <subcommand> [options]
```

Root is never required.

## init

Creates `state/pipeline.json`.

```
python3 tools/pipeline_ctl.py init [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--force` | None | Off | Overwrite an existing state file, discarding the crash registry and the round history |

Idempotent. Against an existing file it reports what is there and writes
nothing.

## show

Prints the phase table, the loop position, the crash summary and an integrity
count.

```
python3 tools/pipeline_ctl.py show [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--json` | None | Off | Print the whole state file |

| Mark | Phase status |
|---|---|
| `.` | pending |
| `>` | in progress |
| `+` | done |
| `!` | blocked or failed |

## next

Prints what to do next, as one of a phase name, `wait`, `decide`,
`advance-round` or `complete`.

```
python3 tools/pipeline_ctl.py next
```

`wait` is returned while a campaign in this round is still inside its window,
and names the run and the hours left. The `fuzz` phase is exempt, because it is
what starts the campaign.

## set-phase

Sets one phase's status and its note.

```
python3 tools/pipeline_ctl.py set-phase <phase> <status> [--notes TEXT]
```

| Argument | Accepted values |
|---|---|
| `phase` | `provision`, `build`, `describe`, `seeds`, `harness`, `fuzz`, `triage`, `rca`, `poc`, `eval`, `refine`, `report` |
| `status` | `pending`, `in_progress`, `done`, `blocked`, `failed` |

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--notes` | `TEXT` | Empty | Free text describing this status change |

Notes are replaced on each status change, so a stale note cannot survive onto a
later status.

## crash-list

Prints the crash registry, filtered.

```
python3 tools/pipeline_ctl.py crash-list [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--status` | `unique`, `duplicate`, `flagged`, `reliable`, `flaky`, `unreproducible`, `rca_done`, `reported` | All | Filter by status |
| `--track` | `K`, `U` | Both | Filter by track |
| `--signal` | `signal`, `review`, `health`, `noise`, `unclassified` | All | Filter by Xid classification |
| `--json` | None | Off | Print the matching entries as JSON |

Titles are truncated to `agent.crash_title_chars`.

## crash-set

Edits one or more registry entries.

```
python3 tools/pipeline_ctl.py crash-set CRASH_ID [CRASH_ID ...] [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--status` | One of the crash statuses above | Unchanged | Set the status |
| `--duplicate-of` | `ID` or `none` | Unchanged | Link to the surviving entry and set the status to `duplicate`. `none` clears the link and returns the crash to the unique queue |
| `--disclosure` | `pending`, `submitted`, `resolved`, `not_applicable` | Unchanged | Set the disclosure status |
| `--repro-rate` | `F` | Unchanged | A float between 0.0 and 1.0 |
| `--notes` | `TEXT` | Unchanged | Replace the entry's notes. `--notes ''` clears them |

Several ids apply the same edit to each. The call is all-or-nothing: a rejected
id aborts the transaction, so a queue is never left half-decided.

| Condition | Result |
|---|---|
| `--duplicate-of` combined with `--status` | Refused |
| The link target is itself a duplicate | Refused, so chains and cycles cannot form |

## brief

Prints the derived handoff for a fresh or compacted session.

```
python3 tools/pipeline_ctl.py brief [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--last` | `N` | `agent.brief_knowledge_entries` | Knowledge entries per file |

## finding-set

Attaches a research record to a crash.

```
python3 tools/pipeline_ctl.py finding-set <crash-id> --json PATH
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--json` | `PATH` or `-` | Required | Read the record from a file, or from standard input for `-` |

Fields: `subsystem` (required), `bug_class`, `trigger`, `ioctls[]`,
`preconditions[]`, `adjacent[]`, `source_refs[]`, `hypothesis`, `confidence`,
`no_adjacent_reason`. Vocabularies are listed in
[Closed vocabularies](/gspwn/reference/vocabularies/).

| Condition | Result |
|---|---|
| The record carries an unknown field | Refused |
| The record names no `subsystem` | Refused |
| The record carries none of `ioctls`, `preconditions` or `adjacent` | Refused |

## finding-list

Prints the research records, filtered.

```
python3 tools/pipeline_ctl.py finding-list [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--subsystem` | `S` | All | Filter by subsystem |
| `--bug-class` | `C` | All | Filter by bug class |
| `--json` | None | Off | Print the matching records as JSON |

Prints each record, the per-subsystem rollup, and the count of records that can
send the next round somewhere new.

## impact-set

Attaches an impact record to a crash.

```
python3 tools/pipeline_ctl.py impact-set <crash-id> --json PATH
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--json` | `PATH` or `-` | Required | Read the record from a file, or from standard input for `-` |

Fields: `primitive`, `consequence`, `access_type`, `overwrite_target`,
`attacker_control[]`, `corrupted_object`, `cache`, `access_size`,
`reclaim_path`, `race_window`, `allocation_site`, `free_site`, `access_site`,
`evidence[]`, `unverified[]`, `confidence`, `cwe`, `undetermined_reason`.

`cwe` is derived from the finding's `bug_class` when left empty. `access_size`
is a positive integer of bytes or absent.

## impact-list

Prints the impact records, filtered.

```
python3 tools/pipeline_ctl.py impact-list [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--primitive` | `P` | All | Filter by primitive |
| `--consequence` | `C` | All | Filter by consequence |
| `--json` | None | Off | Print the matching records as JSON, each with its derived CWE |

Prints each record, the per-consequence rollup with CWEs, and the count of
records that can carry a severity into the report.

## campaign-add

Records a campaign's configuration summary in the state file.

```
python3 tools/pipeline_ctl.py campaign-add --track k --note "procs=2 sandbox=namespace rung=1"
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--track` | `k` or `u`, case-insensitive | Required | Stored as `K` or `U` |
| `--note` | `TEXT` | Empty | The configuration summary the `eval` and `report` phases cite |

`campaign_ctl.py` logs install, start and stop events. This adds the summary
those events do not carry.

## round-show

Prints the round count against `loop.max_rounds`, the spend against
`loop.max_total_run_hours`, and one block per round.

```
python3 tools/pipeline_ctl.py round-show [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--json` | None | Off | Print the rounds array |

## round-add-run

Attaches a campaign to the current round.

```
python3 tools/pipeline_ctl.py round-add-run --run-id r2-1
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | Required | The campaign to attach |

Installing a campaign registers the run id, which lets the sampler accept it.
This command makes `round-end` measure and bill it.

## round-end

Measures and bills a round's campaigns, then records the round result.

```
python3 tools/pipeline_ctl.py round-end --from-run r2-1 [--from-run r2-2] [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--from-run` | `RUN_ID` | Required, repeatable | Measure the verdict, edges and hours from this run's `coverage.csv`. Pass every campaign this round ran, each measured and billed independently |
| `--coverage-verdict` | `growing`, `plateaued`, `unknown` | Derived | Override the derived verdict |
| `--new-crashes` | `N` | Derived | Override the derived crash count |
| `--edges-start`, `--edges-end` | `N` | Derived | Override the derived edge totals |
| `--run-hours` | `F` | Derived | Bill these hours to the round under its own ledger key, added to the round total |
| `--notes` | `TEXT` | Derived | Override the derived per-run detail lines |
| `--worklist` | `PATH` | None | Record this round's work list, which `round-advance` carries into the next round |
| `--force` | None | Off | Measure a run whose campaign window has not elapsed |

Hours accumulate across calls, and re-billing a run id corrects its entry.

`--force` is for a campaign that has finished behind a stale deadline file.
Measuring a live campaign produces a wrong coverage curve, wrong billed hours
and a wrong crash count.

## worklist

Prints the path the previous round's `refine` recorded.

```
python3 tools/pipeline_ctl.py worklist
```

| Condition | Result |
|---|---|
| No work list was recorded | Exit 1 |
| The recorded file does not exist | Exit 1 with a `MISSING` note |

## round-decide

Prints the continue-or-stop decision for the current round.

```
python3 tools/pipeline_ctl.py round-decide [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--decision` | `continue`, `stop` | Computed | Override the computed decision |
| `--reason` | `TEXT` | None | Required when overriding a plateau or `unknown` stop |

A budget or round-cap stop cannot be overridden.

## round-advance

Opens the next round.

```
python3 tools/pipeline_ctl.py round-advance
```

Resets the nine round phases to `pending`, keeps the setup phases and the crash
registry, and carries the recorded work list forward as `worklist_in`.

| Condition | Result |
|---|---|
| A round phase is not `done` | Refused. Marking a phase `blocked` does not satisfy the check |
| No `round-end` was recorded | Refused |

## spend-init

Rebuilds `state/spend.json` from the hours the state file records.

```
python3 tools/pipeline_ctl.py spend-init
```

Never lowers recorded spend. A no-op when the ledger already exists.

## validate

Prints every integrity problem in the state file.

```
python3 tools/pipeline_ctl.py validate
```

Exits 1 when it finds any. What it checks is listed in
[State file schema](/gspwn/reference/state-file/).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | A problem, or the requested entry was not found |
| 2 | Usage error |

## Files

| Path | Contents |
|---|---|
| `state/pipeline.json` | Phases, crash registry, findings, impacts, rounds |
| `state/spend.json` | The spend ledger |

## See also

- [State file schema](/gspwn/reference/state-file/)
- [Closed vocabularies](/gspwn/reference/vocabularies/)
</content>
</invoke>
