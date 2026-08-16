---
title: pipeline_ctl.py
description: The command surface of the state machine.
---

The command surface over `pipeline_state.py`. Twenty subcommands, no root
required. Every state change an agent makes passes through here.

The module is a leaf: nothing in `tools/` imports it.

## Responsibility

The module owns the command vocabulary of the state machine and the derived
views built from state at read time. It writes state only through
`pipeline_state.transaction`.

| Invariant | Enforced by |
|---|---|
| A round's outcome is measured, not asserted | `_derive_run` reads the run's own `coverage.csv` and the registry; explicit flags override and the notes carry the derived detail |
| A bulk crash edit applies completely or not at all | `cmd_crash_set` validates every id, then applies them inside one transaction |
| A round does not close while its campaign is still running | `_next_action` and `cmd_round_end` consult `campaign_ctl` for live runs |
| The fuzzer's own duplicates and noise never count as findings | `_is_finding` filters them before `_derived_new_crashes` counts |
| A command that reads spend fails closed | `main` catches `SpendLedgerMissing` and prints its remediation |
| The handoff is never stale | `cmd_brief` derives every line at read time and stamps its own timestamp |

## Interface

| Subcommand | Purpose |
|---|---|
| `init` | Create `state/pipeline.json` |
| `show` | Phase table and crash summary |
| `next` | The first phase not marked done, or the wait line |
| `set-phase` | Set a phase status |
| `crash-list` | List registered crashes |
| `crash-set` | Update one or more crash registry entries |
| `brief` | The derived handoff for a replacement agent |
| `finding-set`, `finding-list` | Write and read the research records |
| `impact-set`, `impact-list` | Write and read the impact records |
| `campaign-add` | Record a campaign event |
| `round-show` | Round history and loop budget |
| `round-add-run` | Attach a run id to this round |
| `round-end` | Record the round's measured outcome |
| `worklist` | The worklist this round's `describe` and `seeds` sub-agents execute |
| `round-decide` | Apply the caps and record the loop decision |
| `round-advance` | Open the next round |
| `spend-init` | Rebuild a lost spend ledger from recorded hours |
| `validate` | Report registry and state integrity problems |

`selftest.py` calls `cmd_round_end` through a lazy wrapper.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing. `selftest.py` imports it inside a wrapper function |
| This module imports | `pipeline_state.py`, `gspwn_config.py`, `knowledge_ctl.py` inside a `try` for `brief` |
| Lazily, inside a function | `coverage_ctl` for measurement in `_derive_run`; `campaign_ctl` for the live check in `_live_runs` and `cmd_round_end` |

The two lazy imports exist because `coverage_ctl` and `campaign_ctl` read
configuration when their argument parsers are built, and a module-scope import
would run that read at import time.

## Failure modes

| Condition | Behaviour |
|---|---|
| Loop or agent settings unreadable | Exits 1. The accessors do not fall back to a default |
| Configuration unreadable during `validate` | Passes `None` for the drift check and still reports on the registry |
| `round-end` without `--from-run` | Exits 1 asking for at least one run to measure |
| `round-end` while a run in the round is inside its campaign window | Exits 1 naming the live run |
| `crash-set` given an unknown id, a self-duplicate, a link to a duplicate, or a rate outside 0.0 to 1.0 | Exits 1 before the write, and nothing is changed |
| `round-decide --decision continue` against a tripped hard cap | Exits 1 naming the cap |
| Spend ledger missing on any command that reads spend | Exits 1 with the exception's own remediation |
| Knowledge files unreadable during `brief` | The state summary above them still prints |

## Concurrency and durability

The module takes no lock of its own. Every write goes through
`pipeline_state.transaction`, which holds the exclusive state lock for the
whole read-modify-write, so parallel sub-agents editing the registry serialise
against each other. `cmd_crash_set` places all of its edits in one transaction,
which makes a bulk edit atomic with respect to another agent's transaction.
Read-only commands take the same lock only where they also write.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never fall back to a default for the loop caps or the agent settings | The loop spends machine time unattended, so the caps come from the configuration or the command exits |
| Never run ahead of a live campaign | A round measured while its fuzzer is running records a number the campaign has not finished producing. The `fuzz` phase is exempt, because it starts the campaign |
| Never let a bulk edit half-apply | A rejected id exits before the write, so the flagged queue is never left half-decided |
| Never count duplicates, unresolved flagged entries or noise Xids as findings | They are the fuzzer's own repeat output, and counting them inflates the round's measured result |
| Never silently accept a hand-typed number in place of a measured one | Explicit flags override the derivation, and the notes carry the derived detail so the override is visible |

## Design notes

`_derive_run` measures each run independently. A round's several campaigns never
share a single measurement, and their counters reset between campaigns, so edge
totals are combined as the first run's baseline plus every run's peak-over-start
gain.

`edges_end` uses the peak sample. A fuzzer restart zeroes the counter, and
recording `edges_end` below `edges_start` would show the round losing coverage
in the history the report is built from.

`cmd_brief` is derived and short. A hand-maintained handoff drifts as soon as a
phase changes without it being rewritten. It stamps its own time, so its age is
visible. It is read into a context window that has just been truncated, where
every line displaces something else.

`finding-set` and `impact-set` take JSON. The records are nine and eighteen
fields, several of them lists, and `rca` authors each as a whole. A dozen
repeatable flags would be filled in one call at a time, and a half-written
record must never be stored.

`finding-list` and `impact-list` both end with a count of how many records can
do their job, and name the ones that cannot. An unsupported record reads
identically to a supported one in the rollup above it, so the feedback
edge or an over-claimed severity fails silently.

`_repo_rel` prints a path relative to the repository when it is inside it, and
absolute otherwise, because a redirected `GSPWN_STATE` lives outside the tree
where a relative path is a run of `..` segments.

## See also

- [pipeline_ctl.py reference](/gspwn/reference/cli/pipeline-ctl/)
- [State file schema](/gspwn/reference/state-file/)
