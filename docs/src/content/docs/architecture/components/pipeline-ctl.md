---
title: pipeline_ctl.py
description: The command surface of the state machine.
---

The command surface over `pipeline_state.py`. Twenty subcommands, no root
required. Every state change an agent makes passes through it.

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

## The command vocabulary

Twenty subcommands cover five groups of state change.

| Group | Covers |
|---|---|
| Phases | Reading the phase table, the next phase to run, and setting a phase status |
| Crashes | Listing the registry, and bulk-editing entries with their status, duplicate links and reproduction rates |
| Research | Writing and reading the finding and impact records that carry a crash's analysis |
| Rounds | Attaching runs, recording a round's measured outcome, applying the caps, and opening the next round |
| Completion | Accounting a target as closed, reopening one, and printing the ledger grouped by reason |

Alongside those sit the derived views: a handoff brief for a replacement agent,
the worklist a round's sub-agents execute, and an integrity report over the
registry and the state file.

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
| Never accept an accounting record with an unknown field | A misspelled `reasons` would leave `reason` empty while the command reported success, closing out no target and saying it had |
| Never accept an accounting record with no written detail | The reason vocabulary groups the count and the detail carries the argument, and a closed-out target is closed permanently |
| Never write the completion ledger inside the state file | `state/pipeline.json` is 1177 bytes and is rewritten whole under a lock on every phase transition and every crash registration |
| Never count an accounted target against a different driver release | The inventories are keyed by release, and a ledger written for one accounts for targets another does not contain |

## Design notes

`_derive_run` measures each run independently. A round's several campaigns never
share a single measurement, and their counters reset between campaigns, so edge
totals are combined as the first run's baseline plus every run's peak-over-start
gain.

`edges_end` uses the peak sample. A fuzzer restart zeroes the counter, and
recording `edges_end` below `edges_start` would show the round losing coverage
in the history the report is built from.

A hand-maintained handoff drifts as soon as a phase changes without it being
rewritten, which is why `cmd_brief` derives every line at read time.

`finding-set` and `impact-set` take JSON. The records are nine and eighteen
fields, several of them lists, and `rca` authors each as a whole. A dozen
repeatable flags would be filled in one call at a time, and a half-written
record must never be stored. `surface-account` takes JSON for the same reason
and mirrors the same argument shape.

`surface-account` names its target by `variant`, the name `surface_cov.py gaps`
prints, and resolves it through `surface_cov.load_targets()` to the composite
ABI key, the family and the driver version. A corpus program carries the
variant, and the composite survives a driver refactor renaming a C handler.
Rows are keyed on the composite, so re-accounting a target
replaces its row and preserves `first_recorded`, and the accounted count can
never exceed the denominator through repetition.

The ledger write goes through `pipeline_state._ledger_transaction`, the same
own-lock-file pattern the spend ledger uses, so `surface-account` is safe to
call while a state `transaction()` is open.

`surface-unaccount` is the inverse and takes either handle. `--variant`
resolves through the inventories as `surface-account` does. `--key` names the
stored ABI key, and it is the only handle on a row whose target no inventory
contains any more, which is the state a driver bump leaves behind. Without a
removal operation, a wrong accounting was recoverable only by hand-editing
`surface/completion-ledger.json`, and 852 wrong rows fire a
non-overridable completion stop.

`cmd_round_end` takes the completion reading before `ps.transaction()` opens.
The reading unpacks and rescans one corpus per run, each bounded at
`coverage.unpack_timeout_sec`, and the transaction holds the exclusive lock
every other `pipeline_ctl` and `campaign_ctl` command waits on. The ledger
pointer is read through `ps.load()` first, so the cost is a reading of a state
one instant older, and nothing between the read and the transaction writes that
pointer.

`cmd_round_decide` prints the ledger recovery route only when the hard stop
actually is the completion one, so an operator blocked by the budget is not
sent to the ledger.

`finding-list` and `impact-list` both end with a count of how many records can
do their job, and name the ones that cannot. An unsupported record reads
identically to a supported one in the rollup above it, so the feedback
edge or an over-claimed severity fails silently.

`_repo_rel` prints a path relative to the repository when it is inside it, and
absolute otherwise, because a redirected `GSPWN_STATE` lives outside the tree
where a relative path is a run of `..` segments.

## See also

- [pipeline_ctl.py reference](/gspwn/architecture/components/pipeline-ctl/)
