---
title: pipeline_state.py
description: "The shared state library: schema, durability, locking and the spend ledger."
---

The dependency root of `tools/`. Standard library only, and it imports no other
module in `tools/`. It is the sole writer of `state/pipeline.json` and of the
machine-global spend ledger `state/spend.json`.

`GSPWN_STATE` redirects the state file. `GSPWN_SPEND` redirects the ledger and
exists for the test suite. The ledger does not follow `GSPWN_STATE`, so a run
with its own registry still bills the one machine-global budget.

## Responsibility

The module owns the state schema at `SCHEMA_VERSION = 2`, the durability
contract for every write, the phase and round machines, the crash registry, the
research and impact records, and the spend ledger.

| Invariant | Enforced by |
|---|---|
| A write leaves either the previous state or the new state, never a partial file | `save` writes a temporary file, `fsync`s it, `os.replace`s it into position, then `fsync`s the parent directory |
| Two concurrent read-modify-write cycles cannot lose an update | `transaction` holds `flock(LOCK_EX)` on `.pipeline.lock` for the whole cycle |
| A state file written by an older tool gains every key current readers expect | `normalize` fills defaults for every phase, crash, round, finding and impact |
| A newer writer's top-level keys survive an older reader | `normalize` keeps unknown top-level keys |
| Recorded spend is authoritative and machine-global | `spent_hours` reads the ledger and raises when it is absent while hours are recorded |
| Billing the same run twice does not double-count | `record_run_hours` overwrites the entry keyed on run id |
| A crash status change carries its history and its analysis stamp | `set_crash_status` is the single write path for `status` |

## Interface

| Function | Returns | Raises |
|---|---|---|
| `transaction(path=None)` | Context manager yielding the mutable state; saves on clean exit | Propagates the body's exception without saving |
| `load(path=None)` | The normalised state dict | `ValueError` on invalid JSON |
| `save(state, path=None)` | `None` | `OSError` from the write path |
| `normalize(state)` | The state dict with every default filled | `ValueError` when an object-valued key holds a non-object |
| `default_state()` | A fresh state dict | |
| `update_phase(state, phase, status, notes='')` | `None` | `ValueError` on an unknown phase or status |
| `next_phase(state)` | The first phase not done, or `None` | |
| `next_action(state)` | `(kind, value)` where kind is `phase`, `decide`, `advance-round` or `done` | |
| `register_crash(state, crash)` | The assigned crash id | |
| `set_crash_status(crash, status, tool='pipeline_ctl')` | `None` | |
| `was_analysed(crash)` | `bool` | |
| `set_finding(state, cid, finding)`, `set_impact(state, cid, impact)` | The stored record | `ValueError` on an unknown key or a vocabulary violation |
| `findings(state, subsystem=None, bug_class=None)`, `impacts(state, primitive=None, consequence=None)` | `[(crash_id, record)]`, duplicates skipped | |
| `finding_target_gap(finding)`, `impact_support_gap(impact)` | A reason string, or `None` | |
| `findings_steering_nothing(state)`, `impacts_unsupported(state)` | `[(crash_id, record, why)]` | |
| `cwe_of(crash)` | The CWE string, from the impact override or derived from `bug_class` | |
| `current_round(state)`, `round_number(state)` | The round dict, the round number | |
| `end_round(state, verdict=None, new_crashes=None, edges_start=None, edges_end=None, run_hours=None, notes=None, worklist=None, billed=None, surface=None)` | `None`; `run_hours` accumulates, and `surface` writes the seven completion fields as a unit | `ValueError` on a verdict outside `SURFACE_VERDICT` |
| `record_decision(state, decision, reason='')` | `None` | |
| `loop_decision(state, max_rounds, max_total_run_hours=None, stop_on_plateau=True)` | `(decision, reason)` | `SpendLedgerMissing` |
| `hard_cap_reason(state, max_rounds, max_total_run_hours=None)` | The non-overridable stop reason, or `None`. Checks completion, then the round cap, then the budget | `SpendLedgerMissing` |
| `surface_stop_reason(state)` | The completion stop reason, or `None` while targets remain | |
| `surface_ledger_path(path=None)` | The ledger path, a relative one resolved against the repository | |
| `load_surface_ledger(path=None, driver_version=None)` | The ledger, or an empty one | `SurfaceLedgerMismatch` on a release disagreement, `ValueError` on malformed JSON |
| `empty_surface_ledger(driver_version=None, targets_total=None)` | A ledger with no accounted rows | |
| `normalize_account(record)` | The accounting record with its derived fields filled | `ValueError` on an unknown field, an unknown reason, an empty detail, or missing evidence |
| `set_surface_account(record, path=None, driver_version=None, targets_total=None)` | The stored row | `ValueError`, `SurfaceLedgerMismatch` |
| `clear_surface_account(key, path=None, driver_version=None)` | The row removed, or `None` when the key named none | `SurfaceLedgerMismatch` |
| `surface_completion(exercised_keys, accounted, targets_total)` | `(verdict, counts, closed)`, computed as a union over sets, with the deferred rows subtracted before the union | |
| `advance_round(state)` | `None` | `ValueError` when a round phase is unfinished |
| `record_run_hours(run_id, hours, path=None)` | `None`; idempotent per run id | `ValueError` on an empty run id or negative hours |
| `total_spend_hours(path=None)` | `float` | `ValueError` on a malformed ledger |
| `spent_hours(state)` | `float` | `SpendLedgerMissing` |
| `spend_for_budget()` | `float`, read against the default state path | `SpendLedgerMissing` |
| `seed_spend_ledger(path=None)` | `None`; no-op when the ledger exists | |
| `stamp_triage_settings(state, settings)` | `None`; written once, never overwritten | |
| `triage_drift(state, settings)` | `[(key, recorded, current)]` | |
| `validate(state, triage_settings=None)` | A list of integrity problems, empty when clean | |
| `_fix_root_ownership(paths)` | `None`; hands files back to `$SUDO_USER` | |

Exported constants: `PHASES`, `SETUP_PHASES`, `ROUND_PHASES`, `FINAL_PHASES`,
`PHASE_STATUS`, `CRASH_STATUS`, `CRASH_SIGNAL`, `TRACKS`, `DISCLOSURE_STATUS`,
`COVERAGE_VERDICT`, `SURFACE_VERDICT`, `SURFACE_REASON`,
`SURFACE_REASON_NEEDS_EVIDENCE`, `SURFACE_REASON_DEFERRED`,
`SURFACE_LEDGER_PATH`,
`SURFACE_LEDGER_SCHEMA`, `ROUND_DECISION`, `BUG_CLASS`, `TRIGGER`, `CONFIDENCE`,
`PRIMITIVE`, `CONSEQUENCE`, `ACCESS_TYPE`, `OVERWRITE_TARGET`,
`ATTACKER_CONTROL`, `CWE_OF_BUG_CLASS`, `REPO_ROOT`, `STATE_DIR`, `STATE_PATH`,
`SPEND_PATH`, `SCHEMA_VERSION`.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | `pipeline_ctl.py`, `campaign_ctl.py`, `coverage_ctl.py`, `crash_parse.py`, `repro_ctl.py`, `orchestrator_ctl.py`, `corpus_ctl.py`, `knowledge_ctl.py` |
| This module imports | Nothing in `tools/` |

## Failure modes

| Condition | Behaviour |
|---|---|
| State file holds invalid JSON | `ValueError` naming the file and the parse error, with the instruction to restore from the backup |
| Top level is not a JSON object | `ValueError` |
| `phases` or `crashes` is not an object | `ValueError` naming the key |
| Ledger absent while the state file records billed hours | `SpendLedgerMissing`, carrying its own remediation |
| Ledger holds something other than a run-id mapping | `ValueError` |
| `advance_round` called with a round phase unfinished | `ValueError` naming the two ways to satisfy the check |
| Unknown key in a finding or impact record | `ValueError`; the key is refused, never dropped |
| Body of a `transaction` raises | The state file is left unchanged |

## Concurrency and durability

| Property | Mechanism |
|---|---|
| State mutual exclusion | `flock(LOCK_EX)` on `.pipeline.lock` in the state directory, held across the whole read-modify-write |
| Ledger mutual exclusion | A separate lock, so a state transaction and a billing write do not block each other |
| Write atomicity | Temporary file, `fsync`, `os.replace`, `fsync` of the parent directory |
| Panic durability | A backup file alongside the state file |
| Idempotency | `record_run_hours` is idempotent per run id; `seed_spend_ledger` is a no-op when the ledger exists; `stamp_triage_settings` writes once |
| Root handovers | `_fix_root_ownership` returns files to `$SUDO_USER` after a write performed as root |

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never import `gspwn_config` | The drift check takes `triage_settings` as an optional argument, so a broken configuration cannot stop `validate` from reporting on the registry, and this module stays the dependency root |
| Never change state through a bare `load`/`save` pair | Two loads followed by two saves lose an update, and `AGENTS.md` allows parallel sub-agents |
| Never let the spend ledger follow `GSPWN_STATE` | A run with its own registry still counts against the one machine-global cap; the ledger's fallback reads the default state file for the same reason |
| Never fall back to zero spend when the ledger is missing while hours are recorded | The condition raises `SpendLedgerMissing` |
| Never alias a module-level mutable into a new round | `_new_round` copies `run_ids` and `run_hours_by_run`, because `dict(DEFAULT_ROUND)` shares one list across every round created in the process |
| Never resolve `SPEND_PATH` at import time in a signature default | It resolves at call time, so redirecting the ledger redirects it |
| Never key the completion ledger on the variant name | A control variant carries a C handler function name, which a driver refactor renames freely, and the ledger would lose every accounted row at the next bump while still looking full |
| Never re-create a corrupt completion ledger empty | An empty ledger reads as "nothing is accounted for" and silently reopens every closed target. The load path names the `.bak` to restore from |
| Never write the completion fields on a round one at a time | Omitting one leaves a stale `complete` from a previous call in place, so `end_round` writes all six together and an unmeasurable reading arrives as `unknown` |
| Never add exercised and accounted to close the ledger | The two sets overlap, and the sum can reach the total while targets remain |

## Design notes

`normalize` keeps unknown top-level keys, so a newer writer's fields survive an
older reader, while every phase and crash carries the full key set callers
expect.

A non-dictionary where an object belongs raises a `ValueError` naming what was
wrong. `pipeline_ctl` catches those and prints them as errors.

`set_crash_status` is the single write path for a status. Two things happen
alongside the assignment: the append-only history trail, and the `rca_done_at`
stamp.

`end_round` accumulates `run_hours` because a round spans several campaigns and
`round-end` is called once per run. `billed` corrects a re-billed run by the
delta.

`advance_round` refuses a round with an unfinished phase and names the two ways
out. Marking a phase blocked does not satisfy the check.

`hard_cap_reason` holds three stops that are not the same kind of thing.
Completion means the campaign finished its work. The round cap and the budget
mean it ran out of the allowance the user authorised. Completion is checked
first, so a campaign finishing on its last permitted round records why it
finished and not which limit it also touched. The round cap's own reason names
the failure to converge and points at the completion ledger.

The completion ledger is its own artefact. `state/pipeline.json` is 1177 bytes
and `save()` rewrites it whole under a lock on every phase transition and every
crash registration, so 764 rows do not belong in it. The round carries a
repo-relative path to the ledger under `surface_ledger`, and
`surface_ledger_path` resolves a relative one against the repository root,
because a caller with a different working directory would otherwise create a
second empty ledger beside itself and report nothing accounted for.

`SURFACE_REASON_DEFERRED` names the reasons that do not close a target, and
today it holds `deliberately-deferred` alone. Seven of the eight reasons assert
that the target cannot be reached by this campaign as configured, and the
completion identity means "exercised, or excluded". `deliberately-deferred`
asserts the opposite, so `surface_completion` subtracts its rows before the
union and reports them separately as `deferred`. Counting them in would make
the identity read "exercised, or excluded, or postponed", and the stop it fires
would print "Nothing is left to fuzz" over targets the ledger itself records as
reachable.

`clear_surface_account` is the way out of a wrong accounting, and it is the
reason the completion stop can stay non-overridable. A row closes its target
permanently and the verdict built on it is a stop `round-decide` refuses to
override. Reopening a target moves the campaign back towards fuzzing it, which
is the safe direction, so nothing there refuses anything beyond an unknown key.
A wrong `no-param-model` or `chain-unbuildable` row needs this as much as a
wrong deferral does.

`load_surface_ledger` validates each accounted row as well as the mapping, and
raises `ValueError` naming a row that is not an object. `completion_status`
catches that into `unknown`, which fails closed, and both CLI readers already
catch `ValueError` and exit with the message. It also takes `targets_total` and
passes it to `empty_surface_ledger`, so `surface-ledger --json` on a ledger
that has never been written still reports the denominator.

`validate` reports a round marked `complete` with no ledger path. The primary
stop is non-overridable, so its evidence has to be auditable afterwards.

## See also

- [State file schema](/gspwn/reference/state-file/)
- [Durability](/gspwn/architecture/durability/)
