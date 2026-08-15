---
title: campaign_ctl.py
description: Campaigns as systemd units, deadlines on disk, corpus policy and billing.
---

Installs and manages fuzz campaigns as systemd units that survive panics and
reboots. Track K runs as `gspwn-k.service`, Track U as `gspwn-u.service`, and
each run gets its own `gspwn-deadline@<run-id>` timer instance.

Installing and stopping campaigns requires root. Reading a deadline does not.

## Responsibility

The module owns the run's syz-manager configuration, the campaign window, and
the billing of a finished campaign to the spend ledger.

| Invariant | Enforced by |
|---|---|
| A campaign window survives a reboot | The deadline is an absolute epoch second in a file under `artifacts/runs/<run-id>/` |
| A lost deadline file does not remove the spend ceiling | `reconstruct_deadline` rebuilds it from the recorded install event |
| Enforcement does not depend on a later command being run | `install_deadline_timer` instantiates a per-run timer at install time |
| A second campaign cannot repoint the units of a live one | `check_overlap` refuses unless the run id matches or `--replace` is given |
| Every campaign reaches the ledger | `bill_run` bills round and non-round campaigns alike |
| A campaign cannot start past the run-hour cap | `check_budget` reads machine-global spend before the install |
| Seeds are visible to syz-manager | `install_seeds` packs them into `workdir/corpus.db` |

## Interface

| Subcommand | Purpose |
|---|---|
| `gen-config` | Generate the run's syz-manager configuration |
| `install-k`, `install-u` | Install and start a campaign for one track |
| `check-deadline` | Stop, disable and bill the campaign when its window is up. Idempotent |
| `wait` | Block until the run's campaign window has elapsed |
| `start`, `stop` | Start or stop one track's unit |
| `status` | Report unit state and deadline for a run |

| Function | Returns | Raises |
|---|---|---|
| `read_deadline(run_id)` | The absolute epoch second, or `None` | |
| `reconstruct_deadline(run_id)` | A rebuilt deadline, or `None` | |
| `effective_deadline(run_id)` | The deadline, rebuilt from state when the file is gone | |
| `configured_hours(run_id)` | The window the run was installed with, if recoverable | |
| `measured_run_hours(run_id)` | `(hours, basis)`, the basis naming the derivation | |
| `unit_active(name)` | `bool`; `activating` counts as active | |
| `unit_run_id(name)` | The run id baked into an installed unit, or `None` | |
| `units_for_run(run_id)` | Campaign units currently running that run id | |
| `enabled_deadline_runs()` | Run ids with an enabled deadline timer instance | |
| `check_budget(hours, cap)` | Spend before this campaign | Exits 1 when over the cap |
| `install_seeds(dest_db, seeds_dir)` | `None` | Exits 1 when `syz-db pack` fails |
| `register_campaign(run_id, track, hours)` | `None` | |
| `bill_run(run_id, why)` | `None` | |

## Callers

| Direction | Modules |
|---|---|
| Imports this module | `pipeline_ctl.py`, lazily, for `read_deadline` in `_live_runs` and `cmd_round_end` |
| This module imports | `pipeline_state.py`, `gspwn_config.py`, `corpus_ctl.py` for `SYZ_DB` and `unpack_corpus`, `coverage_ctl.py` for `TRACKS` and `read_rows` |

## Failure modes

| Condition | Behaviour |
|---|---|
| Install attempted as non-root | Exits 1 naming the command |
| Another run's campaign still live | Exits 1 naming the live run, unless `--replace` |
| `--replace` cannot stop the old unit | Exits 1 and leaves the old campaign in place |
| Spend plus this campaign exceeds `loop.max_total_run_hours` | Exits 1 naming both figures and the setting. Exact equality is admitted |
| Spend ledger missing while hours are recorded | Exits 1 with the ledger's remediation |
| Corpus policy `carry` without `--from-run` | Exits 1 |
| No `corpus.db` in the named source run | Exits 1 naming the path searched |
| `syz-db pack` fails | Exits 1 carrying the tool's error |
| `systemctl stop` returns non-zero during `check-deadline` | Exits 1 so the timer retries; no stop is recorded |
| systemd absent | `unit_active` returns `False` |
| No deadline on disk, none reconstructible, units still fuzzing | The campaign is stopped |
| `wait` given a run with no deadline and none reconstructible | Exits 1 |

## Concurrency and durability

| Property | Mechanism |
|---|---|
| Deadline durability | The deadline file is written with `fsync` before use, so a panic does not leave an empty window |
| Enforcement durability | A per-run systemd timer instance, so one run's install cannot retire another run's enforcement |
| Idempotency | `check-deadline` is idempotent; a stop already performed records nothing further |
| Billing idempotency | `bill_run` writes through `pipeline_state.record_run_hours`, which is keyed on run id |
| Overlap exclusion | Unit names are global, so `check_overlap` is the mutual exclusion between runs |

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never install over a live campaign silently | The units are single global names, so installing run B over live run A repoints them while A keeps fuzzing with its deadline enforcement gone. Reinstalling the same run id is admitted; anything else needs `--replace` |
| Never leave a stopped campaign enabled | `check-deadline` stops and disables both units. An enabled `Restart=always` unit returns on the next boot, and this pipeline reboots by design |
| Never record a stop that did not happen | Only a `systemctl stop` that returned zero is appended to the campaign log |
| Never treat an unknown unit state as active | Treating an unknown as active would make `check-deadline` stop a campaign it cannot see |
| Never treat `activating` as stopped | That state is the `RestartSec` backoff after a syz-manager crash. Reading it as stopped disables the unit, bills the run and retires its timer while the restart completes |
| Never leave a campaign unbounded | With no deadline, none reconstructible, and units still fuzzing, the campaign is stopped |
| Never place seeds beside the corpus database | `workdir/corpus.db` is syz-manager's only corpus input; programs in a sibling directory are never loaded |
| Never discard a carried corpus while packing seeds | `install_seeds` unpacks what the database already holds into the staging directory first |
| Never let one run's install retire another's deadline enforcement | The deadline units are templates instantiated per run |

## Design notes

The deadline is an absolute epoch second in a file, so it survives the reboots
this pipeline causes. `install-u` writes its own, which resets the clock when it
runs after `install-k`.

`reconstruct_deadline` rebuilds a lost deadline from the install event, which
already records when the campaign started and the window it was given. Without
it, losing that one file removes the spend ceiling silently.

`measured_run_hours` returns the basis alongside the figure, so the fallback to
the configured window is visible in the output.

`bill_run` bills every campaign, round or not. Skipping round campaigns on the
assumption that `round-end` bills them leaves a round that never closes with its
hours off the ledger.

`cmd_wait` re-reads the deadline on every pass, because a `--replace` install
moves it and the wait has to follow the campaign that is actually running. On
return it enforces the deadline itself if the units are still active. Measuring
a campaign that is still running produces the same wrong number the wait exists
to prevent.

`register_campaign` records the install with its hours, which is what makes the
run id a registered run the coverage sampler accepts, and what a lost deadline
is reconstructed from.

## See also

- [campaign_ctl.py reference](/gspwn/reference/cli/campaign-ctl/)
- [systemd units](/gspwn/reference/systemd-units/)
