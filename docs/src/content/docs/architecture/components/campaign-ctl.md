---
title: campaign_ctl.py
description: Campaigns as systemd units, deadlines on disk, corpus policy and billing.
---

Installs and manages fuzz campaigns as systemd units that survive panics and
reboots. Track K runs as `gspwn-k.service`, Track U as `gspwn-u.service`, and
each run gets its own `gspwn-deadline@<run-id>` timer instance.

`install-k`, `install-u`, `start` and `stop` require root. Reading a deadline
does not. Every tunable comes from `config/campaign.yaml` through
`gspwn_config.py`.

## Responsibility

The module owns the run's syz-manager configuration, the campaign window, and
the billing of a finished campaign to the spend ledger.

| Invariant | Enforced by |
|---|---|
| A campaign window survives a reboot | The deadline is an absolute epoch second in `artifacts/runs/<run-id>/deadline` |
| A lost deadline file does not remove the spend ceiling | `reconstruct_deadline` rebuilds it from the recorded install event |
| Enforcement does not depend on a later command being run | `install_deadline_timer` instantiates a per-run timer at install time |
| A second campaign cannot repoint the units of a live one | `check_overlap` refuses unless the run id matches or `--replace` is given |
| Every campaign reaches the ledger | `bill_run` bills round and non-round campaigns alike |
| A campaign cannot start past the run-hour cap | `check_budget` reads machine-global spend before the install, through `pipeline_state.spend_for_budget`, which reconciles the ledger against the state file and returns the larger figure |
| Seeds are visible to syz-manager | `install_seeds` packs them into `workdir/corpus.db` |

## Subcommands

| Subcommand | Arguments | Purpose |
|---|---|---|
| `gen-config` | `--run-id` | Write the run's syz-manager configuration |
| `install-k` | `--run-id`, `--corpus`, `--from-run`, `--seeds`, `--hours`, `--replace` | Install and start the Track K campaign |
| `install-u` | `--run-id`, `--hours`, `--replace` | Install and start the Track U campaign |
| `check-deadline` | `--run-id` | Stop, disable and bill the campaign when its window is up. Idempotent |
| `wait` | `--run-id`, `--check`, `--poll-min` | Block until the run's campaign window has elapsed |
| `start`, `stop` | `k` or `u` positional, `--run-id` | Start or stop one track's unit |
| `status` | `--run-id` | Report unit state, corpus size and deadline |

`--run-id` is required everywhere except `start`, `stop` and `status`, where it
is optional and names the run a manual stop is billed against.

| Flag | Default | Effect |
|---|---|---|
| `--corpus` | `loop.corpus_policy` | `fresh` starts empty, `carry` copies another run's `corpus.db` |
| `--from-run` | none | The source run id, required by `--corpus carry` |
| `--seeds` | none | Directory of `.syz` files packed into the run's `corpus.db` |
| `--hours` | `loop.campaign_hours` | The campaign window, as a float |
| `--replace` | off | Retire a still-live older campaign before installing |
| `--check` | off | Make `wait` return at once: 0 when the window has elapsed, 1 while the campaign is inside it |
| `--poll-min` | `loop.deadline_check_min` | Heartbeat interval of `wait`, in minutes |

## Generated configuration

`gen-config` writes `artifacts/runs/<run-id>/syz-manager.cfg` as JSON. Nine
fields are always present and a tenth appears when `track_k.enabled_syscalls`
is non-empty. syz-manager validates the file at startup and exits on a bad
field, so a version mismatch surfaces at once.

| Field | Value |
|---|---|
| `target` | `linux/amd64` |
| `http` | `track_k.http` |
| `workdir` | `artifacts/runs/<run-id>/workdir` |
| `kernel_obj` | `artifacts/src/linux` |
| `syzkaller` | `artifacts/src/syzkaller` |
| `sandbox` | `track_k.sandbox` |
| `procs` | `track_k.procs` |
| `type` | `none` |
| `vm` | `{"count": 1}` |
| `enable_syscalls` | `track_k.enabled_syscalls`, when it holds anything |

## Files written

| Path | Content |
|---|---|
| `artifacts/runs/<run-id>/syz-manager.cfg` | The generated syz-manager configuration |
| `artifacts/runs/<run-id>/workdir/corpus.db` | The run's corpus, syz-manager's only corpus input |
| `artifacts/runs/<run-id>/deadline` | The absolute epoch second the campaign stops at, `fsync`ed |
| `/etc/systemd/system/gspwn-k.service` | syz-manager under `Restart=always`, `RestartSec=30`, `MemoryMax=track_k.memory_max` |
| `/etc/systemd/system/gspwn-u.service` | `docker run` of `track_u.docker_image` under the same restart policy, with `--pids-limit=512` and `artifacts/` and `harnesses/` bind-mounted |
| `/etc/systemd/system/gspwn-deadline@.service` | Template running `check-deadline --run-id %i` |
| `/etc/systemd/system/gspwn-deadline@.timer` | Template firing at `loop.deadline_check_min` minutes, on boot and after each activation |
| `/etc/systemd/system/gspwn-deadline@<run-id>.service.d/gspwn-state.conf` | A drop-in carrying `GSPWN_STATE`, written when the variable is set and removed when it is not |
| `state/spend.json` | The machine-global ledger, through `pipeline_state.record_run_hours` |
| `state/pipeline.json` | An `install` or `stop` event appended to `campaigns` |

`loop.deadline_check_min` is its own configuration key and defaults to 2.
Raising `loop.coverage_sample_min` must not delay every deadline stop past the
window it enforces.

`install_deadline_timer` removes the pre-template global
`gspwn-deadline.timer` and `gspwn-deadline.service` left by older installs.
One shared unit can enforce one run's deadline.

`state/spend.json` is machine-global and `GSPWN_STATE` does not redirect it. A
run that redirects its state file gets an empty `pipeline.json` and the same
budget.

## Callers

- `pipeline_ctl.py` imports this module lazily, for `read_deadline` in
  `_live_runs` and `cmd_round_end`.
- This module imports `pipeline_state.py`, `gspwn_config.py`, `corpus_ctl.py`
  for `SYZ_DB` and `unpack_corpus`, and `coverage_ctl.py` for `TRACKS` and
  `read_rows`.

## Exit codes

| Code | Conditions |
|---|---|
| 0 | The subcommand completed |
| 1 | Any of the thirteen stopping conditions below, and `wait --check` while the campaign is still inside its window |

## Failure modes

Nineteen conditions are handled. Thirteen stop the command, three warn and
carry on, and three resolve to a value.

| Condition | Behaviour |
|---|---|
| `config/campaign.yaml` fails validation | Exits carrying the config error |
| `install-k`, `install-u`, `start` or `stop` attempted as non-root | Exits naming which of the two groups it was |
| Spend ledger missing while the state file records billed hours | Exits with the ledger's own remediation, `pipeline_ctl.py spend-init` |
| Spend plus this campaign exceeds `loop.max_total_run_hours` | Exits naming both figures and the setting. Exact equality is admitted |
| Another run's campaign still live | Exits naming the live units and the run ids holding deadline timers, unless `--replace` |
| `--replace` cannot stop the old unit | Exits, and nothing is installed |
| Corpus policy `carry` without `--from-run` | Exits |
| No `corpus.db` in the named source run | Exits naming the path searched |
| Corpus policy `fresh` on a run that already has a `corpus.db` | Exits, directing a new run id |
| `--seeds` names something that is not a directory | Exits naming the path |
| `syz-db pack` fails | Exits carrying the tool's error |
| `systemctl stop` returns non-zero during `check-deadline` | Exits 1 so the timer retries. No stop is recorded and nothing is billed |
| `wait` given a run with no deadline and none reconstructible | Exits, directing an install |
| `--seeds` directory holds no `.syz` files | Warns that the run starts from an empty corpus, and installs it anyway |
| The ledger write raises `OSError` during billing | Warns naming the hours, the path and the error, and directs a re-run as root |
| Spend ledger below the hours the state file records | Warns naming both figures and the shortfall, and the larger figure counts against the cap |
| systemd absent | `unit_active` returns `False`, so `check-deadline` never stops a campaign whose state it cannot read |
| No deadline on disk, none reconstructible, units still fuzzing | The campaign is stopped, since nothing bounds what it spends |
| No deadline on disk, none reconstructible, no unit running | Reports that there is nothing to enforce |

## Concurrency and durability

Five properties keep a campaign's window and its billing correct across a
panic, a reboot and a concurrent install.

| Property | Mechanism |
|---|---|
| Deadline durability | The deadline file is written with `fsync` before use, so a panic does not leave an empty window |
| Enforcement durability | A per-run systemd timer instance, so one run's install cannot retire another run's enforcement |
| Idempotency | `check-deadline` is idempotent, and a stop already performed records nothing further |
| Billing idempotency | `bill_run` writes through `pipeline_state.record_run_hours`, which is keyed on run id |
| Overlap exclusion | Unit names are global, so `check_overlap` is the mutual exclusion between runs |

## Prohibited behaviour

Nine rules bound what the module may do to a live campaign, a stopped one and
its corpus.

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

`install-u` writes its own deadline file, which resets the clock when it runs
after `install-k`. `reconstruct_deadline` takes the latest of the install
events for that reason.

`reconstruct_deadline` rebuilds a lost deadline from the install event, which
records when the campaign started and the window it was given. Without it,
losing that one file removes the spend ceiling in silence.

`measured_run_hours` derives the figure from the span between the first and the
last coverage sample on either track, and falls back to the configured window
when fewer than two samples carry a timestamp. It returns the basis alongside
the figure, so the fallback is visible in the output.

Skipping round campaigns in `bill_run` on the assumption that `round-end` bills
them leaves a round that never closes with its hours off the ledger.
`round-end` derives the same figure the same way and declines to bill when a
run left no samples, so the fallback stands.

`cmd_wait` re-reads the deadline on every pass, because a `--replace` install
moves it. On return it enforces the deadline itself if the units are still
active, since measuring a campaign that is still running produces the same
wrong number the wait exists to prevent.

`register_campaign` records the install with its hours, which makes the run id
a registered run the coverage sampler accepts.
