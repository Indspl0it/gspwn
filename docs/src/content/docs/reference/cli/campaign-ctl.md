---
title: campaign_ctl.py
description: Installing, starting, stopping and bounding fuzz campaigns as systemd units.
---

Installs and manages fuzz campaigns as systemd units that survive panics and
reboots.

## Synopsis

```
python3 tools/campaign_ctl.py <subcommand> [options]
```

`install-k`, `install-u`, `start` and `stop` require root. All tunables come
from `config/campaign.yaml`.

## gen-config

Writes `artifacts/runs/<run-id>/syz-manager.cfg` from the `track_k` section.

```
python3 tools/campaign_ctl.py gen-config --run-id r2-1
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | Required | The campaign identifier |

| Field | Source |
|---|---|
| `target` | Fixed at `linux/amd64` |
| `http` | `track_k.http` |
| `workdir` | `artifacts/runs/<run-id>/workdir` |
| `kernel_obj` | `artifacts/src/linux` |
| `syzkaller` | `artifacts/src/syzkaller` |
| `sandbox` | `track_k.sandbox` |
| `procs` | `track_k.procs` |
| `type` | Fixed at `none` |
| `vm.count` | Fixed at 1 |
| `enable_syscalls` | `track_k.enabled_syscalls`, omitted when empty |

Deterministic output. `install-k` calls this itself. syz-manager validates the
file at startup and exits on a bad field.

## install-k

Installs a Track K campaign as `gspwn-k.service`.

```
sudo python3 tools/campaign_ctl.py install-k --run-id r2-1 [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | Required | The campaign identifier |
| `--corpus` | `fresh`, `carry` | `loop.corpus_policy` | Corpus policy |
| `--from-run` | `ID` | Required with `--corpus carry` | Source run for the carried corpus |
| `--seeds` | `DIR` | None | Seed directory to pack into the run's `corpus.db` |
| `--hours` | `H` | `loop.campaign_hours` | Campaign window |
| `--replace` | None | Off | Retire a still-live older campaign first: stop and disable its units and its deadline timer |

Order of operations: check the run-hour budget, refuse an overlap, apply the
corpus policy, write the deadline file, install the per-run deadline timer,
generate the syz-manager config, write and enable `gspwn-k.service`, and record
the install in the state file.

## install-u

Installs a Track U campaign as `gspwn-u.service`.

```
sudo python3 tools/campaign_ctl.py install-u --run-id r2-1 [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | Required | The campaign identifier |
| `--hours` | `H` | `loop.campaign_hours` | Campaign window |
| `--replace` | None | Off | Retire a still-live older campaign first |

The unit runs `track_u.docker_image` with `artifacts/` bind-mounted at
`/artifacts` and `RUN_ID` in the environment, executing
`/artifacts/harnesses/run_all.sh`.

`install-u` writes its own deadline file, so it resets the clock when it runs
after `install-k`.

## check-deadline

Enforces one run's campaign window. `gspwn-deadline@<run-id>.timer` runs this every `loop.deadline_check_min`
minutes.

```
python3 tools/campaign_ctl.py check-deadline --run-id r2-1
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | Required | The campaign to check |

Idempotent. Reads the deadline, rebuilding it from the install record when the
file is gone.

| Condition | Result |
|---|---|
| The window is open | Reports the hours left, exits 0 |
| The window is up | Stops and disables both units, records the stops, bills the run's measured hours, retires this run's deadline timer |
| A `systemctl stop` failed | Exit 1, leaving the timer to retry. No stop is recorded that did not happen |
| No deadline on disk, none reconstructible, units still fuzzing for this run | Stops the units |

## wait

Blocks until the campaign window elapses. This is the `fuzz` phase's gate.

```
python3 tools/campaign_ctl.py wait --run-id r2-1 [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | Required | The campaign to wait on |
| `--check` | None | Off | Do not block. Exit 0 if the window has elapsed, 1 if the campaign is still inside it |
| `--poll-min` | `N` | `loop.deadline_check_min` | Heartbeat interval in minutes |

The deadline is re-read each pass, so a `--replace` install is followed. On
return it enforces the deadline itself if the units are still active.

| Condition | Result |
|---|---|
| The run has no recorded deadline and none can be reconstructed | Exits with an error |

## start

Starts a track's unit.

```
sudo python3 tools/campaign_ctl.py start k
```

| Argument | Accepted values |
|---|---|
| `track` | `k` or `u` |

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | The run id baked into the unit's description | Recorded in the campaign log alongside the event |

## stop

Stops a track's unit and bills the run's measured hours.

```
sudo python3 tools/campaign_ctl.py stop u --run-id r2-1
```

| Argument | Accepted values |
|---|---|
| `track` | `k` or `u` |

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | The run id baked into the unit's description | Recorded in the campaign log alongside the event |

## status

Prints each unit's `systemctl is-active` state.

```
python3 tools/campaign_ctl.py status --run-id r2-1
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | None | Also print the corpus size, and bill the run if its deadline has already passed |

With `--run-id`, a campaign that finished without going through the timer still
owes its hours to the budget.

## Deadlines

The deadline is an absolute epoch second in `artifacts/runs/<run-id>/deadline`,
written with `fsync`. A file on disk survives the reboots this pipeline causes,
so an unattended round ends on time.

When the file is lost, it is rebuilt from the install event in the state file,
which records when the campaign started and the window it was given. The latest
install for that run is the one in force.

## Overlap refusal

The campaign units are single global names. `install-k` and `install-u` refuse
while another run's units are active or another run's deadline timer is still
installed:

```
refusing to install run r2-2: another campaign is still live (active unit(s) gspwn-k (run r2-1); deadline timer(s) for run(s) r2-1). Overlapping campaigns are not independent runs, and installing over one retires its deadline enforcement. Stop the old campaign first, or re-run with --replace to retire it (stops and disables its units and its deadline timer).
```

Reinstalling the same run id is allowed without a flag.

## Billing

A campaign's hours are the wall-clock span from its first coverage sample to
its last, on either track. The configured window stands in when a run left no
usable samples, and the fallback says so.

Recording is idempotent per run id, so billing here and again at `round-end`
cannot double-count.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. For `wait --check`, the window has elapsed |
| 1 | A `systemctl stop` failed, the run has no recoverable deadline, or `wait --check` found the campaign still inside its window |

## Files

| Path | Contents |
|---|---|
| `artifacts/runs/<run-id>/syz-manager.cfg` | The generated Track K configuration |
| `artifacts/runs/<run-id>/deadline` | The absolute epoch second the window ends |
| `artifacts/runs/<run-id>/workdir` | The syzkaller working directory |
| `gspwn-k.service`, `gspwn-u.service` | The campaign units |
| `gspwn-deadline@<run-id>.timer` | The per-run deadline timer |

## See also

- [Running a campaign](/gspwn/guides/running-a-campaign/)
- [systemd units](/gspwn/reference/systemd-units/)
</content>
</invoke>
