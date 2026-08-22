---
title: systemd units
description: The seven units the tools generate, what each runs, and the constraints each one carries.
---

Seven units are generated. None is committed, and each is written to
`/etc/systemd/system/` by the tool that owns it.

| Unit | Written by | Purpose |
|---|---|---|
| `gspwn-k.service` | `campaign_ctl.py install-k` | The Track K campaign |
| `gspwn-u.service` | `campaign_ctl.py install-u` | The Track U campaign |
| `gspwn-deadline@.service` | `campaign_ctl.py install-k`/`install-u` | Deadline enforcement, per run |
| `gspwn-deadline@.timer` | The same | Its cadence |
| `gspwn-coverage.service` | `coverage_ctl.py install-timer` | One coverage sample of both tracks |
| `gspwn-coverage.timer` | The same | Its cadence |
| `gspwn-orchestrator.service` | `orchestrator_ctl.py install` | The supervised agent |

## gspwn-k.service

```ini
[Unit]
Description=gspwn Track K (syzkaller) run r2-1
After=multi-user.target

[Service]
Type=simple
WorkingDirectory=/path/to/gspwn
ExecStart=/path/to/gspwn/artifacts/src/syzkaller/bin/syz-manager -config /path/to/gspwn/artifacts/runs/r2-1/syz-manager.cfg
Restart=always
RestartSec=30
MemoryMax=12G

[Install]
WantedBy=multi-user.target
```

| Directive | Source | Note |
|---|---|---|
| `Description` | The run id | `campaign_ctl.py` reads the run id back from this line to tell whether a live unit belongs to the run being installed |
| `MemoryMax` | `track_k.memory_max` | A syz-manager killed by the cgroup limit restarts, which shows in the curve as a counter reset |

## gspwn-u.service

```ini
[Unit]
Description=gspwn Track U (NCT userspace fuzzers) run r2-1
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/docker run --rm --name gspwn-u \
  --memory=8G \
  --pids-limit=512 \
  -v /path/to/gspwn/artifacts:/artifacts \
  -v /path/to/gspwn/harnesses:/harnesses \
  -e RUN_ID=r2-1 aflplusplus/aflplusplus:latest \
  /harnesses/run_all.sh
Restart=always
RestartSec=30
MemoryMax=8G

[Install]
WantedBy=multi-user.target
```

| Directive | Source | Note |
|---|---|---|
| Image argument | `track_u.docker_image` | Where the harnesses are built and executed |
| `--memory` and `MemoryMax` | `track_u.memory_max` | Applied at both the container and the cgroup level |
| `RUN_ID` | The run id | `run_all.sh` writes each harness's output under `/artifacts/runs/$RUN_ID/u/<harness>/`, which is where the coverage sampler looks |

## gspwn-deadline@.service and .timer

```ini
[Unit]
Description=gspwn campaign deadline enforcement (%i)

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /path/to/gspwn/tools/campaign_ctl.py check-deadline \
  --run-id %i
```

```ini
[Unit]
Description=gspwn campaign deadline enforcement (%i)

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min

[Install]
WantedBy=timers.target
```

| Directive | Source | Note |
|---|---|---|
| `OnUnitActiveSec` | `loop.deadline_check_min` | Separate from the sampling interval. Raising the sampling interval leaves campaign stop timing unchanged |
| `OnBootSec` | `loop.deadline_check_min` | This pipeline reboots by design, and enforcement resumes on the new boot |
| Instance `%i` | The run id | Template units, instantiated per run as `gspwn-deadline@<run-id>.timer`. Installing run B leaves run A's enforcement in place |

`install_deadline_timer` removes any pre-template global unit it finds.

Under `GSPWN_STATE`, a per-instance drop-in at
`/etc/systemd/system/gspwn-deadline@<run-id>.service.d/gspwn-state.conf`
carries the setting, because the shared template cannot.

## gspwn-coverage.service and .timer

```ini
[Unit]
Description=gspwn coverage sampler (r2-1)

[Service]
Type=oneshot
ExecStart=-/usr/bin/python3 /path/to/gspwn/tools/coverage_ctl.py sample \
  --run-id r2-1 --url http://127.0.0.1:56744
ExecStart=-/usr/bin/python3 /path/to/gspwn/tools/coverage_ctl.py sample \
  --run-id r2-1 --track u --skip-surface
```

```ini
[Unit]
Description=gspwn coverage sampler

[Timer]
OnBootSec=10min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
```

| Directive | Source | Note |
|---|---|---|
| `OnUnitActiveSec`, `OnBootSec` | `loop.coverage_sample_min` | Overridable with `--interval-min` |
| `--url` | `track_k.http` | The syz-manager stats endpoint |
| `-` prefix on `ExecStart` | Fixed | A failure sampling one track does not suppress the other |
| `--skip-surface` on the Track U line | Fixed | Container harnesses produce no syzlang programs, so the run would measure no surface and pay the corpus unpack for it |

One timer covers both tracks. Sampling runs from a timer so that it outlives
the agent session and survives panics. The campaign deadline is enforced by its
own per-run timer, so the spend ceiling holds even if the sampler is never
installed or is removed mid-run.

## gspwn-orchestrator.service

```ini
[Unit]
Description=gspwn orchestrator (drives the pipeline across panics)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=3600
StartLimitBurst=20

[Service]
Type=simple
User=researcher
Environment=HOME=/home/researcher
Environment=XDG_CONFIG_HOME=/home/researcher/.config
WorkingDirectory=/path/to/gspwn
ExecStart=/usr/bin/python3 /path/to/gspwn/tools/orchestrator_ctl.py run
Restart=always
RestartSec=60
RestartPreventExitStatus=78

[Install]
WantedBy=multi-user.target
```

| Directive | Source | Requirement |
|---|---|---|
| `StartLimitIntervalSec` | `orchestrator.window_min`, in seconds | Must sit under `[Unit]`. `systemd.unit(5)` documents both `StartLimit*` directives there, and `systemd.service(5)` cross-references them |
| `StartLimitBurst` | Four times `orchestrator.max_same_boot_starts` | As above |
| `User` | `--user`, defaulting to `$SUDO_USER` | A system unit runs as root unless told otherwise |
| `Environment=HOME` | The agent user's home directory | `User=` alone does not set `HOME` |
| `RestartPreventExitStatus` | Fixed at `78` | Stops the unit. `run` returns 78 for a tripped breaker, an unset command, a blocked phase and a complete pipeline |

Written under `[Service]`, the `StartLimit*` directives are an unknown key,
silently ignored, and the manager default of five starts per ten seconds
applies. `RestartSec=60` cannot reach that default, so the backstop would have
no effect. The breaker inside `run` is the primary guard. These two directives
are the backstop for a crash occurring before the breaker's state file can be
written.

A coding agent keeps its login under the invoking user's home directory.
Running as root, it reads `/root`, finds no credentials, fails, and is
restarted until the breaker trips.

## Verifying the units

```
systemd-analyze verify /etc/systemd/system/gspwn-*.service
systemctl is-active gspwn-k gspwn-u
systemctl list-timers 'gspwn-*'
journalctl -u gspwn-orchestrator -n 200
```

## Removing the units

```
sudo python3 tools/coverage_ctl.py remove-timer
sudo python3 tools/orchestrator_ctl.py remove
```

Campaign units are stopped and disabled by `check-deadline` when the window
elapses, and by `--replace` on the next install. Disabling is required as well
as stopping: an enabled `Restart=always` unit comes back on the next boot.

## See also

- [Unattended operation](/gspwn/guides/unattended-operation/)
- [Long-running campaigns](/gspwn/guides/long-running-campaigns/)
