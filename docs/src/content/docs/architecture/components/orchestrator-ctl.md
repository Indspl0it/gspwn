---
title: orchestrator_ctl.py
description: The supervisor, the circuit breaker, session resume and stall detection.
---

Keeps the orchestrating agent alive across panics, with a circuit breaker. The
rest of the pipeline survives a kernel panic through systemd units and on-disk
state; the agent driving it does not, and without this module its recovery
requires an interactive login.

The supervisor is `gspwn-orchestrator.service`. Its breaker state file is
machine-global and does not follow `GSPWN_STATE`. `GSPWN_ORCH` redirects it for
the test suite.

## Responsibility

The module owns the supervisor unit, the restart breaker, and the session
identity carried across a restart. It is the sole writer of the breaker state
file.

| Invariant | Enforced by |
|---|---|
| A restart never runs into a condition that will recur | Four situations return `BLOCKED_EXIT`, which the unit names in `RestartPreventExitStatus` |
| Reboots and same-boot restarts are counted separately | Two limits over one window, since kernel fuzzing panics the box by design |
| A session id exists before the agent is launched | The id is a UUID generated here and substituted into the invocation |
| A panic cannot lose the record of the launch | The session and the resume count are written before the launch |
| The agent never runs as root | `install` refuses without a non-root user and sets both `User=` and `Environment=HOME=` |
| The invocation is never stale | It is read from the configuration at every launch |
| A stalled agent is bounded | `launch_agent` kills the process group after `orchestrator.max_agent_hours` |

## Interface

| Subcommand | Purpose |
|---|---|
| `install` | Write and enable the supervisor unit |
| `run` | One supervised launch: harvest, breaker check, session resolution, launch |
| `status` | Report breaker counts and the stored session |
| `preflight` | Check what an unattended run needs and nothing else verifies |
| `reset` | Clear a tripped breaker and its counted history |
| `remove` | Disable and remove the unit |

| Function | Returns | Raises |
|---|---|---|
| `check(state, conf, now, this_boot)` | `(reason, None)` when a breaker has tripped, else `(None, counts)`. Pure | |
| `resolve_session(state, conf, now, new_id=None, size_bytes=None)` | `(session, resuming, why)`. Pure, mutates nothing | |
| `transcript_bytes(glob_pattern, session_id)` | Total transcript size, or `None` when it cannot be read | |
| `render_command(template, session_id, anchor=None)` | The invocation with placeholders substituted | |
| `launch_agent(command, max_hours=0)` | The completed process, or a stand-in carrying the stall exit code | |
| `harvest()` | `None`; best-effort, reports failure and continues | |
| `pipeline_stop_reason()` | Why the agent should not be launched, or `None` | |
| `boot_id()` | The current boot id, or `None` | |
| `sudo_ok(user=None)` | `(ok, detail)` | |

Exported constant: `BLOCKED_EXIT = 78`.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing. `selftest.py` exercises `check`, `resolve_session`, `transcript_bytes`, `render_command`, `launch_agent` and `sudo_ok` directly |
| This module imports | `pipeline_state.py`, `gspwn_config.py`, and `coverage_ctl.py` lazily inside a `try` for the disk check |
| Invokes as a subprocess | `crashlog_ctl.py` for the post-panic harvest |

## Failure modes

| Condition | Behaviour | Exit code |
|---|---|---|
| Breaker tripped | Message naming the limit and the window | 78 |
| `orchestrator.command` unset | Message naming the setting | 78 |
| Current phase blocked | Message naming the phase | 78 |
| Pipeline complete | Message saying so | 78 |
| State file corrupt | Message naming the parse error; a relaunched agent would read the same file | 78 |
| Agent exceeds `orchestrator.max_agent_hours` | Process group killed with `SIGTERM` then `SIGKILL`; non-zero and distinct from `BLOCKED_EXIT`, so systemd restarts into a fresh session | The agent's code, or 124 |
| Breaker file unparseable | Every read raises; only `reset` starts over | 1 |
| `install` without a non-root user | Refused | 1 |
| `install` with no agent command configured | Refused | 1 |
| Post-panic harvest fails | Reported loudly, and the launch proceeds | |
| Boot id unreadable | Counted against the same-boot limit | |
| Transcript unmeasurable | `transcript_bytes` returns `None` and rotation falls back to the resume count, reported explicitly | |
| Resume exits non-zero | The stored session id is cleared, so the next start is fresh | |

## Concurrency and durability

| Property | Mechanism |
|---|---|
| Breaker mutual exclusion | `flock(LOCK_EX)` on the breaker state file for the whole read-modify-write |
| Breaker scope | Machine-global; it does not follow `GSPWN_STATE`, so a run redirecting its state does not also get a fresh, empty breaker |
| Ordering | The session and the resume count are written before the launch, because a panic kills the agent with no exit code |
| Restart policy | `RestartPreventExitStatus` names `BLOCKED_EXIT`, so systemd stops on that exit code |
| Process control | `start_new_session=True` and `killpg`, so a stall kills the whole group |

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never restart into a condition that will recur | A relaunched agent reads the same broken state and stops again, once per restart |
| Never count reboots against the same-boot limit | A single shared limit would stop a healthy campaign that panics often, or allow a same-boot restart loop to continue indefinitely |
| Never treat an unreadable boot id as a fresh boot | Assuming a reboot lets a same-boot loop run forever |
| Never reset a corrupt breaker file silently | Resetting outside `reset` clears a trip the operator has not seen |
| Never clear a trip without clearing the history | The counted window has not moved, so the next start re-trips |
| Never record the session after the launch | A panic terminates the agent with no exit code, so anything recorded afterwards is lost on precisely the restarts this exists for |
| Never discover the session id | Parsing it out of the agent's output, or globbing for the newest transcript, races every other agent on the machine |
| Never treat an unmeasurable transcript as small | `transcript_bytes` returns `None`, and the fallback to the resume count is reported |
| Never run the agent as root | A system unit runs as root unless told otherwise, and a coding agent keeps its login under the invoking user's home directory |
| Never bake the command into the unit | Editing `config/campaign.yaml` and rebooting must not keep running the old invocation |
| Never let a harvest failure stop the pipeline | Refusing to resume because pstore was empty costs a whole run |
| Never make preflight part of `run` | A preflight that blocked the supervisor would turn a warning into an outage |
| Never kill only the immediate child on a stall | The launch goes through a shell, so killing the child leaves the agent running, detached and still stuck |

## Design notes

`check` is pure: it takes the state it judges as an argument, so the thresholds
can be exercised without a machine that reboots.

`resolve_session` is pure and mutates nothing. It returns the session to store,
which invocation to use, and a one-line explanation, which is where an operator
sees whether a restart carried the previous context.

Rotation is primarily by transcript size, because size drives
auto-compaction. Restart count does not: a campaign that panics twenty times in
an hour writes almost nothing, while one that panics twice in three days writes
a great deal.

A resume that exits non-zero clears the session id. A transcript that cannot be
resumed would fail identically every `RestartSec` until the breaker tripped.
Dropping the id costs the reasoning history and preserves the campaign.

`render_command` substitutes with `str.replace`. These invocations routinely
carry a prompt containing braces. Its anchor falls back to the module default
when the configuration cannot be read, because this runs on the post-panic
recovery path and a resume that fails on a configuration error strands the
campaign.

`launch_agent` uses `shell=True` because the configured value is a command line
written by the operator. Nothing user-controlled reaches it at run time: it
comes from a configuration file only root can install a unit from.

## See also

- [Unattended operation](/gspwn/guides/unattended-operation/)
- [orchestrator_ctl.py reference](/gspwn/reference/cli/orchestrator-ctl/)
