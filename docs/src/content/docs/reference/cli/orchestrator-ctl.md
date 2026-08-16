---
title: orchestrator_ctl.py
description: The unattended supervisor, its circuit breaker and its session handling.
---

Keeps the orchestrating agent alive across panics, with a circuit breaker.

## Synopsis

```
python3 tools/orchestrator_ctl.py <subcommand> [options]
```

`install` and `remove` require root. The unit calls `run`. Running it
by hand does the same thing in the foreground.

## install

Writes and enables `gspwn-orchestrator.service`.

```
sudo python3 tools/orchestrator_ctl.py install [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--command` | `CMD` | `orchestrator.command` | The headless agent invocation |
| `--restart-sec` | `N` | 60 | systemd `RestartSec` |
| `--user` | `NAME` | `$SUDO_USER` | The user to run the agent as. Its home directory is where the agent's credentials live |
| `--force` | None | Off | Install even when that user has no `~/.claude` |

The command is read from the configuration at every launch, so editing
`config/campaign.yaml` and rebooting puts the new invocation in force. Passing
`--command` that differs from the configuration prints a note saying the next
install will overwrite it.

| Condition | Result |
|---|---|
| No agent command is set | Refused |
| No non-root user is available | Refused. A system unit runs as root, and a coding agent keeps its login under the invoking user's home directory. Left as root the agent would find no credentials and be restarted until the breaker tripped |
| That user cannot use `sudo -n` | Warning |
| `ANTHROPIC_API_KEY` is set in the installing environment | Warning |

## run

Launches one supervised agent session.

```
python3 tools/orchestrator_ctl.py run [--command CMD]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--command` | `CMD` | `orchestrator.command` | The headless agent invocation |

1. Read the configuration and resolve the agent command.
2. Take the breaker lock. Read the breaker state, record this start, check both
   limits.
3. Resolve the session and store it before launching, because a panic kills the
   agent with no exit code.
4. Check whether the pipeline should be driven at all.
5. Harvest crash logs, through `sudo -n` when not already root.
6. Launch the agent, bounded by `orchestrator.max_agent_hours`.
7. Clear the session id if a resume exited non-zero.

Returns the agent's exit code, or 78 when it declined to launch.

## status

Prints the unit state, the resolved command, the session, and the breaker
window.

```
python3 tools/orchestrator_ctl.py status
```

```
unit:      installed
command:   claude --session-id {session} -p 'Drive the pipeline per AGENTS.md.'
session:   3f9a0c2e-...; opened 2026-08-15 09:12:44
           transcript 2.3 MB (rotates at 6 MB)
           4 of 40 resume(s) used (backstop)
window:    60 min; limits: 5 same-boot start(s), 10 reboot(s)
in window: 3 start(s) across 3 boot(s)
  2026-08-16 03:44:01  boot 8a1c4d92
not blocked
```

Exits 1 when the breaker is tripped, 0 otherwise.

## preflight

Checks the configuration, the agent command, passwordless sudo, and disk
headroom.

```
python3 tools/orchestrator_ctl.py preflight [--user NAME]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--user` | `NAME` | The current user | Check `sudo -n` as the named user |

Exits 1 listing the problems. Deliberately not part of `run`: a preflight that
blocked the supervisor would turn a warning into an outage.

## reset

Clears the trip, the counted start history, and the session id.

```
python3 tools/orchestrator_ctl.py reset
```

Clearing the trip alone would re-trip on the next start, since the counted
window has not moved.

`reset` is the one command allowed to start over from a corrupt breaker file.
Every other read refuses on a parse error, because resetting it would clear a
trip nobody has seen.

## remove

Stops, disables and deletes the unit.

```
sudo python3 tools/orchestrator_ctl.py remove
```

The breaker state in `state/orchestrator.json` is kept.

## The circuit breaker

| Limit | Key | Trips when |
|---|---|---|
| Same-boot starts | `orchestrator.max_same_boot_starts` | The agent has started more than this many times on the current boot within `orchestrator.window_min` |
| Reboots | `orchestrator.max_reboots` | More than this many distinct boots appear in the window |

Counted separately because they mean different things: kernel fuzzing panics
the box by design, so reboots are expected, while an agent restarting on one
boot means nothing is progressing.

A start whose boot id cannot be read counts against the same-boot limit,
because assuming a reboot would let a same-boot loop run forever.

## The blocked exit

`run` returns 78 in four situations, and the unit lists that value in
`RestartPreventExitStatus`.

| Situation | Message |
|---|---|
| A breaker tripped | `circuit breaker tripped: ...` |
| `orchestrator.command` is unset | `orchestrator.command is not set in config/campaign.yaml` |
| A phase is `blocked` | `phase(s) X are blocked. A blocked gate is a stop by design` |
| The pipeline is complete | `the pipeline is complete. Nothing left to drive` |

A corrupt state file also stops the launch.

78 is `EX_CONFIG` from `sysexits.h`, chosen because it is expressible as a
process exit status and no Python runtime or shell produces it on its own.

## Session resume

Active only when `orchestrator.resume_command` is set.

| Decision | Reason printed |
|---|---|
| Fresh | `resume_command is unset, so every start is fresh; brief carries the position` |
| Fresh | `no previous session on record` |
| Fresh | `previous transcript is N MB (limit M), which is several auto-compactions in; rotating rather than carrying a summary of a summary` |
| Fresh | `previous session reached the resume backstop (N), rotating to a fresh one` |
| Resume | `resuming session ABC (resume N of M, transcript X MB)` |

The session id is a UUID generated here and substituted into the invocation for
`{session}`. Parsing it out of the agent's output, or globbing for the newest
transcript, races every other agent on the box.

Transcript size is measured by expanding `orchestrator.session_transcript_glob`
with the session id and summing the matches. An unmeasurable transcript is
recorded as `None`, because a size of zero would disable the rotation rule.

The resume count is incremented before the launch. A panic kills the agent
without an exit code, and that is the case where the transcript is growing
fastest.

`{anchor}` is replaced with `orchestrator.resume_anchor`. Substitution uses
`str.replace`, because an agent invocation routinely carries a prompt
containing braces.

## Stall detection

`orchestrator.max_agent_hours` bounds one launch. The process is killed by
process group, with `SIGTERM` and a 30-second grace, then `SIGKILL` and 10
seconds. Killing only the immediate child would leave the agent running,
detached and still stuck, because the launch goes through a shell.

A stall exit is non-zero and distinct from 78, so systemd restarts into a fresh
session.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. For `status`, the breaker is not tripped |
| 1 | A problem. For `status`, the breaker is tripped. For `preflight`, a check failed |
| 78 | `run` declined to launch |
| The agent's own code | `run` launched the agent |

## Files

| Path | Contents |
|---|---|
| `state/orchestrator.json` | Start history, the blocked record, and the current session |
| `state/orchestrator.json.lock` | The exclusive lock for read-modify-write on it |
| `gspwn-orchestrator.service` | The supervisor unit |

Machine-global. `GSPWN_ORCH` redirects the state file, and exists so the test
suite can point it at a temporary directory. A run that redirects `GSPWN_STATE`
must not also get a fresh, empty breaker.

## See also

- [Unattended operation](/gspwn/guides/unattended-operation/)
- [systemd units](/gspwn/reference/systemd-units/)
</content>
</invoke>
