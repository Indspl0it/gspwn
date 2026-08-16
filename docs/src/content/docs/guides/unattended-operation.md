---
title: Unattended operation
description: Install the orchestrator supervisor, understand the circuit breaker, and manage session resume.
---

The pipeline's state, timers and campaigns survive a kernel panic. An agent
session does not: after a panic the session is gone and the recovery procedure
needs a login before it runs. `tools/orchestrator_ctl.py` installs a process
supervisor that runs the recovery procedure without one.

A fresh agent needs no memory of the old session, because
`pipeline_ctl.py next` reports where the pipeline is. The state machine holds
that position across restarts.

## Preflight

```
python3 tools/orchestrator_ctl.py preflight
```

```
config:    valid
command:   claude --session-id {session} -p 'Drive the pipeline per AGENTS.md.'
sudo -n:   ok (sudo -n succeeds)
           needs it for: crashlog_ctl.py harvest (post-panic crash log capture)
           needs it for: campaign_ctl.py install-k (starting a Track K campaign)
           needs it for: coverage_ctl.py install-timer (installing the coverage sampler)
disk:      412.6 GB free

preflight clean
```

It checks the configuration, the agent command, passwordless sudo and disk
headroom, and exits 1 listing what is missing. It is deliberately not part of
`run`: a preflight that blocked the supervisor would turn a warning into an
outage.

## Passwordless sudo

The orchestrator harvests crash logs with `sudo -n`, and campaign installs and
the coverage sampler need root from a headless session that cannot answer a
password prompt. Without a passwordless rule the harvest silently captures
nothing and every campaign install fails.

Write the rule with `visudo`, which validates it:

```
sudo visudo -f /etc/sudoers.d/gspwn
```

```
<agent-user> ALL=(root) NOPASSWD: /usr/bin/python3 /path/to/repo/tools/*.py
```

:::danger[Equivalent to unrestricted root unless the repository is protected]
If the agent user can write those scripts, it can write anything root would
run. Keep the repository root-owned on the machine under test and grant the
agent user read and execute only. No tool writes this rule.
:::

## Set the agent command

```yaml
orchestrator:
  command: "claude --session-id {session} -p 'Drive the pipeline per AGENTS.md.'"
```

There is no default. The repository works with any `AGENTS.md`-aware coding
agent and does not guess which one is installed, so `install` refuses until
this is set.

## Install the supervisor

```
sudo python3 tools/orchestrator_ctl.py install
```

```
installed and enabled gspwn-orchestrator
  runs as:  researcher (HOME=/home/researcher)
  command:  claude --session-id {session} -p 'Drive the pipeline per AGENTS.md.'
  resume:   off — every restart starts a fresh session. Set orchestrator.resume_command to carry the previous one.
  restart:  every 60s, blocked at 5 same-boot start(s) or 10 reboot(s) per 60 min
start it now with: sudo systemctl start gspwn-orchestrator
```

The unit runs as a non-root user, taken from `--user` or `$SUDO_USER`. A system
unit runs as root unless told otherwise, and a coding agent keeps its login
under the invoking user's home directory. Left as root the agent would look in
`/root`, find no credentials, fail, and be restarted until the breaker trips.
`install` refuses when it has no non-root user to use.

The command lives in the configuration and the unit reads it at launch, so
editing `config/campaign.yaml` and rebooting cannot silently keep running the
old invocation.

:::caution[ANTHROPIC_API_KEY in the unit environment bills the API]
`install` warns when the variable is set in its own environment. If it is also
set for the unit, through `/etc/environment` or a drop-in, it takes precedence
over a subscription login. The unit written here does not set it.
:::

## The circuit breaker

An always-restarting agent consumes tokens with no ceiling. `run` refuses to
launch under two conditions, counted separately because they mean different
things.

| Condition | Key | Meaning |
|---|---|---|
| Same-boot starts | `orchestrator.max_same_boot_starts` | The agent keeps exiting and being restarted without the machine going down. Nothing is progressing and each restart costs tokens |
| Reboots | `orchestrator.max_reboots` | The machine keeps going down. Kernel fuzzing panics the machine by design, so this is expected; it is a problem only when reboots arrive faster than a round can progress between them |

Both are counted within `orchestrator.window_min`. Counting them against one
limit would stop a campaign that is panicking normally, or allow a same-boot
loop to run for hours.

A start whose boot id cannot be read counts against the same-boot limit, because
assuming a reboot would let a same-boot loop run forever.

## Conditions that stop the unit

`run` exits 78 in four situations, and the unit lists that code in
`RestartPreventExitStatus`, so systemd stops the unit and does not restart it.

| Situation | Reason a restart does not help |
|---|---|
| A breaker tripped | The next start hits the same limit |
| `orchestrator.command` is unset | Only a human can supply it |
| A phase is `blocked` | A blocked gate is a stop by design |
| The pipeline is complete | Nothing left to drive |

A corrupt state file also stops the launch, because a relaunched agent would
read the same broken file and stop again, once per restart.

## Reading and clearing the breaker

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
  2026-08-16 04:12:07  boot 1f2e9b77
  2026-08-16 04:51:33  boot c40db8a1
not blocked
```

```
sudo systemctl status gspwn-orchestrator
journalctl -u gspwn-orchestrator -n 200
```

After fixing the cause:

```
python3 tools/orchestrator_ctl.py reset
sudo systemctl start gspwn-orchestrator
```

`reset` clears the trip, clears the counted history, and starts a fresh
session. Clearing the trip alone would re-trip on the very next start, since
the counted window has not moved. The session is cleared because a transcript
the agent kept failing to resume is one of the likelier causes of a trip.

`reset` is also the documented way out of a corrupt breaker file. Every other
read of that file refuses on a parse error, because an automatic reset would
clear a trip nobody has seen.

## Session resume

A fresh agent is always sufficient to continue the pipeline. A fresh start
loses the previous session's reasoning, which the state file does not record:
what was tried and what was ruled out.

```yaml
orchestrator:
  command: "claude --session-id {session} -p 'Drive the pipeline per AGENTS.md.'"
  resume_command: "claude --resume {session} -p '{anchor}'"
  session_transcript_glob: "~/.claude/projects/*/{session}.jsonl"
```

Three properties of the session make resuming safe.

The session id is assigned by the tool. It is a UUID generated before the
launch and substituted into the invocation. Parsing it out of the agent's
output, or globbing for the newest transcript, races every other agent on the
machine. Both invocations must contain `{session}`, and the configuration
refuses a pair where one does not.

The session is bounded. It rotates once its transcript passes
`orchestrator.max_session_mb`, measured through
`orchestrator.session_transcript_glob`. Size is the rule because size drives
auto-compaction. Restart count tracks it poorly, since twenty restarts may
write less than one long uninterrupted stretch. `orchestrator.max_resumes` is
the backstop for when the transcript cannot be measured, and the tool reports
each fall back to it.

A resume that exits non-zero clears the session id. The next start is then
clean, and no loop forms against a transcript that cannot be resumed.

The resume count is incremented before the launch. A panic kills the agent
without an exit code, and that is the case where the transcript is growing
fastest.

`{anchor}` is replaced with `orchestrator.resume_anchor`: a paragraph telling
the resumed agent that its last turn predates the interruption and that
`pipeline_ctl.py brief` is authoritative. Without it the agent continues from a
half-finished tool call issued at the moment the kernel died.

The anchor may contain no apostrophe or double quote, because it is substituted
into a shell command line the operator has already quoted.

## Stall detection

The breaker counts starts, not stalls. An agent blocked on an interactive
prompt or a wedged tool would hold the pipeline open indefinitely while the
instance billed.

```yaml
orchestrator:
  max_agent_hours: 30
```

The launch is killed by process group when it exceeds that, because the
immediate child is a shell and killing only that leaves the agent running
detached. `0` disables the timeout.

The value must exceed `loop.campaign_hours`, because the `fuzz` phase
legitimately waits out the whole campaign window inside one launch. The
configuration refuses a value that does not.

A stall exit is distinct from the blocked exit code, so systemd restarts into a
fresh session, which recovers a stalled launch.

## The `run` sequence

```
python3 tools/orchestrator_ctl.py run
```

Running it by hand performs the same sequence in the foreground.

1. Read the configuration and the agent command.
2. Take the breaker lock, read the breaker state, record this start, check both
   limits.
3. Resolve the session, deciding fresh against resume, and store it **before**
   launching.
4. Check whether the pipeline should be driven at all.
5. Harvest crash logs. A harvest failure is reported and does not stop the
   resume, because refusing to resume over an empty pstore would cost a whole
   run to preserve one log.
6. Launch the agent, bounded by `max_agent_hours`.
7. On a failed resume, clear the session id.

## Removing the supervisor

```
sudo python3 tools/orchestrator_ctl.py remove
```

```
removed gspwn-orchestrator (breaker state in state/orchestrator.json is kept; `reset` clears it)
```

## See also

- [Long-running campaigns](/gspwn/guides/long-running-campaigns/) covers the
  recovery sequence the supervisor automates.
- [systemd units](/gspwn/reference/systemd-units/) lists every generated unit.
- [orchestrator_ctl.py reference](/gspwn/reference/cli/orchestrator-ctl/)
