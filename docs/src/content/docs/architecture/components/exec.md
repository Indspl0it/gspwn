---
title: exec.py
description: Logged command execution with retries and a timeout.
---

A logged local command runner. Standard library only, and it imports nothing
from `tools/`. Output is appended to `artifacts/logs/<name>.log`.

The `build` sub-agent wraps each rung of the degradation ladder in it, so a
failed rung leaves a log the next rung's diagnosis can read.

## Responsibility

The module owns one command invocation and its log file.

| Invariant | Enforced by |
|---|---|
| A log never lands outside `artifacts/logs/` | `--log` is reduced to its basename |
| An attempt is never lost to an uncaught exception | `FileNotFoundError` and `TimeoutExpired` are caught and logged like any other failure |
| A timeout is recorded before the exit code is set | The timeout line is written inside the `except` branch |
| The log shows what a terminal would have shown | Standard error is merged into standard output |
| Several attempts in one log stay readable | Each attempt appends a header with the timestamp, attempt number and command |
| The reported code describes the final outcome | `run` returns the last attempt's code |

## Interface

Command form: `--log NAME [--retries N] [--timeout S] -- CMD [ARGS...]`.

| Function | Returns |
|---|---|
| `run(cmd, log_name, retries=0, timeout=None)` | The last attempt's exit code |

The gap between attempts is a fixed two seconds.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing |
| Invokes it | The `build` sub-agent, wrapping each rung of the degradation ladder |
| This module imports | Nothing in `tools/` |

## Failure modes

| Condition | Behaviour | Exit code |
|---|---|---|
| Command succeeds | Retries stop immediately | 0 |
| Command fails with retries left | The failure is logged and the attempt repeats after two seconds | |
| Command fails with no retries left | The last attempt's code is returned | The command's code |
| Attempt exceeds `--timeout` | `TIMEOUT after Ns` is written to the log | 124 |
| Binary does not exist | `command not found: <cmd>` is written to the log | 127 |
| No command given after `--` | Argument parser error | 2 |

## Concurrency and durability

The module opens the log in append mode for each attempt and passes the file
object directly to the child as stdout and stderr, so the child's output reaches
the file without buffering through this process. No lock is taken: two
invocations sharing a log name interleave their attempts, which is why each
attempt writes its own header line. No import from `gspwn_config` and no
dependency on `tools/`, because this wraps builds that may run before anything
else on the machine is installed.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never let a path component escape the log directory | `--log` is agent-supplied, so a value of `../../x` would write outside `artifacts/logs/` |
| Never lose an attempt to an uncaught exception | A missing binary raises `FileNotFoundError`, which is caught, logged and mapped to 127 |
| Never lose the output of an attempt that timed out | The timeout is recorded in the log before the exit code is set |
| Never import from `gspwn_config` or the rest of `tools/` | This runs before the rest of the machine is provisioned |

## Design notes

Standard output and standard error are merged into the log file, so the
interleaving matches what a terminal would have shown.

Each attempt appends a header with the timestamp, the attempt number and the
command, so a log holding several attempts is readable.

The exit code returned is the last attempt's, so it reports whether the command
eventually succeeded.

## See also

- [exec.py reference](/gspwn/reference/cli/exec/)
- [build_kernel.sh](/gspwn/architecture/components/build-kernel/)
