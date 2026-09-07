---
title: exec.py
description: Logged command execution with retries and a timeout.
---

`exec.py` runs one local command, appends everything it prints to
`artifacts/logs/<name>.log`, and repeats the attempt when it fails. The module
uses the standard library alone and imports nothing from `tools/`.

The `build` sub-agent wraps each rung of the degradation ladder in it, so a
failed rung leaves a log the next rung's diagnosis can read.

## Invocation

```
python3 tools/exec.py --log NAME [--retries N] [--timeout S] -- CMD [ARGS...]
```

| Option | Default | Effect |
|---|---|---|
| `--log NAME` | required | Names the log file. `NAME` is reduced to its basename, and an empty basename becomes `exec` |
| `--retries N` | `0` | Repeats a failing command up to `N` times, so the run makes at most `N + 1` attempts |
| `--timeout S` | `14400`, four hours, or the value of `GSPWN_EXEC_TIMEOUT_SEC` | Seconds one attempt may take. `0` runs unbounded. The longest command wrapped here is a kernel build, which takes hours on the smaller instances, so four hours is a backstop and not a working limit |
| `CMD [ARGS...]` | required | The command. A leading `--` separator is dropped before the command is run |

The exit code is the last attempt's exit code.

| Exit code | Meaning |
|---|---|
| The command's own code | The command ran to completion on the final attempt |
| 124 | The final attempt exceeded `--timeout` |
| 127 | The binary named by `CMD` does not exist |
| 2 | No command followed `--` |

## Responsibility

The module owns one command invocation and its log file.

| Invariant | Enforced by |
|---|---|
| A log is never written outside `artifacts/logs/` | `--log` is reduced to its basename |
| An attempt is never lost to an uncaught exception | `FileNotFoundError` and `TimeoutExpired` are caught and logged like any other failure |
| A timeout is recorded before the exit code is set | The timeout line is written inside the `except` branch |
| The log shows what a terminal would have shown | Standard error is merged into standard output |
| Several attempts in one log stay readable | Each attempt appends a header carrying the timestamp, the attempt number and the command |
| The reported code describes the final outcome | `run` returns the last attempt's code |

## Callers

The `build` sub-agent invokes the module as a command, wrapping each rung of
the degradation ladder. No module imports it, and it imports no module in
`tools/`.

## Failure modes

Six conditions decide the outcome of an attempt. Every one but the argument
error reaches the log.

| Condition | Behaviour |
|---|---|
| Command succeeds | Retries stop immediately |
| Command fails with retries left | The failure is logged and the attempt repeats after two seconds |
| Command fails with no retries left | The last attempt's code is returned |
| Attempt exceeds `--timeout` | `TIMEOUT after Ns` is written to the log and the code becomes 124 |
| Binary does not exist | `command not found: <cmd>` is written to the log and the code becomes 127 |
| No command given after `--` | Argument parser error, exit 2, and no log is written |

## Concurrency and durability

The module opens the log in append mode for each attempt and hands the file
object to the child as its standard output and standard error, so the child's
output reaches the file without buffering through this process.

Two invocations sharing a log name interleave their attempts, because the
module takes no lock. Each attempt therefore writes its own header line, and a
reader separates the two runs by attempt number and timestamp.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never let a path component escape the log directory | `--log` is agent-supplied, so a value of `../../x` would write outside `artifacts/logs/` |
| Never lose an attempt to an uncaught exception | A missing binary raises `FileNotFoundError`, which is caught, logged and mapped to 127 |
| Never lose the output of an attempt that timed out | The timeout is recorded in the log before the exit code is set |
| Never import from `gspwn_config` or the rest of `tools/` | This runs before the rest of the machine is provisioned |

## See also

- [build_kernel.sh](/gspwn/architecture/components/build-kernel/)
