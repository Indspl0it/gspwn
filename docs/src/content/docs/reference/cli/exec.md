---
title: exec.py
description: Running a command with logging, retries and a timeout.
---

A logged local command runner. Standard library only.

## Synopsis

```
python3 tools/exec.py --log NAME [--retries N] [--timeout S] -- CMD [ARGS...]
```

No subcommands. Root is never required. Everything after `--` is the command
and its arguments. The leading `--` is consumed.

## Options

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--log` | `NAME` | Required | The log file name, written to `artifacts/logs/<NAME>.log` |
| `--retries` | `N` | 0 | Additional attempts after a failure |
| `--timeout` | `S` | None | Seconds per attempt |

```
python3 tools/exec.py --log build-rung1 --timeout 21600 -- \
  bash tools/build_kernel.sh
```

`--log` is reduced to its basename, so a value containing path segments cannot
escape `artifacts/logs/`. The directory is created if absent.

## Retries

An attempt that exits 0 returns immediately. Otherwise the runner sleeps two
seconds and tries again, until `--retries` additional attempts are exhausted.
The last attempt's exit code is returned.

| Condition | Result |
|---|---|
| The attempt exceeded `--timeout` | Recorded as `TIMEOUT after Ns`, exit 124 |
| The command does not exist | Recorded as an attempt like any other failure, exit 127 |

## The log

Each attempt appends a header, then the command's merged standard output and
standard error:

```
=== 2026-08-15T09:12:44 attempt 1: bash tools/build_kernel.sh
...

=== 2026-08-15T09:14:02 attempt 2: bash tools/build_kernel.sh
TIMEOUT after 21600s
```

## Callers

The `build` sub-agent wraps each rung of the degradation ladder in it, so a
failed rung leaves a log the next rung's diagnosis can read.

## Exit codes

| Code | Meaning |
|---|---|
| The command's own code | Normal completion |
| 124 | The attempt exceeded `--timeout` |
| 127 | The command does not exist |

## Files

| Path | Contents |
|---|---|
| `artifacts/logs/<NAME>.log` | Per-attempt headers and merged command output |

## See also

- [build_kernel.sh](/gspwn/reference/cli/build-kernel/)
- [Artifacts](/gspwn/reference/artifacts/)
</content>
</invoke>
