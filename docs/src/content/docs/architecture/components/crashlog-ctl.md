---
title: crashlog_ctl.py
description: Persistent kernel-crash capture, harvesting and pruning.
---

Sets up and operates the crash-capture path: ramoops and pstore plus kdump on
bare metal, kdump plus the EC2 serial console in the cloud. Harvested evidence
lands in a timestamped directory under `artifacts/crashes/`.

Every command except environment detection requires root.

## Responsibility

The module owns the crash-capture configuration and the harvest directory. It is
the sole writer of `artifacts/crashes/`.

| Invariant | Enforced by |
|---|---|
| An empty harvest means the sources were readable and empty | `cmd_harvest` refuses to run as non-root, where the globs return empty and the copies raise |
| "Nothing to harvest" and "could not read a source" are distinguishable | The two conditions carry different exit codes |
| pstore is left with space for the next panic | Every copied record is deleted from `/sys/fs/pstore` |
| Several panics between harvests are all captured | Every `/var/crash` dump is taken, not only the newest |
| A harvest already taken is not re-copied | `harvested_kdumps` recognises the `kdump-` prefixed directories of earlier harvests |
| Evidence is never deleted without an explicit command | `prune` is the only deletion path |

## Interface

The argument parser is hand-rolled, so there is no `--help`. A usage error
prints the module docstring.

| Command | Purpose |
|---|---|
| `setup` | Install kdump and pstore and add `crashkernel=` to the boot line |
| `verify` | Check readiness and print the deliberate-panic test |
| `harvest` | Copy every source into a new timestamped directory |
| `prune --keep N` | Delete the oldest harvest directories beyond N |

| Function | Returns | Raises |
|---|---|---|
| `detect_env()` | `"ec2"` when the instance metadata service answers, else `"baremetal"` | |
| `imds_get(path)` | The metadata value | Raises on failure, bounded by a two-second timeout |
| `get_instance_id()` | The instance id | |
| `harvested_kdumps()` | Basenames of `/var/crash` dumps already copied | |
| `report_disk()` | `None`; prints harvest size and a low-space warning | |
| `cmd_harvest(env)` | `None`; prints the harvest path as its last line | Exits per the table below |

## Callers

| Direction | Modules |
|---|---|
| Invokes this module | `orchestrator_ctl.harvest` runs it as a subprocess, through `sudo -n` when not already root |
| Uses its documented behaviour | The `provision` sub-agent reproduces `detect_env` |
| This module imports | `coverage_ctl.py` lazily, inside a `try`, for the disk report |

## Failure modes

| Condition | Behaviour | Exit code |
|---|---|---|
| `setup`, `prune` or `harvest` run as non-root | Message naming the command and why root is needed | 1 |
| Neither `GRUB_CMDLINE_LINUX_DEFAULT` nor `GRUB_CMDLINE_LINUX` present | `setup` stops and prints the line to add by hand | 1 |
| `verify` finds the capture path ready | Prints the deliberate-panic test | 0 |
| `verify` finds it not ready | Prints what is missing | 1 |
| Harvest finds nothing and every source was readable | Prints what was checked and removes the directory it created | 0 |
| Harvest finds nothing and at least one source failed | Names the failed sources and states this is not evidence that no crash occurred | 1 |
| Harvest reads some sources and fails on others | Warns naming the missing sources, and the partial harvest succeeds | 0 |
| Instance metadata service does not answer | `detect_env` reports `baremetal` after the two-second timeout | |
| `coverage_ctl` import fails | The disk report is skipped and the harvest continues | |

## Concurrency and durability

The harvest directory is created per invocation and named for the time the
harvest ran, so two harvests never write the same path. Each file is copied
independently and failures are collected, so a file that vanishes mid-harvest
does not abandon the rest. `kdump-tools` may be writing to `/var/crash`
concurrently, which is the condition that makes per-file isolation necessary.
An empty harvest removes its own directory. No lock is taken; `harvested_kdumps`
makes a re-run copy only what is new.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never report an empty result when the sources are unreadable | `/sys/fs/pstore` and `/var/crash` are root-only. Run as another user, the globs return empty and the copies raise, which produces a clean exit 0 while the evidence stays on the machine until pstore fills and drops later panics |
| Never conflate an empty harvest with an unreadable source | The orchestrator runs this unattended after every panic and has to tell them apart |
| Never leave pstore records in place | It is a small fixed-size backend that frees a record only when the file is deleted |
| Never take only the newest `/var/crash` dump | Several panics can land between two harvests |
| Never abandon a harvest on one unreadable file | Files can vanish mid-harvest; a partial harvest succeeds while naming what is missing |
| Never prune automatically | Harvested logs are evidence, and the count that is kept is a stated decision |
| Never guess a GRUB anchor | With neither anchor present, `setup` stops and prints the line to add by hand |

## Design notes

Environment detection prefers IMDSv2 and falls back to IMDSv1 only when the
token endpoint does not answer, bounded by a two-second timeout so a non-EC2
host does not stall.

`prune` never runs detection, because what it deletes does not depend on the
environment.

The harvest directory is named for the time the harvest ran. `repro_ctl.py`
treats a harvest older than the current boot as absent, because it cannot
describe the run that panicked the machine.

Already-harvested `/var/crash` dumps are recognised by the `kdump-` prefixed
directories of earlier harvests, so a re-run copies only what is new.

An empty harvest removes the directory it created, so the tree does not fill
with empty timestamped directories on a quiet machine.

`report_disk` runs on both `harvest` and `prune`, because those are the two
commands where the operator is already reviewing what the crash logs cost.

## See also

- [Disk and crash logs](/gspwn/guides/disk-and-crash-logs/)
- [crashlog_ctl.py reference](/gspwn/reference/cli/crashlog-ctl/)
