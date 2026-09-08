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
| Several panics between harvests are all captured | Every `/var/crash` dump present is taken |
| A harvest already taken is not re-copied | `harvested_kdumps` recognises the `kdump-` prefixed directories of earlier harvests |
| Evidence is never deleted without an explicit command | `prune` is the only deletion path |

## Operations

| Command | Purpose |
|---|---|
| `setup` | Install kdump and pstore and add `crashkernel=` to the boot line |
| `verify` | Check readiness and print the deliberate-panic test |
| `harvest` | Copy every source into a new timestamped directory, whose path is the last line of output |
| `prune` | Delete the oldest harvest directories beyond the count kept |

## Callers

| Direction | Modules |
|---|---|
| Invokes this module | `orchestrator_ctl.harvest` runs it as a subprocess, through `sudo -n` when not already root |
| Uses its documented behaviour | The `provision` sub-agent reproduces `detect_env` |
| This module imports | `coverage_ctl.py` lazily, inside a `try`, for the disk report |

## Failure modes

| Condition | Behaviour |
|---|---|
| `setup`, `prune` or `harvest` run as non-root | Message naming the command and why root is needed |
| Neither `GRUB_CMDLINE_LINUX_DEFAULT` nor `GRUB_CMDLINE_LINUX` present | `setup` stops and prints the line to add by hand |
| `verify` finds the capture path ready | Prints the deliberate-panic test |
| `verify` finds it not ready | Prints what is missing |
| Harvest finds nothing and every source was readable | Prints what was checked and removes the directory it created |
| Harvest finds nothing and at least one source failed | Names the failed sources and states this is not evidence that no crash occurred |
| Harvest reads some sources and fails on others | Warns naming the missing sources, and the partial harvest succeeds |
| Instance metadata service does not answer | `detect_env` reports `baremetal` after the two-second timeout |
| `coverage_ctl` import fails | The disk report is skipped and the harvest continues |

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

Environment detection is bounded by a two-second timeout, so a non-EC2 host
does not stall.

`repro_ctl.py` treats a harvest older than the current boot as absent, because
it cannot describe the run that panicked the machine.

`report_disk` runs on both `harvest` and `prune`, because those are the two
commands where the operator is already reviewing what the crash logs cost.

## See also

- [Disk and crash logs](/gspwn/guides/disk-and-crash-logs/)
