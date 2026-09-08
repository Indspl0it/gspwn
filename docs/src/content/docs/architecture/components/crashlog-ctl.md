---
title: crashlog_ctl.py
description: Persistent kernel-crash capture, harvesting and pruning.
---

Sets up and operates the crash-capture path: ramoops and pstore plus kdump on
bare metal, kdump plus the EC2 serial console in the cloud. Harvested evidence
is written to `artifacts/crashes/pstore-<YYYYmmdd-HHMMSS>/`, one directory per
harvest, and the directory path is the last line `harvest` prints.

`setup`, `harvest` and `prune` require root. `verify` does not. Debian-family
package management only.

The command line is read from `sys.argv` by hand, with no argparse, so an
unknown subcommand, a missing `--env` value or a bad `--keep` value prints the
module docstring or a one-line message and exits 1.

| Argument | Values | Default |
|---|---|---|
| Subcommand | `setup`, `verify`, `harvest`, `prune` | required, exactly one |
| `--env` | `ec2`, `baremetal`, `auto` | `auto`, which detects through the instance metadata service |
| `--keep` | A non-negative integer, read by `prune` alone | `10`. `0` deletes every harvest directory |

## Responsibility

The module owns the crash-capture configuration and the harvest directory. It is
the sole writer of `artifacts/crashes/`. `repro_ctl.harvested_logs` reads the
newest `pstore-*` directory there.

| Invariant | Enforced by |
|---|---|
| An empty harvest means the sources were readable and empty | `cmd_harvest` refuses to run as non-root, where the globs return empty and the copies raise |
| Nothing to harvest, could not look, and looked partially are distinguishable | The three conditions carry different exit codes: 0, 1 and 2 |
| pstore is left with space for the next panic | Every copied record is deleted from `/sys/fs/pstore` |
| Several panics between harvests are all captured | Every `/var/crash` dump present is taken, oldest first by modification time |
| A harvest already taken is not re-copied | `harvested_kdumps` recognises the `kdump-` prefixed directories of earlier harvests |
| Evidence is never deleted without an explicit command | `prune` is the only deletion path |

## Subcommands

| Command | Work |
|---|---|
| `setup` | Install `kdump-tools`, and `pstore-tools` off EC2; add `crashkernel=256M` to the boot line; mount `/sys/fs/pstore` off EC2; enable `kdump-tools` |
| `verify` | Check readiness and print the deliberate-panic test |
| `harvest` | Copy every source into a new timestamped directory, whose path is the last line of output |
| `prune` | Delete the oldest harvest directories beyond the newest `--keep`, and report what was freed |

`setup` backs `/etc/default/grub` up to `/etc/default/grub.bak-gspwn` before
editing it, and skips the edit outright when `crashkernel=` is already on the
line.

`verify` checks four things and exits 1 if any of the three hard checks fails.

| Check | Applies to | Result of failure |
|---|---|---|
| `/sys/fs/pstore` is a directory | Bare metal | Fails |
| `crashkernel=` in `/proc/cmdline` | Both | Fails, directing a reboot |
| The `aws` CLI is on `PATH` | EC2 | Fails, since console-output harvest needs it |
| `kdump-tools` is active | Both | Warns, and readiness still holds |

## Sources harvested

| Environment | Sources |
|---|---|
| EC2 | `aws ec2 get-console-output --latest` for this instance, written to `console-output.log`, plus every new `/var/crash` dump |
| Bare metal | Every file in `/sys/fs/pstore`, deleted after it is copied, plus every new `/var/crash` dump |

Each `/var/crash` dump is copied to `kdump-<name>` inside the harvest directory,
which is also how a later harvest recognises it as already taken.

## Environment detection

`detect_env` requests `instance-id` from `http://169.254.169.254/latest`, an
IMDSv2 token first and IMDSv1 when the token endpoint does not answer. Each
request is bounded by a two-second timeout, so a bare-metal host stalls for at
most that per request. An answer means `ec2` and anything else means
`baremetal`.

## Callers

- `orchestrator_ctl.harvest` runs it as a subprocess with a 300 second timeout,
  through `sudo -n` when not already root, and reports a non-zero exit without
  stopping the resume.
- The `provision` sub-agent reproduces `detect_env`, relying on its documented
  behaviour.
- It imports `coverage_ctl.py` lazily, inside a `try`, for the disk report.

## Exit codes

| Code | Conditions |
|---|---|
| 0 | The command completed, including a harvest that found nothing with every source readable |
| 1 | A root refusal, a missing GRUB anchor, a failed `verify`, a harvest that read nothing while a source failed, or an unusable command line |
| 2 | `HARVEST_PARTIAL`: evidence was collected and at least one source was unread or deferred. The harvest directory exists and its path is still the last line on stdout |

2 is separate from 0 because an unattended caller that reads only the exit code
has no other way to learn the harvest is incomplete, and a partial harvest
reported as success leaves a panic's only record treated as collected. It is
separate from 1 because 1 collected nothing and 2 has evidence on disk. A source
is deferred when kdump is still writing the dump, which a later `harvest` picks
up.

## Failure modes

Thirteen conditions have a defined behaviour.

| Condition | Behaviour |
|---|---|
| `setup`, `harvest` or `prune` run as non-root | Message naming the command and why root is needed. `harvest` also names `orchestrator_ctl.py preflight` for the passwordless rule |
| Neither `GRUB_CMDLINE_LINUX_DEFAULT` nor `GRUB_CMDLINE_LINUX` present | `setup` stops and prints the line to add by hand |
| `verify` finds the capture path ready | Prints the deliberate-panic test, three numbered steps |
| `verify` finds it not ready | Prints what is missing and exits 1 |
| `aws ec2 get-console-output` fails or returns nothing | Warns carrying the tool's stderr, and the rest of the harvest continues |
| A pstore record cannot be copied | Warns naming the file, records it as a failure and continues |
| A pstore record cannot be deleted after copying | Warns that pstore may fill and drop later panics |
| A `/var/crash` dump cannot be copied | Warns naming the directory, records it as a failure and continues |
| Harvest finds nothing and every source was readable | Prints what was checked and removes the directory it created |
| Harvest finds nothing and at least one source failed | Names up to five failed sources and states this is not evidence that no crash occurred |
| Harvest reads some sources and fails on others | Warns naming up to five missing sources, prints the harvest directory and exits 2 |
| A `/var/crash` dump is still being written | Warns naming up to five deferred dumps, tells the operator to re-run once they finish, prints the harvest directory and exits 2 |
| `coverage_ctl` import fails | The disk report drops the free-space figure and the harvest continues |

## Concurrency and durability

The harvest directory is created per invocation and named for the time the
harvest ran, so two harvests never write the same path. Each file is copied
independently and failures are collected, so a file that vanishes mid-harvest
does not abandon the rest. `kdump-tools` may be writing to `/var/crash`
concurrently, which is the condition that makes per-file isolation necessary.
An empty harvest removes its own directory. No lock is taken, and
`harvested_kdumps` makes a re-run copy only what is new.

## Prohibited behaviour

Seven rules cover the harvest's reporting, pstore's fixed size and the GRUB
edit.

| Rule | Rationale |
|---|---|
| Never report an empty result when the sources are unreadable | `/sys/fs/pstore` and `/var/crash` are root-only. Run as another user, the globs return empty and the copies raise, which produces a clean exit 0 while the evidence stays on the machine until pstore fills and drops later panics |
| Never conflate an empty harvest with an unreadable source | The orchestrator runs this unattended after every panic and has to tell them apart |
| Never leave pstore records in place | It is a small fixed-size backend that frees a record only when the file is deleted |
| Never take only the newest `/var/crash` dump | Several panics can occur between two harvests |
| Never abandon a harvest on one unreadable file | Files can vanish mid-harvest. The rest of the harvest is written and the missing sources are named, and the exit code is 2 so the incompleteness reaches a caller that reads nothing else |
| Never prune automatically | Harvested logs are evidence, and the count that is kept is a stated decision |
| Never guess a GRUB anchor | With neither anchor present, `setup` stops and prints the line to add by hand |

## Design notes

Environment detection is bounded by a two-second timeout, so a non-EC2 host
does not stall.

`repro_ctl.py` treats a harvest older than the current boot as absent, because
it cannot describe the run that panicked the machine. It skips `vmcore` files
and reads the dmesg and console text beside them.

`report_disk` runs on both `harvest` and `prune`, because those are the two
commands where the operator is already reviewing what the crash logs cost. It
sizes `artifacts/crashes/` and `/var/crash`, adds the free space
`coverage_ctl.disk_free_mb` reports, and appends the `prune` command when free
space is under `loop.min_free_disk_gb`.

## See also

- [Disk and crash logs](/gspwn/guides/disk-and-crash-logs/)
