---
title: crashlog_ctl.py
description: Persistent kernel-crash capture, harvesting and pruning.
---

Sets up and operates persistent kernel-crash capture: ramoops/pstore plus kdump
on bare metal, kdump plus EC2 console output in the cloud.

## Synopsis

```
python3 tools/crashlog_ctl.py [--env ec2|baremetal|auto] [--keep N] <subcommand>
```

:::note[No --help]
This tool has a hand-rolled argument parser. A usage error prints the module
docstring.
:::

`setup`, `harvest` and `prune` require root. Debian-family only: `setup` uses
`apt-get`.

## Options

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--env` | `ec2`, `baremetal`, `auto` | `auto` | Override environment detection |
| `--keep` | `N` | 10 | `prune` only. Harvest directories to keep |

Auto-detection queries `http://169.254.169.254/latest/meta-data/instance-id`
with a two-second timeout, preferring IMDSv2 and falling back to IMDSv1 only
when the token endpoint does not answer.

`prune` never runs detection, because what it deletes does not depend on the
environment.

## setup

Installs and configures the crash-capture machinery.

```
sudo python3 tools/crashlog_ctl.py setup
```

1. `apt-get update`.
2. Install `kdump-tools`, and `pstore-tools` on bare metal.
3. Add `crashkernel=256M` to the GRUB command line if absent, backing up
   `/etc/default/grub` to `/etc/default/grub.bak-gspwn` first, then
   `update-grub`.
4. Mount pstore on bare metal if it is not mounted.
5. Enable `kdump-tools`.

The `crashkernel` parameter is added to `GRUB_CMDLINE_LINUX_DEFAULT`, or to
`GRUB_CMDLINE_LINUX` when the first is absent.

| Condition | Result |
|---|---|
| Neither GRUB command-line variable is present | Stops and prints the line to add by hand |

A reboot is required before `verify` passes.

## verify

Checks that the machinery is in place.

```
sudo python3 tools/crashlog_ctl.py verify
```

| Check | Failure |
|---|---|
| `/sys/fs/pstore` exists, bare metal only | `FAIL`, exit 1 |
| `kdump-tools` is active | `WARN`, does not fail |
| `crashkernel=` is in `/proc/cmdline` | `FAIL`, exit 1. A reboot is needed |
| The `aws` CLI is present, EC2 only | `FAIL`, exit 1 |

On success it prints `READY` and the deliberate-panic sequence. `READY` covers
the machinery. The sysrq test proves it works.

## harvest

Creates `artifacts/crashes/pstore-<YYYYmmdd-HHMMSS>/` and collects the crash
sources into it.

```
sudo python3 tools/crashlog_ctl.py harvest
```

| Source | Environment | Destination |
|---|---|---|
| `/sys/fs/pstore/*` | Bare metal | The harvest directory root |
| `aws ec2 get-console-output --latest` | EC2 | `console-output.log` |
| Every unharvested `/var/crash/*` directory | Both | `kdump-<name>/` |

pstore records are deleted after copying. pstore is a small fixed-size backend
that frees a record only when the file is deleted, so leaving records in place
means the next panic has nowhere to write.

Already-harvested `/var/crash` dumps are recognised by the `kdump-` prefixed
directories of earlier harvests, so a re-run copies only what is new.

The last line of output is the harvest directory path, which callers consume.

| Condition | Result |
|---|---|
| No new crash logs found, every source readable | Exit 0 |
| The harvest is empty | The directory it created is removed |
| A source could not be read | Non-zero exit. This is no evidence that no crash occurred |
| Some sources readable, some not | Succeeds and names what is missing |

Root is mandatory. A non-root harvest reads none of the sources and reports an
empty result.

## prune

Deletes the oldest `artifacts/crashes/pstore-*` directories beyond the newest
`--keep`, ordered by modification time.

```
sudo python3 tools/crashlog_ctl.py prune --keep 10
```

```
removed artifacts/crashes/pstore-20260814-221004
pruned 1 of 12 harvest dir(s), freeing 2.1 GB
disk: harvested 1.8 GB, /var/crash 3.4 GB, 392.4 GB free
```

Never automatic: harvested logs are evidence. `--keep 0` removes all of them.

## Disk reporting

`harvest` and `prune` both report what the crash logs cost and warn below
`loop.min_free_disk_gb`:

```
disk: harvested 2.1 GB, /var/crash 3.4 GB, 14.2 GB free
WARN: 14.2 GB free, under loop.min_free_disk_gb (20 GB). ...
      prune old harvests with: sudo python3 tools/crashlog_ctl.py prune --keep 10
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. For `verify`, every check passed |
| 1 | A `verify` check failed, or a harvest source could not be read |

## Files

| Path | Contents |
|---|---|
| `artifacts/crashes/pstore-<timestamp>/` | One harvest |
| `/sys/fs/pstore` | The bare-metal panic records, cleared after copying |
| `/var/crash` | The kdump output |
| `/etc/default/grub.bak-gspwn` | The pre-`setup` backup of the GRUB defaults |

## See also

- [Disk and crash logs](/gspwn/guides/disk-and-crash-logs/)
- [Artifacts](/gspwn/reference/artifacts/)
