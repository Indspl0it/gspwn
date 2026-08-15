---
title: Disk and crash logs
description: Persistent crash capture on bare metal and EC2, harvesting after a panic, and reclaiming space.
---

Findings arrive as kernel panics. Capturing them is a prerequisite for triage,
and the capture path differs between bare metal and EC2.

| Environment | Primary | Hard-hang fallback |
|---|---|---|
| Bare metal | kdump to `/var/crash` | ramoops/pstore |
| EC2 | kdump to `/var/crash` | `aws ec2 get-console-output` |

EC2 has no pstore. A hard hang that never reaches kdump leaves nothing on disk,
and the serial console is the only remaining record.

## Environment detection

Every subcommand takes `--env ec2|baremetal|auto`, defaulting to `auto`.
Auto-detection queries the instance metadata service, preferring IMDSv2 and
falling back to IMDSv1 only when the token endpoint does not answer, with a
two-second timeout so a non-EC2 host does not stall.

## Setup

```
sudo python3 tools/crashlog_ctl.py setup
```

It installs `kdump-tools`, adds `pstore-tools` on bare metal, adds
`crashkernel=256M` to the GRUB command line if it is absent, backs up
`/etc/default/grub` first, runs `update-grub`, mounts pstore on bare metal, and
enables `kdump-tools`.

```
added crashkernel=256M to GRUB_CMDLINE_LINUX_DEFAULT; reboot required
setup done. Next: reboot, then run: crashlog_ctl.py verify
```

When neither `GRUB_CMDLINE_LINUX_DEFAULT` nor `GRUB_CMDLINE_LINUX` exists in
the file, it stops and prints the line to add by hand.

On EC2 it says what it skipped:

```
NOTE (EC2): pstore skipped — hard-hang capture uses the EC2 console output instead. The instance needs an IAM instance profile allowing ec2:GetConsoleOutput.
```

Reboot before verifying. The `crashkernel` parameter takes effect at boot.

## Verify

```
sudo python3 tools/crashlog_ctl.py verify
```

```
READY. Now validate capture with a deliberate panic:
  1. sync
  2. echo c > /proc/sysrq-trigger   # machine panics, reboots
  3. after boot: crashlog_ctl.py harvest
     (must produce a dmesg/ramoops dump containing the panic)
```

It checks that `/sys/fs/pstore` exists on bare metal, that `kdump-tools` is
active, that `crashkernel=` reached `/proc/cmdline`, and on EC2 that the `aws`
CLI is present. It exits 1 listing the failures.

The verification is not complete until a real panic has been captured. `READY`
means the machinery is in place; the sysrq test proves it works.

## Harvest

```
sudo python3 tools/crashlog_ctl.py harvest
```

The last line is the harvest directory path, which callers consume:

```
disk: harvested 2.1 GB, /var/crash 3.4 GB, 388.1 GB free
artifacts/crashes/pstore-20260816-041205
```

Collected sources:

| Source | Environment |
|---|---|
| Everything under `/sys/fs/pstore/*` | Bare metal |
| `aws ec2 get-console-output --latest` into `console-output.log` | EC2 |
| Every unharvested directory under `/var/crash/*`, copied as `kdump-<name>` | Both |

pstore records are **deleted after copying**. pstore is a small fixed-size
backend that frees a record only when the file is deleted, so leaving records
in place means the next panic has nowhere to write, and on a machine that panics
by design that loses findings. It also means every later harvest re-copies the
same records.

Every unharvested `/var/crash` dump is taken, including all dumps written since
the previous harvest. Several panics can land between two harvests, and taking
only the last one silently discards the earlier crashes. Files can vanish mid-harvest, since `kdump-tools`
may be writing at the same time, so each file is copied independently and a
failure on one does not abandon the rest.

:::danger[harvest must run as root]
`/sys/fs/pstore` and `/var/crash` are root-only. Run as anyone else the globs
come back empty and the copies raise permission errors, which previously
produced "no new crash logs found" and exit 0 while the evidence stayed on the
machine until pstore filled up and started dropping later panics. `harvest`
refuses instead.
:::

The orchestrator runs it through `sudo -n`, so the unit's user needs a
passwordless rule. See
[Unattended operation](/gspwn/guides/unattended-operation/).

## Exit codes

| Exit | Meaning |
|---|---|
| 0 | No new crash logs were found. Both sources were readable |
| non-zero | A source could not be read |

The distinction matters because the orchestrator runs `harvest` unattended
after every panic. "Nothing to harvest" and "could not look" must not be the
same answer:

```
harvest read nothing and failed on 2 source(s): /sys/fs/pstore/dmesg-ramoops-0, /var/crash/202608160412. This is not evidence that no crash occurred — fix the cause and re-run before treating the panic as unrecorded.
```

A partial harvest still succeeds, and says what is missing from it:

```
WARN: 1 source(s) could not be read and are missing from this harvest: /var/crash/202608160412
```

## Parsing the harvest

```
for f in <harvest>/dmesg-ramoops-*; do python3 tools/crash_parse.py --dmesg "$f"; done
for f in <harvest>/kdump-*/dmesg.* <harvest>/kdump-*/dump/dmesg.*; do
  [ -e "$f" ] && python3 tools/crash_parse.py --dmesg "$f"
done
[ -e <harvest>/console-output.log ] && python3 tools/crash_parse.py --dmesg <harvest>/console-output.log
```

`vmcore` files are too large to scan and are skipped; the dmesg or console text
alongside them carries the signature.

## Reclaiming space

kdump writes hundreds of megabytes per panic, and this pipeline panics by
design. `/var/crash` and the harvested copies are the fastest-growing
directories on the machine.

```
sudo python3 tools/crashlog_ctl.py prune --keep 10
```

```
removed artifacts/crashes/pstore-20260814-221004
removed artifacts/crashes/pstore-20260814-233117
pruned 2 of 12 harvest dir(s), freeing 4.3 GB
disk: harvested 1.8 GB, /var/crash 3.4 GB, 392.4 GB free
```

Pruning is never automatic. Harvested logs are evidence, so no tool removes
them on its own. `prune` makes reclaiming the space one command, and the
retained count is a stated decision. It keeps the newest `--keep`
directories by modification time, defaulting to 10, and requires root because
the harvest directories are written by the root harvester.

`--keep 0` removes every harvest directory.

## The free-space floor

Everything lands on one filesystem: kernel dumps, the corpus, the coverage CSVs
and the agent transcript. A full disk stops the fuzzer, the sampler and every
state write at the same moment.

```yaml
loop:
  min_free_disk_gb: 20
```

Every coverage sample records free space in the `disk_free_mb` column, and the
tools warn below the floor:

```
WARN: 14.2 GB free, under loop.min_free_disk_gb (20 GB). A full disk stops the fuzzer, the sampler and every state write at once. Prune harvested crash dirs (crashlog_ctl.py prune) or grow the volume before it runs out.
```

`series` reports the low-water mark across the run:

```
  disk free: 412.6 GB -> 388.1 GB (low water 388.1 GB)
```

`0` disables the check.

## See also

- [Cloud runbook](/gspwn/guides/cloud-runbook/) covers the EC2 console path in
  context.
- [Artifacts](/gspwn/reference/artifacts/) documents the harvest directory
  layout.
- [crashlog_ctl.py reference](/gspwn/reference/cli/crashlog-ctl/)
