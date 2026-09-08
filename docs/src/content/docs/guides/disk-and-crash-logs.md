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

`setup`, `harvest` and `prune` exit immediately unless run as root.

## Environment detection

`setup`, `verify` and `harvest` take `--env ec2|baremetal|auto`, defaulting to
`auto`. Auto-detection queries the instance metadata service for
`instance-id`, preferring IMDSv2 and falling back to IMDSv1 only when the token
endpoint does not answer, with a two-second timeout so a non-EC2 host does not
stall. A metadata service that answers means `ec2`, and every other outcome
means `baremetal`. `prune` reads no environment.

## 1. Set up capture

```
sudo python3 tools/crashlog_ctl.py setup
```

`setup` installs `kdump-tools`, adds `pstore-tools` on bare metal, adds
`crashkernel=256M` to the GRUB command line when the file carries no
`crashkernel=` at all, backs up `/etc/default/grub` to
`/etc/default/grub.bak-gspwn` first, runs `update-grub`, mounts pstore on bare
metal, and enables `kdump-tools`.

```
added crashkernel=256M to GRUB_CMDLINE_LINUX_DEFAULT; reboot required
setup done. Next: reboot, then run: crashlog_ctl.py verify
```

On EC2 it names what it skipped:

```
NOTE (EC2): pstore skipped — hard-hang capture uses the EC2 console output instead. The instance needs an IAM instance profile allowing ec2:GetConsoleOutput.
```

When the file carries neither `GRUB_CMDLINE_LINUX_DEFAULT` nor
`GRUB_CMDLINE_LINUX`, `setup` exits 1 without editing anything and prints the
line to add by hand, followed by `update-grub` and a reboot.

Reboot before verifying. The `crashkernel` parameter takes effect at boot.

## 2. Verify the machinery

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

`verify` runs four checks, and two of them decide the exit status.

| Check | Environment | On failure |
|---|---|---|
| `/sys/fs/pstore` exists | bare metal | `FAIL`, exit 1 |
| `crashkernel=` reached `/proc/cmdline` | both | `FAIL`, exit 1 |
| `kdump-tools` is active | both | `WARN`, exit unchanged |
| the `aws` CLI is on `PATH` | EC2 | `FAIL`, exit 1 |

`READY` therefore prints while `kdump-tools` is inactive. Read the `WARN` line
as well as the exit status, because kdump is the primary capture path in both
environments.

## 3. Confirm with a deliberate panic

`READY` means the machinery is in place. Capture is confirmed by a captured
panic and by nothing else, so run the sysrq sequence `verify` prints and then
harvest. An empty harvest directory sends the operator back to step 1.

## 4. Harvest after a panic

```
sudo python3 tools/crashlog_ctl.py harvest
```

The last line is the harvest directory path, which callers consume:

```
disk: harvested 2.1 GB, /var/crash 3.4 GB, 388.1 GB free
artifacts/crashes/pstore-20260816-041205
```

The directory is named `pstore-<YYYYmmdd-HHMMSS>` in both environments. Two
sources are collected, one of them environment-specific:

| Source | Environment | Written into the harvest as |
|---|---|---|
| everything under `/sys/fs/pstore/*` | bare metal | the record's own file name |
| `aws ec2 get-console-output --latest` | EC2 | `console-output.log` |
| every `/var/crash/*` directory no earlier harvest copied | both | `kdump-<name>` |

pstore records are deleted after copying. pstore is a small fixed-size backend
that frees a record only when the file is deleted, so leaving records in place
means the next panic has nowhere to write, and on a machine that panics by
design that loses findings. It also means every later harvest re-copies the
same records.

Every unharvested `/var/crash` dump is taken, because several panics can occur
between two harvests and taking only the last one silently discards the earlier
crashes. `kdump-tools` may be writing at the same time, so each source is
copied independently and a failure on one leaves the rest to continue.

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

### Harvest exit codes

| Exit | Condition | Last line |
|---|---|---|
| 0 | Something was harvested and every source was read | the harvest directory path |
| 0 | Nothing was found and every source was readable | `no new crash logs found (checked pstore and /var/crash)` |
| 1 | Nothing was found and at least one source could not be read | the refusal below |
| 1 | The command was not run as root | the root refusal |
| 2 | Something was harvested and at least one source was unread or still being written | the harvest directory path |

The three outcomes are separated because the orchestrator runs `harvest`
unattended after every panic and a caller may read nothing but the exit code.
"Nothing to harvest" and "could not look" must not be the same answer:

```
harvest read nothing and left 2 source(s) unread: /sys/fs/pstore/dmesg-ramoops-0, /var/crash/202608160412. This is not evidence that no crash occurred — fix the cause and re-run before treating the panic as unrecorded.
```

A harvest that collected something and also left a source unread exits 2 and
names what is missing. The directory path is still the last line, so a caller
reading it gets the partial evidence:

```
WARN: 1 source(s) could not be read and are missing from this harvest: /var/crash/202608160412
```

A dump `kdump-tools` is still writing is deferred, not failed, and a later
`harvest` picks it up. It carries the same exit 2:

```
WARN: 1 dump(s) were still being written and are missing from this harvest: /var/crash/202608160412. Re-run harvest once they finish.
```

All three messages name at most five sources.

## 5. Parse the harvest into the registry

```
for f in <harvest>/dmesg-ramoops-*; do python3 tools/crash_parse.py --dmesg "$f"; done
for f in <harvest>/kdump-*/dmesg.* <harvest>/kdump-*/dump/dmesg.*; do
  [ -e "$f" ] && python3 tools/crash_parse.py --dmesg "$f"
done
[ -e <harvest>/console-output.log ] && python3 tools/crash_parse.py --dmesg <harvest>/console-output.log
```

Each invocation ends with the registry size:

```
registry now holds 7 crashes
```

Two things about these loops:

- The globs name the dmesg text and never `vmcore`. `crash_parse.py` reads text
  and matches report-start lines and `NVRM: Xid` lines against it, and the
  dmesg or console text beside a `vmcore` carries the same signature at a
  fraction of the size.
- `--dmesg` does not narrow the scan. Every invocation also scans the
  syzkaller workdir for the round's last registered run and
  `artifacts/u-crashes`, printing a `WARN` per absent source. Pass `--run-id`
  where the round has more than one run, or accept that each iteration
  re-reads the same workdir.

A crash whose report carries no usable stack frames is registered on a
signature over the report's opening wording, bounded by
`triage.frameless_signature_lines` and `triage.frameless_signature_chars`, with
the faulting symbol from the `RIP:` line appended after the cut so a long
prologue cannot push it out of the identity.
[Results and triage](/gspwn/guides/results-and-triage/) covers the registry
that results.

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

With nothing beyond the keep count, it removes nothing and says so:

```
nothing to prune: 8 harvest dir(s), keeping 10
```

Pruning is never automatic. Harvested logs are evidence, so no tool removes
them on its own. `prune` keeps the newest `--keep` directories by modification
time, defaulting to 10, matching `artifacts/crashes/pstore-*` in both
environments, and requires root because the harvest directories are written by
the root harvester. `--keep 0` removes every harvest directory, and a negative
value is refused.

`prune` never touches `/var/crash` itself. The `/var/crash` figure in the disk
line falls only when `kdump-tools` or an operator removes a dump there.

## The free-space floor

```yaml
loop:
  min_free_disk_gb: 20
```

Every coverage sample records free space in the `disk_free_mb` column, and the
tools warn below the floor:

```
WARN: 14.2 GB free, under loop.min_free_disk_gb (20 GB). A full disk stops the fuzzer, the sampler and every state write at once. Prune harvested crash dirs (crashlog_ctl.py prune) or grow the volume before it runs out.
```

`coverage_ctl.py series` reports the low-water mark across the run:

```
  disk free: 412.6 GB -> 388.1 GB (low water 388.1 GB)
```

`0` disables the check. The same measurement is one of the problems
`orchestrator_ctl.py preflight` reports.

## See also

- [Cloud runbook](/gspwn/guides/cloud-runbook/) covers the EC2 console path in
  context.
- [crashlog_ctl.py reference](/gspwn/architecture/components/crashlog-ctl/)
