---
title: repro_ctl.py
description: Reproducer extraction, the verdict rules, and panic-durable verification.
---

Extracts a reproducer and measures how often it works. The rate and the
classification it records are what a disclosure package is built on.

Verification scores each run as a hit, a void or a clean run, and writes the
resulting rate and status to the crash registry.

## Responsibility

The module owns the reproduction verdict for a crash and the progress record
that survives a panic mid-verification.

| Invariant | Enforced by |
|---|---|
| A run is scored against this crash, not against any crash | `crash_signature` derives phrases and frames from the registry title and the registered report |
| A run is never scored on an unreadable ring buffer | `probe_dmesg` fails before the first run |
| The delta window is the run's own output | `dmesg_delta` anchors on the tail of the pre-run buffer and reports a wrap |
| A void run affects neither numerator nor denominator | Void runs are excluded and re-run under the attempt cap |
| A verified binary matches its source | `needs_rebuild` compares the compiled reproducer against `repro.c` |
| A panic mid-verification loses no progress | Progress is persisted before and after every run and recovered from the boot id |
| Only one verifier touches the ring buffer | A non-blocking `flock` on `state/repro.lock` |

## Interface

| Subcommand | Purpose |
|---|---|
| `extract` | Copy or generate the reproducer for a crash |
| `verify` | Run the reproducer N times and record the rate and classification |

| Function | Returns | Raises |
|---|---|---|
| `cmd_extract(cid, force=False, track=None)` | `None` | Exits 1 on a failed or empty generation |
| `cmd_verify(cid, runs, restart, cmd=None, crash_exit=None, track=None, allow_live=False)` | `0`, `1` or `2` per the failure table | Exits 1 on the refusals below |
| `crash_entry(cid)` | The registry entry | Exits 1 on an unknown crash id |
| `crash_signature(c, cid)` | `{"phrases": [...], "funcs": [...]}` | |
| `matched_signature(delta, sig)` | The matched element, or `None` | |
| `dmesg_delta(before, after)` | `(new text, wrapped)` | |
| `probe_dmesg()` | `None` | Exits 1 when the ring buffer is unreadable or empty |
| `hang_class(title)` | The hang-class marker, or `None` | |
| `harvested_logs()` | Text of the newest harvested crash logs, or `None` | |
| `boot_id()` | The current boot identifier, or `None` | |
| `needs_rebuild(src, exe)` | `bool` | |

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing at run time. `selftest.py` exercises `needs_rebuild`, `crash_signature`, `matched_signature`, `dmesg_delta`, `hang_class`, `cmd_extract` and `cmd_verify` |
| This module imports | `pipeline_state.py`, `gspwn_config.py` |

## Failure modes

| Condition | Behaviour | Exit code |
|---|---|---|
| Every requested run counted and the rate recorded | Rate, classification and counted-run count written to the registry | 0 |
| Zero counted runs, all void | No rate recorded; the void count is printed | 1 |
| Fewer runs counted than requested, attempt cap reached | Rate recorded, and the short denominator is named as a protocol shortfall | 2 |
| Unknown crash id | Message naming the id | 1 |
| `--track` disagrees with the registry | Message naming both tracks | 1 |
| Track K verification attempted while `gspwn-k` is fuzzing | Refused unless `--allow-live-campaign`, which records the rate as an overestimate | 1 |
| `dmesg` unreadable, or returns no output | Refused before any run is scored | 1 |
| No signature derivable for the crash | Refused | 1 |
| Another verify session holds the lock | Refused; the lock is non-blocking | 1 |
| `syz-prog2c` fails or produces an empty `repro.c` | `repro.c` is not written | 1 |
| No usable `repro.c`, or `gcc` fails | Message naming the run directory | 1 |
| Track U `--cmd` missing, or without the `{input}` placeholder | Refused | 1 |
| `--cmd` or `--crash-exit` passed for a Track K crash | Refused | 1 |
| Ring buffer wrapped past the anchor | The run is void and re-run |
| Run times out | Hit when the crash title is hang-class, void otherwise, with the reason recorded |

## Concurrency and durability

| Property | Mechanism |
|---|---|
| Mutual exclusion | `flock(LOCK_EX \| LOCK_NB)` on `state/repro.lock`, held for the whole verify session |
| Lock scope | The lock lives in the machine's own state directory and does not follow `GSPWN_STATE`, because it protects the machine's single dmesg ring |
| Progress durability | The progress record is persisted before and after every run |
| Panic recovery | An in-flight run is resolved on the next invocation from the boot id and the harvested logs |
| Write atomicity | The reproducer copy and `repro.c` generation both write a temporary file, `fsync`, then rename |
| Registry writes | Through `pipeline_state.transaction` and `set_crash_status` |

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never score a run while the fuzzer is live | A run counts as a reproduction partly because the machine panicked during it, and that inference holds only when the reproducer is the only thing capable of panicking the machine |
| Never score against generic crash patterns | A `BUG:` or `Oops` line in the window does not identify which crash reproduced |
| Never score an unreadable dmesg | With `kernel.dmesg_restrict=1` a non-root `dmesg` yields empty output, an empty before-and-after pair reads as a clean run, and every run scores clean, producing a 0% rate for a real bug |
| Never slice the ring buffer by length | Under heavy KASAN output the old head is evicted, so a length slice returns the wrong window. A missing anchor means the ring wrapped and the run is void |
| Never count a void run | Void runs are excluded from both numerator and denominator, and the attempt cap bounds the re-runs |
| Never treat a death on the same boot as a reproduction | Only a reboot proves the kernel went down; a process that exited on the same boot was terminated by something else |
| Never treat a reboot alone as proof on Track U | A userspace replay cannot take the kernel down, so an unexplained reboot there is void |
| Never verify a stale binary | `extract` regenerates `repro.c` whenever `syz-prog2c` produces new output, and a build-if-absent check would verify the previous binary against the new source |
| Never leave an empty `repro.c` behind | Generation renames into place only on a non-empty result, and an existing zero-byte file is treated as missing |
| Never run two verifiers at once | They share one dmesg ring and would corrupt each other's delta windows |
| Never let the reproduction class retire the analysis stamp | The status goes through `set_crash_status`, which keeps the history trail and the `rca_done_at` stamp |

## Design notes

A hit on a boot-id change with no recoverable logs is recorded as a weaker
evidence class alongside the count, and the summary reports how many hits rest
on it.

A timeout never scores clean. It is a hit when the crash title is hang-class,
and void otherwise, with the reason recorded. Timeouts are counted separately
and broken down in the summary.

`_report_texts` reads the extracted PoC copy first, then the syzkaller crash
directory, then the registry path itself, which is a file for dmesg-harvested
and Track U entries. Files over 8 MB are skipped.

`harvested_logs` skips `vmcore` files, which are far too large to scan, and
ignores a harvest older than the current boot.

Track U's replay command comes from the harness's entry in `TARGETS.md`, and the
tool refuses a template with no `{input}` placeholder. The path is shell-quoted
before substitution.

## See also

- [Reproducing a crash](/gspwn/guides/reproducing-a-crash/)
- [repro_ctl.py reference](/gspwn/reference/cli/repro-ctl/)
