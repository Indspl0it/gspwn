---
title: repro_ctl.py
description: Reproducer extraction and reproduction-rate verification, with the verdict rules.
---

Extracts a reproducer and measures how often it works.

## Synopsis

```
python3 tools/repro_ctl.py <extract|verify> <crash-id> [options]
```

The track is read from the registry entry. `--track` cross-checks it, and the
registry is authoritative. Track K `verify` requires root to read the kernel
ring buffer under `kernel.dmesg_restrict`.

## extract

Copies a crash's reproducer into `artifacts/pocs/<crash-id>/`.

```
python3 tools/repro_ctl.py extract crash-0001 [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--force` | None | Off | Track U: overwrite an existing input file whose content differs |
| `--track` | `K`, `U` | From the registry | Cross-check against the registry |

Track K copies the syzkaller crash directory and normalises the names it
stores.

| Source in the crash directory | Stored as |
|---|---|
| `repro.prog`, or `repro.syz` in a hand-assembled directory | `repro.prog` |
| `repro.cprog`, `repro.report`, `repro.log`, `repro.stats`, `repro.c`, `description` | Their own names |
| The lowest-numbered `report<N>`, or a bare `report` | `report` |
| The lowest-numbered `log<N>`, or a bare `log` | `log` |

`repro.c` is copied from a non-empty `repro.cprog` when there is one, and
otherwise generated from `repro.prog` with `syz-prog2c`. Generation writes to a
temporary file and renames into place only on a non-empty result, so a failed
`syz-prog2c` leaves no stub behind. A zero-byte `repro.c` from an older failure
is detected and regenerated. A crash directory holding neither a reproducer
program nor a non-empty `repro.cprog` produces a warning naming the directory.

Track U copies the registry crash input to `artifacts/pocs/<crash-id>/input`
with a temporary file, `fsync` and rename.

| Condition | Result |
|---|---|
| Track U, an existing file is identical | Left alone |
| Track U, an existing file differs | Refused without `--force` |
| Track U, no existing file | Copied |
| Track U, the registry path is not a file | Exits naming the path |
| Track K, `--force` passed | Warned and ignored |
| Track K, the registry path is not a directory | Exits naming the kernel log |

`--force` is a Track U flag. Track K extraction has nothing to clobber: it
regenerates `repro.c` whenever `syz-prog2c` has something better to say and
copies everything else unconditionally, so accepting the flag silently would
read as an authorised overwrite. The warning names the crash and says the flag
changed nothing.

`crash_parse.py` registers a crash harvested out of a kernel log as track K
with the path of the log it was read out of as its `dir`. That path names a
file. syz-manager never saw that crash, so there is no crash
directory to copy and no reproducer to find. `extract` exits naming the log.
The generic "syz-manager found no reproducer" message would blame the manager
for a crash it was never shown. A log-harvested crash reaches a PoC only by
writing one by hand into `artifacts/pocs/<crash-id>/repro.c` and then running
`verify`.

A Track U input reaches `artifacts/pocs/<crash-id>/input` because that is the
file `verify --track u --cmd` replays. The registry records the input path and
not its `.sanlog` replay report, so `verify` is never handed a text log to
replay.

## verify

Runs the reproducer repeatedly and records the reproduction rate.

```
python3 tools/repro_ctl.py verify crash-0001 [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--runs` | `N` | `poc.default_runs` | Counted runs to reach |
| `--restart` | None | Off | Discard partial progress and start from run 1 |
| `--allow-live-campaign` | None | Off | Track K: verify while `gspwn-k` is fuzzing, accepting an overestimated rate |
| `--cmd` | `TEMPLATE` | None | Track U: the command run once per run, with `{input}` replaced by the shell-quoted crash input path |
| `--crash-exit` | `N` | None | Track U: this harness exit code also counts as a reproduction |
| `--track` | `K`, `U` | From the registry | Cross-check against the registry |

`--cmd` and `--crash-exit` are refused against a Track K crash.

## Preconditions

Track K refuses while `gspwn-k` is active, compiles `repro.c` with
`gcc -pthread -static`, rebuilds when the source is newer than the binary,
derives the crash signature, and probes `dmesg` before any run is scored.

Track U requires the input file to exist and `--cmd` to contain `{input}`.

| Condition | Result |
|---|---|
| The ring buffer is unreadable | Refused |
| The title yields no usable phrases and the report registers no frames | Refused. Scoring it would fall back on generic patterns any crash would trip |

```
dmesg returned no output — refusing to verify: with an unreadable ring buffer every run would score 'clean' and the crash would be misclassified unreproducible. Re-run via sudo, or allow non-root reads with 'sudo sysctl -w kernel.dmesg_restrict=0'.
```

## The crash signature

Derived at verification start, and required in the evidence for a run to count
as a reproduction of this crash.

| Part | Derivation |
|---|---|
| `funcs` | Top `triage.signature_frames` stack frames from the registered report, plus identifier-like title tokens containing `_` or `.` |
| `phrases` | The registry title split on volatile fields, keeping runs of at least twelve characters |

Volatile fields are hex addresses, `pid=` values, bare numbers of six digits or
more, and printk timestamps.

Generic kernel-crash markers are not consulted. Any `BUG:` or `Oops` in the
window is no evidence that this crash reproduced.

## Verdicts

| Verdict | Track K | Track U |
|---|---|---|
| `hit` | The signature appears in the dmesg delta | A sanitizer signature in the harness output |
| `hit` | A timeout with a hang-class title | A timeout with a hang-class title |
| `hit` | | The `--crash-exit` code |
| `hit` on recovery | A boot-id change plus a harvested log carrying this signature | Never |
| `hit` on recovery | A boot-id change with no recoverable logs, recorded as weak evidence | Never |
| `void` | The ring wrapped, dmesg was empty, the reproducer would not run, a timeout with no hang-class title, or the process died on the same boot | A harness infrastructure failure, exit 126 or 127, a timeout with no hang-class title, or an unexplained reboot |
| `clean` | Neither | Neither |

Hang-class titles contain `hung task`, `task hung`, `watchdog`, `soft lockup`,
`softlockup`, `rcu_sched`, `rcu_preempt` or `deadlock`.

Track U sanitizer signatures are `ERROR: AddressSanitizer`,
`SUMMARY: AddressSanitizer`, `runtime error:`, `SEGV` and `ABORTING`.

## The dmesg delta

The window is anchored on the tail of the pre-run buffer. dmesg is a ring
buffer, and under KASAN spam the old head is evicted, so a slice taken by
length can return the wrong window and miss the reproduction.

When the anchor is gone the ring wrapped, no delta can be computed, and the run
is void. The remaining buffer holds crash reports from earlier runs, so
scanning it would score a hit on every subsequent run and report a rate of 1.0
for an unreproducible crash.

## The rate

```
rate = hits / counted runs
```

Void runs are excluded from both sides and re-run. `repro_runs_counted` and
`repro_runs_requested` are recorded next to the rate, so a short denominator
stays visible.

| Rate | Status |
|---|---|
| At or above `poc.reliable_threshold` | `reliable` |
| Above 0, below the threshold | `flaky` |
| 0 | `unreproducible` |

Every classification is appended to the crash's history trail, leaving the
previous status readable, and the `rca_done_at` stamp survives it.

## Panic durability

Progress is persisted before and after every run. A run left in flight when the
process died is resolved on the next invocation:

| Condition | Resolution |
|---|---|
| Same boot id | Void. The verification process died, and the kernel stayed up |
| New boot id, harvested log carries this signature | Hit |
| New boot id, harvested log shows a different crash | Void |
| New boot id, no recoverable logs, Track K | Hit, recorded as weak evidence |
| New boot id, no recoverable logs, Track U | Void. A userspace replay cannot panic the kernel |

Harvested logs older than the current boot are treated as absent, because they
cannot describe the run that panicked the machine. `vmcore` files are skipped.

## Mutual exclusion

`verify` holds an exclusive, non-blocking lock on `state/repro.lock` for the
whole session. A second session exits immediately, because a queued
verification would start against a ring full of the other session's crashes.

The lock does not follow `GSPWN_STATE`. It protects the single dmesg ring on
the machine.

## Exit codes

`verify` only. `extract` returns 0 on success and 1 on a problem.

| Code | Meaning |
|---|---|
| 0 | The protocol was satisfied: at least `--runs` counted runs |
| 1 | A precondition failed, or no counted runs landed so no rate was recorded |
| 2 | A rate was recorded on fewer counted runs than requested, because the attempt cap fired |

## Files

| Path | Contents |
|---|---|
| `artifacts/pocs/<crash-id>/` | The extracted reproducer and its generated `repro.c` |
| `artifacts/pocs/<crash-id>/input` | Track U: the crash input |
| `state/repro.lock` | The exclusive session lock |

## See also

- [Reproducing a crash](/gspwn/guides/reproducing-a-crash/)
- [State file schema](/gspwn/reference/state-file/)
