---
title: repro_ctl.py
description: Reproducer extraction, the verdict rules, and panic-durable verification.
---

Extracts the reproducer for a registered crash, replays it a requested number
of times, and records how often it reproduced. A disclosure package is built on
the recorded rate and the classification derived from it.

## Commands

| Command | Effect |
|---|---|
| `extract <crash-id>` | Track K: copies the syzkaller crash directory into `artifacts/pocs/<crash-id>/` and puts a `repro.c` there. Track U: copies the registry crash input to `artifacts/pocs/<crash-id>/input`. |
| `verify <crash-id>` | Replays the reproducer until the requested number of counted runs land, then writes `repro_rate`, `repro_runs_counted`, `repro_runs_requested`, `repro_progress` and a classification onto the crash registry entry. |

The registry entry decides which track a crash belongs to. `--track` only
cross-checks that value and exits when the two disagree.

| Option | Command | Effect |
|---|---|---|
| `--force` | `extract` | Track U: overwrites an existing `input` whose content differs. On Track K it prints a warning and changes nothing, because Track K extraction refreshes every artefact it copies. |
| `--runs N` | `verify` | Counted runs to reach. Defaults to `poc.default_runs`. |
| `--restart` | `verify` | Discards partial progress and starts from run 1. |
| `--allow-live-campaign` | `verify` | Track K: proceeds while `gspwn-k` is fuzzing. The recorded rate is then an overestimate. |
| `--cmd '<template>'` | `verify` | Track U: the replay command. `{input}` is replaced by the shell-quoted path of the crash input. |
| `--crash-exit N` | `verify` | Track U: this harness exit code also scores a hit. |

`verify` exits 0 when at least `--runs` runs were counted, 1 when a
precondition failed or no run could be counted so no rate was recorded, and 2
when a rate was recorded on fewer counted runs than `--runs` requested because
the attempt cap fired.

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
| The reproduction class does not retire the analysis stamp | The status goes through `pipeline_state.set_crash_status`, which appends to the history trail and keeps `rca_done_at` |

## Refusal conditions

`verify` refuses before it scores anything when the evidence would be
unreliable.

| Condition | Rationale |
|---|---|
| The kernel ring buffer is unreadable or empty | An empty before-and-after pair reads as a clean run, so every run would score clean and a real bug would report a 0% rate |
| No signature can be derived for the crash | Nothing would distinguish this crash reproducing from any other crash in the window |
| Another verify session holds `state/repro.lock` | The two share one ring buffer and would corrupt each other's delta windows |
| A Track K crash is verified while `gspwn-k` is active or activating | A run counts as a reproduction partly because the machine panicked during it, and that inference holds only when the reproducer is the one thing capable of panicking the machine |
| `repro.c` is absent or zero bytes, or `gcc` fails on it | There is nothing to run |
| Track U: `artifacts/pocs/<crash-id>/input` is absent | There is nothing to replay |
| Track U: `--cmd` is absent or carries no `{input}` placeholder | The crash input would never reach the harness |
| `--cmd` or `--crash-exit` is passed for a Track K crash | Those options describe a userspace replay |

## Crash signature

A signature is two lists, derived at the start of `verify` from the registry
title and the report text registered for the crash.

| List | Derivation |
|---|---|
| `phrases` | The title with the `kernel ` or `NVRM ` prefix stripped, split on volatile fields (hex addresses, `pid=N`, bare numbers of six digits or more, printk timestamps), keeping the parts of at least 12 characters |
| `funcs` | The top stack frames of the registered report, with the sanitizer's own machinery frames dropped first, capped at `triage.signature_frames`. Where the report carries no crash-specific frame at all, title tokens of at least four characters containing `_` or `.` stand in |

A window matches when it contains every member of `funcs`. Frames 2 to 5 of
a sanitizer report are the sanitizer's own machinery, so a rule satisfied by any
one frame scored an unrelated KASAN report as a reproduction of this crash on
`dump_stack_lvl` alone. `UBIQUITOUS_FRAME_RE` drops those frames by subsystem
prefix before the `triage.signature_frames` cap is applied, so the cap spends
its slots on frames that name this crash, and the predicate then requires all of
them together.

`phrases` is consulted only for a crash whose report carries no frames at all,
where the title wording is the only evidence there is, and it matches on the
same all-members rule. A crash with frames never falls back to it: a phrase from
the title is weaker evidence than the stack that produced it, and admitting it
as an alternative would restore the single-element match. Generic
kernel-crash markers (`KASAN:`, `BUG:`, `Kernel panic`,
`general protection fault`, `Oops`) never score a hit on their own, because the
fuzzer panics this machine by design and any-crash matching would inflate the
rate that gates disclosure. Those markers are used only to describe what a
harvested log shows in a void-run explanation.

## Run verdicts

Each run scores as a hit, a void or a clean run. The rate is hits divided by
counted runs, and a void run enters neither figure.

| Verdict | Condition | Evidence class |
|---|---|---|
| hit | The dmesg delta for the run contains the crash signature | `dmesg-signature` |
| hit | The run timed out and the crash title carries a hang-class marker | `timeout-hang-class` |
| hit | Track U: the harness output matched a sanitizer signature | `sanitizer-signature` |
| hit | Track U: the harness exit code equalled `--crash-exit` | `exit-condition` |
| void | The reproducer could not be executed | |
| void | `dmesg` returned no output before or after the run | |
| void | The ring buffer wrapped past the anchor, so no delta is computable | |
| void | The run timed out and the crash title carries no hang-class marker | |
| void | Track U: the harness exited 126 or 127, so the command was not runnable | |
| clean | The run completed and the delta held no signature | |

The hang-class markers are `hung task`, `task hung`, `watchdog`,
`soft lockup`, `softlockup`, `rcu_sched`, `rcu_preempt` and `deadlock`. The
sanitizer signatures are `ERROR: AddressSanitizer`,
`SUMMARY: AddressSanitizer`, `runtime error:`, `SEGV` and `ABORTING`.

Void runs are re-run. The attempt cap is the runs already done, plus
`poc.void_retry_factor` per still-needed counted run, plus a fixed slack of
five. Reaching it stops the loop, and a rate recorded over fewer runs than were
requested is reported as a protocol shortfall and exits 2.

## Panic recovery

A run in flight when the verify process died is resolved on the next
invocation, from the boot id and the logs harvested since.

| Boot id | Harvested logs | Verdict |
|---|---|---|
| Unchanged | any | void, because the verification process died locally and the kernel stayed up |
| Changed | contain this crash's signature | hit, evidence class `harvested-log-signature` |
| Changed | show a different crash | void, with the recognised marker line recorded as the reason |
| Changed | none recoverable, Track U | void, because a userspace replay cannot take the kernel down |
| Changed | none recoverable, Track K | hit, evidence class `boot-id-change-only`, counted separately as a weak hit |

## Rate and classification

| Classification | Condition |
|---|---|
| `reliable` | The rate is at or above `poc.reliable_threshold` |
| `flaky` | At least one hit, below the threshold |
| `unreproducible` | No hits over at least one counted run |

The summary line reports the hits, the counted runs, the rate and the
classification, and appends the void run count, a timeout breakdown into
hang-class hits and voids, and the count of hits resting on
`boot-id-change-only` evidence.

## Progress record

`repro_progress` on the registry entry carries nine keys: `runs_done`, `hits`,
`inconclusive`, `in_flight`, `boot_id`, `timeouts`, `timeout_hits`,
`weak_hits` and `evidence`.

## Concurrency and durability

| Property | Mechanism |
|---|---|
| Mutual exclusion | `flock(LOCK_EX \| LOCK_NB)` on `state/repro.lock`, held for the whole verify session |
| Lock scope | The lock path is `<repo>/state/repro.lock`, which `GSPWN_STATE` does not redirect, because the lock protects the machine's single dmesg ring and two runs with separate registries must still exclude each other |
| Progress durability | The progress record is persisted before and after every run |
| Panic recovery | An in-flight run is resolved on the next invocation from the boot id and the harvested logs |
| Write atomicity | The reproducer copy and `repro.c` generation both write a temporary file, `fsync`, then rename |
| Registry writes | Through `pipeline_state.transaction` and `set_crash_status` |

## Configuration

| Key | Default | Governs |
|---|---|---|
| `poc.repro_timeout_sec` | 120 | Seconds one run may take before it counts as a hang |
| `poc.reliable_threshold` | 0.8 | The rate at or above which the classification is `reliable` |
| `poc.default_runs` | 10 | Counted runs `verify` aims for without `--runs` |
| `poc.void_retry_factor` | 2 | Attempts allowed per still-needed counted run |
| `triage.signature_frames` | 5 | Crash-specific stack frames taken from the registered report into `funcs`, all of which a run must reproduce |

`config/campaign.yaml` carries the four `poc` keys, because a reliable label is
a research decision. When the config cannot be read at all, the shipped
defaults apply, so verification still runs on a machine whose config is
mid-edit.

## Extraction details

Track K extraction normalises what it stores. It copies the reproducer program
to `repro.prog`, whichever of `repro.prog` and `repro.syz` the source directory
named it, and copies the lowest-numbered `report` and `log` files to the bare
names `report` and `log`, which is where the signature builder reads them.

`repro.c` is taken from `repro.cprog` when syzkaller wrote a non-empty one,
because syz-manager already reproduced the crash with that translation on the
machine that faulted. Otherwise `syz-prog2c` generates it from `repro.prog`.
Generation writes a temporary file and renames it into place only on a
non-empty result, and an existing zero-byte `repro.c` is treated as missing and
regenerated.

A crash registered by `scan_dmesg` carries a kernel log file as its `dir`, and
syz-manager never saw that crash, so no syzkaller crash directory exists for it.
Extraction stops there and states that a reproducer must be written by hand into
`artifacts/pocs/<crash-id>/repro.c`.

## Design notes

`_report_texts` reads the extracted PoC copy first, then the syzkaller crash
directory, then the registry path itself, which is a file for dmesg-harvested
and Track U entries. Files over 8 MB are skipped.

`harvested_logs` reads the newest `artifacts/crashes/pstore-*` directory. It
skips `vmcore` files and any file over 32 MB, and it ignores a harvest older
than the current boot, which cannot describe the run that took the machine
down.

`dmesg_delta` anchors on the last 512 bytes of the pre-run buffer. Slicing by
length would silently return the wrong window under heavy KASAN output, and the
remaining buffer holds crash reports from earlier runs, so scanning it would
score a hit on every subsequent run.

`needs_rebuild` compares modification times, because `extract` regenerates
`repro.c` whenever `syz-prog2c` produces new output and a build-if-absent check
would verify the previous binary against the new source.

The Track U replay template is a command-line argument. The `poc` sub-agent
takes it from the harness entry in `harnesses/TARGETS.md` and blocks the crash
on the `harness` phase when it is missing.

## See also

- [Reproducing a crash](/gspwn/guides/reproducing-a-crash/)
- [Sub-agents](/gspwn/architecture/sub-agents/)
- [Configuration](/gspwn/reference/configuration/)
