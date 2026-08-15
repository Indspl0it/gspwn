---
title: Durability
description: The atomic write path, the four locks, the ownership repair after a root write, and how each persistent file behaves when it is found corrupt.
---

Track K fuzzing panics the machine as a normal part of its work. Every
persistent write is built to survive a power loss at any point during the
write, and every read-modify-write is built for a second process performing the
same operation concurrently.

## The write path

```
write to a temp file in the target directory
  -> flush
  -> fsync the file
  -> os.replace onto the target      (atomic)
  -> fsync the parent directory
```

| Step | Property it provides |
|---|---|
| Temp file in the **same** directory as the target | `os.replace` is atomic only within one filesystem |
| `flush` then `fsync` of the file | The new contents reach the disk before the rename |
| `os.replace` | A reader sees either the previous complete file or the new complete file, never a truncated one |
| `fsync` of the parent directory | The rename itself is durable. Without it the rename is lost even though the contents were flushed |
| Unlink of the temp file on any failure, before the exception propagates | A failed write leaves no temp file behind |

A panic before the rename leaves the previous good file untouched. A panic
after it leaves the new file complete.

## The backup

Before each state-file write, the previous good file is copied to
`state/pipeline.json.bak`. The corrupt-state error message names it:

```
state/pipeline.json is not valid JSON (Expecting value: line 1 column 1 (char 0)). Restore it from state/pipeline.json.bak or re-init.
```

## Files on the atomic path

| File | Written by | Mode |
|---|---|---|
| `state/pipeline.json` | Every tool, through `tools/pipeline_state.py` | Atomic replace |
| `state/spend.json` | The spend ledger functions | Atomic replace |
| `state/orchestrator.json` | `orchestrator_ctl.py`, the breaker | Atomic replace |
| `artifacts/seeds/promoted.json` | The promotion ledger | Atomic replace |
| `artifacts/runs/<id>/deadline` | `campaign_ctl.py` at install | Written and `fsync`ed |
| `knowledge/learnings.md`, `knowledge/mistakes.md` | `knowledge_ctl.py` | Atomic append under a per-file lock |
| `artifacts/pocs/<id>/input` | `repro_ctl.py extract` | Atomic copy |
| `artifacts/runs/<id>/coverage.csv` | `coverage_ctl.py sample` | Append, then `fsync` |

The coverage CSV is appended to. A sample is a new row, and rewriting the whole
file every `loop.coverage_sample_min` minutes is the more fragile operation.
`knowledge_ctl.py` holds a per-file lock for its append, because a panic
mid-append leaves a torn entry and two agents appending at once interleave
their lines.

## Transactions

```python
with ps.transaction() as st:
    st["crashes"][cid]["status"] = "reliable"
```

The transaction takes an exclusive `flock`, loads the state, yields it, and
saves on clean exit. An exception inside the block aborts the write and leaves
the file untouched.

A bare load-and-save pair is a defect. `AGENTS.md` allows parallel sub-agents
for `describe`, `seeds` and `harness`, plus a background `fuzz` monitor, and
all of them touch this file. Two loads followed by two saves lose one update.

`crash_parse.py` scans every source inside a single transaction, so a harvest
running while another phase writes cannot interleave with it.

## Locks

| Lock | Protects | Follows `GSPWN_STATE` | Blocking |
|---|---|---|---|
| `state/.pipeline.lock` | The state file | Yes. It sits beside the file it protects | Yes |
| `state/spend.json.lock` | The spend ledger | No | Yes |
| `state/repro.lock` | The one dmesg ring on the machine | No | No |
| `state/orchestrator.json.lock` | The breaker file | No | Yes |

The state lock and the ledger lock are separate, so billing a run is safe while
a state transaction is open. One lock covering both deadlocks the moment
`round-end` bills inside its own transaction.

The reproduction lock is non-blocking. Two concurrent verifiers share one dmesg
ring and corrupt each other's delta windows, so a second session exits
immediately. A queued verification would start against a ring already full of
the other session's crashes.

The breaker lock exists because `orchestrator_ctl.py status` and `reset` can
touch the file while the unit is starting.

## Root ownership repair

`campaign_ctl.py start` and `stop` run as root and write state. The state file
is created with `mkstemp`, mode 0600, owner root, and so is its lock file. Left
alone, every subsequent non-root agent command fails with a permission error.

| Condition | Action |
|---|---|
| A root write completed and `SUDO_USER` names a real user | The state file, its backup, the ledger and the lock files are chowned to that user |
| A non-root process tries to append to a root-owned `coverage.csv` | The condition is reported as a message and does not raise |

```
cannot write artifacts/runs/r2-1/coverage.csv — it is owned by the root sampler. Re-run this check with sudo, or read the curve with `series` instead.
```

## The deadline on disk

`artifacts/runs/<run-id>/deadline` holds one absolute epoch second, written and
`fsync`ed at install time.

| Condition | Resolution |
|---|---|
| The file is present | Read it and compare against the clock |
| The file is lost | Reconstruct it from the install event in the state file, which records the campaign start and the window it was given |
| Nothing on disk, nothing reconstructible, units still fuzzing | Stop the campaign |
| Nothing on disk, nothing reconstructible, no units fuzzing | Nothing to enforce, exit 0 |

The deadline is a file because a one-shot timer dies with the machine and this
machine reboots routinely. After a reboot the check reads the same deadline and
still stops on time. Without the reconstruction path, losing one small file
removes the spend ceiling with no visible symptom.

## Verification progress

`repro_ctl.py verify` writes `crash.repro_progress` before and after each run,
carrying an `in_flight` flag and the current boot id. A kernel reproducer often
takes the machine down mid-run, and the next invocation resolves the in-flight
run from the boot id and the harvested logs.

| Condition | Resolution |
|---|---|
| Same boot id | Void: the verification process died while the kernel stayed up |
| New boot id, harvested log carries this signature | Hit |
| New boot id, harvested log shows a different crash | Void |
| New boot id, no recoverable logs, Track K | Hit on weak evidence |
| New boot id, no recoverable logs, Track U | Void |

The Track K and Track U rows differ because a Track K reproducer is expected to
take the box down, and a Track U harness runs in a container that does not.

## Session recorded before the launch

The orchestrator resolves and stores the session id before launching the agent.
A panic terminates the agent with no exit code, so anything written after the
launch is never written on the restarts this mechanism exists for. The resume
count is incremented for the same reason: counting only clean exits leaves a
panic-heavy campaign never rotating its session.

## Corrupt-file behaviour

| File | Behaviour on a parse failure |
|---|---|
| `state/pipeline.json` | Raises, naming the backup. The orchestrator declines to launch an agent against it |
| `state/spend.json` | Raises, naming the backup |
| `state/orchestrator.json` | Raises. `orchestrator_ctl.py reset` is the one command allowed to start over, because resetting it silently clears a trip nobody has seen |
| `artifacts/seeds/promoted.json` | Rebuilt from the `.syz` files present, with a warning. Files on disk still count as known, so nothing is promoted twice |

## pstore clearing after harvest

pstore is a small fixed-size backend that frees a record only when the file is
deleted. `crashlog_ctl.py harvest` copies every record out and then unlinks it.

Records left in place leave the next panic with nowhere to write, which on a
machine that panics by design loses findings. Every later harvest also
re-copies the same records.

## Enforcement points

| Property | Enforced by |
|---|---|
| No reader sees a truncated file | Temp file, `fsync`, `os.replace`, directory `fsync` |
| Parallel sub-agents do not lose each other's updates | An exclusive `flock` across the whole transaction |
| Billing does not deadlock against a state transaction | Separate locks for the state file and the ledger |
| Two verifiers do not corrupt each other's dmesg window | A non-blocking lock on `state/repro.lock` |
| A campaign stays bounded after the deadline file is lost | Reconstruction from the install event, and a forced stop when neither is available |
| A non-root command still works after a root write | Ownership handed back to `$SUDO_USER` |

## See also

- [State file schema](/gspwn/reference/state-file/)
- [Loops](/gspwn/architecture/loops/)
- [Long-running campaigns](/gspwn/guides/long-running-campaigns/)
