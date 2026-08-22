---
title: Scope and oracle
description: The four oracles that convert an execution into a verdict, the conditions none of them detect, and the five stages that bound what a campaign can claim.
---

An oracle converts an execution into a verdict. A campaign detects a condition
only when one of the four oracles below fires on it, and reports that condition
only when every stage in the bounding chain carried it through.

Scope exclusions decided by the attacker definition live in
[Threat model](/gspwn/architecture/threat-model/). The limits below are those
imposed by the detection mechanism itself.

## Oracle inventory

| Oracle | Source | Signals | Track |
|---|---|---|---|
| KASAN | Kernel log | Use-after-free, out-of-bounds read, out-of-bounds write, with the allocation, free and access sites | K |
| Kernel self-reporting | Kernel log | `BUG:`, `Oops`, `Kernel panic`, general protection fault, hung task, watchdog stall, RCU stall | K |
| NVRM Xid lines | Kernel log | Driver-reported faults, classified by Xid number into `signal`, `review`, `health` and `noise` | K |
| Sanitizer output | Harness stderr | `ERROR: AddressSanitizer`, `SUMMARY: AddressSanitizer`, `runtime error:`, `SEGV`, `ABORTING` | U |

`crash_parse.py` reads all four. Xid classification runs before the PCI bus id
is stripped from the title, because the Xid number parser consumes the
parenthesised bus id as a group. See
[Crash identity](/gspwn/architecture/crash-identity/).

## Hang as a reproduction verdict

A `repro_ctl.py verify` run that exceeds `poc.repro_timeout_sec` counts as a
hit when the crash title is hang-class. `HANG_PATTERNS` in `tools/repro_ctl.py`
holds the match list:

| Pattern |
|---|
| `hung task` |
| `task hung` |
| `watchdog` |
| `soft lockup` |
| `softlockup` |
| `rcu_sched` |
| `rcu_preempt` |
| `deadlock` |

A timeout on any other title is void, and the run is retried against the
attempt cap.

## Undetected conditions

| Condition | Mechanism that fails |
|---|---|
| Any fault inside GSP firmware | Not instrumented. KCOV cannot see it, and a fault path entering GSP RPC cannot be followed from the kernel side |
| A logic bug with no memory-safety consequence | No oracle fires. The call returns a wrong answer and the kernel log stays clean |
| An information leak that never faults | KASAN reports a bad access. A correct read of data that should not have been returned produces no report |
| Symlink TOCTOU and mount-escape logic on Track U | Fuzzing finds these poorly. Recorded in the report as future work |
| Memory corruption in the Go toolkit | Go is memory-safe. A panic there supports a denial-of-service finding only |
| Anything behind an excluded device node | `nvidia-modeset` and `/dev/dri/*` are outside the attacker definition and are not modelled |
| Anything behind an ioctl with no syzlang description | syzkaller generates what the grammar describes |

The information-leak row is the widest gap on Track K. A driver returning
uninitialised kernel memory inside a valid response is a real vulnerability,
and no oracle in the inventory fires on it.

## The bounding chain

Five stages sit between an ioctl in the driver and a severity in the report.
Each stage bounds every stage after it.

```mermaid
flowchart TB
  B["build<br/>instrumentation rung 1 to 3"] --> D["describe<br/>syzlang for the ioctl surface"]
  D --> S["seeds<br/>object chains random generation<br/>will not construct"]
  S --> F["fuzz<br/>coverage measured, crashes captured"]
  F --> P["poc<br/>repro_ctl.py verify"]
  P --> R["rca<br/>impact record"]
  R --> OUT(["severity in the report"])

  B -.->|"rung reached bounds<br/>which faults are caught"| OUT
  D -.->|"unmodelled ioctls are<br/>never generated"| OUT
  S -.->|"unreached preconditions<br/>leave paths unexercised"| OUT
  P -.->|"no reproducer means<br/>unreproducible"| OUT
  R -.->|"unfollowable path means<br/>undetermined"| OUT
```

### Instrumentation rung

The `build` phase walks a degradation ladder and stops at the first rung whose
gate passes. The rung reached is recorded in `config/machine.yaml` and in
`artifacts/builds/manifest.json`, and the report cites it.

| Rung | Kernel | NVIDIA modules | Detection available |
|---|---|---|---|
| 1 | KASAN and KCOV | KASAN and KCOV | Memory-safety violations inside the modules are caught, and module coverage is measured |
| 2 | KASAN and KCOV | KCOV only | Module coverage is measured. A use-after-free inside a module is caught only when it faults |
| 3 | KASAN and KCOV | Uninstrumented | Only faults reaching instrumented kernel code are reported, and no module coverage is measured |

The ladder is L9 in [Loops](/gspwn/architecture/loops/).

### Coverage

Two statements are attached to every coverage number, and `coverage_ctl.py
series` and `coverage_ctl.py plateau` print both on every invocation.

| Statement | Consequence |
|---|---|
| Kernel-side reachable code only | GSP firmware is uninstrumented. On a GSP-based GPU a large part of the Resource Manager runs where KCOV cannot see it, and a plateau verdict describes none of it |
| No total-coverage claim | The aggregate edge counter supports a fitted discovery curve and an extrapolation from it. A fraction-of-driver-covered figure needs per-edge frequency counts that syz-manager does not report |

A second curve carries a denominator the edge curve cannot. `surface_cov.py`
counts the distinct targets of the 764 the run's corpus has a program for, so
its reading is a fraction and its ceiling is known. That answers whether the
round is still reaching new targets, and the edge curve answers whether it is
still reaching new code inside the targets it already has. See
[Coverage and plateau](/gspwn/architecture/coverage-and-plateau/).

### Descriptions

Fuzzing quality is decided in the `describe` phase. Every coverage number and
every crash is downstream of the syzlang grammar.

| Failure | Symptom | Detected by |
|---|---|---|
| No description exists for an ioctl | The call is never generated | The `refine` phase classifies the surface `unmodeled` |
| A description exists and is wrong | Calls are rejected before reaching real work. A smoke run shows one device node early-outing uniformly | The `describe` gate's audit of five sampled descriptions against source |
| Handles are not chained with syzkaller resources | Generated programs fail at the first handle check | The smoke run's dmesg shows no program reaching the driver |

### Seeds

Some paths need a real object or handle chain that random generation does not
construct. `refine` classifies those surfaces `unreachable-by-construction`,
and the remedy is a seed from `trace2seed.py`, from either of its two
subcommands. `convert` derives a program from a real workload trace.
`chains` builds the allocation prologue from `rm-chains.json` and reaches 514
of the 531 control commands, which no trace names, because `strace` decodes no
NVIDIA parameter struct.

A seed that does not establish a precondition leaves the path unexercised. The
`seeds` gate names every precondition it could not reach, so the next round
retains the target.

### Reproduction

| Bound | Recorded outcome |
|---|---|
| syz-manager produced no reproducer | The crash is `unreproducible`. Nothing hand-crafts one |
| The dmesg ring wraps under crash spam | Runs are void and re-run, up to `poc.void_retry_factor` attempts per still-needed counted run |
| The crash title yields no signature | Verification exits. Scoring against generic patterns is not attempted |
| A Track U harness has no replay command in `harnesses/TARGETS.md` | The crash cannot be scored, and `poc` blocks it on the `harness` phase |

### Impact analysis

The impact record stops at the primitive. Stating that a use-after-free yields
a controlled write into a reclaimable allocation is analysis. Building the
escalation is out of scope.

`undetermined` is a valid outcome and carries no penalty, provided
`undetermined_reason` names what blocked the analysis. A fault path entering
GSP firmware cannot be followed further from the kernel side. See
[Impact and severity](/gspwn/architecture/impact-and-severity/).

## Enforcement points

| Property | Enforced by |
|---|---|
| Every coverage artifact states the GSP blind spot | `coverage_ctl.py series` and `coverage_ctl.py plateau`, on every invocation |
| The instrumentation rung reaches the report | `config/machine.yaml` and `artifacts/builds/manifest.json`, cited by the `report` sub-agent |
| An unmodelled surface is named for the next round | The `refine` sub-agent, in `gaps.md` |
| An unreached precondition is named | The `seeds` gate |
| A conclusion exceeding its evidence is refused | `pipeline_ctl.py impact-set` and `pipeline_ctl.py validate` |

## See also

- [Execution model](/gspwn/architecture/execution-model/)
- [Coverage and plateau](/gspwn/architecture/coverage-and-plateau/)
- [Impact and severity](/gspwn/architecture/impact-and-severity/)
