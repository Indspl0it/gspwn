---
title: Glossary
description: Every project-specific term, defined once, alphabetically.
---

| Term | Definition |
|---|---|
| adjacent | A field of the research record. Calls that share an object, lock, refcount or teardown path with the fault and were not exercised by its reproducer. It carries information the crash report does not, and the feedback edge moves it into the next round |
| AFL++ | The fuzzer used for Track U harnesses that report edge counts through `fuzzer_stats`. Runs inside `track_u.docker_image` |
| brief | `pipeline_ctl.py brief`. The derived handoff for a fresh or compacted agent session: position, blocked phases, the crash registry, the findings, the impact records and the tail of `knowledge/`. Computed at read time, so it cannot be stale |
| campaign | One fuzzing run under systemd, bounded by a deadline written to disk. Runs for `loop.campaign_hours` and survives the panics the pipeline expects |
| circuit breaker | The two limits that stop the orchestrator supervisor relaunching an agent: same-boot starts and reboots, counted separately within `orchestrator.window_min` |
| corpus | The set of programs syzkaller has evolved for one run, stored in `artifacts/runs/<run-id>/workdir/corpus.db`. Discarded with the run. Compare seed bank |
| CWE | Common Weakness Enumeration. Derived from the research record's `bug_class`, because the mapping is mechanical and a free-text field invites a plausible wrong number |
| degradation ladder | The three instrumentation rungs `build_kernel.sh` walks, stopping at the first that passes its gate: full KASAN and KCOV on the modules, KCOV only, then uninstrumented modules |
| discovery exponent | Beta in the fitted curve `S(n) = K * n^beta`, where `S` is distinct edges and `n` is executions. Near 1 the run finds edges about as fast as it executes them; near 0 it has saturated |
| flagged | A crash status. A collision in exactly one of the two dedup keys, which may be a second bug or the same bug reported twice. Distinguishing them requires reading both reports, so the entry persists as a durable review queue |
| frameless signature | The fallback identity for a report with no usable stack: a hash of the normalised wording around its start line, with the faulting function from the `RIP:` line appended |
| gate | The evidence a phase must produce before it is marked `done`. Checked against files on disk, never accepted on a sub-agent's assertion |
| GSP | The GPU System Processor, a microcontroller on Turing and later cards. A large part of the Resource Manager runs there, where KCOV cannot instrument it, so coverage numbers exclude that region |
| gspwn | The pipeline in this repository. Always lowercase |
| Heaps' law | The species-accumulation model `S(n) = K * n^beta`, fitted by least squares on log `S` against log `n`. An exponential saturation curve assumes a finite asymptote, which this data does not support |
| impact record | The structured output of `rca` that says what the fault hands an attacker: the primitive, the field the corruption lands on, whether a freed allocation can be reclaimed with attacker data, and what the attacker influences. Attached with `pipeline_ctl.py impact-set` |
| KASAN | The Kernel Address Sanitizer. Detects use-after-free and out-of-bounds accesses and prints the allocation, free and access sites, which the impact record transcribes |
| KCOV | The kernel's coverage collection facility. What syzkaller's inner loop measures against |
| knowledge | `knowledge/learnings.md` and `knowledge/mistakes.md`. Committed to a public repository, carrying ABI and process facts and never findings. The only state a rebuilt machine starts with |
| learning | A knowledge entry about the target: an ABI fact, a driver behaviour, a tooling quirk. Compare mistake |
| libFuzzer | The in-process fuzzer used for Track U C harnesses. Writes no `fuzzer_stats`, so those harnesses contribute a corpus count and no edge curve |
| mistake | A knowledge entry about the process: something that cost a round, produced a wrong number, or would repeat. Compare learning |
| noise | An Xid class. Xids the fuzzer produces by design, such as illegal instruction and illegal address. Kept in the registry as an audit trail and excluded from every derived crash count |
| phase | One of twelve units of work. A sub-agent executes a phase; a gate guards it |
| plateau | A coverage verdict. Another campaign is not expected to find at least `coverage.plateau_new_edges` new edges |
| primitive | The impact record's central field: what the memory-safety violation hands an attacker. `none` is the correct value for a fault that only kills the machine, which covers most kernel faults |
| profile check | The `poc` phase's experiment: re-running a Track K reproducer inside a container matching the threat model, as a non-root user with the default capability set. Its three outcomes are `tenant-reachable`, `not-tenant-reachable` and `profile-check-blocked` |
| pstore | The kernel's persistent store, backed by ramoops on bare metal. A small fixed-size backend that frees a record only when the file is deleted, which is why `harvest` clears it after copying. Absent on EC2 |
| registry | The `crashes` map in `state/pipeline.json` |
| research record | The structured output of `rca` that says where to look next: the subsystem, the bug class, the trigger, the ioctls called, the preconditions needed, and the adjacent calls. Attached with `pipeline_ctl.py finding-set` |
| RM | The Resource Manager, the NVIDIA driver's object model. Its escape ioctls allocate, control and free objects in a client-rooted hierarchy |
| round | One pass through the nine round phases, from `describe` to `refine` |
| run id | The identifier for one campaign, of the form `r<round>-<n>`. One id covers both tracks |
| seed bank | `artifacts/seeds/`. Outlives rounds and campaigns, deduplicated by content hash. What later rounds start from. Compare corpus |
| smoke window | `track_k.smoke_window_minutes`. The early-abort check at the start of a campaign, during which coverage must increase. The `fuzz` phase's gate is separate |
| spend ledger | `state/spend.json`, mapping run id to billed hours. Machine-global, and not redirected by `GSPWN_STATE` |
| sub-agent | One of the twelve definitions in `agents/`, referred to by name. Executes one phase |
| syz-db | The syzkaller tool that packs and unpacks a corpus database. What `corpus_ctl.py` and the seed packing in `campaign_ctl.py` call |
| syz-manager | The syzkaller fuzzing manager. What `gspwn-k.service` runs |
| syz-prog2c | The syzkaller tool that turns a `.syz` program into a standalone C reproducer. What `repro_ctl.py extract` calls when only `repro.syz` exists |
| syzkaller | The coverage-guided kernel fuzzer that drives Track K. Its inner loop mutates, measures edges through KCOV, and keeps corpus-advancing inputs |
| syzlang | syzkaller's interface description language. What the `describe` phase authors for the driver's ioctl surface |
| Track K | The NVIDIA GPU kernel driver, `open-gpu-kernel-modules` |
| Track U | The NVIDIA Container Toolkit: `libnvidia-container` and `nvidia-container-toolkit` |
| UBSAN | The Undefined Behavior Sanitizer. Enabled in the instrumented kernel, and run with `halt_on_error=1` in Track U harnesses so the crashing input still matches the report |
| UVM | Unified Virtual Memory. A driver subsystem with its own device nodes and its own ioctl numbering scheme, which does not follow the RM escape convention |
| void run | A reproduction attempt that produced no usable verdict. Excluded from both the numerator and the denominator of the rate, and re-run |
| worklist | `artifacts/eval/<run-id>/worklist.md`. The ordered, tagged work items the next round's `describe` and `seeds` phases execute |
| Xid | NVIDIA's error identifier, printed as an `NVRM:` line in the kernel log. Classified as `signal`, `review`, `health` or `noise` at registration |
