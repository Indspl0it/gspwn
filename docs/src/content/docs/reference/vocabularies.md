---
title: Closed vocabularies
description: Every fixed value set the tools accept, with its members.
---

A closed vocabulary is a fixed set of enum values a field is allowed to hold. A
value outside its set is refused at write time, so `refine` can group across
rounds and the report can group across findings. Free text alone would make
`uaf`, `UAF` and `use-after-free` three different things.

## Index

| Vocabulary | Field it constrains |
|---|---|
| [Phases](#phases) | Keys of `phases` in `state/pipeline.json` |
| [Phase status](#phase-status) | Phase record `status` |
| [Crash status](#crash-status) | Crash record `status` |
| [Crash signal](#crash-signal) | Crash record `signal` |
| [Track](#track) | Crash record `track`, campaign event `track` |
| [Disclosure status](#disclosure-status) | Crash record `disclosure` |
| [Coverage verdict](#coverage-verdict) | Round record `coverage_verdict` |
| [Surface verdict](#surface-verdict) | Round record `surface_verdict` |
| [Surface accounting reason](#surface-accounting-reason) | Completion ledger row `reason` |
| [Round decision](#round-decision) | Round record `decision` |
| [Bug class](#bug-class) | Research record `bug_class` |
| [Trigger](#trigger) | Research record `trigger` |
| [Confidence](#confidence) | Research record and impact record `confidence` |
| [Primitive](#primitive) | Impact record `primitive` |
| [Consequence](#consequence) | Impact record `consequence` |
| [Access type](#access-type) | Impact record `access_type` |
| [Overwrite target](#overwrite-target) | Impact record `overwrite_target` |
| [Attacker control](#attacker-control) | Impact record `attacker_control` |
| [Reproduction evidence classes](#reproduction-evidence-classes) | `repro_progress.evidence` |
| [Configuration value sets](#configuration-value-sets) | `track_k.sandbox`, `loop.corpus_policy` |
| [Coverage sources](#coverage-sources) | The `source` column of every coverage sample |
| [GPU statuses](#gpu-statuses) | The `gpu` column of every coverage sample |

## Phases

`provision`, `build`, `describe`, `seeds`, `harness`, `fuzz`, `triage`, `rca`,
`poc`, `eval`, `refine`, `report`

| Group | Members | Lifetime |
|---|---|---|
| Setup | `provision`, `build` | Once per machine |
| Round | `describe`, `seeds`, `harness`, `fuzz`, `triage`, `rca`, `poc`, `eval`, `refine` | Once per round |
| Final | `report` | Once, after the loop stops |

`describe`, `seeds` and `harness` may run concurrently after `build`, and the
phase-ordering check exempts that trio from each other.

## Phase status

| Value | Meaning |
|---|---|
| `pending` | Not started |
| `in_progress` | Dispatched |
| `done` | The gate evidence was confirmed |
| `blocked` | The evidence could not be confirmed. A stopping point |
| `failed` | The phase errored |

## Crash status

| Value | Set by |
|---|---|
| `unique` | `crash_parse`, on no key collision |
| `duplicate` | `crash_parse` on a full match, or `crash-set --duplicate-of` |
| `flagged` | `crash_parse`, on a collision in one key only |
| `reliable` | `repro_ctl verify`, at or above `poc.reliable_threshold` |
| `flaky` | `repro_ctl verify`, above 0 and below the threshold |
| `unreproducible` | `repro_ctl verify`, at 0 |
| `rca_done` | The `rca` phase |
| `reported` | The `report` phase, once a disclosure package is assembled |

## Crash signal

How a crash reads against the campaign's own noise floor. Set from the Xid
classification for NVRM entries, and everything else stays `unclassified`.

| Value | Meaning |
|---|---|
| `signal` | Security-relevant or memory-integrity relevant. Triage it |
| `review` | Everything else, including every Xid not in the table |
| `health` | The GPU or the box is degraded. It blocks measurement and is excluded from the crash count |
| `noise` | The fuzzer caused it on purpose. Not a finding on its own |
| `unclassified` | Not an NVRM entry, so no verdict applies |

## Track

| Value | Target |
|---|---|
| `K` | The GPU kernel driver |
| `U` | The NVIDIA Container Toolkit |

## Disclosure status

`pending`, `submitted`, `resolved`, `not_applicable`

## Coverage verdict

| Value | Meaning | `plateau` exit |
|---|---|---|
| `growing` | The run is still finding edges | 0 |
| `unknown` | No verdict could be produced. Stops the loop | 1 |
| `plateaued` | Another campaign is not expected to find enough new edges | 3 |

## Surface verdict

The completion reading recorded on the round by `pipeline_ctl.py round-end`.

| Value | Meaning | `coverage_ctl.py completion` exit |
|---|---|---|
| `complete` | Every enumerated target is exercised or accounted for | 0 |
| `incomplete` | Targets remain that are neither | 3 |
| `unknown` | The exercised set could not be measured | 1 |

`complete` is the campaign's primary termination and it sits in the
non-overridable stop set. `unknown` never satisfies the completion stop, so a
failed corpus read cannot end a campaign by claiming it is done.

## Surface accounting reason

Why a target is closed out without being exercised. Written by
`pipeline_ctl.py surface-account` into the completion ledger. The first four
are spelled identically to the exclusion categories `surface_cov.py` already
reports, so the two group together.

| Value | Meaning | Evidence required | Closes the target |
|---|---|---|---|
| `control_gsp` | Handler compiled out. The parameter buffer crosses the RPC queue and runs on GSP, where KCOV cannot follow | Yes | Yes |
| `uvm_test` | Gated on `uvm_enable_builtin_tests=1`, which the target does not set | No | Yes |
| `escape_dead` | Declared with no dispatch case, so no kernel code runs | Yes | Yes |
| `escape_mux` | A multiplexer whose leaves are counted in another family | No | Yes |
| `needs-privilege` | The handler body checks a capability the modelled caller does not hold | Yes | Yes |
| `chain-unbuildable` | No allocation chain a default tenant can build reaches the object this call needs | Yes | Yes |
| `no-param-model` | The parameter struct cannot be modelled well enough for the call to reach its handler | Yes | Yes |
| `deliberately-deferred` | In scope and reachable, left for a later campaign by an explicit decision. Recorded, and does not close the target | No | No |

Evidence is a list of `file.c:line`. `detail` is required for every reason, and
"not reached yet" is refused, because an unreached target belongs in the
worklist.

Seven of the eight assert that the target cannot be reached by this campaign as
configured, and the completion identity `exercised + accounted-for = 764` means
"exercised, or excluded". `deliberately-deferred` asserts the opposite, so
`surface_completion` subtracts its rows before the union and reports them on
their own as `deferred`. A round's count of them is `surface_deferred` in the
state file.

Evidence is not required for it, and requiring it was rejected: evidence is a
`file:line`, a scope decision rests on no line of driver source, and demanding
one produces citations chosen to satisfy the check.

A row written in error is removed with
`python3 tools/pipeline_ctl.py surface-unaccount`, which reopens its target.

## Round decision

`continue`, `stop`

## Bug class

| Value | Derived CWE |
|---|---|
| `uaf` | CWE-416 |
| `double-free` | CWE-415 |
| `oob-read` | CWE-125 |
| `oob-write` | CWE-787 |
| `race` | CWE-362 |
| `refcount` | CWE-911 |
| `null-deref` | CWE-476 |
| `uninit` | CWE-908 |
| `deadlock` | CWE-833 |
| `leak` | CWE-401 |
| `type-confusion` | CWE-843 |
| `integer-overflow` | CWE-190 |
| `other` | None. The CWE is left empty |

The mapping is mechanical, so the CWE is derived from `bug_class`. A free-text
CWE field invites a plausible wrong number that nobody re-checks. Setting `cwe`
on the impact record overrides the derived value, for `other` and for cases
where a more specific child class applies.

## Trigger

`single-ioctl`, `ioctl-sequence`, `mmap-touch`, `concurrency`, `fd-lifecycle`,
`other`

## Confidence

`low`, `medium`, `high`

Used by both the research record and the impact record. `high` on a research
record requires `source_refs`.

## Primitive

What the memory-safety violation hands an attacker. The central field of the
impact record.

| Value | Meaning |
|---|---|
| `none` | The fault only kills the machine. The correct value for most kernel faults |
| `info-leak` | Uninitialised or out-of-bounds data reaches the attacker |
| `uncontrolled-write` | A write the attacker cannot aim |
| `controlled-write` | A write the attacker can aim |
| `controlled-free` | A free the attacker can aim |
| `refcount-imbalance` | A reference count the attacker can skew |
| `type-confusion` | An object read as the wrong type |
| `undetermined` | The analysis stopped. Requires `undetermined_reason` |

Every value except `none` and `undetermined` is a claim about code and requires
a non-empty `evidence` list.

## Consequence

The highest outcome the evidence supports.

| Value | Meaning |
|---|---|
| `dos-only` | The complete outcome for most kernel faults |
| `info-disclosure` | Data crosses a boundary it should not |
| `privilege-escalation` | Requires a determined primitive and a non-empty `attacker_control` |
| `container-escape` | Same requirement |
| `undetermined` | Requires `undetermined_reason` |

## Access type

`read`, `write`, `free`, `unknown`

Transcribed from the sanitizer report.

## Overwrite target

`function-pointer`, `length-or-size`, `refcount`, `index-or-offset`,
`list-pointer`, `flags-or-state`, `data-buffer`, `unknown`, `not-applicable`

Which field the corruption lands on. It sets the severity ceiling: an
overwritten function pointer and an overwritten flags byte are the same
memory-safety bug with different exploitability.

## Attacker control

`allocation-timing`, `allocation-size`, `written-data`, `written-offset`,
`freed-pointer`, `object-lifetime`, `call-ordering`, `none`, `unknown`

What the attacker influences. A list of values. A consequence above denial of
service argued from `none` or `unknown` alone is refused as unsupported.

## Reproduction evidence classes

| Value | Meaning |
|---|---|
| `dmesg-signature` | This crash's signature appeared in the dmesg delta |
| `timeout-hang-class` | The run hung and the crash title is hang-class |
| `harvested-log-signature` | The box rebooted and the harvested log carries this signature |
| `boot-id-change-only` | The box rebooted with no recoverable logs. Weak evidence |
| `sanitizer-signature` | Track U: a sanitizer signature in the harness output |
| `exit-condition` | Track U: the `--crash-exit` code |

## Configuration value sets

| Key | Members |
|---|---|
| `track_k.sandbox` | `none`, `setuid`, `namespace`, `android` |
| `loop.corpus_policy` | `fresh`, `carry` |

## Coverage sources

| Value | Meaning |
|---|---|
| `json:<path>` | A syz-manager JSON endpoint answered |
| `html` | The dashboard HTML was scraped |
| `corpus.db-size` | Only the corpus database's size was available |
| `afl-fuzzer_stats:<n>` | Track U: `n` harnesses reported AFL++ statistics |
| `corpus-count-only` | Track U: no harness wrote `fuzzer_stats`, so no edge count |
| `unreachable` | Nothing answered |

## GPU statuses

| Value | Meaning |
|---|---|
| `ok` | The only status that permits a plateau claim |
| `dead` | `nvidia-smi` exited non-zero, or returned no GPU |
| `hung` | No answer within `coverage.gpu_probe_timeout_sec` |
| `missing` | `nvidia-smi` is not on `PATH` |
| `error` | The probe could not be run |
| `n/a` | Track U, which never touches the GPU |

## See also

- [State file schema](/gspwn/reference/state-file/)
- [Xid classification](/gspwn/reference/xid-classification/)
