---
title: Impact and severity
description: The impact record schema, the derived CWE mapping, the three support gaps that block a severity, and the chain the report writes to argue one.
---

A reproducer proves a crash condition. It constitutes a bug report: the
software faulted, and the input that caused it is recorded.

A vulnerability report names the weakness and states what the fault hands an
attacker. A product security team rates the finding from those two facts.
Without the second, a severity is an assertion, and an asserted severity that a
vendor engineer disproves reduces the credibility of every other finding in the
same report.

## The two halves

| Half | Determines | Phase | Recorded as |
|---|---|---|---|
| What the fault is worth | What the memory-safety violation hands an attacker | `rca` | The impact record, `crash.impact` |
| Who can reach it | Whether the modelled attacker can trigger it | `poc` | The profile-check outcome, in the PoC README |

Neither substitutes for the other. A controlled write no unprivileged process
can trigger and a trivially reachable null dereference are both real findings,
and neither is critical. The `report` phase joins them.

The reachability half is specified in
[Threat model](/gspwn/architecture/threat-model/). `rca` does not claim tenant
reachability, and the `poc` phase answers it by experiment.

## Record schema

`DEFAULT_IMPACT` in `tools/pipeline_state.py` holds eighteen fields, written
through `pipeline_ctl.py impact-set`.

### Judgement fields

| Field | Vocabulary | Role |
|---|---|---|
| `primitive` | `none`, `info-leak`, `uncontrolled-write`, `controlled-write`, `controlled-free`, `refcount-imbalance`, `type-confusion`, `undetermined` | What the violation hands an attacker. The record exists to carry this field. `none` is the correct value for a fault that only halts the machine, which covers most kernel faults |
| `consequence` | `dos-only`, `info-disclosure`, `privilege-escalation`, `container-escape`, `undetermined` | The highest outcome the evidence supports. `dos-only` is a complete answer |
| `overwrite_target` | `function-pointer`, `length-or-size`, `refcount`, `index-or-offset`, `list-pointer`, `flags-or-state`, `data-buffer`, `unknown`, `not-applicable` | Which field the corruption lands on. An overwritten function pointer and an overwritten flags byte are the same memory-safety bug and different vulnerabilities |
| `attacker_control` | `allocation-timing`, `allocation-size`, `written-data`, `written-offset`, `freed-pointer`, `object-lifetime`, `call-ordering`, `none`, `unknown` | What the attacker influences. A consequence above denial of service argued from an attacker who influences nothing is challenged first |

### Transcription fields

Seven fields are copied from the sanitizer report and involve no judgement.
KASAN prints all of them.

| Field | Source |
|---|---|
| `access_type` | The read, write or free the sanitizer reported |
| `access_size` | Bytes, from the sanitizer report |
| `corrupted_object` | The struct or allocation the fault touches |
| `cache` | The slab cache or size class it comes from |
| `allocation_site` | `file.c:line` |
| `free_site` | `file.c:line` |
| `access_site` | `file.c:line` |

### Analysis fields

| Field | Question it answers |
|---|---|
| `reclaim_path` | For a use-after-free, whether the attacker can get the freed allocation back with data they chose, and by what mechanism |
| `race_window` | For a race, what has to interleave |

Both are free text and both may be left empty. An empty field claims nothing.

### Provenance fields

| Field | Content |
|---|---|
| `evidence` | `file.c:line` references or report references behind the claim |
| `unverified` | The specific claims not checked against source |
| `confidence` | `low`, `medium` or `high` |
| `undetermined_reason` | What blocked the analysis, required when `primitive` or `consequence` is `undetermined` |

## CWE derivation

`CWE_OF_BUG_CLASS` maps the research record's `bug_class` to a weakness class.

```
uaf -> CWE-416          double-free -> CWE-415
oob-read -> CWE-125     oob-write -> CWE-787
race -> CWE-362         refcount -> CWE-911
null-deref -> CWE-476   uninit -> CWE-908
deadlock -> CWE-833     leak -> CWE-401
type-confusion -> CWE-843
integer-overflow -> CWE-190
other -> (empty)
```

The mapping is mechanical, and a free-text CWE field admits a plausible wrong
number that nobody re-checks. Setting `cwe` on the impact record overrides the
derived value, for `other` and for cases where a more specific child class
applies. `bug_class` is a closed vocabulary, so the two cannot disagree by
drift.

## Analysis boundary

The record stops at the primitive. Stating that a use-after-free gives a
controlled write into an allocation the attacker can reclaim is analysis.
Building the escalation is out of scope for this campaign.

`undetermined` costs nothing and is checked for exactly one thing: that
`undetermined_reason` was given.

```json
{"primitive": "undetermined",
 "consequence": "undetermined",
 "undetermined_reason": "the fault path enters GSP RPC, so the callee that writes the corrupted field is not visible from the kernel side",
 "confidence": "low"}
```

An unexplained `undetermined` is indistinguishable from an analysis nobody did.
An invented impact narrative is the most costly outcome, so `undetermined` is
never penalised and only an unexplained one is reported as a problem.

## Support gaps

`impact_support_gap()` reports three conditions, in rising order of cost.

| Gap | Condition | Message tail |
|---|---|---|
| 1. Concludes nothing without saying why | `primitive` **or** `consequence` is `undetermined`, and `undetermined_reason` is empty. Either field alone triggers it | `Undetermined is a valid answer here, but an unexplained one is not, because nobody later can tell it apart from an analysis that was skipped` |
| 2. Claims a primitive with no evidence | `primitive` in `PRIMITIVE_NEEDS_EVIDENCE` and `evidence` empty | `That is a claim about code, so it needs the file:line it rests on before a report can put a severity on it` |
| 3. Consequence outruns its mechanism | `consequence` in `CONSEQUENCE_NEEDS_CONTROL` and `primitive` is `none` or `undetermined` | `The conclusion outruns the mechanism: name what the fault actually gives an attacker, or lower the consequence` |
| 4. Consequence rests on an attacker who controls nothing | `consequence` in `CONSEQUENCE_NEEDS_CONTROL` and `attacker_control` is empty or holds only `none` and `unknown` | `An outcome above denial of service needs the attacker to influence something. With no influence, the defensible answer is dos-only` |

Gap 1 is checked first, so a record carrying `primitive=oob-write` with
`consequence=undetermined` and no `undetermined_reason` is refused there and
never reaches gaps 2 to 4. Each message opens with the record's own field
values, and the column above carries the tail.

A primitive other than `none` or `undetermined` is a claim about code, and a
claim about code with no `file:line` behind it carries no evidence.

Gaps 3 and 4 carry the highest cost. A privilege-escalation conclusion drawn
from an undetermined primitive is the finding a vendor engineer disproves
first, and its disproof reduces the credibility of every other finding in the
report.

A consequence **weaker** than the primitive would support is not flagged.
Under-claiming costs nothing, and flagging it pushes the analysis towards
escalating, which is the direction that carries a cost.

## The closing count

```
python3 tools/pipeline_ctl.py impact-list
```

```
by consequence (what the report's severity table rests on):
  dos-only                 4  CWE-476, CWE-833
  privilege-escalation     1  CWE-416

4 of 5 record(s) can carry a severity into the report.
These cannot, and rca should revisit them:
  crash-0009: consequence=privilege-escalation with attacker_control=unknown. An outcome above denial of service needs the attacker to influence something. With no influence, the defensible answer is dos-only
```

An unsupported record reads identically to a supported one in the rollup above
it, which is the path by which an over-claimed severity reaches a vendor. The
closing count names each unsupported record, and `pipeline_ctl.py validate`
reports the same set.

A round where every crash was analysed and no record can carry a severity found
crashes and no vulnerabilities, and the `eval` write-up states that.

## The severity chain

The `report` phase writes the argument explicitly, in this order:

```
weakness (CWE) -> primitive -> what it lands on -> what the attacker controls -> reachability -> consequence
```

| Link | Source field |
|---|---|
| Weakness | `cwe`, derived from `finding.bug_class` |
| Primitive | `impact.primitive` |
| What it lands on | `impact.overwrite_target`, `impact.corrupted_object` |
| What the attacker controls | `impact.attacker_control` |
| Reachability | The `poc` profile-check outcome |
| Consequence | `impact.consequence` |

Writing each link lets a reviewer identify which one they disagree with. A
severity presented as a single adjective exposes nothing to check. "The chain
could not be followed past here" is a legitimate place to stop.

Claims listed in `impact.unverified` are carried into the finding text, because
a severity resting on an unchecked claim has to state that where the reader
sees it.

Findings whose record cannot carry a severity are reported with their mechanism
and **no severity claim at all**, in the same way an unreproducible crash is
reported as unverified. `rca` had the source open and stopped there. A severity
invented at report time rests on less evidence than the analysis phase had.

## Integrity checks

| Check | Reported by |
|---|---|
| A crash with an `rca_done_at` stamp and no impact record | `pipeline_ctl.py validate`, `brief` |
| An impact record that does not support its conclusion | `validate`, `impact-list`, `impact-set` |
| A malformed record | `impact-set` refuses it outright |
| An unknown field name | `impact-set` refuses it |

Unknown fields are refused, so a misspelled field cannot leave the real one at
its default while the command reports success.

Duplicates are exempt from the count. They describe the same bug as their
surviving entry, and counting both reports one vulnerability as several.

## See also

- [Steering the next round](/gspwn/guides/steering-the-next-round/)
- [Threat model](/gspwn/architecture/threat-model/)
- [Closed vocabularies](/gspwn/reference/vocabularies/)
