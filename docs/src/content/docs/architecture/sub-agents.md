---
title: Sub-agents
description: The twelve phases, the dispatch contract and its isolation boundary, the prohibitions and method rules the contracts enforce, and the path by which a finding reaches the next round.
---

`agents/` holds twelve sub-agent definitions, one per phase. Each file is a
contract stating what the sub-agent reads, what it does, what it writes, what
gate evidence it returns, and what it records in `knowledge/`.

| Sub-agent | Runs | Track | Produces |
|---|---|---|---|
| `provision` | Once per machine | Both | A prepared machine, its recorded facts, the build manifest |
| `build` | Once per machine | K | An instrumented kernel and NVIDIA modules |
| `describe` | Once per round | K | syzlang descriptions |
| `seeds` | Once per round | K | Seed programs from traces and from allocation chains |
| `harness` | Once per round | U | libFuzzer and AFL++ harnesses |
| `fuzz` | Once per round | Both | A completed campaign |
| `triage` | Once per round | Both | A deduplicated crash registry |
| `rca` | Once per round | Both | RCA prose, research records, impact records |
| `poc` | Once per round | Both | Verified reproducers with reproduction rates |
| `eval` | Once per round | Both | The round's measurements |
| `refine` | Once per round | Both | The gap analysis and the next round's work list |
| `report` | Once, after the loop stops | Both | The report and the disclosure packages |

The gate each phase must satisfy is tabulated in
[First campaign](/gspwn/getting-started/first-campaign/), and the gate
section of `agents/<phase>.md` is the authority on the full evidence list.

## The dispatch contract

Three clauses fix what crosses the dispatch boundary.

- Into the sub-agent goes the full contents of `agents/<phase>.md`,
  `config/machine.yaml`, `config/campaign.yaml`, and the paths of the artifacts
  the phase reads.
- Out of the sub-agent comes a one-paragraph summary, plus gate evidence naming
  artifact paths.
- Another sub-agent's transcript never crosses.

Sub-agents hand off artifact paths. Two properties follow from that boundary.

### Gate evidence as a claim about files

The orchestrator reads the named artifacts and checks that they exist and state
what the sub-agent reported, before recording `done`. A phase whose evidence
cannot be confirmed is recorded `blocked`. See
[Execution model](/gspwn/architecture/execution-model/).

The `fuzz` phase carries the largest cost of an unconfirmed claim. Advancing on
the smoke window makes `triage` scan a nearly empty workdir, satisfies every
later gate, and bills a full campaign for `track_k.smoke_window_minutes` of
measurement.

### Cross-phase state on disk

The handoff between rounds is a field of the round record in
`state/pipeline.json`, never a filename two contracts agree on. `round-end
--worklist <path>` writes `round.worklist`, `round-advance` copies it into the
new round's `round.worklist_in`, and the next round's `describe` and `seeds`
read it back with `pipeline_ctl.py worklist`. The same record carries the run
ids a round covers, in `round.run_ids`, so a sub-agent asked for the previous
run id reads it from there.

## Prohibitions

Seven actions are prohibited across the contracts.

- Never hand-edit `state/pipeline.json`. The tool validates, locks and writes
  atomically, and parallel sub-agents editing the file directly lose each
  other's updates.
- Never type in a measured number. `round.run_hours` feeds the spend ceiling,
  and the sampler already wrote every figure to `coverage.csv`.
- Never remove a target because a hypothesis places the bug elsewhere. `rca`
  holds the only judgement in the loop, so a confident wrong one narrows every
  remaining round.
- Never work past a `blocked` phase. A blocked gate halts the walk.
- Never widen scope because an ioctl surface looked reachable. Scope is a
  threat-model decision, recorded in
  [Threat model](/gspwn/architecture/threat-model/) first.
- Never claim tenant reachability from the fuzzer's own environment. syzkaller
  holds a wider capability set than the modelled attacker.
- Never record a finding in `knowledge/`. Those files are committed to a public
  repository.

## The steering signals

Three signals reach the work list, and they answer different questions.
Surface names the enumerated commands the corpus has never called. Findings
name the calls adjacent to a bug that already happened, sharing its object,
lock, refcount or teardown path. History names the calls whose handlers NVIDIA
has already patched for a kernel-mode CVE. A fourth reading, the edge curve,
says whether the fuzzer is still finding code inside the calls it already
makes. It steers the stop decision, it names no call, and so it produces no
work-list item.

The diagram below draws the two signals a round measures for itself. History is
written once, before any campaign has run, and enters the same merge.

```mermaid
flowchart LR
  subgraph COV["Surface: which enumerated commands the corpus has NOT named"]
    C1["surface_cov.py gaps<br/>over the 852 targets"] --> C2["gaps: unmodeled,<br/>mismodeled,<br/>unreachable-by-construction"]
  end
  subgraph FIND["Findings: where the bugs HAVE been"]
    F1["research records"] --> F2["per-subsystem rollup:<br/>which subsystem yields"]
    F1 --> F3["adjacent calls,<br/>preconditions"]
  end
  C2 --> MERGE["refine merges both"]
  F2 --> MERGE
  F3 --> MERGE
  MERGE --> WL["worklist.md<br/>every item tagged<br/>[surface], [finding crash-NNNN]<br/>or [history CVE-YYYY-NNNNN]"]
```

| Signal | Produced by | Answers | Work-list tag |
|---|---|---|---|
| Surface | `surface_cov.py gaps --run-id <id>`, by stage | Which enumerated commands the corpus has not named | `[surface]` |
| Findings | `pipeline_ctl.py finding-list` | Which calls are adjacent to a bug that already happened | `[finding crash-NNNN]` |
| History | `surface/worklist-round1.md`, from `cve_patch_map.py worklist` | Which handlers NVIDIA has already patched | `[history CVE-YYYY-NNNNN]` |
| Edge curve | `coverage_ctl.py series` and `plateau` | Whether the fuzzer is still finding code inside the calls it makes | None |

A loop following the surface alone keeps widening it and never returns to a
subsystem that already yielded a bug. Every work-list item carries the tag of
the signal that produced it, and the `refine` gate reports the split. A history
item decays. `refine` carries it into the next round only while
`surface_cov.py gaps` still reports it unmodelled or unexercised, and an item
that produced a finding re-enters under its own `[finding crash-NNNN]` tag. The
tags are specified in
[Historical targeting](/gspwn/architecture/historical-targeting/).

## The feedback edge

```mermaid
flowchart TB
  CR["crash-0001"] --> RCA["rca reads the driver source"]
  RCA --> FS["finding-set:<br/>adjacent, preconditions,<br/>hypothesis, source_refs"]
  FS --> REG[("registry entry<br/>crash.finding")]
  REG --> FL["finding-list:<br/>records + rollup +<br/>'N of M can steer'"]
  FL --> RF["refine"]
  RF --> WL["artifacts/eval/&lt;run-id&gt;/worklist.md"]
  WL --> RE["round-end --worklist PATH"]
  RE --> RA["round-advance"]
  RA --> WI[("round.worklist_in")]
  WI --> DS["describe:<br/>models the adjacent calls"]
  WI --> SD["seeds:<br/>builds the preconditions"]
  DS --> NC["the next campaign"]
  SD --> NC
  NC -.->|"a new crash in the same subsystem"| CR
```

Each hop carries a check, because each can fail without producing an error.

| Hop | Failure | Check | Reported by |
|---|---|---|---|
| `rca` records the finding | No research record written | An `rca_done_at` stamp with no research record | `pipeline_ctl.py validate` |
| The record steers | An empty `adjacent`, or one repeating `ioctls` | The offending field named per crash | `finding-list`, `validate` |
| `refine` consumes the records | Work items derived from coverage only | The gate reports the split of items by source | The `refine` sub-agent |
| The work list is recorded | `--worklist` omitted from `round-end` | `round-advance` carries only what was recorded | `pipeline_ctl.py` |
| `describe` consumes the items | An item modelled in name only | The gate reports, per item, what was modelled and whether the smoke run reached it | The `describe` sub-agent |

The `rca_done_at` stamp is durable, and `rca_done` is a transient status the
`poc` phase writes the reproduction class over. See
[Crash identity](/gspwn/architecture/crash-identity/).

## The three targeting fields

`rca` fills `ioctls`, `preconditions` and `adjacent` through
`pipeline_ctl.py finding-set`. `FINDING_TARGETING` in
`tools/pipeline_state.py` holds the set.

| Field | Derived from | Use in the next round |
|---|---|---|
| `ioctls` | Transcribed from the reproducer | Models the calls that already ran |
| `preconditions` | Largely the same source | Builds the state that already existed |
| `adjacent` | Reading the driver source for the faulting object's other callers | Reaches code this reproducer never touched |

Only `adjacent` carries information the crash does not already contain. It is
populated by taking the object the bug touches, locating its other callers, and
listing the ones this reproducer never reached.

An empty `adjacent` is accepted only alongside a `no_adjacent_reason`. A bug
with no siblings on its lock or teardown path is a valid answer, as is a path
that disappears into GSP where the other callers are not visible. A
neighbouring call invented to fill the field costs the next round a full
describe-and-fuzz cycle against a target that was never adjacent to the bug.

## Method rules the contracts carry

A gate says what a phase must show. Six of the contracts also carry a rule
about how the work is done, and each exists because the cheap way to satisfy
the gate produces a wrong number.

- `describe`. Descriptions are agent-authored and treated as untrusted until
  measured, and every number and struct layout comes from the driver source.
  The ABI shifts between branches, and a wrong direction bit produces
  descriptions that compile, run and never reach the driver.
- `seeds`. A precondition no available CUDA workload reaches is reported as
  unreached, and a control command reaches a program through the allocation
  chains and never through a trace. `strace` decodes no NVIDIA parameter
  struct, so a trace names the escape and never the command behind it.
- `harness`. Sanitizer settings are explicit per harness. Leak detection is a
  stated choice, and UBSan runs with `halt_on_error=1`, without which the
  process continues past the first error and the crashing input no longer
  matches the report.
- `fuzz`. The smoke window is an early abort check, and the gate requires the
  full campaign window. Advancing on the smoke window bills a full campaign for
  half an hour of measurement.
- `rca`. Every claim about code behaviour not verified against source is marked
  `[UNVERIFIED]`, and `eval` samples from exactly that set. `rca` records what
  the fault is worth, and `poc` establishes who can reach it. An unmarked guess
  about a fault path otherwise reaches a vendor as an asserted mechanism.
- `report`. Detailed vulnerability sections only, no executive summary. A
  severity is argued as an explicit chain, and a finding whose impact record
  cannot carry a severity is reported with its mechanism and no severity claim.
  A severity invented at report time rests on less evidence than the analysis
  phase had.

`eval` carries two more. Version persistence replays every reliable reproducer
against one newer driver branch, and its outcome is required: a recorded
`skipped` with a reason satisfies the gate, and an absent answer fails it. The
impact audit re-reads the evidence behind every record claiming
`privilege-escalation` or `container-escape`, the two claims a vendor
challenges first.

## Knowledge

Every sub-agent reads the accumulated knowledge for its phase before starting,
and records what it learns as it learns it.

- `knowledge/learnings.md` holds what the campaigns learn about the target, as
  in "UVM has its own ioctl numbering scheme and does not follow the RM escape
  convention".
- `knowledge/mistakes.md` holds what they learn about the process, as in "A
  flat coverage curve was reported as a plateau on a card that had stopped
  answering".

These files are committed and outlive the box, the campaign and the session.
They are the only content a rebuilt machine starts with. Entries are appended
through `knowledge_ctl.py`, which holds a per-file lock, at the point the fact
is learned. An entry written at the end of a round from memory has already lost
the detail that mattered.

The repository is public, so entries carry ABI and process facts.
`knowledge_ctl.py note` refuses text naming a crash id or a path under
`artifacts/crashes`, `artifacts/pocs` or `artifacts/rca`.

## See also

- [Steering the next round](/gspwn/guides/steering-the-next-round/)
- [Execution model](/gspwn/architecture/execution-model/)
- [Impact and severity](/gspwn/architecture/impact-and-severity/)
