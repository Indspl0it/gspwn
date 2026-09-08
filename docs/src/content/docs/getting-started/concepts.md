---
title: Concepts
description: Definitions of the terms used across the gspwn documentation.
sidebar:
  order: 1
---

Every term below names a unit of work the pipeline schedules or a record it
writes to `state/pipeline.json`.

## Terms

| Term | Definition |
|---|---|
| Track | One of the two codebases under test. Track K is the NVIDIA GPU kernel driver (`open-gpu-kernel-modules`), fuzzed with syzkaller against an instrumented kernel. Track U is the NVIDIA Container Toolkit (`libnvidia-container` and `nvidia-container-toolkit`), fuzzed with libFuzzer and AFL++ harnesses inside a container. |
| Phase | One of twelve units of work. Each phase holds a status in `state/pipeline.json`. |
| Sub-agent | The definition of how a phase is carried out, one file per phase in `agents/`. The twelve sub-agents are named for their phases. |
| Gate | The evidence a phase must produce before it is marked `done`. |
| Round | One pass through the nine round phases, from `describe` to `refine`. Rounds are numbered from 1 in `state/pipeline.json`. |
| Campaign | One fuzzing run under systemd, bounded by a deadline written to disk. A campaign runs until `loop.campaign_hours` have elapsed. |
| Run id | The identifier for one campaign, of the form `r<round>-<n>`. `r2-1` is the first campaign of round 2. One run id covers both tracks. |
| Registry | The `crashes` map in `state/pipeline.json`. |
| Research record | The structured output of the `rca` phase, one per analysed crash, attached with `pipeline_ctl.py finding-set`. |
| Impact record | The second structured output of `rca`, attached with `pipeline_ctl.py impact-set`. |
| Worklist | The file `artifacts/eval/<run-id>/worklist.md`, written by the `refine` phase. It holds ordered, deduplicated work items in a describe section and a seeds section. |
| Plateau | The verdict that another campaign is not expected to find enough new edges to be worth running. |

## Phases

The twelve phases in dependency order:

```
provision  build  describe  seeds  harness  fuzz  triage  rca  poc  eval  refine  report
```

`provision` and `build` run once per machine. The nine phases from `describe`
to `refine` run once per round. `report` runs once, after the loop stops.

A phase carries one of five statuses: `pending`, `in_progress`, `done`,
`blocked` and `failed`. Only `tools/pipeline_ctl.py` writes them.

## Sub-agent dispatch

The orchestrator dispatches one sub-agent per phase and hands it the contents
of `agents/<phase>.md`, both configuration files, and the paths of the
artifacts it needs. Sub-agents are isolated from each other and hand off file
paths.

## Gate evidence

Gate evidence is checked against files on disk. A sub-agent's assertion does
not satisfy a gate. A phase whose evidence cannot be confirmed is marked
`blocked`, and the pipeline stops there.
[Sub-agents](/gspwn/architecture/sub-agents/) lists the gate for every phase.

## Rounds and campaigns

A round inherits two things from its predecessor: the corpus and the worklist.
A round contains at least one campaign. A round with a Track K campaign and a
Track U campaign contains two.

A kernel panic does not end a campaign. The systemd units restart after the
reboot and the deadline is a file on disk, so the campaign resumes against the
same end time.

The run id names the campaign directory (`artifacts/runs/<run-id>/`), its
coverage files, its deadline file and its systemd deadline timer. It is also
the key the spend ledger bills against.

## Registry entry

A registry entry carries fourteen fields. `id` is the key in the `crashes` map,
and the other thirteen are the entry.

| Field | Value | Written by |
|---|---|---|
| `id` | `crash-0001` and upward | `triage` |
| `track` | `K` or `U` | `triage` |
| `title` | canonicalised crash title | `triage` |
| `stack_hash` | hash over the top stack frames | `triage` |
| `dir` | location of the raw crash artifacts | `triage` |
| `signal` | `signal`, `review`, `health`, `noise` or `unclassified`, from the Xid class | `triage` |
| `status` | one of eight values, below | `triage`, then `rca` and `poc` |
| `duplicate_of` | the surviving entry this one duplicates, or none | `triage` |
| `notes` | free text recorded with a status decision | `triage` |
| `rca_done_at` | when `rca` finished with the crash, stamped once and never cleared | `rca` |
| `finding` | the research record, or none | `rca` |
| `impact` | the impact record, or none | `rca` |
| `repro_rate` | measured reproduction rate, or none | `poc` |
| `disclosure` | `pending`, `submitted`, `resolved` or `not_applicable` | `report` |

`status` takes `unique`, `duplicate`, `flagged`, `rca_done`, `reliable`,
`flaky`, `unreproducible` or `reported`. It is not durable: `poc` overwrites
`rca_done` with the reproduction class, so `rca_done_at` carries the record
that the crash was analysed.

## Research record

A research record carries ten keys.

| Key | Content |
|---|---|
| `subsystem` | the driver subsystem the fault occurs in |
| `bug_class` | the memory-safety class of the bug |
| `trigger` | what drives the fault |
| `ioctls` | the ioctls the reproducer called |
| `preconditions` | the state the bug needed |
| `adjacent` | calls that share an object, lock, refcount or teardown path with the fault and were never exercised |
| `no_adjacent_reason` | why `adjacent` is empty, required when it is |
| `source_refs` | `file:line` references into the driver source |
| `hypothesis` | the proposed mechanism |
| `confidence` | the analyst's confidence in the hypothesis |

`bug_class`, `trigger` and `confidence` take values from a closed vocabulary,
so `refine` can group findings across rounds.

`refine` derives worklist items from the `adjacent` calls. That is the only
path by which a finding changes where the fuzzer looks in the next round, and a
record with an empty `adjacent` and no `no_adjacent_reason` fails
`pipeline_ctl.py validate`.

## Impact record

An impact record states what the memory-safety violation hands an attacker.
`report` reads impact records to argue a severity. The two record types are
stored separately, because a research record steers the next round and an
impact record supports a severity claim.

| Key | Content |
|---|---|
| `primitive` | the memory-safety primitive the fault yields |
| `consequence` | what the primitive is argued to reach |
| `cwe` | the CWE, derived from `bug_class` when empty |
| `corrupted_object` | the struct or allocation the fault touches |
| `cache` | the slab cache or size class it comes from |
| `access_type` | `read`, `write`, `free` or `unknown`, transcribed from the sanitizer report |
| `access_size` | bytes, from the sanitizer report |
| `overwrite_target` | the field the corruption overwrites, from a closed vocabulary |
| `reclaim_path` | how a freed allocation can be re-occupied with attacker data |
| `race_window` | what has to interleave, for a race or use-after-free |
| `allocation_site` | `file.c:line` |
| `free_site` | `file.c:line` |
| `access_site` | `file.c:line` |
| `attacker_control` | what the attacker influences, from a closed vocabulary |
| `evidence` | source references behind the claim |
| `unverified` | the specific claims not checked against source |
| `undetermined_reason` | why `primitive` or `consequence` is undetermined, required when either is |
| `confidence` | `low`, `medium` or `high` |

`overwrite_target` sets the ceiling on the severity `report` can argue. An
overwritten function pointer and an overwritten flags byte are the same
memory-safety bug and different vulnerabilities.

## Worklist tags

Every worklist item carries the tag of its source.

| Tag | Source of the item |
|---|---|
| `[surface]` | an enumerated command the corpus has not reached |
| `[finding crash-NNNN]` | a call adjacent to the named registered crash |
| `[history CVE-YYYY-NNNNN]` | a place a published fix changed, from the round-1 history worklist |

A history item touched by more than one CVE carries the oldest, with the rest
counted: `[history CVE-2024-0090 +2]`.

`round-end --worklist <path>` records the file, `round-advance` carries it into
the new round, and the next round's `describe` and `seeds` sub-agents read it
back with `pipeline_ctl.py worklist`.

## Plateau verdicts

The verdict comes from fitting a species-accumulation curve to the run's
coverage series and extrapolating it over `coverage.horizon_hours`.

| Verdict | Condition |
|---|---|
| `growing` | expected new edges at or above `coverage.plateau_new_edges` |
| `plateaued` | expected new edges below `coverage.plateau_new_edges` |
| `unknown` | no verdict could be computed |

`unknown` stops the loop, so a broken sampler cannot authorise another
campaign.

## Next

- [Requirements](/gspwn/getting-started/requirements/) lists what the machine
  must provide.
- [Architecture overview](/gspwn/architecture/overview/) shows how the phases
  connect.
