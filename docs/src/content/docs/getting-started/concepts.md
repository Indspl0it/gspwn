---
title: Concepts
description: Definitions of the terms used across the gspwn documentation.
sidebar:
  order: 1
---

Every term below carries the meaning given here throughout the documentation.
The [glossary](/gspwn/reference/glossary/) repeats the same definitions.

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
`blocked`, `failed`. The statuses live in `state/pipeline.json` and are written
only by `tools/pipeline_ctl.py`.

## Sub-agent dispatch

The orchestrator dispatches one sub-agent per phase and hands it the contents
of `agents/<phase>.md`, both configuration files, and the paths of the
artifacts it needs. Sub-agents are isolated from each other and hand off file
paths.

## Gate evidence

Gate evidence is checked against files on disk. A sub-agent's assertion does
not satisfy a gate. A phase whose evidence cannot be confirmed is marked
`blocked`, and the pipeline stops there.
[Sub-agents](/gspwn/reference/sub-agents/) lists the gate for every phase.

## Rounds and campaigns

A round inherits two things from its predecessor: the corpus and the worklist.
A round contains at least one campaign. A round with a Track K campaign and a
Track U campaign contains two.

A campaign survives the kernel panics the pipeline expects. The systemd units
restart after the reboot, and the deadline is a file on disk.

The run id names the campaign directory (`artifacts/runs/<run-id>/`), its
coverage files, its deadline file and its systemd deadline timer. It is also
the key the spend ledger bills against.

## Registry entry

| Field | Value |
|---|---|
| id | `crash-0001` and upward |
| track | `K` or `U` |
| title | canonicalised crash title |
| stack hash | hash over the top stack frames |
| status | `unique`, `duplicate` or `flagged` |
| source directory | location of the raw crash artifacts |
| reproduction rate | optional, written by `poc` |
| research record | optional, written by `rca` |
| impact record | optional, written by `rca` |

## Research record

| Key | Content |
|---|---|
| `subsystem` | the driver subsystem the fault sits in |
| `bug_class` | the memory-safety class of the bug |
| `trigger` | what drives the fault |
| `ioctls` | the ioctls the reproducer called |
| `preconditions` | the state the bug needed |
| `adjacent` | calls that share an object, lock, refcount or teardown path with the fault and were never exercised |
| `source_refs` | `file:line` references into the driver source |
| `hypothesis` | the proposed mechanism |
| `confidence` | the analyst's confidence in the hypothesis |

The research record is the mechanism by which a finding changes where the
fuzzer looks in the next round. `refine` derives worklist items from the
`adjacent` calls.

## Impact record

An impact record states the primitive the memory-safety violation hands an
attacker, the field the corruption lands on, whether a freed allocation can be
reclaimed with attacker data, and what the attacker influences. `report` reads
impact records to argue a severity. The two record types are stored separately.

## Worklist tags

Every worklist item carries the tag of its source.

| Tag | Source of the item |
|---|---|
| `[surface]` | an enumerated command the corpus has not reached |
| `[finding crash-NNNN]` | a call adjacent to the named registered crash |
| `[history CVE-YYYY-NNNNN]` | a place a published fix changed, from the round-1 history worklist |

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
