---
title: object_graph.py
description: The RM allocation DAG extracted from the driver's own class table, and the two source inconsistencies that break a naive parser.
---

Extracts the Resource Manager allocation DAG from
`src/nvidia/src/kernel/rmapi/resource_list.h` in an open-gpu-kernel-modules
checkout. The `describe` phase needs the legal parent of every allocatable
class to chain syzlang resources. The driver declares that relation in one
table, and this module reads it.

The module runs entirely off the source tree. It reaches no device, opens no
socket, and needs no GPU.

## Responsibility

The module owns the parse of `RS_ENTRY` records and the graph derived from
them. It writes only the JSON file it is given.

| Invariant | Enforced by |
|---|---|
| A field the source labels inconsistently is still read | The last field's label matches `Required Access Rights?`, covering the 15 records that omit the plural |
| A class with no `RS_LIST` parent still appears | `RS_ROOT_OBJECT` maps to the root sentinel and `RS_ANY_PARENT` to its own sentinel |
| Every external class an internal parent exports is a legal parent | The internal-to-external map holds a list per internal class, and the resolve loop extends the parent list with all of them |
| An `RS_ANY_PARENT` edge does not flatten the tree | The sentinel is seeded at depth 1 and is not an edge from any real class |
| Allocation privilege comes from the field that carries it | `RS_FLAGS_ALLOC_*` in Flags, never Required Access Rights |
| A record naming no privilege flag is never counted as reachable | It is classified `unclassified` and reported separately |
| A table format change fails loudly | Zero `RS_ENTRY` matches exits with a message naming the file |
| An unresolved parent is visible | Unresolved internal class names are counted and logged as a warning |

## Interface

| Subcommand | Output |
|---|---|
| `extract [--out PATH]` | One JSON record per class: external and internal class, parents, alloc param kind and struct, allocation privilege, flags, access rights, depth |
| `summary` | Privilege split, alloc-param split, depth distribution, widest parents |
| `chain CLASS` | The shortest allocation chain from the device node to one class, with each step's privilege and parameter struct |
| `targets [--top N]` | Parents ranked by reachable subtree size, with the unprivileged count in each subtree |
| `chains [--control PATH] [--out PATH]` | `surface/rm-chains.json`: one chain record per NVOC internal class, joined to the control commands that class owns, plus the cumulative-reach curve and the owning classes no chain reaches |

`--src` selects the checkout and defaults to
`artifacts/src/open-gpu-kernel-modules`. `chains` also reads
`surface/rm-control-inventory.json`, which `--control` overrides.

| Function | Returns |
|---|---|
| `parse_entries(src)` | One dict per `RS_ENTRY` record |
| `build_graph(entries)` | The class-to-parents map, and the internal-to-external class map, which holds every external class an internal class exports |
| `depths(graph)` | Depth from the device node, the sentinel root being 0 |
| `privilege(rec)` | `unprivileged`, `privileged`, `kernel` or `unclassified` |
| `alloc_param(rec)` | The requirement kind and the struct name |
| `shortest_chain(graph, depth, cls)` | The allocation chain, shallowest parent at each step |
| `allocatable_depths(graph, by_ext)` | Depth over the classes an unprivileged process can allocate, blocking on `privileged` and `kernel` |
| `chain_records(...)` | One chain record per internal class, with its commands and its per-step allocation parameter |
| `cumulative_reach(recs)` | The greedy curve of commands unlocked against allocations built |

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing at run time. The `describe` phase invokes it as a command |
| This module imports | Nothing in `tools/` |

## Failure modes

| Condition | Behaviour | Exit |
|---|---|---|
| `resource_list.h` absent under `--src` | Message naming the expected path and the flag to override it | 1 |
| No `RS_ENTRY` record matches | Message stating the table format has changed and the parser needs updating | 1 |
| `chain` names a class with no record | Message on stderr | 2 |
| A field label does not match | The field reads as null, and the count per field is logged as a warning | 0 |
| A parent's internal class resolves to no external class | Counted and logged as a warning, and the edge is dropped | 0 |
| The output directory does not exist | Created, and the creation is logged | 0 |

## Concurrency and durability

The module reads one file and writes one file per invocation, and takes no
lock. It holds no state between runs and is safe to re-run. Two concurrent
invocations writing the same output path race for it, and the phase invokes it
sequentially.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never read allocation privilege from Required Access Rights | All 222 records carry `RS_ACCESS_NONE` there. A reader keyed on that field reports the entire table as reachable by an unprivileged client |
| Never treat an unclassified record as unprivileged | A record naming no `RS_FLAGS_ALLOC_*` marker says nothing about privilege, and defaulting it to unprivileged inflates the surface count |
| Never present the privilege split as a reachability count | Class constructors add their own checks, and `gpuGetClassByClassId` rejects classes absent from the installed part |
| Never let an `RS_ANY_PARENT` class inherit a depth from a real edge | Those classes attach under any object, and adding real edges for them collapses the depth distribution the chaining argument rests on |
| Never drop an unmatched field silently | A silently null field reads downstream as a class with no privilege requirement |

## Design notes

The source carries two inconsistencies that a straightforward parser mishandles
without warning. 15 records label the final field `Required Access Right`
without the plural. 5 records declare `RS_ANY_PARENT` where the rest declare
`RS_LIST(classId(...))`, and those five are the event and context-DMA classes,
which attach under any allocated object and are therefore the cheapest way to
place a second reference on an object under test.

Parent resolution is textual and one-to-many. `classId(X)` names an internal
class, and 18 of the 98 internal classes in the table export more than one
external class: `DispChannelDma` exports 23, `KernelGraphicsObject` 17,
`KernelChannel` 11. Every one of those is a legal parent, so a `classId(X)`
edge resolves to all of them. Resolving through the first declaring record
instead loses 970 of the 1216 parent edges and under-reports the parent list on
122 of the 222 records.

The loss propagates into the descriptions. `syzlang_gen.py` pins
`hObjectParent` to a single resource when a class has exactly one legal parent,
and a collapsed map manufactures that condition: 63 allocation variants pinned
their parent to `GF100_CHANNEL_GPFIFO` alone, where the widened map gives those
same 63 a parent set of 11 channel classes. No check reported the narrowing,
because the set compiled, the counts held, and `surface_cov.py` measured 155 of
155 modelled. What a single wrong pin costs a campaign is unverified: no chain
has been allocated, no GPU was involved, and no syzkaller tree executed any of
these variants.

No class changed depth when the map was widened. The recovered edges run from a
class to siblings of the parent it already had, and those siblings sit at the
same depth.

Depth is measured from the open file descriptor. 151 of 222 classes sit at
depth 4, which is the quantitative form of the warning in the `describe` phase
prompt: a description set without resource chaining reaches the 25 classes at
depth 1 and 2 and no further.

## Chain grouping

Commands sharing an owning class share an allocation chain, so one program can
build the chain once and issue every command that class owns against it.
`chains` performs the join that makes that shape buildable: the control
inventory carries `owning_class`, the NVOC internal class name, and this table
carries `internal_class` on every record.

| Field on a chain record | Contents |
|---|---|
| `internal_class` | The join key to the control inventory's `owning_class` |
| `external_classes` | Every external class this internal class exports, with its allocation privilege and table depth |
| `target_external_class` | The one the chain reaches, cheapest over all of them |
| `chain` | Ordered from the file descriptor, each step carrying `external_class`, `alloc_param_struct`, `alloc_param_kind` and `alloc_privilege` |
| `chain_length` | Prologue cost in allocations |
| `unclassified_steps` | Steps whose `RS_ENTRY` names no `RS_FLAGS_ALLOC_*` flag |
| `unallocatable_reason` | Why there is no chain, null when there is one |
| `commands`, `command_count` | The targetable control commands this class owns |

The artefact carries 98 records, 82 of them chained. 514 of the 531 targetable
control commands resolve to a chain.

`cumulative_reach` is the greedy curve. Each step buys the class with the
highest command count per allocation the built set does not already hold, and
every class allocated along the way is credited, so a class whose whole chain is
already built costs nothing.

| Objects built | Commands unlocked | Share of 531 | Last class added at that count |
|---|---|---|---|
| 1 | 91 | 17% | RmClientResource |
| 3 | 315 | 59% | Device |
| 4 | 337 | 63% | VgpuConfigApi |
| 11 | 429 | 81% | ConfidentialComputeApi |
| 15 | 455 | 86% | SemaphoreSurface |
| 38 | 514 | 97% | ZbcApi |

Beyond 38 allocations nothing further unlocks. Three allocations reach 59% of
the control surface, against a naive program shape that rebuilds a chain for a
single call.

17 commands reach no chain, for two reasons that are not parser defects, and
`unresolved_owning_classes` records the class, the reason and the handler names
for each.

| Owning class | Commands | Cause |
|---|---|---|
| `Memory` | 6 | NVOC base class, no `RS_ENTRY` row |
| `ProfilerBase` | 9 | NVOC base class, no `RS_ENTRY` row |
| `MmuFaultBuffer` | 1 | Every external class carries `RS_FLAGS_ALLOC_PRIVILEGED` |
| `NvDispApi` | 1 | Every external class carries `RS_FLAGS_ALLOC_PRIVILEGED` |

The chain walk blocks on `privileged` and `kernel` and admits `unclassified`.
`NV01_ROOT`, `NV01_ROOT_NON_PRIV` and `NV01_ROOT_CLIENT` name no
`RS_FLAGS_ALLOC_*` flag, and every chain starts at one of the three, so a strict
test empties the whole chain set: 82 chains become 2 and the curve tops out at 2
commands. Every chain carrying such a step lists it in `unclassified_steps`, so
an admitted step is distinguishable from a verified unprivileged one.

`rm-chains.json` is the data a chain-grouped program is built from. The
conversion into `.syz` programs belongs to
[`trace2seed.py chains`](/gspwn/architecture/components/trace2seed/).

## Stated limits

| Limit | Consequence |
|---|---|
| Chip gating is invisible in the table | The chain records name one external class and do not model `gpuGetClassByClassId`, which searches the per-chip class descriptor lists `gpu.c:1183` copies into `pGpu->classDB`. Over the 34 lists in `src/nvidia/generated/g_gpu_class_list.c`, 31 name a `*_CHANNEL_GPFIFO` class and all 31 name `GF100_CHANNEL_GPFIFO`, so the channel family is not one class per part on this release. The display family is gated: at most 2 of its 8 members appear together on any one part |
| Nothing in CI runs `chains` | The artefact goes stale against a driver bump. `regression_check.py derived` reports the drift against the control inventory and does not repair it |
| No chain has been allocated | The cumulative-reach curve, the chain lengths and the 514 count are arithmetic over the `RS_ENTRY` table. No GPU was involved, no allocation was issued and no emitted program was executed, so the reach these numbers describe is unverified |

## See also

- [Resource Manager object model](/gspwn/knowledgebase/rm-object-model/)
- [ctrl_rank.py](/gspwn/architecture/components/ctrl-rank/)
- [trace2seed.py](/gspwn/architecture/components/trace2seed/)
- [Threat model](/gspwn/architecture/threat-model/)
