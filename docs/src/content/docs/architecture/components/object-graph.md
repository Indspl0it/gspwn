---
title: object_graph.py
description: The RM allocation DAG extracted from the driver's own class table, and the two source inconsistencies that break a naive parser.
---

Extracts the Resource Manager allocation DAG from
`src/nvidia/src/kernel/rmapi/resource_list.h` in an open-gpu-kernel-modules
checkout. The `describe` phase needs the legal parent of every allocatable
class to chain syzlang resources; the driver declares that relation in one
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

`--src` selects the checkout and defaults to
`artifacts/src/open-gpu-kernel-modules`.

| Function | Returns |
|---|---|
| `parse_entries(src)` | One dict per `RS_ENTRY` record |
| `build_graph(entries)` | The class-to-parents map, and the internal-to-external class map |
| `depths(graph)` | Depth from the device node, the sentinel root being 0 |
| `privilege(rec)` | `unprivileged`, `privileged`, `kernel` or `unclassified` |
| `alloc_param(rec)` | The requirement kind and the struct name |
| `shortest_chain(graph, depth, cls)` | The allocation chain, shallowest parent at each step |

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

Parent resolution is textual. `classId(X)` maps to an external class through
the first record declaring internal class X, so several external classes
sharing one internal class collapse onto the first. Every per-generation
channel class shares `KernelChannel`, so engine classes parented by a channel
all resolve to `GF100_CHANNEL_GPFIFO`.

Depth is measured from the open file descriptor. 151 of 222 classes sit at
depth 4, which is the quantitative form of the warning in the `describe` phase
prompt: a description set without resource chaining reaches the 25 classes at
depth 1 and 2 and no further.

## See also

- [Resource Manager object model](/gspwn/knowledgebase/rm-object-model/)
- [Threat model](/gspwn/architecture/threat-model/)
