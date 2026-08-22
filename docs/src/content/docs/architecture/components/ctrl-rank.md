---
title: ctrl_rank.py
description: The measured ordering of the 531 targetable control commands, the three components behind the score, and the join that makes the CVE history usable.
---

Ranks the 531 targetable RM control commands on allocation chain length, fix
history and parameter size. `syzlang_gen.py --max-control N` emits the first N
commands of an ordering, and the describe phase's work order asks for the same
ordering.

The ordering this module replaced was a four-value ladder on the SDK class id,
hardcoded in the generator. That ladder read no measurement and put 216 of the
531 commands in one bucket, separating nothing inside it.

The module runs off the driver source tree and the committed artefacts. It
reaches no device, opens no socket, and needs no GPU.

## Responsibility

The module owns the score, the ordering and `surface/rm-control-rank.json`.
It writes only that file.

| Invariant | Enforced by |
|---|---|
| Reachability outranks every other component | Whether a chain exists leads the sort key, ahead of the score, so the 17 commands with no chain sort after every command that has one whatever they score. Chain length is the third term |
| A command with no chain still carries its reason | `no_chain_reason` is copied from the chains artefact onto the record |
| A judgement about weights can be revised without a rescan | `rank_components` holds `depth`, `cve` and `size` beside `rank_score` |
| A skewed distribution does not dominate the score | The CVE and size components are normalised logarithmically |
| The ordering is stable across runs and hosts | Ties break on chain length, then CVE releases descending, then method id |
| The rank is a dense ordinal | `rank` is assigned after the sort and starts at 1 |
| The hot-spot join reaches the definition and not the declaration | `scan_impl_definitions` scans `src/` for `<handler>_<SUFFIX>(` at the start of a line, admitting an optional same-line return type in front of the name |
| A handler with more than one definition resolves the same way every run | `SUFFIX_RANK` orders `IMPL`, `KERNEL`, `PHYSICAL`, `VF`, then sorted path, then line number. 8 of the 531 carry more than one candidate |
| A null `impl_file` is distinguishable from a scan that failed | `impl_state` reads `resolved` or `no hand-written definition`, and `impl_suffix` names the suffix that won |

## Interface

| Subcommand | Output |
|---|---|
| `rank [--src DIR] [--control PATH] [--chains PATH] [--hotspots PATH] [--sizes PATH] [--out PATH]` | `rm-control-rank.json`: one record per targetable command, the counts block, the source block and the weighting |
| `report [--rank PATH] [--top N]` | The head of the ranking as a table |

| Function | Returns |
|---|---|
| `scan_impl_definitions(src)` | Handler name to `(file, line, suffix)` for every hand-written definition under `src/`, over the four suffixes `IMPL`, `KERNEL`, `PHYSICAL` and `VF` |
| `hotspot_index(hotspots)` | The by-file and by-function lookups, built from the two JSON arrays |
| `chain_index(chains)` | Owning class to chain length, target class and no-chain reason |
| `targetable(control)` | The methods the inventory marks reachable by an unprivileged client |
| `build_records(...)` | One record per command, with the three raw measurements attached |
| `score_records(rows)` | The same records carrying `rank_components`, `rank_score` and `rank` |
| `sort_key(row)` | The ordering tuple, reachability first |

## Record fields

| Field | Contents |
|---|---|
| `handler`, `owning_class`, `sdk_prefix`, `method_id`, `class_id` | The command's identity, from the control inventory |
| `param_struct`, `param_size`, `param_size_state` | The parameter struct, its measured size, and whether a size was found |
| `chain_length`, `chain_target_class`, `no_chain_reason` | The allocation prologue, from `rm-chains.json` |
| `impl_file`, `impl_line`, `impl_suffix`, `impl_state` | Where the handler is defined, from the definition scan, which suffix won, and whether the scan resolved it or found no hand-written definition |
| `cve_file_releases`, `cve_function`, `cve_function_releases` | The fix history behind the two CVE readings |
| `rank_components`, `rank_score`, `rank` | The three normalised components, the weighted score, and the dense ordinal |
| `routed_to_physical` | Whether the parameter buffer crosses the RPC queue to GSP |

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing at run time |
| Reads this module's output | `tools/syzlang_gen.py`, as the default for `--ctrl-rank`. `tools/trace2seed.py chains`, to order the commands inside a program |
| This module imports | Nothing in `tools/`. It reads four JSON artefacts and the driver source |

## Failure modes

| Condition | Behaviour | Exit |
|---|---|---|
| An input artefact is absent | Message naming the file and stating the ranking cannot be computed without it | 1 |
| An input artefact does not parse | Message naming the file and the parse error | 1 |
| The control inventory carries no `methods` array | Message naming the file | 1 |
| `cve-hotspots.json` carries no `hotspots` object | Message naming the file | 1 |
| The `src` tree is absent under `--src` | Message naming the path and the flag to override it | 1 |
| A handler resolves to no implementation file | `impl_file` and `impl_line` are null, `impl_state` reads `no hand-written definition`, and the CVE component scores zero | 0 |
| A parameter struct has no measured size | `param_size_state` is `unmeasured` and the size component scores zero | 0 |

## Concurrency and durability

One invocation reads four JSON files and the source tree, then writes one file
through a temp file in the target directory and an `os.replace`. No lock is
taken. Two concurrent invocations sharing an output path race for it, and the
phase invokes it once.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never let the depth component carry reachability on its own | A command at the maximum chain length also scores 0 on depth, so without a leading reachability term an unreachable command with a large struct and a long CVE history outscores a reachable one |
| Never score the parameter size on a raw byte count | The distribution runs from 0 to 229392 bytes with a median of 16, and a linear scale puts a handful of diagnostic structs at the top of every campaign |
| Never join the hot spots on the inventory's `source` field | Handlers are declared in the NVOC generated tables and defined elsewhere under one of the four suffixes, so that join matches nothing and scores every command at zero CVE weight |
| Never drop the start-of-line anchor from the definition pattern | NVOC generated code calls the symbol from inside a function body, where it is indented. Dropping the anchor to admit a return type would match every call site, so the return type is admitted in front of the name instead |
| Never restrict the scan to `src/nvidia/src` | The `cliresCtrlCmdOsUnix*` export and import family is defined in `src/nvidia/arch/nvalloc/unix/src/os.c`, and that family is the historically CVE-dense unprivileged path on this surface |
| Never read `hotspots.by_file` and `hotspots.by_function` as maps | Both are JSON arrays of objects, and an index by name reads nothing |
| Never assign the rank before the sort | The ordinal describes the ordering, and assigning it first makes it describe the input order |
| Never invent an implementation file for an unlocated handler | A guessed file inherits another function's fix history |

## Design notes

The score is a weighted sum of three normalised components.

```
rank_score = 0.50 * depth + 0.30 * cve + 0.20 * size
```

| Component | Measurement | Normalisation |
|---|---|---|
| `depth` | Allocations an unprivileged process makes before the owning object exists, from `rm-chains.json` | `(max - length) / (max - 1)`, and 0 for a command with no chain |
| `cve` | Driver releases that changed the handler's function, or the file holding it | `log2(releases + 1) / log2(max + 1)`, with a function-level match scaled by 1.5 |
| `size` | Bytes of attacker-controlled parameter struct, from `ctrl-param-sizes.json` | `log2(bytes + 1) / log2(max + 1)` |

The weights are a judgement no measurement settles, and no campaign has run to
tune them against. All three components are written out beside the score, so a
consumer that disagrees re-sorts without re-running the scan.

The definition scan gives the CVE component a non-zero value. Control handlers
are declared in the NVOC generated tables the inventory reads and defined
elsewhere under a suffix: `subdeviceCtrlCmdGpuGetInfoV2` is defined as
`subdeviceCtrlCmdGpuGetInfoV2_IMPL`. The hot-spot file names implementation
files, so a join on the inventory's own `source` field matches nothing.

Four suffixes are accepted. `_IMPL` is the sole implementation wherever there
is no HAL split. Where there is one, the NVOC table dispatches to a per-variant
symbol instead: `_KERNEL` and `_PHYSICAL` divide the kernel-side and GSP-side
halves, and `_VF` is the SR-IOV guest variant. All four are hand-written code
with their own release history, which is the only property the CVE join needs.

| Measure | Count |
|---|---|
| Source files scanned under `src/` | 1340 |
| Handler definitions found | 3191, being `IMPL` 3007, `KERNEL` 102, `VF` 81 and `PHYSICAL` 1 |
| Handlers resolved to an implementation file | 518 of 531 |
| Of those, in a file the hot spots name | 245 |
| Matching a hot-spot function record | 11 |

The 13 that resolve to nothing have no hand-written definition anywhere in the
tree. Each dispatches to an NVOC generated inline under `src/nvidia/generated/`:
`kchannelCtrlGetTpcPartitionMode_a094e1` at `g_kernel_channel_nvoc.h:1315`
forwards to `kgrctxCtrlHandle`. A null `impl_file` is the correct reading for
them, `impl_state` says so, and their `cve_file_releases` of 0 is not a scan
failure.

The reordering against the ladder is substantial and it moves nothing in the
shipping invocation. With no `--max-control` cap the ordering decides the order
of the emitted blocks and nothing else, so `nvidia_ctrl.txt` and
`nvidia_structs.txt` are permutations of the pre-change files with identical
line multisets. Two consumers read the order: `--max-control`, and the describe
phase's work order.

`impl_file` and `impl_line` are provenance for the inventory and they sit on
the rank record. Merging them into `rm-control-inventory.json` belongs with
`ctrl_surface.py`, which is the module that writes that file.

## Stated limits

| Limit | Consequence |
|---|---|
| Regenerating `cve-hotspots.json` needs the network | The file is committed, at 4.4 MB, so a clean checkout scores the CVE component without rebuilding it. Rebuilding it after a driver bump goes through `cve_patch_map.py`, which reads the PSIRT bulletins over the network |
| Nothing in CI runs `rank` | The artefact goes stale against a driver bump, and the describe phase's extractor block is the only thing that reruns it. `regression_check.py derived` reports the drift and does not repair it |
| The breadth-first graph depth and the chain length are different numbers | `rm-object-graph.json` records depth over every edge, and `rm-chains.json` records the length of a walk an unprivileged process can make. They would disagree wherever the shallowest parent is privileged. On this release they agree on all 514 chained commands |
| The weighting is untuned | No campaign result has been measured against it |

## See also

- [ctrl_surface.py](/gspwn/architecture/components/ctrl-surface/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
- [syzlang_gen.py](/gspwn/architecture/components/syzlang-gen/)
- [cve_patch_map.py](/gspwn/architecture/components/cve-patch-map/)
- [RM control surface](/gspwn/knowledgebase/rm-control-surface/)
