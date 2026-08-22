---
title: syzlang_gen.py
description: The first-cut syzlang description set generated from the three measured inventories, and the size check that keeps every derived struct layout honest.
---

Generates a syzlang description set for the NVIDIA driver ioctl surface from
the three measured inventories. `ioctl_inventory.py` supplies the dispatched
escapes and their request numbers, `ctrl_surface.py` the RM control command
space with its privilege classification, and `object_graph.py` the allocation
DAG. Without this module the `describe` phase transcribes all three by hand on
a live SUT, and spends the time it has on the target writing down numbers that
are already extracted.

Struct field layout appears in none of the inventories, which carry struct
names and sizes only. This module parses layout out of the driver headers and
checks every derived layout against a `sizeof` measured by compiling the same
header for x86-64.

The module runs entirely off the source tree and the committed inventories. It
reaches no device, opens no socket, and needs no GPU.

## Responsibility

The module owns the header parse, the layout derivation and the emitted
description set. It writes only the files under its output directory.

| Invariant | Enforced by |
|---|---|
| A derived struct layout never ships unchecked | Every struct a description names is compared against a measured `sizeof` |
| A layout that disagrees with its measurement is still correctly sized | The struct falls back to an opaque array at the measured size |
| A disagreement is visible | `generation.json` records the struct, the derived total and the measured total, and `--strict` exits 2 |
| Nothing is guessed to complete a description | A parameter type with neither a derived layout nor a measured size is skipped and counted |
| The emitted size does not depend on syzkaller's alignment rules | Padding is explicit and every struct carries `[packed]` |
| The client allocation is always emitted | The three `RS_ROOT_OBJECT` classes name no `RS_FLAGS_ALLOC_*` flag and are emitted anyway, with a log line naming them |
| The control multiplexer is a constant set | One variant per command, with `cmd` pinned to `const[<method id>, int32]` |
| No emitted call leaves its leaf selector free | `require_pinned()` reads the rendered struct text and exits on a `cmd` or `hClass` that is not `const[...]`, over 768 variants |
| The wrapper escape reaches no command the direct route cannot | `emit_xfer` declines both multiplexers and emits one typed variant per remaining inner escape |
| A description set is reproducible from a clean checkout | `--ctrl-sizes` and `--ctrl-rank` both default to a committed artefact, and `generation.json` records the path, the digest and the entry count of each |
| A parent pin is never a chip-gated guess | `parent_is_narrow()` expands a class to one variant per legal parent only when no member of its parent set is chip-exclusive |
| A UVM request number carries no `_IOC` fields | UVM commands are read from the inventory's `bare_command_number` nodes and emitted as bare values |
| Out-of-scope device nodes stay absent | Only `/dev/nvidiactl`, `/dev/nvidiaN`, `/dev/nvidia-uvm` and `/dev/nvidia-uvm-tools` get an `openat$` variant |

## Interface

| Subcommand | Output |
|---|---|
| `emit [--out-dir DIR]` | `nvidia.txt`, `nvidia_ctrl.txt`, `nvidia_uvm.txt`, `nvidia_structs.txt`, the `_IOWR` header, and `generation.json` |
| `emit-probe --probe-dir DIR` | One C translation unit per SDK header group, plus a runner that compiles them for x86-64 and writes `sizes.json` |
| `verify` | The size-match table and nothing else |
| `summary` | Counts per category, and control coverage by SDK prefix |

`--src` selects the checkout. `--inventory`, `--control` and `--graph` select
the three inventory files. `--strict` turns any size disagreement into exit 2.
`--max-control` caps the control family, `--control-order` picks between chain
depth and table order, `--uvm-test` adds the 104 test commands, and
`--all-classes` adds the privileged allocation classes.

Two inputs carry a committed default, so `emit --commit <sha>` alone reproduces
the shipped set.

| Flag | Default | Opt-out |
|---|---|---|
| `--ctrl-sizes PATH` | `surface/ctrl-param-sizes.json`, 739 entries. May be given more than once | `--no-ctrl-sizes` generates without measured control sizes, with a warning |
| `--ctrl-rank PATH` | `surface/rm-control-rank.json` when present, from `ctrl_rank.py rank` | `--no-ctrl-rank` orders control commands on object-graph depth alone |

| Function | Returns |
|---|---|
| `scan_headers(src)` | A `TypeIndex` over every header under the include roots |
| `TypeIndex.layout(name)` | Flat field layout with offsets, explicit padding, total size and alignment |
| `TypeIndex.canonical_struct(name)` | The struct a typedef or macro alias resolves to |
| `TypeIndex.const(expr)` | The integer value of a macro expression, or `None` |
| `Emitter.ensure(name)` | The emitted struct name, or `None` when neither a layout nor a measured size exists |
| `class_numbers(index, wanted)` | External class name to class number, for the names the object graph carries |
| `base_param_type(index, name)` | Size and syzlang type when a parameter type is a base type |
| `escape_param_type(emitter, command)` | The emitted parameter struct for one escape, resolved once and read by the direct route and the XFER route alike |
| `emit_xfer(emitter, inventory)` | The `NV_ESC_IOCTL_XFER_CMD_*` family, one typed variant per in-scope inner escape |
| `require_pinned(emitter, variant, field, what)` | Nothing. Raises `SystemExit` unless the named field renders `const[...]` |
| `parent_resource(record, by_class, class_map)` | The syzlang resource for `hObjectParent` when a class has one legal parent |
| `parent_is_narrow(concrete)` | Whether a parent set names at most one chip-exclusive class |
| `parent_options(record, by_class)` | One `(parent class, resource)` option per legal parent for a narrow class, and one generic option otherwise |
| `resolve_ctrl_sizes(args)`, `resolve_ctrl_rank(args)` | The measured-size files to merge, and the ranking to order by |

## Callers

| Direction | Modules |
|---|---|
| Imports this module | `tools/selftest.py`, for the size-verification invariant. The `describe` phase invokes it as a command |
| This module imports | Nothing in `tools/`. It reads the three inventory JSON files and the driver headers |
| Consumes this module's output | `tools/surface_cov.py` measures `descriptions/` against the same inventories |

## Failure modes

| Condition | Behaviour | Exit |
|---|---|---|
| An inventory file is absent | Message naming the file and stating that it has to be regenerated | 1 |
| An inventory file has the wrong shape | Message naming the missing keys and the extractor that writes them | 1 |
| An include root is absent under `--src` | Message naming the path and the flag to override it | 1 |
| `NV_ESC_RM_ALLOC` or `NV_ESC_RM_CONTROL` is absent from the escape inventory | Message stating that the allocation chain or the multiplexer cannot be modelled | 1 |
| `--ctrl-sizes` names a file that does not exist | Message naming `emit-probe` and its runner | 1 |
| The committed measured-size file is absent and no flag was passed | Message naming `emit-probe`, `--ctrl-sizes` and `--no-ctrl-sizes` | 1 |
| `--ctrl-sizes` and `--no-ctrl-sizes` are both passed | Message stating that the two contradict each other | 1 |
| `--ctrl-rank` names a file that does not exist | Message naming `ctrl_rank.py rank` and `--no-ctrl-rank` | 1 |
| The committed ranking is absent and no flag was passed | Warning, and control commands order on object-graph depth alone | 0 |
| An emitted call renders `cmd` or `hClass` as anything but `const[...]` | `require_pinned()` names the variant, the field and the override that has to name it | 1 |
| A per-parent variant name collides with a class-level name | Message naming both, so one description never overwrites another | 1 |
| A size in the probe output is not a non-negative integer | Message naming the struct, the file and the value found | 1 |
| A derived layout disagrees with its measured size | Recorded in `generation.json`, printed, and emitted opaque at the measured size | 0, or 2 under `--strict` |
| A parameter type resolves to no layout and no measured size | Counted in `generation.json`, and the description is skipped | 0 |
| A class number evaluates outside the 16-bit class space | Rejected, logged, and no variant is emitted for that class | 0 |
| A struct definition carries a bitfield | The struct is rejected by the member parser and falls back to its measured size | 0 |

## Concurrency and durability

Each invocation reads three JSON files and the header tree, then writes six
files. Every output goes to a temp file in its target directory and moves into
place with `os.replace`, so a crash mid-write leaves the previous file intact
and never a truncated one. The module takes no lock and holds no state between
runs. Two concurrent invocations sharing an output directory race for it, and
the phase invokes it once.

`emit-probe` deletes the probe units an earlier run left behind, because the
runner globs `probe_*.c` and a unit from a different grouping would still
compile and contribute sizes for structs the current set no longer names.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never emit a struct whose derived layout disagrees with its measured `sizeof` | The ioctl request number encodes the size the driver expects. A wrong layout compiles, runs, and lands on a different field or on none |
| Never model `NV_ESC_RM_CONTROL` as one escape carrying an opaque buffer | `agents/describe.md` step 4b. One opaque ioctl gives the fuzzer no command number to mutate and no parameter structure, and it puts the command number out of reach of any corpus-text measurement |
| Never emit a description for `nvidia-drm`, `nvidia-modeset` or `/dev/dri/*` | Those nodes sit outside the threat model, and a seed naming them fails the syzkaller parse gate |
| Never classify a record carrying no `RS_FLAGS_ALLOC_*` flag with the privileged ones | The three such records are the root client classes. Filtering them drops the client allocation and every description that consumes its handle |
| Never widen a variant's file descriptor argument past its node restriction | `NV_ESC_RM_CONTROL` carries `NV_CTL_DEVICE_ONLY`, so all 531 control variants take `fd_nvidiactl` |
| Never leave padding to syzkaller | Whether its alignment rules agree with the compiler's is an assumption no compile gate checks |
| Never report a count against 1372 exported control methods | 841 of them are privileged, kernel-only or internal, and the reachable denominator is 531 |

## Design notes

One predicate decides the whole control family:
`reachability == "non_privileged" and not handler_compiled_out`. It selects 531
of the 1372 exported methods. `reachability` partitions the export table into
767 non-privileged, 250 privileged, 241 internal and 114 kernel-only, and the
second clause removes the 236 non-privileged methods whose local handler is
compiled out and whose parameter buffer crosses the RPC queue to GSP firmware.

Each control command is named as its own variant,
`ioctl$NV_ESC_RM_CONTROL_<handler>`. A single `NV_ESC_RM_CONTROL` description
with a command field would put the command number inside a mutable parameter
buffer and out of the corpus text. Naming it in the description makes corpus
text self-describing, so [`surface_cov.py`](/gspwn/architecture/components/surface-cov/)
measures which commands a corpus reaches with no KCOV, no syz-manager and no
GPU. Variants are named after the handler and not the command number, so the 5
duplicate method ids in the export table still produce distinct descriptions.

`surface_cov.py` measures the generated baseline at 764 of 764 targets
modelled, 100.0%. The denominator decomposes as 32 escapes, 39 UVM commands, 7
UVM tools commands, 531 control commands and 155 allocation classes. The set
declares 845 `ioctl$` variants, split 268 in `nvidia.txt`, 531 in
`nvidia_ctrl.txt` and 46 in `nvidia_uvm.txt`, plus four `openat$` descriptions.

81 of the 845 sit outside the denominator, and every one of them is an
additional calling form or an additional route to a target the denominator
already counts.

| Variants outside the denominator | Count | Calling form |
|---|---|---|
| `NV_ESC_RM_ALLOC_<class>_UNDER_<parent>` | 49 | One allocation variant per legal parent, for the 32 classes whose parent set is not chip-gated |
| `NV_ESC_IOCTL_XFER_CMD_<escape>` | 31 | The typed wrapper route to each inner escape |
| `NV_ESC_RM_ALLOC_NVOS21` | 1 | The NVOS21 calling form of `NV01_ROOT` |

`NV_ESC_RM_ALLOC` dispatches on two parameter sizes,
`sizeof(NVOS64_PARAMETERS)` at 48 and `sizeof(NVOS21_PARAMETERS)` at 32, so one
class takes two parameter structs where the inventories count one target.

595 of the 1540 emitted structs are named directly by a description and were
measured by the probe. All 595 derived layouts match their measured `sizeof`,
so `generation.json` records a size-mismatch count of zero. The remaining 945
structs are nested inside those, or are synthetic names for an anonymous inner
struct or union. A nested struct has no `sizeof` of its own to check, and a
wrong nested layout moves its parent's total, which the check does see.

The check is verified to fail when the layout is wrong. Widening `NvHandle`
from 4 bytes to 8 in the base type table turns 105 of the 595 into reported
mismatches, each falling back to an opaque array at the measured size.
`tools/selftest.py` carries the same invariant as five scenario tests against
`Emitter.ensure`.

Nothing in the set has been through `syz-compile`. This repository carries no
syzkaller tree, so 845 variants and 1540 structs have never met the syzlang
parser, and compiling them is the `describe` phase's first SUT gate. Three
spellings the set depends on are unverified against the compiler:
`array[const[0, int8], N]` for explicit padding, `ptr64[in, T]` for the `NvP64`
parameter pointers, and a resource produced by an inout struct field. Every
allocation depends on the third of those, because syzkaller has to treat
`hObjectNew` as an output. A smoke run reporting uniform early-out across a
device node is the symptom of it doing otherwise.

Request numbers are literal in the description files. `syz-extract` produces
the `.const` file that would let them be named constants, and its exact format
could not be checked against source here. `nvidia_gspwn.h` carries the same
numbers as `_IOWR` macros for `syz-extract` to consume on the SUT. That header
was compiled and its macros evaluated as an independent check on the encoding,
and `NV_ESC_RM_ALLOC`, `NV_ESC_RM_CONTROL` and `UVM_REGISTER_GPU` expand to the
numbers the inventory computed.

Four header constructs defeat a straightforward member parser, and each
accounted for parameter types the first generation could not lay out. `nvos.h`
places `#define` lines between struct members, which makes a naive splitter
read a macro and the field after it as one declaration. 25 control parameter
structs carry an `enum` typed field, and `ctrl2080gr.h` uses an enumerator as
an array bound. 41 control parameter types are typedef aliases of another
command's struct. 17 allocation parameter types are macro aliases, and
`nv-ioctl-numa.h` spells alignment `__aligned(8)` where the rest of the tree
uses `NV_DECLARE_ALIGNED`.

## The parent rule

A syzlang field carries one type, and 98 of the 155 allocatable classes name
more than one legal parent. The emitter splits them on whether their parent set
is chip-gated.

| Parent set | Classes | Emission | `hObjectParent` |
|---|---|---|---|
| One legal parent | 49 | One variant | That parent's `nvh_*` resource |
| Narrow: several parents, at most one chip-exclusive | 32 | One variant per legal parent, 81 in total | Each variant pins its own parent's resource |
| Wide: several parents drawn from the chip-gated GPFIFO channel family | 66 | One variant | `nv_handle` |
| `RS_ROOT_OBJECT` | 3 | One variant | `const[0, int32]`, parented by the file descriptor |
| `RS_ANY_PARENT` | 5 | One variant | `nv_handle` |

`parent_is_narrow()` tests for a chip-exclusive class by name, through
`CHIP_EXCLUSIVE_PARENT_RES`. Two families are matched: `CHANNEL_GPFIFO`, and
the chip-numbered display classes under `^NV[0-9A-F]{3}0_DISPLAY$`, which
leaves the unnumbered `NV04_DISPLAY_COMMON`, `NVC372_DISPLAY_SW` and
`NVA083_GRID_DISPLAYLESS` out of the family. A wide class expanded per parent
produces about eleven variants, and a variant whose parent the installed part
does not carry stays in the choice table and in the corpus for the whole
campaign.

The display family is gated: over the 34 per-chip class descriptor lists in
`src/nvidia/generated/g_gpu_class_list.c`, at most 2 of its 8 members appear
together on one part, against parent sets naming all 8.

The channel family is treated as exclusive on a stricter basis than that file
supports. GB202 lists all 8 of the `*_CHANNEL_GPFIFO` classes that appear
anywhere, and all 31 lists carrying any channel class carry
`GF100_CHANNEL_GPFIFO`, so the driver keeps older channel classes allocatable
on newer parts. Treating the family as exclusive refuses an expansion the
driver would permit, which is the conservative direction: it holds the alloc
variant count at 204 over 155 classes and produces no variant naming a parent
the part refuses. Widening it is a change to the emitted set and not a
correction, so the classification is left alone deliberately.

`nvidia.txt` declares `resource nv_handle[int32]` and every `nvh_*` resource
derives from it. A loose pin is expected to correct itself, because
`nv_handle` draws from a pool that includes the correct handle and coverage
feedback selects it. That is syzkaller run-time behaviour and it is unverified:
no syzkaller tree exists in this repository and no description set has been
executed.

The split needs no tuning parameter, because two independent readings of the
data agree on where the line falls. Over the 155 allocatable classes the
parent-set sizes are 1, 2, 3, 11, 12 and 13, so no threshold between 4 and 10
changes the answer, and all 66 wide classes carry all 11 GPFIFO channel classes
while no narrow class carries any. No record has an empty parent list. Over all
222 `RS_ENTRY` records there is also a size of 8, on the 38 privileged records
the split never sees.

The class-level name `ioctl$NV_ESC_RM_ALLOC_<class>` stays on exactly one
variant per class, carrying the cheapest legal parent, measured as the
shallowest in the object graph and then by name. The rest are named
`ioctl$NV_ESC_RM_ALLOC_<class>_UNDER_<parent>`. No external class in
`resource_list.h` contains `_UNDER_`, and the emitter exits on a collision.
One class-level name per class holds the alloc denominator at 155.
`surface_cov.load_targets` keys that family on `NV_ESC_RM_ALLOC_<CLASS>` built
from the object graph, and `scan_variants` joins on the whole name.

`generation.json.counts` carries `alloc_classes` at 155 and
`alloc_parent_variants` at 49 beside `alloc_variants` at 204, so the invariant
the denominator rests on is machine-readable.

`hObject` on a control variant is typed from the command's own SDK class id.
`control_object_resource` joins that number against the external classes of
`rm-object-graph.json` that carry a class number in the headers, and falls back
to `nv_handle` when the number names none. 12 of the 531 take the fallback, and
`generation.json` carries the count on the `object_resource` field of each
control record.

| Owning class | Commands | SDK class id | Owning class has an `RS_ENTRY` row |
|---|---|---|---|
| `ProfilerBase` | 9 | `0xb0cc` | no |
| `KernelChannel` | 1 | `0x506f` | yes |
| `NvDispApi` | 1 | `0xc370` | yes |
| `MmuFaultBuffer` | 1 | `0xb069` | yes |

The absence of an `RS_ENTRY` row is a different property and does not decide
this. The 6 `Memory` commands whose owning class also has no row carry class id
`0x0041`, which does resolve, so they take `nvh_nv01_root_client` and are not
among the 12. The 15 commands whose owning class has no row are
[recorded separately](/gspwn/reference/surface/control-commands/) as
`ProfilerBase` 9 and `Memory` 6.

Whether the fallback reaches real work is settled by coverage on an
instrumented run, and no such run has been made.

## The XFER wrapper family

`NV_ESC_IOCTL_XFER_CMD` is a second entry path to every escape. `nv.c:2509`
assigns `arg_cmd` from the payload and re-enters the same dispatch switch, so a
description modelling `cmd` and `ptr` as unconstrained integers reaches every
escape and every control command in the driver through one field, including the
236 GSP-routed commands and the 250 privileged ones. In that model `ptr` is a
raw integer with no pointer type, so the address it carries is unrelated to any
mapping syzkaller made. The expected consequence, that `copy_from_user` returns
`-EFAULT` on almost every attempt, is syzkaller run-time behaviour and is
unverified here: no program has been executed and no driver was involved.

`emit_xfer` replaces that with one typed variant per in-scope inner escape.

```
ioctl$NV_ESC_IOCTL_XFER_CMD_RM_FREE(fd fd_nvidiactl, cmd const[0xc01046d3], arg ptr[inout, nv_xfer_rm_free])

nv_xfer_rm_free {
	cmd 	const[41, int32]
	size	const[16, int32]
	ptr 	ptr64[inout, NVOS00_PARAMETERS]
} [packed]
```

| Field | Value | Driver constraint |
|---|---|---|
| Outer `cmd` | The wrapper's own request number | From the escape inventory |
| `fd` | The inner escape's device node | The node restriction is checked in the case body, after the unwrap. 20 variants take `fd_nvidiactl`, 6 `fd_nvidia`, 6 `fd_nv` |
| Inner `cmd` | `const[<bare escape number>, int32]` | `nv.c:2412` masks the dispatch key to 8 bits |
| `size` | `const[<measured sizeof>, int32]` | `nv.c:2439` requires exact equality for a non-array escape |
| `ptr` | `ptr64[inout, T]` | The inner `copy_from_user` at `nv.c:2535` reads a mapped address |

`T` is resolved once by `escape_param_type` and read by both routes, so a struct
rename cannot make the direct description and the wrapper disagree.

The escape inventory records 34 dispatched escapes. 31 take a suffixed variant,
`NV_ESC_IOCTL_XFER_CMD` keeps its own bare name because the driver admits
escape 211 as an inner command, and `NV_ESC_RM_CONTROL` and `NV_ESC_RM_ALLOC`
are declined. A wrapper naming either multiplexer selects nothing, because the
target sits in `NVOS54_PARAMETERS.cmd` and `NVOS64_PARAMETERS.hClass` and the
field would have to be left free. One wrapper per leaf, 531 plus 155, reaches
no driver code the 32 do not already reach. An XFER variant adds only the
unwrap at `nv.c:2499` through `:2525`, which is identical for every inner
command.

A generator check declines any inner escape whose argument exceeds the 16384
bytes `nv.c:2513` accepts. No escape in this release reaches it, the largest
being `NV_ESC_RM_LOCKLESS_DIAGNOSTIC` at 15412 bytes.

`size` renders as a constant on all 32 variants, which fixes the two
argument-array escapes at one element. `NV_ESC_CARD_INFO` accepts up to 227
elements on the direct path and `NV_ESC_ATTACH_GPUS_TO_FD` up to 4095, and the
XFER route is bounded by 16384 bytes and not by the 14-bit `_IOC_SIZE` field, so
it can carry more elements than the direct route can encode. Expressing that
needs a construct absent from the existing set, and this repository holds no
syzkaller tree to check one against.

## See also

- [ioctl_inventory.py](/gspwn/architecture/components/ioctl-inventory/)
- [ctrl_surface.py](/gspwn/architecture/components/ctrl-surface/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
- [surface_cov.py](/gspwn/architecture/components/surface-cov/)
- [Attack surface](/gspwn/architecture/attack-surface/)
- [RM control surface](/gspwn/knowledgebase/rm-control-surface/)
