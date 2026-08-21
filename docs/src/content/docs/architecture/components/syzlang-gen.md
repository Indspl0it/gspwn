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
the three inventory files. `--ctrl-sizes` supplies the probe's measured sizes
and may be given more than once. `--strict` turns any size disagreement into
exit 2. `--max-control` caps the control family, `--control-order` picks
between chain depth and table order, `--uvm-test` adds the 104 test commands,
and `--all-classes` adds the privileged allocation classes.

| Function | Returns |
|---|---|
| `scan_headers(src)` | A `TypeIndex` over every header under the include roots |
| `TypeIndex.layout(name)` | Flat field layout with offsets, explicit padding, total size and alignment |
| `TypeIndex.canonical_struct(name)` | The struct a typedef or macro alias resolves to |
| `TypeIndex.const(expr)` | The integer value of a macro expression, or `None` |
| `Emitter.ensure(name)` | The emitted struct name, or `None` when neither a layout nor a measured size exists |
| `class_numbers(index, wanted)` | External class name to class number, for the names the object graph carries |
| `base_param_type(index, name)` | Size and syzlang type when a parameter type is a base type |

## Callers

| Direction | Modules |
|---|---|
| Imports this module | `tools/selftest.py`, for the size-verification invariant. The `describe` phase invokes it as a command |
| This module imports | Nothing in `tools/`. It reads the three inventory JSON files and the driver headers |
| Consumes this module's output | `tools/surface_cov.py` measures `artifacts/descriptions/` against the same inventories |

## Failure modes

| Condition | Behaviour | Exit |
|---|---|---|
| An inventory file is absent | Message naming the file and stating that it has to be regenerated | 1 |
| An inventory file has the wrong shape | Message naming the missing keys and the extractor that writes them | 1 |
| An include root is absent under `--src` | Message naming the path and the flag to override it | 1 |
| `NV_ESC_RM_ALLOC` or `NV_ESC_RM_CONTROL` is absent from the escape inventory | Message stating that the allocation chain or the multiplexer cannot be modelled | 1 |
| `--ctrl-sizes` names a file that does not exist | Message naming `emit-probe` and its runner | 1 |
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
declares 765 variants, split 188 in `nvidia.txt`, 531 in `nvidia_ctrl.txt` and
46 in `nvidia_uvm.txt`, plus four `openat$` descriptions. The one variant no
inventory names is `NV_ESC_RM_ALLOC_NVOS21`, the NVOS21 calling form of
`NV01_ROOT`. `NV_ESC_RM_ALLOC` dispatches on two parameter sizes,
`sizeof(NVOS64_PARAMETERS)` at 48 and `sizeof(NVOS21_PARAMETERS)` at 32, so one
class takes two parameter structs where the inventories count one target.

595 of the 1459 emitted structs are named directly by a description and were
measured by the probe. All 595 derived layouts match their measured `sizeof`,
so `generation.json` records a size-mismatch count of zero. The remaining 864
structs are nested inside those, or are synthetic names for an anonymous inner
struct or union. A nested struct has no `sizeof` of its own to check, and a
wrong nested layout moves its parent's total, which the check does see.

The check is verified to fail when the layout is wrong. Widening `NvHandle`
from 4 bytes to 8 in the base type table turns 105 of the 595 into reported
mismatches, each falling back to an opaque array at the measured size.
`tools/selftest.py` carries the same invariant as five scenario tests against
`Emitter.ensure`.

Nothing in the set has been through `syz-compile`. This repository carries no
syzkaller tree, so 765 variants and 1459 structs have never met the syzlang
parser, and compiling them is the `describe` phase's first SUT gate. Three
spellings the set depends on are unverified against the compiler:
`array[const[0, int8], N]` for explicit padding, `ptr64[in, T]` for the `NvP64`
parameter pointers, and a resource produced by an inout struct field. The last
one carries the whole chain. Every allocation depends on syzkaller treating
`hObjectNew` as an output, and a smoke run reporting uniform early-out across a
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

The emitted chain is looser than the class table in two places, both by
construction. 23 allocation classes have several legal parents, and a syzlang
field carries one type, so `hObjectParent` takes the generic `nv_handle` for
them. 12 control commands belong to a class with no `RS_ENTRY` record, so
`hObject` takes `nv_handle` as well. Both counts are in `generation.json`, and
coverage on an instrumented run is the only thing that settles whether either
reaches real work.

## See also

- [ioctl_inventory.py](/gspwn/architecture/components/ioctl-inventory/)
- [ctrl_surface.py](/gspwn/architecture/components/ctrl-surface/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
- [surface_cov.py](/gspwn/architecture/components/surface-cov/)
- [Attack surface](/gspwn/architecture/attack-surface/)
- [RM control surface](/gspwn/knowledgebase/rm-control-surface/)
