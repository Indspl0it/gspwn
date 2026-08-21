---
title: ioctl_inventory.py
description: The in-scope ioctl surface read out of the driver source, the two numbering schemes it keeps apart, and the compiled sizes behind every request number.
---

Derives the dispatched ioctl surface of the three in-scope device nodes from an
open-gpu-kernel-modules checkout, and generates `tools/ioctl_map.json` from it.
The `describe` phase needs one command per syzlang description; the `seeds`
phase needs the 32-bit request number `strace` prints for each. Both live in the
driver source and both move when the driver branch moves.

The module runs off the source tree and a sizes file. Producing the sizes file
needs a C compiler once; every later run reads it back.

## Responsibility

The module owns the parse of the command numbers, the three argument-validation
tables, and the dispatch switches, plus the request-number arithmetic derived
from them. It writes only the JSON files it is given.

| Invariant | Enforced by |
|---|---|
| A request number is never published without a measured size | `size_source` is `measured`, `unresolved` or `no_parameter_struct`, and `requests` stays empty unless a size resolved |
| The two numbering schemes stay apart | RM commands go through `rm_request()`; UVM commands take the bare command number, and the Linux `UVM_IOCTL_BASE(i) -> i` definition is asserted present |
| A banner comment does not swallow a file | `strip_c_noise` is a left-to-right scanner, so `//*****` is a line comment and never an open block comment |
| A nested switch does not steal its parent's case body | `case_blocks` tracks brace depth and reports an assertion inside a nested block separately |
| Line numbers survive comment stripping | Every removed character becomes a space |
| A UVM command is paired with the struct the driver compiles against | `check_uvm_storage` re-derives the `BUILD_BUG_ON` in each route macro against the measured size |
| A declared but undispatched escape is visible | `find_dead_escapes` reports every command number no switch names |
| An escape reached only through an `if` is still dispatched | `parse_rm_dispatch` collects `arg_cmd ==` comparisons alongside case labels |
| Two commands never share one map key | `build_map` raises on a collision, so a later command cannot overwrite an earlier one |
| A checkout missing a parsed file fails before it emits | `REQUIRED_FILES` is checked in full before any parse runs |

## Interface

`--src` selects the checkout. `--out` writes the inventory JSON, `--emit-map`
writes the request-number map, and `--emit-probe DIR` writes the size probes and
exits. `--sizes` names the measured-size JSON; without it every command is
reported unresolved and no request number is emitted. `-v` logs each parsing
step.

| Function | Returns |
|---|---|
| `build_inventory(src, sizes)` | The whole inventory as a dict: encoding, one entry per device node, dead escapes, counts |
| `build_map(inventory)` | The request-number map and the list of omitted commands |
| `rm_request(magic, nr, size)` | The Linux ioctl request number, matching the decoder in `trace2seed.py` |
| `strip_c_noise(text)` | The source with comments and literals blanked, line numbering intact |
| `case_blocks(text)` | Per case label: the line, the body at its own brace depth, and the full body |
| `parse_escape_numbers(src)` | The magic, the base, every `NV_ESC_*` number, and where each is defined |
| `parse_validation_tables(src)` | Command to parameter struct, with the argument-array flag |
| `parse_uvm_numbers(src)` | Every `UVM_*` command number across the three UVM headers |
| `emit_probe(src, out_dir, rm, uvm)` | The written probe paths |

Exported constants: `DIRECTION_BITS`, `DIRECTION_SOURCE`, `IOC_SIZE_MAX`,
`XFER_ESCAPE`, `MAP_COMMENTS`, `REQUIRED_FILES`.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing at run time. `selftest.py` exercises `strip_c_noise`, `case_blocks`, `rm_request` and `build_map`. The `describe` and `seeds` phases invoke it as a command |
| This module imports | Nothing in `tools/` |
| Consumes its output | `trace2seed.py` reads `tools/ioctl_map.json` |

## Failure modes

| Condition | Behaviour | Exit |
|---|---|---|
| `--src` is not a directory, or a required source file is absent | Message naming the count and every missing path | 2 |
| None of `--out`, `--emit-map`, `--emit-probe` given | Message naming the three flags | 2 |
| `NV_IOCTL_MAGIC` or `NV_IOCTL_BASE` absent from the header | Message stating the header changed shape and the request numbers would be wrong | 1 |
| The dual-size check for `NV_ESC_RM_ALLOC` is absent | Message stating one request number for it would miss half the traffic | 1 |
| The Linux `UVM_IOCTL_BASE(i) -> i` definition is absent | Message stating UVM request numbers rest on that identity | 1 |
| The `uvm_enable_builtin_tests` gate is absent | Message stating the test commands would otherwise be recorded as reachable | 1 |
| A measured UVM size contradicts its route macro's `BUILD_BUG_ON` | Message naming every mismatched command and its struct | 1 |
| A command is dispatched with no header defining its number | Message naming the command and the dispatch site | 1 |
| Two commands resolve to the same request number | Message naming both and the shared key | 1 |
| `--sizes` names a file that is absent, is not JSON, or holds a non-positive size | Message naming the file and the offending entry | 1 |
| A parameter struct has no measured size | Recorded `unresolved`, its request number omitted, and the struct listed in `unresolved_param_structs` | 0 |
| `--sizes` omitted entirely | Warning that every command will read unresolved | 0 |
| The output directory does not exist | Created, and the creation is logged | 0 |

## Concurrency and durability

The module reads source files and writes at most two JSON files per invocation,
and takes no lock. It holds no state between runs and is safe to re-run against
an unchanged checkout, which yields byte-identical output.

Both writes go through a temp file in the target directory and `os.replace`, so
an interrupted run leaves the previous file intact. `tools/ioctl_map.json` is
committed data the `seeds` phase reads on a machine where regenerating it needs
a compiler, and a truncated map there is worse than a stale one. Two concurrent
invocations writing the same path race for it, and the phases invoke it
sequentially.

The generated probes write outside this module. `measure_sizes.sh` compiles and
runs them and writes `sizes.json` beside itself, and it is the only part of the
pipeline that needs `gcc`.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never guess a struct size to fill a map row | The size is 16 bits of the request number. A wrong one produces a key `strace` never shows, so the command reads as unmapped, and a key that collides with a real request converts one ioctl into a description for another |
| Never emit a fixed request key for an argument-array escape | `NV_ESC_CARD_INFO` and `NV_ESC_ATTACH_GPUS_TO_FD` are validated as any nonzero multiple of the element size, so the element count lands in the request number. One key names one element count. The map carries the one-element form and the inventory carries `max_direct_elements`; covering the rest needs `trace2seed.py` to decompose the request into `(nr, size)` |
| Never assume UVM follows the RM numbering | `UVM_IOCTL_BASE(i)` expands to `i` on Linux and both UVM switches read the raw `cmd`. There is no magic, no size field and no direction, and `_IOC_SIZE` is never read on that path. Encoding a UVM command the RM way yields a number no switch matches |
| Never treat `NV_ESC_IOCTL_XFER_CMD` as one command among the rest | It is a second entry path to every escape: `nv.c` substitutes the command, the size and the buffer pointer from its payload, then re-validates. Every call through it carries one request number, so a trace cannot say which escape it was, and a description for it models a struct holding a pointer to a second buffer |
| Never read the argument size from `_IOC_SIZE` for a UVM command | The route macro copies `sizeof(params)` regardless. A description sized from the request number describes a field the driver does not consult |
| Never take a `case` label as a dispatch site without checking its brace depth | `uvm.c` switches on unrelated `UVM_*` enumerators, and `NV_ESC_RM_ALLOC` contains a nested switch. A line-only scan invents commands and misattributes privilege checks |
| Never strip block comments with a pattern that runs before line comments | `escape.c` opens with a `//*****` banner whose second and third characters are a valid `/*`. A block-comment pattern consumes the file to the next `*/`, and all 21 escape dispatch sites in it disappear with no error |
| Never publish a request number for a command declared but never dispatched | Three `NV_ESC_RM_*` names exist only in `nv_escape.h`. Calls to them are rejected at the first validation check, so a description spends executions on a path that ends there |
| Never record the gated test commands as reachable | `uvm_test_ioctl` refuses all 104 unless the module carries `uvm_enable_builtin_tests=1`, and their numbers are small integers an unrelated ioctl could occupy |

## Design notes

Three numbers describe the RM surface and each comes from a different place.
The command number is in a header, the parameter struct is in one of three
validation tables, and the size is `sizeof()` on that struct. Only the third
resists reading, which is why `--emit-probe` exists: the probe is generated from
the parsed struct list, so it cannot drift from the table it was derived from.

The direction bits are `_IOC_READ|_IOC_WRITE`. The kernel never checks them,
since `nv_validate_ioctls` forwards only `_IOC_NR` and `_IOC_SIZE`, but the
value is stated by `__NV_IOWR` in `nv.h`, which expands to
`_IOWR(NV_IOCTL_MAGIC, nr, type)`. No open-module code calls that macro, so it
describes a closed component's behaviour.

A ceiling on the direct path sits above the architectural one and cannot be
resolved from the open tree. `__NV_IOWR_ASSERT` refuses any type larger than
`NV_PLATFORM_MAX_IOCTL_SIZE`, which is defined nowhere in the checkout. 16383 is
what the 14-bit `_IOC_SIZE` field allows, and the size at which the user-mode
driver switches to the transfer path may be lower.

The transfer path adds one byte over the direct path, so the description of it
as a way past the size ceiling holds architecturally and buys almost nothing
against this command set. No dispatched escape has a struct above 16383 bytes.
What it does change is the shape of the call: the buffer pointer comes out of
the payload, the command widens from 8 bits to 32, and every escape shares one
request number.

Validation masks the command with `0xFF` and dispatch does not, so a command
with high bits set validates through the RM tables and then matches no case in
any of the three switches. The result is an error return, reached after the
argument has been allocated and copied. Nothing found here validates as one
escape and dispatches to another.

One cross-check covers the whole UVM half. The STACK route macro asserts
`sizeof(params) <= UVM_MAX_IOCTL_PARAM_STACK_SIZE` and the ALLOC macro asserts
the opposite, both as `BUILD_BUG_ON`. Re-deriving that from the measured sizes
turns a silent mispairing into a raised error, because a command paired with the
wrong struct almost always lands on the wrong side of 288.

## See also

- [trace2seed.py](/gspwn/architecture/components/trace2seed/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
- [UVM subsystem](/gspwn/knowledgebase/uvm/)
- [RM control surface](/gspwn/knowledgebase/rm-control-surface/)
- [Threat model](/gspwn/architecture/threat-model/)
- [Seeds from traces](/gspwn/guides/generating-seeds-from-traces/)
