---
title: ioctl_inventory.py
description: The in-scope ioctl surface read out of the driver source, the two numbering schemes it keeps apart, and the compiled sizes behind every request number.
---

`ioctl_inventory.py` derives the dispatched ioctl surface of `/dev/nvidiactl`
and `/dev/nvidiaN`, `/dev/nvidia-uvm` and `/dev/nvidia-uvm-tools` from an
open-gpu-kernel-modules checkout, and generates `tools/ioctl_map.json` from it.
The other two in-scope nodes are enumerated elsewhere: `/dev/nvidia-modeset` by
`nvkms_inventory.py` and `/dev/dri` by `drm_inventory.py`.

The `describe` phase needs one command per syzlang description, and the `seeds`
phase needs the 32-bit request number `strace` prints for each. Both come from
the driver source, and both move when the driver branch moves.

The module runs off the source tree and a sizes file. Producing the sizes file
needs a C compiler once, and every later run reads it back.

## Invocation

```
python3 tools/ioctl_inventory.py --src artifacts/src/open-gpu-kernel-modules
```

| Option | Default | Effect |
|---|---|---|
| `--src` | required | The open-gpu-kernel-modules checkout |
| `--out` | `surface/ioctl-inventory.json` | Where the inventory JSON is written |
| `--sizes` | `surface/ioctl-sizes.json` | The measured struct sizes, from the runner `--emit-probe` writes |
| `--emit-probe DIR` | off | Writes the C size probes and their runner into `DIR`, prints where they went, and exits without writing an inventory |
| `--emit-map PATH` | off | Also writes the trace2seed request-number map, `tools/ioctl_map.json` |
| `--emit-entry-points PATH` | off | Also writes the `file_operations` entry-point census, `surface/entry-points.json`. Entry points are counted beside the command denominator and never inside it |
| `-v`, `--verbose` | off | Logs every parsing step |

| Exit code | Condition |
|---|---|
| 0 | The inventory was written, or `--emit-probe` wrote its probes |
| 1 | An `InventoryError`: a parse, a cross-check or a write failed |
| 2 | `--src` is not a directory, or a required source file is absent |

Re-measuring against a new driver release takes the full route.

```
python3 tools/ioctl_inventory.py --src artifacts/src/open-gpu-kernel-modules \
    --emit-probe tmp/surface/probe
bash tmp/surface/probe/measure_sizes.sh          # on a machine with gcc
cp tmp/surface/probe/sizes.json surface/ioctl-sizes.json
python3 tools/ioctl_inventory.py --src artifacts/src/open-gpu-kernel-modules
```

## Numbering schemes

Two schemes appear in the tree, and conflating them produces request numbers
the driver never sees.

| Scheme | Encoding | Read by the driver |
|---|---|---|
| RM escapes | The Linux `_IOC` encoding, `dir << 30 \| size << 16 \| type << 8 \| nr`, with `type` set to `NV_IOCTL_MAGIC` and `nr` the `NV_ESC_*` number. Direction is `_IOWR` from the `__NV_IOWR` macro in `nv.h` | `_IOC_NR` and `_IOC_SIZE` only. The direction is never checked |
| UVM | The bare command number. `uvm.c` switches on the raw `cmd` argument, and `UVM_IOCTL_BASE(i)` expands to `i` on Linux | The whole value, with no `_IOC` fields to read |

## Committed figures

`surface/ioctl-inventory.json` records these figures for driver 610.57.04.

| Figure | Value |
|---|---|
| RM escapes dispatched | 34 |
| UVM commands dispatched | 39 |
| UVM-tools commands dispatched | 7 |
| UVM-test commands dispatched, gated | 104 |
| Struct sizes measured | 183 |
| Struct sizes unresolved | 0 |
| Escapes declared and never dispatched | 3 |

The 34 RM escapes dispatch from three switches: 21 sites in `escape.c`, 10 in
`nv.c` and 3 in `osapi.c`.

## Responsibility

The module owns the parse of the command numbers, the three argument-validation
tables, and the dispatch switches, plus the request-number arithmetic derived
from them. It writes only the JSON files it is given.

| Invariant | Enforced by |
|---|---|
| A request number is never published without a measured size | `size_source` is `measured`, `unresolved` or `no_parameter_struct`, and `requests` stays empty unless a size resolved |
| The two numbering schemes stay apart | RM commands go through `rm_request()`, which builds the same request number `trace2seed.py` decodes; UVM commands take the bare command number, and the Linux `UVM_IOCTL_BASE(i) -> i` definition is asserted present |
| A banner comment does not swallow a file | `strip_c_noise` is a left-to-right scanner, so `//*****` is a line comment and never an open block comment |
| A nested switch does not steal its parent's case body | `case_blocks` tracks brace depth and reports an assertion inside a nested block separately |
| Line numbers survive comment stripping | Every removed character becomes a space |
| A UVM command is paired with the struct the driver compiles against | `check_uvm_storage` re-derives the `BUILD_BUG_ON` in each route macro against the measured size |
| A declared but undispatched escape is visible | `find_dead_escapes` reports every command number no switch names |
| An escape reached only through an `if` is still dispatched | `parse_rm_dispatch` collects `arg_cmd ==` comparisons alongside case labels |
| Two commands never share one map key | `build_map` raises on a collision, so a later command cannot overwrite an earlier one |
| A checkout missing a parsed file fails before it emits | `REQUIRED_FILES` is checked in full before any parse runs |

## Output

One invocation against a checkout reproduces the committed inventory byte for
byte.

Every request number is derived from a measured struct size, so a run without
`--sizes` writes an inventory carrying 0 sizes measured, 183 unresolved and no
request numbers at all. That file parses, validates and reads clean
downstream while every consumer reports a smaller surface with nothing naming
the cause. `refuse_size_regression` therefore fails the run before that file
is written.

## Callers

- No module imports this one. The `describe` and `seeds` phases invoke it as a
  command.
- This module imports no module in `tools/`.
- `trace2seed.py` consumes its output, reading `tools/ioctl_map.json`.

## Failure modes

Thirteen conditions are detected by name, and most stop the run before anything
is written.

| Condition | Behaviour |
|---|---|
| `--src` is not a directory, or a required source file is absent | Message naming the count and every missing path, and exit 2 |
| The run measured fewer struct sizes than the inventory it would replace | `refuse_size_regression` names both counts and the file, and nothing is written |
| `NV_IOCTL_MAGIC` or `NV_IOCTL_BASE` absent from the header | Message stating the header changed shape and the request numbers would be wrong |
| The dual-size check for `NV_ESC_RM_ALLOC` is absent | Message stating one request number for it would miss half the traffic |
| The Linux `UVM_IOCTL_BASE(i) -> i` definition is absent | Message stating UVM request numbers rest on that identity |
| The `uvm_enable_builtin_tests` gate is absent | Message stating the test commands would otherwise be recorded as reachable |
| A measured UVM size contradicts its route macro's `BUILD_BUG_ON` | Message naming every mismatched command and its struct |
| A command is dispatched with no header defining its number | Message naming the command and the dispatch site |
| Two commands resolve to the same request number | Message naming both and the shared key |
| `--sizes` names a file that is absent, is not JSON, or holds a non-positive size | Message naming the file and the offending entry |
| A parameter struct has no measured size | Recorded `unresolved`, its request number omitted, and the struct listed in `unresolved_param_structs` |
| `--sizes` names no file and the default is absent | Warning that every command will read unresolved, then the size-regression refusal above |
| The output directory does not exist | Created, and the creation is logged |

## Concurrency and durability

The module reads source files and writes at most two JSON files per invocation,
and takes no lock. It holds no state between runs and is safe to re-run against
an unchanged checkout, which yields byte-identical output.

Both writes go through a temporary file in the target directory and
`os.replace`, so an interrupted run leaves the previous file intact.
`tools/ioctl_map.json` is committed data the `seeds` phase reads on a machine
where regenerating it needs a compiler, and a truncated map there is worse than
a stale one. Two concurrent invocations writing the same path race for it, and
the phases invoke it sequentially.

The generated probes write outside this module. `measure_sizes.sh` compiles and
runs them and writes `sizes.json` beside itself, and it is the only part of the
pipeline that needs `gcc`.

## Prohibited behaviour

- Never guess a struct size to fill a map row. The size is 16 bits of the
  request number. A wrong one produces a key `strace` never shows, so the
  command reads as unmapped, and a key that collides with a real request
  converts one ioctl into a description for another.
- Never emit a fixed request key for an argument-array escape.
  `NV_ESC_CARD_INFO` and `NV_ESC_ATTACH_GPUS_TO_FD` are validated as any
  nonzero multiple of the element size, so the element count is encoded in the
  request number, and one key names one element count. The map carries the
  one-element form and the inventory carries `max_direct_elements`, which is
  227 for the first and 4095 for the second. Covering the rest needs
  `trace2seed.py` to decompose the request into `(nr, size)`.
- Never assume UVM follows the RM numbering. `UVM_IOCTL_BASE(i)` expands to
  `i` on Linux and both UVM switches read the raw `cmd`. That path carries no
  magic, no size field and no direction, and `_IOC_SIZE` is never read on it.
  Encoding a UVM command the RM way yields a number no switch matches.
- Never treat `NV_ESC_IOCTL_XFER_CMD` as one command among the rest. It is a
  second entry path to every escape. `nv.c` substitutes the command, the size
  and the buffer pointer from its payload, then re-validates. Every call
  through it carries one request number, so a trace cannot say which escape it
  was. `syzlang_gen.py emit_xfer` models the route as 31 typed variants, each
  pinning the inner escape number and typing the payload pointer as a pointer
  to that escape's own parameter struct. It declines the two multiplexers,
  whose leaves each already carry a direct variant.
- Never read the argument size from `_IOC_SIZE` for a UVM command. The route
  macro copies `sizeof(params)` regardless, and a description sized from the
  request number describes a field the driver does not consult.
- Never take a `case` label as a dispatch site without checking its brace
  depth. `uvm.c` switches on unrelated `UVM_*` enumerators, and
  `NV_ESC_RM_ALLOC` contains a nested switch. A line-only scan invents commands
  and misattributes privilege checks.
- Never strip block comments with a pattern that runs before line comments.
  `escape.c` opens with a `//*****` banner whose second and third characters
  are a valid `/*`. A block-comment pattern consumes the file to the next `*/`,
  and all 21 escape dispatch sites in it disappear with no error.
- Never publish a request number for a command declared but never dispatched.
  Three `NV_ESC_RM_*` names exist only in `nv_escape.h`. Calls to them are
  rejected at the first validation check, so a description spends executions on
  a path that ends there.
- Never record the gated test commands as reachable. `uvm_test_ioctl` refuses
  all 104 unless the module carries `uvm_enable_builtin_tests=1`, and their
  numbers are small integers an unrelated ioctl could occupy.

## Design notes

Three numbers describe the RM surface and each comes from a different place.
The command number is in a header, the parameter struct is in one of three
validation tables, and the size is `sizeof()` on that struct. Only the third
resists reading, so `--emit-probe` generates the probe from the parsed struct
list, which cannot drift from the table it was derived from.

The direction bits are `_IOC_READ|_IOC_WRITE`. The kernel never checks them,
since `nv_validate_ioctls` forwards only `_IOC_NR` and `_IOC_SIZE`, but the
value is stated by `__NV_IOWR` in `nv.h`, which expands to
`_IOWR(NV_IOCTL_MAGIC, nr, type)`. No open-module code calls that macro, so it
describes a closed component's behaviour.

A ceiling on the direct path is lower than the architectural one and cannot be
resolved from the open tree. `__NV_IOWR_ASSERT` refuses any type larger than
`NV_PLATFORM_MAX_IOCTL_SIZE`, which is defined nowhere in the checkout. The
14-bit `_IOC_SIZE` field allows 16383, and the size at which the user-mode
driver switches to the transfer path may be lower.

The transfer path accepts 16384 bytes where the direct path accepts 16383, so
its description as a way past the size ceiling holds architecturally and buys
one byte against this command set. No dispatched escape has a struct above
16383 bytes. It changes the shape of the call: the buffer pointer comes out of
the payload, the command widens from 8 bits to 32, and every escape shares one
request number.

Validation masks the command with `0xFF` and dispatch does not, so a command
with high bits set validates through the RM tables and then matches no case in
any of the three switches. The result is an error return, reached after the
argument has been allocated and copied. Nothing found here validates as one
escape and dispatches to another.

One cross-check covers the whole UVM half. The STACK route macro asserts
`sizeof(params) <= UVM_MAX_IOCTL_PARAM_STACK_SIZE`, which is 288, and the ALLOC
macro asserts the opposite, both as `BUILD_BUG_ON`. Re-deriving that from the
measured sizes turns a silent mispairing into a raised error, because a command
paired with the wrong struct almost always falls on the wrong side of 288.

## Stated limits

- Measured sizes come from a committed file. `surface/ioctl-sizes.json` is the
  `--sizes` default, a checkout without it measures nothing, and
  `refuse_size_regression` fails the run at exit 1 before the smaller inventory
  is written.
- Measuring the sizes needs the driver headers compiled. `--emit-probe` writes
  the probes and a runner, and running them needs a toolchain and the headers.
  A clean checkout cannot produce the measurements itself.
- `/dev/nvidia-modeset` carries one request number for its whole command set,
  and the sub-command travels in `NvKmsIoctlParams.cmd`, which appears in no ioctl
  trace. A crash matched on that number is matched at family level, never at
  command level. `--emit-map` records the number and
  [`nvkms_inventory.py`](/gspwn/architecture/components/nvkms-inventory/)
  enumerates the command set behind it.

## See also

- [trace2seed.py](/gspwn/architecture/components/trace2seed/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
- [UVM subsystem](/gspwn/knowledgebase/uvm/)
- [RM control surface](/gspwn/knowledgebase/rm-control-surface/)
- [Threat model](/gspwn/architecture/threat-model/)
- [Seeds from traces](/gspwn/guides/generating-seeds-from-traces/)
