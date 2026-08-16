---
title: trace2seed.py
description: strace to syz-program conversion, and the two strace quirks it handles.
---

Converts an strace of a real CUDA workload into seed syz-programs. Valid
Resource Manager object-allocation chains from real workloads are difficult for
random generation to produce.

One invocation reads a trace and the ioctl map, and writes one
`seed-NNNN.syz` into the output directory. It is self-contained: it imports
nothing from `tools/` and nothing in `tools/` imports it.

## Responsibility

The module owns the strace-to-syzlang translation and the ioctl request lookup.
It writes only the seed file it names.

| Invariant | Enforced by |
|---|---|
| A generated seed parses under syz-manager | `openat` is emitted with all four arguments, `AT_FDCWD` written as `0xffffffffffffff9c` |
| A file descriptor belongs to one process | Descriptors are keyed on `(pid, fd)` |
| An undecoded request is still looked up | The symbolic `_IOC(dir, type, nr, size)` form is decoded back to a request number |
| An out-of-scope device never reaches a seed | `OUT_OF_SCOPE` devices are refused with a comment |
| A map key's case does not affect lookup | Map keys are lowercased on load, and lookups render hex lowercase |
| An existing seed is never overwritten | The output name is the lowest unused `seed-NNNN.syz` |
| An unmapped ioctl stays visible | It is emitted as a comment, and the ratio is printed |

## Interface

The command form takes `--trace`, `--out-dir` and `--map`, which defaults to
`tools/ioctl_map.json`. It prints the written path with the mapped and unmapped
ioctl counts.

| Function | Returns |
|---|---|
| `convert(trace_text, ioctl_map)` | The generated program text |
| `parse_request(raw)` | The ioctl request number, or `None` when the argument cannot be interpreted |
| `dev_desc(path)` | The syzlang description for a device path |

Exported constants: `DEV_TO_DESC`, `OUT_OF_SCOPE`, `AT_FDCWD`.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing at run time. `selftest.py` exercises `convert`, `parse_request` and `dev_desc` |
| This module imports | Nothing in `tools/` |

## Failure modes

| Condition | Behaviour |
|---|---|
| Request argument is a symbolic name the decoder cannot interpret | `parse_request` returns `None` and the call is emitted as a comment |
| Request number absent from the map | Emitted as `# unmapped ioctl` and counted in the printed ratio |
| Trace references an out-of-scope device | Refused with a comment naming the device |
| Trace contains bytes that are not valid text | Read with `errors="replace"` |
| Output directory has gaps in its seed numbering | The lowest unused index is used, so no existing file is overwritten |
| Map file contains `comment` keys | They are ignored on load |

## Concurrency and durability

The module writes one file per invocation and takes no lock. The output name is
chosen by scanning the directory for the lowest unused index, so two concurrent
invocations against the same output directory can race for a name. Runs are
sequential from the `seeds` phase, one trace at a time. The conversion itself is
pure: `convert` reads text and returns text, which makes it directly
testable.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never emit a three-argument `openat` | `openat` takes four arguments, the first being the directory file descriptor. Emitting three produces seeds syz-manager refuses to parse, and the whole bank then fails the seeds gate with an error that resembles a description problem |
| Never share a descriptor across processes | File descriptors are a per-process namespace, and `strace -f` interleaves several |
| Never treat an undecoded request as unmappable | `strace -v` prints unrecognised requests as `_IOC(...)`; decoding that form makes an unmapped entry a genuine gap in the map |
| Never emit a seed referencing an out-of-scope device | The `describe` phase does not model `/dev/nvidia-modeset`, so a seed referencing it fails the syzkaller-parse gate |
| Never count mapped calls by a description-name prefix | The map's values are whatever the `describe` phase named its descriptions; the count matches any emitted call whose first argument is a resource variable |
| Never overwrite an existing seed | A count-based name overwrites an existing file when the bank has gaps |
| Never let uppercase-hex map keys silently miss | A map written in uppercase would yield 100% unmapped |

## Design notes

An unmapped ioctl is emitted as a comment, so the ratio in the output line is
meaningful and the missing entries are visible in the seed itself.

The `_IOC` decoder handles hex and decimal fields, and a direction that either
combines `_IOC_READ` and `_IOC_WRITE` or is numeric. The reassembled request is
`dir << 30 | size << 16 | type << 8 | nr`.

Map keys beginning with `comment` are ignored, so notes can be kept in
the file.

`close` removes the descriptor from the tracking table and emits a `close` on
the resource, so the generated program's object lifetimes match the workload's.

## See also

- [Seeds from traces](/gspwn/guides/generating-seeds-from-traces/)
- [trace2seed.py reference](/gspwn/reference/cli/trace2seed/)
