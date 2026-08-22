---
title: trace2seed.py
description: The two halves a seed needs, strace to syz-program conversion and chain-shaped programs, and what a trace cannot carry.
---

Builds seed syz-programs from two sources, because a trace and the surface
artefacts each carry half of what a seed needs and neither half works alone.

| Subcommand | Source | Supplies |
|---|---|---|
| `convert` | An strace of a real CUDA workload | A real file-descriptor lifecycle, the escapes whose command is the request number, and the order a workload issues them in |
| `chains` | `rm-chains.json` and `rm-control-rank.json` | The command identity a trace cannot carry, with each allocation prologue built once |

`convert` exists because valid Resource Manager object-allocation chains from
real workloads are difficult for random generation to produce. `chains` exists
because `NV_ESC_RM_CONTROL` and `NV_ESC_RM_ALLOC` dispatch on a field inside the
parameter struct that no trace records.

The module is self-contained: it imports nothing from `tools/` and nothing in
`tools/` imports it.

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
| A traced multiplexer is neither a call nor a map gap | It is emitted as a comment naming the escape, the parameter struct and the selector field, and counted in a third column of the summary |
| A chain-shaped program builds its prologue once | `reachable()` credits a chain whose path is a prefix of a longer one, and `group_chains()` picks prologues greedily on commands per allocation |
| A request number in a seed comes from the description set | `declared_calls()` reads the pinned request number off `descriptions/*.txt`, because a driver bump moves every struct size and with it every request number |
| No chain-shaped program exceeds syzkaller's call limit | `--max-calls`, default 40, splits a command list and repeats the prologue |
| Every targetable control command is accounted for | The run reports emitted commands plus commands with no chain, and reads the artefact's `unresolved_owning_classes` block so the base classes with no `RS_ENTRY` row are counted |

## Interface

| Subcommand | Arguments | Output |
|---|---|---|
| `convert` | `--trace`, `--out-dir`, `--map` defaulting to `tools/ioctl_map.json` | One `seed-NNNN.syz`, and a summary line counting mapped calls, unmapped requests and multiplexer calls carrying no decodable command |
| `chains` | `--chains`, `--rank`, `--no-rank`, `--descriptions`, `--out-dir`, `--max-calls` | One `chain-<class>-NN.syz` per prologue, and a per-class account of the commands no chain reaches |

The pre-subcommand form `--trace X --out-dir Y` routes to `convert`, so a
script written against the older command line keeps working. `--max-calls`
reads `GSPWN_SEED_MAX_CALLS` for its default and falls back to 40.

| Function | Returns |
|---|---|
| `convert(trace_text, ioctl_map, multiplexers=None)` | The generated program text |
| `parse_request(raw)` | The ioctl request number, or `None` when the argument cannot be interpreted |
| `dev_desc(path)` | The syzlang description for a device path |
| `load_map(path)` | The request-number to call-name map, comment keys dropped, and the multiplexer records |
| `declared_calls(desc_dir)` | Call name to pinned request number, read off the description set |
| `reachable(paths, path)` | Whether a built prologue already covers one chain path |
| `group_chains(paths)` | The greedy prologue grouping, on commands per allocation |
| `buildable_paths(paths, declared, max_calls)` | The chains whose every allocation step has a declared variant and whose prologue fits the call limit |
| `unreached(chains)` | The owning classes no chain reaches, with the reason and the command count |

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
| A request number is recorded twice in the multiplexer section | Refused, naming the number |
| A multiplexer record carries no parameter struct | Refused, naming the record |
| `chains` runs with `rm-chains.json` absent | Exits, naming `tools/object_graph.py chains` as the remedy |
| `chains` runs with the ranking absent and no `--rank` | Warning, and the commands fall back to handler-name order |
| `--rank` names a file that does not exist | Exits, naming the flag |
| A chain artefact of the wrong schema | Refused, naming the schema it expected |
| A chain's deepest allocation has no declared variant | That chain alone is dropped, before the grouping, so the shorter chains it covered keep their commands |

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
| Never count mapped calls by a description-name prefix | The map's values are whatever the `describe` phase named its descriptions, and the count matches any emitted call whose first argument is a resource variable |
| Never overwrite an existing seed | A count-based name overwrites an existing file when the bank has gaps |
| Never let uppercase-hex map keys silently miss | A map written in uppercase would yield 100% unmapped |
| Never give a multiplexer request number a call name in the map | `NVOS54_PARAMETERS.cmd` and `NVOS64_PARAMETERS.hClass` select the real target, strace decodes neither, and a call named after the dispatcher resolves to no description |
| Never hardcode a request number in a chain-shaped program | A driver bump moves every struct size and with it every request number, and a seed carrying the old one dispatches to nothing |
| Never run the declaration filter after the grouping | A chain with no declared allocation would otherwise be picked as the best prologue and then dropped, taking the commands of every shorter chain it covered with it |
| Never scan the chain records alone for the unreached account | `Memory` and `ProfilerBase` have no `RS_ENTRY` row and appear under no record, so their 15 commands vanish without a line saying so |

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

## Trace limits

| Fact | Consequence |
|---|---|
| `strace` does not decode NVIDIA parameter structs | `NVOS54_PARAMETERS.cmd` and `NVOS64_PARAMETERS.hClass` never appear in the trace text |
| The request number is identical for all 531 control commands | Reading the request number, which is all `convert` can do, identifies the dispatcher and no leaf |
| The map is keyed by request number | No entry in it can carry an identity the trace does not hold |

No repair of `tools/ioctl_map.json` changes this, so the two multiplexers are
recorded there under `comment_multiplexers` and carry no call name. Each record
holds the escape, the parameter struct, the selector field and the description
family a command-targeted call would come from. `convert` writes a comment:

```
# 2 call(s) here reached a dispatching escape whose command is inside the parameter struct (NV_ESC_RM_ALLOC x1, NV_ESC_RM_CONTROL x1).
# A trace carries the object chain and the fd lifecycle and cannot carry those commands.
# The command-targeted programs come from `tools/trace2seed.py chains`.
```

The summary line carries a third count, so the seeds gate separates a real map
gap from a call the map cannot hold.

`convert` counts multiplexer calls per request number and not per escape, so
one escape traced under two calling forms is reported as two. `request_size()`
decodes the Linux `dir<<30 | size<<16 | type<<8 | nr` packing, so the parameter
size on each note is read off the request number and cannot drift from the map.
Where an escape carries more than one form the header names each with its
struct and size.

```
# NV_ESC_RM_ALLOC was traced under 2 calling forms: 0xc020462b (NVOS21_PARAMETERS, 32 bytes, x1), 0xc030462b (NVOS64_PARAMETERS, 48 bytes, x1). They are separate parameter layouts and the description set declares a variant per class for each form it carries, so a class reached only through one of them is modelled only there.
# NV_ESC_RM_ALLOC on r0, request 0xc030462b: NVOS64_PARAMETERS.hClass selects the command and strace does not decode it, so no ioctl$NV_ESC_RM_ALLOC_* call can be named from this trace (48-byte parameter form)
```

`0xc030462b` is the 48-byte `NVOS64_PARAMETERS` form and carries 204 declared
variants, one per allocatable class. `0xc020462b` is the 32-byte
`NVOS21_PARAMETERS` form and carries one, `ioctl$NV_ESC_RM_ALLOC_NVOS21` for
`NV01_ROOT`, at `descriptions/nvidia.txt:476`. A trace issuing the
narrower form for any of the other 203 classes reaches an allocation route the
surface model does not carry, and the note makes that visible.

## Chain-shaped programs

A chain is a walk from the file descriptor down one parent edge at a time, so a
class whose own path is a prefix of a longer path is allocated on the way and
its commands need no second prologue. `chains` groups on that, and
`cumulative_reach` in `rm-chains.json` is computed with the same rule.

```
# chain-shaped program: 2 allocation(s) reaching NV_CONFIDENTIAL_COMPUTE
# prologue: NV01_ROOT -> NV_CONFIDENTIAL_COMPUTE
# commands 1-8 of 8, ordered by surface/rm-control-rank.json
# every parameter struct is written &AUTO, so this text wires no handles. descriptions/nvidia_structs.txt types hObjectParent and hObjectNew as nv_handle resources, which is what syzkaller's resource machinery would need to carry a parent handle from one call to the next. Whether it does so for an argument written &AUTO has not been checked against syzkaller's prog text parser: no syzkaller tree exists in this repository. If it does not, the first execution allocates with a zero parent handle and the chain is a prologue in name only.
r0 = openat$nvidiactl(0xffffffffffffff9c, &AUTO='/dev/nvidiactl\x00', 0x2, 0x0)
ioctl$NV_ESC_RM_ALLOC_NV01_ROOT(r0, 0xc030462b, &AUTO)
ioctl$NV_ESC_RM_ALLOC_NV_CONFIDENTIAL_COMPUTE(r0, 0xc030462b, &AUTO)
ioctl$NV_ESC_RM_CONTROL_confComputeApiCtrlCmdGetGpuAttestationReport(r0, 0xc020462a, &AUTO)
```

One `openat` covers every call in the program. Every chain step's allocation
variant takes `fd_nv` and every control variant takes `fd_nvidiactl`, and
`nvidia.txt` declares `fd_nvidiactl` a subtype of `fd_nv`.

Against the committed artefacts the run emits 44 programs over 36 prologues and
38 distinct chains, carrying 514 control commands, and accounts for all 531
with no residue.

```
wrote 44 chain-shaped program(s) to artifacts/seeds: 36 prologue(s) over 38 distinct chain(s), carrying 514 control command(s)
no chain for Memory, so its 6 command(s) reach no program: no RS_ENTRY row for this class
no chain for MmuFaultBuffer, so its 1 command(s) reach no program: every external class requires allocation privilege
no chain for NvDispApi, so its 1 command(s) reach no program: every external class requires allocation privilege
no chain for ProfilerBase, so its 9 command(s) reach no program: no RS_ENTRY row for this class
531 control command(s) accounted for: 514 emitted, 0 dropped before emission, 17 with no chain
```

| Prologue length | Prologues | Commands behind them |
|---|---|---|
| 2 | 10 | 50 |
| 3 | 7 | 368 |
| 4 | 18 | 95 |
| 5 | 1 | 1 |

No prologue is one allocation long. A class whose own path is a prefix of a
longer path is allocated on the way, so `RmClientResource`'s 91 commands sit
behind the three-allocation subdevice prologue and not behind a program of
their own.

The largest group is `NV01_ROOT -> NV01_DEVICE_0 -> NV20_SUBDEVICE_0`, carrying
315 commands. That reproduces the `cumulative_reach` figure in `rm-chains.json`
from an independent implementation.

The saving, counted in allocation calls the fuzzer executes to reach the same
514 commands:

| Bank shape | Allocation calls |
|---|---|
| One program per command, each rebuilding its own chain | 1365 |
| Chain-shaped, `--max-calls 40` | 142 |

1365 is the sum of `chain_length` over the 514 chained commands. 142 is the
count of `ioctl$NV_ESC_RM_ALLOC_*` lines across the 44 emitted programs. Both
count calls a fuzzer would issue and neither is a coverage measurement.

Program count against the call limit is 58 at `--max-calls 20`, 44 at 40 and 41
at 60. The prologue, chain and command counts do not move with the limit.

## Unwired handles

The parameter structs are written `&AUTO`, so the seed text wires no handles.
`descriptions/nvidia_structs.txt` types `hObjectParent` and
`hObjectNew` as `nv_handle` resources, which is the declaration syzkaller's
resource machinery would need to carry a parent handle from one call to the
next. Whether it does so for an argument written `&AUTO` has not been checked
against syzkaller's prog text parser, because no syzkaller tree exists in this
repository. If it does not, the first execution allocates with a zero parent
handle and the chain is a prologue in name only. The head comment of every
emitted program states that, in those terms.

Writing the handles explicitly means emitting a full syzkaller struct literal
with an `<r1=>` marker on the resource field, which means rendering every field
of the 55 distinct allocation parameter structs the chain steps name, including
nested pointers. That is syzlang this checkout cannot parse-check, and a
malformed literal fails the whole seed bank at parse. `&AUTO` is the form this
repository can produce and label honestly, and wiring the handles belongs with
the first run that has a syzkaller tree to compile against.

## Stated limits

| Limit | Consequence |
|---|---|
| Nothing in CI runs `chains` | `rm-chains.json` and `rm-control-rank.json` go stale against a driver bump, and the seeds phase is the first thing to notice |
| `--max-calls 40` is syzkaller's `prog.MaxCalls` from memory | No syzkaller tree exists here to read it from, which is why the value is a flag and an environment variable |
| No chain-shaped program has been parsed by syz-db or executed | The reach figures rest on the `RS_ENTRY` table by way of `rm-chains.json` |
| The 1365-against-142 comparison counts allocation calls issued | It is not a coverage measurement |

## See also

- [Seeds from traces](/gspwn/guides/generating-seeds-from-traces/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
- [ctrl_rank.py](/gspwn/architecture/components/ctrl-rank/)
- [trace2seed.py reference](/gspwn/reference/cli/trace2seed/)
