---
title: trace2seed.py
description: The two halves a seed needs, strace to syz-program conversion and chain-shaped programs, and what a trace cannot carry.
---

Builds seed syz-programs from two sources, because a trace and the surface
artefacts each carry half of what a seed needs and neither half works alone.

| Subcommand | Source | Supplies |
|---|---|---|
| `convert` | An strace of a real CUDA workload | A real file-descriptor lifecycle, the escapes whose command is the request number, and the order a workload issues them in |
| `chains` | `surface/rm-chains.json` and `surface/rm-control-rank.json` | The command identity a trace cannot carry, with each allocation prologue built once |

`convert` exists because valid Resource Manager object-allocation chains from
real workloads are difficult for random generation to produce. `chains` exists
because `NV_ESC_RM_CONTROL` and `NV_ESC_RM_ALLOC` dispatch on a field inside the
parameter struct that no trace records.

## Commands

| Option | Subcommand | Effect |
|---|---|---|
| `--trace PATH` | `convert` | The strace file to read. Required. |
| `--out-dir DIR` | `convert` | Where the seed is written. Required. |
| `--map PATH` | `convert` | The ioctl map, default `tools/ioctl_map.json` |
| `--chains PATH` | `chains` | The chain artefact, default `surface/rm-chains.json` |
| `--rank PATH` | `chains` | The control ranking, default `surface/rm-control-rank.json` when it exists |
| `--no-rank` | `chains` | Order the commands inside a program by handler name. Contradicts `--rank` and is refused beside it |
| `--descriptions DIR` | `chains` | The description set the call names and request numbers are read from, default `descriptions/` |
| `--out-dir DIR` | `chains` | Where the programs are written, default `artifacts/seeds/` |
| `--max-calls N` | `chains` | Calls per program, syzkaller's `prog.MaxCalls`, default 40. The floor is 3, one `openat`, one allocation and one control command |

`-v` is accepted before the subcommand and after it. `GSPWN_SEED_MAX_CALLS`
overrides the `--max-calls` default. A value that is not a whole number fails
`chains` as a named error, because the variable is read at import and a
traceback there precedes even the usage line.

`chains` exits 1 when it wrote no program at all, naming the commands dropped
before emission and the commands that reach no chain.

## Responsibility

The module owns the strace-to-syzlang translation and the ioctl request lookup.
It writes only the seed files it names.

| Invariant | Enforced by |
|---|---|
| A generated seed parses under syz-manager | `openat` is emitted with all four arguments, `AT_FDCWD` written as `0xffffffffffffff9c` |
| A file descriptor belongs to one process | Descriptors are keyed on `(pid, fd)` |
| An undecoded request is still looked up | The symbolic `_IOC(dir, type, nr, size)` form is decoded back to a request number |
| A device no description models never reaches a seed | `dev_desc` returns a call name for seven device forms and `None` for everything else, and a traced open it does not recognise emits nothing |
| A map key's case does not affect lookup | Map keys are lowercased on load, and lookups render hex lowercase |
| One request number is reported one way | `load_map` refuses a map giving the same request number both a call name and a multiplexer record |
| An existing seed is never overwritten by `convert` | The output name is the lowest unused `seed-NNNN.syz` |
| A re-run of `chains` does not grow the bank | Chain program names are deterministic, `chain-<class>-NN.syz`, so a re-run replaces its own output |
| An unmapped ioctl stays visible | It is emitted as a comment, and the ratio is printed |
| A traced multiplexer is neither a call nor a map gap | It is emitted as a comment naming the escape, the parameter struct and the selector field, and counted in a third column of the summary |
| A chain-shaped program builds its prologue once | `reachable()` credits a chain whose path is a prefix of a longer one, and `group_chains()` picks prologues greedily on commands per allocation |
| A request number in a seed comes from the description set | `declared_calls()` reads the pinned request number off `descriptions/*.txt`, because a driver bump moves every struct size and with it every request number |
| No chain-shaped program exceeds syzkaller's call limit | `--max-calls`, default 40, splits a command list and repeats the prologue |
| Every targetable control command is accounted for | The run reports emitted commands plus commands with no chain, and reads the artefact's `unresolved_owning_classes` block so the base classes with no `RS_ENTRY` row are counted |

## The ioctl map

`tools/ioctl_map.json` holds 78 call names keyed by request number, three
multiplexer request numbers over two escapes, and eight `comment`-prefixed
keys the loaders skip.

| Section | Content |
|---|---|
| Request-number entries | 78 hex request numbers mapping to the syzlang call name `convert` emits |
| `comment_multiplexers` | `0xc020462a` for `NV_ESC_RM_CONTROL` over `NVOS54_PARAMETERS.cmd`, and `0xc020462b` and `0xc030462b` for `NV_ESC_RM_ALLOC` over `NVOS21_PARAMETERS.hClass` and `NVOS64_PARAMETERS.hClass`. Each record carries the escape, the parameter struct, the selector field and the variant prefix a command-targeted call would use |
| `comment_driver_version` | The stamp `surface_verify.py` writes |
| The remaining `comment` keys | `comment`, `comment_direction`, `comment_arrays`, `comment_uvm`, `comment_excluded` and `comment_modeset`, which record what the map covers and why the `UVM_TEST_*` numbers are absent |

## Output

`convert` writes one `seed-NNNN.syz` per trace at the lowest unused index, so a
bank with gaps in its numbering does not collide, and prints a summary counting
mapped calls, unmapped requests, and multiplexer calls carrying no decodable
command.

`chains` writes one `chain-<class>-NN.syz` per prologue under a deterministic
name, plus a per-class account of the commands no chain reaches. It also names
any `chain-*.syz` in the output directory that this run did not write, and any
temp file an interrupted run left behind, because neither is visible to the
other.

Nothing is dropped in silence. A request the decoder cannot interpret, and a
request number the map does not carry, are both emitted as comments inside the
seed and counted in the printed ratio, so a map gap is visible in the artefact
itself.

The chain mode refuses to run at all when the artefact it reads is absent or
carries a schema it does not recognise, and names the command that regenerates
it. A missing default ranking is a warning and the commands fall back to
handler-name order. A ranking named with `--rank` and absent is an error,
because the caller asked for that ordering. A single chain whose deepest
allocation has no declared variant is dropped before the grouping, so the
shorter chains it covered keep their commands.

## Device nodes

`dev_desc` maps a traced open onto a declared `openat` variant. Seven forms
resolve.

| Path | Call |
|---|---|
| `/dev/nvidiactl` | `openat$nvidiactl` |
| `/dev/nvidiaN` | `openat$nvidia` |
| `/dev/nvidia-uvm` | `openat$nvidia_uvm` |
| `/dev/nvidia-uvm-tools` | `openat$nvidia_uvm_tools` |
| `/dev/nvidia-modeset` | `openat$nvidia_modeset` |
| `/dev/dri/cardN` | `openat$dri_card` |
| `/dev/dri/renderDN` | `openat$dri_render` |

The refusal tables `OUT_OF_SCOPE` and `OUT_OF_SCOPE_PREFIXES` are both empty.
`/dev/nvidia-modeset` was the only member of the first and moved out when the
modeset family was modelled, and `/dev/dri/` was the only member of the second
and moved out when the DRM family was modelled. The refusal path still exists,
because a node listed there produces a `# skipped:` comment naming the reason,
and returning a call name the description set has never declared fails the
syzkaller parse gate and takes the whole seed bank down with it.

The two DRI node types map to two calls, because `drm_ioctl_permit` refuses a
render client any command whose flag word omits `DRM_RENDER_ALLOW`, so a trace
on a card node and a trace on a render node convert to different programs.

## Concurrency and durability

Every file is written through a temp file in the same directory, flushed,
`fsync`ed and moved into place with `os.replace`, so an interrupted run leaves
the previous program intact, and never a half file the corpus importer
refuses. No lock is taken. `convert` chooses its output name by scanning the
directory for the lowest unused index, so two concurrent `convert` invocations
against the same output directory can race for a name. Runs are sequential from
the `seeds` phase, one trace at a time. The conversion itself is pure:
`convert` reads text and returns text, which makes it directly testable.

## Rules and their rationale

| Rule | Rationale |
|---|---|
| `openat` always carries four arguments | The first is the directory file descriptor. Emitting three produces seeds syz-manager refuses to parse, and the whole bank then fails the seeds gate with an error that resembles a description problem |
| A descriptor is never shared across processes | File descriptors are a per-process namespace, and `strace -f` interleaves several |
| An undecoded request is never treated as unmappable | `strace -v` prints unrecognised requests as `_IOC(...)`; decoding that form makes an unmapped entry a genuine gap in the map |
| A seed never references a device no description models | A call name the description set does not declare fails the syzkaller-parse gate, and the whole seed bank fails with it |
| Mapped calls are counted by shape, never by a description-name prefix | The map's values are whatever the `describe` phase named its descriptions, and the count matches any emitted call whose first argument is a resource variable |
| `convert` never overwrites an existing seed | A count-based name overwrites an existing file when the bank has gaps |
| Map keys are lowercased on load | A map written in uppercase hex would otherwise yield 100% unmapped |
| A multiplexer request number never carries a call name in the map | `NVOS54_PARAMETERS.cmd` and `NVOS64_PARAMETERS.hClass` select the real target, strace decodes neither, and a call named after the dispatcher resolves to no description |
| A chain-shaped program never hardcodes a request number | A driver bump moves every struct size and with it every request number, and a seed carrying the old one dispatches to nothing |
| The declaration filter runs before the grouping | A chain with no declared allocation would otherwise be picked as the best prologue and then dropped, taking the commands of every shorter chain it covered with it |
| The unreached account reads `unresolved_owning_classes` | `Memory` and `ProfilerBase` have no `RS_ENTRY` row and appear under no chain record, so their 15 commands would vanish without a line saying so |

## Design notes

The `_IOC` decoder handles hex and decimal fields, and a direction that either
combines `_IOC_READ` and `_IOC_WRITE` or is numeric. The reassembled request is
`dir << 30 | size << 16 | type << 8 | nr`.

`close` removes the descriptor from the tracking table and emits a `close` on
the resource, so the generated program's object lifetimes match the workload's.

## Trace limits

Three facts about a trace put the control command out of `convert`'s reach.

- `strace` does not decode NVIDIA parameter structs, so
  `NVOS54_PARAMETERS.cmd` and `NVOS64_PARAMETERS.hClass` never appear in the
  trace text.
- The request number is identical for all 531 control commands. Reading the
  request number, which is all `convert` can do, identifies the dispatcher and
  no leaf.
- The map is keyed by request number, so no entry in it can carry an identity
  the trace does not hold.

No repair of `tools/ioctl_map.json` changes this, so the two multiplexers are
recorded there under `comment_multiplexers` and carry no call name. `convert`
writes a comment:

```
# 2 call(s) here reached a dispatching escape whose command is inside the parameter struct (NV_ESC_RM_ALLOC x1, NV_ESC_RM_CONTROL x1).
# A trace carries the object chain and the fd lifecycle and cannot carry those commands.
# The command-targeted programs come from `tools/trace2seed.py chains`.
```

`convert` counts multiplexer calls per request number, so an escape traced
under two calling forms contributes two counts, and the summary line above adds
them per escape. `request_size()` decodes the Linux
`dir<<30 | size<<16 | type<<8 | nr` packing, so the parameter size on each note
is read off the request number and cannot drift from the map. Where an escape
carries more than one form the header names each with its struct and size.

```
# NV_ESC_RM_ALLOC was traced under 2 calling forms: 0xc020462b (NVOS21_PARAMETERS, 32 bytes, x1), 0xc030462b (NVOS64_PARAMETERS, 48 bytes, x1). They are separate parameter layouts and the description set declares a variant per class for each form it carries, so a class reached only through one of them is modelled only there.
# NV_ESC_RM_ALLOC on r0, request 0xc030462b: NVOS64_PARAMETERS.hClass selects the command and strace does not decode it, so no ioctl$NV_ESC_RM_ALLOC_* call can be named from this trace (48-byte parameter form)
```

`0xc030462b` is the 48-byte `NVOS64_PARAMETERS` form and carries 204 declared
variants: one per allocatable class, plus the 49 per-parent forms. `0xc020462b`
is the 32-byte `NVOS21_PARAMETERS` form and carries one,
`ioctl$NV_ESC_RM_ALLOC_NVOS21` for `NV01_ROOT`, at
`descriptions/nvidia.txt:623`. A trace issuing the narrower form for any of the
other 203 classes reaches an allocation route the surface model does not carry,
and the note makes that visible.

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
ioctl$NV_ESC_RM_CONTROL_confComputeApiCtrlCmdGetGpuCertificate(r0, 0xc020462a, &AUTO)
ioctl$NV_ESC_RM_CONTROL_confComputeApiCtrlCmdGpuGetVidmemSize(r0, 0xc020462a, &AUTO)
ioctl$NV_ESC_RM_CONTROL_confComputeApiCtrlCmdGpuGetNumSecureChannels(r0, 0xc020462a, &AUTO)
ioctl$NV_ESC_RM_CONTROL_confComputeApiCtrlCmdSystemGetSecurityPolicy(r0, 0xc020462a, &AUTO)
ioctl$NV_ESC_RM_CONTROL_confComputeApiCtrlCmdGpuGetKeyRotationState(r0, 0xc020462a, &AUTO)
ioctl$NV_ESC_RM_CONTROL_confComputeApiCtrlCmdSystemGetCapabilities(r0, 0xc020462a, &AUTO)
ioctl$NV_ESC_RM_CONTROL_confComputeApiCtrlCmdSystemGetGpusState(r0, 0xc020462a, &AUTO)
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

The 36 prologues group by length.

| Prologue length | Prologues | Commands behind them |
|---|---|---|
| 2 | 10 | 50 |
| 3 | 7 | 368 |
| 4 | 18 | 95 |
| 5 | 1 | 1 |

No prologue is one allocation long, so `RmClientResource`'s 91 commands, whose
own chain length is 1, are reached through the three-allocation subdevice
prologue.

The largest group is `NV01_ROOT -> NV01_DEVICE_0 -> NV20_SUBDEVICE_0`, carrying
315 commands. That reproduces the `cumulative_reach` figure in `rm-chains.json`
from an independent implementation.

The saving, counted in allocation calls the fuzzer executes to reach the same
514 commands:

- One program per command, each rebuilding its own chain: 1365 allocation
  calls.
- Chain-shaped, `--max-calls 40`: 142 allocation calls.

1365 is the sum of `chain_length` over the 514 chained commands. 142 is the
count of `ioctl$NV_ESC_RM_ALLOC_*` lines across the 44 emitted programs.

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

Four limits apply to the figures above.

- Nothing in CI runs `chains` itself. `python3 tools/regression_check.py
  derived` compares `rm-chains.json` and `rm-control-rank.json` against the
  control inventory, so a driver bump that moves the inventory is caught, and
  a change in what `chains` emits from unchanged artefacts is not.
- `--max-calls 40` is syzkaller's `prog.MaxCalls` from memory. No syzkaller
  tree exists here to read it from, which is why the value is a flag and an
  environment variable.
- No chain-shaped program has been parsed by syz-db or executed. The reach
  figures rest on the `RS_ENTRY` table by way of `rm-chains.json`.
- The 1365-against-142 comparison counts allocation calls issued. It is no
  coverage measurement.

## See also

- [Seeds from traces](/gspwn/guides/generating-seeds-from-traces/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
- [ctrl_rank.py](/gspwn/architecture/components/ctrl-rank/)
- [surface_cov.py](/gspwn/architecture/components/surface-cov/)
