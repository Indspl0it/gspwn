---
title: trace2seed.py
description: Converting an strace of a CUDA workload into seed syz-programs, and building chain-shaped programs from the surface artefacts.
---

Builds seed programs syz-manager can import through the corpus, from two
sources. A trace supplies a real file-descriptor lifecycle and the escapes whose
command is the request number. The surface artefacts supply the control command
identity a trace cannot carry.

## Synopsis

```
python3 tools/trace2seed.py convert --trace PATH --out-dir DIR [--map PATH]
python3 tools/trace2seed.py chains [--out-dir DIR] [--chains PATH] [--rank PATH]
                                   [--no-rank] [--descriptions DIR] [--max-calls N]
```

Root is never required. The pre-subcommand form
`trace2seed.py --trace X --out-dir Y` routes to `convert`. `-v` is accepted
before or after the subcommand.

## convert

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--trace` | `PATH` | Required | The strace output file |
| `--out-dir` | `DIR` | Required | Where the seed is written. Created if absent |
| `--map` | `PATH` | `tools/ioctl_map.json` | The ioctl map |

```
wrote artifacts/seeds/seed-0000.syz (2 mapped ioctls, 1 unmapped, 2 multiplexer calls carrying no decodable command)
the 2 multiplexer call(s) are control or allocation commands this trace cannot identify. Run `chains` for those.
```

The second line is printed whenever the multiplexer count is non-zero.

The output file is `seed-NNNN.syz` at the lowest unused index in the target
directory, so a bank with gaps is never overwritten.

`convert` reads no environment variable, so a rejected `GSPWN_SEED_MAX_CALLS`
does not affect it.

## chains

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--chains` | `PATH` | `surface/rm-chains.json` | The allocation chain per owning class, from `object_graph.py chains` |
| `--rank` | `PATH` | `surface/rm-control-rank.json` when it exists | The order of the commands inside a program, from `ctrl_rank.py rank` |
| `--no-rank` | None | Off | Order the commands inside a program by handler name |
| `--descriptions` | `DIR` | `descriptions` | Where the declared call names and their pinned request numbers are read from |
| `--out-dir` | `DIR` | `artifacts/seeds` | Where the programs are written |
| `--max-calls` | `N` | `GSPWN_SEED_MAX_CALLS`, else 40 | Calls per program, syzkaller's `prog.MaxCalls` |

```
wrote 44 chain-shaped program(s) to artifacts/seeds: 36 prologue(s) over 38 distinct chain(s), carrying 514 control command(s)
no chain for Memory, so its 6 command(s) reach no program: no RS_ENTRY row for this class
no chain for MmuFaultBuffer, so its 1 command(s) reach no program: every external class requires allocation privilege
no chain for NvDispApi, so its 1 command(s) reach no program: every external class requires allocation privilege
no chain for ProfilerBase, so its 9 command(s) reach no program: no RS_ENTRY row for this class
531 control command(s) accounted for: 514 emitted, 0 dropped before emission, 17 with no chain
```

The closing line closes on the whole control surface at any budget. Every
chained command is emitted or dropped before emission, and every unchained one
is counted under the third number, so no command falls out of every total. At
`--max-calls 5` it reads `531 control command(s) accounted for: 418 emitted,
96 dropped before emission, 17 with no chain`.

`--max-calls` has a floor of 3, the shortest program being one `openat`, one
allocation and one control command. A lower value exits 2 before anything is
written. A non-integer `GSPWN_SEED_MAX_CALLS` also exits 2, naming the variable
and the rejected value, and `--help` still works.

A run that writes no program exits 1, so a seeds gate reading the status does
not see success against an empty bank.

A missing ranking is a warning and the commands fall back to handler-name
order, because the ranking decides which commands a cap keeps and never what any
of them contains. A ranking named explicitly and absent is an error. A missing
`rm-chains.json` is an error naming `tools/object_graph.py chains` as the
remedy.

A leftover `.trace2seed-*.tmp` file in the output directory is reported by name,
stated not to be a program, and left for the operator to remove. The tool does
not delete it, because a concurrent run may be mid-write.

## The expected trace command

```
strace -v -f -P /dev/nvidiactl -P /dev/nvidia0 -P /dev/nvidia-uvm \
  -P /dev/nvidia-uvm-tools -o artifacts/seeds/trace.txt <workload>
```

`-v` and `-f` are both required. Their output quirks are handled here:

| Quirk | Handling |
|---|---|
| `-f` prefixes lines with `[pid N]` | The prefix is stripped, and file descriptors are tracked per process, because they are a per-process namespace |
| `-v` prints unknown requests as `_IOC(dir, type, nr, size)` | The symbolic form is decoded back into a request number before lookup, so an unmapped entry is a real gap in the map |

The `_IOC` decoder handles hex and decimal fields, and a direction that either
combines `_IOC_READ` and `_IOC_WRITE` or is numeric. The reassembled request is
`dir << 30 | size << 16 | type << 8 | nr`.

## The device map

| Path | Description |
|---|---|
| `/dev/nvidiactl` | `openat$nvidiactl` |
| `/dev/nvidia-uvm` | `openat$nvidia_uvm` |
| `/dev/nvidia-uvm-tools` | `openat$nvidia_uvm_tools` |
| `/dev/nvidiaN` | `openat$nvidia` |
| `/dev/dri/*` | `openat$dri` |
| `/dev/nvidia-modeset` | Refused: out of scope |

Any other path is skipped silently.

## The converted program

The program behind the summary above:

```
# 2 call(s) here reached a dispatching escape whose command is inside the parameter struct (NV_ESC_RM_ALLOC x1, NV_ESC_RM_CONTROL x1).
# A trace carries the object chain and the fd lifecycle and cannot carry those commands.
# The command-targeted programs come from `tools/trace2seed.py chains`.
r0 = openat$nvidiactl(0xffffffffffffff9c, &AUTO='/dev/nvidiactl\x00', 0x2, 0x0)
ioctl$NV_ESC_REGISTER_FD(r0, 0xc00446c9, &AUTO)
# NV_ESC_RM_ALLOC on r0, request 0xc030462b: NVOS64_PARAMETERS.hClass selects the command and strace does not decode it, so no ioctl$NV_ESC_RM_ALLOC_* call can be named from this trace (48-byte parameter form)
# NV_ESC_RM_CONTROL on r0, request 0xc020462a: NVOS54_PARAMETERS.cmd selects the command and strace does not decode it, so no ioctl$NV_ESC_RM_CONTROL_* call can be named from this trace (32-byte parameter form)
ioctl$NV_ESC_RM_FREE(r0, 0xc0104629, &AUTO)
# unmapped ioctl 0xdeadbeef on fd 3
# skipped: nvidia-modeset out of scope
close(r0)
```

The three-line header block is prepended once per program whenever any
multiplexer comment is present.

Each opened device becomes a syzkaller resource, so the generated program chains
handles the way the workload did. An ioctl on a tracked descriptor becomes a
call when the map names it, a multiplexer comment when the map records it as a
dispatching escape, and an unmapped comment otherwise.

Multiplexer calls are counted per request number and not per escape, and each
comment carries the parameter size the request number encodes. Where one escape
was traced under more than one calling form the header names each form with its
struct and size.

`openat` carries four arguments, the first being the directory file descriptor.
`AT_FDCWD` is -100, which syzkaller writes as the unsigned 64-bit value
`0xffffffffffffff9c`. A three-argument form does not parse under syz-manager,
and the whole bank then fails the seeds gate for a reason that looks like a
description problem.

## The chain-shaped program

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

The prologue is written once per program and covers every command the chain
reaches, including the commands of every shorter chain whose path is a prefix of
it. A command list longer than `--max-calls` splits into several programs, each
repeating the prologue.

The request numbers come from `descriptions/*.txt` and not from a
constant, because a driver bump moves every struct size and with it every
request number.

## The ioctl map

`tools/ioctl_map.json` maps request numbers to the syzlang description names the
`describe` phase produced. The map is committed data, read at each run.

Keys are lowercased before lookup, so uppercase-hex keys work. Keys beginning
with `comment` are ignored, so notes can be kept in the file.

Three request numbers over two dispatching escapes sit under
`comment_multiplexers` and carry no call name: `0xc020462a` for
`NV_ESC_RM_CONTROL`, and `0xc030462b` and `0xc020462b` for the 48-byte and
32-byte calling forms of `NV_ESC_RM_ALLOC`. `NVOS54_PARAMETERS.cmd` selects one
of 531 control commands and `NVOS64_PARAMETERS.hClass` selects one of 155
allocation classes, and strace decodes neither, so a call named after the
dispatcher would resolve to no description. Each record holds the escape, the
parameter struct, the selector field and the description family the
command-targeted call would come from.

## Reading the counts

The mapped count counts emitted calls whose first argument is a resource
variable, so it is independent of whatever prefix the `describe` phase chose for
its description names.

Unmapped requests become comments. A seed that is mostly unmapped is an
open-and-close chain that exercises nothing, and the seeds gate reads this
ratio.

The multiplexer count is reported separately from the unmapped count, so the
gate separates a real gap in the map from a call the map cannot hold.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | At least one program was written |
| 1 | A problem, including a `chains` run that wrote no program |
| 2 | `--max-calls` below the floor of 3, or a non-integer `GSPWN_SEED_MAX_CALLS` |

## Files

| Path | Contents |
|---|---|
| `tools/ioctl_map.json` | Request number to syzlang description name, plus the multiplexer records |
| `surface/rm-chains.json` | The allocation chain per owning class |
| `surface/rm-control-rank.json` | The order of the commands inside a chain-shaped program |
| `<out-dir>/seed-NNNN.syz` | The generated seed program |
| `<out-dir>/chain-<class>-NN.syz` | One chain-shaped program per prologue |

## See also

- [Seeds from traces](/gspwn/guides/generating-seeds-from-traces/)
- [trace2seed.py component page](/gspwn/architecture/components/trace2seed/)
- [Scope and targets](/gspwn/guides/scope-and-targets/)
