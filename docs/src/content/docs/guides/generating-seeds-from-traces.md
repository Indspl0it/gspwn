---
title: Seeds from traces
description: Capture a CUDA workload with strace, convert it to syz-programs, build the chain-shaped programs, and read the ratios.
---

A seed bank is built from two sources, and neither half works alone.

- `trace2seed.py convert` reads an strace of a CUDA workload, and supplies a
  real file-descriptor lifecycle and the order a workload issues escapes in.
- `trace2seed.py chains` reads `rm-chains.json` and `rm-control-rank.json`, and
  supplies a program naming each of 529 of the 531 control commands, each
  behind an allocation prologue built once.

The trace half exists because random generation rarely produces valid Resource
Manager object-allocation chains, and real workloads exercise them directly.

The chains half exists because `NV_ESC_RM_CONTROL` and `NV_ESC_RM_ALLOC`
dispatch on a field inside the parameter struct that `strace` does not decode.
The request number is identical for every leaf behind the dispatcher, so no
trace can name a control command however the map is written.

## 1. Populate the ioctl map

`tools/ioctl_map.json` maps ioctl request numbers to the syzlang description
names the `describe` phase produced. Build it from the `NV_*` header `describe`
authored, computing the `_IOWR` values with `gcc -E` or a small C probe.

The map is static data and is committed to the repository. Its one writer is
`tools/ioctl_inventory.py --emit-map tools/ioctl_map.json`, and the file
records the driver version it was built from under `comment_driver_version`.

Keys are matched case-insensitively against a lowercase hex rendering of the
request number, so uppercase-hex keys work. Keys beginning with `comment` are
excluded from the name map, so notes can be kept in the file.

78 keys carry a call name. Three request numbers carry none, because they reach
a dispatching escape whose command is inside the parameter struct. The
`comment_multiplexers` section holds those three, and the prefix rule keeps the
section out of the name map:

| Request | Escape | Parameter struct | Selector field | Parameter size |
|---|---|---|---|---|
| `0xc020462a` | `NV_ESC_RM_CONTROL` | `NVOS54_PARAMETERS` | `cmd` | 32 bytes |
| `0xc030462b` | `NV_ESC_RM_ALLOC` | `NVOS64_PARAMETERS` | `hClass` | 48 bytes |
| `0xc020462b` | `NV_ESC_RM_ALLOC` | `NVOS21_PARAMETERS` | `hClass` | 32 bytes |

The size is the `size` field of the request number itself, which is the only
thing separating the two `NV_ESC_RM_ALLOC` forms. `convert` refuses a map that
gives one request number both a call name and a multiplexer record, because a
traced call would then be reported two ways.

Naming the bare escape in the name map produced seeds calling a syscall no
description declares, because the `describe` phase emits one variant per leaf
and no single name covers the request number. The two allocation forms differ
in how much of the class space they name:

- `0xc030462b`, the 48-byte `NVOS64` form, carries 204 declared variants, one
  per allocatable class.
- `0xc020462b`, the 32-byte `NVOS21` form, carries one,
  `ioctl$NV_ESC_RM_ALLOC_NVOS21` for `NV01_ROOT`.

A trace issuing the narrower form for any of the other 203 classes reaches an
allocation route the surface model does not carry. Where a trace uses both
forms, the seed's header block names each form with its parameter struct, its
size and its call count.

## 2. Trace a workload

```
strace -v -f -P /dev/nvidiactl -P /dev/nvidia0 -P /dev/nvidia-uvm \
  -P /dev/nvidia-uvm-tools -o artifacts/seeds/trace.txt <workload>
```

Both flags are required. `-v` prints unabbreviated structures, and `-f` follows
forked children, because CUDA runtimes open device nodes from more than one
process.

Target the workload at what the round needs. From round 2 on, the worklist's
seeds section lists surfaces classified `unreachable-by-construction`, and a
`[finding crash-NNNN]` item carries the precondition a real bug needed, which
identifies the workload to trace and the point in it to capture.

## 3. Convert

```
python3 tools/trace2seed.py convert --trace artifacts/seeds/trace.txt \
  --out-dir artifacts/seeds/
```

`--trace` and `--out-dir` are both required. `--map` points at a different
ioctl map and defaults to `tools/ioctl_map.json`. The pre-subcommand form
`trace2seed.py --trace X --out-dir Y` routes to `convert`.

Output files are named `seed-NNNN.syz` at the lowest unused index, so a bank
with gaps is not overwritten. An unreadable trace or map exits 2 with the
reason.

The summary line counts three outcomes apart, and a second line appears when
the count of dispatching escapes is above zero. A conversion of a trace holding
one `NV_ESC_REGISTER_FD`, one `NV_ESC_RM_ALLOC`, one `NV_ESC_RM_CONTROL`, one
`NV_ESC_RM_FREE` and one unknown request:

```
$ python3 tools/trace2seed.py convert --trace tmp/trace.txt --out-dir tmp/out
wrote tmp/out/seed-0000.syz (2 mapped ioctls, 1 unmapped, 2 multiplexer calls carrying no decodable command)
the 2 multiplexer call(s) are control or allocation commands this trace cannot identify. Run `chains` for those.
```

The conversion wrote this program:

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
close(r0)
```

### Traced device nodes and their declared calls

`convert` reads only `openat` lines whose path starts `/dev/nvidia` or
`/dev/dri`. Seven paths convert to a declared call.

| Traced path | Emitted call |
|---|---|
| `/dev/nvidiactl` | `openat$nvidiactl` |
| `/dev/nvidia<N>` | `openat$nvidia` |
| `/dev/nvidia-uvm` | `openat$nvidia_uvm` |
| `/dev/nvidia-uvm-tools` | `openat$nvidia_uvm_tools` |
| `/dev/nvidia-modeset` | `openat$nvidia_modeset` |
| `/dev/dri/card<N>` | `openat$dri_card` |
| `/dev/dri/renderD<N>` | `openat$dri_render` |

The two `/dev/dri` node types convert to two calls because they do not grant
the same command set: `drm_ioctl_permit` refuses a render client any command
whose flag word omits `DRM_RENDER_ALLOW`.

### Conversion rules

Seven trace-line shapes are recognised. Three emit a comment, and one emits
nothing at all.

| Trace line | Emitted |
|---|---|
| `openat(..., "/dev/nvidiactl", ...) = 3` | `r0 = openat$nvidiactl(0xffffffffffffff9c, &AUTO='/dev/nvidiactl\x00', 0x2, 0x0)` |
| `openat` on a `/dev/nvidia` or `/dev/dri` path outside the table above | nothing. The descriptor is untracked, so its later ioctls are ignored too |
| `ioctl(3, 0xc0104629, ...)`, a request number the map names | `ioctl$NV_ESC_RM_FREE(r0, 0xc0104629, &AUTO)` |
| An ioctl on one of the three dispatching request numbers | a comment naming the escape, the parameter struct and the selector field, and a header block once per program |
| An ioctl with no map entry | `# unmapped ioctl 0xdeadbeef on fd 3` |
| `close(3)` on a tracked descriptor | `close(r0)` |
| A device no description models | `# skipped: <path> out of scope`. `OUT_OF_SCOPE` and `OUT_OF_SCOPE_PREFIXES` in `tools/trace2seed.py` are both empty on this branch, so no traced node takes this route |

A dispatching escape becomes a comment and never a call, so no seed carries a
name the description set does not declare.

File descriptors become syzkaller resources, so the generated program chains
handles the way the workload did. Descriptors are tracked per process, because
they are a per-process namespace and `-f` interleaves several.

Two strace quirks are handled. The `[pid N]` prefix is stripped before parsing,
and the symbolic `_IOC(dir, type, nr, size)` form that `strace -v` prints for
requests it does not recognise is decoded back into a request number before
lookup. An unmapped entry therefore indicates a real gap in the map.

`openat` is emitted with four arguments, the first being the directory file
descriptor. `AT_FDCWD` is -100, which syzkaller writes as the unsigned 64-bit
value `0xffffffffffffff9c`. A three-argument form does not parse under
syz-manager, and the whole bank then fails the seeds gate for a reason that
looks like a description problem.

## 4. Read the ratio

The seeds gate reads all three counts on the summary line.

| Count | Meaning | Action |
|---|---|---|
| mapped ioctls | the request number resolved to a declared call name | the part of the trace that reaches the surface model |
| unmapped | the request number appears in no map entry | a real gap. Extend `tools/ioctl_map.json` and re-run the conversion |
| multiplexer calls carrying no decodable command | the call reached one of the three dispatching request numbers | none. The commands come from the chains half |

Unmapped requests become comments, so a mostly-unmapped seed is an
open-and-close chain that exercises nothing. The seeds gate reports the ratio
as evidence.

The third count is never a map gap. No entry in a map keyed by request number
can carry an identity the trace does not hold. A rising multiplexer count means
the workload is doing real Resource Manager work.

The ratio detects a request number the map lacks and never a request number
whose value is wrong, so it is secondary evidence.
`python3 tools/regression_check.py names` is the primary check, and it reports
any map name the description set does not declare.

## 5. Build the chain-shaped programs

```
python3 tools/trace2seed.py chains --out-dir artifacts/seeds/
```

```
wrote 45 chain-shaped program(s) to artifacts/seeds: 37 prologue(s) over 40 distinct chain(s), carrying 529 control command(s)
no chain for MmuFaultBuffer, so its 1 command(s) reach no program: every external class requires allocation privilege
no chain for NvDispApi, so its 1 command(s) reach no program: every external class requires allocation privilege
531 control command(s) accounted for: 529 emitted, 0 dropped before emission, 2 with no chain
```

The exit status is part of the result, and the gate reads it beside the account
line.

| Exit | Condition |
|---|---|
| 0 | at least one program was written |
| 1 | no program was written, so the bank is empty. The lines above name every command dropped and every command with no chain |
| 2 | the arguments or the input artefacts could not produce a program |

`--out-dir` defaults to `artifacts/seeds`, `--chains` to
`surface/rm-chains.json` and `--rank` to `surface/rm-control-rank.json`. A
missing ranking at the default path is a warning, and the commands inside each
program are then ordered by handler name. A ranking named with `--rank` and
absent is exit 2, because the caller asked for that ordering. `--rank` and
`--no-rank` together are exit 2.

The closing line accounts for the whole control surface at any `--max-calls`.
Every chained command is emitted or dropped before emission, and every
unchained one is counted under the third number. At `--max-calls 5` the same
line reads `531 control command(s) accounted for: 424 emitted, 105 dropped
before emission, 2 with no chain`.

Each program opens one device node, builds an allocation prologue once, and
then issues every control command that prologue reaches, ordered by
`rm-control-rank.json`. The prologue covers every shorter chain whose path is a
prefix of it, so `NV01_ROOT -> NV01_DEVICE_0 -> NV20_SUBDEVICE_0` carries 315 of
the 531 commands behind three allocations.

`--max-calls` bounds the calls in one program, defaults to 40, and reads
`GSPWN_SEED_MAX_CALLS` for that default. The bound is syzkaller's
`prog.MaxCalls`, taken from memory and not read from a syzkaller tree. It
decides how often a prologue is repeated across a split: 59 programs at 20, 45
at 40, 42 at 60. Values below 3 are exit 2, because the shortest chain-shaped
program is one `openat`, one allocation and one control command, and below that
floor the run would write an empty bank while exiting 0.

Counted in allocation calls the fuzzer issues to reach the same 529 commands,
the chain shape costs 145 against 1413 for one program per command, each
rebuilding its own chain. That comparison counts calls issued. Whether the
chain shape finds more was not measured, and no chain-shaped program has been
parsed by `syz-db` or executed.

Every parameter struct is written `&AUTO`, and the seed text wires no handles.
`descriptions/nvidia_structs.txt` types `hObjectParent` and
`hObjectNew` as `nv_handle` resources, which is the declaration syzkaller's
resource machinery would need to carry a parent handle from one call to the
next. Whether it does so for an argument written `&AUTO` has not been checked
against syzkaller's prog text parser, because no syzkaller tree exists in this
repository. If it does not, the first execution allocates with a zero parent
handle and the chain is a prologue in name only. The head comment of every
emitted program states that.

Programs are written through a temporary file and renamed into place, so an
interrupted run leaves the previous program intact. A run killed between the
write and the rename leaves the temporary file behind, and the next run reports
it:

```
1 temp file(s) from an interrupted run are in artifacts/seeds: .trace2seed-x8f2q1.tmp. They are not programs; delete them.
```

Rebuild the two input artefacts after a driver bump, in this order:

```
python3 tools/object_graph.py chains
python3 tools/ctrl_rank.py rank
```

The 2 commands with no chain are reported per owning class with the reason.
`MmuFaultBuffer` and `NvDispApi` have every external class marked
`RS_FLAGS_ALLOC_PRIVILEGED`. Those belong in the completion ledger under
`needs-privilege`, and not in the next round's worklist.

## 6. Validate against syz-manager

Every seed must parse. Add the bank to a corpus and watch the manager log for
parse errors during a five-minute smoke run:

```
sudo python3 tools/campaign_ctl.py install-k --run-id smoke-1 \
  --corpus fresh --seeds artifacts/seeds --hours 1
sudo python3 tools/campaign_ctl.py start k
journalctl -u gspwn-k -f
```

A seed that does not parse is silently dropped by syz-manager, so the run
starts with fewer programs than the bank holds and nothing says so.

## Modeset and DRM nodes

`/dev/nvidia-modeset` is modelled from this branch onward and converts to
`openat$nvidia_modeset`. A trace does not name the modeset sub-command. All 64
modeset commands share the single request number `0xc0106d00` and the selector
is `NvKmsIoctlParams.cmd`, which the trace text does not record. Build a modeset
seed from `surface/nvkms-command-inventory.json` instead, which carries the
dispatch ordinal and the parameter struct of every command.

A DRM call carries its own request number, so a traced `/dev/dri` call does
name its command and converts to a seed. `surface/drm-command-inventory.json`
records the node each of the 24 DRM commands reaches: 21 carry
`DRM_RENDER_ALLOW` and reach either node, and the other 3 reach `cardN` alone.
See [Scope and targets](/gspwn/guides/scope-and-targets/).

## Preconditions that cannot be reached

If a precondition from a research record cannot be reached from any CUDA
workload available on the machine, the `seeds` gate records that fact and no
substitute seed is supplied. A seed that does not establish the precondition
does not exercise the path, and reporting it as covered loses the target for
the next round.

## See also

- [Corpus and seeds](/gspwn/guides/corpus-and-seeds/) covers the bank itself.
- [trace2seed.py reference](/gspwn/architecture/components/trace2seed/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
