---
title: Seeds from traces
description: Capture a CUDA workload with strace, convert it to syz-programs, build the chain-shaped programs, and read the ratios.
---

A seed bank is built from two sources, and neither half works alone.

| Half | Source | Supplies |
|---|---|---|
| `trace2seed.py convert` | An strace of a CUDA workload | A real file-descriptor lifecycle and the order a workload issues escapes in |
| `trace2seed.py chains` | `rm-chains.json` and `rm-control-rank.json` | A program naming each of 514 of the 531 control commands, each behind an allocation prologue built once |

The trace half exists because random generation rarely produces valid Resource
Manager object-allocation chains and real workloads exercise them directly.
The chains half exists because `NV_ESC_RM_CONTROL` and `NV_ESC_RM_ALLOC`
dispatch on a field inside the parameter struct, `strace` decodes no NVIDIA
parameter struct, and the request number is identical for every leaf behind the
dispatcher, so no trace can name a control command however the map is
written.

## 1. Populate the ioctl map

`tools/ioctl_map.json` maps ioctl request numbers to the syzlang description
names the `describe` phase produced. Build it from the `NV_*` header `describe`
authored, computing the `_IOWR` values with `gcc -E` or a small C probe.

The map is static data and is committed to the repository.

Keys are matched case-insensitively against a lowercase hex rendering of the
request number, so uppercase-hex keys work. Keys beginning with `comment` are
ignored, so notes can be kept in the file.

78 keys carry a call name. Three request numbers carry none, because they
reach a dispatching escape whose command sits inside the parameter struct.
They live under `comment_multiplexers`, which the prefix rule keeps out of the
name map:

| Request | Escape | Parameter struct | Selector field |
|---|---|---|---|
| `0xc020462a` | `NV_ESC_RM_CONTROL` | `NVOS54_PARAMETERS` | `cmd` |
| `0xc030462b` | `NV_ESC_RM_ALLOC` | `NVOS64_PARAMETERS` | `hClass` |
| `0xc020462b` | `NV_ESC_RM_ALLOC` | `NVOS21_PARAMETERS` | `hClass` |

Naming the bare escape in the name map produced seeds calling a syscall no
description declares, because the `describe` phase emits one variant per leaf
and no single name covers the request number. `0xc030462b` is the 48-byte
`NVOS64` allocation form and carries 204 declared variants, one per allocatable
class. `0xc020462b` is the 32-byte `NVOS21` form and carries one,
`ioctl$NV_ESC_RM_ALLOC_NVOS21` for `NV01_ROOT`. A trace issuing the narrower
form for any of the other 203 classes reaches an allocation route the surface
model does not carry.

## 2. Trace a workload

```
strace -v -f -P /dev/nvidiactl -P /dev/nvidia0 -P /dev/nvidia-uvm \
  -P /dev/nvidia-uvm-tools -o artifacts/seeds/trace.txt <workload>
```

Both flags are required. `-v` prints unabbreviated structures, and `-f` follows
forked children, because CUDA runtimes open device nodes from more than one
process.

Target the workload at what the round needs. From round 2 on, the work list's
seeds section lists surfaces classified `unreachable-by-construction`, and a
`[finding crash-NNNN]` item carries the precondition a real bug needed, which
identifies the workload to trace and the point in it to capture.

## 3. Convert

```
python3 tools/trace2seed.py convert --trace artifacts/seeds/trace.txt \
  --out-dir artifacts/seeds/
```

`--map` points at a different ioctl map, and it defaults to
`tools/ioctl_map.json`. The pre-subcommand form
`trace2seed.py --trace X --out-dir Y` routes to `convert`.

Output files are named `seed-NNNN.syz` at the lowest unused index, so a bank
with gaps is not overwritten.

The summary line counts three outcomes apart, and a second line appears when
the count of dispatching escapes is above zero. A conversion of a trace
holding one `NV_ESC_REGISTER_FD`, one `NV_ESC_RM_ALLOC`, one
`NV_ESC_RM_CONTROL`, one `NV_ESC_RM_FREE`, one unknown request and one open of
`/dev/nvidia-modeset`:

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
# skipped: nvidia-modeset out of scope
close(r0)
```

### Conversion rules

| Trace line | Emitted |
|---|---|
| `openat(..., "/dev/nvidiactl", ...) = 3` | `r0 = openat$nvidiactl(0xffffffffffffff9c, &AUTO='/dev/nvidiactl\x00', 0x2, 0x0)` |
| `ioctl(3, 0xc0104629, ...)`, a request number the map names | `ioctl$NV_ESC_RM_FREE(r0, 0xc0104629, &AUTO)` |
| `close(3)` | `close(r0)` |
| An ioctl on one of the three dispatching request numbers | A comment naming the escape, the parameter struct and the selector field, and a header block once per program |
| An ioctl with no map entry | `# unmapped ioctl 0xdeadbeef on fd 3` |
| An out-of-scope device | `# skipped: nvidia-modeset out of scope` |

A dispatching escape is a comment and never a call, so no seed carries a name
the description set does not declare. The header block names the `chains`
route that supplies the commands the trace could not.

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

The summary line's three counts each mean a different thing, and the seeds
gate reads all three.

| Count | Meaning | Action |
|---|---|---|
| mapped ioctls | The request number resolved to a declared call name | The part of the trace that reaches the surface model |
| unmapped | The request number appears in no map entry | A real gap. Extend `tools/ioctl_map.json` and re-run the conversion |
| multiplexer calls carrying no decodable command | The call reached one of the three dispatching request numbers | None. The commands come from the chains half |

Unmapped requests become comments, so a mostly-unmapped seed is an
open-and-close chain that exercises nothing. A high unmapped count means
`tools/ioctl_map.json` is missing entries the `describe` phase should have
produced. The seeds gate reports the ratio as evidence.

The third count is never a map gap. No entry in a map keyed by request number
can carry an identity the trace does not hold, and the selector field sits
inside a parameter struct `strace` prints as a bare pointer. A rising
multiplexer count means the workload is doing real Resource Manager work, and
the commands it issued come from the chains half.

## 4b. Build the chain-shaped programs

```
python3 tools/trace2seed.py chains --out-dir artifacts/seeds/
```

```
wrote 44 chain-shaped program(s) to artifacts/seeds: 36 prologue(s) over 38 distinct chain(s), carrying 514 control command(s)
no chain for Memory, so its 6 command(s) reach no program: no RS_ENTRY row for this class
no chain for MmuFaultBuffer, so its 1 command(s) reach no program: every external class requires allocation privilege
no chain for NvDispApi, so its 1 command(s) reach no program: every external class requires allocation privilege
no chain for ProfilerBase, so its 9 command(s) reach no program: no RS_ENTRY row for this class
531 control command(s) accounted for: 514 emitted, 0 dropped before emission, 17 with no chain
```

The closing line accounts for the whole control surface at any `--max-calls`.
Every chained command is emitted or dropped before emission, and every
unchained one is counted under the third number. At `--max-calls 5` the same
line reads `531 control command(s) accounted for: 418 emitted, 96 dropped
before emission, 17 with no chain`.

Each program opens one device node, builds an allocation prologue once, and
then issues every control command that prologue reaches, ordered by
`rm-control-rank.json`. The prologue covers every shorter chain whose path is a
prefix of it, so `NV01_ROOT -> NV01_DEVICE_0 -> NV20_SUBDEVICE_0` carries 315 of
the 531 commands behind three allocations.

`--max-calls` bounds the calls in one program, defaults to 40, and reads
`GSPWN_SEED_MAX_CALLS` for that default. The bound is syzkaller's
`prog.MaxCalls`, taken from memory and not read from a syzkaller tree. It
decides how often a prologue is repeated across a split: 58 programs at 20, 44
at 40, 41 at 60.

Counted in allocation calls the fuzzer issues to reach the same 514 commands,
the chain shape costs 142 against 1365 for one program per command, each
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

Rebuild the two input artefacts after a driver bump, in this order:

```
python3 tools/object_graph.py chains
python3 tools/ctrl_rank.py rank
```

The 17 commands with no chain are reported per owning class with the reason.
`Memory` and `ProfilerBase` are NVOC base classes with no `RS_ENTRY` row, and
`MmuFaultBuffer` and `NvDispApi` have every external class marked
`RS_FLAGS_ALLOC_PRIVILEGED`. Those belong in the completion ledger under
`chain-unbuildable` or `needs-privilege`, and not in the next round's
worklist.

## 5. Validate against syz-manager

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

## Out-of-scope devices

`/dev/nvidia-modeset` is refused at conversion time. The `describe` phase does
not model it, so a seed referencing it would fail the syzkaller-parse gate.
See [Scope and targets](/gspwn/guides/scope-and-targets/) for why those nodes
are excluded.

## Preconditions that cannot be reached

If a precondition from a research record cannot be reached from any CUDA
workload available on the machine, the `seeds` gate records that fact and no
substitute seed is supplied. A seed that does not establish the
precondition does not exercise the path, and reporting it as covered loses the
target for the next round.

## See also

- [Corpus and seeds](/gspwn/guides/corpus-and-seeds/) covers the bank itself.
- [trace2seed.py reference](/gspwn/reference/cli/trace2seed/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
