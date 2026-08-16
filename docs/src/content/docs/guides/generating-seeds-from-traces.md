---
title: Seeds from traces
description: Capture a CUDA workload with strace, convert it to syz-programs, and read the mapped ratio.
---

Random generation rarely produces valid Resource Manager object-allocation
chains, and real workloads exercise them directly. `tools/trace2seed.py`
converts an strace of a CUDA workload into seed programs syzkaller can import.

## 1. Populate the ioctl map

`tools/ioctl_map.json` maps ioctl request numbers to the syzlang description
names the `describe` phase produced. Build it from the `NV_*` header `describe`
authored, computing the `_IOWR` values with `gcc -E` or a small C probe.

The map is static data and is committed to the repository.

Keys are matched case-insensitively against a lowercase hex rendering of the
request number, so uppercase-hex keys work. Keys beginning with `comment` are
ignored, so notes can be kept in the file.

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
python3 tools/trace2seed.py --trace artifacts/seeds/trace.txt \
  --out-dir artifacts/seeds/
```

```
wrote artifacts/seeds/seed-0000.syz (37 mapped ioctls, 4 unmapped)
```

`--map` points at a different ioctl map; it defaults to `tools/ioctl_map.json`.

Output files are named `seed-NNNN.syz` at the lowest unused index, so a bank
with gaps is not overwritten.

### Conversion rules

| Trace line | Emitted |
|---|---|
| `openat(..., "/dev/nvidiactl", ...) = 3` | `r0 = openat$nvidiactl(0xffffffffffffff9c, &AUTO='/dev/nvidiactl\x00', 0x2, 0x0)` |
| `ioctl(3, 0xc020462b, ...)` | `ioctl$NV_ESC_RM_ALLOC(r0, 0xc020462b, &AUTO)` |
| `close(3)` | `close(r0)` |
| An ioctl with no map entry | `# unmapped ioctl 0xc020462b on fd 3` |
| An out-of-scope device | `# skipped: nvidia-modeset out of scope` |

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

```
wrote artifacts/seeds/seed-0004.syz (3 mapped ioctls, 61 unmapped)
```

Unmapped requests become comments, so a mostly-unmapped seed is an open/close
chain that exercises nothing. A high unmapped count means
`tools/ioctl_map.json` is missing entries the `describe` phase should have
produced.

Extend the map and re-run the conversion. The seeds gate reads this ratio, and
it is reported as gate evidence.

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
