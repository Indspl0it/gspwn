---
title: trace2seed.py
description: Converting an strace of a CUDA workload into seed syz-programs.
---

Converts an strace of a real CUDA workload into seed programs syz-manager can
import through the corpus.

## Synopsis

```
python3 tools/trace2seed.py --trace PATH --out-dir DIR [--map PATH]
```

No subcommands. Root is never required.

## Options

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--trace` | `PATH` | Required | The strace output file |
| `--out-dir` | `DIR` | Required | Where the seed is written. Created if absent |
| `--map` | `PATH` | `tools/ioctl_map.json` | The ioctl map |

```
wrote artifacts/seeds/seed-0000.syz (37 mapped ioctls, 4 unmapped)
```

The output file is `seed-NNNN.syz` at the lowest unused index in the target
directory, so a bank with gaps is never overwritten.

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

## The emitted program

```
r0 = openat$nvidiactl(0xffffffffffffff9c, &AUTO='/dev/nvidiactl\x00', 0x2, 0x0)
ioctl$NV_ESC_RM_ALLOC(r0, 0xc020462b, &AUTO)
# unmapped ioctl 0xc0384657 on fd 3
close(r0)
```

Each opened device becomes a syzkaller resource, so the generated program
chains handles the way the workload did. An ioctl on a tracked descriptor
becomes a call when the map names it, and a comment when it does not.

`openat` carries four arguments, the first being the directory file descriptor.
`AT_FDCWD` is -100, which syzkaller writes as the unsigned 64-bit value
`0xffffffffffffff9c`. A three-argument form does not parse under syz-manager,
and the whole bank then fails the seeds gate for a reason that looks like a
description problem.

## The ioctl map

`tools/ioctl_map.json` maps request numbers to the syzlang description names
the `describe` phase produced. The map is committed data, read at each run.

Keys are lowercased before lookup, so uppercase-hex keys work. Keys beginning
with `comment` are ignored, which is how notes are kept in the file.

## Reading the counts

The mapped count counts emitted calls whose first argument is a resource
variable, so it is independent of whatever prefix the `describe` phase chose
for its description names.

Unmapped requests become comments. A seed that is mostly unmapped is an
open-and-close chain that exercises nothing, and the seeds gate reads this
ratio.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | A problem |

## Files

| Path | Contents |
|---|---|
| `tools/ioctl_map.json` | Request number to syzlang description name |
| `<out-dir>/seed-NNNN.syz` | The generated seed program |

## See also

- [Seeds from traces](/gspwn/guides/generating-seeds-from-traces/)
- [Scope and targets](/gspwn/guides/scope-and-targets/)
</content>
</invoke>
