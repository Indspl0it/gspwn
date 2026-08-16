---
title: Scope and targets
description: Which device nodes and syscalls Track K covers, which Track U entry points qualify, and how each list is set.
---

Scope is a configuration decision on Track K and a source-analysis decision on
Track U. Both are recorded before any modelling starts.

## Track K: the enabled syscall set

`track_k.enabled_syscalls` is the list syz-manager receives as its
`enable_syscalls` field. The shipped value:

```yaml
track_k:
  enabled_syscalls:
    - "openat$nvidia*"
    - "mmap$nvidia*"
    - "ioctl$NV_*"
    - "ioctl$UVM_*"
```

Each entry is a syzkaller syscall pattern, and the `$` suffix names a
description variant that the `describe` phase authored. An empty list enables
everything syzkaller knows, which on this target means the whole kernel.

:::caution[The enabled syscall set must be a YAML list]
`enabled_syscalls: "ioctl$NV_*"` reaches syz-manager as a one-character list
and the campaign starts with the wrong syscall set. The configuration validator
refuses it: the value must be a list of non-empty strings.
:::

## Device nodes in scope

| Node | In scope | Reason |
|---|---|---|
| `/dev/nvidiactl` | Yes | Granted by the default `compute,utility` capability set |
| `/dev/nvidiaX` | Yes | Same |
| `/dev/nvidia-uvm` | Yes | Same |
| `/dev/nvidia-uvm-tools` | Yes | Same |
| `/dev/nvidia-modeset` | No | Requires the `graphics` or `display` capability |
| `/dev/dri/*` | No | Same |

`NVIDIA_DRIVER_CAPABILITIES` gates which device nodes a container receives. The
default that CUDA images request, `compute,utility`, yields no `/dev/dri` and
no `nvidia-drm` nodes. Any ioctl surface reachable only through them is outside
a default tenant's reach, so a crash found there falls outside the threat model
and the descriptions for it are not written.

The exclusion is enforced in two places. The `describe` sub-agent is told to
skip those nodes, and `tools/trace2seed.py` refuses to emit a seed referencing
`/dev/nvidia-modeset`:

```
# skipped: nvidia-modeset out of scope
```

A seed that referenced it would fail the syzkaller-parse gate anyway, because
no description models it.

Widening scope requires a decision recorded in the
[threat model](/gspwn/architecture/threat-model/) before the `describe`
sub-agent models the added surface.

## Track K: modelling priority

The `describe` sub-agent works an unexplored surface in this order, which puts
modelling depth on the reachable surface first.

| Order | Surface | Modelling requirement |
|---|---|---|
| 1 | Object lifecycle: the RM allocation escape, the free escape, the device-open path | Nothing else is reachable until a client handle exists |
| 2 | The control multiplexer: one ioctl whose command number selects the parameter struct | Model the command number as a constant set with per-command parameter structs attached. Most of the attack surface is here, and an opaque buffer leaves it untested |
| 3 | UVM ioctls | Flat structs |

From round 2 on, `[finding crash-NNNN]` work items take precedence over this
order within their own subsystem.

Handles are chained with syzkaller resources so generated programs build valid
object trees: the root client handle is produced by the client allocation and
consumed by every subsequent allocate, control and free call. A description set
without resource chaining generates programs that fail at the first handle
check, which shows up in a smoke run as uniform early-out.

## Track U: choosing entry points

Track U has no configuration list of targets. The `harness` sub-agent
enumerates candidates from the checked-out source and ranks them by how
directly attacker-controlled bytes reach them.

| Target | Priority | Qualifying surface |
|---|---|---|
| `libnvidia-container` (C) | Primary | The memory-safety surface: config parsing, ldcache handling, ELF and library inspection, mount and path construction, capability and option string parsing |
| `nvidia-container-toolkit` (Go) | Secondary | Panic and denial-of-service surface only: OCI `config.json` handling, CDI spec parsing, environment variable processing |

Go is memory-safe. A Track U harness against the Go toolkit does not support a
memory-corruption claim.

Symlink TOCTOU and mount-escape logic bugs are out of scope and recorded in the
report as future work. Fuzzing has a low detection rate for both classes.

Three properties make a candidate a usable target:

1. A container image or OCI config can influence its input. A function that
   cannot be reached from an image is not a Track U target.
2. It takes a buffer and a length, or a path.
3. It can be called without a live GPU and without a real container.

The ranked list, with a one-line reachability justification per entry point,
goes into `artifacts/harnesses/TARGETS.md` before any harness is written. That
file is what the report cites when describing Track U coverage.

## Track U: recording the harness names

```yaml
track_u:
  targets: []
```

`track_u.targets` holds the harness directory names, written by the `harness`
phase and read by the `fuzz` phase when it checks per-harness coverage output.
No tool reads the list; it reaches behaviour through what the orchestrator
pastes into a sub-agent's context. The configuration validator checks its shape
and nothing else, so a name that does not correspond to a real harness is
accepted here and discovered during the fuzz phase.

Each harness must write its fuzzer output under
`artifacts/runs/$RUN_ID/u/<harness-name>/`. That is where the coverage sampler
looks: AFL++ `fuzzer_stats` there gives Track U its edge curve, and without it
Track U contributes nothing to the round's coverage verdict, so the loop decides
on Track K alone and can stop while these harnesses are still growing.

## Track U: the replay command

For each harness, `TARGETS.md` records the exact command that replays one input
against it, with `{input}` where the file path goes:

```
./build/parse_cfg {input}
```

The `poc` phase passes that string to `repro_ctl.py verify --cmd`. Without it a
Track U crash from that harness cannot be scored for reproduction rate, and the
crash stays blocked on the harness phase until the command is recorded.

## See also

- [Threat model](/gspwn/architecture/threat-model/) states the attacker each
  track assumes.
- [Scope and oracle](/gspwn/architecture/scope-and-oracle/) states what the
  pipeline detects and what it cannot.
- [Configuration keys](/gspwn/reference/configuration/) lists every value.
