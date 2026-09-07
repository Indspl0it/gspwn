---
title: Scope and targets
description: Which device nodes and syscalls Track K covers, which Track U entry points qualify, and how each list is set.
---

Scope is a configuration decision on Track K and a source-analysis decision on
Track U. Both are recorded before the `describe` phase models anything.

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
    - "ioctl$NVKMS_*"
    - "ioctl$DRM_NVIDIA_*"
    - "mmap$dri*"
    - "poll$dri*"
```

`ioctl$NVKMS_*` and `ioctl$DRM_NVIDIA_*` have their own patterns because every
variant is named for an `NvKmsIoctlCommand` enumerator or a `DRM_NVIDIA_`
command number macro, neither of which matches `NV_*`.

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
| `/dev/nvidia-modeset` | Yes | Injected by the CDI generator with no capability check |
| `/dev/dri/card*` and `/dev/dri/renderD*` | Yes | Injected by the CDI generator with no capability check. Withheld on the legacy path alone |

The injection path decides the modeset node and the DRM nodes. The CDI
generator lists the modeset node beside the other control nodes and applies no
capability test, and it adds every `/dev/dri` node found for the GPU's PCI bus
id. `internal/info/auto.go:89` resolves the default mode `auto` to `jit-cdi`,
so a stock instance takes that path and its tenant holds both.

`NVIDIA_DRIVER_CAPABILITIES` gates the legacy path, which withholds the modeset
node unless the `display` value is set and yields no `/dev/dri` and no
`nvidia-drm` nodes under the `compute,utility` default that CUDA images
request. That exclusion is a property of a deployment pinned to `legacy` mode.
The
[threat model](/gspwn/architecture/threat-model/#device-node-injection-paths)
carries both mechanisms with their source citations.

The DRM nodes are inside the modelled set. `surface/entry-points.json` records
`nv_drm_fops` with `tenant_surface` true and `modelled` true, and
`tools/trace2seed.py` converts a traced `/dev/dri/cardN` open to
`openat$dri_card` and a `/dev/dri/renderDN` open to `openat$dri_render`.
`nvkms_fops`, for `/dev/nvidia-modeset`, is recorded `tenant_surface` true and
`modelled` false.

A seed referencing an unmodelled node fails the syzkaller-parse gate, because
no description declares a call against it.

Widening scope requires a decision recorded in the
[threat model](/gspwn/architecture/threat-model/) before the `describe`
sub-agent models the added surface.

## Track K: modelling priority

`agents/describe.md` step 4 fixes the order in which the `describe` sub-agent
corrects an unexplored surface. The generated baseline already declares every
target, so the phase's work is correction and constraint.

| Order | Surface | Rationale |
|---|---|---|
| a | Object lifecycle: the RM alloc escape, the free escape and the device-open path | Nothing is exercised until a client handle exists |
| b | The `NV_ESC_IOCTL_XFER_CMD` constraint set | The wrapper re-enters the same dispatch switch, so until it is fenced every measurement below it describes a corpus that can leave the scope |
| c | Control commands by owning class, ranked by the `rank` field of `surface/rm-control-rank.json` | One correct allocation chain makes a class's whole command set emittable: one allocation reaches 91 commands, three reach 315 and fifteen reach 455 |
| d | Within a class, that class's `[history ...]` items | NVB0CC (ProfilerBase) and NV83DE (KernelSMDebuggerSession) carry most of the directly targetable ones |
| e | UVM ioctls, ranked with the classes above on their history weight | Flat structs make them cheap to correct, and cheapness is no evidence of low yield |
| f | Everything no worklist item names, from `surface_cov.py gaps --stage corpus` | The remainder |

Two kinds of work item outrank that order. From round 2 on, a worklist
`[finding crash-NNNN]` item comes ahead of it inside its own subsystem. A
`[history CVE-YYYY-NNNNN]` item ranks alongside it in every round and replaces
no part of it.

16 of the 531 targetable control commands enforce a capability inside the
handler body that the RMCTRL flag word does not show, and `surface_cov.py
report` prints that count as a floor. Read a command's handler for an
`rmclientIsCapableOrAdmin` or `osIsAdministrator` call before spending a round
on it. [Attack surface](/gspwn/architecture/attack-surface/) carries the
derivation of the 531 and of the groups excluded from it.

Handles are chained with syzkaller resources so generated programs build valid
object trees: the root client handle is produced by the client allocation and
consumed by every subsequent allocate, control and free call. A description set
without resource chaining generates programs that fail at the first handle
check, which shows up in a smoke run as uniform early-out.

## Track U: choosing entry points

The `harness` sub-agent enumerates candidates from the checked-out source and
ranks them by how directly attacker-controlled bytes reach them. That ranking
decides the harness set, and `track_u.targets` records the result afterwards.

- `libnvidia-container`, written in C, is the primary target. It carries the
  memory-safety surface: config parsing, ldcache handling, ELF and library
  inspection, mount and path construction, capability and option string
  parsing.
- `nvidia-container-toolkit`, written in Go, is the secondary target. It
  carries a panic and denial-of-service surface only: OCI `config.json`
  handling, CDI spec parsing, environment variable processing.

Go is memory-safe. A Track U harness against the Go toolkit does not support a
memory-corruption claim.

Symlink time-of-check-to-time-of-use races and mount-escape logic bugs are out
of scope and recorded in the report as future work, because fuzzing finds them
poorly. Seven of the ten disclosed Container Toolkit CVEs are in that class,
and the harnesses target the parsing and path construction underneath those
races, which is a smaller claim.

One property qualifies a candidate, and two more rank it.

| Property | Effect |
|---|---|
| A container image or OCI config can influence its input | Required. Only a function an image can reach qualifies as a Track U target |
| It takes a buffer and a length, or a path | Preferred. It harnesses cleanly |
| It can be called without a live GPU and without a real container | Preferred, for the same reason |

The ranked list, with a one-line reachability justification per entry point,
goes into `harnesses/TARGETS.md` before any harness is written. The
report cites that file when describing Track U coverage.

## Track U: recording the harness names

`track_u.targets` holds the harness directory names, written by the `harness`
phase and read by the `fuzz` phase when it checks per-harness coverage output.
The shipped value carries six:

```yaml
track_u:
  targets:
    - fuzz_ldcache
    - fuzz_path_resolve
    - fuzz_dsl_evaluate
    - fuzz_options_parse
    - fuzz_imex_channels
    - fuzz_path_join
```

The same six names appear in four places, and a target added to one and not
the others is built and never run, or run and never built.

| Source | Construct |
|---|---|
| `config/campaign.yaml` | `track_u.targets` |
| `harnesses/run_all.sh` | the `C_TARGETS` array |
| `harnesses/TARGETS.md` | the Harness column of the ranked entry-point table |
| `harnesses/` | the directories holding a `build.sh` |

Two directories under `harnesses/` carry no target and are declared exclusions:
`common`, a shared helper tree holding the `build_common.sh` that every
harness `build.sh` sources, and `go_cudacompat_elf`, whose `go test -fuzz`
writes no `fuzzer_stats` and so produces no coverage output for the sampler to
read. Check the four lists against each other:

```
python3 tools/regression_check.py harnesses
```

```
harnesses: 6 target(s) across 4 source(s), 2 declared exclusion(s)
```

It exits non-zero and names the offending line when a target is missing from
one of the four, or when a directory holds no `build.sh` and appears in no
exclusion.

No tool reads `track_u.targets` for behaviour. It reaches the campaign through
what the orchestrator pastes into a sub-agent's context. The configuration
validator checks its shape alone, so a name that corresponds to no real
harness is accepted here and discovered during the fuzz phase.

Each harness must write its fuzzer output under
`artifacts/runs/$RUN_ID/u/<harness-name>/`. That is where the coverage sampler
looks: AFL++ `fuzzer_stats` there gives Track U its edge curve, and without it
Track U contributes nothing to the round's coverage verdict, so the loop decides
on Track K alone and can stop while these harnesses are still growing.

## Track U: the replay command

For each harness, `TARGETS.md` records the exact command that replays one input
against it, with `{input}` where the file path goes and every path written
relative to the repository root:

```
harnesses/fuzz_ldcache/build/fuzz_ldcache {input}
```

The six C binaries are libFuzzer or AFL++ driver targets, and both accept a
file path as a single positional argument, which runs the input once and exits.

The `poc` phase passes that string to `repro_ctl.py verify --track u --cmd`.
Without it a Track U crash from that harness cannot be scored for reproduction
rate, and the crash stays blocked on the harness phase until the command is
recorded.

## See also

- [Threat model](/gspwn/architecture/threat-model/) states the attacker each
  track assumes.
- [Scope and oracle](/gspwn/architecture/scope-and-oracle/) states what the
  pipeline detects and what it cannot.
- [Configuration keys](/gspwn/reference/configuration/) lists every value.
