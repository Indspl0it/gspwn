---
title: Attack surface
description: "The Track K surface measured from driver source. 34 escapes, 1372 control methods, 222 object classes, and the 531 commands where a kernel-side bug can be seen."
---

Every number on this page is derived from a checkout of
`NVIDIA/open-gpu-kernel-modules` at `610.57.04`, commit `e4a5faa`, together
with `libnvidia-container` and `nvidia-container-toolkit`. No GPU took part.

Three commands regenerate the inventories from a checkout:

| Tool | Output |
|---|---|
| [`ioctl_inventory.py`](/gspwn/architecture/components/ioctl-inventory/) | The escape and UVM commands, their parameter structs and their request numbers |
| [`ctrl_surface.py`](/gspwn/architecture/components/ctrl-surface/) | The RM control command space and its privilege classification |
| [`object_graph.py`](/gspwn/architecture/components/object-graph/) | The RM object allocation DAG and its chaining depth |

The records land under `artifacts/surface/`, which is not committed. The
platform-side detail behind the numbers is in the knowledgebase:
[RM control surface](/gspwn/knowledgebase/rm-control-surface/),
[Resource Manager object model](/gspwn/knowledgebase/rm-object-model/),
[container device access](/gspwn/knowledgebase/container-device-access/) and
[prior vulnerabilities](/gspwn/knowledgebase/prior-vulnerabilities/).

## The surface in one table

| Layer | Total | Reachable by an unprivileged tenant | Instrumented by KCOV |
|---|---|---|---|
| RM escapes on `/dev/nvidiactl` and `/dev/nvidiaN` | 34 dispatched | 33 (`RM_LOCKLESS_DIAGNOSTIC` is root-only) | Yes |
| RM control commands behind escape 0x2A | 1372 exported | 767 marked non-privileged | 531 of those have a kernel-side handler |
| RM object classes | 222 | 152 unprivileged, 147 reachable from the client root | Yes |
| UVM commands on `/dev/nvidia-uvm` | 39 | 39 | Yes |
| UVM tools commands on `/dev/nvidia-uvm-tools` | 7 | 7 | Yes |
| UVM test commands | 104 | Compiled out unless the module is built for test | Yes when present |

183 parameter struct sizes were measured by compiling the driver headers. None
were left unresolved, so every request number in the table is computed and not
estimated.

## Effort allocation across the control space

The control multiplexer holds the surface, and most of it is not where KASAN
can see a bug.

| Set | Count | Consequence |
|---|---|---|
| Exported control methods | 1372 | The full export table |
| Marked `NON_PRIVILEGED` | 767 | The flag word admits an unprivileged caller |
| Also marked `INTERNAL` | 23 | Rejected before the privilege check, so not reachable from an ioctl |
| Carrying `ROUTE_TO_PHYSICAL` with no local handler | 236 of the 767 | The parameter buffer crosses the RPC queue to GSP firmware |
| **Non-privileged with a kernel-side handler** | **531** | The set where a kernel memory-safety bug can exist and coverage can measure it |

531 is the number a round should be sized against. A campaign that reports
progress against 1372, or against the 2572 command numbers defined in the SDK
headers, is measuring against a denominator that includes firmware it cannot
instrument and internal commands it cannot call.

## Three ways to miscount this surface

Each of these was found by reading the enforcement code, and each inverts or
inflates a count if taken at face value.

| Trap | Mechanism | Effect if missed |
|---|---|---|
| An empty flag word means kernel-only | `RMCTRL_FLAGS_NONE` and `RMCTRL_FLAGS_KERNEL_PRIVILEGED` are both `0x0`, and `flags == 0` is rejected below `RS_PRIV_LEVEL_KERNEL` | 114 kernel-only commands read as unrestricted |
| `INTERNAL` outranks `NON_PRIVILEGED` | The `INTERNAL` check in `serverControl_ValidateCookie` runs first and returns `NV_ERR_NOT_SUPPORTED` for every ioctl caller | The reachable set overstates by 23 |
| Object privilege is not in Required Access Rights | All 222 `RS_ENTRY` records carry `RS_ACCESS_NONE`. The gate is `RS_FLAGS_ALLOC_*` in the Flags field | The whole class table reads as unprivileged |

## Object chaining decides whether any of it is reached

| Depth from the file descriptor | Classes |
|---|---|
| 1 | 3 |
| 2 | 22 |
| 3 | 45 |
| 4 | 151 |
| 5 | 1 |

151 of 222 classes sit at depth 4. A description set without resource chaining
reaches the 25 classes at depth 1 and 2 and stops. Three allocations open the
widest part of the tree.

```
open("/dev/nvidiactl")
  -> NV01_ROOT              param optional NvHandle
    -> NV01_DEVICE_0        param optional NV0080_ALLOC_PARAMETERS
      -> KEPLER_CHANNEL_GROUP_A | GF100_CHANNEL_GPFIFO | NV20_SUBDEVICE_0
```

| Parent | Classes unlocked | Unprivileged among them |
|---|---|---|
| NV01_DEVICE_0 | 197 | 130 |
| KEPLER_CHANNEL_GROUP_A | 80 | 78 |
| GF100_CHANNEL_GPFIFO | 67 | 66 |
| NV20_SUBDEVICE_0 | 54 | 39 |

Channel allocation returns the most per description authored and is the
hardest to model, because it needs a GPFIFO buffer and an address space object.

## Scope corrections the source supports

Four surfaces are reachable by the modelled attacker and were absent from the
[threat model](/gspwn/architecture/threat-model/) until this measurement. Each
is now named there. The evidence for each is below.

### NV04_DISPLAY_COMMON and 20 control commands

`NV04_DISPLAY_COMMON` (class 0x0073) carries `RS_FLAGS_ALLOC_NON_PRIVILEGED`
and hangs off `NV01_DEVICE_0`, so it is allocated over `/dev/nvidiactl` with no
display device node involved. The threat model excludes display by device node,
naming `/dev/nvidia-modeset` and `/dev/dri/*`, and that exclusion does not
reach this class.

| `NV0073` commands | Count |
|---|---|
| Total, all exported by `DispCommon` | 157 |
| Privileged | 105 |
| Kernel-only | 28 |
| Internal | 4 |
| Non-privileged and not internal | 20 |
| Of those, with a kernel-side handler | 4 |

`dispcmnCtrlCmdSystemExecuteAcpiMethod` (`0x00730120`) is among the four. Its
parameter struct carries two `NvP64` fields alongside separate input and output
size fields, which is the shape that produces length-confusion bugs. The same
parameter shape appears at the client level as
`cliresCtrlCmdSystemExecuteAcpiMethod` (`0x00000130`).

The display *channel* tree is closed. `NVC570_DISPLAY` and all 38 classes
below it carry `RS_FLAGS_ALLOC_PRIVILEGED`, and zero unprivileged classes sit
in that subtree. The exclusion holds there on the privilege flag, which is a
stronger argument than the device-node one and belongs in the threat model
next to it.

### NVSwitch nodes, reachable through the image environment

| Step | Evidence |
|---|---|
| `NVIDIA_NVSWITCH=enabled` injects `/dev/nvidia-nvswitchctl` and `/dev/nvidia-nvswitch*` | `internal/discover/nvswitch.go:25-35`, reached from `internal/modifier/cdi.go:142-144` |
| Environment device requests are honoured for unprivileged containers | `accept-nvidia-visible-devices-envvar-when-unprivileged` defaults to `true`, `api/config/v1/config.go:106` |
| `nvidia.ko` registers the nodes at module load, with no NVSwitch hardware required | `linux_nvswitch.c:1731-1747`, called from `nv.c:712` |
| Neither node checks privilege on open | `nvswitch_device_open` has no `capable()` call. `ctl_fops` has no `.open` member at all |
| Roughly a third of the device ioctl surface has no privilege gate | 38 plain `NVSWITCH_DEV_CMD_DISPATCH` against 82 `_PRIVILEGED` in `src/common/nvswitch/kernel/nvswitch.c` |
| The intended node mode is world read/write | `procfs_nvswitch.c:49` hardcodes `DeviceFileMode: 438` |

`/dev/nvidia-nvlink` is never injected. It appears in the toolkit only inside
`blockedPrefixes` at `pkg/nvcdi/management.go:141`, so it is out of reach.

The chain crosses the campaign's two-track split: the image supplier sets the
environment variable, which is the Track U attacker's control, and the
in-container process then issues the ioctls, which is the Track K attacker's.
Neither track alone describes it.

### Host root IPC endpoints

A `compute,utility` container receives three IPC endpoints, and two of them
speak to processes running as root on the host.

| Endpoint | Capability | Peer |
|---|---|---|
| `/var/run/nvidia-persistenced/socket` | `utility` | Host root daemon |
| `/var/run/nvidia-fabricmanager/socket` | `utility` | Host NVSwitch fabric manager |
| `/tmp/nvidia-mps`, or `CUDA_MPS_PIPE_DIRECTORY` | `compute` | Host MPS server |

### Container-driven host mknod

`NVIDIA_IMEX_CHANNELS` is read from the container image environment, and
`nvc.c:296-303` calls `nvidia_cap_imex_channel_mknod` once per requested
channel id while running as root on the host, unless
`disable-imex-channel-creation` is set. The kernel side creates no node itself
by default: `NVreg_CreateImexChannel0` defaults to 0, and the one
`device_create` in the driver tree forces mode 0666 when it is enabled.

## Prior art, settled

Two questions that phase prompts currently guess at.

| Question | Answer |
|---|---|
| Does upstream syzkaller carry NVIDIA descriptions | No. At commit `1e72964b`, the only `nvidia` match under `sys/linux/` is `typec_nvidia` in `auto.txt`, which belongs to the USB Type-C driver |
| Did Interrupt Labs publish theirs | No. Their July 2026 article describes writing them and names no repository |
| Does any public NVIDIA syzlang exist | Yes, one set: Moneta's vendored syzkaller tree, `github.com/yonsei-sslab/moneta`, 30 named `syz_ioctl_nvidia$*` variants |

`agents/describe.md` step 1 instructs the describe agent to import Interrupt
Labs' descriptions if published. They are not, so that step resolves to no
import available and should point at Moneta instead. Moneta's payloads are
untyped byte arrays, so they carry the escape numbering and not the parameter
structure, and they cover `/dev/nvidia-modeset`, which is out of scope here.

## Limits of the CVE record

61 CVEs were classified. The record fixes the layer and rarely the ioctl.

| Claim | Confidence |
|---|---|
| Which ioctl any historical CVE reached | Unknown for 59 of 61. Not to be manufactured |
| Whether a historical CVE is reachable from a `compute,utility` container | Asserted publicly for CVE-2025-23282 and CVE-2025-23332 only |
| UVM is over-represented in real bugs | Weak. One paper's eleven-bug sample plus five of 61 CVEs |
| The CWE distribution shows where bugs live | Weak. It shows where bugs get found, and NULL dereference is the cheapest class to notice |
| Two bulletins hold half the kernel-module CVEs | Verified, and a caution. Bulletins 5415 and 5452 are batch fixes with near-identical descriptions, so they may describe one audit of one file |

## Limits

| Limit | Detail |
|---|---|
| Chip gating is invisible | The class table spans generations. `gpuGetClassByClassId` decides at runtime which exist, and `config/machine.yaml` leaves `gpu_model` empty until provision runs |
| Privilege flags are necessary and not sufficient | Class constructors and control handlers carry further checks |
| GSP-routed commands are not measurable | 236 of the 767 non-privileged control commands cross the RPC queue, where KCOV cannot follow |
| The escape inventory is one driver version | Every number is tied to commit `e4a5faa`. The ABI moves between branches |

## Requires SUT

| Item | Reason |
|---|---|
| Which classes and control commands the installed part supports | Resolved at runtime against the real GPU |
| Whether the three-allocation prologue succeeds under the container capability set | Needs a running container against a real device node |
| Whether a container on this platform actually receives the NVSwitch nodes | Needs the deployed toolkit configuration as installed, beyond its documented defaults |
| Coverage attribution across the 531 kernel-side control commands | Needs an instrumented run |
