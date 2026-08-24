# Learnings

What the campaigns have established about the target: ABI facts, driver
behaviour, tooling quirks. Carried across every campaign, on every box.

Audience: the `describe`, `seeds` and `rca` agents of later rounds. Write for
someone who has the source open and does not have your context.

PUBLIC REPO: ABI and behaviour only, never findings. A specific vulnerability
belongs in the crash registry and its research record, both gitignored.

Appended by `tools/knowledge_ctl.py note --kind learning`. Do not hand-edit:
the tool timestamps and locks, and hand-edits are how the format rots.

## 2026-08-15T07:36:41+00:00 — provision
Tags: gpu, scope
open-gpu-kernel-modules supports Turing and later only: those carry the GSP
microcontroller the open modules depend on. Volta and earlier run the
proprietary driver, whose Resource Manager ships as a prebuilt binary that
KCOV cannot instrument, so coverage-guided kernel fuzzing does not work there
at all. Check the instance family before provisioning, not after building.

## 2026-08-15T07:36:41+00:00 — provision
Tags: ec2, crashlog
EC2 has no pstore. A hard hang that never reaches kdump leaves nothing on
disk, and the only remaining record is the serial console
(ec2:GetConsoleOutput). The IAM instance profile has to be attached at launch
for that to be reachable when it is needed.

## 2026-08-15T07:36:41+00:00 — describe
Tags: abi, scope
NVIDIA_DRIVER_CAPABILITIES gates which device nodes a container receives. The
default that CUDA images request, compute,utility, yields no /dev/dri and no
nvidia-drm nodes; those appear only for the graphics or display capabilities.
Any ioctl surface reachable only through them is outside a default tenant's
reach.

## 2026-08-15T07:36:41+00:00 — describe
Tags: abi, uvm
UVM has its own ioctl numbering scheme and does not follow the convention the
RM escapes use. Derive it from kernel-open/nvidia-uvm/uvm_ioctl.h directly;
deriving it from nv-ioctl-numbers.h produces descriptions that compile, run,
and never reach the driver.

## 2026-08-15T07:36:42+00:00 — triage
Tags: xid, noise
A fuzzer produces illegal instructions and bad pointers by design, and the
driver reports exactly that as Xid 13 and 31. They are the campaign's noise
floor, not findings. Harvesting every NVRM line as a crash buries the
interesting entries and makes any crash count meaningless.

## 2026-08-15T07:36:42+00:00 — fuzz
Tags: gpu, recovery
A guest reboot does not power-cycle a passthrough GPU, so a card that has
fallen off the bus does not come back from one. The recovery ladder is
nvidia-smi -r, then reloading the modules, then a guest reboot, and only a
stop/start moves the instance to different hardware.

## 2026-08-15T07:36:42+00:00 — refine
Tags: coverage, gsp
GSP firmware is not instrumented, so an edge count measures kernel-side
reachable code and never total driver coverage. On a GSP-based GPU a large
part of the Resource Manager runs where KCOV cannot see it, and a coverage
plateau says nothing about that region.

## 2026-08-21T19:44:19+00:00 — describe
Tags: abi, rmapi, object-model
The RM allocation DAG is declared in src/nvidia/src/kernel/rmapi/resource_list.h as one RS_ENTRY record per allocatable class: external class number, legal parents, alloc param struct, and privilege flags. It is the machine-readable source for syzlang resource chaining and needs no GPU to read. 222 records, and 151 of them sit at depth 4 from the file descriptor, so a description set without chaining reaches only the 25 classes at depth 1 and 2.

## 2026-08-21T19:44:19+00:00 — describe
Tags: abi, rmapi, privilege
Allocation privilege in resource_list.h lives in the Flags field as RS_FLAGS_ALLOC_NON_PRIVILEGED, RS_FLAGS_ALLOC_PRIVILEGED or RS_FLAGS_ALLOC_KERNEL_PRIVILEGED. It does not live in Required Access Rights: every one of the 222 records carries RS_ACCESS_NONE there, so a reader keyed on that field reports the whole table as reachable. The Flags split is 152 unprivileged, 62 privileged, 5 kernel-only, 3 unmarked.

## 2026-08-21T19:44:19+00:00 — describe
Tags: abi, parsing
Two inconsistencies in resource_list.h break a naive parser. 15 records label the last field Required Access Right without the plural. 5 records declare RS_ANY_PARENT where the rest declare RS_LIST(classId(...)), and those five are the event and context-dma classes that attach under any allocated object.

## 2026-08-21T21:23:03+00:00 — describe
The RMCTRL privilege flag is necessary and not sufficient. 16 of the 531 control commands that are NON_PRIVILEGED with a kernel-side handler call rmclientIsCapableOrAdmin, rmclientIsCapable or rmclientIsAdmin inside the handler body, which the flag word does not show. subdeviceCtrlCmdGpuSetFabricAddr (0x2080016f) is flagged NON_PRIVILEGED and then checks NV_RM_CAP_EXT_FABRIC_MGMT. The 16 is a floor: the scan attributes a call to its enclosing function, so a check inside a helper the handler calls is invisible. Read the handler body before spending a round on any command the flag table calls reachable. Others in the set: the NVC637 gisubscription ExecPartitions family, NV2080 GpuGetPartitions and GpuSetPartitions, NV2080 GpuGetPids and GpuGetPidInfo, NV00F8 memoryfabricCtrlCmdDescribe, NVCBCA kccuapiCtrlCmdSubscribe.

## 2026-08-24T10:53:32+00:00 — describe
Tags: nvidia_uvm, syzlang, ordering
The UVM driver states its call-ordering constraint per command in the route macro name in kernel-open/nvidia-uvm/uvm.c: UVM_ROUTE_CMD_STACK_INIT_CHECK and UVM_ROUTE_CMD_ALLOC_INIT_CHECK refuse the call until a prior UVM_INITIALIZE has made the file descriptor a VA space, and UVM_ROUTE_CMD_STACK_NO_INIT_CHECK does not. The split is 34, 2 and 2 over the 38 macro-routed commands on driver 610.57.04. UVM_DEINITIALIZE is routed by a bare case label and not by the macro, giving 39 commands on the node, of which 36 require an initialised descriptor and 3 do not. tools/ioctl_inventory.py already records the requirement per command as requires_initialized_fd, and surface/ioctl-inventory.json already carries it; the emitter is what does not read it. A description set that gives every UVM command the same file descriptor resource reaches at most those 3 unguarded commands by generation. The constraint is expressible as a syzkaller resource subtype and needs no runtime capture to recover.
## 2026-08-24T10:58:01+00:00 — describe
syzkaller ships no syz-compile binary. Compiling a syzlang set is ast.ParseGlob then compiler.Compile from pkg/compiler, and compiler.Compile short-circuits on a nil consts map after the type-check pass alone, reporting a clean compile over an empty program. A non-nil map, even an empty one, is required for the semantic checker and genSyscalls to run. pkg/compiler/types.go also prepends 6 syz_builtinN pseudo-syscalls to every compile, so a reported syscall count is always 6 above the description set own count.

## 2026-08-24T15:00:40+00:00 — provision
Tags: container, threat-model, cdi
The NVIDIA container stack has two injection paths and they hand a container different device nodes, so a tenant surface stated without naming the path states nothing. nvidia-container-runtime, reached by --runtime=nvidia and by both the ECS and EKS GPU AMIs, resolves mode auto to jit-cdi from toolkit 1.18.0 onward and injects /dev/nvidia-modeset and every /dev/dri node for the GPU PCI bus id with no capability check at all; internal/platform-support/dgpu/nvml.go:48-55 adds them and internal/edits/device.go:76 grants rwm. nvidia-container-runtime-hook, which Docker Engine 29.1.x and older injects for the --gpus flag, pins its own default to legacy at cmd/nvidia-container-runtime-hook/hook_config.go:120-123, and the legacy libnvidia-container path withholds the modeset node without the display capability at src/nvc_mount.c:786 and never references /dev/dri at all. Docker 29.2.0 and later reads a CDI specification for --gpus and lands on the CDI device set again. No AWS GPU AMI pins mode; the toolkit packages write mode = auto at install time. Measuring a tenant surface with docker run --gpus all on an older Docker therefore reports the legacy device set, which is not the set the deployment will see.

## 2026-08-24T15:34:47+00:00 — provision
Tags: container, toolkit, provisioning
The container runtime that injects GPU device nodes is a separate installation from the GPU driver, and installing the driver alone leaves a machine unable to start a GPU container at all. A distribution docker package provides no nvidia runtime. The four packages nvidia-container-toolkit, nvidia-container-toolkit-base, libnvidia-container-tools and libnvidia-container1 come from NVIDIA's own apt repository and are released together, so pin all four to one version and record it: the injection path a container takes depends on the toolkit version, and a campaign that did not record it cannot defend its own reachable-surface denominator afterwards. Registration is a second step after the install, nvidia-ctk runtime configure --runtime=docker followed by a daemon restart, and without it --runtime=nvidia names a runtime docker does not know. Any measurement of what a container receives therefore belongs after both steps in the provisioning order.

## 2026-08-24T17:16:10+00:00 — provision
Tags: provision, toolchain, dependencies
A host dependency that the development machine already carries is invisible to every offline check, because the checks run on the machine that carries it. Nothing in the documented provisioning path installed a Go toolchain, and syzkaller builds on the host and is written in Go, so the documented install would have stopped at the syzkaller build on a fresh instance. The compile gate had passed here throughout, which is exactly what hid it. The check that finds this class is mechanical: enumerate every external binary the tools and harness scripts invoke, by reading the subprocess argument lists and the shell command positions, then compare that set against the packages the install documentation names. Two gaps came out of one such pass, the NVIDIA container runtime and the Go toolchain, and both would have cost metered instance time to diagnose. Binaries reached only inside a container are not gaps: the Track U harnesses build inside the aflplusplus image named in config/campaign.yaml, so afl-clang-fast and clang need no host package.
