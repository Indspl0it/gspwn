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
