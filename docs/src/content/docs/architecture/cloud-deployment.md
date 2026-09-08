---
title: Cloud deployment
description: The instance, storage, IAM and purchasing constraints for running gspwn on AWS, and the crash-capture path that replaces pstore on EC2.
---

gspwn requires a machine it can panic repeatedly, a GPU the open kernel modules
support, and a capture path for the final kernel log output when the machine
hangs without reaching disk.

The operational sequence is in [Cloud runbook](/gspwn/guides/cloud-runbook/).

## Topology

```mermaid
flowchart TB
  subgraph INST["EC2 instance"]
    GPU["NVIDIA GPU<br/>Turing or later"]
    KERN["instrumented kernel<br/>KASAN + KCOV"]
    ROOT["root volume<br/>kernel tree, /var/crash"]
    ART["artifacts volume<br/>corpus, coverage, harvests"]
  end
  IAM["IAM instance profile<br/>ec2:GetConsoleOutput only"] -->|"attached at launch"| INST
  INST -->|"hard hang, nothing on disk"| CONSOLE["EC2 serial console"]
  IAM -->|"authorises the read"| CONSOLE
  CONSOLE --> HV["crashlog_ctl.py harvest<br/>console-output.log"]
  KERN -->|"panic"| KD["kdump to /var/crash"]
  KD --> HV
  HV --> ART
  ROOT -.->|"lost on instance replacement"| GONE(["gone"])
  ART -.->|"detach and reattach"| KEEP(["survives instance loss"])
  INST -->|"AMI after provision + build"| IMG[("provisioned image<br/>skips hours of rebuild")]
```

## Instance constraints

Three constraints narrow the instance choice.

| Constraint | Required value | Reason |
|---|---|---|
| GPU generation | Turing or later | `open-gpu-kernel-modules` supports only cards carrying the GSP microcontroller. Volta and earlier run the proprietary driver, whose Resource Manager ships as a prebuilt binary KCOV cannot instrument |
| CPU architecture | x86-64 | `campaign_ctl.py gen-config` writes `"target": "linux/amd64"` into the syz-manager configuration |
| Instance size | The smallest usable size in a family | The campaign exercises the driver's ioctl surface. `track_k.procs` ships at 2, capped against a 32 GB RAM budget, and `track_k.memory_max` caps syz-manager's systemd cgroup at 12G |

The GPU families AWS offers fall into three groups against those constraints.

| Family | GPU | Microarchitecture | Usable |
|---|---|---|---|
| `g4dn` | T4 | Turing | Yes |
| `g5` | A10G | Ampere | Yes |
| `g6`, `gr6` | L4 | Ada Lovelace | Yes |
| `g6e` | L40S | Ada Lovelace | Yes |
| `p4d`, `p4de` | A100 | Ampere | Yes, at multi-GPU sizes |
| `p5`, `p5e`, `p5en` | H100, H200 | Hopper | Yes, at multi-GPU sizes |
| `p3`, `p3dn` | V100 | Volta | No. The card carries no GSP, and the open modules do not support it |
| `g5g` | T4G | Turing | No. Graviton, so arm64 |
| `g4ad` | Radeon Pro V520 | AMD | No. Not an NVIDIA driver |

The `p4` and `p5` families come only in multi-GPU sizes. A multi-GPU box does
not change what is fuzzed. Xid classification strips the PCI bus id from the
crash identity, so the same driver bug on two cards registers as one bug.

## Container runtime and the injection path

The threat model is a container tenant, so the device nodes a container receives
on this instance decide what the campaign is entitled to call reachable. A
capability here is one of the comma-separated values in
`NVIDIA_DRIVER_CAPABILITIES`, which the container image sets.

| Injection path | Reached by | `/dev/nvidia-modeset` | `/dev/dri` |
|---|---|---|---|
| jit-cdi | `--runtime=nvidia`, and the ECS and EKS GPU AMIs | Injected with no capability check | Injected with no capability check, every node found for the GPU's PCI bus id |
| legacy | The `nvidia-container-runtime-hook` prestart hook Docker Engine 29.1.x and older inject for `--gpus` | Withheld without the `display` capability | Withheld without `display` or `graphics` |

Docker Engine 29.2.0 and later read `/var/run/cdi/nvidia.yaml` for `--gpus`,
which restores the CDI device set.

Four settings put an instance on the jit-cdi path and keep it there.

| Setting | Value |
|---|---|
| AMI | Any Debian-family image. No AWS GPU AMI pins the toolkit mode |
| Toolkit packages | `nvidia-container-toolkit`, `nvidia-container-toolkit-base`, `libnvidia-container-tools` and `libnvidia-container1` from NVIDIA's repository, all four at one pinned version, recorded in `config/machine.yaml` as `container_toolkit_version` |
| Runtime registration | `nvidia-ctk runtime configure --runtime=docker`, then `systemctl restart docker` |
| Confirmation | `verify_tenant_surface.py runtime-mode` before the campaign, and `verify_tenant_surface.py measure` at the `provision` gate |

The toolkit packages write `mode = auto` at install time, and
`internal/info/auto.go:89` resolves that to jit-cdi on an NVML platform from
toolkit 1.18.0 onward, so a stock instance takes the first path. The recorded
tenant surface assumes it. An instance on the legacy path holds a smaller
device set than the 852-target denominator covers, and the campaign would
report coverage against surface no tenant on that instance can reach.

## Region and quota

Availability of these families moves between regions and over time, so it is
queried against the account before a campaign is planned. GPU instances also
need a service quota granted before launch, per region and per family. A new
account commonly holds a quota of 0 for them, and the increase request takes
time to approve, which puts a lead time in front of any campaign window.

## Storage

Two volumes split the machine, and only the second one outlives it.

| Volume | Holds | Sized for | Survives instance replacement |
|---|---|---|---|
| Root | The kernel source tree, the build output, `/var/crash`, the OS | A full kernel build plus several kdump dumps | No |
| `artifacts/` | The corpus, the coverage series, the harvested crash logs, the reproducers | The campaign's evidence | Yes, by detach and reattach |

Without the split, everything the pipeline writes goes to one filesystem, and
a full disk stops the fuzzer, the sampler and every state write at the same
moment. kdump writes hundreds of megabytes per panic, and this pipeline panics
by design.

| Mechanism | Behaviour |
|---|---|
| `loop.min_free_disk_gb`, 20 as shipped | The tools warn below the floor. 0 disables the check |
| Every coverage sample | Records free space in its row |
| `crashlog_ctl.py prune --keep N` | The one command that reclaims harvest space. It deletes the oldest harvest directories beyond the newest N, default 10 |

Space is reclaimed only by that command. Harvested logs are evidence.

## Purchasing model

Use on-demand for the campaign. Spot is defensible for `provision` and `build`,
which produce an AMI and can be re-run.

| Affected by a spot interruption | Recoverable |
|---|---|
| The campaign window | Yes. The deadline is on disk and reconstructible, so the run resumes bounded |
| The coverage curve's continuity | Yes. The gap presents as a counter reset, which the accumulation model absorbs |
| The measured hours | Partially. Billed from the samples that exist, which under-reports the run |
| Anything on instance store | No |
| A reproducer verification in flight | Yes. Resolved as void or as a weak hit on the next invocation |

The pipeline does not distinguish a spot reclaim from a panic, so a
spot-interrupted round measures a shorter run than it configured and its
verdict rests on less data.

## Termination protection

Enable termination protection. The instance panics, hangs and reboots by
design, so an instance reporting an unhealthy status is in its normal operating
state.

## IAM instance profile

One permission:

```json
{"Version": "2012-10-17",
 "Statement": [{"Effect": "Allow",
                "Action": "ec2:GetConsoleOutput",
                "Resource": "*"}]}
```

`crashlog_ctl.py harvest` calls that action on EC2. Attach the profile at
launch. The action is needed after a hard hang, when attaching a profile to
the running instance is no longer practical.

Nothing else in the pipeline calls an AWS API, and nothing needs write access.
A broader role places wider credentials on a machine that is crashed by hostile
input by design. Never place long-lived access keys on the instance.

## Serial console capture

pstore is the kernel's persistent-store subsystem, which writes the final log
output to a backend that survives a reboot. On bare metal the backend is
ramoops, a reserved region of main memory. EC2 provides neither.

| Failure mode | Captured by | Available on EC2 |
|---|---|---|
| A panic that reaches the crash kernel | kdump, to `/var/crash` | Yes |
| A hard hang, where the machine stops before reaching the crash kernel | The serial console, through `ec2:GetConsoleOutput` | Yes, with the instance profile attached |
| Either, on bare metal | pstore or ramoops | No |

`crashlog_ctl.py setup` skips pstore on EC2 and reports that it did.
`crashlog_ctl.py verify` fails when the `aws` CLI is absent, because without it
the fallback capture path does not exist.

`aws` and `nvidia-ctk` are the two entries in `HOST_BINARIES` in
`tools/orchestrator_ctl.py` that no deployment universally needs. The other six
are `go`, `docker`, `gcc`, `make`, `git` and `nvidia-smi`.
`orchestrator_ctl.py preflight` resolves all eight against PATH and reports the
two conditional ones separately, because an absent one reads differently on
EC2 than on bare metal.

## Snapshot after provision and build

`provision` and `build` run once per machine and cost hours. Create an AMI once
both gates have passed.

Record in the image description what it contains. `config/machine.yaml` holds
`kernel_version`, `driver_branch`, `instrumentation_rung` and
`syzkaller_commit`, `artifacts/builds/manifest.json` holds the clone commits
and the gcc version, and the report cites both.

An image taken with `aws ec2 create-image --no-reboot` is crash-consistent.
Stop the instance first when the state file matters.

Three things do not travel in an image and are re-checked on every relaunch:

| Check | Command |
|---|---|
| The instance profile is attached | `aws ec2 get-console-output --instance-id <id> --latest` |
| The state file matches what is expected | `python3 tools/pipeline_ctl.py show` |
| The spend ledger reflects prior campaigns | `python3 tools/pipeline_ctl.py round-show` |

## GPU recovery

A card that has fallen off the bus, Xid 79, leaves the fuzzer running against
nothing and the coverage curve flat. `coverage_ctl.py gpu-health` probes with
`nvidia-smi` and reports one of `ok`, `dead`, `hung`, `missing` or `error`.
Anything other than `ok` downgrades the plateau verdict to `unknown`, so the
loop stops.

| Step | Action | Recovers a passthrough GPU |
|---|---|---|
| 1 | `sudo nvidia-smi -r` | Sometimes |
| 2 | Unload and reload the modules | Sometimes |
| 3 | A guest reboot | Sometimes. A guest reboot does not power-cycle a passthrough GPU |
| 4 | An instance stop and start from the console, which moves the instance to different hardware | Yes. Nothing in the repository can do this |

The probe reports and attempts no recovery:

```
GPU: dead (nvidia-smi exit 255: Unable to determine the device handle for GPU 0000:00:1E.0: Unknown Error)
A plateau verdict will read 'unknown' while the GPU is in this state, so the loop stops without recording a plateau the fuzzer did not actually reach.
```

## Cost

The caps in `config/campaign.yaml` count machine time and reach no currency
figure, as [Spend accounting](/gspwn/architecture/spend-accounting/) sets out.
Watch real money in the AWS console, and set a budget alert independently of
anything here.

## See also

- [Cloud runbook](/gspwn/guides/cloud-runbook/)
- [Disk and crash logs](/gspwn/guides/disk-and-crash-logs/)
- [Requirements](/gspwn/getting-started/requirements/)
