---
title: Cloud runbook
description: The operational sequence on an AWS instance, from launch to a reusable image.
---

Operations on a cloud instance run in the order below. Each step states its
command, what a passing run prints, and what to do when it fails. The instance,
storage and IAM choices are derived in
[Cloud deployment](/gspwn/architecture/cloud-deployment/).

The steps up to and including step 11 are the `provision` phase on EC2. Step 12
is the `build` phase. `agents/provision.md` holds the gate the phase is marked
`done` against.

## 1. Launch

Launch a GPU instance to this specification.

| Item | Value |
|---|---|
| GPU | Turing or later |
| AMI | Ubuntu or Debian-family |
| Root volume | Large enough for the kernel build tree |
| Second volume | Mounted for `artifacts/` |
| IAM instance profile | `ec2:GetConsoleOutput` and nothing else |
| Termination protection | Enabled |

Attach the instance profile at launch. Console output is reached after a hard
hang, which is the moment an unattached profile cannot be fixed from inside the
instance.

## 2. Confirm the environment is detected

```
python3 -c "import sys; sys.path.insert(0,'tools'); import crashlog_ctl; print(crashlog_ctl.detect_env())"
```

```
ec2
```

Detection queries `http://169.254.169.254/latest/meta-data/instance-id` with a
two-second timeout, preferring IMDSv2.

Any other answer means the metadata service did not respond. Every
`crashlog_ctl.py` subcommand accepts `--env ec2` to override the detection, and
`--env auto` runs it again.

## 3. Install the baseline driver

On EC2, install the NVIDIA driver from the distribution's non-free repositories
before cloning the source trees. Step 6 reads GPU model and GSP firmware facts
from `nvidia-smi`, and those facts go into `config/machine.yaml` and
`artifacts/builds/manifest.json`.

```
sudo apt-get update
sudo apt-get install -y nvidia-driver
nvidia-smi --query-gpu=name --format=csv,noheader
```

`nvidia-smi` prints the GPU model on one line. An error from `nvidia-smi` means
the module did not load, and the rest of this runbook depends on it.

Secure Boot is skipped on EC2, because Nitro instances have none by default.
`config/machine.yaml` `secure_boot` stays empty there.

## 4. Install the AWS CLI

```
sudo apt-get install -y awscli
aws ec2 get-console-output --instance-id "$(curl -s http://169.254.169.254/latest/meta-data/instance-id)" --latest --output text | head
```

The command prints the head of the console log. An `AccessDenied` response
means the instance profile from step 1 is absent or lacks
`ec2:GetConsoleOutput`.

`crashlog_ctl.py verify` fails without the CLI, because hard-hang capture on
EC2 is the console output. Run the call once by hand here, before a hang
depends on it.

## 5. Grant passwordless sudo and clear the preflight

Crash harvesting after a panic runs `sudo -n`, and campaign installs and the
coverage sampler need root from a headless session that cannot answer a
password prompt. Write `/etc/sudoers.d/gspwn` with `visudo -f`, which validates
the file before installing it:

```
<agent-user> ALL=(root) NOPASSWD: /usr/bin/python3 /path/to/repo/tools/*.py
```

Those scripts must be unwritable by that user, or the rule grants unrestricted
root. Keep the repository root-owned and give the agent user read and execute.

```
python3 tools/orchestrator_ctl.py preflight
```

A passing run ends:

```
preflight clean
```

It checks the configuration, `orchestrator.command`, `sudo -n`, the host
binaries on `PATH`, free disk against `loop.min_free_disk_gb`, and the pairing
of `orchestrator.resume_command` with `orchestrator.session_transcript_glob`.
On a failure it exits 1 and lists one line per problem. A failing preflight is
a blocked `provision` gate.

## 6. Record the machine facts

Fill `config/machine.yaml` from this instance.

| Key | Source on EC2 |
|---|---|
| `distro` | the `ID` field of `/etc/os-release` |
| `environment` | `ec2`, from step 2 |
| `gpu_model` | `nvidia-smi --query-gpu=name --format=csv,noheader` |
| `secure_boot` | left empty; Nitro has none |
| `kernel_version` | the kernel step 12 builds |
| `driver_branch` | the `open-gpu-kernel-modules` release tag checked out |
| `container_toolkit_version` | the version pinned in step 7 |
| `gsp_firmware` | the firmware line of `nvidia-smi -q` |
| `syzkaller_commit` | the syzkaller checkout |
| `instrumentation_rung` | 1 for full KASAN and KCOV, 2 for KCOV-only modules, 3 for uninstrumented modules |
| `paths.workdir` | `artifacts`, repository-relative |

`instrumentation_rung` starts at 0, which records that the rung is undecided.
The `report` phase cites every one of these.

## 7. Install and register the container runtime

`docker.io` from the distribution provides no `nvidia` runtime. Install the
toolkit from NVIDIA's repository, pinned, and register it, following
[Installation](/gspwn/getting-started/installation/) step 5. Record the pinned
version in `config/machine.yaml` as `container_toolkit_version`. Then confirm
the path this instance resolved:

```
python3 tools/verify_tenant_surface.py runtime-mode
```

`runtime-mode` always exits 0 and prints the mode it read together with the
file it read it from. No AWS GPU AMI pins the mode, and the toolkit packages
write `mode = auto` at install time, so a stock instance resolves to jit-cdi.

A `legacy` verdict is a blocked gate. The legacy path hands a container fewer
device nodes than the recorded tenant surface, so step 9 would report
`MODELLED AND NOT REACHABLE` and exit 1 for a reason belonging to this step.
Record the verdict here, before running `measure`.

## 8. Confirm the driver checkout matches the recorded branch

Clone the five source trees first, following
[Installation](/gspwn/getting-started/installation/) step 6, and check
`open-gpu-kernel-modules` out at the release tag matching the driver that will
run:

```
git -C artifacts/src/open-gpu-kernel-modules tag --sort=-creatordate | head
```

The `describe` and `seeds` phases derive escape numbers, parameter struct
sizes, control command numbers and class privilege flags from that checkout. A
checkout that disagrees with the running driver produces descriptions that
compile, run, and model a different release.

```
python3 tools/surface_verify.py show
python3 tools/surface_verify.py check --no-running
```

`show` reaches no verdict and always exits 0. Confirm it lists both the
checkout version and `config/machine.yaml` `driver_branch`, so `check` has two
sources to compare.

| Exit from `check --no-running` | Meaning | Action |
|---|---|---|
| 0 | Every answering source agrees with every other. The line names the source count and the pairwise comparison count | Continue |
| 3 | A pair disagrees. The line names which two and what each carries | Blocked gate. Check out the matching release tag |
| 4 | Fewer than two version sources answered | Blocked gate. Fill in `driver_branch` |

`--no-running` skips the loaded-driver comparison, which is correct here
because the driver is not loaded at provision time. A wrong tag caught here
costs a re-checkout; caught two phases later it costs the clone and the kernel
build as well.

## 9. Set up and confirm crash capture

Follow [Installation](/gspwn/getting-started/installation/). On EC2 the capture
path skips pstore and adds the console output:

```
sudo python3 tools/crashlog_ctl.py setup
sudo reboot
sudo python3 tools/crashlog_ctl.py verify
```

```
NOTE (EC2): console-output capture requires an IAM instance profile allowing ec2:GetConsoleOutput.
READY. Now validate capture with a deliberate panic:
  1. sync
  2. echo c > /proc/sysrq-trigger   # machine panics, reboots
  3. after boot: crashlog_ctl.py harvest
     (must produce a /var/crash kdump dump; hard hangs are captured via console-output.log in the harvest dir)
```

`verify` exits 1 on a failed check and names what failed. Correct each failure
and re-run it.

Then run the sysrq test the output prints. A capture path is confirmed by a
captured panic and by nothing else: an empty harvest directory sends the
operator back to `setup`.

## 10. Measure the tenant surface

Run this before the campaign starts, because it is cheaper to satisfy before
the instance bill starts than after a campaign has run against the wrong
surface.

```
python3 tools/verify_tenant_surface.py measure
```

The command starts a container, lists the device nodes inside it, and compares
that list against `surface/entry-points.json`.

| Exit | Meaning | Action |
|---|---|---|
| 0 | The measured node set matches the recorded tenant surface | Continue |
| 1 | The two disagree | Blocked gate. Read the two lists it prints |
| 2 | The measurement could not be taken | Blocked gate. An unmeasured tenant surface is not a passing one |

The two disagreements have different consequences:

- `REACHABLE AND NOT MODELLED` counts nodes the container received that
  `surface/entry-points.json` places outside the tenant surface. That is
  reachable surface the campaign does not model, and every coverage figure is
  measured against the wrong denominator.
- `MODELLED AND NOT REACHABLE` counts nodes the artefact places inside the
  tenant surface that the container never received. That is budgeted effort no
  attacker can use.

Record the full output, including the injection path it detected and the node
list it measured. A summary line stating agreement records no measurement.

## 11. Install the orchestrator supervisor

```
sudo python3 tools/orchestrator_ctl.py install
sudo systemctl start gspwn-orchestrator
python3 tools/orchestrator_ctl.py status
```

`install` refuses while `orchestrator.command` is unset, because the repository
works with any AGENTS.md-aware coding agent and does not guess which one is on
the instance. Set it in `config/campaign.yaml` first.

Without the supervisor, every kernel panic ends the campaign until a human logs
in. [Unattended operation](/gspwn/guides/unattended-operation/) covers session
rotation and the circuit breaker.

## 12. Build the instrumented kernel

The kernel configuration starts from `/boot/config-$(uname -r)`, and that
choice decides whether a cloud instance boots the result:

```
sudo JOBS=$(nproc) LINUX_SRC=artifacts/src/linux \
  NVIDIA_SRC=artifacts/src/open-gpu-kernel-modules RUNG=1 \
  bash tools/build_kernel.sh
```

A generic x86 defconfig carries no NVMe or ENA driver, so the resulting kernel
cannot find its own root filesystem, and the failure arrives after a full build
and a reboot. The script warns when it falls back:

```
WARNING: /boot/config-6.1.0-21-amd64 not found, falling back to 'make defconfig'.
         A defconfig kernel usually lacks the storage and network drivers this
         machine boots with and will not come back up.
         Set BASE_CONFIG to a config known good for this hardware.
```

On that warning, stop and set `BASE_CONFIG` to a configuration known good for
this instance family, then rebuild. Do not reboot into a fallback kernel.

## 13. Snapshot the provisioned machine

Once `provision` and `build` have passed their gates, create an AMI. Those two
phases run once per machine and cost hours, and every later instance can start
from the image.

```
aws ec2 create-image --instance-id <id> --name gspwn-provisioned-<date> --no-reboot
```

Record in the image description what it contains: the kernel release, the
driver branch, the instrumentation rung and the syzkaller commit. Those are
four of the facts step 6 wrote to `config/machine.yaml`, and a later campaign's
report cites them.

An image taken with `--no-reboot` is crash-consistent. Stop the instance first
when the state file matters.

## 14. Relaunch from the image

A fresh instance from that AMI starts at `describe`. Re-check three things,
because none of them travels in an image:

| Check | Command |
|---|---|
| The instance profile is attached | `aws ec2 get-console-output --instance-id <id> --latest` |
| The state file matches what is expected | `python3 tools/pipeline_ctl.py show` |
| The spend ledger reflects prior campaigns | `python3 tools/pipeline_ctl.py round-show` |

`state/` is gitignored, so an instance provisioned from a clone starts with no
ledger. The first command that reads spend refuses while the state file records
hours the ledger does not, and
[Budget and spend](/gspwn/guides/budget-and-spend/) covers the recovery:

```
python3 tools/pipeline_ctl.py spend-init
```

## 15. Recover a wedged GPU

A card that has fallen off the bus leaves the fuzzer running against nothing,
and the coverage curve flattens exactly as a real plateau would.

```
python3 tools/coverage_ctl.py gpu-health
```

```
GPU: dead (nvidia-smi exit 255: Unable to determine the device handle for GPU 0000:00:1E.0: Unknown Error)
A plateau verdict will read 'unknown' while the GPU is in this state, so the loop stops without recording a plateau the fuzzer did not actually reach.
```

The recovery ladder, in order:

1. `sudo nvidia-smi -r`
2. Unload and reload the modules
3. A guest reboot

Re-run `gpu-health` after each rung and stop at the first healthy reading. A
guest reboot does not power-cycle a passthrough GPU, so a card that survives
all three needs an instance stop and start from the AWS console, which moves
the instance to different hardware. Nothing in the repository can do that.

## 16. Monetary cost

The repository has no view of what the instance costs and produces no estimate.
The stop conditions in `config/campaign.yaml` bound the search itself, and
[Budget and spend](/gspwn/guides/budget-and-spend/) covers them. Monetary spend
is visible in the AWS console. Set a budget alert there.

## See also

- [Cloud deployment](/gspwn/architecture/cloud-deployment/) covers instance,
  storage and IAM selection.
- [Disk and crash logs](/gspwn/guides/disk-and-crash-logs/) covers the capture
  path in detail.
