---
title: Cloud runbook
description: The operational sequence on an AWS instance, from launch to a reusable image.
---

Operations on a cloud instance run in the order below. The instance, storage
and IAM choices are derived in
[Cloud deployment](/gspwn/architecture/cloud-deployment/).

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

The instance profile must be attached **at launch** for the console output to
be reachable when it is needed, which is after a hard hang.

## 2. Confirm the environment is detected

```
python3 -c "import sys; sys.path.insert(0,'tools'); import crashlog_ctl; print(crashlog_ctl.detect_env())"
```

```
ec2
```

Detection queries `http://169.254.169.254/latest/meta-data/instance-id` with a
two-second timeout, preferring IMDSv2. Every `crashlog_ctl.py` subcommand
accepts `--env ec2` to override it.

## 3. Install the baseline driver first

On EC2, install the NVIDIA driver from the distribution's non-free
repositories **before** cloning the source trees. The `provision` phase reads
GPU model and GSP firmware facts from `nvidia-smi`, and those go into
`config/machine.yaml` and the build manifest.

```
sudo apt-get update
sudo apt-get install -y nvidia-driver
nvidia-smi --query-gpu=name --format=csv,noheader
```

Secure Boot is skipped on EC2. Nitro instances have none by default.

## 4. Install the AWS CLI

```
sudo apt-get install -y awscli
aws ec2 get-console-output --instance-id "$(curl -s http://169.254.169.254/latest/meta-data/instance-id)" --latest --output text | head
```

`crashlog_ctl.py verify` fails without the CLI, because hard-hang capture on
EC2 is the console output. Run the command once by hand to confirm the instance
profile grants the call, before a hang depends on it.

## 5. Provision

Follow [Installation](/gspwn/getting-started/installation/). On EC2 the crash
capture path skips pstore:

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

Run the sysrq test. A capture path is confirmed only by a captured panic.

## 6. Build the instrumented kernel

The kernel configuration starts from `/boot/config-$(uname -r)`, and that
choice matters most on a cloud instance:

```
sudo JOBS=$(nproc) LINUX_SRC=artifacts/src/linux \
  NVIDIA_SRC=artifacts/src/open-gpu-kernel-modules RUNG=1 \
  bash tools/build_kernel.sh
```

A generic x86 defconfig has no NVMe or ENA driver, so the resulting kernel
cannot find its own root filesystem, and the failure arrives after a full build
and a reboot. The script warns when it falls back:

```
WARNING: /boot/config-6.1.0-21-amd64 not found, falling back to 'make defconfig'.
         A defconfig kernel usually lacks the storage and network drivers this
         machine boots with and will not come back up.
         Set BASE_CONFIG to a config known good for this hardware.
```

Stop there and set `BASE_CONFIG` before rebuilding. Do not reboot.

## 7. Snapshot the provisioned machine

Once `provision` and `build` have passed their gates, create an AMI. Those two
phases run once per machine and cost hours; every later instance can start from
the image.

```
aws ec2 create-image --instance-id <id> --name gspwn-provisioned-<date> --no-reboot
```

Record in the image description what it contains: the kernel release, the
driver branch, the instrumentation rung and the syzkaller commit. Those are the
same facts `config/machine.yaml` and `artifacts/builds/manifest.json` hold, and
a later campaign's report cites them.

An image taken with `--no-reboot` is crash-consistent. Stop the instance first
when the state file matters.

## 8. Relaunch from the image

A fresh instance from that AMI starts at `describe`. Re-check three things,
because none of them travel in an image:

| Check | Command |
|---|---|
| The instance profile is attached | `aws ec2 get-console-output --instance-id <id> --latest` |
| The state file matches what is expected | `python3 tools/pipeline_ctl.py show` |
| The spend ledger reflects prior campaigns | `python3 tools/pipeline_ctl.py round-show` |

`state/` is gitignored, so an instance provisioned from a clone starts with no
ledger. The first command that reads spend refuses if the state file records
hours the ledger does not:

```
python3 tools/pipeline_ctl.py spend-init
```

## 9. Recover a wedged GPU

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

A guest reboot does not power-cycle a passthrough GPU, so a card that survives
all three needs an instance stop and start from the AWS console, which moves
the instance to different hardware. Nothing in the repository can do that.

## 10. Monetary cost

The caps in `config/campaign.yaml` bound the search itself. The repository has
no view of what the instance costs and produces no estimate. Monetary spend is
visible in the AWS console. Set a budget alert there.

## See also

- [Cloud deployment](/gspwn/architecture/cloud-deployment/) covers instance,
  storage and IAM selection.
- [Disk and crash logs](/gspwn/guides/disk-and-crash-logs/) covers the capture
  path in detail.
