---
title: Requirements
description: The operating system, hardware, packages and privileges gspwn needs.
sidebar:
  order: 2
---

gspwn runs on one dedicated Linux machine and panics it deliberately. That
machine must carry no other workload.

## Software

| Requirement | Value | Verified by |
|---|---|---|
| Operating system | Linux. `tools/pipeline_state.py` locks the state file with `fcntl.flock`, which has no portable fallback. | no automatic check |
| Init system | systemd. Campaigns, the coverage sampler, deadline enforcement and the orchestrator supervisor all run as units. | no automatic check |
| Package manager | `apt`. `tools/crashlog_ctl.py setup` installs `kdump-tools` and `pstore-tools` with `apt-get`. | `crashlog_ctl.py setup` |
| Python | Python 3 with PyYAML. Every tool is stdlib-only except the configuration reader, which parses `config/campaign.yaml`. | `python3 tools/gspwn_config.py` |
| Line endings | LF. `.gitattributes` normalises every file on checkout, and a CRLF checkout makes the shell scripts unrunnable. | no automatic check |

Development on Windows goes through WSL. See
[Development](/gspwn/project/development/).

## GPU

| Requirement | Value | Verified by |
|---|---|---|
| Track K card | Turing or later | `nvidia-smi --query-gpu=name --format=csv,noheader` |
| Track U card | none | no check needed |

Turing and later carry the GSP microcontroller that `open-gpu-kernel-modules`
depends on. Volta and earlier run the proprietary driver, whose Resource
Manager ships as a prebuilt binary that KCOV cannot instrument, so
coverage-guided kernel fuzzing does not work on those cards.

Check the card before provisioning:

```
nvidia-smi --query-gpu=name --format=csv,noheader
```

Track U harnesses run in a container and never touch the card. Their coverage
samples record the GPU column as `n/a`.

For instance selection on AWS, see
[Cloud deployment](/gspwn/architecture/cloud-deployment/).

## Firmware and boot

| Requirement | Value | Verified by |
|---|---|---|
| Secure Boot, bare metal | disabled, or a Machine Owner Key enrolled and every `nvidia*.ko` signed | `mokutil --sb-state`, run by `tools/build_kernel.sh` |
| Secure Boot, EC2 Nitro | absent by default. The `provision` sub-agent skips the check there. | no check |

The out-of-tree NVIDIA modules are unsigned and refuse to load on a Secure Boot
machine. `build_kernel.sh` stops with a signing error. Without that check the
failure surfaces at the build gate as `nvidia-smi` errors that say nothing
about signing.

## Crash capture

Findings arrive as kernel panics. An uncaptured panic leaves no evidence on
disk.

| Environment | Capture path | Also required |
|---|---|---|
| Bare metal | ramoops/pstore plus kdump | `pstore-tools`, `kdump-tools` |
| EC2 | kdump plus `aws ec2 get-console-output` | `awscli`, and an IAM instance profile granting `ec2:GetConsoleOutput` and nothing else, attached at launch |

EC2 has no pstore. A hard hang that never reaches kdump leaves nothing on disk,
and the serial console holds the only record.

`crashlog_ctl.py setup` adds `crashkernel=256M` to the GRUB command line.
`crashlog_ctl.py verify` passes only after the reboot that applies it, and a
harvested test panic confirms the whole path.

## Packages

Install through `apt`, never through a PPA:

```
build-essential bc flex bison libssl-dev libelf-dev dwarves rsync git
python3-yaml docker.io kdump-tools pstore-tools mokutil
```

| Package | Needed on | Purpose |
|---|---|---|
| `awscli` | EC2 | hard-hang capture reads the console output, and `crashlog_ctl.py verify` fails without it |
| `mokutil` | bare metal | reports Secure Boot state to the `build` phase |

## Source trees

The `provision` phase clones five repositories into `artifacts/src/`:

| Directory | Contents |
|---|---|
| `linux` | Upstream stable branch matching the newest that `open-gpu-kernel-modules` supports |
| `open-gpu-kernel-modules` | Latest production branch |
| `syzkaller` | master, built so `bin/syz-manager`, `bin/syz-db` and `bin/syz-prog2c` exist |
| `nvidia-container-toolkit` | Track U target |
| `libnvidia-container` | Track U target, the primary memory-safety surface |

Their commits and the `gcc` version are recorded in
`artifacts/builds/manifest.json`, which the `report` phase cites for affected
versions.

## Privileges

The agent driving the pipeline needs passwordless sudo for the pipeline tools.
Crash harvesting after a panic runs `sudo -n`. Campaign installs and the
coverage sampler need root from a headless session that cannot answer a
password prompt.

```
<agent-user> ALL=(root) NOPASSWD: /usr/bin/python3 /path/to/repo/tools/*.py
```

:::danger[This rule is equivalent to unrestricted root unless the repository is protected]
If the agent user can write those scripts, it can write anything root would
run. Keep the repository root-owned on the machine under test and grant the
agent user read and execute only. No tool writes this sudoers rule; it is a
deliberate human step, validated with `visudo -f /etc/sudoers.d/gspwn`.
:::

Confirm the whole prerequisite set before starting a campaign:

```
python3 tools/orchestrator_ctl.py preflight
```

`preflight` checks the configuration, the agent command, passwordless sudo and
disk headroom. It exits non-zero and lists what is missing.

## Disk

| Requirement | Value | Verified by |
|---|---|---|
| Free space floor | `loop.min_free_disk_gb`, default 20 GB | `orchestrator_ctl.py preflight`, and every coverage sample records free space |

One filesystem holds the kernel dumps copied out of `/var/crash`, the corpus,
the coverage CSVs and the agent transcript. A full disk stops the fuzzer and
the sampler, and every state write fails. kdump writes hundreds of megabytes
per panic, and this pipeline panics the machine by design.

## Next

- [Installation](/gspwn/getting-started/installation/) prepares the machine.
- [Disk and crash logs](/gspwn/guides/disk-and-crash-logs/) covers capture and
  pruning.
