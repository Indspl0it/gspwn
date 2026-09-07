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

Development on Windows goes through WSL.

## GPU

| Requirement | Value | Verified by |
|---|---|---|
| Track K card | Turing or later | `nvidia-smi --query-gpu=name --format=csv,noheader` |
| Track U card | none | no check needed |

Turing and later carry the GSP microcontroller that `open-gpu-kernel-modules`
depends on. Volta and earlier run the proprietary driver, whose Resource
Manager ships as a prebuilt binary that KCOV cannot instrument, so
coverage-guided kernel fuzzing does not work on those cards.

Track U harnesses run in a container and never touch the card. Their coverage
samples record the GPU column as `n/a`.

For instance selection on AWS, see
[Cloud deployment](/gspwn/architecture/cloud-deployment/).

## Firmware and boot

Secure Boot handling depends on where the machine runs.

- Bare metal needs Secure Boot disabled, or a Machine Owner Key enrolled and
  every `nvidia*.ko` signed. `tools/build_kernel.sh` reads the state with
  `mokutil --sb-state`.
- EC2 Nitro carries no Secure Boot by default, and the `provision` sub-agent
  skips the check there.

The out-of-tree NVIDIA modules are unsigned and refuse to load on a Secure Boot
machine. `build_kernel.sh` stops with a signing error. Without that check the
failure surfaces at the build gate as `nvidia-smi` errors that say nothing
about signing.

## Crash capture

Findings arrive as kernel panics. An uncaptured panic leaves no evidence on
disk.

- Bare metal captures through ramoops/pstore plus kdump, which needs
  `pstore-tools` and `kdump-tools`.
- EC2 captures through kdump plus `aws ec2 get-console-output`, which needs
  `awscli` and an IAM instance profile granting `ec2:GetConsoleOutput` and
  nothing else, attached at launch.

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
ca-certificates curl gnupg2
```

The last three add NVIDIA's package repository in
[Installation](/gspwn/getting-started/installation/) step 5. `awscli` is a
fourth package, needed on EC2 alone, where hard-hang capture reads the console
output and `crashlog_ctl.py verify` fails without it.

Two packages carry a requirement that is not obvious from the name.

- `mokutil` reports Secure Boot state to the `build` phase, and applies to bare
  metal alone.
- `docker.io` is needed on every machine. The Track U harnesses run in a
  container, and the tenant-surface measurement starts one.

## Host binaries

`orchestrator_ctl.py preflight` resolves eight binaries on `PATH` and names the
phase that stops without each. Six are needed on every deployment. A binary
reached only inside a container is absent from this list, so the Track U
toolchain is the image's problem.

| Binary | Needed on | Stops without it |
|---|---|---|
| `go` | every machine | `describe` builds syzkaller and runs `syzlang_gen.py compile`, which exits 3 when `go` is absent |
| `docker` | every machine | the Track U harnesses, and `verify_tenant_surface.py measure` |
| `gcc` | every machine | `repro_ctl.py extract` compiles `repro.c` |
| `make` | every machine | the instrumented kernel build and the syzkaller build |
| `git` | every machine | the inventories record the checkout revision they derived from |
| `nvidia-smi` | every machine | `surface_verify.py` reads the running driver version through it |
| `nvidia-ctk` | hosts starting GPU containers | `provision` registers the `nvidia` runtime with Docker through it |
| `aws` | EC2 | hard-hang capture reads the serial console, and `crashlog_ctl.py verify` fails without it |

`preflight` reports the two non-universal binaries as absent without failing,
because an absent one is a fact the operator reads differently on EC2 than on
bare metal.

## Go toolchain

syzkaller builds on the host. Its pinned revision declares `go 1.26.0` in
`go.mod`, which is not the version the machine must carry: Go 1.21 and later
read the directive and fetch the named toolchain on demand, because
`GOTOOLCHAIN` defaults to `auto`. A distribution package at 1.21 or later
therefore satisfies the build wherever `proxy.golang.org` is reachable.

| Condition | Result |
|---|---|
| Go 1.21 or later, `proxy.golang.org` reachable | `make` fetches the 1.26 toolchain on first build, which adds minutes |
| Go 1.21 or later, `GOTOOLCHAIN=local` or no proxy route | `make` stops on the `go.mod` directive and `bin/syz-manager` is never produced |
| Go below 1.21 | no download mechanism, and `make` stops on the same directive |
| `go` absent from the phase's own shell | `syzlang_gen.py compile` exits 3, which is no verdict reached and distinct from a description set that fails to compile |

[Installation](/gspwn/getting-started/installation/) step 7 installs the
declared version from the upstream tarball, which keeps the download off the
build's critical path and assumes no proxy access.

## Container runtime

The threat model is a container tenant, so the `provision` phase measures which
device nodes a container on this machine actually receives. That measurement
runs a container through `--runtime=nvidia`, which the distribution's `docker.io`
package does not provide. It comes from NVIDIA's own repository.

| Package | Purpose |
|---|---|
| `nvidia-container-toolkit` | the `nvidia` runtime and `nvidia-ctk` |
| `nvidia-container-toolkit-base` | the runtime's shared components |
| `libnvidia-container-tools` | `nvidia-container-cli`, the legacy injection path |
| `libnvidia-container1` | the library both paths link against |

Pin all four to one version. The four are released together and a mixed set is
not a configuration NVIDIA tests. [Installation](/gspwn/getting-started/installation/)
carries the commands.

Two consequences follow for the campaign, both from
[Threat model](/gspwn/architecture/threat-model/):

- The toolkit resolves `mode = auto` to jit-cdi from 1.18.0 onward. The
  container receives `/dev/nvidia-modeset` and every `/dev/dri` node for the
  GPU, with no capability check.
- Docker 29.1.x and older inject the legacy hook for `--gpus`. That path
  withholds both, so a measurement taken with `--gpus all` on such a host
  reports a device set the deployment will not see.

`verify_tenant_surface.py runtime-mode` reports which path this machine is
configured for and reads files only, so it answers before a GPU is present.

## Source trees

The `provision` phase clones five repositories into `artifacts/src/`:

| Directory | Contents |
|---|---|
| `linux` | Upstream stable branch matching the newest that `open-gpu-kernel-modules` supports |
| `open-gpu-kernel-modules` | Latest production branch. The surface inventories in this branch were taken from 610.57.04 |
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
agent user read and execute only. No tool writes this sudoers rule. It is a
deliberate human step, validated with `visudo -f /etc/sudoers.d/gspwn`.
:::

Confirm the whole prerequisite set before starting a campaign:

```
python3 tools/orchestrator_ctl.py preflight
```

`preflight` checks the configuration, the agent command, passwordless sudo, the
host binaries and disk headroom. It exits non-zero and lists what is missing.

## Disk

The free space floor is `loop.min_free_disk_gb`, default 20 GB.
`orchestrator_ctl.py preflight` verifies it, and every coverage sample records
free space.

One filesystem holds the kernel dumps copied out of `/var/crash`, the corpus,
the coverage CSVs and the agent transcript. A full disk stops the fuzzer and
the sampler, and every state write fails. kdump writes hundreds of megabytes
per panic, and this pipeline panics the machine by design.

## Next

- [Installation](/gspwn/getting-started/installation/) prepares the machine.
- [Disk and crash logs](/gspwn/guides/disk-and-crash-logs/) covers capture and
  pruning.
