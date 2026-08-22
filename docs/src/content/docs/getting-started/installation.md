---
title: Installation
description: Clone the repository, install dependencies, create the state file and build syzkaller.
sidebar:
  order: 3
---

These steps prepare the machine to the point where a campaign can be
configured. They do not build the instrumented kernel, which is the `build`
phase and takes hours, and they do not install the orchestrator supervisor,
which is covered in
[Unattended operation](/gspwn/guides/unattended-operation/).

Run every command on the machine under test, after that machine meets
[Requirements](/gspwn/getting-started/requirements/).

## 1. Clone the repository

```
git clone git@github.com:Indspl0it/gspwn.git
cd gspwn
```

## 2. Install the build and capture dependencies

```
sudo apt-get update
sudo apt-get install -y build-essential bc flex bison libssl-dev libelf-dev \
  dwarves rsync git python3-yaml docker.io kdump-tools pstore-tools mokutil
```

On EC2, add the AWS CLI, which captures a hard hang there:

```
sudo apt-get install -y awscli
```

## 3. Set up persistent crash capture

```
sudo python3 tools/crashlog_ctl.py setup
sudo reboot
```

`setup` installs kdump, mounts pstore on bare metal, and adds
`crashkernel=256M` to the GRUB command line. The reboot applies that parameter.

After the reboot:

```
sudo python3 tools/crashlog_ctl.py verify
```

`verify` prints `READY` and the instructions for a deliberate test panic when
every check passes. On a failed check it exits 1 and names what failed.
Correct each failure and re-run `verify` before step 4.

## 4. Confirm capture with a test panic

`verify` prints this sequence:

```
sync
echo c > /proc/sysrq-trigger
```

The machine panics and reboots. After it returns:

```
sudo python3 tools/crashlog_ctl.py harvest
```

The last line of `harvest` is the path of the harvest directory. That directory
must hold the panic:

| Environment | Required contents |
|---|---|
| Bare metal | a dmesg or ramoops dump holding the panic |
| EC2 | a `/var/crash` kdump dump, with hard hangs captured in `console-output.log` |

An empty harvest directory means the panic was not captured. Return to step 3.

:::caution[harvest must run as root]
`/sys/fs/pstore` and `/var/crash` are root-only. Under any other user the globs
come back empty and the harvest reads no crash data. `harvest` refuses to run
without root.
:::

## 5. Clone the source trees

```
mkdir -p artifacts/src
cd artifacts/src
git clone https://github.com/torvalds/linux.git
git clone https://github.com/NVIDIA/open-gpu-kernel-modules.git
git clone https://github.com/google/syzkaller.git
git clone https://github.com/NVIDIA/nvidia-container-toolkit.git
git clone https://github.com/NVIDIA/libnvidia-container.git
cd ../..
```

Check out the branches [Requirements](/gspwn/getting-started/requirements/)
names: a Linux stable branch the driver supports, and the driver's latest
production branch. Record every commit and the `gcc` version in
`artifacts/builds/manifest.json`, because the `report` phase reads affected
versions from there.

## 6. Build syzkaller

```
cd artifacts/src/syzkaller
make
cd ../../..
```

Three binaries must exist afterwards, because other tools invoke them by path:

| Binary | Used by |
|---|---|
| `bin/syz-manager` | the Track K campaign unit |
| `bin/syz-db` | `corpus_ctl.py` and the seed packing in `campaign_ctl.py` |
| `bin/syz-prog2c` | `repro_ctl.py extract`, to generate `repro.c` from `repro.prog` |

A missing binary blocks the `fuzz` phase. Re-run `make` and read its error.

## 7. Create the state file

```
python3 tools/pipeline_ctl.py init
```

This writes `state/pipeline.json`, the file every later phase reads. `init` is
idempotent. Run against an existing state file, it reports the current contents
and changes nothing:

```
state/pipeline.json already exists (0 crashes, next phase: provision). Use --force to reset.
```

`--force` overwrites the state file, discarding the crash registry and the
round history.

## Next

- [Quickstart](/gspwn/getting-started/quickstart/) checks the configuration and
  the tools offline.
- [Your first campaign](/gspwn/getting-started/first-campaign/) walks round 1
  end to end.
