---
title: verify_tenant_surface.py
description: The measurement that confirms the device nodes a container receives on this machine match the tenant surface the campaign models.
---

Compares the device nodes a container actually receives against the
`tenant_surface` field in `surface/entry-points.json`, which
`python3 tools/ioctl_inventory.py --emit-entry-points` writes. The `provision`
phase runs it at step 7, before any campaign spend.

Every coverage figure the campaign reports is a fraction whose denominator is
the command surface a tenant can reach. That denominator rests on which device
nodes the container runtime hands a container, and the two injection paths in
the NVIDIA container stack hand it different sets.

## Commands

| Command | Needs | Effect |
|---|---|---|
| `expected` | Files only | Prints the recorded tenant surface, the paths inside it and the paths outside it, each with its `file_operations` table |
| `runtime-mode` | Files only | Reads the configured injection mode from `/etc/nvidia-container-runtime/config.toml` or `/usr/share/nvidia-container-runtime/config.toml`, and prints what a container receives on that mode |
| `measure` | A container runtime and a GPU | Starts a container, lists its device nodes from inside, compares, and exits non-zero on any disagreement |

`--root DIR` points at a repository root other than this tool's own, and `-v`
logs every external command before running it.

| `measure` option | Default | Effect |
|---|---|---|
| `--runtime` | `docker` | The container runtime binary |
| `--image` | `ubuntu:22.04` | The image to start. It needs no CUDA runtime, because the nodes are injected before any process starts |
| `--capabilities` | `compute,utility` | The `NVIDIA_DRIVER_CAPABILITIES` value the container requests |
| `--via` | `runtime` | `runtime` uses `--runtime=nvidia`, `gpus` uses `--gpus all`, and `both` measures each and reports them apart |
| `--no-pull` | pull | Skips the image pull, for a host already holding it or with no registry access |

Each default is overridable by an environment variable:
`GSPWN_VERIFY_RUNTIME`, `GSPWN_VERIFY_IMAGE`, `GSPWN_VERIFY_CAPABILITIES` and
`GSPWN_VERIFY_VIA`. `GSPWN_VERIFY_RUN_TIMEOUT` bounds the container run at 120
seconds and `GSPWN_VERIFY_PULL_TIMEOUT` bounds the pull at 600, because a pull
on a cold instance is slower than the listing and is timed separately.

| Exit code | Condition | Phase treatment |
|---|---|---|
| 0 | The measured node set matches the record | Gate passes |
| 1 | A disagreement in either direction | Blocked |
| 2 | The measurement could not be taken, or no subcommand was given | Blocked |

## Responsibility

The module owns one comparison and the measurement that feeds it.

| Invariant | Enforced by |
|---|---|
| The artefact is the claim under test, never recomputed | `expected_surface` reads `tenant_surface` and derives nothing |
| The node list comes from inside the container | `measure_nodes` runs a listing in the container and ignores the runtime's own report of what it injected |
| The path that produced a reading is recorded with it | `report_one` prints the flag it measured through, and `--via both` reports each path apart |
| A mode the toolkit adds later still reaches a verdict | `mode_verdict` returns a paragraph for an unrecognised mode, because a branch chain that falls through prints nothing and nothing reads as agreement |
| An unmeasured surface never reads as a passing one | A measurement that could not be taken exits 2, which the phase treats as blocked |
| A numbered node matches every device index | `path_to_pattern` turns a declared trailing `N` into `\d+` |
| Every external call carries a timeout and a failure log | All of them go through `run`, so neither is forgotten at one call site |

## The measurement

The tool reads the recorded tenant surface, resolves the runtime's configured
injection mode, reads the Docker server version, and then starts a container
and lists the device nodes from inside it. The listing comes from inside the
container and never from the runtime's own report of what it injected. The two
can disagree, and only the listing describes what an attacker in that container
actually holds.

`expected` and `runtime-mode` need no GPU. `measure` needs one, and the
provision gate reads it.

## Injection paths

The two paths differ on the display-related nodes.

| Path | Reached by | Hands the container `/dev/nvidia-modeset` and `/dev/dri` |
|---|---|---|
| jit-cdi | `--runtime=nvidia`, and the ECS and EKS GPU AMIs | Yes, with no capability check |
| legacy | the prestart hook Docker 29.1.x and older inject for `--gpus` | No. The modeset node needs the `display` capability, and `/dev/dri` is never injected |

Docker 29.2.0 and later read a CDI specification for `--gpus` and reach the
first path again. `--via` defaults to `runtime` for that reason: a measurement
taken with `--gpus all` on an older Docker reports the legacy device set, which
is not the set a deployment using `--runtime=nvidia` will see.

`gpus_flag_path` reports which of the two a given Docker server version
reaches, and `measure` prints it beside the node list.

## Mode verdicts

`runtime-mode` prints the mode read from `config.toml`, the evidence it read it
from, and what a container receives on that mode.

| Mode | Verdict |
|---|---|
| `auto` | Resolved to jit-cdi on an NVML platform from toolkit 1.18.0 onward. This is the value the toolkit packages write at install time, so it is the reading a stock instance produces |
| `cdi`, `jit-cdi` | `/dev/nvidia-modeset` and every `/dev/dri` node found for the GPU's PCI bus id are injected with no capability check, which is the device set the artefact records as the tenant surface |
| `legacy` | `/dev/nvidia-modeset` is withheld unless the `display` capability is requested, and no `/dev/dri` node is injected. The `provision` gate treats this verdict as blocked on its own, before `measure` runs |
| `csv` | The device set is whatever the files under `/etc/nvidia-container-runtime/host-files-for-container.d` name, so neither reading applies and only `measure` settles it |
| Not stated | The toolkit default applies, jit-cdi on an NVML platform from 1.18.0 onward |
| Anything else | Reported as unrecognised, together with the two nodes that distinguish the paths |

## Disagreements

The report names three findings apart.

| Finding | Meaning |
|---|---|
| A node the container received that no `file_operations` table in the artefact covers | The artefact is incomplete, and the campaign models no part of that node |
| A node the container received that the artefact records outside the tenant surface | Reachable surface the campaign does not model. The threat model understates the attacker, and every coverage figure is measured against the wrong denominator |
| A node recorded inside the tenant surface that the container never received | Campaign effort budgeted against surface no attacker on this instance can use |

The first two print under `REACHABLE AND NOT MODELLED` and the third under
`MODELLED AND NOT REACHABLE`. Both exit 1.

An absent or unparseable artefact, an artefact carrying no `tables` list, a
runtime absent from `PATH`, a failed image pull, a timed-out command and a
container that did not start all exit 2, each carrying a sentence written for
an operator on a fresh instance.

## Limits

The tool measures one host. A campaign that provisions a second instance
measures again, because the injection path is a property of the toolkit
version and the Docker version on that machine.

`runtime-mode` reports the configured mode. `auto` is resolved by the runtime
at container start, and this tool states what that resolution is on an NVML
platform without observing it. `measure` observes the outcome, and the gate
reads that subcommand.

The listing covers `/dev`, `/dev/dri`, `/dev/nvidia-caps` and
`/dev/nvidia-caps-imex-channels`, and keeps the entries beginning `/dev/nvidia`
or `/dev/dri/`. A node the driver creates elsewhere is outside what this
measures.

## See also

- [Threat model](/gspwn/architecture/threat-model/)
- [Attack surface](/gspwn/architecture/attack-surface/)
- [Cloud runbook](/gspwn/guides/cloud-runbook/)
- [`ioctl_inventory.py`](/gspwn/architecture/components/ioctl-inventory/)
