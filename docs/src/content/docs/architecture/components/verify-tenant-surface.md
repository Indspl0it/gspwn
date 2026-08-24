---
title: verify_tenant_surface.py
description: The measurement that confirms the device nodes a container receives on this machine match the tenant surface the campaign models.
---

Compares the device nodes a container actually receives against the
`tenant_surface` field in `surface/entry-points.json`. The `provision` phase
gates on it before any campaign spend.

Every coverage figure the campaign reports is a fraction whose denominator is
the command surface a tenant can reach. That denominator rests on which device
nodes the container runtime hands a container, and the two injection paths in
the NVIDIA container stack hand it different sets. Driver source settles what
the code can do. Only the instance settles what the instance does.

## Responsibility

The module owns one comparison and the measurement that feeds it.

| Invariant | Enforced by |
|---|---|
| The artefact is the claim under test, never recomputed | `expected_surface` reads `tenant_surface` and derives nothing |
| The node list comes from inside the container | `measure_nodes` runs a listing in the container and ignores the runtime's own report of what it injected |
| The path that produced a reading is recorded with it | `report_one` prints the flag it measured through, and `--via both` reports each path apart |
| A mode the toolkit adds later still reaches a verdict | `mode_verdict` returns a paragraph for an unrecognised mode |
| An unmeasured surface never reads as a passing one | A measurement that could not be taken exits 2, which the phase treats as blocked |
| A numbered node matches every device index | `path_to_pattern` turns a declared trailing `N` into `\d+` |

## Interface

| Subcommand | Reads | Needs a GPU |
|---|---|---|
| `expected` | `surface/entry-points.json` | No |
| `runtime-mode` | `/etc/nvidia-container-runtime/config.toml`, `nvidia-ctk` on `PATH` | No |
| `measure` | Both of the above, and a container it starts | Yes |

| Flag | Applies to | Effect |
|---|---|---|
| `--root` | every subcommand | Repository root holding the artefact |
| `--runtime` | `measure` | Container runtime binary, default `docker` |
| `--image` | `measure` | Image to start, default `ubuntu:22.04` |
| `--capabilities` | `measure` | The `NVIDIA_DRIVER_CAPABILITIES` value the container requests |
| `--via` | `measure` | `runtime`, `gpus`, or `both` |
| `--no-pull` | `measure` | Skip the image pull, for a host with no registry access |

Five environment variables override the defaults: `GSPWN_VERIFY_IMAGE`,
`GSPWN_VERIFY_RUNTIME`, `GSPWN_VERIFY_VIA`, `GSPWN_VERIFY_RUN_TIMEOUT` and
`GSPWN_VERIFY_PULL_TIMEOUT`.

## Injection paths

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

## Disagreements

The two possible disagreements are not symmetric, and the report names them
apart.

| Disagreement | Consequence |
|---|---|
| A node the container received, recorded outside the tenant surface | Reachable surface the campaign does not model. The threat model understates the attacker, and every coverage figure is measured against the wrong denominator |
| A node recorded inside the tenant surface, which the container never received | Campaign effort budgeted against surface no attacker on this instance can use |

## Exit codes

| Code | Condition |
|---|---|
| 0 | The measured node set matches the record |
| 1 | The two disagree in either direction |
| 2 | The measurement could not be taken, or no subcommand was given |

Exit 2 covers an absent artefact, an unparseable one, a runtime absent from
`PATH`, a pull that failed, and a container that did not start. Each raises
`VerifyError` carrying a sentence written for an operator on a fresh instance,
because a stack trace is not the useful output there.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing |
| Invokes it | The `provision` sub-agent, at step 7, before the kernel build |
| Reads the same artefact | `ioctl_inventory.py --emit-entry-points` writes it |

## Limits

The tool measures one host. A campaign that provisions a second instance
measures again, because the injection path is a property of the toolkit
version and the Docker version on that machine.

`runtime-mode` reports the configured mode. `auto` is resolved by the runtime
at container start, and this tool states what that resolution is on an NVML
platform without observing it. `measure` observes the outcome, and it is the
subcommand the gate reads.

The listing covers `/dev`, `/dev/dri`, `/dev/nvidia-caps` and
`/dev/nvidia-caps-imex-channels`, and keeps the entries beginning `/dev/nvidia`
or `/dev/dri/`. A node the driver creates elsewhere is outside what this
measures.

## See also

- [Threat model](/gspwn/architecture/threat-model/)
- [Attack surface](/gspwn/architecture/attack-surface/)
- [Cloud runbook](/gspwn/guides/cloud-runbook/)
- [`ioctl_inventory.py`](/gspwn/architecture/components/ioctl-inventory/)
