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
the NVIDIA container stack hand it different sets.

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

## The measurement

The tool reads the recorded tenant surface, resolves the runtime's configured
injection mode, and then starts a container and lists the device nodes from
inside it. The listing comes from inside the container and never from the
runtime's own report of what it injected. The two can disagree, and only the
listing describes what an attacker in that container actually holds.

The first two readings need no GPU. The measurement does, and the provision
gate reads it.

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

The report names the two disagreements apart.

| Disagreement | Consequence |
|---|---|
| A node the container received, recorded outside the tenant surface | Reachable surface the campaign does not model. The threat model understates the attacker, and every coverage figure is measured against the wrong denominator |
| A node recorded inside the tenant surface, which the container never received | Campaign effort budgeted against surface no attacker on this instance can use |

## Verdicts

A measured node set matching the record passes. A disagreement in either
direction fails, and an unmeasurable surface fails separately, because a
measurement that could not be taken must never read as a passing one. An absent
or unparseable artefact, a runtime absent from `PATH`, a failed image pull and
a container that did not start all land there, each carrying a sentence written
for an operator on a fresh instance.

The `provision` phase runs this before the kernel build, and treats an
unmeasurable surface as blocked.

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
