---
title: surface_verify.py
description: The version guard on the statically derived ioctl surface, and why a driver mismatch is silent without it.
---

Confirms that the ioctl map, the descriptions and the inventories describe the
driver release actually under test. Every number the describe and seeds phases
model comes from a source checkout, and every one of them is tied to one
release: escape numbers move between branches, parameter structs gain fields,
control commands are added and removed, and class privilege flags change.

A mismatch produces no error anywhere else. The map parses, syzkaller runs, the
descriptions compile, the campaign reports coverage, and the driver being
measured is not the driver installed. This module is the only place that
mismatch becomes visible.

## Responsibility

The module owns the version comparison and the stamp in `tools/ioctl_map.json`.
It reads every other source and writes only that one key.

| Invariant | Enforced by |
|---|---|
| The stamp cannot be read as a request number | The key is `comment_driver_version`, and `trace2seed.py` drops every key beginning with `comment` |
| An interrupted stamp cannot corrupt the map | The map is written whole to a temp file in the same directory and moved into place with `os.replace` |
| Absence of comparable sources is not agreement | Fewer than two sources reports that fact, and `--strict` turns it into a failure |
| A workstation's own GPU cannot force a false alarm | `--no-running` drops the loaded-driver comparison |
| Each disagreement carries its own remedy | Artefact-against-checkout and artefact-against-target are reported separately, because the fix differs |
| A missing `nvidia-smi` is not an error | The subprocess failure is logged at DEBUG and the source is reported absent |

## Interface

| Subcommand | Output |
|---|---|
| `check [--strict] [--no-running]` | Every available source, then agreement or a per-problem verdict with its remedy |
| `stamp` | Records the checkout's `NVIDIA_VERSION` and short commit into the ioctl map |
| `show` | Every source and the checkout commit, with no verdict |

`--src` selects the checkout and is accepted before or after the subcommand.

| Function | Returns |
|---|---|
| `checkout_version(src)` | `NVIDIA_VERSION` from `version.mk`, or `None` |
| `artefact_versions()` | Version per artefact file that records one |
| `running_version()` | The loaded driver from `/proc/driver/nvidia/version` or `nvidia-smi`, or `None` |
| `declared_version()` | `driver_branch` from `config/machine.yaml`, or `None` |

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing at run time. The `describe` and `seeds` phases invoke it as a command, and `describe` gates on it |
| This module imports | Nothing in `tools/`. It shells out to `git` and `nvidia-smi` |

## Failure modes

| Condition | Behaviour | Exit |
|---|---|---|
| Sources agree | The agreement and the count of sources compared | 0 |
| Sources disagree | Each problem with its remedy, then the regeneration commands | 3 |
| Fewer than two sources, without `--strict` | Reports that nothing was compared | 0 |
| Fewer than two sources, with `--strict` | Same report, treated as a failure | 3 |
| `version.mk` present but defines no `NVIDIA_VERSION` | Message naming the file and stating the format changed | 1 |
| `stamp` with no checkout under `--src` | Message naming the flag to point at a checkout | 1 |
| `git` or `nvidia-smi` absent | Logged, the source is reported absent, the run continues | unchanged |

## Concurrency and durability

`check` and `show` are read-only. `stamp` rewrites the map through a temp file
and an atomic replace, so a crash mid-write leaves the previous map intact and
never a truncated one. No lock is taken, and the phases invoke it
sequentially.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never report agreement when only one source exists | Nothing to compare is not a verified match, and a green line reads as one |
| Never write the stamp under a key not beginning with `comment` | `trace2seed.py` would treat it as a request number and the seeds phase would silently lose it |
| Never collapse the two comparisons into one verdict | Artefacts disagreeing with the checkout means regenerate locally. Artefacts disagreeing with the target means check out a different release first. The remedies are different work |
| Never let the check pass by ignoring an unreadable artefact | An artefact that cannot be parsed is logged as a warning and excluded, and the exclusion is visible in the printed source list |
| Never treat a version prefix match as agreement | 610.57.04 and 610.62 share a branch and differ in ABI |

## Design notes

The version lives in the map under `comment_driver_version` because the map is
the one artefact that is committed and read at run time. The inventories under
`artifacts/surface/` are regenerated on demand and record their own provenance,
so a fresh clone carrying only the map still has a version to check against.

`--no-running` exists because a development workstation with its own NVIDIA
driver reports a version that has nothing to do with the target. On the target
the loaded driver is the authority, and the flag is left off.

## See also

- [Attack surface](/gspwn/architecture/attack-surface/)
- [ioctl_inventory.py](/gspwn/architecture/components/ioctl-inventory/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
