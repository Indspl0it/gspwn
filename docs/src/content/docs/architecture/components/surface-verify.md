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
| Absence of comparable sources is not agreement | Two independent source groups are the minimum for a verdict, and `check` fails below that. `--allow-single-source` covers the deliberate case |
| Files that cannot disagree count once | The committed artefacts are one group, because all six take their `driver_version` from one `version.mk`. Six files agreeing with each other is one observation |
| A workstation's own GPU cannot force a false alarm | `--no-running` drops the loaded-driver comparison |
| Each disagreement carries its own remedy | Artefact-against-checkout and artefact-against-target are reported separately, because the fix differs |
| A missing `nvidia-smi` is not an error | The subprocess failure is logged at DEBUG and the source is reported absent |

## Interface

| Subcommand | Output |
|---|---|
| `check [--allow-single-source] [--no-running]` | Every available source, then agreement or a per-problem verdict with its remedy |
| `stamp` | Records the checkout's `NVIDIA_VERSION` and short commit into the ioctl map |
| `show` | Every source and the checkout commit, with no verdict |

`--src` selects the checkout and is accepted before or after the subcommand.

| Function | Returns |
|---|---|
| `checkout_version(src)` | `NVIDIA_VERSION` from `version.mk`, or `None` |
| `artefact_versions()` | Version per artefact file that records one, across `tools/ioctl_map.json`, `surface/*.json` and `descriptions/*.json` |
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
| Groups agree | The agreement and the groups compared, by name and file count | 0 |
| Groups disagree | Each problem with its remedy, then the regeneration commands | 3 |
| One group, without `--allow-single-source` | Reports that nothing was compared, then the sources that could supply a second reading | 4 |
| One group, with `--allow-single-source` | The same report, accepted | 0 |
| No source at all | Reports which four reads came back empty. `--allow-single-source` does not cover this | 4 |
| A partial regeneration inside the artefact group | Reported separately from the group count, and still exit 3 | 3 |
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
| Never report agreement when only one independent group answered | Nothing to compare is not a verified match, and a green line reads as one |
| Never count two files that cannot disagree as two sources | Six artefacts built from one `version.mk` agree by construction, and counting them as six turned a guard that compared nothing into a clean exit 0 |
| Never write the stamp under a key not beginning with `comment` | `trace2seed.py` would treat it as a request number and the seeds phase would silently lose it |
| Never collapse the two comparisons into one verdict | Artefacts disagreeing with the checkout means regenerate locally. Artefacts disagreeing with the target means check out a different release first. The remedies are different work |
| Never let the check pass by ignoring an unreadable artefact | An artefact that cannot be parsed is logged as a warning and excluded, and the exclusion is visible in the printed source list |
| Never treat a version prefix match as agreement | 610.57.04 and 610.62 share a branch and differ in ABI |

## Design notes

The version lives in the map under `comment_driver_version` because the map is
the one artefact that is committed and read at run time. The inventories under
`surface/` are regenerated on demand and record their own provenance,
so a fresh clone carrying only the map still has a version to check against.

`--no-running` exists because a development workstation with its own NVIDIA
driver reports a version that has nothing to do with the target. On the target
the loaded driver is the authority, and the flag is left off.

## Independent source groups

A group is independent when its answer can differ from every other group's
answer. Independence is a question of whether two observations can disagree,
and not of causal isolation.

| Group | Members | Observation |
|---|---|---|
| `artefacts` | `tools/ioctl_map.json` and every versioned JSON under `surface/` and `descriptions/` | The release the committed surface was built from |
| `checkout version.mk` | `NVIDIA_VERSION` under `--src` | The release the source tree at hand holds |
| `running driver` | `/proc/driver/nvidia/version`, or `nvidia-smi` | The release the kernel actually has loaded |
| `config/machine.yaml driver_branch` | One field | The release provisioning intended |

The artefacts are one group. `ioctl_inventory.py`, `ctrl_surface.py` and
`object_graph.py` each read one checkout, and `generation.json` copies the
value out of the control inventory, so all six take their `driver_version` from
one `version.mk`. They cannot disagree with each other except through a partial
regeneration, which `check` reports separately and still fails on.

The checkout is a second group even when the artefacts were built from that
same tree, because a checkout can be updated without regenerating. The guard
exists to catch that divergence.

```
$ python3 tools/surface_verify.py check --no-running --src artifacts/src/open-gpu-kernel-modules
agreement across 2 independent sources: artefacts (6 files), checkout version.mk
```

With `--no-running` and no reachable checkout, the same tree reports:

```
only the artefacts carry a version, and 6 file(s) built from one checkout are one source
```

and exits 4. `--allow-single-source` accepts the artefact group as the one
deliberate source, and it still cannot mask a disagreement.

Exit 3 and exit 4 are separate codes because the operator does different work
for each. Exit 3 means the artefacts model a release the target is not running,
and the fix is to regenerate them against the installed release. Exit 4 means
the guard compared nothing, and the fix is to bring a second group up. A single
code for both would lose the distinction the printed remedy already draws. The
value 4 was chosen because argparse exits 2 on a usage error, so a mistyped flag
cannot be read as a verdict.

`descriptions/generation.json` counts as a source because the
description set is the artefact syzkaller consumes, so its staleness carries
the most weight. A fresh inventory paired with descriptions generated from an
older checkout used to pass `check` cleanly. The four `.txt` files carry the
same version in their headers, written by the same `syzlang_gen.py` run that
writes the generation record, so reading the record covers them without adding
rows that always agree.

## See also

- [Attack surface](/gspwn/architecture/attack-surface/)
- [ioctl_inventory.py](/gspwn/architecture/components/ioctl-inventory/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
