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
measured is not the driver installed.

## Commands

| Command | Effect |
|---|---|
| `check` | Compares every available version source and prints the verdict. `--allow-single-source` accepts one deliberate source. `--no-running` skips the loaded-driver comparison. |
| `stamp` | Records the checkout's `NVIDIA_VERSION` into `tools/ioctl_map.json`, for use after regenerating the map. |
| `show` | Prints each source, the value read from it, and the checkout commit. |

All three take `--src DIR`, the `open-gpu-kernel-modules` checkout, which
defaults to `artifacts/src/open-gpu-kernel-modules`, and `-v` to log at DEBUG.
Both options are accepted before the subcommand and after it, because argparse
binds a parent-level option before the subcommand only and both orders read
naturally.

| Exit code | Meaning | Remedy |
|---|---|---|
| 0 | Two or more independent groups answered and agree, or one group answered under `--allow-single-source` | None |
| 1 | Bad input: `version.mk` defines no `NVIDIA_VERSION`, `--src` names no checkout for `stamp`, or the map is absent | Point `--src` at a checkout, or restore the map |
| 3 | Disagreement | Regenerate the artefacts |
| 4 | Fewer than two independent sources | Bring a second source up |

3 and 4 are separate values because the operator does different work for each.
4 is not 2, because argparse exits 2 on a usage error and a mistyped flag must
not read as a verdict.

## Responsibility

The module owns the version comparison and the stamp in `tools/ioctl_map.json`.
It reads every other source and writes only that one key.

| Invariant | Enforced by |
|---|---|
| The stamp cannot be read as a request number | The key is `comment_driver_version`, and `trace2seed.py` drops every key beginning with `comment` |
| An interrupted stamp cannot corrupt the map | The map is written whole to a temp file in the same directory, flushed, `fsync`ed and moved into place with `os.replace` |
| A stamp produces the same bytes on every platform | The temp file is opened with `newline="\n"`, so a run on Windows and a run under WSL do not differ by a line ending on every line of the map |
| Absence of comparable sources is not agreement | Two independent source groups are the minimum for a verdict, and `check` fails below that. `--allow-single-source` covers the deliberate case |
| Files that cannot disagree count once | The committed artefacts are one group, because all eleven take their `driver_version` from one `version.mk`. Eleven files agreeing with each other is one observation |
| A workstation's own GPU cannot force a false alarm | `--no-running` drops the loaded-driver comparison |
| Each disagreement carries its own remedy | Artefact-against-checkout and artefact-against-target are reported separately, because the fix differs |
| A missing `nvidia-smi` is not an error | The subprocess failure is logged at DEBUG and the source is reported absent |

## The verdict

The gate compares a driver version read from four places and reports whether
the independent readings agree. The version it takes as the checkout's own is
`NVIDIA_VERSION` in `version.mk` of the source tree, never a running driver.
Every inventory was derived from that source tree, and a workstation's own GPU
says nothing about the release under test.

| Verdict | Condition | Remedy |
|---|---|---|
| Agreement | Two or more independent groups answered and agree | None |
| Disagreement | Two or more groups answered and disagree, or a partial regeneration falls inside the artefact group | Named per problem, since the two disagreements have different remedies |
| Nothing compared | Only one group could answer | Bring a second group up, or accept the single source deliberately |

A disagreement and an unmeasured comparison exit differently, because the
operator does different work for each. A disagreement means the artefacts model
a release the target is not running, and the fix is to regenerate them against
the installed release. Nothing compared means the guard measured nothing, and
the fix is to bring a second group up. A single code for both would lose that
distinction.

On a disagreement, `check` prints the seven regeneration commands in dependency
order: the three extractors, the two joins that read them, the description
emission, and the stamp.

A missing `git` or `nvidia-smi` is not an error. The source is reported absent,
and the run continues on the sources that answered.

## Independent source groups

A group is independent when its answer can differ from every other group's
answer.

| Group | Members | Observation |
|---|---|---|
| `artefacts` | `tools/ioctl_map.json`, `descriptions/generation.json`, and every versioned JSON directly under `surface/` | The release the committed surface was built from |
| `checkout version.mk` | `NVIDIA_VERSION` under `--src` | The release the source tree at hand holds |
| `running driver` | `/proc/driver/nvidia/version`, or `nvidia-smi` | The release the kernel actually has loaded |
| `config/machine.yaml driver_branch` | One field | The release provisioning intended |

The artefacts are one group. Every extractor reads one checkout, and the
generation record copies the value out of the control inventory, so all eleven
files take their `driver_version` from one `version.mk`. They cannot disagree
with each other except through a partial regeneration, which is reported
separately and still fails.

The checkout is a second group even when the artefacts were built from that
same tree, because a checkout can be updated without regenerating.

```
$ python3 tools/surface_verify.py check --no-running --src artifacts/src/open-gpu-kernel-modules
agreement across 2 independent sources: artefacts (11 files), checkout version.mk
```

With `--no-running` and no reachable checkout, the same tree reports:

```
only the artefacts carry a version, and 11 file(s) built from one checkout are one source
```

`--allow-single-source` accepts the artefact group as the one deliberate
source, and it still cannot mask a disagreement.

`descriptions/generation.json` counts as a source because the description set
is the artefact syzkaller consumes, so its staleness carries the most weight. A
fresh inventory paired with descriptions generated from an older checkout would
otherwise pass cleanly. The description files carry the same version in their
headers, written by the same `syzlang_gen.py` run that writes the generation
record, so reading the record covers them without adding rows that always
agree.

## Artefacts carrying no version

The scan over `surface/` and `descriptions/` is not recursive, so
`artifacts/bulletins/` stays invisible: those are cached vendor HTML and belong
to no driver build. Within the two directories, an artefact recording no
`driver_version` is counted, logged as a warning and excluded from the
comparison, so a guard never reports agreement it did not establish.
`surface/ctrl-param-sizes.json`, `surface/ioctl-sizes.json` and
`surface/rm-control-rank.json` are reported that way.

Two artefacts describe something other than one driver build and are exempt
from the warning by name, because warning about them would train the reader to
ignore the warning that matters.

| Artefact | Reason |
|---|---|
| `surface/prior-cves.json` | Records published vulnerabilities across releases |
| `surface/cve-hotspots.json` | Maps CVEs to release tag pairs, so it spans versions by construction |

## Concurrency and durability

`check` and `show` are read-only. `stamp` rewrites the map through a temp file
and an atomic replace, so a crash mid-write leaves the previous map intact and
never a truncated one. No lock is taken, and the phases invoke it
sequentially.

## Comparison rules

| Rule | Rationale |
|---|---|
| Agreement is never reported when only one independent group answered | Nothing to compare is not a verified match, and a green line reads as one |
| Two files that cannot disagree never count as two sources | Eleven artefacts built from one `version.mk` agree by construction, and counting them as eleven turned a guard that compared nothing into a clean exit 0 |
| The stamp key always begins with `comment` | `trace2seed.py` would treat any other key as a request number and the seeds phase would silently lose it |
| The two comparisons stay apart | Artefacts disagreeing with the checkout means regenerate locally. Artefacts disagreeing with the target means check out a different release first. The remedies are different work |
| An unreadable artefact never lets the check pass | An artefact that cannot be parsed is logged as a warning and excluded, and the exclusion is visible in the printed source list |
| Only an exact version string counts as agreement | 610.57.04 and 610.62 share a branch and differ in ABI |

## Design notes

`tools/ioctl_map.json` carries the stamp because the map is a flat mapping of
names to request numbers with no provenance block of its own. Every
inventory under `surface/` records its own `driver_version` when it is
generated, so none of them needs a stamp, and `_find_driver_version` searches
the first two levels of each record by key name so a new extractor with its own
record shape is still read.

`--no-running` exists because a development workstation with its own NVIDIA
driver reports a version that has nothing to do with the target. On the target
the loaded driver is the authority, and the flag is left off.

## See also

- [Attack surface](/gspwn/architecture/attack-surface/)
- [ioctl_inventory.py](/gspwn/architecture/components/ioctl-inventory/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
