---
title: Historical targeting
description: "The third steering signal. NVIDIA's bulletins name the release that fixed each CVE, the driver's 216 release tags let that release be diffed, and the changed functions join to the ioctl surface."
---

Two of the campaign's three steering signals come from the campaign itself.
Coverage says where the fuzzer has not been, derived by `refine` from the run's
own curve. Findings say where bugs have been found, derived by `rca` from
crashes this campaign produced. Both are empty before anything has run, which
left round 1 following the structural priority order alone across the 531
non-privileged control commands that have a kernel-side handler.

The third signal exists in public data and costs no campaign time. NVIDIA's PSIRT
bulletins name, per CVE and per driver branch, the version that carries the
fix. `NVIDIA/open-gpu-kernel-modules` carries 216 release tags from `515.43.04`
to `610.57.04`, and NVIDIA squashes each release into a single commit, so the
diff from a release to its predecessor is that release's complete patch set.

`tools/cve_patch_map.py` mechanises the resolution and the diff and writes
`surface/cve-hotspots.json`. `tools/cve_fix_verdicts.json` carries
the per-CVE judgement about which hunk in a patch set is the fix, with the
evidence behind each. `cve_patch_map.py worklist` renders both into
`surface/worklist-round1.md`, in the format `refine` produces for
every later round, so a new bulletin regenerates the worklist without a
rewrite.

## Claims a release diff supports

| Claim | Status | Basis |
|---|---|---|
| The release that carries the fix for one CVE on one branch | Established when the bulletin names a Linux row for a product shipping the open kernel modules, and the updated version is present as a tag | The Security Updates table in the bulletin |
| The tag pair whose diff is that release | Established | `git describe --tags --abbrev=0 <tag>^` on the fixing tag |
| The ioctl-reachable functions that release changed | Established | The diff, filtered to the path set below |
| Which hunk in the release is the security fix | Not given by NVIDIA. Feature work and refactoring ship in the same release, labelled the same way | Judgement, recorded per CVE with its evidence |
| Which of several CVEs a hunk belongs to | Not given, and undecidable from the diff when one release fixes several | Bulletin 5415 fixes 19 kernel-mode CVEs in one release per branch |
| The version that introduced the defect | Never stated by NVIDIA, and not derivable from the fixing release | |

## Branch bracketing

The predecessor tag comes from git ancestry and never from a version sort.
NVIDIA maintains its driver branches as separate lines of history in this
repository: 216 tags sit on 216 distinct commits, and only 95 of them are
ancestors of `HEAD`. Sorting `580.95.05` against the tag list numerically
returns `580.94.18`, which is on a different line, and `git describe` on its
parent returns `580.82.09`, which is the release it actually followed.

Two bracket shapes carry no evidence and the tool marks both.

| Shape | Detection | Consequence |
|---|---|---|
| Cross-branch | The predecessor tag's major version differs from the fixing tag's | The diff is a branch divergence. `565.77..570.86.15` changes 528 ioctl-reachable files |
| Version bump only | Zero ioctl-reachable files changed | `570.86.15..570.86.16` touches the version headers and the README |

Neither counts toward the hot-spot ranking, and neither counts as a branch in
the cross-branch intersection described below.

## Path filter

An RM control handler lives under `src/nvidia/src/kernel`, so a filter that
stops at the unix arch layer misses the surface the control multiplexer
reaches.

| Included | Reason |
|---|---|
| `kernel-open/nvidia/` | The `nvidia.ko` glue and the escape entry points |
| `kernel-open/nvidia-uvm/` | The whole UVM module |
| `kernel-open/common/inc/` | The ioctl ABI headers |
| `src/nvidia/arch/nvalloc/unix/` | The escape dispatch and the file-private layer |
| `src/nvidia/interface/` | The RM interface headers |
| `src/nvidia/src/kernel/` | Every control handler and every object constructor |
| `src/nvidia/src/libraries/` | The MMU walker and the port utilities the handlers call |
| `src/common/sdk/nvidia/inc/` | The parameter structs |
| `src/common/nvswitch/` | The NVSwitch device ioctls that `architecture/attack-surface` places in scope |

| Excluded | Reason |
|---|---|
| `kernel-open/nvidia-drm/`, `kernel-open/nvidia-modeset/`, `src/nvidia-modeset/` | Out of scope by threat model. The nodes exist only under the `graphics` or `display` container capability |
| `kernel-open/nvidia-peermem/` | An RDMA peer-memory shim with no ioctl of its own |
| `src/nvidia/generated/` | NVOC output, regenerated wholesale on every release. Opt back in with `--include-generated` |

## Isolating the fix

Three mechanisms narrow a patch set, and all three are recorded so a reader can
see which one carried a given verdict.

**Cross-branch intersection.** A CVE fixed on three branches produces three
diffs. Each carries its own branch's feature work and none of them carries the
others'. The intersection is small: for CVE-2025-23277 it is exactly one
function across two branches, and for CVE-2024-0090 it is two across three, one
of which is a 240-line named hardware workaround.

**Signal classification.** Each changed function is scored against a table of
security-shaped edits: a NULL test added, a bounds check added, a size compared
before a copy, a `portSafe*` arithmetic guard, a refcount taken, a lock
acquired, a handle validated, a signedness change, a `memset` of a structure, a
free reordered, a user pointer handled. A signal orders the reading queue. A
signal is never a verdict, and a CVE never graduates by accumulating signal
points.

**Reading the hunk.** A subject line, a filename and a signal name are all
evidence about where to look. The verdict comes from the hunk, and
`cve_patch_map.py` refuses a `located` or `plausible` entry that carries no
`basis` string.

| Verdict | Meaning |
|---|---|
| `located` | The fix hunk is identified and the evidence is stated |
| `plausible` | A hunk matches the CWE and the description, and the release carries other CVEs or other work the diff cannot separate from it |
| `not_located` | The release was diffed and no hunk in it can be called the fix |
| `unresolved` | Not examined, or no tag pair brackets the fix |

## The join to the ioctl surface

A changed function becomes a target when it joins one of the three surface
inventories.

| Join | Key | Result |
|---|---|---|
| RM control | The handler name, with the NVOC suffixes stripped | The `methodId`, the parameter struct, the privilege classification, and whether the command has a kernel-side handler or routes to GSP |
| UVM | The handler name | The UVM command and its syzlang name |
| Escape | The source file | The escapes that file dispatches. This is a file-level join and it does not place a function on any one escape's path |
| Object graph | The owning class of a joined control method | The allocation chain and its depth, which a description has to build before the command is reachable |

The join also carries the privilege caveat `architecture/attack-surface`
records. `subdeviceCtrlCmdGpuSetFabricAddr` (`0x2080016f`) carries
`NON_PRIVILEGED` in the NVOC export table and then calls
`rmclientIsCapableOrAdmin(NV_RM_CAP_EXT_FABRIC_MGMT)` in its handler body. The
inventory reads it as reachable and the modelled attacker cannot call it. A
history item whose target fails that second check belongs in the worklist's
excluded table with the reason, so a later round does not spend itself on it.

## Reading the worklist tag

`refine` writes `artifacts/eval/<run-id>/worklist.md` with every item tagged
`[surface]`, `[finding crash-NNNN]` or `[history CVE-YYYY-NNNNN]`.

| Tag | Claim | Strength |
|---|---|---|
| `[finding crash-NNNN]` | A bug exists here now, in this driver, in this campaign | Strongest. Nothing else in the pipeline produces it |
| `[history CVE-YYYY-NNNNN]` | A bug existed here once, in a version since patched, and the patched code shows its shape | Weaker than a finding, stronger than an unexplored surface |
| `[surface]` | Nobody has looked here | The default |

`[surface]` absorbed the older `[coverage]` tag. It names the exact enumerated
command the corpus has not reached, where an edge count only gestures at a
region, and `surface_cov.py gaps` already emits the line in that form.

A `[history ...]` item is a prior over a surface with no findings yet, and it
expires as findings accumulate. From round 2 on, `refine` produces the worklist
from coverage and findings, and a history item that no round has converted into
a crash carries less weight each round it survives.

A later phase that meets `[history ...]` and does not recognise it should treat
it as `[surface]`. The tag orders the queue and gates nothing.

## Limits

| Limit | Mechanism |
|---|---|
| The record starts at 515.43.04 | Fixes shipped in R390, R450, R470 and R510 have no tag to diff. Four kernel-mode CVEs from 2020 and 2021 predate the PSIRT repository as well |
| Batch bulletins do not decompose | Bulletins 5415 and 5452 fix 19 and 12 kernel-mode CVEs in one release each, with near-identical per-CVE descriptions. One patch set answers for all of them |
| The bulletin names a public release, and the commit may be earlier | For CVE-2024-53869 the R550 bulletin row names `550.144.03`, and `550.142` already carries the hunk. A branch can receive a fix before the release the bulletin names |
| A fix outside the open modules is invisible | The user-mode driver, the GSP firmware image and `nvidia-modeset` all ship in the same driver package and none of them is in this repository |
| The signal table is a heuristic | It fires on ordinary refactoring and misses a fix expressed as a data-structure change. Its only job is ordering the reading queue |
| Frequency measures release churn until it is filtered | An unfiltered count ranks `nvidia.Kbuild`, the version headers and the GSP RPC poll loop above every handler. The ranking counts only same-branch releases under a footprint ceiling, and only named functions carrying a signal |

## Requires SUT

| Item | Reason |
|---|---|
| Whether the modelled container can allocate `MAXWELL_PROFILER_DEVICE` | The profiler classes sit at depth 4 and their constructors carry checks beyond the allocation privilege flag |
| Whether CVE-2026-24195's path is reachable at all | The fixed hunk needs two GPUs registered in one UVM VA space |
| Whether a history item converts to a crash | The point of the tag. Round 1 measures it |
