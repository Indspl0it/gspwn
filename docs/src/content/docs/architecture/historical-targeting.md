---
title: Historical targeting
description: "The third steering signal. NVIDIA's bulletins name the release that fixed each CVE, the driver's 216 release tags let that release be diffed, and the changed functions join to the ioctl surface."
---

Two of the campaign's three steering signals come from the campaign itself:
coverage, derived by `refine` from the run's own curve, and findings, derived
by `rca` from crashes this campaign produced. Both are empty before anything
has run, which left round 1 following the structural priority order alone
across the 531 non-privileged control commands that have a kernel-side
handler.

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

A release diff establishes three claims and leaves three open.

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
repository: 216 tags resolve to 216 distinct commits, and 65 of them are
ancestors of `HEAD`. Sorting `580.95.05` against the tag list numerically
returns `580.94.18`, which is on a different line, and `git describe` on its
parent returns `580.82.09`, which is the release it actually followed.

Two bracket shapes carry no evidence and the tool marks both.

- Cross-branch, detected when the predecessor tag's major version differs from
  the fixing tag's. The diff is a branch divergence. `565.77..570.86.15`
  changes 528 ioctl-reachable files.
- Version bump only, detected when zero ioctl-reachable files changed.
  `570.86.15..570.86.16` touches the version headers and the README.

Neither counts toward the hot-spot ranking, and neither counts as a branch in
the cross-branch intersection described below.

## Path filter

RM control handlers are under `src/nvidia/src/kernel`, so a filter stopping at
the unix arch layer misses the surface the control multiplexer reaches.

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

Three path families are excluded.

- `kernel-open/nvidia-drm/`, `kernel-open/nvidia-modeset/` and
  `src/nvidia-modeset/` were excluded when the filter was written, on the
  reading that those nodes reach a container only under the `graphics` or
  `display` capability. The CDI injection path grants both node families to a
  `compute,utility` tenant, so the threat model places them inside the Track K
  attacker's reach and this exclusion is a known gap in the historical signal.
  See [Threat model](/gspwn/architecture/threat-model/).
- `kernel-open/nvidia-peermem/`, an RDMA peer-memory shim with no ioctl of its
  own.
- `src/nvidia/generated/`, NVOC output regenerated wholesale on every release.
  Opt back in with `--include-generated`.

## Isolating the fix

Three mechanisms narrow a patch set, and all three are recorded so a reader can
see which one carried a given verdict.

### Cross-branch intersection

A CVE fixed on three branches produces three
diffs. Each carries its own branch's feature work and none of them carries the
others'. The intersection is small: for CVE-2025-23277 it is exactly one
function across two branches, and for CVE-2024-0090 it is two across three, one
of which is a 240-line named hardware workaround.

### Signal classification

Each changed function is scored against
`SIGNAL_PATTERNS` in `tools/cve_patch_map.py`, twelve regular expressions over
the added lines of a hunk. A signal orders the reading queue. A signal is never
a verdict, and a CVE never graduates by accumulating signal points.

| Signal | Added line it fires on |
|---|---|
| `null_check` | A comparison against `NULL`, or `if (!pFoo)` |
| `bounds_check` | `NV_CHECK_OR_RETURN`, `NV_ASSERT_OR_RETURN`, `NV_CHECK_OK_OR_RETURN` or `NV_ASSERT_OR_ELSE` carrying a relational operator |
| `size_validation` | A size, length, count, offset or index compared |
| `overflow_guard` | `portSafe*`, `overflow`, `NV_U32_MAX`, `NV_U64_MAX`, or a `MAX_*` divided or subtracted |
| `copy_bound` | `portMemCopy`, `portMemExCopy`, `copy_from_user`, `copy_to_user`, `NV_COPY_FROM_USER`, `NV_COPY_TO_USER` or `os_mem_copy` |
| `refcount` | A refcount name, `serverutilRef*`, `IncRef`, `DecRef`, or an atomic increment or decrement |
| `locking` | A lock, mutex, semaphore or spinlock acquire or release, `rmapiLock*`, or `GPU_LOCK*` |
| `handle_validation` | `serverutilValidate*`, `clientValidate*`, `refFind*`, `serverGetClientUnderLock`, `RES_GET_HANDLE`, or an `hClient` comparison |
| `signedness` | An `NvU8` to `NvS64` type name, `unsigned` or `size_t`. Kept only where the hunk both adds an `NvU`/`NvS` type its removed lines lack and removes one its added lines lack, because a type name in an added line is otherwise ordinary |
| `uninitialized_memory` | `portMemSet`, `memset`, `os_mem_set`, `NV_ZERO_STRUCT` or `portMemSetPattern` |
| `free_ordering` | `portMemFree`, `objDelete`, `os_free_mem`, `kfree`, `uvm_kvfree`, or an assignment of `NULL` |
| `user_pointer` | `NvP64`, `NvP64_VALUE`, `__user` or `pUserParams` |

### Reading the hunk

A subject line, a filename and a signal name are all
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

Four joins turn a changed function into a target. Three match it into a surface
inventory, and the fourth reads the object graph for the allocation chain the
matched command needs.

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

The three tags carry claims of decreasing strength.

- `[finding crash-NNNN]` claims a bug exists here now, in this driver, in this
  campaign. It is the strongest of the three, because nothing else in the
  pipeline produces it.
- `[history CVE-YYYY-NNNNN]` claims a bug existed here once, in a version since
  patched, and that the patched code shows its shape. It is weaker than a
  finding and stronger than an unexplored surface.
- `[surface]` claims only that nobody has looked here. It is the default.

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

Seven limits bound the historical signal.

- The record starts at 515.43.04. Fixes shipped in R390, R450, R470 and R510
  have no tag to diff. Four kernel-mode CVEs from 2020 and 2021 predate the
  PSIRT repository as well.
- Batch bulletins do not decompose. Bulletins 5415 and 5452 fix 19 and 12
  kernel-mode CVEs in one release each, with near-identical per-CVE
  descriptions. One patch set answers for all of them.
- The bulletin names a public release, and the commit may be earlier. For
  CVE-2024-53869 the R550 bulletin row names `550.144.03`, and `550.142`
  already carries the hunk. A branch can receive a fix before the release the
  bulletin names.
- A fix outside the open modules is invisible. The user-mode driver, the GSP
  firmware image and `nvidia-modeset` all ship in the same driver package and
  none of them is in this repository.
- The signal table is a heuristic. It fires on ordinary refactoring and misses
  a fix expressed as a data-structure change. Its only job is ordering the
  reading queue.
- Two of the seven command families carry no historical signal. The join
  reaches the RM control, UVM and escape inventories and the object graph. The
  `modeset` family, 64 targets, and the `drm` family, 24 targets, entered the
  denominator after the path filter was written and neither is diffed.
- Frequency measures release churn until it is filtered. An unfiltered count
  ranks `nvidia.Kbuild`, the version headers and the GSP RPC poll loop above
  every handler. The ranking counts only same-branch releases under a footprint
  ceiling, and only named functions carrying a signal.

## Requires SUT

Three questions the historical signal raises need a system under test to
answer.

- Whether the modelled container can allocate `MAXWELL_PROFILER_DEVICE`. The
  profiler classes are at depth 4 and their constructors carry checks beyond
  the allocation privilege flag.
- Whether CVE-2026-24195's path is reachable at all. The fixed hunk needs two
  GPUs registered in one UVM VA space.
- Whether a history item converts to a crash. That is the point of the tag, and
  round 1 measures it.
