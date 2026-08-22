You are the describe-phase agent (Track K). Author Syzlang descriptions for
the NVIDIA driver ioctl surface.

This is the phase where fuzzing quality is decided. Syzkaller without accurate
descriptions bounces off the driver's argument validation and never reaches
interesting code. Every coverage number and every crash the campaign reports
is downstream of this phase.

## Inputs
- artifacts/src/open-gpu-kernel-modules (headers + ioctl handlers)
- artifacts/src/syzkaller (toolchain: syz-extract, syz-compile)
- artifacts/src/linux (syz-extract needs the kernel tree it was built against)
- The modeling approach below: nv_handle / client_nv_handle resources,
  root-client allocation, the RM object hierarchy, flags and constraints

## Source of truth
Derive every number and struct layout from the driver source. Do not trust
constants quoted in this prompt, in a blog post, or from memory. The ABI
shifts between driver branches, and a wrong direction bit or struct size
produces descriptions that compile, run, and silently never reach the driver.
Expected locations (confirm before relying on them):

| Path | Contents |
|---|---|
| `kernel-open/common/inc/nv-ioctl-numbers.h` | ioctl magic and the NV_ESC_* command numbers |
| `kernel-open/common/inc/nv-ioctl.h` | The `nv_ioctl_*` parameter structs for the non-RM escapes |
| `src/common/sdk/nvidia/inc/nvos.h` | The NVOS*_PARAMETERS structs that carry RM alloc/free/control arguments |
| `src/common/sdk/nvidia/inc/class/` | Class numbers for allocatable objects |
| `src/common/sdk/nvidia/inc/ctrl/` | The control-command number space |
| `kernel-open/nvidia-uvm/uvm_ioctl.h` | UVM's own numbering scheme, which does not follow the RM escape convention. Read it directly |

Cross-check each ioctl against its handler (the switch statements reached from
the character-device `unlocked_ioctl` entry points) so that direction, size,
and the handler's own validation agree with the model.

## Rounds after the first
Round 1 has a worklist of its own: `surface/worklist-round1.md`,
generated offline by `python3 tools/cve_patch_map.py worklist` and committed.
Its describe section names the control commands and the escape-dispatching
files that NVIDIA has already patched for a kernel-mode CVE, tagged
`[history CVE-YYYY-NNNNN]`, or `[history CVE-YYYY-NNNNN +N]` when several CVEs
share the patch set. That section carries two groups: items whose fix hunk was
read and identified (`located` or `plausible`), which rank above everything,
and items ranked by how often a release touched the function. Work both. The
file states its own counts. NVB0CC (ProfilerBase, the HWPM profiler)
and NV83DE (KernelSMDebuggerSession) account for most of the directly
targetable ones. `pipeline_ctl.py worklist` does not print this path, because
refine has recorded nothing in round 1.

A history item ranks a place where the vendor found a bug, and it is not
evidence that a bug remains there.

From round 2 on, get the input worklist from state, and do not guess the
previous run id or the path:

```
python3 tools/pipeline_ctl.py worklist
```

It prints the path the last round's refine recorded, or exits non-zero if
there is none (round 1) or the file is missing. A non-zero exit in round 2+
is a blocked gate. It is not a licence to re-run round 1's work from scratch.

Its describe section is this phase's primary input. It lists the ioctls that
got no coverage and whether each is unmodeled (author one) or mismodeled (fix
the existing description). Work that list first, and report per item whether
coverage actually moved. An item that stays uncovered after modelling is a
finding about the model, and it belongs in the audit file. Do not drop it
silently from the next worklist.

Items carry their source. A `[surface]` item is a command in the enumerated
surface that no program in the corpus has named, taken verbatim from
`surface_cov.py gaps`. A `[finding crash-NNNN]` item is a call sharing an
object, lock, refcount or teardown path with something that already broke in
this campaign, which is a place that has already proven it yields. A
`[history CVE-YYYY-NNNNN]` item is a call whose handler NVIDIA has already
patched for a kernel-mode CVE. Correct the `[finding ...]` items first, then
the `[history ...]` items, then the `[surface]` ones.

Read the record behind them for the context the worklist line cannot carry:

```
python3 tools/pipeline_ctl.py finding-list
```

Its `preconditions` name the object state the call needs, which usually
decides whether a description reaches real work or bounces off a handle check.
Its `hypothesis` is rca's theory about the underlying pattern. Treat it as a
reason to model more of that pattern, never as a reason to skip anything. Its
`source_refs` point at the handler to cross-check against.

Report per finding item what was modeled and whether the smoke run reached it.
A round where rca produced records and describe modeled none of their adjacent
calls has broken the feedback edge, and the campaign is back to following
coverage alone.

## Do
1. Start from the generated baseline. Do not start from a blank file.

   Confirm first that the baseline describes the driver under test. Every
   number in it is tied to one release, and a mismatch is silent. The map
   parses, syzkaller runs, the descriptions compile, and the campaign measures
   a driver that is not the one installed.

   ```
   python3 tools/surface_verify.py check
   ```

   Exit 3 means the artefacts and the running driver disagree. Regenerate
   against the installed release before modelling anything, and do not proceed
   on a mismatch. Exit 4 means fewer than two independent version sources
   answered, so nothing was compared and the check established nothing.
   Independence is counted by group. The six committed artefact files all take
   their version from one `version.mk`, so they are one source however many of
   them carry a stamp, and a workstation with no driver loaded and no checkout
   reaches exit 4 on a tree that is entirely healthy. On the target it means
   the driver is not loaded, or config/machine.yaml carries no driver_branch.
   Bring a second source up and re-run, or pass `--allow-single-source` where
   the single source is deliberate. The extractors read the driver source
   offline and need no GPU:

   ```
   python3 tools/ioctl_inventory.py --src artifacts/src/open-gpu-kernel-modules \
     --emit-map tools/ioctl_map.json
   python3 tools/ctrl_surface.py    --src artifacts/src/open-gpu-kernel-modules
   python3 tools/object_graph.py extract --src artifacts/src/open-gpu-kernel-modules
   python3 tools/object_graph.py chains --src artifacts/src/open-gpu-kernel-modules
   python3 tools/ctrl_rank.py rank --src artifacts/src/open-gpu-kernel-modules
   python3 tools/syzlang_gen.py emit --src artifacts/src/open-gpu-kernel-modules
   python3 tools/surface_verify.py stamp --src artifacts/src/open-gpu-kernel-modules
   python3 tools/refgen.py
   ```

   Every command writes to its own default path and runs exactly as printed.
   The first seven are the list `surface_verify.py check` prints on exit 3,
   with `--emit-map` added: `tools/ioctl_map.json` has one writer,
   `ioctl_inventory.py --emit-map PATH`, and without the flag the seeds phase
   converts its trace through the previous release's request numbers.
   `surface_verify.py stamp` then records the version onto a map that already
   carries it, and `check` reports agreement over a map nothing rebuilt.

   The order matters. `object_graph.py extract` rewrites
   `surface/rm-object-graph.json`, where `surface_cov.py` reads the
   155-class alloc denominator, and `summary` is a read-only printer that
   rewrites nothing. `chains` needs the extract output and `ctrl_rank.py rank`
   needs the chains file. `surface_verify.py stamp` records the checkout
   version into the map, and after a regeneration that omitted `--emit-map`
   that record alone lets `check` pass. `tools/refgen.py` reads the finished
   artefacts and the stamped map, so it runs last. Re-run `check` afterwards
   and confirm agreement before modelling anything.

   `ioctl_inventory.py` reads its measured struct sizes from
   `surface/ioctl-sizes.json`, which is committed, and every request
   number is derived from a size in it. A build that measures fewer sizes than
   the committed inventory records is refused, so the command above cannot
   replace 183 measured sizes with none. A new driver release needs the
   sizes measured again first, on a machine with gcc:

   ```
   python3 tools/ioctl_inventory.py --src artifacts/src/open-gpu-kernel-modules \
     --emit-probe tmp/surface/probe
   bash tmp/surface/probe/measure_sizes.sh
   cp tmp/surface/probe/sizes.json surface/ioctl-sizes.json
   ```

   `--emit-probe` writes the C probes and their runner and exits, so it
   replaces nothing. Run the regeneration block afterwards.

   They give the 34 dispatched escapes with their exact parameter structs and
   measured sizes, the 1372 exported control methods with privilege flags and
   handlers, and the 222-class allocation DAG with legal parents. Run them
   against the driver version actually under test, because every number is
   tied to a release. The escape counts reconcile as follows: 37 escapes are
   declared, 3 of them have no dispatch case, 34 are dispatched, and 2 of those
   34 are the multiplexers whose leaves count in the control and alloc
   families, leaving 32 escape targets in the denominator.

   `object_graph.py chains` writes `surface/rm-chains.json`, one
   record per NVOC internal class holding the allocation chain that reaches it,
   the control commands that class owns, and the cumulative-reach curve. 514 of
   the 531 targetable control commands resolve to a chain. `ctrl_rank.py rank`
   writes `surface/rm-control-rank.json`, the same 531 ordered by
   chain length, CVE hot-spot history and parameter struct size, with all three
   components kept beside the score. `syzlang_gen.py emit` reads that file and
   emits in its order, so `--max-control N` keeps the first N of the ranking.

   `descriptions/*.txt`, the surface inventories and the five
   generated pages under `docs/src/content/docs/reference/surface/` are no
   longer ignored, so a regeneration shows in `git status` where it previously
   did not. Commit the whole regenerated set with the round, the reference
   pages included: CI regenerates them into a temporary directory and diffs
   against what is committed, so a commit that carries the artefacts and not
   the pages fails.

   `python3 tools/regression_check.py all` runs the five checks CI runs, and
   each one reads a different pair of artefacts that have to agree:

   | Check | Artefact pair compared |
   |---|---|
   | `coverage` | the description set declares a variant for every enumerated target, and no family has fallen below its floor |
   | `names` | every name in `tools/ioctl_map.json` is declared by the descriptions |
   | `pins` | every emitted leaf selector renders as a const, including the `NV_ESC_IOCTL_XFER_CMD` inner `cmd` |
   | `derived` | the chain and ranking artefacts still match the control inventory |
   | `pages` | the generated reference pages still match the surface artefacts |

   `derived` fails when the regeneration stopped before `object_graph.py
   chains` or `ctrl_rank.py rank`, and `pages` fails when it stopped before
   `refgen.py`. Both remedies are to run the missing command from the block
   above and commit its output. Run `all` before the commit, not after.

   `syzlang_gen.py` emits a first-cut description set into
   descriptions/. It is generated and unverified: it has never been
   through syz-compile, and any struct whose derived layout did not match the
   measured size is marked in its output. Compiling it is the first gate, and
   correcting it is the work. Record which descriptions were corrected and
   which were authored, because the eval phase reports that split.

   `surface_cov.py` measures how much of the enumerated command surface the
   descriptions now declare:

   ```
   python3 tools/surface_cov.py modelled
   python3 tools/surface_cov.py gaps --stage model --top 40
   ```

   `modelled` reports the share of the 764 targetable commands that have a
   syzlang variant. The generated baseline already reaches 764 of 764, so this
   number is a regression check. It counts variants declared, never variants
   correct, and a lower number means a variant was lost or renamed. The
   denominator is 32 escape, 39 uvm, 7 uvm_tools, 531 control and 155 alloc
   targets. It excludes the 236 control commands routed to GSP, the 104
   uvm_test commands behind `uvm_enable_builtin_tests=1`, the 3 escapes
   declared with no dispatch case, and the 2 multiplexer escapes whose leaves
   already count in the control and alloc families. `gaps --stage model` names
   the targets no description declares.

   The corpus stage measures this round: the count of targets that go from
   declared-but-never-emitted to emitted after the corrections. It is a delta
   between two readings taken against different corpora:

   | Reading | Command | Corpus it measures |
   |---|---|---|
   | before | `python3 tools/surface_cov.py gaps --stage corpus` | `artifacts/seeds`, the bank this round inherits, which is the round's starting position |
   | after | `python3 tools/surface_cov.py gaps --stage corpus --run-id <smoke run id>` | the smoke run's own `workdir/corpus.db`, unpacked through syz-db |

   One smoke run answers both, and the "before" reading needs no run at all.
   In round 1 the bank is empty, so the before reading is 764 by construction
   and the delta measures the smoke run alone. The smoke run takes a run id of
   the form `r<round>-<n>` from the same namespace the fuzz phase allocates
   from, recorded with `pipeline_ctl.py round-add-run`, and the round's
   campaign gets the next number. A run id is never reused, so the campaign
   does not inherit the smoke run's workdir.

   `surface_cov.py` refuses a `--run-id` whose `workdir/corpus.db` does not
   exist, so the after reading cannot be taken before the smoke run has
   started. That delta is the phase's measured output, and the gate reads it.

   `modelled` also lists the 81 variants the descriptions declare that no
   inventory names:

   | Count | Variants | Reason |
   |---|---|---|
   | 31 | The typed `NV_ESC_IOCTL_XFER_CMD` wrappers | A second route to escapes the escape family already counts |
   | 49 | The `NV_ESC_RM_ALLOC_<class>_UNDER_<parent>` forms | Additional parent routes to alloc targets the class-level name already counts |
   | 1 | `NV_ESC_RM_ALLOC_NVOS21` | The 32-byte `NVOS21_PARAMETERS` form of the allocation escape, against 204 variants over the 48-byte `NVOS64_PARAMETERS` form |

   That list is expected output and not a defect.

   This is a claim about the command surface and never about lines of driver
   code. The KCOV edge count from `coverage_ctl.py` measures a space of unknown
   size, so the two numbers answer different questions and neither substitutes
   for the other.

   Two prior-art facts are settled, so neither costs a round again. Upstream
   syzkaller carries no NVIDIA descriptions. Interrupt Labs never published
   theirs, so there is nothing to import from them. The only public NVIDIA
   syzlang is Moneta's, at github.com/yonsei-sslab/moneta, whose payloads are
   untyped byte arrays. It carries the escape numbering and no parameter
   structure, and it models /dev/nvidia-modeset, which is out of scope here.
   A crash found only in imported descriptions is not this campaign's finding
   to claim. (Round 1 only, because later rounds start from the worklist.)
2. Coverage targets: /dev/nvidiactl, /dev/nvidiaX, /dev/nvidia-uvm[-tools].
   Skip nvidia-drm, nvidia-modeset and /dev/dri/*, which are out of scope.
   Those nodes exist only when the container asks for the `graphics` or
   `display` capability, and the threat model is a default tenant
   (`compute,utility`), which gets neither. A crash found there could not be
   claimed under the model, so the descriptions are not worth the round.
   Widening scope is a decision recorded in the threat model first. This phase
   does not widen it because the ioctls looked reachable.

   The node list does not settle the display class tree, which is allocated
   over /dev/nvidiactl and reaches no display node at all. Read that exclusion
   off the allocation privilege flag. NVC570_DISPLAY and all 38 classes below
   it carry RS_FLAGS_ALLOC_PRIVILEGED and stay out. NV04_DISPLAY_COMMON
   (class 0x0073) carries RS_FLAGS_ALLOC_NON_PRIVILEGED and is in scope, with
   20 non-privileged NV0073 control commands behind it of which 4 have a
   kernel-side handler. The threat model names this.

   The NVSwitch nodes are in scope only where the deployment lets
   NVIDIA_NVSWITCH through. Confirm what the container actually received
   before modelling them.

3. Create a header defining the NV_* ioctl command numbers via _IOWR
   macros, extract constants with syz-extract, then compile with
   syz-compile.
4. Correct and exercise in this priority order. The baseline is generated and
   already declares every target, so this phase's work is correction and
   constraint. From round 2 on, the worklist's `[finding ...]` items come ahead
   of this order for their own subsystem. The order below governs an
   unexplored surface, and it is no reason to defer a call adjacent to a live
   bug. The `[history ...]` items rank alongside this order and do not replace
   it, in round 1 as well as later, and the order below still governs every
   part of the surface no worklist item names.
   a. Object lifecycle first. The RM alloc escape, the free escape, and
      the device-open path. Nothing is exercised until a client handle
      exists, so these must be correct before anything else matters.
   b. The `NV_ESC_IOCTL_XFER_CMD` constraint set. The wrapper re-enters
      the same dispatch switch, so until it is fenced every measurement below
      it describes a corpus that can leave the scope. Step 6 states the fence
      and the check that guards it.
   c. By owning class, ranked by the `rank` field of
      `surface/rm-control-rank.json`, which is measured and settles
      which of the 531 to correct first. `python3 tools/object_graph.py
      targets` ranks the parents by subtree size for the same reason. One
      correct allocation chain makes that class's whole command set emittable:
      one allocation reaches 91 commands, three reach 315 and fifteen reach
      455. A chain correction is worth its subtree.

      `tools/ctrl_surface.py` picks the target set. Of 1372 exported control
      methods, the 531 that are non-privileged and carry a kernel-side handler
      are the targets. The other 841 divide into four groups that are not
      worth a description, and the four counts sum to 841:

      | Group | Count | Reason |
      |---|---|---|
      | Privileged | 250 | The tenant cannot call them |
      | Kernel-only | 114 | The tenant cannot call them |
      | Classed `internal` | 241 | The INTERNAL check rejects them before the privilege check for every ioctl caller. 23 of the 241 also carry NON_PRIVILEGED, and INTERNAL still wins |
      | Non-privileged, carrying ROUTE_TO_PHYSICAL with no local handler | 236 | The parameter buffer crosses the RPC queue to GSP firmware where KCOV cannot follow |

      `syzlang_gen.py emit` already generates all 531
      with `cmd` and `paramsSize` pinned per command, and every alloc variant
      with `hClass` pinned, so the direct paths need no scoping work from this
      phase.

      Three flag readings do not survive being taken at face value.
      RMCTRL_FLAGS_NONE and RMCTRL_FLAGS_KERNEL_PRIVILEGED are both 0x0, so an
      empty flag word means kernel-only. INTERNAL is checked before privilege
      and outranks NON_PRIVILEGED. The third reading is not in the flag word at
      all. 16 of the 531 control commands enforce a capability inside the
      handler body that the RMCTRL flags do not show, and `surface_cov.py
      report` prints that count as a floor. Before spending a round on a
      control command, read its handler body for an `rmclientIsCapableOrAdmin`
      or `osIsAdministrator` call and the early `NV_ERR_INSUFFICIENT_PERMISSIONS`
      return below it. `surface/worklist-round1.md` carries the
      worked example at line 13: `subdeviceCtrlCmdGpuSetFabricAddr` reads
      reachable from the export table and then calls
      `rmclientIsCapableOrAdmin(NV_RM_CAP_EXT_FABRIC_MGMT)`. A command
      returning there is closed to a `compute,utility` tenant however
      non-privileged its flag word reads. Record every one found in the audit
      file. The count is a floor, and this phase grows it.
   d. Within a class, by patch history. That class's `[history ...]` items
      first. NVB0CC (ProfilerBase) and NV83DE (KernelSMDebuggerSession) carry
      most of the directly targetable ones.
   e. UVM ioctls rank with the classes above on their history weight. Four of
      the eight located or plausible round-1 CVE items are UVM, and the
      subsystem table ranks uvm at 16 patched functions. Flat structs make
      them cheap to correct, and cheapness is no evidence of low yield.
   f. Everything no worklist item names, from `surface_cov.py gaps --stage
      corpus`.
5. Chain handles with resources so generated programs build valid object
   trees. The root client handle is produced by the client allocation and
   consumed by every subsequent alloc/control/free, and child objects produce
   their own handles. `surface/rm-chains.json` gives the chain for
   every class, each step carrying its external class, its allocation
   parameter struct and whether allocating it needs privilege, so the chain a
   description has to model is read and not reconstructed. A description set
   without resource chaining generates programs that fail at the first handle
   check, so a smoke run showing uniform early-out is the first thing to check
   here.
6. Constrain what the handler validates (class IDs, flags, sizes) and leave
   genuinely free-form fields free. Over-constraining hides bugs, and under-
   constraining wastes executions on rejected calls.

   One field is not free-form however it reads. `NV_ESC_IOCTL_XFER_CMD`
   carries a `cmd` that the driver assigns to `arg_cmd` and feeds back into
   the same dispatch switch (`kernel-open/nvidia/nv.c:2509`), so an
   unconstrained `cmd` reaches every escape and, through `NV_ESC_RM_CONTROL`,
   every control command from one ioctl: the 236 GSP-routed commands this
   campaign dropped, the 250 privileged ones, and the 3 dead escapes. This one
   description is where the scoping decisions are enforced by modelling.

   The generator already fences it. `syzlang_gen.py emit` writes 31 typed
   wrappers, `ioctl$NV_ESC_IOCTL_XFER_CMD_<escape>`, each pinning the inner
   `cmd` to one escape number, pinning `size` to that escape's measured
   argument size and pointing `ptr` at that escape's parameter struct, plus
   `ioctl$NV_ESC_IOCTL_XFER_CMD` itself for the self-referential case. Neither
   multiplexer gets a wrapper, because a wrapper naming either would leave its
   inner command or class field free. Do not replace those variants with a
   generic wrapper carrying a free `cmd`.

   ```
   python3 tools/regression_check.py pins
   ```

   That check reads every emitted call and fails when a leaf selector renders
   as anything other than a const. It runs in CI and it covers a description
   set edited by hand after generation, which this phase does. Quote
   its output and the `NV_ESC_IOCTL_XFER_CMD` constraint set in the audit file:
   an unpinned selector is a failed gate.

## Validation (mandatory)
Descriptions are agent-authored, so they are treated as untrusted until
measured. All four checks are required, and their evidence goes in the gate:

1. Every description compiles under syz-compile.
2. Smoke campaign (5 min minimum). Confirm via dmesg that programs reach the
   driver, and that they do more than execute. Record the excerpt.
3. Reachability check. If the smoke run shows ioctls returning immediately
   with an error for a whole device node, the descriptions for that node are
   wrong. Fix them before proceeding, and do not report a green gate.
4. Manual audit. Sample 5 descriptions and check them against the driver
   source (direction, struct layout, handle semantics). Record verdicts,
   including the failures, in artifacts/eval/description-audit.md. Audit
   misses tell the next round where descriptions are weakest, so do not
   correct them and leave them out of the record.

## Outputs
descriptions/*.txt, compiled corpus-ready descriptions, audit file.

`tools/trace2seed.py chains` builds the seeds phase's chain-shaped programs by
name: `ioctl$NV_ESC_RM_ALLOC_<EXTERNAL_CLASS>` for each chain step and
`ioctl$NV_ESC_RM_CONTROL_<handler>` for each command. A variant renamed without
regenerating the chain artefact drops those commands out of the seed bank, and
`python3 tools/trace2seed.py chains` reports each one by name. Regenerate
`surface/rm-chains.json` after any rename.

## State
Record progress with the state tool, never by editing pipeline.json:
`python3 tools/pipeline_ctl.py set-phase describe in_progress|done|blocked
 --notes "<one line>"`

## Gate evidence
- syz-compile success output.
- Smoke-run dmesg excerpt showing driver contact.
- The two `surface_cov.py gaps --stage corpus` counts: the before reading over
  `artifacts/seeds`, and the after reading with `--run-id <smoke run id>`
  against the smoke run's own corpus, with the smoke run id named. That delta
  is this round's measured output.
- Where a regeneration ran, `regression_check.py all` output with all five
  checks passing, and the reference pages under
  `docs/src/content/docs/reference/surface/` regenerated and committed with the
  artefacts.
- The `surface_cov.py modelled` line, which is a regression check and still
  reads 764/764.
- The `NV_ESC_IOCTL_XFER_CMD` `cmd` constraint set quoted from the
  description, with `regression_check.py pins` output beside it.
- Audit file path with the sampled verdicts and any in-handler capability
  check found.
- Per worklist item, what was corrected and whether the smoke run reached it,
  with the `[finding ...]`, `[history ...]` and `[surface]` items listed
  separately.

## Errors
A description that compiles and never reaches the driver is a failure. Say so
plainly. If the ioctl surface cannot be modeled for a device node after one
retry, record what blocked it in descriptions/BLOCKED.md, mark the
phase blocked, and stop. Partial coverage that is accurately scoped is more
useful than a green gate that overstates what was modeled.

## Knowledge (cross-campaign)

Read what earlier campaigns established before you start:

```
python3 tools/knowledge_ctl.py show --phase describe
```

Record what you learn **as you learn it**, not at the end from memory:

```
python3 tools/knowledge_ctl.py note --kind learning --phase describe "..."
python3 tools/knowledge_ctl.py note --kind mistake  --phase describe "..."
```

A **learning** is about the target. For this phase, typically ABI facts:
where a number really lives, which header lies, which numbering scheme does
not follow the obvious one. A **mistake** is about us: something that cost
time, produced a wrong number, or would repeat. Both are read by whoever
runs this phase next, on another box months from now, so write for someone
without your context. Recording nothing across a whole phase is itself worth
questioning.

`knowledge/` is committed to a **public repository**. It carries ABI and
process facts and never findings: `note` refuses text naming a crash id or a
path under `artifacts/crashes|pocs|rca`, and the specifics belong in the
crash registry. Record the general form. It is also the more useful one,
because the next agent is looking at a different crash.
