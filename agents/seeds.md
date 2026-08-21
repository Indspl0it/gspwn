You are the seeds-phase agent (Track K). Generate seed syz-programs from
runtime traces of real CUDA workloads using tools/trace2seed.py.

## Rounds after the first
Round 1 has a worklist of its own: `artifacts/surface/worklist-round1.md`,
generated offline by `python3 tools/cve_patch_map.py worklist` and committed.
Before this file, round 1 had nothing to aim a trace at. Its seeds section
names the allocation chain each targeted control command needs, with the class
and its allocation depth: GT200_DEBUGGER at depth 3, NV04_DISPLAY_COMMON at
depth 3, NV01_DEVICE_0 at depth 2, NV01_ROOT_CLIENT at depth 1. It currently
carries 4 seeds items. Trace a workload that builds those chains. A trace that
does not build the chain leaves the command unreachable however well describe
modelled it.

Round-1 items are tagged `[history CVE-YYYY-NNNNN]`, or
`[history CVE-YYYY-NNNNN +N]` when several CVEs share the patch set. NVB0CC
(ProfilerBase, the HWPM profiler) and NV83DE (KernelSMDebuggerSession) account
for most of the commands behind them. A history item ranks a place where the
vendor found a bug. It is not evidence that a bug remains there. History orders
the work and does not predict findings. `pipeline_ctl.py worklist` does not
print this path, because refine has recorded nothing in round 1.

From round 2 on, get your input worklist from state rather than guessing the
previous run id: `python3 tools/pipeline_ctl.py worklist` prints the path the
last round's refine recorded. Its
seeds section lists surfaces classified `unreachable-by-construction` — code
that needs a real object/handle chain random generation will not build. Those
are exactly what tracing buys, so target your workloads at them rather than
re-tracing the same CUDA sample each round.

Items carry their source. A `[history CVE-YYYY-NNNNN]` item names an object
chain a patched command needs. A `[finding crash-NNNN]` item comes from the
`preconditions` of a research record: the object state that had to exist
before a real bug in this campaign could be reached. Those come first, and
they are the most specific brief you will get — "channel bound with async work
in flight" says exactly which workload to trace and at what moment. Read the
full record for the rest of the context:

```
python3 tools/pipeline_ctl.py finding-list
```

If a precondition cannot be reached from any CUDA workload you can run, say so
in the gate rather than substituting a seed that is merely nearby. A seed that
does not establish the precondition does not exercise the path, and reporting
it as covered is how the next round loses the target.

The persistent seed bank at artifacts/seeds/ also accumulates programs
promoted from previous rounds' corpora (`corpus_ctl.py promote`). Check what
is already there with `python3 tools/corpus_ctl.py stats` before generating
more — the bank is deduplicated by content, so re-adding equivalents is wasted
tracing time.

## Do
1. Check tools/ioctl_map.json covers what you will trace. It is committed and
   pre-populated: 81 request numbers covering the 34 dispatched escapes and
   the UVM and UVM-tools commands, derived from the driver source by
   `tools/ioctl_inventory.py` with every struct size measured by compiling the
   headers. It does not depend on the describe phase, so seeds runs fully
   parallel with describe and harness in round 1 as well as later rounds.

   The map records the driver version it was built from. Confirm that matches
   the driver under test before tracing, because a stale map turns real ioctls
   into comments and the seed exercises nothing:

   ```
   python3 tools/surface_verify.py check
   ```

   Exit 3 means regenerate against the installed release:

   ```
   python3 tools/ioctl_inventory.py --src artifacts/src/open-gpu-kernel-modules
   python3 tools/surface_verify.py stamp --src artifacts/src/open-gpu-kernel-modules
   ```

   A request number the map lacks is a gap to fix in the map, and never a
   reason to accept a seed that traced it as a comment.
2. Install a small CUDA workload (python3 + a minimal CUDA sample or
   pytorch if already present). Trace it:
   strace -v -f -P /dev/nvidiactl -P /dev/nvidia0 -P /dev/nvidia-uvm \
     -P /dev/nvidia-uvm-tools -o artifacts/seeds/trace.txt <workload>
3. Convert: python3 tools/trace2seed.py --trace artifacts/seeds/trace.txt \
   --out-dir artifacts/seeds/
   It prints "<n> mapped ioctls, <m> unmapped". Unmapped requests become
   comments, not syscalls, so a seed that is mostly unmapped is an open/close
   chain that exercises nothing. Read that ratio before moving on: a high
   unmapped count means tools/ioctl_map.json is missing entries describe
   should have produced, and the fix is to extend the map and re-run, not to
   accept the seed. strace prints requests it cannot name as
   `_IOC(dir, type, nr, size)`; the tool decodes that form back to a number,
   so an unmapped entry is a real gap in the map, not a parsing artefact.
4. Validate: every seed parses under syz-manager (add to corpus, watch for
   parse errors in the manager log during a 5-min smoke run).

## Outputs
artifacts/seeds/*.syz, populated tools/ioctl_map.json (commit it — it is
data, not runtime state), trace kept at artifacts/seeds/trace.txt.

## State
Record progress with the state tool, never by editing pipeline.json:
`python3 tools/pipeline_ctl.py set-phase seeds in_progress|done|blocked
 --notes "<seed count>"`

## Gate evidence
seed count, mapped/unmapped ioctl counts, smoke-run log excerpt showing no
seed parse errors. Report the unmapped count — a high unmapped ratio
means the ioctl_map is incomplete and the seeds cover less than they appear to.
Report per `[finding ...]` and `[history ...]` item whether a seed now
establishes its precondition, and name the ones you could not reach.

## Knowledge (cross-campaign)

Read what earlier campaigns established before you start:

```
python3 tools/knowledge_ctl.py show --phase seeds
```

Record what you learn **as you learn it**, not at the end from memory:

```
python3 tools/knowledge_ctl.py note --kind learning --phase seeds "..."
python3 tools/knowledge_ctl.py note --kind mistake  --phase seeds "..."
```

A **learning** is about the target — for this phase, typically workload facts:
which CUDA calls reach which ioctls, which object chains a trace can and
cannot produce.
A **mistake** is about us: something that cost time, produced a wrong number,
or would repeat. Both are read by whoever runs this phase next, on another box
months from now, so write for someone without your context. Recording nothing
across a whole phase is itself worth questioning.

`knowledge/` is committed to a **public repository**. It carries ABI and
process facts and never findings: `note` refuses text naming a crash id or a
path under `artifacts/crashes|pocs|rca`, and the specifics belong in the crash
registry instead. Record the general form — it is also the more useful one,
because the next agent is looking at a different crash.
