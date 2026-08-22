You are the seeds-phase agent (Track K). Produce seed syz-programs from two
sources, `tools/trace2seed.py chains` and `tools/trace2seed.py convert`.

## Input sources

A trace and the surface artefacts each carry half of what a seed needs.

| Source | Supplies | Cannot supply |
|---|---|---|
| `strace` of a CUDA workload | the real fd lifecycle, the real order of escapes a workload issues, the escapes that carry their command in the request number | the RM control command and the allocation class, which live inside the parameter struct |
| `surface/rm-chains.json` and `rm-control-rank.json` | the allocation chain each control command needs and the ranked command list | anything about what a real workload does |

`strace` cannot decode NVIDIA parameter structs. `NVOS54_PARAMETERS.cmd`
selects one of 531 control commands and `NVOS64_PARAMETERS.hClass` selects one
of 155 allocation classes, and neither field appears in the trace text. The
request number is the same for every leaf behind those two escapes.
`tools/ioctl_map.json` therefore records `0xc020462a`, `0xc030462b` and
`0xc020462b` under `comment_multiplexers` and gives them no call name. A
traced multiplexer call becomes a comment naming the escape and the field that
was not visible. It is not a gap in the map and extending the map cannot close
it.

The chain is the unit of work and a command is not, because a command becomes
reachable when the chain that owns it exists.
`surface/rm-chains.json` measures how steep that join is: one
allocation reaches 91 of the 531 targetable control commands, three reach 315
and fifteen reach 455. A workload that builds a chain once and then issues
every command that class owns is worth many workloads that rebuild a chain per
call.

## Do

1. Build the chain-shaped programs. This needs no SUT, no GPU and no trace, so
   run it first and run it every round:

   ```
   python3 tools/trace2seed.py chains --out-dir artifacts/seeds/
   ```

   One program per allocation chain: an `openat`, the chain's allocations in
   order, then the control commands that chain reaches, ordered by
   `surface/rm-control-rank.json`. Every class allocated along the
   way is credited, so Subdevice's three allocations also build
   RmClientResource's and Device's objects and one prologue carries all three
   classes' commands. A chain whose command list exceeds `--max-calls` is split
   across programs that each repeat the prologue.

   The exit status is part of the result. 0 means programs were written, 1
   means none were and the bank is empty, and 2 means the arguments could not
   produce one: `--max-calls` below 3 is refused, because the shortest
   chain-shaped program is one `openat`, one allocation and one control
   command. The gate reads the status alongside the account line.

   Every parameter struct in an emitted program is written `&AUTO`, so the
   program text wires no handles itself.
   `descriptions/nvidia_structs.txt` types `hObjectParent` and
   `hObjectNew` as `nv_handle` resources, the typing syzkaller's resource
   machinery needs to carry a parent handle from one call to the next.
   Whether it does that for an argument written `&AUTO` has not been checked
   against syzkaller's own prog text parser, because no syzkaller tree exists
   in this repository. If it does not, the first execution allocates with a
   zero parent handle and the prologue is a prologue in name only. The head
   comment of every emitted program says the same, and the gate reports the
   question as open until it is settled.

   Three questions need a machine with a syzkaller tree, and none of them is
   answered here:

   | Question | Command that settles it |
   |---|---|
   | whether `&AUTO` carries the prior allocation's handle into `hObjectParent` | `syz-prog2c` over one chain program |
   | whether an emitted program parses at all | `syz-db`, or `prog.Deserialize` over `artifacts/seeds/chain-*.syz` |
   | whether `--max-calls 40` is syzkaller's real `prog.MaxCalls` | read `prog.MaxCalls` from the tree and set `GSPWN_SEED_MAX_CALLS` |

   Record each answer with
   `python3 tools/knowledge_ctl.py note --kind learning --phase seeds "..."`,
   because the next campaign runs on another box and inherits nothing else.

   The last line is the account:

   ```
   531 control command(s) accounted for: 514 emitted, 0 dropped before emission, 17 with no chain
   ```

   All three numbers belong in the gate, and they close on the whole control
   surface at any `--max-calls`. The middle number counts commands a reduced
   budget dropped before emission, each named individually in the lines above
   it, so a run at a lower budget states what it lost and the surface it
   reports stays 531. The 17 are named with a reason, taken from
   `unresolved_owning_classes` in the chain artefact: 15 are owned by `Memory`
   or `ProfilerBase`, NVOC base classes with no `RS_ENTRY` row, so no external
   class exists to allocate and the inherited handler is reached only through a
   concrete subclass the flat `owning_class` field cannot name, and 2 are owned
   by `MmuFaultBuffer` and `NvDispApi`, whose every external class carries
   `RS_FLAGS_ALLOC_PRIVILEGED`. Record them and do not trace for them. A
   command reported under "call name(s) the chains need are declared by no
   description" is a describe gap. Report it and name the variant.

2. Check the map before tracing. It is committed and pre-populated: 78 request
   numbers covering the dispatched escapes and the UVM and UVM-tools commands,
   plus three multiplexer request numbers carrying no call name, all derived
   from the driver source by `tools/ioctl_inventory.py` with every struct size
   measured by compiling the headers. It does not depend on the describe phase,
   so seeds runs fully parallel with describe and harness.

   Every name in the map has to be declared by the description set. A name no
   description declares produces a program syz-manager refuses, and the mapped
   count reports it as a success:

   ```
   python3 tools/regression_check.py names
   ```

   The map records the driver version it was built from. A stale map turns real
   ioctls into comments and the seed exercises nothing:

   ```
   python3 tools/surface_verify.py check
   ```

   Exit 4 means fewer than two independent version sources answered, so
   nothing was compared and the check established nothing. Independence is
   counted by group: the six committed artefact files all take their version
   from one `version.mk` and count once, so a workstation with no driver
   loaded and no checkout reaches exit 4 on a healthy tree. Load the driver,
   set `driver_branch` in `config/machine.yaml`, or point `--src` at a
   checkout, then re-run. Do not trace against an unverified map. Exit 3 means
   regenerate against the installed release:

   ```
   python3 tools/ioctl_inventory.py --src artifacts/src/open-gpu-kernel-modules \
     --emit-map tools/ioctl_map.json
   python3 tools/ctrl_surface.py --src artifacts/src/open-gpu-kernel-modules
   python3 tools/object_graph.py extract --src artifacts/src/open-gpu-kernel-modules
   python3 tools/object_graph.py chains --src artifacts/src/open-gpu-kernel-modules
   python3 tools/ctrl_rank.py rank --src artifacts/src/open-gpu-kernel-modules
   python3 tools/syzlang_gen.py emit --src artifacts/src/open-gpu-kernel-modules
   python3 tools/surface_verify.py stamp --src artifacts/src/open-gpu-kernel-modules
   python3 tools/refgen.py
   ```

   This is the same block `agents/describe.md` step 1 carries, and it is one
   procedure with one order. Every command writes to its own default path. The
   tool prints the first seven itself, and `--emit-map` is added because
   `tools/ioctl_map.json` has one writer, `ioctl_inventory.py --emit-map PATH`.
   A regeneration without it leaves this phase converting its trace through
   the previous release's request numbers while `stamp` writes the new version
   over them and `check` reports agreement.

   The last four commands matter to this phase directly.
   `object_graph.py chains` writes `surface/rm-chains.json` and
   `ctrl_rank.py rank` writes `surface/rm-control-rank.json`, which
   are the two defaults step 1 reads, so a regeneration that stops before them
   builds this round's seed bank from the previous release's chains and
   ranking. `python3 tools/regression_check.py derived` reports exactly that
   staleness, and `pages` reports a reference set `refgen.py` did not rebuild.
   Run `python3 tools/regression_check.py all` after any regeneration.

3. Install a small CUDA workload (python3 with a minimal CUDA sample, or
   pytorch if already present) and trace it:

   ```
   strace -v -f -P /dev/nvidiactl -P /dev/nvidia0 -P /dev/nvidia-uvm \
     -P /dev/nvidia-uvm-tools -o artifacts/seeds/trace.txt <workload>
   ```

4. Convert the trace:

   ```
   python3 tools/trace2seed.py convert --trace artifacts/seeds/trace.txt \
     --out-dir artifacts/seeds/
   ```

   It prints three counts: mapped, unmapped, and multiplexer calls carrying no
   decodable command. Read all three.

   | Count | Meaning | Action |
   |---|---|---|
   | mapped | a request number the map names, emitted as a call | none |
   | unmapped | a request number the map does not hold | a real gap. Extend the map and re-run. Never accept the seed with the request as a comment |
   | multiplexer | a control or allocation call whose command is inside the parameter struct | none. Step 1 covers those commands. Reporting it as a map gap sends the next round after an entry the map cannot hold |

   `strace` prints requests it cannot name as `_IOC(dir, type, nr, size)`, and
   the tool decodes that form back to a number, so an unmapped entry is a real
   gap and not a parsing artefact.

   One escape reaches the dispatcher under two request numbers.
   `NV_ESC_RM_ALLOC` takes `NVOS64_PARAMETERS` at 48 bytes under `0xc030462b`
   and `NVOS21_PARAMETERS` at 32 bytes under `0xc020462b`, and the size field
   of the request number is the only thing that separates them. Where a trace
   uses both, the seed's header block names each calling form with its
   parameter struct, its size and its call count. The description set declares
   204 variants over the 48-byte form and 1 over the 32-byte form, so a trace
   issuing the narrower form for any other class reaches an allocation route no
   description declares. Record it as a coverage gap and name the class, the
   same way an undeclared call name is recorded.

   With the commands absent, the trace still supplies the fd lifecycle, the
   escapes whose command is the request number, the order a real workload
   issues them in, and evidence about which object chains a real workload
   actually builds. The worklist asks for that last one.

5. Validate: every seed parses under syz-manager. Add them to the corpus and
   watch for parse errors in the manager log during a 5-minute smoke run.

## Rounds after the first

Round 1 has a worklist of its own: `surface/worklist-round1.md`,
generated offline by `python3 tools/cve_patch_map.py worklist` and committed.
Its seeds section names the allocation chain each targeted control command
needs, with the class and its allocation depth: GT200_DEBUGGER at depth 3,
NV04_DISPLAY_COMMON at depth 3, NV01_DEVICE_0 at depth 2, NV01_ROOT_CLIENT at
depth 1. It carries 4 seeds items. The chain-shaped programs from step 1
already build those chains. Trace a workload that builds them to confirm a
real workload can, and to capture the fd lifecycle around them.

Round-1 items are tagged `[history CVE-YYYY-NNNNN]`, or
`[history CVE-YYYY-NNNNN +N]` when several CVEs share the patch set. NVB0CC
(ProfilerBase, the HWPM profiler) and NV83DE (KernelSMDebuggerSession) account
for most of the commands behind them. ProfilerBase is one of the four classes
`rm-chains.json` reports no chain for, so its 9 commands reach no chain-shaped
program and a trace is the only route to them. A history item ranks a place
where the vendor found a bug. It is not evidence that a bug remains there.
`pipeline_ctl.py worklist` does not print this path, because refine has
recorded nothing in round 1.

From round 2 on, get the input worklist from state. Guessing the previous run
id is not needed:

```
python3 tools/pipeline_ctl.py worklist
```

Its seeds section lists surfaces classified `unreachable-by-construction`: code
that needs a real object chain random generation will not build. Target the
workloads at those.

Items carry their source, and the three tags are the loop's steering signals. A
`[surface]` item is a command the driver's own enumeration names and no program
in the corpus has named, taken verbatim from `surface_cov.py gaps`. A
`[history CVE-YYYY-NNNNN]` item names an object chain a patched command needs.
A `[finding crash-NNNN]` item comes from the `preconditions` of a research
record: the object state that had to exist before a real bug in this campaign
could be reached. Those come first, and they are the most specific brief the
phase gets. "Channel bound with async work in flight" says which workload to
trace and at what moment. Read the full record for the rest of the context:

```
python3 tools/pipeline_ctl.py finding-list
```

If a precondition cannot be reached from any CUDA workload available, say so in
the gate. A seed that does not establish the precondition does not exercise the
path, and reporting it as covered loses the target for the next round.

The persistent seed bank at `artifacts/seeds/` also accumulates programs
promoted from previous rounds' corpora (`corpus_ctl.py promote`). Check what is
already there with `python3 tools/corpus_ctl.py stats` before generating more.
The bank is deduplicated by content, so re-adding equivalents is wasted tracing
time. The `chains` subcommand writes deterministic file names and overwrites
its own output, so re-running it does not grow the bank.

## Outputs

`artifacts/seeds/chain-*.syz` from step 1, `artifacts/seeds/seed-*.syz` from
step 4, the trace kept at `artifacts/seeds/trace.txt`, and
`tools/ioctl_map.json` if a regeneration moved it (commit it: it is data, not
runtime state).

## State

Record progress with the state tool, never by editing pipeline.json:

```
python3 tools/pipeline_ctl.py set-phase seeds in_progress|done|blocked \
  --notes "<seed count>"
```

## Gate evidence

- The account line from step 1 with all three of its numbers: commands
  emitted, commands dropped before emission, commands with no chain, and the
  reason for each of the last two. The exit status of the command beside it.
- Any call name the chains needed and no description declares.
- A statement that the chain prologue's handle wiring is unsettled, or the
  `syz-prog2c` result that settles it.
- Seed count for the whole bank, chain-shaped and trace-derived separately.
- The three counts from step 4: mapped, unmapped, multiplexer. A high unmapped
  ratio means the map is incomplete and the trace-derived seeds cover less than
  they appear to. The ratio detects a request number the map lacks and never a
  request number whose value is wrong, so it is secondary evidence.
  `regression_check.py names` from step 2 is the primary check, and its output
  belongs in the gate.
- Smoke-run log excerpt showing no seed parse errors.
- Per `[finding ...]`, `[history ...]` and `[surface]` item, whether a seed now
  establishes its precondition, and the ones not reached.

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

A **learning** is about the target. For this phase, typically workload facts:
which CUDA calls reach which ioctls, which object chains a trace can and cannot
produce. A **mistake** is about us: something that cost time, produced a wrong
number, or would repeat. Both are read by whoever runs this phase next, on
another box months from now, so write for someone without your context.
Recording nothing across a whole phase is itself worth questioning.

`knowledge/` is committed to a **public repository**. It carries ABI and
process facts and never findings: `note` refuses text naming a crash id or a
path under `artifacts/crashes|pocs|rca`, and the specifics belong in the
crash registry. Record the general form. It is also the more useful one,
because the next agent is looking at a different crash.
