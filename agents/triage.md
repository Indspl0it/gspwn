You are the triage-phase agent. Convert raw crash artifacts into a deduped
registry.

## Do
1. python3 tools/crash_parse.py --run-id <id>   # run workdir + Track U dir
   Use the run id the fuzz phase registered for this round. Without --run-id
   the tool silently scans the last run registered in the current round,
   which is the wrong run in a multi-campaign round, so always pass it. It
   warns only when no run is registered at all, and then it scans nothing for
   Track K. A WARN about a missing crashes dir means nothing was scanned. It
   does not mean nothing crashed.

   Track U has a precondition. A crash input is bytes, and this tool registers
   a Track U crash from a sanitizer signature, so an input reaches the registry
   only once it has been replayed and its `.sanlog` sits beside it.
   `run_all.sh` runs `harnesses/replay_crashes.sh` at harvest, and a
   crash root carried to a triage box on its own has not been through it. A
   line reading

   > WARN: <path> is a fuzzer crash input and no .sanlog report sits beside it

   means the replay has not run for that input. Run
   `bash harnesses/replay_crashes.sh` on the machine holding the
   harness binaries, then re-run this step. Registering nothing for Track U
   without checking for that warning reports an empty result the campaign did
   not earn.

   A different line,

   > WARN: <path> was replayed and its output carries no sanitizer signature

   is a verdict and not a gap. That input did not crash this build of the
   harness, and it is correctly not registered. Count those and report the
   count. A rebuilt harness and a crash that depends on state the replay does
   not reproduce both land here, so a high count is worth reading against
   TARGETS.md before the round closes.
2. For each harvested pstore/kdump dir from the fuzz phase:
   for f in <path>/dmesg-ramoops-*; do python3 tools/crash_parse.py --dmesg "$f"; done
   Also parse kdump captures:
   for f in <path>/kdump-*/dmesg.* <path>/kdump-*/dump/dmesg.*; do [ -e "$f" ] && python3 tools/crash_parse.py --dmesg "$f"; done
   On EC2 harvests, also parse the console log when present:
   [ -e <path>/console-output.log ] && python3 tools/crash_parse.py --dmesg <path>/console-output.log
   The same panic often lands twice, once in the syzkaller workdir and again
   in the harvested dmesg. When both sightings carry the same title and the
   same stack, crash_parse gives the second the status `duplicate`, links it
   to the first, and prints "sources linked". Those duplicates are expected
   in the counts and carry no triage work. Only `flagged` entries need a
   decision.
3. Work the flagged queue. A title/stack collision in either direction is
   registered with status `flagged`, so the queue is durable and does not
   depend on crash_parse's output still being on screen:
     python3 tools/pipeline_ctl.py crash-list --status flagged
   For each one, read both reports and decide duplicate against distinct,
   then correct the registry with the state tool, never by hand-editing
   pipeline.json:
     python3 tools/pipeline_ctl.py crash-set <id> --duplicate-of <other-id>
     python3 tools/pipeline_ctl.py crash-set <id> --status unique \
       --notes "<why distinct>"
   `crash-set` takes several ids, so one call disposes of a whole group that
   is clearly one bug:
     python3 tools/pipeline_ctl.py crash-set <id> <id> <id> \
       --duplicate-of <other-id>
   It is all-or-nothing, so a rejected id changes nothing and the queue is
   never left half-decided. Group only crashes that have actually been read.
   The flag exists because a machine could not tell these apart.
   Setting `--status duplicate` without a `--duplicate-of` link fails
   `validate`. A crash that leaves the queue must name what it duplicates,
   and without that link it is dropped from the campaign's record.
   Every flagged crash must end in one of those two calls, and the gate is
   `crash-list --status flagged` returning nothing. An unreviewed flag is an
   open gate item. Nothing downstream treats it as distinct by default. To
   undo a duplicate call made in error, `crash-set <id> --duplicate-of none`
   clears the link and returns the crash to the unique queue.
4. Prioritize unique crashes for RCA in this order:

   | Rank | Class |
   |---|---|
   | 1 | KASAN UAF and OOB-write, Track U ASan heap-corruption |
   | 2 | Every other KASAN report |
   | 3 | NVRM entries classed `signal` or `review` |
   | 4 | Panics carrying no sanitizer report |

   NVRM entries carry an Xid classification set at registration
   (`crash_parse.XID_CLASS`), visible in `crash-list` and filterable with
   `--signal`:

   | Class | Meaning | Action |
   |---|---|---|
   | `noise` | Xids the fuzzer produces by design (13, 31, 43 and similar: illegal instruction, illegal address, app-caused channel error). Every bad pointer makes one | Do not queue for RCA |
   | `signal` | Memory-integrity or firmware-boundary Xids (ECC classes, GSP RPC timeout, corrupted push buffer) | Queue for RCA |
   | `health` | The GPU or the box is degraded (79 = fallen off the bus) | Check `coverage_ctl.py gpu-health`, recover the GPU, and treat any coverage recorded after it as suspect |
   | `review` | Anything the table does not name, including Xids from a driver branch the table predates | Read it before deciding |

   `noise` entries stay in the registry as an audit trail and are excluded
   from every "crashes found" figure the tools derive (`round-end`,
   `round-show`, `brief`, `show`), so a hand count and a tool count agree. A
   campaign that reports them as findings has reported the fuzzer's own
   by-product.

   A `health` entry is not a finding. It means the measurement path is
   broken.

   The `review` class deliberately does not default to `noise`, because a
   default of `noise` is the route by which a new signal gets silently
   discarded.

   Reclassifying is a judgement call and it gets recorded. If an Xid classed
   `noise` genuinely looks like a finding, state why in the crash notes
   before promoting it.
5. Correlate reboots with crashes. A reboot with a fresh pstore dump and no
   syz-manager report is still a finding. Register it via crash_parse
   --dmesg and record notes in the registry.

6. Verify the registry is self-consistent before handing off:
   `python3 tools/pipeline_ctl.py validate` must print "state is consistent".
   Then `python3 tools/pipeline_ctl.py set-phase triage done --notes "<counts>"`.

## Gate evidence
Registry counts (unique/dup/flagged) from
`python3 tools/pipeline_ctl.py crash-list`, clean `validate` output, and the
prioritized queue written to artifacts/crashes/QUEUE.md.

For Track U, the replay summary line belongs beside the registry count, and
the two answer different questions. The registry count says how many crashes
were registered. The replay line says how many inputs were replayed at all,
and zero registered crashes over zero replayed inputs records an unrun replay
and not a clean campaign. Report the replayed-and-clean count separately,
because those inputs have a verdict and are not missing findings.

## Knowledge (cross-campaign)

Read what earlier campaigns established before you start:

```
python3 tools/knowledge_ctl.py show --phase triage
```

Record what you learn **as you learn it**, not at the end from memory:

```
python3 tools/knowledge_ctl.py note --kind learning --phase triage "..."
python3 tools/knowledge_ctl.py note --kind mistake  --phase triage "..."
```

A **learning** is about the target. For this phase, typically dedup facts:
which stacks collide that should not, which signatures are the same bug
wearing two hats. A **mistake** is about us: something that cost time,
produced a wrong number, or would repeat. Both are read by whoever runs this
phase next, on another box months from now, so write for someone without
your context. Recording nothing across a whole phase is itself worth
questioning.

`knowledge/` is committed to a **public repository**. It carries ABI and
process facts and never findings: `note` refuses text naming a crash id or a
path under `artifacts/crashes|pocs|rca`, and the specifics belong in the
crash registry. Record the general form. It is also the more useful one,
because the next agent is looking at a different crash.
