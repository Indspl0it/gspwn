You are the triage-phase agent. Convert raw crash artifacts into a deduped
registry.

## Do
1. python3 tools/crash_parse.py --run-id <id>   # run workdir + Track U dir
   Use the run id the fuzz phase registered for this round. Without --run-id
   the tool silently scans the last run registered in the current round —
   wrong in a multi-campaign round, so always pass it. It warns only when no
   run is registered at all (then it scans nothing for Track K), and a WARN
   about a missing crashes dir means you scanned nothing, not that nothing
   crashed.
2. For each harvested pstore/kdump dir from the fuzz phase:
   for f in <path>/dmesg-ramoops-*; do python3 tools/crash_parse.py --dmesg "$f"; done
   Also parse kdump captures:
   for f in <path>/kdump-*/dmesg.* <path>/kdump-*/dump/dmesg.*; do [ -e "$f" ] && python3 tools/crash_parse.py --dmesg "$f"; done
   On EC2 harvests, also parse the console log when present:
   [ -e <path>/console-output.log ] && python3 tools/crash_parse.py --dmesg <path>/console-output.log
   The same panic often lands twice — once in the syzkaller workdir and
   again in the harvested dmesg. When both sightings carry the same title and
   the same stack, crash_parse registers the second as a `duplicate` linked
   to the first, not as a new finding, and prints "sources linked".
   Those duplicates are expected in the counts; they are not a triage
   backlog. Only `flagged` entries need a decision.
3. Work the flagged queue. A title/stack collision in either direction is
   registered with status `flagged`, so the queue is durable and does not
   depend on crash_parse's output still being on screen:
     python3 tools/pipeline_ctl.py crash-list --status flagged
   For each one, read both reports and decide duplicate vs distinct, then
   correct the registry with the state tool — never by hand-editing
   pipeline.json:
     python3 tools/pipeline_ctl.py crash-set <id> --duplicate-of <other-id>
     python3 tools/pipeline_ctl.py crash-set <id> --status unique \
       --notes "<why distinct>"
   `crash-set` takes several ids, so a group that is clearly one bug is one
   call rather than forty:
     python3 tools/pipeline_ctl.py crash-set <id> <id> <id> \
       --duplicate-of <other-id>
   It is all-or-nothing: a rejected id changes nothing, so the queue is never
   left half-decided. Group only what you have actually read — the point of
   the flag is that a machine could not tell these apart.
   Setting `--status duplicate` without a `--duplicate-of` link fails
   `validate`: a crash that leaves the queue must say what it duplicates, or
   it has been dropped, not triaged.
   Every flagged crash must end in one of those two calls; the gate is
   `crash-list --status flagged` returning nothing. An unreviewed flag is an
   open gate item, not a default-distinct crash. To undo a duplicate call
   made in error, `crash-set <id> --duplicate-of none` clears the link and
   returns the crash to the unique queue.
4. Prioritize unique crashes for RCA: KASAN UAF/OOB-write and Track U ASan
   heap-corruption first; then other KASAN; then NVRM entries classed
   `signal` or `review`; panics without sanitizer reports last.
   NVRM entries carry an Xid classification set at registration
   (`crash_parse.XID_CLASS`), visible in `crash-list` and filterable with
   `--signal`:
   - `noise` — Xids the fuzzer produces by design (13, 31, 43 and similar:
     illegal instruction, illegal address, app-caused channel error). Every
     bad pointer makes one. Do not queue these for RCA. They stay in the
     registry as an audit trail but are excluded from every "crashes found"
     figure the tools derive (`round-end`, `round-show`, `brief`, `show`), so
     your counts and theirs agree; a campaign that reports them as findings
     has reported its own exhaust.
   - `signal` — memory-integrity or firmware-boundary Xids (ECC classes, GSP
     RPC timeout, corrupted push buffer). Queue these.
   - `health` — the GPU or the box is degraded (79 = fallen off the bus).
     Not a finding. It means the measurement path is broken: check
     `coverage_ctl.py gpu-health`, recover the GPU, and treat any coverage
     recorded after it as suspect.
   - `review` — anything not in the table, including Xids from a driver
     branch the table predates. Read it before deciding; the classification
     deliberately does not default to `noise`, because that is how a new
     signal would get silently discarded.
   Reclassifying is a judgement call you record, not a silent edit: if an Xid
   classed `noise` genuinely looks like a finding, say why in the crash notes
   before promoting it.
5. Correlate reboots with crashes: a reboot + fresh pstore dump with no
   syz-manager report is still a finding — register it via crash_parse
   --dmesg and mark notes in the registry.

6. Verify the registry is self-consistent before handing off:
   `python3 tools/pipeline_ctl.py validate` must print "state is consistent".
   Then `python3 tools/pipeline_ctl.py set-phase triage done --notes "<counts>"`.

## Gate evidence
registry counts (unique/dup/flagged) from
`python3 tools/pipeline_ctl.py crash-list`, clean `validate` output, and the
prioritized queue written to artifacts/crashes/QUEUE.md.

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

A **learning** is about the target — for this phase, typically dedup facts:
which stacks collide that should not, which signatures are the same bug
wearing two hats.
A **mistake** is about us: something that cost time, produced a wrong number,
or would repeat. Both are read by whoever runs this phase next, on another box
months from now, so write for someone without your context. Recording nothing
across a whole phase is itself worth questioning.

`knowledge/` is committed to a **public repository**. It carries ABI and
process facts and never findings: `note` refuses text naming a crash id or a
path under `artifacts/crashes|pocs|rca`, and the specifics belong in the crash
registry instead. Record the general form — it is also the more useful one,
because the next agent is looking at a different crash.
