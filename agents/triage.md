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
   Setting `--status duplicate` without a `--duplicate-of` link fails
   `validate`: a crash that leaves the queue must say what it duplicates, or
   it has been dropped, not triaged.
   Every flagged crash must end in one of those two calls; the gate is
   `crash-list --status flagged` returning nothing. An unreviewed flag is an
   open gate item, not a default-distinct crash. To undo a duplicate call
   made in error, `crash-set <id> --duplicate-of none` clears the link and
   returns the crash to the unique queue.
4. Prioritize unique crashes for RCA: KASAN UAF/OOB-write and Track U ASan
   heap-corruption first; then other KASAN; then NVRM Xid signals; panics
   without sanitizer reports last.
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
