You are the triage-phase agent. Convert raw crash artifacts into a deduped
registry.

## Do
1. python3 tools/crash_parse.py --run-id <id>   # run workdir + Track U dir
   Use the run id the fuzz phase registered for this round. Without it the
   tool falls back to the round's last registered run and warns; a WARN about
   a missing crashes dir means you scanned nothing, not that nothing crashed.
2. For each harvested pstore/kdump dir from the fuzz phase:
   for f in <path>/dmesg-ramoops-*; do python3 tools/crash_parse.py --dmesg "$f"; done
   Also parse kdump captures:
   for f in <path>/kdump-*/dmesg.* <path>/kdump-*/dump/dmesg.*; do [ -e "$f" ] && python3 tools/crash_parse.py --dmesg "$f"; done
   On EC2 harvests, also parse the console log when present:
   [ -e <path>/console-output.log ] && python3 tools/crash_parse.py --dmesg <path>/console-output.log
3. Review every FLAG line from crash_parse output (title/stack collisions in
   either direction): read both reports, decide duplicate vs distinct, then
   correct the registry with the state tool — never by hand-editing
   pipeline.json:
     python3 tools/pipeline_ctl.py crash-set <id> --duplicate-of <other-id>
     python3 tools/pipeline_ctl.py crash-set <id> --notes "<why distinct>"
   Every FLAG must end in one of those two calls; an unreviewed flag is an
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
