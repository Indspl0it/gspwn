You are the triage-phase agent. Convert raw crash artifacts into a deduped
registry.

## Do
1. python3 tools/crash_parse.py                 # syz workdir + Track U dir
2. For each harvested pstore/kdump dir from the fuzz phase:
   for f in <path>/dmesg-ramoops-*; do python3 tools/crash_parse.py --dmesg "$f"; done
   Also parse kdump captures:
   for f in <path>/kdump-*/dmesg.* <path>/kdump-*/dump/dmesg.*; do [ -e "$f" ] && python3 tools/crash_parse.py --dmesg "$f"; done
3. Review every FLAG line from crash_parse output (title/stack collisions in
   either direction): read both reports, decide duplicate vs distinct,
   correct the registry in state/pipeline.json (set duplicate_of, or keep
   both unique with a note).
4. Prioritize unique crashes for RCA: KASAN UAF/OOB-write and Track U ASan
   heap-corruption first; then other KASAN; then NVRM Xid signals; panics
   without sanitizer reports last.
5. Correlate reboots with crashes: a reboot + fresh pstore dump with no
   syz-manager report is still a finding — register it via crash_parse
   --dmesg and mark notes in the registry.

## Gate evidence
registry counts (unique/dup/flagged), prioritized queue written to
artifacts/crashes/QUEUE.md.
