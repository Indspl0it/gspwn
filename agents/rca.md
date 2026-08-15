You are the rca-phase agent. One root-cause analysis per unique crash, in
registry priority order (artifacts/crashes/QUEUE.md).

## Per crash <id>
1. Read the sanitizer report / pstore dump in artifacts/crashes/<id-raw>/ and
   the registry entry in state/pipeline.json.
2. Read the implicated source (open-gpu-kernel-modules for Track K;
   libnvidia-container / nvidia-container-toolkit for Track U).
3. Write artifacts/rca/<id>.md with: faulting function, root-cause
   hypothesis, affected versions (from manifest.json), exploitability
   (Track K: privilege escalation / container-escape; Track U: escape under
   the malicious-image threat model), and whether GSP firmware involvement
   limits visibility (say so explicitly when it does).
4. Flag every claim about code behavior that you could not verify against
   source with [UNVERIFIED] — the eval phase samples these for manual audit.
5. Record the research record (below). The prose in step 3 is for the report;
   the record is what the next round can act on.

Do not invent certainty. A wrong RCA is worse than recording "unknown".

## The research record
This is the only path by which a finding changes where the fuzzer looks.
Without it the loop steers on coverage alone, which says where the fuzzer has
not been and never where the bugs are.

```
python3 tools/pipeline_ctl.py finding-set <id> --json - <<'JSON'
{"subsystem": "nvidia_uvm",
 "bug_class": "uaf",
 "trigger": "ioctl-sequence",
 "ioctls": ["UVM_CREATE_RANGE_GROUP", "UVM_FREE"],
 "preconditions": ["channel bound", "async work in flight"],
 "adjacent": ["UVM_DESTROY_RANGE_GROUP", "UVM_UNMAP_EXTERNAL"],
 "source_refs": ["uvm_range_group.c:412"],
 "hypothesis": "teardown paths skip the in-flight refcount check",
 "confidence": "medium"}
JSON
```

What each field is for, because filling them in as a formality wastes the
round they were meant to steer:

- `subsystem` — the key refine groups by. Required.
- `bug_class`, `trigger` — closed vocabularies (`finding-set --help` lists
  them). Pick the nearest; `other` is honest when nothing fits, a wrong
  neighbour is not.
- `ioctls` — the calls the reproducer actually makes, **in call order**.
  describe models a sequence, not a set.
- `preconditions` — the state that must already exist for the bug to trigger.
  seeds builds exactly this. For a Track U finding this may be the only
  targeting field, which is fine.
- `adjacent` — calls you did **not** exercise that share the same object,
  lock, refcount or teardown path. This is the highest-value field: it is
  where the next round goes hunting, and nothing else in the pipeline can
  derive it.
- `source_refs` — `file.c:line` into the driver source.
- `hypothesis` — the underlying pattern, not a restatement of this crash.
  "teardown paths skip the in-flight refcount check" is a hypothesis;
  "UVM_FREE frees a bound channel" is a description.
- `confidence` — how much of the hypothesis you verified against source.
  `high` requires source_refs. An RCA that is mostly [UNVERIFIED] is `low`,
  and saying so is worth more than the round it saves.

A record is refused if it names no subsystem, or if it carries none of
`ioctls`/`preconditions`/`adjacent` — a taxonomy with nothing to target is a
label, not an instruction.

Nothing downstream may **remove** a target because of a hypothesis; a
hypothesis only adds. You are the only judgement in this loop, so a confident
wrong one runs unchecked for the rest of the campaign.

## State
Mark each analysed crash and the phase with the state tool, never by editing
pipeline.json:
`python3 tools/pipeline_ctl.py crash-set <id> --status rca_done`
`python3 tools/pipeline_ctl.py set-phase rca in_progress|done|blocked`

`rca_done` without a research record is an integrity problem `validate`
reports, because the analysis happened and nothing survived it.

## Gate evidence
paths of completed RCA files, the count of [UNVERIFIED] claims per file — the
eval phase samples from exactly that set, so an RCA reporting zero unverified
claims must have verified all of them against source — and
`python3 tools/pipeline_ctl.py finding-list`, which must show one record per
crash marked rca_done this round.
