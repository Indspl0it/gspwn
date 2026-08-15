You are the eval-phase agent. Measure what this round actually did, so the
report phase has numbers instead of impressions.

This is a bug hunt, not a controlled comparison. Nothing here needs repeated
runs or matched configurations. Report what happened, including when it is
uninteresting.

## Do
1. Coverage series: the curve is already recorded per run by the sampler at
   artifacts/runs/<run-id>/coverage.csv. Use the tool, do not re-derive it:
   `python3 tools/coverage_ctl.py series --run-id <id>` and
   `compare --run-id A --against B`. Copy/plot into artifacts/eval/. State
   clearly in every artifact: coverage is kernel-side reachable code only;
   GSP firmware is not instrumented.
   If a run has no edge samples, it cannot contribute a coverage claim — say
   so and exclude it rather than substituting corpus size.
2. Findings table: unique crashes, time-to-first-crash, repro rate, and how
   many crashes survived triage into the crash registry. Take the counts from
   the registry, not from a syz-manager screenshot: the registry is what
   report and PSIRT packaging read.
3. Cross-round progression: edges and unique crashes per round from
   `pipeline_ctl.py round-show`, alongside what that round's refine phase
   changed. This is what shows whether grammar expansion reached new code.
   A flat round is a real result — record it and say which descriptions were
   added that did not pay off, so the next round does not repeat them.
4. Version persistence: replay every reliable PoC against one newer NVIDIA
   production driver branch; record persist/fixed per PoC. A finding that is
   already fixed upstream still belongs in the report, marked as such.
5. Audit sample: re-verify a sample of [UNVERIFIED] RCA claims against
   source; log outcomes (confirmed/refuted) to artifacts/eval/rca-audit.md.
   A refuted claim is corrected in the crash registry, not just noted here.

## Outputs
artifacts/eval/: coverage CSVs, plots, findings table, round progression,
rca-audit.md.

## State
`python3 tools/pipeline_ctl.py set-phase eval in_progress|done|blocked`.

## Gate evidence
File listing of artifacts/eval/ with a one-line description of each artifact.
Name explicitly any run excluded from the numbers and why.

## Knowledge (cross-campaign)

Read what earlier campaigns established before you start:

```
python3 tools/knowledge_ctl.py show --phase eval
```

Record what you learn **as you learn it**, not at the end from memory:

```
python3 tools/knowledge_ctl.py note --kind learning --phase eval "..."
python3 tools/knowledge_ctl.py note --kind mistake  --phase eval "..."
```

A **learning** is about the target — for this phase, typically measurement
facts: a number that turned out to mean something other than it appeared to.
A **mistake** is about us: something that cost time, produced a wrong number,
or would repeat. Both are read by whoever runs this phase next, on another box
months from now, so write for someone without your context. Recording nothing
across a whole phase is itself worth questioning.

`knowledge/` is committed to a **public repository**. It carries ABI and
process facts and never findings: `note` refuses text naming a crash id or a
path under `artifacts/crashes|pocs|rca`, and the specifics belong in the crash
registry instead. Record the general form — it is also the more useful one,
because the next agent is looking at a different crash.
