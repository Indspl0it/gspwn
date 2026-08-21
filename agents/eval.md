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
2. Surface coverage: `python3 tools/surface_cov.py report --json` writes the
   three-stage decomposition of the driver's enumerated command surface, and
   `python3 tools/surface_cov.py targets --json --out artifacts/eval/<run-id>/surface-targets.json`
   records the denominator it was measured against. Report all three stages,
   because the headline alone hides which one lost the surface:

   | Stage | Population | Diagnosis of a loss |
   |---|---|---|
   | targetable | commands a default tenant may call, 764 in total | the scope of the claim |
   | modelled | targets a syzlang variant declares | the describe phase is incomplete |
   | exercised | targets a program in the corpus names | the fuzzer builds programs too invalid to emit the call, usually a wrong resource chain |

   The denominator is 32 escape, 39 uvm, 7 uvm_tools, 531 control and 155
   alloc targets. Four groups sit outside it and stay outside every
   percentage: 236 control commands routed to GSP, whose handler is compiled
   out and where KCOV cannot follow; 104 uvm_test commands that need
   `uvm_enable_builtin_tests=1`; 3 escapes declared in nv_escape.h with no
   dispatch case; and the 2 multiplexer escapes NV_ESC_RM_CONTROL and
   NV_ESC_RM_ALLOC, whose leaves already count in the control and alloc
   families. State the exclusions wherever the percentage appears.

   This number is a claim about the command surface and never about lines of
   driver code. The KCOV edge count measures an edge space of unknown size, so
   it can carry no percentage at all. The surface ratio has a measured
   denominator and carries one. Report the plateau verdict beside it: a
   plateau at low surface coverage means the descriptions or the resource
   chains are wrong, and a plateau at high surface coverage is the real
   stopping condition.
3. Findings table: unique crashes, time-to-first-crash, repro rate, and how
   many crashes survived triage into the crash registry. Take the counts from
   the registry, not from a syz-manager screenshot: the registry is what
   report and PSIRT packaging read.
4. Cross-round progression: edges and unique crashes per round from
   `pipeline_ctl.py round-show`, alongside what that round's refine phase
   changed. This is what shows whether grammar expansion reached new code.
   A flat round is a real result — record it and say which descriptions were
   added that did not pay off, so the next round does not repeat them.
5. Version persistence: replay every reliable PoC against one newer NVIDIA
   production driver branch; record persist/fixed per PoC. A finding that is
   already fixed upstream still belongs in the report, marked as such.

   This is the most expensive step in the phase and the only one with no
   tooling behind it: it means rebuilding the driver and rebooting, which
   changes the machine every other measurement was taken on. Do it last, after
   the coverage and findings artifacts are written.

   It is also the step most easily skipped without anyone noticing, so its
   outcome is not optional. Write `artifacts/eval/version-persistence.md`
   containing either the per-PoC persist/fixed table, or the single line
   `skipped: <why>` — for example that a newer branch would not build against
   this kernel, or that no crash reached `reliable`. Both are acceptable
   results. A missing file is not, and the gate below asks for it.
6. Audit sample: re-verify a sample of [UNVERIFIED] RCA claims against
   source; log outcomes (confirmed/refuted) to artifacts/eval/rca-audit.md.
   A refuted claim is corrected in the crash registry, not just noted here.
7. Impact audit: `python3 tools/pipeline_ctl.py impact-list`. Two numbers
   belong in the findings table — how many crashes have an impact record, and
   how many of those can carry a severity. A round that analysed every crash
   and produced no record able to carry a severity found crashes, not
   vulnerabilities, and the write-up has to say so plainly.
   Then re-check the strongest claims specifically. Every record with
   consequence `privilege-escalation` or `container-escape` gets its evidence
   read against source, because those are what a vendor challenges first and
   they are the only ones where being wrong is expensive. Refuted ones are
   corrected with `impact-set`, not annotated here. A high count of
   `undetermined` is not a failure to report — an honest one is the expected
   outcome for faults that vanish into GSP.

## Outputs
artifacts/eval/: coverage CSVs, plots, findings table, surface coverage report
and target denominator, round progression, rca-audit.md,
version-persistence.md.

## State
`python3 tools/pipeline_ctl.py set-phase eval in_progress|done|blocked`.

## Gate evidence
File listing of artifacts/eval/ with a one-line description of each artifact,
including version-persistence.md (a recorded `skipped: <why>` counts; a
missing file does not) and the surface coverage report with its three stages.
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
