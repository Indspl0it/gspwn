You are the eval-phase agent. Measure what this round actually did, and give
the report phase numbers.

The campaign is a bug hunt. Nothing here needs repeated runs or matched
configurations. Report what happened, including when it is uninteresting.

## Do
1. Coverage series: the curve is already recorded per run by the sampler at
   artifacts/runs/<run-id>/coverage.csv. Use the tool, do not re-derive it:
   `python3 tools/coverage_ctl.py series --run-id <id>` and
   `compare --run-id A --against B`. Copy/plot into artifacts/eval/. State
   clearly in every artifact that coverage is kernel-side reachable code
   only, and that GSP firmware is not instrumented.
   If a run has no edge samples, it cannot contribute a coverage claim. Say
   so and exclude it, and do not substitute corpus size.
2. Surface coverage: `python3 tools/surface_cov.py report --json --run-id
   <run-id> > artifacts/eval/<run-id>/surface-report.json` writes the
   three-stage decomposition of the driver's enumerated command surface. The
   `report` subcommand has no `--out`, so the redirect writes the file.
   `python3 tools/surface_cov.py targets --json --out artifacts/eval/<run-id>/surface-targets.json`
   records the denominator it was measured against. Report all three stages,
   because the headline alone hides which one lost the surface:

   | Stage | Population | Diagnosis of a loss |
   |---|---|---|
   | targetable | commands a default tenant may call, 764 in total | the scope of the claim |
   | modelled | targets a syzlang variant declares | the describe phase is incomplete |
   | exercised | targets a program in the corpus names | the fuzzer builds programs too invalid to emit the call, usually a wrong resource chain |

   `--run-id` is required here. This phase promotes nothing, so without it the
   report measures `artifacts/seeds`, which is the state of the previous round.
   The JSON carries `corpus` and `corpus_mtime`. Quote both wherever the
   exercised number appears, so a reader can tell which corpus produced it.

   The denominator is 32 escape, 39 uvm, 7 uvm_tools, 531 control and 155
   alloc targets. Four groups sit outside it and stay outside every
   percentage:

   | Group | Count | Reason for exclusion |
   |---|---|---|
   | control_gsp | 236 | Control commands routed to GSP, whose handler is compiled out and where KCOV cannot follow |
   | uvm_test | 104 | Commands that need `uvm_enable_builtin_tests=1` |
   | escape_dead | 3 | Escapes declared in nv_escape.h with no dispatch case |
   | escape_mux | 2 | NV_ESC_RM_CONTROL and NV_ESC_RM_ALLOC, whose leaves already count in the control and alloc families |

   State the exclusions wherever the percentage appears.

   This number is a claim about the command surface and never about lines of
   driver code. The KCOV edge count measures an edge space of unknown size, so
   it can carry no percentage at all. The surface ratio has a measured
   denominator and carries one. Report the plateau verdict beside it. A
   plateau at low surface coverage means the descriptions or the resource
   chains are wrong, and a plateau at high surface coverage is the real
   stopping condition.
2b. Completion: `python3 tools/coverage_ctl.py completion --run-id <id>` prints
   whether every one of the 764 targets is either exercised or accounted for,
   and lists the ones that are neither. Exit 0 is complete, 3 is incomplete and
   1 means the reading failed. This is the campaign's primary stopping rule, so
   record the three counts in `artifacts/eval/<run-id>/` alongside the coverage
   series.

   `--run-id` is repeatable and the sets are unioned, so a multi-campaign round
   is read in one call. `--corpus <dir>` measures a directory of programs
   instead, and the two are refused together. Pass one or the other. Omitting
   both reads the seed bank, which is the previous round's state.

   The denominator entitles this phase to one claim it could not make before:

   > On driver <version>, the campaign exercised N of the 764 commands a
   > default `compute,utility` container tenant can reach. The remaining
   > 764 minus N are accounted for, each with a recorded reason. The
   > accounted-for set excludes the 345 commands outside the denominator by
   > construction.

   That template covers the remainder only where the ledger holds no
   `deliberately-deferred` rows. Those rows record a reachable target the
   campaign chose to put aside, they close nothing, and `completion` counts
   them separately. Where any exist, the claim covers exercised plus excluded,
   and the deferred count is stated beside it as work this campaign chose not
   to do. Folding them into the accounted-for number claims a surface the
   campaign did not account for.

   Six pieces of evidence have to be cited for the claim to stand:

   | # | Evidence | Fact established |
   |---|---|---|
   | 1 | `surface_verify.py check` exit 0 | the inventories describe the driver that ran |
   | 2 | `surface_cov.py targets --json --out .../surface-targets.json` | the denominator, stamped with its driver version |
   | 3 | `surface_cov.py report --run-id <run-id>`, all three stages, naming the corpus path and its modification time | the measurement, against the right corpus |
   | 4 | `regression_check.py pins` exit 0 | the denominator bounds the corpus, because no emitted selector including `NV_ESC_IOCTL_XFER_CMD`'s inner `cmd` is free |
   | 5 | the exclusion line verbatim: 236 control_gsp, 104 uvm_test, 3 escape_dead, 2 escape_mux | the population the percentage is taken over |
   | 6 | the 16 in-handler capability checks, stated as a floor | `targetable` is an upper bound on what a tenant can call |

   Missing any of the six, report the three stages and state no completion
   claim.
3. Findings table: unique crashes, time-to-first-crash, repro rate, and how
   many crashes survived triage into the crash registry. Take the counts from
   the registry and not from a syz-manager screenshot. Report and PSIRT
   packaging read the registry.
4. Cross-round progression: edges and unique crashes per round from
   `pipeline_ctl.py round-show`, alongside what that round's refine phase
   changed. That progression shows whether grammar expansion reached new code.
   A flat round is a real result. Record it and say which descriptions were
   added that did not pay off, so the next round does not repeat them.
5. Version persistence: replay every reliable PoC against one newer NVIDIA
   production driver branch, and record persist/fixed per PoC. A finding that
   is already fixed upstream still belongs in the report, marked as such.

   This is the most expensive step in the phase and the only one with no
   tooling behind it. It means rebuilding the driver and rebooting, which
   changes the machine every other measurement was taken on. Do it last, after
   the coverage and findings artifacts are written.

   It is also the step most easily skipped without anyone noticing, so its
   outcome is not optional. Write `artifacts/eval/version-persistence.md`
   containing either the per-PoC persist/fixed table, or the single line
   `skipped: <why>`, for example that a newer branch would not build against
   this kernel, or that no crash reached `reliable`. Both are acceptable
   results. A missing file fails the gate below.
6. Audit sample: re-verify a sample of [UNVERIFIED] RCA claims against
   source, and log outcomes (confirmed/refuted) to
   artifacts/eval/rca-audit.md. A refuted claim is corrected in the crash
   registry, and a note here does not replace that correction.
7. Impact audit: `python3 tools/pipeline_ctl.py impact-list`. Two numbers
   belong in the findings table: how many crashes have an impact record, and
   how many of those can carry a severity. A round that analysed every crash
   and produced no record able to carry a severity found crashes and no
   vulnerabilities, and the write-up has to say so plainly.
   Then re-check the strongest claims specifically. Every record with
   consequence `privilege-escalation` or `container-escape` gets its evidence
   read against source, because a vendor challenges those first and they are
   the only ones where being wrong is expensive. Refuted ones are corrected
   with `impact-set`, and an annotation here does not replace that. A high
   count of `undetermined` is not a failure to report. An honest one is the
   expected outcome for faults that vanish into GSP.

## Outputs
artifacts/eval/: coverage CSVs, plots, findings table, surface coverage report
and target denominator, the completion counts, round progression, rca-audit.md,
version-persistence.md.

## State
`python3 tools/pipeline_ctl.py set-phase eval in_progress|done|blocked`.

## Gate evidence
File listing of artifacts/eval/ with a one-line description of each artifact,
including version-persistence.md (a recorded `skipped: <why>` counts, and a
missing file fails), the surface coverage report with its three stages and
the corpus path it was measured against, and the completion counts with their
exit status. Name explicitly any run excluded from the numbers and why. State
whether the completion claim was made, and where any of its six evidence items
was missing, which one.

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

A **learning** is about the target. For this phase, typically measurement
facts: a number that turned out to mean something other than it appeared to.
A **mistake** is about us: something that cost time, produced a wrong
number, or would repeat. Both are read by whoever runs this phase next, on
another box months from now, so write for someone without your context.
Recording nothing across a whole phase is itself worth questioning.

`knowledge/` is committed to a **public repository**. It carries ABI and
process facts and never findings: `note` refuses text naming a crash id or a
path under `artifacts/crashes|pocs|rca`, and the specifics belong in the
crash registry. Record the general form. It is also the more useful one,
because the next agent is looking at a different crash.
