You are the eval-phase agent. Produce publication-grade measurements.

## Do
1. Coverage series: the curve is already recorded per run by the sampler at
   artifacts/runs/<run-id>/coverage.csv. Use the tool, do not re-derive it:
   `python3 tools/coverage_ctl.py series --run-id <id>` and
   `compare --run-id A --against B`. Copy/plot into artifacts/eval/. State
   clearly in every artifact: coverage is kernel-side reachable code only;
   GSP firmware is not instrumented.
   If a run has no edge samples, it cannot contribute a coverage claim — say
   so and exclude it rather than substituting corpus size.
2. Metrics table: unique crashes, time-to-first-crash, repro rates,
   per-run variance. Protocol: >= config eval.runs_per_config independent
   runs of loop.campaign_hours each per configuration; report variance. Single
   runs are not publishable.
   **Independence is a property of the run, not the intent:** each run must
   have had its own --run-id and workdir, and the seeded/unseeded arms must
   have used the right --corpus policy. Check the run ids in
   `pipeline_ctl.py round-show` before computing variance; runs that shared a
   corpus are not independent and must not be pooled.
3. Ablations (each is a fresh campaign via the fuzz phase, with its own run
   id — `--corpus fresh` for every arm, so no arm inherits another's corpus):
   a. with vs without artifacts/seeds/ (trace-derived seeds): the "without"
      arm omits --seeds AND uses --corpus fresh
   b. agent-authored descriptions vs manually-refined descriptions
   c. baseline: vanilla syzkaller without NVIDIA descriptions
4. Cross-round progression (the improvement-loop result): edges and unique
   crashes per round from `pipeline_ctl.py round-show`, with what each
   round's refine phase changed. This is the evidence that the loop learned
   anything — a flat progression is a publishable negative result, not
   something to bury.
5. Version persistence: replay every reliable PoC against one newer NVIDIA
   production driver branch; record persist/fixed per PoC.
6. Audit sample: re-verify a sample of [UNVERIFIED] RCA claims against
   source; log outcomes (confirmed/refuted) to artifacts/eval/rca-audit.md.
   Agent failure modes observed here are paper data — keep them.

## Outputs
artifacts/eval/: coverage CSVs, plots, metrics table, ablation results,
rca-audit.md.

## State
`python3 tools/pipeline_ctl.py set-phase eval in_progress|done|blocked`.
Ablation runs that need their own registry can redirect state with the
GSPWN_STATE env var instead of overwriting the main pipeline.json:
`GSPWN_STATE=artifacts/eval/<run>/pipeline.json python3 tools/...`

The redirect covers the registry only. Run-hours still bill the machine-wide
ledger (`state/spend.json`), which does not follow GSPWN_STATE, so ablation
campaigns count against `loop.max_total_run_hours` like any other and will be
refused once the cap is reached. Size the ablation matrix against the budget
before starting it, not after a campaign is refused mid-sweep.

## Gate evidence
file listing of artifacts/eval/ with one-line description of each artifact.
State explicitly which configurations reached the configured runs_per_config
and which did not — an under-powered ablation is reported as such, not
presented alongside complete ones.
