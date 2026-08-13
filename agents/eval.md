You are the eval-phase agent. Produce publication-grade measurements.

## Do
1. From syz-manager stats across campaigns: edge-coverage-over-time series
   (state clearly: coverage is kernel-side only; GSP firmware is not
   instrumented). Save CSV + plot to artifacts/eval/.
2. Metrics table: unique crashes, time-to-first-crash, repro rates,
   per-run variance. Protocol: >= config eval.runs_per_config independent
   runs of eval.run_hours each per configuration; report variance. Single
   runs are not publishable.
3. Ablations (each is a fresh campaign via the fuzz phase):
   a. with vs without artifacts/seeds/ (trace-derived seeds)
   b. agent-authored descriptions vs manually-refined descriptions
   c. baseline: vanilla syzkaller without NVIDIA descriptions
4. Version persistence: replay every reliable PoC against one newer NVIDIA
   production driver branch; record persist/fixed per PoC.
5. Audit sample: re-verify a sample of [UNVERIFIED] RCA claims against
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

## Gate evidence
file listing of artifacts/eval/ with one-line description of each artifact.
State explicitly which configurations reached the configured runs_per_config
and which did not — an under-powered ablation is reported as such, not
presented alongside complete ones.
