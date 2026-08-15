---
title: coverage_ctl.py
description: Sampling both tracks, the accumulation model, and the plateau verdict.
---

Records the coverage curve for a run and reports whether the run is still
discovering new edges. syzkaller runs the inner coverage-guided loop; this
module serves the outer one, whose decision is whether another campaign is
worth running.

Samples land in one CSV per run per track. The sampler runs from the
`gspwn-coverage` timer as root.

## Responsibility

The module owns the sample schema, the accumulation model, and the plateau
verdict. It is the sole writer of each run's `coverage.csv`.

| Invariant | Enforced by |
|---|---|
| A plateau is never claimed on an unhealthy GPU | Every sample records GPU status; `plateau_verdict` downgrades a plateau to `unknown` when any sample in the window is not `ok` |
| Replayed corpus is not counted as discovery | `accumulate` takes a running maximum and `since_last_reset` detects the restart |
| The verdict is measured against work done | The curve's x axis is cumulative executions where they are available |
| A curve the model does not describe yields no number | Below `coverage.model_min_r2` the verdict is `unknown` |
| A CSV keeps its shape for the life of a run | `existing_fields` reads the header the file already carries and writes to it |
| A failed sample is visible in the curve | `collect` never raises; the row records with `source: unreachable` |
| Only registered runs are sampled | `cmd_sample` checks `registered_runs` first |

## Interface

| Subcommand | Purpose |
|---|---|
| `sample` | Append one sample for a run and track |
| `install-timer`, `remove-timer` | Install or remove the sampler timer for a run |
| `series` | Print the recorded series for a metric |
| `plateau` | Print the verdict for a run |
| `gpu-health` | Probe the GPU and print status and detail |
| `compare` | Compare series across runs |

| Function | Returns | Raises |
|---|---|---|
| `read_rows(run_id, track='k')` | Recorded rows, oldest first | |
| `metric_rows(run_id, metric='edges', track='k')` | Rows carrying a usable value for the metric | |
| `collect(run_id, url, track='k')` | `(row_dict, source)`; never raises | |
| `collect_u(run_id)` | `(row, source)` summed across the run's harnesses | |
| `plateau_verdict(rows, window_min, min_growth, horizon_hours=None, cov=None)` | `(verdict, detail)`, verdict one of `growing`, `plateaued`, `unknown` | |
| `run_verdict(run_id, window_min, min_growth, tracks=TRACKS, horizon_hours=None)` | Per-track verdicts and the combined one | |
| `accumulate(rows)` | `[(cum_execs or None, cum_edges)]` | |
| `heaps_fit(points)` | The fitted curve as a dict, or `None` | |
| `expected_new_edges(fit, extra_execs)` | Edges the fit expects from further executions | |
| `exec_rate_per_hour(rows)` | Executions per hour, or `None` | |
| `since_last_reset(rows)` | `(rows since the last restart, whether it restarted)` | |
| `unhealthy_gpu_samples(window)` | `{status: count}` for samples not recording `ok` | |
| `gpu_health(timeout=None)` | `(status, detail)` | |
| `disk_free_mb(path=None)` | Free megabytes, or `None` | |
| `disk_warning(free_mb=None)` | A warning line, or `''` | |
| `campaign_finished(run_id)` | `bool` | |
| `registered_runs(state)` | Run ids the pipeline knows about | |

Exported constants: `TRACKS`, `FIELDS`, `GPU_OK`, `GPU_NOT_APPLICABLE`.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | `pipeline_ctl.py` for `_derive_run`, `campaign_ctl.py` for `measured_run_hours`, `crashlog_ctl.py` for `report_disk`, `orchestrator_ctl.py` for `cmd_preflight` |
| This module imports | `pipeline_state.py`, `gspwn_config.py` |

`crashlog_ctl` and `orchestrator_ctl` import it inside a `try`, so a broken
import cannot stop a harvest or a resume.

## Failure modes

| Condition | Behaviour |
|---|---|
| Sample source unreachable | The row records with `source: unreachable`; no exception |
| Run not registered | `sample` exits 1 naming the run and the state file |
| Campaign window elapsed | `sample` stops appending |
| CSV written before a column existed | The existing header is reused and the row is written to that shape |
| Any sample in the window not `ok` | A plateau reads `unknown`; `growing` is unaffected |
| Fit quality below `coverage.model_min_r2` | Verdict `unknown` |
| Degenerate fit | `_ols` returns `None` |
| Configuration unreadable | `_coverage_cfg` falls back to the shipped defaults |
| Track U harness writes no `fuzzer_stats` | Source reads `corpus-count-only` |
| `install-timer` or `remove-timer` run as non-root | Exits 1 |

## Concurrency and durability

The sampler appends one row per invocation and `fsync`s the file, so a panic
between samples leaves a complete row set. The timer is per run, and the service
unit's two `ExecStart` lines are `-` prefixed, so a failure sampling one track
does not suppress the other. No lock is taken: one timer owns each run's CSV,
and the append is the only write. Sampling after the window elapses is
suppressed by `campaign_finished`, which bounds the file's growth.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never let a dead GPU read as a plateau | A card that has fallen off the bus does not stop the fuzzer; the curve flattens. The recorded GPU status is what separates the two |
| Never count replay as discovery | syzkaller re-executes its corpus after every restart. Measured naively, a saturated run reports tens of percent of growth after each panic |
| Never measure against wall-clock when executions are available | A fixed wall-clock window contains very different amounts of executed testing on a machine that panics by design |
| Never extrapolate from a curve the model does not describe | Below `coverage.model_min_r2` the verdict is `unknown` |
| Never sample an unregistered run | The sampler runs as root, and a typo leaves a root-owned run directory that later confuses `series` and `status` |
| Never keep sampling after the window elapses | The timer outlives the campaign and would append an empty row every interval, padding the sample count and the apparent duration |
| Never write a row wider than the file's own header | A run that started before a column existed keeps its shape and every later read stays aligned |
| Never let a sample failure raise | A failed sample records with `source: unreachable`, so the gap is visible |
| Never let a missing configuration stop the verdict path | Several other tools call this path |
| Never charge Track U for the GPU | Those harnesses run in a container and never touch the card; their samples record `n/a` |

## Design notes

`corpus` is a program count and `corpus_bytes` is a file size, in separate
columns. A single combined column makes any comparison spanning a source change
meaningless.

The Track K source ladder tries the JSON endpoints, then scrapes the dashboard
HTML, then falls back to the corpus database's size, because syz-manager's HTTP
surface has changed across syzkaller versions. Whichever answered is written
into every row.

`_dig` handles both shapes syz-manager has used: direct mappings, and
`{"name": ..., "value": ...}` records inside a stats list.

Track U sums `fuzzer_stats` across harnesses. Each keeps its own coverage
bitmap, so the sum is a per-run trend line for the whole track. AFL++ keeps its
queue in the same directory it writes `fuzzer_stats` to, so counting both would
double every AFL++ harness's corpus.

`_ols` returns `None` on a degenerate fit. A slope of zero would read as a flat
and fully trusted curve.

`flat_tail` is handled before the fit, because a curve with no variance cannot
be fitted at all and would otherwise fall through to the weaker clock-based
test. Its guard on a measurable execution rate makes the recent stretch mean the
end of the run. A source that stopped reporting executions mid-run leaves the
tail covering only the prefix, and without the guard a run whose last hours
quadrupled its coverage reports a plateau quoting the flat prefix.

## See also

- [Coverage and plateau](/gspwn/architecture/coverage-and-plateau/)
- [coverage_ctl.py reference](/gspwn/reference/cli/coverage-ctl/)
