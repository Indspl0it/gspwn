---
title: coverage_ctl.py
description: Sampling both tracks, the two curves, the accumulation model, and the plateau and completion verdicts.
---

Records both coverage curves for a run and reports whether the run is still
discovering new edges and whether it has reached the commands the descriptions
declare. syzkaller runs the inner coverage-guided loop, and this module serves
the outer one, whose decision is whether another campaign is worth running.

- The edge curve counts distinct KCOV edges against cumulative executions. It
  has no known asymptote, so the verdict is an extrapolation from a fitted
  curve.
- The surface curve counts the enumerated targets this run's corpus names.
  Those are counted at 852, so the reading is a subtraction.

Samples are written to one CSV per run per track: `coverage.csv` for Track K and
`coverage-u.csv` for Track U, both under `artifacts/runs/<run-id>/`. The sampler
runs from the `gspwn-coverage` timer as root. Coverage is kernel-side reachable
code only, since GSP firmware carries no instrumentation.

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
| An unmeasurable surface is never charted as zero | `collect_surface` returns `None` on any failure, and `metric_rows` drops it |
| Track U records no surface value | `surface_due` refuses the track, because those harnesses produce no syzlang programs |
| The surface measurement runs on its own cadence | `surface_due` reads the last surface-carrying row's timestamp out of the CSV, so the cadence survives a sampler restart and a reboot |
| A measurement that cannot be stored is never taken | `surface_due` checks storability before cadence, so a CSV whose header lacks the column returns not-due. The check runs ahead of the `interval <= 0` early return, which was the second way into the unpack |
| A truncated inventory cannot fire the completion stop | `completion_status` requires every family in `surface_cov.FAMILIES` to contribute at least one target, and raises `SurfaceError` naming the empty ones otherwise, which yields `unknown` |
| A flat edge curve against a climbing surface curve reads as growth | `plateau_verdict` takes the second curve and returns `growing` with a detail line naming both |

## Sample schema

Every row carries the same eleven columns, in this order. `surface` was
appended and never inserted, because anything reading a CSV with `cut -d,`
counts positions.

| Column | Content |
|---|---|
| `ts` | Sample time, epoch seconds |
| `uptime_s` | Fuzzer uptime as the source reports it |
| `edges` | Distinct edges the source reports |
| `corpus` | Programs in the corpus |
| `corpus_bytes` | Size of `corpus.db`, a separate column from `corpus` because the two were once one and no comparison across a source change meant anything |
| `crashes` | Crashes the source reports |
| `execs` | Cumulative executions |
| `source` | Where the row came from: `json:<path>`, `html`, `corpus.db-size`, `afl-fuzzer_stats:<n>`, `corpus-count-only` or `unreachable` |
| `gpu` | `ok`, `dead`, `hung`, `missing`, `error`, or `n/a` for Track U |
| `disk_free_mb` | Free megabytes on the filesystem holding `artifacts/` |
| `surface` | Enumerated targets this run's corpus names, empty on the rows between surface samples |

`source` and `gpu` hold text and stay out of the integer conversion, so a
healthy GPU is never un-recorded by parsing `ok` as a number.

Track K reads syz-manager's stats endpoint, trying `/stats?format=json`,
`/api/stats` and `/stats.json` in that order, then scraping the dashboard HTML,
then falling back to the size of `corpus.db`. Track U sums AFL++ `fuzzer_stats`
across `artifacts/runs/<run-id>/u/<harness>/`.

## Subcommands

| Subcommand | Arguments | Purpose |
|---|---|---|
| `sample` | `--run-id`, `--track`, `--url`, `--force`, `--skip-surface` | Append one row for a run and track |
| `install-timer` | `--run-id`, `--url`, `--interval-min` | Install and start the sampler timer |
| `remove-timer` | none | Stop and remove the sampler timer |
| `series` | `--run-id`, `--track` | Print the recorded series for one track |
| `plateau` | `--run-id`, `--track`, `--window-min`, `--min-growth`, `--horizon-hours` | Print the verdict for a run |
| `gpu-health` | none | Probe the GPU and print status and detail |
| `compare` | `--run-id`, `--against`, `--track` | Print the endpoints of two runs side by side |
| `completion` | `--run-id`, `--corpus`, `--ledger`, `--top` | The ledger identity: whether every target is exercised or accounted for |
| `migrate-csv` | `--run-id`, `--track` | Add the columns a run's CSV header lacks and pad every existing row |

| Flag | Default | Effect |
|---|---|---|
| `--track` | `k` | The track to read or write. Omitting it on `plateau` gives the combined verdict over both tracks, and on `migrate-csv` migrates both files |
| `--url` | `gspwn_config.manager_url()`, derived from `track_k.http` | The syz-manager address to poll |
| `--force` | off | Sample even after the campaign window has elapsed |
| `--skip-surface` | off | Skip the surface column on this sample |
| `--interval-min` | `loop.coverage_sample_min` | Timer cadence, in minutes |
| `--window-min` | `loop.plateau_window_min` | Trailing window the GPU gate and the clock-based fallback measure over |
| `--min-growth` | `loop.plateau_min_growth` | Fractional growth floor, used only for runs whose source records no execution count |
| `--horizon-hours` | `coverage.horizon_hours` | How far ahead the fitted curve is extrapolated |
| `--run-id` on `completion` | none, which reads the seed bank | Repeatable, and the exercised sets are unioned |
| `--corpus` | none | A directory of programs to measure instead. It cannot be combined with `--run-id` |
| `--ledger` | `ps.SURFACE_LEDGER_PATH` | The completion ledger to account against |
| `--top` | `40` | How many unaddressed targets to list. `0` lists none and reports the count |

The sampler address is derived from `track_k.http` on every run. A sampler
carrying its own copy of the address kept polling the old port after the config
changed and recorded a whole campaign as unreachable.

The surface cadence is `coverage.surface_sample_min`, overridden by the
environment variable `GSPWN_SURFACE_SAMPLE_MIN`. That column is an unpack and a
full rescan of the run's corpus, so it runs coarser than the HTTP fetch the
other columns come from.

## Callers

- Four modules import this one. `pipeline_ctl.py` for `_derive_run`,
  `campaign_ctl.py` for `measured_run_hours`, `crashlog_ctl.py` for
  `report_disk`, and `orchestrator_ctl.py` for `cmd_preflight`.
- This module imports `pipeline_state.py`, `gspwn_config.py`, and
  `surface_cov.py` lazily for the surface column and the completion ledger.

`crashlog_ctl` and `orchestrator_ctl` import it inside a `try`, so a broken
import cannot stop a harvest or a resume.

## Exit codes

Two subcommands carry a three-valued verdict in their exit status, so a shell
can branch on it without parsing the output.

| Subcommand | 0 | 1 | 3 |
|---|---|---|---|
| `plateau` | `growing` | `unknown` | `plateaued` |
| `completion` | `complete` | `unknown` | `incomplete` |
| `gpu-health` | GPU status `ok` | Any other status | |
| `sample` | Row appended | Run unregistered, CSV not writable, or the source unreachable | |
| `series` | Samples found | No samples recorded for that run and track | |
| `migrate-csv` | Migrated, or already complete | The rewrite aborted | |
| `install-timer`, `remove-timer` | Done | Not root, or the run is unregistered | |
| `compare` | Always | | |

## Failure modes

Fifteen conditions have a defined behaviour.

| Condition | Behaviour |
|---|---|
| Run not registered | `sample` prints the run id and the state file and returns 1. `install-timer` exits with the same reason |
| Campaign window elapsed | `sample` returns 0 without appending, unless `--force` |
| Sample source unreachable | The row records with `source: unreachable` and no exception, and `sample` returns 1 with a warning naming the address or the Track U output directory |
| CSV owned by the root sampler | `sample` catches the `PermissionError`, reports the ownership, directs a re-run under `sudo` and returns 1 |
| CSV written before a column existed | The existing header is reused, the row is written to that shape, and a warning names `migrate-csv` |
| The CSV grows during `migrate-csv` | The rewrite aborts with the original untouched, and `migrate-csv` returns 1 directing that the sampler be stopped first |
| Any sample in the window not `ok` | A plateau reads `unknown`. `growing` is unaffected, because coverage cannot climb on a GPU that is not answering |
| Fewer than three usable samples, or no edge data | Verdict `unknown` |
| The fuzzer is still replaying its corpus after a restart | Verdict `unknown`, naming the current count and the run's high-water mark |
| Fit quality below `coverage.model_min_r2`, or `beta` outside `(0, 1]` | Verdict `unknown`, quoting the figure and the threshold |
| Degenerate fit | `_ols` returns `None`, and the clock-based window verdict stands in |
| Configuration unreadable | `_coverage_cfg` falls back to the shipped defaults, so a verdict path other tools call keeps working. The CLI itself exits at parser construction, since it needs the manager address and the loop tunables |
| Anything that stops the corpus or the ledger being read | `completion_status` never raises and yields `unknown` with the error in the detail line |
| `completion` given both `--run-id` and `--corpus` | Exits, since the two name two different corpora |
| Track U harness writes no `fuzzer_stats` | Source reads `corpus-count-only`, and no edge count is inferred from corpus size |

Free disk is read on every sample, and a figure under `loop.min_free_disk_gb`
prints a warning naming the floor. A full disk stops the fuzzer, the sampler and
every state write at the same moment.

## Concurrency and durability

The sampler appends one row per invocation and `fsync`s the file, so a panic
between samples leaves a complete row set. The timer is per run, and the service
unit's two `ExecStart` lines are `-` prefixed, so a failure sampling one track
does not suppress the other. The Track U line passes `--skip-surface`. No lock
is taken: one timer owns each run's CSV, and the append is the only write.
Sampling after the window elapses is suppressed by `campaign_finished`, which
bounds the file's growth.

`install-timer` carries `GSPWN_STATE` into the unit when the install was made
with it set, so the unattended sampler validates and records against the same
registry.

## Prohibited behaviour

Fourteen rules hold, most of them against a curve that would read as a plateau
without being one.

| Rule | Rationale |
|---|---|
| Never let a dead GPU read as a plateau | A card that has fallen off the bus does not stop the fuzzer; the curve flattens. The recorded GPU status separates the two |
| Never count replay as discovery | syzkaller re-executes its corpus after every restart. Measured naively, a saturated run reports tens of percent of growth after each panic |
| Never measure against wall-clock when executions are available | A fixed wall-clock window contains an unpredictable amount of executed testing on a machine that panics by design |
| Never extrapolate from a curve the model does not describe | Below `coverage.model_min_r2` the verdict is `unknown` |
| Never sample an unregistered run | The sampler runs as root, and a typo leaves a root-owned run directory that later confuses `series` and `status` |
| Never keep sampling after the window elapses | The timer outlives the campaign and would append an empty row every interval, padding the sample count and the apparent duration |
| Never write a row wider than the file's own header | A run that started before a column existed keeps its shape and every later read stays aligned |
| Never let a sample failure raise | A failed sample records with `source: unreachable`, so the gap is visible |
| Never let a missing configuration stop the verdict path | Several other tools call this path |
| Never charge Track U for the GPU | Those harnesses run in a container and never touch the card, so their samples record `n/a` |
| Never record a surface count for Track U | Those harnesses produce no syzlang programs, and a 0 would put an absence of evidence into the curve as a measurement |
| Never fit Heaps' law to the surface series | An unbounded power law over a quantity bounded at 852 predicts more new targets than remain, and the dynamic range makes the `R2` gate close to arbitrary |
| Never apply the surface reading before the GPU gate | A dead GPU does not flatten the surface count the way it flattens the edge count, so a climbing surface curve is no evidence that the card is alive |
| Never add the exercised and accounted counts | A target can be exercised in a later round after an earlier one wrote a reason for it, and the sum would close the ledger while targets remained |

## Design notes

`_dig` handles both shapes syz-manager has used: direct mappings, and
`{"name": ..., "value": ...}` records inside a stats list.

Track U sums AFL++ `fuzzer_stats` across the run's harnesses. Each harness
keeps its own coverage bitmap, so the sum is a per-run trend line for the whole
track. AFL++ keeps its queue in the same directory it writes `fuzzer_stats` to,
and counting both would double every AFL++ harness's corpus, so the queue and
corpus directories are counted only for a harness that wrote no stats file.

`_ols` returns `None` on a degenerate fit. A slope of zero would read as a flat
and fully trusted curve.

`flat_tail` is handled before the fit, because a curve with no variance cannot
be fitted at all and would otherwise fall through to the weaker clock-based
test. Its guard on a measurable execution rate makes the recent stretch mean the
end of the run. A source that stopped reporting executions mid-run leaves the
tail covering only the prefix, and without the guard a run whose last hours
quadrupled its coverage reports a plateau quoting the flat prefix.

`run_verdict` combines the tracks: the round is still learning if either track
is growing, a track with no samples at all is ignored, and no track with data
leaves the answer `unknown`, which the loop treats as a stop.

The surface column stays out of `TEXT_FIELDS`, so `read_rows` runs it through
`_to_int` and an older CSV yields an empty value with no `KeyError`. A run
already in progress gains no surface curve from a sample, because `cmd_sample`
appends under the header the file carries. That case warns and the run reads
`surface_verdict=unknown`.

`migrate-csv` is the path to the column for a run already in flight. The header
rewrite is not automatic, because doing it from inside a sample would rewrite a
file the root sampler holds. `migrate_csv` writes a temp file in the same
directory and calls `os.replace`, carries the original's mode over, and
compares the file's size before and after, so a sample landing mid-rewrite
aborts the migration with the original untouched and drops no row.

`since_last_reset` takes only the rows. It reads the edge curve, where a drop
means the fuzzer process restarted and its counter went back to zero. The
surface column falls for a different cause, syzkaller minimising its corpus, so
`surface_growth` reads that curve through `accumulate`, a running maximum. A
falling surface count therefore contributes nothing and is never attributed to
a restart, which left the metric parameter with no caller and no way to acquire
one.

A truncated inventory yields a smaller denominator that a corpus can close,
which would fire the completion stop over commands nobody counted.
`completion_status` yields `unknown` instead, which fails closed. No expected
count is stored and no constant can drift. A truncated
`rm-control-inventory.json` empties `control`, a truncated ioctl inventory
empties the three escape and UVM families, a truncated object graph empties
`alloc`, a truncated `nvkms-command-inventory.json` empties `modeset`, and a
truncated `drm-command-inventory.json` empties `drm`.

A ledger row naming a target no inventory contains is reported and not counted,
so a ledger outliving a driver bump cannot close the surface with reasons
written for commands that no longer exist. `completion` also stamps the
denominator version the reading was taken against, and states both versions
where a run's round was measured on a different one.

The completion check is its own subcommand. `plateau` keeps `growing`,
`plateaued` and `unknown` with its three exit codes, and `completion` carries
`complete`, `incomplete` and `unknown` with its own.

## See also

- [Coverage and plateau](/gspwn/architecture/coverage-and-plateau/)
- [surface_cov.py](/gspwn/architecture/components/surface-cov/)
- [pipeline_state.py](/gspwn/architecture/components/pipeline-state/)
