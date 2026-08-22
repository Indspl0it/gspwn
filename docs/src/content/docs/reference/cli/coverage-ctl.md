---
title: coverage_ctl.py
description: Sampling both coverage curves, summarising them, and deriving the plateau and completion verdicts.
---

Records both coverage curves for a run and answers whether the run is still
buying new edges and whether it has reached the commands the descriptions
declare. syzkaller runs the inner coverage-guided loop. This tool serves the
outer loop.

## Synopsis

```
python3 tools/coverage_ctl.py <subcommand> [options]
```

`sample`, `install-timer` and `remove-timer` require root. `migrate-csv`
carries no root check of its own and rewrites a file the root sampler owns, so
it runs under `sudo` wherever that sampler is installed.

## sample

Appends one row to `artifacts/runs/<id>/coverage.csv` for Track K, or
`coverage-u.csv` for Track U.

```
sudo python3 tools/coverage_ctl.py sample --run-id r2-1 [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | Required | Must be a registered run |
| `--url` | `URL` | Derived from `track_k.http` | Stats endpoint |
| `--track` | `k`, `u` | `k` | Which track to sample |
| `--force` | None | Off | Sample even after the campaign window has elapsed |
| `--skip-surface` | None | Off | Do not measure the surface column on this sample |

```
artifacts/runs/r2-1/coverage.csv edges=18422 surface=317 corpus=512 crashes=0 (source: json:/stats?format=json, gpu: ok)
```

The surface column comes from unpacking the run's `corpus.db` and rescanning
every program in it. It runs on the coarser cadence
`coverage.surface_sample_min` sets, and the rows in between record no value. The
timer's Track U line passes `--skip-surface`, because those harnesses produce
no syzlang programs. A sample that skipped the measurement says so:

```
  surface: last measured 12 min ago, under the 60 min surface interval
```

The row is appended under the header the file already carries. A run that
started before a column existed keeps its shape, and every later read stays
aligned.

Sampling is skipped once the campaign's deadline has passed. The timer outlives
the campaign, and further samples would append an empty row every interval,
padding the run's sample count and its apparent duration.

| Condition | Result |
|---|---|
| The source was unreachable | Exit 1 |
| The run is not registered | Exit 1 |
| The CSV cannot be written | Exit 1 |

### Track K sources, in order

| Source | Definition |
|---|---|
| `json:/stats?format=json`, `json:/api/stats`, `json:/stats.json` | syz-manager's JSON endpoints, newest style first |
| `html` | The dashboard HTML, scraped for label-and-number pairs |
| `corpus.db-size` | The corpus database's byte size, recorded in its own column so it can never be charted as coverage |
| `unreachable` | Nothing answered |

syz-manager's HTTP surface has changed across syzkaller versions. The source
that answered is printed and written into every row.

### Track U source

Sums AFL++ `fuzzer_stats` across `artifacts/runs/<id>/u/<harness>/`. Each
harness keeps its own coverage bitmap, so the edge count is a per-run trend
line across the whole harness set.

`corpus-count-only` means no harness wrote `fuzzer_stats`. libFuzzer harnesses
do not write it. The corpus directory is then the only signal and it
carries no edge count.

## install-timer

Installs `gspwn-coverage.service` and `gspwn-coverage.timer`, sampling both
tracks on one timer.

```
sudo python3 tools/coverage_ctl.py install-timer --run-id r2-1 [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | Required | Must be a registered run |
| `--url` | `URL` | Derived from `track_k.http` | Stats endpoint |
| `--interval-min` | `N` | `loop.coverage_sample_min` | Sampling interval |

The service's two `ExecStart` lines are `-` prefixed, so a failure sampling one
track does not suppress the other.

The campaign deadline is enforced by a separate per-run timer, so the spend
ceiling holds even if the sampler is never installed.

## remove-timer

Disables and deletes both units.

```
sudo python3 tools/coverage_ctl.py remove-timer
```

## series

Summarises one run's samples on one track.

```
python3 tools/coverage_ctl.py series --run-id r2-1 [--track k|u]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | Required | The run to summarise |
| `--track` | `k`, `u` | `k` | Which track to read |

```
run r2-1 track k: 141 samples over 23.5 h
  sources: json:/stats?format=json
  gpu: healthy across all 141 sample(s)
  disk free: 412.6 GB -> 388.1 GB (low water 388.1 GB)
  edges: 18422 -> 41907 (+23485)
  corpus: 512 -> 4183
  crashes: 0 -> 8  NOTE: kernel-side reachable coverage only. GSP firmware is not instrumented.
```

`edges: never recorded` means the run cannot support a coverage claim.

| Condition | Result |
|---|---|
| No samples exist for that run and track | Exit 1 |

## plateau

Derives the plateau verdict for a run.

```
python3 tools/coverage_ctl.py plateau --run-id r2-1 [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | Required | The run to judge |
| `--track` | `k`, `u` | Combined | One track. Omit for the combined view the loop acts on |
| `--window-min` | `N` | `loop.plateau_window_min` | Trailing window for the fallback growth test |
| `--min-growth` | `F` | `loop.plateau_min_growth` | Fractional growth threshold for that fallback |
| `--horizon-hours` | `H` | `coverage.horizon_hours` | How far ahead to extrapolate |

| Combined verdict | Condition |
|---|---|
| `growing` | Any sampled track is still finding edges |
| `plateaued` | Any decided track has plateaued and none is growing |
| `unknown` | No track produced a verdict |

A track that was never sampled is ignored.

A flat edge curve is read against the surface curve before any plateau is
reported. A climbing surface curve makes the verdict `growing`, because the
round is still reaching commands it had not reached whatever the edge count
did.

Derivation: [Coverage and plateau](/gspwn/architecture/coverage-and-plateau/).

## completion

Answers the ledger identity: whether every enumerated target is either
exercised by a corpus or accounted for by a written reason.

```
python3 tools/coverage_ctl.py completion [--run-id r2-1] [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | The seed bank | Measure the exercised set from this run's own `corpus.db`. Repeatable, and the sets are unioned |
| `--corpus` | `DIR` | The seed bank | A directory of programs to measure. The seed bank is not read. Refused with `--run-id` |
| `--ledger` | `PATH` | `surface/completion-ledger.json` | The completion ledger |
| `--top` | `N` | 40 | How many unaddressed targets to list. 0 lists none and reports the count |

The output names the driver version, every corpus read with its modification
time and program count, the ledger path, the three counts, and the targets that
are neither exercised nor accounted for. Each of those prints as a
worklist-ready line carrying the variant in brackets, which is the handle
`pipeline_ctl.py surface-account` resolves.

The closed count is a union and not a sum, because a target can be exercised in
a later round after an earlier one wrote a reason for it.

`--top` takes a non-negative integer, and a negative value is a parser error.
At 0 the line reads `N target(s) not listed (--top 0)`, and the offer to raise
`--top` prints only where some targets were shown.

`--corpus` and `--run-id` together are refused, matching `surface_cov.py
report`: the two name different corpora and one of them would be dropped
silently.

With neither, the command reads the seed bank and says so. A target counts as
exercised because a generated program names it and not because a fuzzer ran it,
the bank holds this round's programs only after `corpus_ctl.py promote`, and
the reading the stop rule uses needs `--run-id`.

A row written under a reason that does not close a target is reported as
`deferred` and is subtracted before the union, so a deferral never satisfies
the completion identity. See
[Closed vocabularies](/gspwn/reference/vocabularies/).

## gpu-health

Probes the GPU with `nvidia-smi`.

```
python3 tools/coverage_ctl.py gpu-health
```

```
GPU: ok (NVIDIA L4, 00000000:31:00.0)
```

| Status | Meaning |
|---|---|
| `ok` | `nvidia-smi` answered with at least one GPU |
| `dead` | Non-zero exit, or no GPU in the output |
| `hung` | No answer within `coverage.gpu_probe_timeout_sec` |
| `missing` | `nvidia-smi` is not on `PATH` |
| `error` | The probe could not be run |

Exits 0 for `ok` and 1 otherwise. The probe reports. It does not attempt
recovery.

Only `ok` permits a plateau claim. Every other status means the curve cannot be
trusted to say why it flattened.

## compare

Prints two runs' edge growth side by side.

```
python3 tools/coverage_ctl.py compare --run-id r2-1 --against r1-1 [--track k|u]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | Required | The first run |
| `--against` | `ID` | Required | The second run |
| `--track` | `k`, `u` | `k` | Which track to read |

```
r2-1                 edges  18422 ->  41907  (+23485) over 23.5 h
r1-1                 edges  12004 ->  31220  (+19216) over 23.8 h
Comparing runs is only meaningful when each had its own workdir and corpus policy. See campaign_ctl.py --corpus.
```

## The CSV columns

| Column | Contents |
|---|---|
| `ts` | Unix timestamp of the sample |
| `uptime_s` | Fuzzer uptime, where the source reports one |
| `edges` | Distinct edges reported |
| `corpus` | Program count |
| `corpus_bytes` | The corpus database's byte size, from the fallback source only |
| `crashes` | Crashes the fuzzer counted |
| `execs` | Executions performed |
| `source` | Which source answered |
| `gpu` | `ok`, `dead`, `hung`, `missing`, `error`, or `n/a` for Track U |
| `disk_free_mb` | Free megabytes on the artifacts filesystem |
| `surface` | Enumerated targets this run's corpus names. Empty on a sample that skipped the measurement, and on every Track U row |

`corpus` is a program count and `corpus_bytes` is a file size. Separate columns
keep a comparison valid across a change of source.

`surface` is appended last, never inserted, so anything reading an older file
with `cut -d,` stays aligned. A run that started before the column existed
gains no surface curve and reads `surface_verdict=unknown`, because rows are
appended under the header the file already carries.

Such a run also costs nothing. `surface_due` checks storability before cadence,
so a CSV whose header lacks the column is not measured at all. The measurement
used to be taken and then dropped by the writer, at one corpus unpack and one
full rescan per sample.

## migrate-csv

Adds the columns a run's CSV header lacks and pads every existing row.

```
python3 tools/coverage_ctl.py migrate-csv --run-id r2-1 [--track k|u]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | Required | The run whose CSV is migrated |
| `--track` | `k`, `u` | Both | Which track to migrate |

This is the one operation on a `coverage.csv` that is not an append, so it is
an operator step and nothing migrates automatically. Stop the sampler first.

```
sudo systemctl stop gspwn-coverage.timer
sudo python3 tools/coverage_ctl.py migrate-csv --run-id r2-1
sudo systemctl start gspwn-coverage.timer
```

Existing columns keep their positions, so a header this version does not know
about survives and anything reading by column index reads the same numbers. The
write is a temp file in the same directory followed by `os.replace`, and the
mode is carried over from the original. The file's size is compared before and
after: a sample landing mid-rewrite aborts the migration with the original
untouched and drops no row.

Track U gains the column and is still never asked for a surface sample.

After the migration the next sample measures, the cadence gate engages at
`coverage.surface_sample_min`, and the run gains a surface curve from that
point. Rows written before the migration carry no surface value and
`metric_rows` drops them, so the curve starts where the migration ran.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. For `plateau`, the verdict is `growing` |
| 1 | A read or write failed. For `plateau` and `completion`, the verdict is `unknown`. For `gpu-health`, the status is not `ok` |
| 2 | A usage error, including `--top` below 0 |
| 3 | `plateau`: the verdict is `plateaued`. `completion`: the verdict is `incomplete` |

## Files

| Path | Contents |
|---|---|
| `artifacts/runs/<id>/coverage.csv` | The Track K sample series |
| `artifacts/runs/<id>/coverage-u.csv` | The Track U sample series |
| `artifacts/runs/<id>/u/<harness>/` | Per-harness AFL++ state the Track U source sums |
| `artifacts/runs/<id>/workdir/corpus.db` | What the surface column and `completion --run-id` measure |
| `surface/completion-ledger.json` | The accounted targets `completion` reads |
| `gspwn-coverage.service`, `gspwn-coverage.timer` | The sampler units |

## See also

- [Artifacts](/gspwn/reference/artifacts/)
- [Coverage and plateau](/gspwn/architecture/coverage-and-plateau/)
