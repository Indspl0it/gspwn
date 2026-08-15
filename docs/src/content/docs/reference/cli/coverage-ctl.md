---
title: coverage_ctl.py
description: Sampling the coverage curve, summarising it, and deriving the plateau verdict.
---

Records the coverage curve for a run and answers whether the run is still
buying new edges. syzkaller runs the inner coverage-guided loop. This tool
serves the outer loop.

## Synopsis

```
python3 tools/coverage_ctl.py <subcommand> [options]
```

`sample`, `install-timer` and `remove-timer` require root.

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

```
artifacts/runs/r2-1/coverage.csv edges=18422 corpus=512 crashes=0 (source: json:/stats?format=json, gpu: ok)
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

| Source | What it is |
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

`corpus-count-only` means no harness wrote `fuzzer_stats`, which is what
libFuzzer harnesses do. The corpus directory is then the only signal and it
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
  crashes: 0 -> 8
  NOTE: kernel-side reachable coverage only; GSP firmware is not instrumented.
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

Derivation: [Coverage and plateau](/gspwn/architecture/coverage-and-plateau/).

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
Comparing runs is only meaningful when each had its own workdir and corpus policy — see campaign_ctl.py --corpus.
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

`corpus` is a program count and `corpus_bytes` is a file size. Separate columns
keep a comparison valid across a change of source.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. For `plateau`, the verdict is `growing` |
| 1 | A read or write failed. For `plateau`, the verdict is `unknown`. For `gpu-health`, the status is not `ok` |
| 3 | `plateau` only: the verdict is `plateaued` |

## Files

| Path | Contents |
|---|---|
| `artifacts/runs/<id>/coverage.csv` | The Track K sample series |
| `artifacts/runs/<id>/coverage-u.csv` | The Track U sample series |
| `artifacts/runs/<id>/u/<harness>/` | Per-harness AFL++ state the Track U source sums |
| `gspwn-coverage.service`, `gspwn-coverage.timer` | The sampler units |

## See also

- [Artifacts](/gspwn/reference/artifacts/)
- [Coverage and plateau](/gspwn/architecture/coverage-and-plateau/)
</content>
</invoke>
