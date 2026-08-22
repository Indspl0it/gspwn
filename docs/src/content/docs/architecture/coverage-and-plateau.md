---
title: Coverage and plateau
description: The species-accumulation model, the Heaps' law fit, the parameters that decide a plateau, the unknown cases, and the two limits the model states.
---

Two curves and a ledger decide whether to run another round. The edge curve
answers whether the fuzzer is still finding code, and its verdict is an
extrapolation from a fitted species-accumulation curve computed by
`coverage_ctl.py plateau`. The surface curve answers whether the commands the
descriptions declare have been tried, and the completion ledger answers whether
every target the inventories enumerate is either exercised or accounted for.

| Edge curve | Surface curve | Ledger | Recorded verdict | Loop decision |
|---|---|---|---|---|
| Climbing | Any | Open | `coverage_verdict=growing` | Continue |
| Flat | Climbing | Any | `coverage_verdict=growing` | Continue. The round is still reaching commands it had not reached |
| Flat | Flat | Open | `plateaued` and `surface_verdict=incomplete` | Stop, overridable. The reason names a stuck corpus and the number of open targets |
| Flat | Unknown | Any | `plateaued` and `surface_verdict=unknown` | Stop, overridable. The reason says no completion reading exists |
| Any | Any | Closed | `surface_verdict=complete` | Stop, non-overridable. Nothing is left to fuzz |

Completion is the campaign's primary termination. `loop.max_rounds` is a
backstop against a runaway loop, and a campaign that reaches it has failed to
converge.

## Model

Coverage growth is a species-discovery process. The framing is Böhme's, from
*STADS: Software Testing as Species Discovery* (TOSEM, 2018).

| Model term | Pipeline quantity |
|---|---|
| Species | One distinct edge |
| Sampled individual | One executed input |
| Species accumulation curve | Distinct edges against cumulative executions |
| Discovery exponent | `beta` in the fitted curve |

The output is the number of new edges another campaign of
`coverage.horizon_hours` is expected to find. That figure is in the units of
the quantity being predicted. A growth percentage is scale-dependent: the same
percentage means ten edges early in a run and a thousand late in one.

## Axis construction

`accumulate()` in `tools/coverage_ctl.py` transforms the sampled rows into the
curve. Both counters reset when the fuzzer restarts, and the two axes handle
that reset differently.

| Axis | Quantity | Accumulation | Behaviour on a counter reset |
|---|---|---|---|
| x | Cumulative executions | Sum of per-sample deltas | The delta is the new reading itself, so no negative delta is recorded |
| y | Distinct edges | Running maximum | The replayed count contributes zero until it passes the previous high-water mark |

Executions accumulate as a sum because they are work done. Edges accumulate as
a maximum because they are a set.

| Axis choice | Failure it removes |
|---|---|
| Executions on x | A fixed wall-clock window contains widely varying amounts of testing on a machine that panics by design, so a slow hour has the same shape as saturation |
| Running maximum on y | syzkaller re-executes its corpus after every restart. Taken from the raw reported count, a saturated run reports tens of percent of growth after each panic, and a campaign that has stopped finding edges continues on the strength of its own crashes |

## The fit

Heaps' law relates distinct edges `S` to cumulative executions `n`:

```
S(n) = K * n^beta
```

`heaps_fit()` fits it by ordinary least squares on `log S` against `log n`,
which needs nothing beyond the standard library. `beta` is the discovery
exponent: near 1 the run finds edges about as fast as it executes them, near 0
it has saturated.

Heaps' law assumes no asymptote. An exponential saturation curve assumes a
finite one, and this data does not support reporting an asymptote.

`fit_tail()` restricts the fit to the last `coverage.fit_tail_fraction` of the
run's executions. A power law fitted over a whole run is dominated by the early
steep phase, where syzkaller is still working through the seeds, so a run that
climbed hard and then went flat still reports a healthy exponent. The cut is
made by executions, so a stretch where the box was panicking and doing little
work does not count as recent history.

The extrapolation is:

```
expected new edges = K * ((n + dn)^beta - n^beta)
```

where `dn` is `coverage.horizon_hours` multiplied by the run's measured
execution rate.

## Parameters

| Config key | Default | Effect |
|---|---|---|
| `coverage.plateau_new_edges` | 50 | Expected new edges below which the run is `plateaued` |
| `coverage.horizon_hours` | 24 | How far ahead the extrapolation runs. Matches `loop.campaign_hours`, the unit of spend the decision authorises |
| `coverage.model_min_r2` | 0.90 | Fit quality below which no extrapolation is reported and the verdict is `unknown` |
| `coverage.min_fit_samples` | 8 | Points needed inside the tail before extrapolating |
| `coverage.fit_tail_fraction` | 0.5 | Fraction of the run's executions fitted. 1.0 fits everything |
| `coverage.beta_tolerance` | 0.05 | Slack above `beta = 1` absorbing early sampling noise |
| `coverage.gpu_probe_timeout_sec` | 20 | Ceiling on `nvidia-smi` before the driver counts as wedged. Track K only |
| `coverage.surface_sample_min` | 60 | Minutes between surface samples. 0 measures the surface on every coverage sample |
| `coverage.surface_min_samples` | 5 | Surface samples needed before the second curve's shape is read. Minimum 2 |
| `coverage.unpack_timeout_sec` | 300 | Ceiling on one `syz-db unpack` of a run's corpus |
| `loop.plateau_window_min` | 240 | Trailing wall-clock window for the legacy fallback |
| `loop.plateau_min_growth` | 0.02 | Growth threshold for the legacy fallback |
| `loop.coverage_sample_min` | 10 | Sampling cadence, which sets how many points a run produces |

## Decision procedure

1. Reject fewer than 3 usable rows as `unknown`.
2. Build the accumulation curve. Reject an empty curve as `unknown`.
3. Compare the latest reported edge count against this run's high-water mark.
   A lower reading means the fuzzer is still replaying, and the verdict is
   `unknown`.
4. Cut the tail to the last `coverage.fit_tail_fraction` of executions, and
   measure the execution rate.
5. When the tail holds at least `coverage.min_fit_samples` points, carries an
   execution axis, and contains exactly one distinct edge value, return
   `plateaued`. A curve with no variance in `S` cannot be fitted.
6. When no execution rate is measurable, fall through to the legacy
   wall-clock window and mark the result a degraded measurement.
7. Fit `S = K n^beta` over the tail. Reject fewer than
   `coverage.min_fit_samples` fitted points, an `R2` below
   `coverage.model_min_r2`, or a `beta` outside
   `(0, 1 + coverage.beta_tolerance]`, each as `unknown`.
8. Extrapolate over `coverage.horizon_hours` at the measured rate. Return
   `growing` at or above `coverage.plateau_new_edges`, and `plateaued` below
   it.
9. Downgrade a `plateaued` verdict to `unknown` when any Track K sample in the
   window recorded a GPU state other than `ok`.

```mermaid
flowchart TB
  S["rows with an edge count"] --> N3{"at least 3 samples?"}
  N3 -->|no| U1["unknown: too few samples"]
  N3 -->|yes| ACC["accumulate:<br/>x = cumulative executions<br/>y = running max of edges"]
  ACC --> EMPTY{"any edge data?"}
  EMPTY -->|no| U2["unknown: no edge data"]
  EMPTY -->|yes| REPLAY{"latest reported count<br/>below this run's high-water mark?"}
  REPLAY -->|yes| U3["unknown: still replaying<br/>after a restart"]
  REPLAY -->|no| TAIL["fit_tail: the last<br/>fit_tail_fraction of executions"]
  TAIL --> FLAT{"no new edge across<br/>the whole tail?"}
  FLAT -->|yes| P1["plateaued: the clearest case"]
  FLAT -->|no| RATE{"an execution rate<br/>is measurable?"}
  RATE -->|no| LEG["legacy fallback:<br/>growth over a wall-clock window"]
  RATE -->|yes| FIT["fit S = K n^beta"]
  FIT --> PTS{"enough points<br/>for min_fit_samples?"}
  PTS -->|no| U4["unknown: too few for a fit"]
  PTS -->|yes| R2{"R2 &gt;= model_min_r2?"}
  R2 -->|no| U5["unknown: the curve does not<br/>fit the model"]
  R2 -->|yes| BETA{"0 &lt; beta &lt;= 1 + beta_tolerance?"}
  BETA -->|no| U6["unknown: not an<br/>accumulation curve"]
  BETA -->|yes| EXT["expected = K((n+dn)^beta - n^beta)"]
  EXT --> THR{"expected &gt;= plateau_new_edges?"}
  THR -->|yes| G["growing"]
  THR -->|no| P2["plateaued"]
  P1 --> GPU{"was the GPU healthy<br/>across the window?"}
  P2 --> GPU
  LEG --> GPU
  GPU -->|no| U7["unknown: a dead GPU flattens<br/>the curve the same way"]
  GPU -->|yes| PLAT["plateaued"]
```

A detail line accompanies every verdict:

```
41907 distinct edges after 3.41e+09 executions; beta 0.412, R2 0.987 over 68 samples. At 1.45e+08 exec/h another 24 h is expected to find ~1180 new edge(s), 2.8% more (plateau below 50)
```

The relative figure is reported alongside the absolute one. The threshold is a
judgement about what would justify another campaign of machine time, and 2.5%
of a run's coverage reads differently from 37%.

## Unknown verdicts

`unknown` is a verdict, and `round-decide` treats it as a stop, so a broken
sampler cannot authorise more spend.

| Case | Message | Cause |
|---|---|---|
| Too few samples | `only N usable sample(s); need >= 3` | The run is too short, or the sampler started late |
| No edge data | `no edge data in any sample` | The source never reported an edge count |
| Still replaying | `the fuzzer is still replaying its corpus after a restart` | The round ended before the fuzzer regained its own high-water mark. A flat curve here indicates recovery |
| Too few fitted points | `only N sample(s) usable for a discovery fit` | The tail holds fewer than `coverage.min_fit_samples` points |
| Model mismatch | `the discovery curve does not fit the model well enough to extrapolate from (R2 ...)` | A stuck sampler, a source change mid-run, or a genuine regime change. All three present identically and need different responses |
| Not an accumulation curve | `discovery exponent beta=... is outside (0, 1]` | No extrapolation from the series is meaningful |
| GPU gate | `the GPU was not healthy for N of M sample(s) in the window` | See below |

## The GPU gate

A GPU that has fallen off the bus does not stop the fuzzer. syz-manager keeps
executing, the sampler keeps appending rows, the edge count stops moving, and
an ungated test reports a plateau that the fuzzer never reached.

Every Track K sample records the GPU state alongside the counters. A
`plateaued` verdict is downgraded to `unknown` when any sample in the window
recorded a state other than `ok`:

```
..., but the GPU was not healthy for 12 of 24 sample(s) in the window (dead x12). A dead GPU flattens the curve the same way a real plateau does, so this is not reported as a plateau. Check `coverage_ctl.py gpu-health` and the run's Xid entries before deciding the round is done.
```

| Rule | Reason |
|---|---|
| The gate applies to `plateaued` only | Coverage cannot climb on a GPU that is not answering, so a `growing` verdict establishes that the probe result was transient |
| A row written before the GPU column existed counts as unhealthy | Such a row carries no evidence that the GPU was alive |
| Track U rows record `n/a` and are excluded | Those harnesses run in a container and never touch the GPU, so gating them would report a genuine Track U plateau as `unknown` |

## Legacy fallback

A source that reports no execution count still has to produce a verdict.
`_legacy_window_verdict()` measures growth across a trailing wall-clock window
of `loop.plateau_window_min` against `loop.plateau_min_growth`, on the
accumulation curve.

The result is reported as a degraded measurement. A wall-clock window cannot
distinguish a slow hour from a saturated one, which is the reason the model
path exists:

```
no execution counts recorded, so growth is measured over elapsed time with no measure of work done: distinct edges 41200 -> 41907 over 240 min = 1.716% growth (threshold 2.000%)
```

## Combining the tracks

```
python3 tools/coverage_ctl.py plateau --run-id r2-1
```

| Per-track verdicts | Combined |
|---|---|
| Any `growing` | `growing` |
| Some `plateaued`, none `growing` | `plateaued` |
| All `unknown`, or no track sampled | `unknown` |

A round is still learning while any track is still finding edges. Stopping
because Track K flattened while the container-toolkit harnesses were still
growing ends the campaign early. A track with no samples at all is ignored and
does not force `unknown`.

## Stated limits

| Limit | Consequence | Direction of the bias |
|---|---|---|
| No Good-Turing or Chao1 estimate | Those estimators need per-species frequency counts, and syz-manager's stats endpoint reports an aggregate edge count with nothing per-edge. No fraction-of-driver-covered figure is computed | None. The figure is absent |
| `max()` under-reports the union | A post-restart process can cover an edge the earlier one missed while its total is still lower, and that edge is not counted | Under-reports discovery, which ends a campaign early |
| Kernel-side reachable code only | GSP firmware is uninstrumented, so no coverage number describes it | None. `series` and `plateau` print the statement on every invocation |

## The surface curve

The `surface` column of each coverage sample holds how many of the 764
enumerated targets this run's own corpus names. `collect_surface(run_id)`
unpacks `artifacts/runs/<id>/workdir/corpus.db` through syz-db and matches
variant names against the inventories, which is a measurement syz-manager's
stats endpoint cannot supply: it holds no model of the 764 targets.

| Property | Value |
|---|---|
| Cadence | `coverage.surface_sample_min`, default 60 minutes, gated by `surface_due()` |
| Cadence memory | The CSV itself. The last row carrying a surface value is the last measurement, so the cadence survives a sampler restart and a reboot |
| Operator escape hatch | `--skip-surface` on `sample`, which the timer's Track U line passes |
| Track U | Refused. Those harnesses produce no syzlang programs, and a 0 would put an absence of evidence into the curve as a measurement |
| Failure | A missing syz-db, a `corpus.db` syz-manager is midway through rewriting, and an unpack failure all record an empty value, which `metric_rows` drops |
| Accumulation | Running maximum, because syzkaller minimises its corpus and a genuine dip must contribute zero |

`surface_growth(rows)` returns `growing`, `flat` or `unknown` and fits nothing.
Heaps' law is not transferred to this series for three reasons: an unbounded
power law fitted to a quantity bounded at 764 predicts more new targets than
remain, the dynamic range makes the `R2` gate close to arbitrary over a
400-to-410 series, and the question the stop rule asks the second curve is only
whether it moved, which is subtraction.

`coverage.surface_min_samples` is 5, higher than the edge curve's floor,
because the surface counter is quantised and a short tail sitting between two
steps is a common state.

The surface reading is applied after the GPU gate. A dead GPU does not flatten
the surface count the way it flattens the edge count, since programs still
execute and still enter the corpus, so a climbing surface curve is not evidence
that the card is alive.

A run started before the `surface` column existed gains no second curve.
`cmd_sample` appends under the header the file already carries and no
header-rewrite path exists, so such a run warns on every sample and reads
`surface_verdict=unknown`, which stops the loop on the plateau rule and never
on completion.

## The completion check

```
python3 tools/coverage_ctl.py completion [--run-id ID ...] [--corpus DIR] [--ledger PATH] [--top N]
```

Completion is the ledger identity `exercised + accounted-for = 764`, computed
as a union of the two sets. A target can be exercised in a later round after an
earlier one wrote a reason for it, and adding the counts would close the ledger
while targets remained.

The accounted-for set is the reasons that assert unreachability. Seven of the
eight accounting reasons do, and `deliberately-deferred` does not: it records
that a reachable target was put aside, so its rows are subtracted before the
union and reported on their own as `deferred`. A deferral does not close a
target and cannot fire the stop. See
[Closed vocabularies](/gspwn/reference/vocabularies/).

`completion_status` also requires every family in `surface_cov.FAMILIES` to
contribute at least one target. A truncated inventory would otherwise yield a
smaller denominator that a corpus can close, firing the stop over commands
nobody counted. It yields `unknown` instead.

| Exit | Verdict |
|---|---|
| 0 | `complete` |
| 3 | `incomplete` |
| 1 | `unknown` |

The output names the driver version, every corpus it read with its
modification time and program count, the ledger path, the three counts, and the
targets that are neither exercised nor accounted for. Each of those prints as a
worklist line carrying the variant in brackets, which is the handle
`pipeline_ctl.py surface-account` resolves:

```
- [surface] control NV0000 0x00000102 cliresCtrlCmdSystemGetCpuInfo  [NV_ESC_RM_CONTROL_cliresCtrlCmdSystemGetCpuInfo]
```

`completion` is its own subcommand and not a fourth state on `plateau`, so
`plateau` keeps its three verdicts and its exit map.

`round-end --from-run` computes the reading from the runs it names and records
it on the round, so no flag transcribes it.

## Reading a plateau against the surface

236 of the non-privileged control commands have their handler compiled out and
their parameter buffer marshalled across the RPC queue to GSP. A corpus
drifting onto those raises executions and moves no edge count, so the
accumulation curve flattens while the fuzzer is still issuing calls it has
never issued. The GSP subset is a structural ceiling in the edge signal, and an
edge count alone reads that ceiling and a plateau identically.

| Surface reading at a flat edge curve | Diagnosis | Next action |
|---|---|---|
| Still climbing | The round is still reaching commands it had not reached, whatever the edge count did | Continue |
| Flat, ledger open | The corpus is stuck. The fuzzer stopped finding edges while modelled targets remain unreached, which is a resource-chain problem | Model the targets `surface_cov.py gaps --stage model` names, or account for them |
| Flat, ledger closed | The grammar has reached the surface it declares and has stopped finding new code | Stop the loop |

See [surface_cov.py](/gspwn/architecture/components/surface-cov/).

## Verdict consumers

| Consumer | Use |
|---|---|
| `pipeline_ctl.py round-end --from-run` | Records the edge verdict and the completion reading on the round, as one write |
| `pipeline_ctl.py round-decide` | `plateaued` stops the loop when `loop.stop_on_plateau` is set. `unknown` always stops it. A `complete` surface verdict stops it non-overridably, checked ahead of the round cap and the budget |
| The `refine` sub-agent | The detail line's expected-new-edges figure goes into `gaps.md`, and the unaddressed targets go into the worklist or the ledger |
| The `eval` sub-agent | The series and the cross-round progression |

A `plateaued` verdict is a statement about the descriptions as much as about
the driver: this grammar has stopped reaching new code. It is the strongest
available argument for what to model next, and it does not establish that the
subsystem is covered.

## See also

- [Throughput against depth](/gspwn/guides/tuning-throughput-vs-depth/)
- [surface_cov.py](/gspwn/architecture/components/surface-cov/)
- [coverage_ctl.py](/gspwn/reference/cli/coverage-ctl/)
- [Loops](/gspwn/architecture/loops/)
- [Artifacts](/gspwn/reference/artifacts/)
- [Scope and oracle](/gspwn/architecture/scope-and-oracle/)
