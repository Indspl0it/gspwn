---
title: Throughput against depth
description: Which knobs change how fast a campaign runs, and which change what it concludes.
---

`config/campaign.yaml` carries two kinds of value. One kind changes how much
work a campaign gets through. The other changes what the campaign concludes
from identical work.

## Knobs that change throughput

The verdict rules are untouched, so a curve measured under a new value is still
comparable in kind to an old one, though not in magnitude.

| Key | Effect | Cost |
|---|---|---|
| `track_k.procs` | Raising it adds parallel executor processes and executions per hour | More RAM held by the campaign |
| `track_k.memory_max` | Raising it raises the systemd `MemoryMax` on the syz-manager unit and reduces out-of-memory kills | Less headroom for everything else on the machine |
| `track_u.memory_max` | The same for the Track U container | The same |
| `loop.campaign_hours` | Raising it lengthens each campaign and adds executions per round | Fewer rounds inside the same budget |
| `loop.corpus_policy` | `carry` starts each round from the previous round's corpus | `fresh` starts empty and re-derives the basics every round |
| `loop.promote_seeds` | `true` accumulates a seed bank across rounds | `false` freezes the bank, and every round starts from the same programs |
| `loop.coverage_sample_min` | Raising it samples less often and lowers sampling overhead | Every curve is coarser and the plateau test has fewer points |

`track_k.procs` defaults to 2 and `track_k.memory_max` to `12G`, sized against
a 32 GB budget. A syz-manager killed by the cgroup limit restarts, and the
restart shows in the coverage curve as a counter reset the accumulation model
then has to work around.

## Knobs that change conclusions

Each of these sets a threshold, a window or an identity that a verdict rests
on. Two runs measured under different values answer different questions, so
record the value in force beside any figure taken from them.

| Key | Effect |
|---|---|
| `coverage.plateau_new_edges` | How many expected new edges justify another campaign |
| `coverage.horizon_hours` | How far ahead the extrapolation reaches |
| `coverage.model_min_r2` | The fit quality below which no verdict is reported at all |
| `coverage.min_fit_samples` | How many points are needed before extrapolating |
| `coverage.fit_tail_fraction` | Which part of the run the fit describes |
| `coverage.beta_tolerance` | When a series stops counting as an accumulation curve |
| `poc.reliable_threshold` | The boundary between `reliable` and `flaky` |
| `poc.repro_timeout_sec` | When a run counts as a hang |
| `triage.stack_hash_frames` | Whether two reports are the same bug |
| `triage.signature_frames` | Whether a reproduction is a hit for this crash |
| `triage.frameless_signature_lines` | The identity of a report with no stack |
| `triage.frameless_signature_chars` | The same |
| `loop.stop_on_plateau` | Whether a `plateaued` verdict ends the loop at all |
| `coverage.gpu_probe_timeout_sec` | Whether a hung GPU is recorded as hung. `plateau` refuses a verdict on that record |
| `coverage.surface_min_samples` | How many surface samples the second curve's shape is read from |
| `coverage.unpack_timeout_sec` | Whether a large corpus reports a surface at all. Too low reads as `surface_verdict=unknown` and blocks the completion stop |

`coverage.surface_sample_min` belongs to both lists. Raising it lowers the cost
of each coverage sample and gives the surface curve fewer points to be read
from.

## Coverage sampling interval

`loop.coverage_sample_min` appears in both lists, and it interacts with the
plateau test.

The validator refuses `loop.plateau_window_min` under three sampling intervals:

```
loop.plateau_window_min (20) is under 3 sampling intervals of 10 min — the plateau test needs >= 3 samples in the window and would always report 'unknown', which stops the loop
```

`coverage.min_fit_samples` sets a second floor. At the default of 8 samples,
and with `coverage.fit_tail_fraction` at 0.5, the fit needs at least eight
samples inside the last half of the run's executions before it will extrapolate
at all. A long sampling interval on a short campaign produces `unknown`, which
stops the loop.

## Fit tail fraction

`coverage.fit_tail_fraction` is the share of the run's **executions** the fit
covers. Sample count does not enter the calculation.

At `1.0` the fit covers the whole run. A power law fitted over a whole run is
dominated by the early steep phase, where syzkaller is still working through
its seeds, so a run that rose steeply and then flattened still reports a high
discovery exponent.

At `0.5`, the default, the fit describes the regime the fuzzer is in now.
Cutting by executions keeps a stretch where the machine was panicking and doing
little work out of the recent history.

## Extrapolation horizon

`coverage.horizon_hours` should match `loop.campaign_hours`, because the
decision the verdict authorises is another campaign of that length.
`gspwn_config.py` prints a note when they differ:

```
  note: horizon 48 h differs from loop.campaign_hours 1000 h, so the verdict answers a different question than the one the next campaign asks
```

## Dedup depth

`triage.stack_hash_frames` fails in both directions. Fewer frames merge
distinct bugs that share a common caller, and more frames split one bug whose
stack varies by an inlined frame.

`triage.frameless_signature_lines` and `triage.frameless_signature_chars`
govern the identity of a report with no usable stack at all. A narrow value
registers one recurring panic as many bugs and fills the flagged queue with
them. A wide value picks up detail that varies per occurrence.

:::danger[Change dedup depth between campaigns, never during one]
Already registered hashes are not recomputed. Across a mid-campaign change one
bug can register twice and two bugs can merge into one that never reaches
`rca`. The settings in force at the first registration are stamped into the
state file, and `validate` reports the drift:

```
PROBLEM: triage.stack_hash_frames is 5 now but the registry's hashes were built with 3. Hashes are not recomputed, so across this change one bug can register twice and two bugs can merge into one that never reaches rca. Restore it for the rest of this campaign, or start a fresh registry
```
:::

## Reproduction threshold

`poc.reliable_threshold` is the threshold a disclosure package is built on. At
the default of 0.8, a crash reproducing 8 times in 10 counted runs is
`reliable` and one reproducing 7 times is `flaky`.

Both are reportable, and the label travels into the report. Raising the
threshold moves findings from `reliable` to `flaky` without changing anything
about the bugs.

`poc.default_runs` changes the denominator and leaves the threshold fixed. A
rate measured over 10 runs and a rate measured over 50 are both recorded with
their counted-run count beside them, so a short denominator stays visible.

## Comparing two configurations

Coverage numbers are comparable only across runs that each had their own
workdir and corpus policy:

```
python3 tools/coverage_ctl.py compare --run-id r2-1 --against r1-1
```

It prints one line per run carrying the first edge count, the last, the
difference and the span in hours, then the caveat that governs the reading:

```
Comparing runs is only meaningful when each had its own workdir and corpus policy. See campaign_ctl.py --corpus.
```

A run with no edge samples prints `no edge samples` in place of its line.
`--track` selects the track and defaults to `k`.

See [Corpus and seeds](/gspwn/guides/corpus-and-seeds/#comparing-runs).

## See also

- [Configuration keys](/gspwn/reference/configuration/) lists every value with
  its accepted range.
- [Coverage and plateau](/gspwn/architecture/coverage-and-plateau/) derives the
  verdict.
- [Crash identity](/gspwn/architecture/crash-identity/) derives the dedup keys.
