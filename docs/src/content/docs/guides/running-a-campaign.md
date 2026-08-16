---
title: Running a campaign
description: Run ids, corpus policy, installation, the smoke window and waiting out the deadline.
---

A campaign is one fuzzing run under systemd, bounded by a deadline written to
disk. `tools/campaign_ctl.py` installs, starts, stops and enforces it. Steps 1
to 8 run in order for every campaign.

## 1. Choose a run id

One run id of the form `r<round>-<n>` covers both tracks. `r2-1` is the first
campaign of round 2.

```
python3 tools/campaign_ctl.py gen-config --run-id r2-1
```

Track U data lives under `artifacts/runs/<id>/u/`, and the coverage sampler and
the deadline timer key on that same id. Per-track ids such as `r2-k1` and
`r2-u1` leave Track U unsampled and break the round accounting.

Never reuse a run id, and never point two campaigns at one workdir. Runs
sharing a workdir share an evolved corpus, so neither run's coverage numbers
describe what that run did.

## 2. Generate the syz-manager configuration

```
python3 tools/campaign_ctl.py gen-config --run-id r2-1
```

```
wrote artifacts/runs/r2-1/syz-manager.cfg (workdir artifacts/runs/r2-1/workdir)
```

The file is derived from `track_k` in `config/campaign.yaml`: `http`,
`sandbox`, `procs` and `enabled_syscalls`, plus the paths of the kernel object
tree and the syzkaller build. syz-manager validates it at startup and exits with
an error on a bad field, so a version mismatch surfaces at campaign start.

`install-k` calls `gen-config` itself, so a separate call is only needed to
inspect the result first.

## 3. Pick the corpus policy

| Policy | Effect |
|---|---|
| `carry` | Copy a previous run's `corpus.db` into this run's workdir |
| `fresh` | Start from an empty corpus |

The default comes from `loop.corpus_policy`. Pass `--corpus` to override it for
one run.

```
sudo python3 tools/campaign_ctl.py install-k --run-id r2-1 \
  --corpus carry --from-run r1-1 --seeds artifacts/seeds
```

`--corpus carry` requires `--from-run`. `--seeds` packs the persistent seed
bank into the run's `corpus.db` with `syz-db pack`, merging whatever was
carried:

```
carried corpus from run r1-1 (4823104 bytes)
packed 12 seed program(s) from artifacts/seeds into artifacts/runs/r2-1/workdir/corpus.db (4183 carried program(s) preserved)
```

:::caution[A clean start requires both flags]
Omit `--seeds` **and** pass `--corpus fresh`. Either one alone still inherits a
corpus. `install-k` refuses `--corpus fresh` against a run id that already has
a `corpus.db`, and directs the operator to a new run id.
:::

Seeds must be packed into `workdir/corpus.db`, because that database is
syz-manager's only corpus input. Programs placed in a directory beside it are
never loaded, and a seeded run then becomes indistinguishable from an unseeded
one.

## 4. Install both tracks

```
sudo python3 tools/campaign_ctl.py install-k --run-id r2-1 --seeds artifacts/seeds
sudo python3 tools/campaign_ctl.py install-u --run-id r2-1
```

Each install does four things before writing a unit:

1. Checks the run-hour budget and refuses a campaign the cap cannot cover.
2. Refuses while another run's campaign is still live.
3. Writes the deadline file `artifacts/runs/<id>/deadline` holding an absolute
   epoch second.
4. Installs and enables `gspwn-deadline@<run-id>.timer`.

```
campaign window: 24 h (stops at epoch 1786000000, enforced by gspwn-deadline@r2-1.timer); budget 23.5 of 216 run-hours spent before this campaign
installed gspwn-k.service for run r2-1 (MemoryMax=12G)
```

`--hours` overrides `loop.campaign_hours` for one campaign.

## Replacing a live campaign

The campaign units are single global names, `gspwn-k` and `gspwn-u`. Installing
run B over a live run A would repoint them while A keeps fuzzing, with A's
deadline enforcement gone.

```
sudo python3 tools/campaign_ctl.py install-k --run-id r2-2 --replace
```

`--replace` stops and disables the old units and retires the old run's deadline
timer before installing:

```
--replace: stopped and disabled gspwn-k (run r2-1)
--replace: retired deadline timer for run r2-1
```

Reinstalling the same run id needs no flag. Without `--replace`, an overlapping
install exits and names what is still live.

## 5. Start the units and the sampler

```
sudo python3 tools/campaign_ctl.py start k
sudo python3 tools/campaign_ctl.py start u
sudo python3 tools/coverage_ctl.py install-timer --run-id r2-1
```

The sampler is one timer covering both tracks, at
`loop.coverage_sample_min` intervals. It runs as a systemd timer so that
sampling outlives the agent session and survives panics.

Confirm the first sample of each track is real, with `sudo`, since the sampler
runs as root and owns the CSV:

```
sudo python3 tools/coverage_ctl.py sample --run-id r2-1
sudo python3 tools/coverage_ctl.py sample --run-id r2-1 --track u
```

```
artifacts/runs/r2-1/coverage.csv edges=18422 corpus=512 crashes=0 (source: json:/stats?format=json, gpu: ok)
```

A `source: unreachable` sample means the campaign records nothing. For Track K,
fix `track_k.http` or the stats endpoint for the pinned syzkaller version. For
Track U, confirm `run_all.sh` writes each harness's output under
`artifacts/runs/<id>/u/<harness>/`.

## 6. Register the run

```
python3 tools/pipeline_ctl.py round-add-run --run-id r2-1
```

```
round 2 now has 1 run(s); added r2-1
```

Installing a campaign already registers the run id, which lets the
sampler accept it. `round-add-run` also attaches it to the current
round, which `round-end` measures and bills.

## 7. Check the smoke window

`track_k.smoke_window_minutes` bounds the early-abort check. Coverage must
increase within it.

```
python3 tools/campaign_ctl.py status --run-id r2-1
python3 tools/coverage_ctl.py series --run-id r2-1
```

Flat coverage across the whole smoke window is a failed gate. Before treating
it as a descriptions problem, check the card, because a GPU that has fallen off
the bus produces an identical curve:

```
python3 tools/coverage_ctl.py gpu-health
```

## 8. Wait out the campaign

```
python3 tools/campaign_ctl.py wait --run-id r2-1
```

It blocks until the window elapses, printing a heartbeat every
`loop.deadline_check_min` minutes, and re-reads the deadline on every pass so a
`--replace` install is followed correctly. On return it checks whether the
units are still active and enforces the deadline itself if the timer did not.

`--check` answers without blocking: exit 0 if the window has elapsed, 1 if the
campaign is still inside it.

```
python3 tools/campaign_ctl.py wait --run-id r2-1 --check
```

## Stopping a campaign early

```
sudo python3 tools/campaign_ctl.py stop k
```

A manual stop bills the run's measured hours to the spend ledger, the same way
the deadline path does. Round accounting reads the actual elapsed time, so an
early stop shortens the round's measured window. Stop early only on a failed
gate.

## See also

- [Corpus and seeds](/gspwn/guides/corpus-and-seeds/) covers the seed bank.
- [Long-running campaigns](/gspwn/guides/long-running-campaigns/) covers
  panics, reboots and resumption.
- [campaign_ctl.py reference](/gspwn/reference/cli/campaign-ctl/) lists every
  flag.
