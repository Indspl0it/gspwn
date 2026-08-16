---
title: Corpus and seeds
description: Corpus policy per run, the persistent seed bank, promotion and the freeze switch.
---

Two stores hold programs, and they have different lifetimes.

| Store | Path | Lifetime |
|---|---|---|
| Run corpus | `artifacts/runs/<run-id>/workdir/corpus.db` | Dies with the run |
| Seed bank | `artifacts/seeds/` | Outlives rounds and campaigns |

syzkaller's corpus lives inside one run's workdir. Later rounds start from the
seed bank, which persists across the outer loop.

## Corpus policy per run

```
sudo python3 tools/campaign_ctl.py install-k --run-id r2-1 \
  --corpus carry --from-run r1-1
```

`carry` copies the source run's `corpus.db` into the new run's workdir:

```
carried corpus from run r1-1 (4823104 bytes)
```

`fresh` starts empty. `install-k` refuses `--corpus fresh` against a run id
that already has a `corpus.db`, because that would silently reuse an evolved
corpus under a policy that says otherwise.

The default comes from `loop.corpus_policy`.

## Packing seeds into the run corpus

```
sudo python3 tools/campaign_ctl.py install-k --run-id r2-1 --seeds artifacts/seeds
```

```
packed 12 seed program(s) from artifacts/seeds into artifacts/runs/r2-1/workdir/corpus.db (4183 carried program(s) preserved)
```

`--seeds` packs the bank into the run's `corpus.db` with `syz-db pack`. The
carried corpus is unpacked first and re-packed alongside the seeds, so packing
does not discard it.

:::caution[corpus.db is the only corpus input]
syz-manager reads `workdir/corpus.db` and nothing else. Programs placed in a
directory beside the database are never loaded: the run starts empty, and a
seeded run becomes indistinguishable from an unseeded one.
:::

An empty seed directory is reported:

```
WARN: --seeds artifacts/seeds holds no .syz files — this run is NOT seeded and starts from an empty corpus.
```

## Starting a run with no inherited programs

Omit `--seeds` **and** pass `--corpus fresh`. Either one alone still inherits a
corpus.

```
sudo python3 tools/campaign_ctl.py install-k --run-id r3-1 --corpus fresh
```

## Promoting a corpus into the bank

At the end of a round, `refine` promotes the run's corpus:

```
python3 tools/corpus_ctl.py promote --run-id r2-1
```

```
r2-1: 187 new program(s) added to artifacts/seeds, 3996 already known (corpus held 4183)
```

Promotion is additive and deduplicated by content hash over the normalised
program text, with comments and blank lines removed. A program already in the
bank is never written twice, so repeated promotion across rounds converges on a
fixed set.

Promoted files are named `promoted-<run-id>-<hash>.syz`, and
`artifacts/seeds/promoted.json` records which run each came from.

`--dry-run` reports what would be added and writes nothing. `--limit N` caps
how many are added in one call, and says what that leaves out:

```
NOTE: stopped at --limit 50; 137 corpus entries were not considered. The bank is now a truncated sample of this run, not all of it.
```

A promotion that adds nothing is itself a recorded result:

```
The run produced nothing the bank did not already have — that is the corpus-level signal that this round stopped learning.
```

## Freezing the bank

```yaml
loop:
  promote_seeds: false
```

With the bank frozen, `promote` refuses and leaves the setting in force:

```
loop.promote_seeds is false in config/campaign.yaml: the seed bank is frozen (e.g. to re-run a round from a known corpus), so promotion is refused. Set it to true to promote this run's corpus.
```

The `refine` sub-agent records the refusal in `gaps.md`.

## Inspecting the bank

```
python3 tools/corpus_ctl.py stats
```

```
seed bank artifacts/seeds: 4370 program(s)
  r1-1                     4183
  r2-1                      175
  untracked                  12 (trace-derived or hand-added)
```

`untracked` is the count of `.syz` files the promotion ledger does not know
about: seeds written by `trace2seed.py`, or added by hand. Ledger entries whose
file was since deleted are reported separately and not counted toward any
source.

## Seed sources

| Source | Tool | Covers |
|---|---|---|
| Real CUDA workload traces | `tools/trace2seed.py` | Valid object-allocation chains random generation struggles to produce |
| Previous rounds' corpora | `tools/corpus_ctl.py promote` | Whatever the fuzzer evolved that reached new code |

Tracing is the only way to reach a surface classified
`unreachable-by-construction` by the `refine` phase: code that needs a real
object or handle chain syzkaller will not build on its own. See
[Seeds from traces](/gspwn/guides/generating-seeds-from-traces/).

## Comparing runs

```
python3 tools/coverage_ctl.py compare --run-id r2-1 --against r1-1
```

```
r2-1                 edges  18422 ->  41907  (+23485) over 23.5 h
r1-1                 edges  12004 ->  31220  (+19216) over 23.8 h
Comparing runs is only meaningful when each had its own workdir and corpus policy — see campaign_ctl.py --corpus.
```

Two runs that shared a workdir shared an evolved corpus, so the comparison
describes that shared corpus and carries no information about the change under
test.

## See also

- [Seeds from traces](/gspwn/guides/generating-seeds-from-traces/)
- [corpus_ctl.py reference](/gspwn/reference/cli/corpus-ctl/)
