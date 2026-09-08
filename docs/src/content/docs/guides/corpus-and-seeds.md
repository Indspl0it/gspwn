---
title: Corpus and seeds
description: Corpus policy per run, the persistent seed bank, promotion and the freeze switch.
---

Two stores hold programs, and they have different lifetimes.

| Store | Path | Lifetime | Written by |
|---|---|---|---|
| Run corpus | `artifacts/runs/<run-id>/workdir/corpus.db` | Dies with the run | syz-manager, and `campaign_ctl.py install-k` at install time |
| Seed bank | `artifacts/seeds/` | Outlives rounds and campaigns | `trace2seed.py`, `corpus_ctl.py promote` |

## Corpus policy per run

`campaign_ctl.py install-k` applies the policy before the campaign starts.
`loop.corpus_policy` in `config/campaign.yaml` supplies the default when
`--corpus` is omitted.

| Policy | Effect | Refuses when |
|---|---|---|
| `carry` | copies the source run's `corpus.db` into the new run's workdir | `--from-run` is absent, or the source run has no `corpus.db` |
| `fresh` | starts from an empty corpus | the run id already has a `corpus.db` |

```
sudo python3 tools/campaign_ctl.py install-k --run-id r2-1 \
  --corpus carry --from-run r1-1
```

```
carried corpus from run r1-1 (4823104 bytes)
```

`fresh` against a run id that already has a `corpus.db` exits with a refusal,
because carrying an evolved corpus under a policy that says otherwise would
make the run measure something it does not claim to. Use a new run id.

## Packing seeds into the run corpus

```
sudo python3 tools/campaign_ctl.py install-k --run-id r2-1 --seeds artifacts/seeds
```

```
packed 12 seed program(s) from artifacts/seeds into artifacts/runs/r2-1/workdir/corpus.db (4183 carried program(s) preserved)
```

`--seeds` packs every `.syz` file in the directory into the run's `corpus.db`
with `syz-db pack`. A carried corpus is unpacked first and re-packed alongside
the seeds, so packing preserves it. The count in parentheses gives the number
of carried programs that survived.

:::caution[corpus.db is the only corpus input]
syz-manager reads `workdir/corpus.db` and nothing else. Programs placed in a
directory beside the database are never loaded: the run starts empty, and a
seeded run becomes indistinguishable from an unseeded one.
:::

A seed directory holding no `.syz` file leaves the run unseeded, and the
install says so and continues:

```
WARN: --seeds artifacts/seeds holds no .syz files — this run is NOT seeded and starts from an empty corpus.
```

A `syz-db pack` failure exits the install with the packer's own error.

## Starting a run with no inherited programs

Omit `--seeds` and pass `--corpus fresh`. Each flag governs one store, so
either one alone still leaves programs in the corpus. `--corpus fresh` with
`--seeds` starts empty and then packs the whole bank in. Omitting `--seeds`
under the default `carry` policy copies the source run's evolved corpus.

```
sudo python3 tools/campaign_ctl.py install-k --run-id r3-1 --corpus fresh
```

```
fresh corpus for run r3-1
```

## Promoting a corpus into the bank

At the end of a round, `refine` promotes the run's corpus into the bank.

1. Add the run's new programs.

   ```
   python3 tools/corpus_ctl.py promote --run-id r2-1
   ```

   ```
   r2-1: 187 new program(s) added to artifacts/seeds, 3996 already known (corpus held 4183)
   ```

   The three figures reconcile: 187 added plus 3996 already known is the 4183
   the corpus held. `--dry-run` prints the same line with `would be added to`
   and writes nothing. `--seeds DIR` promotes into a bank other than
   `artifacts/seeds`.

   A missing `corpus.db` for the run exits 1 and names the path it looked at.
   A missing `syz-db` binary exits 1 and points back at the syzkaller build.

2. Confirm the bank grew by what the promotion claimed.

   ```
   python3 tools/corpus_ctl.py stats
   ```

   ```
   seed bank artifacts/seeds: 4370 program(s)
     r1-1                     4183
     r2-1                      175
     untracked                  12 (trace-derived or hand-added)
   ```

   `stats` exits 1 when the path holds no seed bank at all.

Promotion is additive and deduplicated by a content hash over the normalised
program text, with comments and blank lines removed. Duplicate detection reads
the promotion ledger and the `.syz` files on disk together, so a program added
by hand is recognised without a ledger entry. A program already in the bank is
never written twice, and repeated promotion across rounds converges on a fixed
set.

Promoted files are named `promoted-<run-id>-<hash>.syz`, and
`artifacts/seeds/promoted.json` records which run each came from.

`--limit N` caps how many programs are added in one call, and says what that
leaves out:

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

With the bank frozen, `promote` exits without writing and leaves the setting in
force:

```
loop.promote_seeds is false in config/campaign.yaml: the seed bank is frozen (e.g. to re-run a round from a known corpus), so promotion is refused. Set it to true to promote this run's corpus.
```

The `refine` sub-agent records the refusal in `gaps.md`.

## Reading the bank's provenance

`stats` groups the bank by the source recorded for each program.

| Row | Meaning |
|---|---|
| a run id | programs `promote` added from that run's corpus |
| `untracked` | `.syz` files with no ledger entry: seeds written by `trace2seed.py`, or added by hand |
| the trailing ledger line | ledger entries whose file was since deleted, counted toward no source |

## Seed sources

Three sources fill the bank, and each covers a hole the others cannot.

| Source | Command | Supplies |
|---|---|---|
| CUDA workload traces | `trace2seed.py convert` | a real file-descriptor lifecycle and the order a workload issues escapes in |
| The allocation graph | `trace2seed.py chains` | the control command identity a trace cannot carry |
| Previous rounds' corpora | `corpus_ctl.py promote` | whatever the fuzzer evolved that reached new code |

`NVOS54_PARAMETERS.cmd` selects one of 531 control commands and the field is
inside the parameter struct, which `strace` does not decode, so no trace names
a control command. `chains` closes on the whole 531:

```
531 control command(s) accounted for: 529 emitted, 0 dropped before emission, 2 with no chain
```

The 2 have no allocation chain to reach them. Both are owned by
`MmuFaultBuffer` and `NvDispApi`, whose every external class carries
`RS_FLAGS_ALLOC_PRIVILEGED`, and nothing unprivileged reaches either. The 15
commands owned by `Memory` and `ProfilerBase` are reached through the chain of
a class deriving from them, because a handler compiled into a base class serves
an object allocated as any of its subclasses.

Whether a prologue allocates on real hardware is unverified: no GPU was
involved, no chain was allocated, and no emitted program has been executed or
put through `prog.Deserialize`. See
[Seeds from traces](/gspwn/guides/generating-seeds-from-traces/).

`convert` writes `seed-NNNN.syz` and `chains` writes `chain-<class>-NN.syz`, so
the two never overwrite each other in one directory. `chains` writes
deterministic names and overwrites its own output, so re-running it does not
grow the bank. A `chain-*.syz` file the current run did not write is reported
and left in place, because it belongs to an older driver:

```
2 chain program(s) in artifacts/seeds were not written by this run and are left in place: chain-gt200_debugger-00.syz, chain-nv04_display_common-00.syz. Delete them if they came from an older driver.
```

## Comparing runs

```
python3 tools/coverage_ctl.py compare --run-id r2-1 --against r1-1
```

```
r2-1                 edges  18422 ->  41907  (+23485) over 987.4 h
r1-1                 edges  12004 ->  31220  (+19216) over 991.6 h
Comparing runs is only meaningful when each had its own workdir and corpus policy. See campaign_ctl.py --corpus.
```

Two runs that shared a workdir shared an evolved corpus, so the comparison
describes that shared corpus and carries no information about the change under
test.

## See also

- [Seeds from traces](/gspwn/guides/generating-seeds-from-traces/)
- [corpus_ctl.py reference](/gspwn/architecture/components/corpus-ctl/)
