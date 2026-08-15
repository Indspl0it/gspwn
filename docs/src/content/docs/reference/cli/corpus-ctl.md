---
title: corpus_ctl.py
description: Promoting a finished run's corpus into the persistent seed bank.
---

Promotes programs from a finished run's corpus into `artifacts/seeds/`, the
bank that outlives rounds.

## Synopsis

```
python3 tools/corpus_ctl.py <promote|stats> [options]
```

Requires `syz-db` from the pinned syzkaller build at
`artifacts/src/syzkaller/bin/syz-db`. Root is never required.

## promote

Unpacks a run's `workdir/corpus.db` and adds its programs to the bank.

```
python3 tools/corpus_ctl.py promote --run-id r2-1 [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | Required | The run whose `workdir/corpus.db` is unpacked |
| `--seeds` | `DIR` | `artifacts/seeds` | Target bank |
| `--limit` | `N` | 0 | Cap programs added in this call. `0` means no cap |
| `--dry-run` | None | Off | Report what would be added and write nothing |

```
r2-1: 187 new program(s) added to artifacts/seeds, 3996 already known (corpus held 4183)
```

Promotion is additive and deduplicated by a content hash over the normalised
program text, with blank lines and comments removed. A program already in the
bank is never written twice, so repeated promotion across rounds converges.

Promoted files are named `promoted-<run-id>-<hash>.syz`.

| Condition | Result |
|---|---|
| `loop.promote_seeds` is false | Refused. The bank is frozen |
| `--limit` cut the promotion short | Reported, because the bank is then a partial sample of the run |
| The run's corpus held nothing new | Reported as a result |

```
loop.promote_seeds is false in config/campaign.yaml: the seed bank is frozen (e.g. to re-run a round from a known corpus), so promotion is refused. Set it to true to promote this run's corpus.
```

```
NOTE: stopped at --limit 50; 137 corpus entries were not considered. The bank is now a truncated sample of this run, not all of it.
```

```
The run produced nothing the bank did not already have — that is the corpus-level signal that this round stopped learning.
```

## stats

Prints the bank's size and its per-run breakdown.

```
python3 tools/corpus_ctl.py stats [--seeds DIR]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--seeds` | `DIR` | `artifacts/seeds` | The bank to read |

```
seed bank artifacts/seeds: 4370 program(s)
  r1-1                     4183
  r2-1                      175
  untracked                  12 (trace-derived or hand-added)
```

`untracked` is the count of `.syz` files the ledger does not know about: seeds
written by `trace2seed.py`, or added by hand. Ledger entries whose file has
since been deleted are reported separately and counted toward no source.

| Condition | Result |
|---|---|
| The bank directory does not exist | Exit 1 |

## The ledger

`artifacts/seeds/promoted.json` maps content hash to the file name and the run
it came from. It is written atomically through a temporary file and a rename.

An unreadable ledger is rebuilt from the `.syz` files present:

```
WARN: artifacts/seeds/promoted.json unreadable; rebuilding from the .syz files present
```

Files on disk that the ledger does not mention are still recognised as known
programs, so an unreadable ledger cannot cause the same program to be promoted
twice.

## Packing the bank into a campaign

`campaign_ctl.py install-k --seeds` packs the bank into a run's `corpus.db`
with `syz-db pack`, unpacking whatever the run already carried first so a
carried corpus is preserved.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | The bank directory is missing, or promotion was refused |

## Files

| Path | Contents |
|---|---|
| `artifacts/seeds/` | The persistent seed bank |
| `artifacts/seeds/promoted.json` | Content hash to file name and source run |
| `artifacts/runs/<run-id>/workdir/corpus.db` | The run corpus that `promote` unpacks |

## See also

- [Corpus and seeds](/gspwn/guides/corpus-and-seeds/)
</content>
</invoke>
