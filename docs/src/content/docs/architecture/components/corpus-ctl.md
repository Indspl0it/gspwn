---
title: corpus_ctl.py
description: The persistent seed bank, and content-hash promotion.
---

Promotes programs from a finished run's corpus into `artifacts/seeds/`, the bank
that outlives rounds. The outer improvement loop requires persistent storage,
because syzkaller's `corpus.db` belongs to one run's workdir and is discarded
with it.

Promoted programs are named `promoted-<run-id>-<hash>.syz` and tracked in the
ledger `promoted.json` beside them. The hash is the first 16 hex characters of
the SHA-1 of the normalised program text.

## Responsibility

The module owns the seed bank's ledger and the promoted programs in it. The
`seeds` phase writes `chain-*.syz`, `seed-*.syz` and `trace.txt` into the same
directory through `trace2seed.py`, and `stats` reports those as untracked.

| Invariant | Enforced by |
|---|---|
| The bank holds one copy of each distinct program | `prog_hash` over the normalised program text, with blank lines and comments removed and each remaining line stripped |
| Repeated promotion across rounds converges | The same content hash is recognised on every later run |
| A file on disk counts as known even when the ledger does not mention it | `existing_hashes` reconciles the ledger against the `.syz` files present, recording each as `pre-existing` |
| A frozen bank is never written | `promote` refuses when `loop.promote_seeds` is false |
| A truncated promotion says so | `--limit` reports how many corpus entries were not considered |
| Provenance survives the loss of the ledger | The run id and hash are in every filename |

## Subcommands

| Subcommand | Arguments | Purpose |
|---|---|---|
| `promote` | `--run-id`, `--seeds`, `--limit`, `--dry-run` | Add the run's corpus programs the bank does not already hold |
| `stats` | `--seeds` | Report the bank's size and provenance |

| Flag | Default | Effect |
|---|---|---|
| `--run-id` | required | Names the run whose `artifacts/runs/<run-id>/workdir/corpus.db` is unpacked |
| `--seeds` | `artifacts/seeds` | The bank directory to read and write |
| `--limit` | `0` | Cap on programs added by this call. `0` is no cap |
| `--dry-run` | off | Counts and reports without copying a file or saving the ledger |

`--dry-run` still applies the content hash within the call, so a corpus holding
the same program twice reports one addition either way.

## Callers

`campaign_ctl.install_seeds` imports this module for `SYZ_DB` and
`unpack_corpus`. This module imports `pipeline_state.py` and
`gspwn_config.py`. The `refine` sub-agent runs `promote`, and the `seeds`
sub-agent runs `stats` before generating more programs.

## Exit codes

| Code | Conditions |
|---|---|
| 0 | `promote` completed, or `stats` found a bank |
| 1 | Every condition below that exits, and `stats` against a path that is not a directory |

## Failure modes

Nine conditions are handled. Six exit, and three resolve without stopping the
command.

| Condition | Behaviour |
|---|---|
| `loop.promote_seeds` is false | `promote` refuses and exits; the `refine` sub-agent records the refusal in `gaps.md` |
| Configuration unreadable | Exits with the configuration error |
| No `corpus.db` for the named run | Exits naming the path searched |
| `syz-db` binary absent | Exits naming the provision step that builds it, step 6 |
| `syz-db unpack` fails | Exits carrying the tool's error |
| `stats` given a path that is not a directory | Prints `no seed bank at <path>` and exits 1 |
| Ledger unreadable | Warns, and the bank is reconciled against the files present, so no program is promoted twice |
| A `.syz` file in the bank cannot be opened | Skipped by `existing_hashes`, so its hash counts as unknown |
| Ledger entry whose file was deleted | `stats` counts it toward no source and reports the total separately |

A promotion that adds nothing is a result, and the line reporting it is a direct
input to the stop decision.

## Concurrency and durability

The ledger is written atomically through a temporary file, `fsync` and rename,
matching every other persistent write in the pipeline. No lock is taken:
`promote` runs once per finished run from the `refine` phase. Promotion is
idempotent because the content hash is recomputed from the program text on every
run, so re-running against the same corpus adds nothing.

## Prohibited behaviour

Five rules bound the module.

- Never write a program the bank already has. Repeated promotion across rounds
  converges to a bounded set.
- Never work around the freeze. `loop.promote_seeds: false` exists so a round
  can be re-run from a known corpus.
- Never truncate in silence. With `--limit`, the bank is a sample of the run and
  the note gives the count left out, the corpus size minus the limit minus the
  programs already known.
- Never let an unreadable ledger cause a double promotion. The bank is
  reconciled against the `.syz` files actually present.
- Never count a ledger entry whose file was deleted. Counting it would make the
  untracked figure wrong.

## Design notes

A promotion that adds nothing prints:

```
The run produced nothing the bank did not already have — that is the corpus-level signal that this round stopped learning.
```

`refine` is told to record that line in `gaps.md`.

`syz-db` is a hard prerequisite for both promotion and seed packing, so
`unpack_corpus` names the provision step that builds it when the binary is
missing. `campaign_ctl` calls the same function, so both paths fail with the
same message.

## See also

- [Corpus and seeds](/gspwn/guides/corpus-and-seeds/)
