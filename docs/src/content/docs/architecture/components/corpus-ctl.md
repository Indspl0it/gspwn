---
title: corpus_ctl.py
description: The persistent seed bank, and content-hash promotion.
---

Promotes programs from a finished run's corpus into `artifacts/seeds/`, the bank
that outlives rounds. The outer improvement loop requires persistent storage,
because syzkaller's `corpus.db` lives inside one run's workdir and is discarded
with it.

Promoted programs are named `promoted-<run-id>-<hash>.syz` and tracked in the
ledger `promoted.json` beside them.

## Responsibility

The module owns the seed bank and its ledger. It is the sole writer of
`artifacts/seeds/`.

| Invariant | Enforced by |
|---|---|
| The bank holds one copy of each distinct program | `prog_hash` over the normalised program text, with blank lines and comments removed |
| Repeated promotion across rounds converges | The same content hash is recognised on every later run |
| A file on disk counts as known even when the ledger does not mention it | `existing_hashes` reconciles the ledger against the `.syz` files present |
| A frozen bank is never written | `promote` refuses when `loop.promote_seeds` is false |
| A truncated promotion says so | `--limit` reports how many corpus entries were not considered |
| Provenance survives the loss of the ledger | The run id and hash are in every filename |

## Operations

| Subcommand | Purpose |
|---|---|
| `promote` | Add a run's corpus programs the bank does not already hold |
| `stats` | Report the bank's size and provenance |

## Callers

| Direction | Modules |
|---|---|
| Imports this module | `campaign_ctl.install_seeds` for `SYZ_DB` and `unpack_corpus` |
| This module imports | `pipeline_state.py`, `gspwn_config.py` |

## Failure modes

| Condition | Behaviour |
|---|---|
| `loop.promote_seeds` is false | `promote` refuses and exits 1; the `refine` sub-agent records the refusal in `gaps.md` |
| Configuration unreadable | Exits 1 with the configuration error |
| No `corpus.db` for the named run | Exits 1 naming the path searched |
| `syz-db` binary absent | Exits 1 naming the provision step that builds it |
| `syz-db unpack` fails | Exits 1 carrying the tool's error |
| Ledger unreadable | The bank is reconciled against the files present, so no program is promoted twice |
| Ledger entry whose file was deleted | Reported separately and counted toward no source |
| Run adds no new programs | Reported as a result, and the line is a direct input to the stop decision |

## Concurrency and durability

The ledger is written atomically through a temporary file, `fsync` and rename,
matching every other persistent write in the pipeline. No lock is taken:
`promote` runs once per finished run from the `refine` phase. Promotion is
idempotent because the content hash is recomputed from the program text on every
run, so re-running against the same corpus adds nothing.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never write a program the bank already has | Repeated promotion across rounds converges to a bounded set |
| Never work around the freeze | `loop.promote_seeds: false` exists so a round can be re-run from a known corpus |
| Never silently truncate | With `--limit`, the bank is a sample of the run and the note says how much was left out |
| Never let an unreadable ledger cause a double promotion | The bank is reconciled against the `.syz` files actually present |
| Never count a ledger entry whose file was deleted | Counting it would make the untracked figure wrong |

## Design notes

A promotion that adds nothing is reported as a result:

```
The run produced nothing the bank did not already have — that is the corpus-level signal that this round stopped learning.
```

`refine` is told to record that line in `gaps.md`.

`syz-db` is a hard prerequisite for both promotion and seed packing, so
`unpack_corpus` names the provision step that builds it when the binary is
missing.

## See also

- [Corpus and seeds](/gspwn/guides/corpus-and-seeds/)
