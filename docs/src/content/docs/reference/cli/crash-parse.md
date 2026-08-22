---
title: crash_parse.py
description: Scanning crash sources into the deduplicated registry.
---

Harvests crashes from both tracks and deduplicates them into
`state/pipeline.json`.

## Synopsis

```
python3 tools/crash_parse.py [options]
```

No subcommands. One invocation scans whichever sources its flags name, inside a
single locked read-modify-write on the state file. Root is never required.

## Options

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--run-id` | `ID` | The last run registered in the current round | Scan `artifacts/runs/<id>/workdir` |
| `--syz-workdir` | `PATH` | None | An explicit workdir path, overriding `--run-id` |
| `--track-u-dir` | `PATH` | `artifacts/u-crashes` | Track U crash directory |
| `--dmesg` | `PATH` | None | A kernel log file to scan |

Always pass `--run-id`. The default is wrong in a round with several campaigns,
and the tool warns only when no run is registered at all.

## Title and stack hash per source

| Source | Title | Stack hash |
|---|---|---|
| syzkaller workdir | The crash directory's `description` file | The `report` file's top frames, and the `log` file where no report exists |
| Track U crash directory | The input's own sanitizer signature, else the signature in its `.sanlog` replay report | The same text's top frames |
| Kernel log, NVRM lines | `NVRM ` plus the normalised Xid text | SHA-1 of that text |
| Kernel log, report blocks | The report-start line | The block's top frames, or the frameless signature |

## Track U pairing

The Track U scan walks four levels below the crash root, which covers
`<harness>/<input>`, `<harness>/crashes/<input>` and
`<harness>/default/crashes/<input>`. `README` and `README.txt` are excluded, so
neither produces a warning.

`harnesses/replay_crashes.sh` replays each input under its harness
and writes the sanitizer output to `<input>.sanlog`. Registration reads that
report and records the input path.

| File | Registered as | Reason |
|---|---|---|
| Carries a sanitizer signature itself | Itself | A hand-copied sanitizer log |
| No signature, `.sanlog` sibling with one | The input path, title and frames from the report | The normal case |
| No signature, `.sanlog` sibling without one | Nothing, warned | The input did not crash this build |
| No signature, no sibling | Nothing, warned, naming the replay script | Not yet replayed |
| A `.sanlog` whose input is gone | Itself | Losing the finding is worse than a path `verify` cannot replay |

```
WARN: artifacts/u-crashes/fuzz_dsl_evaluate/id:000000,sig:06,src:000000 is a fuzzer crash input and no .sanlog report sits beside it — skipped, not registered. Replay it with harnesses/replay_crashes.sh, which run_all.sh runs at harvest.
```

The summary warning for a populated directory that registered nothing breaks
the files down into the ones with no replay report and the ones that were
replayed and did not crash. It no longer advises checking that the harnesses
were built with a sanitizer: `harnesses/common/build_common.sh`
compiles every harness `-fsanitize=address,undefined` in both build modes, so
that was never the cause.

## Output lines

```
NEW crash-0001 KASAN: use-after-free in uvm_va_range_destroy
NEW crash-0002 NVRM Xid 13 [noise]
DUP KASAN: use-after-free in uvm_va_range_destroy -> crash-0001 (registered crash-0007 as duplicate; sources linked)
FLAG crash-0008 Kernel panic - not syncing: Fatal exception (same title as crash-0003, different stack) — decide with: pipeline_ctl.py crash-set crash-0008 --duplicate-of crash-0003 | --status unique
registry now holds 8 crashes
1 flagged — every one needs a decision before the triage gate holds: python3 tools/pipeline_ctl.py crash-list --status flagged
```

The bracketed tag on a `NEW` line is the Xid classification, present only for
NVRM entries.

## The dedup keys

| Key | Derivation |
|---|---|
| Primary | The canonicalised report title: whitespace collapsed, a leading `kernel ` or `NVRM ` prefix stripped, `BUG: KASAN:` folded to `KASAN:`, and every hex address replaced with `0xADDR` |
| Secondary | SHA-1 of the top `triage.stack_hash_frames` function names, with addresses, offsets and module names stripped |
| Identity | The tuple of title, stack hash and source directory |

Both keys are normalised identically across sources, so the same bug found in
the syzkaller workdir and again in a harvested dmesg log collides onto one
entry.

An empty stack hash is **no evidence** and never drives a stack-based decision.

## The decision table

| Condition | Result |
|---|---|
| The identity tuple matches an existing entry | `DUP`, nothing registered. This makes re-scans idempotent |
| Same title and same non-empty stack as a non-duplicate entry | Registered as a `duplicate` linked to that entry, and both sources are cross-noted |
| Same title, neither sighting has a stack | `flagged` |
| Same title, only one sighting has a stack | `flagged` |
| Same title, different stacks | `flagged` |
| Same stack, different title | `flagged` |
| No match on either key | `unique` |

A `flagged` entry persists in the registry, so `crash-list --status flagged` is
a durable review queue, readable long after this tool's output has scrolled
away.

## Xid classification

NVRM titles are classified at registration and the class is stored on the
entry. The full table is in
[Xid classification](/gspwn/reference/xid-classification/).

Two fields are stripped from an Xid title before it becomes an identity:

| Field | Reason |
|---|---|
| `pid=` and channel number | The same recurring Xid must deduplicate across processes and channels |
| The PCI bus id | The faulting card is provenance. On a multi-GPU box the same driver bug on two cards is one bug |

The bus id is kept in the entry's notes.

## Report blocks

A kernel log is split into blocks, one per report. A block runs from a
report-start line, which is `BUG:`, `KASAN:`, `Oops` or `Kernel panic`, through
the end of its call trace.

`Oops` and `Kernel panic` lines can also appear in the prologue or the trailing
lines of a report already open, so they do not always start a new block. A
fresh `BUG:` or `KASAN:` line always does. One KASAN report becomes one
registry entry.

## The frameless signature

A report with no usable frames falls back to a hash of the normalised wording
around its start line, over `triage.frameless_signature_lines` lines cut to
`triage.frameless_signature_chars` characters.

Fields that differ on every occurrence of the same bug are blanked first: the
oops counter, the faulting CPU, the faulting PID, the taint string, and the
executor index on a `Comm:` line. Volatile fields are removed **before** hex
blanking, so the address pattern cannot consume an eight-digit PID first.

The faulting function from the `RIP:` line is appended after the character cut,
so a long prologue leaves it inside the identity.

## Dedup settings drift

The settings in force at the first registration are stamped into the state
file, written once and never overwritten. `pipeline_ctl.py validate` reports
when they have moved underneath the stored hashes.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | A problem |

## Files

| Path | Contents |
|---|---|
| `state/pipeline.json` | The crash registry this tool writes |
| `artifacts/runs/<id>/workdir` | The syzkaller crash directories |
| `artifacts/u-crashes` | The Track U crash inputs and, beside each one, its `.sanlog` replay report |

## See also

- [replay_crashes.sh](/gspwn/reference/cli/replay-crashes/)
- [Crash identity](/gspwn/architecture/crash-identity/)
- [Results and triage](/gspwn/guides/results-and-triage/)
