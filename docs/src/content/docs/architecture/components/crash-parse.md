---
title: crash_parse.py
description: Crash identity, deduplication and registration.
---

Harvests crashes from every source and deduplicates them into the registry. One
invocation scans the syzkaller workdir, the Track U crash directory and an
optional kernel log, and registers what it finds.

A crash's identity is two keys: the canonical title and the stack hash. Both are
normalised identically across sources, so the same bug found in two places
collides.

## Responsibility

The module owns crash identity and the registration decision. It writes the
registry only inside one `pipeline_state` transaction.

| Invariant | Enforced by |
|---|---|
| The same bug from two sources produces the same identity | `canon_title` strips source prefixes and folds sanitizer title forms; `stack_frames` reads both syzkaller reports and raw kernel traces |
| An empty stack hash never drives a merge decision | `stack_hash` returns `''` for a frameless report and `register` refuses to key on it |
| A partial key match is never merged | `register` records the crash as `flagged` |
| A re-scan registers nothing twice | The identity tuple is title, hash and source directory |
| Per-occurrence detail never enters an identity | Volatile fields are blanked before hex blanking |
| The dedup settings behind the stored hashes are recoverable | `stamp_triage_settings` runs before the first registration and writes once |
| The whole scan is one atomic registry update | `main` wraps every scan in a single transaction |

## Interface

The command form takes `--run-id`, `--syz-workdir`, `--track-u-dir` and
`--dmesg`, and prints the registry total and the flagged count.

| Function | Returns | Raises |
|---|---|---|
| `canon_title(t)` | The source-independent title | |
| `stack_frames(text)` | Function names in log order | |
| `stack_hash(report_text, depth=None)` | sha1 of the top frames, or `''` when the text carries no frames | |
| `block_signature(block, lines=None, chars=None)` | Title and context hash for a frameless report block | |
| `report_blocks(text)` | Yields `(start_line, block_text)`, one kernel report per block | |
| `xid_class(title)` | `(class, why)`, or `(None, '')` when the title carries no Xid | |
| `sanitizer_title(text)` | The title from a sanitizer signature, or `None` | |
| `existing_keys(state)` | `(title index, hash index, identity index)` | |
| `register(state, track, title, shash, srcdir, signal=None, signal_note='')` | The registration outcome | |
| `scan_syz(state, workdir)`, `scan_track_u(state, udir)`, `scan_dmesg(state, path)` | `None` | |
| `resolve_workdir(a, state)` | The workdir path, or `None` | |

Exported constant: `XID_CLASS`.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing at run time. `selftest.py` imports it, and the `triage` sub-agent documents `XID_CLASS` |
| This module imports | `pipeline_state.py`, `gspwn_config.py` |

## Failure modes

| Condition | Behaviour |
|---|---|
| No run id given and none registered in the round | Warns and skips the syzkaller workdir |
| No `crashes` directory under the resolved workdir | Warns and scans nothing for Track K |
| Track U crash directory missing | Warns and scans nothing for Track U |
| `--dmesg` path does not exist | Warns and scans nothing from kernel logs |
| One identity key collides and the other does not | The crash is registered `flagged` and persists in the registry |
| Track U file carries no sanitizer signature | The file is skipped |
| Xid number absent from `XID_CLASS` | Classified unknown, never defaulted to `noise` |
| Report carries no usable frames | The frameless signature is used, with the RIP anchor appended |

## Concurrency and durability

The whole scan runs inside one `pipeline_state.transaction`, so it holds the
exclusive state lock from the first source to the last. `triage` may run while
the fuzz monitor and other sub-agents are also touching the registry, and the
single transaction makes the scan atomic against them. Registration is
idempotent: `harvest` runs after every reboot, and the identity tuple makes a
re-scan a no-op. Durability comes from `pipeline_state.save`.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never let an empty stack hash drive a decision | An empty hash carries no evidence. Report-less syzkaller crashes and signature-only Track U inputs would alias each other through a constant hash |
| Never merge on a partial match | A collision in one key alone may be a second bug or the same bug reported twice, and distinguishing them requires reading both reports |
| Never register the same sighting twice | The identity tuple of title, hash and source directory makes a re-scan idempotent |
| Never register a Track U file with no sanitizer signature | Logs, manifests and READMEs in a crash directory would become phantom unique crashes |
| Never default an unlisted Xid to `noise` | A new driver branch can introduce an Xid this table has never seen, and defaulting it discards the class of finding the campaign exists to produce |
| Never keep per-occurrence detail in an identity | The `pid=` value, channel number and PCI bus id are stripped from an Xid title; the oops counter, faulting CPU, faulting PID, taint string and executor index are blanked from a frameless signature |
| Never drop the RIP anchor | It is appended after the character cut, so a long prologue cannot push the strongest evidence a frameless report carries out of its identity |
| Never scan without a lock | `triage` runs concurrently with other sub-agents touching the registry |

## Design notes

Both keys are normalised identically across sources, so the same bug found in
the syzkaller workdir and again in a harvested dmesg log collides. That collision
makes the duplicate registration meaningful: the second sighting is linked to
the first, and both sources stay addressable as durable state.

Volatile fields are blanked before hex blanking. An eight-digit PID would
otherwise be consumed as an address first and never recognised as a PID, so the
same panic would split on task id alone.

`report_blocks` runs a small state machine over the log. `Oops` and
`Kernel panic` lines are not always the start of a new report: they can be the
prologue tail or the closing lines of the report already open, since one oops
prints `BUG:`, then `Oops:`, then `Kernel panic`. A fresh `BUG:` or `KASAN:`
line always starts the next one.

The Xid number pattern consumes the parenthesised bus id as a group. Skipping it
loosely reads the first field of the bus id as the Xid number, which classifies
every crash as an unknown Xid 0.

`stamp_triage_settings` is called before the first registration, so `validate`
can later report that the settings moved underneath the stored hashes. It is
self-guarded: written once and never overwritten, because rewriting it would
erase the evidence it exists to preserve.

Duplicates are kept out of the title and hash indexes, so a later sighting links
against the surviving finding.

`resolve_workdir` defaults to the last run registered in the current round, and
warns when nothing is registered. The `triage` sub-agent is told to always pass
`--run-id`, because the default is wrong in a round with several campaigns.

## See also

- [Crash identity](/gspwn/architecture/crash-identity/)
- [crash_parse.py reference](/gspwn/reference/cli/crash-parse/)
