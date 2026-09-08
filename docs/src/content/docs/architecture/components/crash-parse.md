---
title: crash_parse.py
description: Crash identity, deduplication and registration.
---

Harvests crashes from every source and deduplicates them into the registry. One
invocation scans the syzkaller workdir, the Track U crash directory and an
optional kernel log, and registers what it finds. There are no subcommands.

| Flag | Default | Effect |
|---|---|---|
| `--run-id` | The last run registered in the current round | Scans `artifacts/runs/<id>/workdir` |
| `--syz-workdir` | none | An explicit workdir path, overriding `--run-id` |
| `--track-u-dir` | `artifacts/u-crashes` | The Track U crash root |
| `--dmesg` | none | A kernel log to scan for NVRM lines and report blocks |

The tool exits 0 whatever it finds, so the `triage` sub-agent reads the printed
counts and the registry to learn what happened. A bad argument exits 2 from
argparse.

## Identity

A crash's identity is two keys, normalised identically across sources, so the
same bug found in two places collides.

| Key | Derivation |
|---|---|
| Primary | The canonicalised report title: whitespace collapsed, a leading `kernel ` or `NVRM ` prefix stripped, `BUG: ` folded off a `KASAN:` or `UBSAN:` title, and every hex address replaced with `0xADDR` |
| Secondary | The first 16 hex digits of the SHA-1 over the top `triage.stack_hash_frames` function names, with addresses, offsets and module names stripped |
| Identity | The tuple of title, stack hash and source directory |

An empty stack hash is no evidence and never drives a stack-based decision.

Seven conditions decide what `register` does with a sighting.

| Condition | Outcome |
|---|---|
| The identity tuple matches an existing entry | Nothing is registered, which makes a re-scan idempotent |
| Same title and same non-empty stack as a non-duplicate entry | Registered as a duplicate linked to that entry, and both sources are cross-noted |
| Same title, neither sighting has a stack | Flagged |
| Same title, only one sighting has a stack | Flagged |
| Same title, different stacks | Flagged |
| Same stack, different title | Flagged |
| No match on either key | Unique |

A flagged entry persists in the registry, so the review queue outlives the run
that produced it. `pipeline_ctl.py crash-list --status flagged` is that queue,
and the run's closing line names the flagged count.

## Sources

| Source | Title from | Stack hash from |
|---|---|---|
| syzkaller crash directory | The directory's `description` file | The lowest-numbered `report<N>`, falling back to `log<N>` when the manager ran without `kernel_obj` and wrote no symbolized report |
| Track U crash input | The sanitizer signature in the input, or in the `.sanlog` report written beside it by `harnesses/replay_crashes.sh` | The same text |
| Kernel log, NVRM line | `NVRM ` plus the Xid line with `pid=`, channel and PCI bus id stripped | SHA-1 of that same body |
| Kernel log, report block | The block's start line | The block's frames, or the frameless signature when it has none |

An unsuffixed `report` is accepted after the numbered ones, so a directory
written by an older syzkaller still resolves. `repro.report` and `report.html`
are not reports of the crash and are left alone.

Track U inputs are read at most `TRACK_U_MAX_DEPTH`, four levels below the crash
root, which covers the `<harness>/<input>` layout `run_all.sh` writes and the
two deeper trees a wholesale `cp -r` of a fuzzer output directory produces.
`README.txt` and `README` are excluded, since AFL++ writes one into its own
crashes directory.

## Xid classification

An NVRM title carrying an Xid number is classified from `XID_CLASS`, which lists
22 numbers across four classes. The class becomes the entry's `signal` field.

| Class | Meaning | Xids listed |
|---|---|---|
| `noise` | The fuzzer caused it on purpose, so it is its own exhaust and not a finding | 6 |
| `signal` | Security-relevant or memory-integrity relevant, so triage it | 11 |
| `health` | The GPU or the box is degraded, which blocks measurement without being a finding | 4 |
| `review` | Everything else, including every Xid the table does not list | 1 |

An NVRM line carrying no Xid number is left unclassified and registers with
`signal: unclassified`. `GPU at ... error` lines are the case that produces one.

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

## Callers

`repro_ctl.py` imports this module for `REPORT_SUFFIX`, the report-file suffix
it looks for beside a Track U input. `pipeline_ctl.py crash-list --signal`
filters on the classification this module assigns, and the `triage` sub-agent
documents `XID_CLASS`. This module imports `pipeline_state.py` and
`gspwn_config.py`.

## Failure modes

Twelve conditions have a defined behaviour. A missing source warns and scans
nothing, and nothing here aborts the scan.

| Condition | Behaviour |
|---|---|
| No run id given and none registered in the round | Warns and skips the syzkaller workdir, directing `--run-id` or `round-add-run` |
| No `crashes` directory under the resolved workdir | Warns and scans nothing for Track K |
| A syzkaller crash directory with no `description` file | Skipped |
| Track U crash directory missing | Warns and scans nothing for Track U |
| Track U crash root holds no files | Warns naming the directory `run_all.sh` copies inputs to |
| A Track U input with no `.sanlog` report beside it | Skipped with a warning naming `replay_crashes.sh`, because a raw fuzzer input carries no sanitizer output of its own |
| A Track U input whose replay report carries no sanitizer signature | Skipped with a warning that the input did not crash this build of the harness |
| Track U files present and not one usable | Warns with the count and which of the two reasons applies to how many |
| `--dmesg` path does not exist | Warns and scans nothing from kernel logs |
| One identity key collides and the other does not | The crash is registered `flagged` and persists in the registry |
| Xid number absent from `XID_CLASS` | Classified `review`, with a note saying so, and never defaulted to `noise` |
| Report carries no usable frames | The frameless signature is used, with the RIP anchor appended |

## Concurrency and durability

The whole scan runs inside one `pipeline_state.transaction`, so it holds the
exclusive state lock from the first source to the last. `triage` may run while
the fuzz monitor and other sub-agents are also touching the registry, and the
single transaction makes the scan atomic against them. Registration is
idempotent: `harvest` runs after every reboot, and the identity tuple makes a
re-scan a no-op. Durability comes from `pipeline_state.save`.

## Prohibited behaviour

Eight rules bound the module.

- Never let an empty stack hash drive a decision. An empty hash carries no
  evidence. Report-less syzkaller crashes and signature-only Track U inputs
  would alias each other through a constant hash.
- Never merge on a partial match. A collision in one key alone may be a second
  bug or the same bug reported twice, and distinguishing them requires reading
  both reports.
- Never register the same sighting twice. The identity tuple of title, hash and
  source directory makes a re-scan idempotent.
- Never register a Track U file with no sanitizer signature. Logs, manifests
  and READMEs in a crash directory would become phantom unique crashes.
- Never default an unlisted Xid to `noise`. A new driver branch can introduce
  an Xid this table has never seen, so an unlisted number is `review` and the
  class of finding the campaign exists to produce survives.
- Never keep per-occurrence detail in an identity. The `pid=` value, channel
  number and PCI bus id are stripped from an Xid title, and the oops counter,
  faulting CPU, faulting PID, taint string and executor index are blanked from
  a frameless signature.
- Never drop the RIP anchor. It is appended after the character cut, so a long
  prologue cannot push the strongest evidence a frameless report carries out of
  its identity.
- Never scan without a lock. `triage` runs concurrently with other sub-agents
  touching the registry.

## Design notes

The collision between a bug found in the syzkaller workdir and the same bug
found again in a harvested dmesg log makes the duplicate registration
meaningful. The second sighting is linked to the first, and both sources stay
addressable as durable state.

An eight-digit PID left until after hex blanking is consumed as an address and
never recognised as a PID, so the same panic splits on task id alone.

`report_blocks` runs a small state machine over the log. `Oops` and
`Kernel panic` lines are not always the start of a new report: they can be the
prologue tail or the closing lines of the report already open, since one oops
prints `BUG:`, then `Oops:`, then `Kernel panic`. A fresh `BUG:` or `KASAN:`
line always starts the next one.

The Xid number pattern consumes the parenthesised bus id as a group. Skipping it
loosely reads the first field of the bus id as the Xid number, which classifies
every crash as an unknown Xid 0. The bus id is read before it is stripped, so
the note names the card the fault came from while the title stays the same
across cards.

`syz_indexed_path` takes the lowest index syzkaller has written, which is the
only stable selection available. Once a directory holds `MaxCrashLogs` entries
syzkaller overwrites the oldest slot and rewrites `description` on every save,
so the frames and the title can come from two sightings of one bug. That
registers as `flagged`, never as a silent second finding.

`stamp_triage_settings` is self-guarded, written once and never overwritten,
because rewriting it would erase the evidence it exists to preserve. `validate`
reads that stamp to report that the settings moved underneath the stored hashes.

Duplicates are kept out of the title and hash indexes, so a later sighting links
against the surviving finding.

`resolve_workdir` defaults to the last run registered in the current round, and
warns when nothing is registered. The `triage` sub-agent is told to always pass
`--run-id`, because the default is wrong in a round with several campaigns.

## See also

- [Crash identity](/gspwn/architecture/crash-identity/)
