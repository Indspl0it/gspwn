---
title: knowledge_ctl.py
description: The committed knowledge files, and the disclosure refusal.
---

Appends to `knowledge/`: what the campaigns have taught, across all of them. Two
files, `learnings.md` and `mistakes.md`, each with a fixed header.

This is deliberately not part of `state/pipeline.json`. The state file records
where this campaign is, resets its round phases every round, and is gitignored.
These files record what is known, never reset, and are committed.
`GSPWN_KNOWLEDGE` redirects the directory for the test suite.

## Responsibility

The module owns the two knowledge files and their entry format. It is the sole
writer of `knowledge/`.

| Invariant | Enforced by |
|---|---|
| A committed file carries no finding data | A crash id, or a path under `artifacts/crashes`, `artifacts/pocs` or `artifacts/rca`, is refused |
| An entry is never torn by a panic | The append is a read-modify-write through a temporary file and a rename |
| Two agents appending at once do not interleave | An exclusive `flock` for the whole append |
| A file always carries its header | When the file is empty, the header is written with the entry |
| The two kinds stay separate | `KINDS` and `FILENAME` map each kind to its own file |
| An entry is machine-timestamped | `cmd_note` stamps the heading, and the files are not hand-edited |

## Interface

| Subcommand | Purpose |
|---|---|
| `note --kind learning\|mistake --phase P "text" [--tags a,b]` | Append one entry |
| `show` | Read the knowledge files back |

| Symbol | Returns |
|---|---|
| `KINDS` | `("learning", "mistake")` |
| `FILENAME` | Kind to filename mapping |
| `_entries(kind)` | Parsed entries for that kind, split on the heading |

An entry is a Markdown heading carrying an ISO-8601 timestamp and the phase, an
optional `Tags:` line, and the body.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | `pipeline_ctl.cmd_brief`, for `KINDS`, `FILENAME` and `_entries`, inside a `try` |
| This module imports | `pipeline_state.py`, for `_fix_root_ownership` |

`brief` imports it inside a `try`, so an unreadable knowledge file does not
suppress the state summary above it.

## Failure modes

| Condition | Behaviour |
|---|---|
| Note text contains a crash id or an artifact path | `ValueError` from `_check_disclosure`; `cmd_note` exits 1 with a message naming where the specifics belong |
| Note text empty | Exits 1 |
| Knowledge file unreadable | `ValueError` naming the file and the error |
| File empty or missing | The header is written with the entry |
| Write performed as root | The file and its lock are handed back to `$SUDO_USER` |
| Temporary file write fails | The temporary file is removed and the exception propagates; the existing file is untouched |

## Concurrency and durability

| Property | Mechanism |
|---|---|
| Mutual exclusion | `flock(LOCK_EX)` on a sibling `.lock` file, held across read, modify and rename |
| Write atomicity | Temporary file, `fsync`, `os.replace`, then `fsync` of the directory |
| Failure cleanup | The temporary file is unlinked on any exception before the rename |
| Root handover | `pipeline_state._fix_root_ownership` runs on the file and its lock after the append |

This is the same durability guarantee the state file has, for the same reason:
the machine panics by design and `AGENTS.md` allows parallel sub-agents.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never carry finding data into a committed file | The generalised form of the same note is publishable and more useful to the next agent, which is looking at a different crash. The refusal is hard, and the message names where the specifics belong |
| Never append without a lock | A plain append leaves a torn entry on a panic, and two agents appending at once interleave their lines |
| Never write without the durability idiom | Read, add the block, write a temporary file, `fsync`, rename, `fsync` the directory |
| Never leave a file headerless | A deleted file recovers its shape, and no entry begins with a bare block |
| Never mix the two kinds | A learning is about the target; a mistake is about the pipeline's own operation. The test is stated in the module and repeated in every sub-agent definition |

## Design notes

`_entries` parses the format back by splitting on the heading, which is why the
files are not hand-edited: the tool timestamps and locks, and a hand edit breaks
the format.

Both file headers state the public-repository constraint, so a reader who opens
the file directly sees it without reading the tool.

`GSPWN_KNOWLEDGE` redirects the directory and exists so the test suite can point
it at a temporary directory. Unlike the state file this has no per-run use:
knowledge is machine-independent and campaign-independent by design.

`cmd_note` prints a repository-relative path when the file is inside the
repository, and the absolute path otherwise, because a redirected directory
would print a run of `..` segments.

## See also

- [knowledge_ctl.py reference](/gspwn/reference/cli/knowledge-ctl/)
- [Security and disclosure](/gspwn/project/security/)
