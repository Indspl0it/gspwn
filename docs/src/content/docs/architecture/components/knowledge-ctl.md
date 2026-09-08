---
title: knowledge_ctl.py
description: The committed knowledge files, and the disclosure refusal.
---

`knowledge_ctl.py` appends to `knowledge/`, the record of what the campaigns
have established across all of them. Two files hold that record,
`learnings.md` and `mistakes.md`, each with a fixed header.

A learning is about the target, and a mistake is about the pipeline's own
operation. "UVM ioctl numbering does not follow the RM escape convention" is a
learning. "The phase was marked done before the smoke log was read" is a
mistake.

`GSPWN_KNOWLEDGE` redirects the directory. The state file resets its round
phases every round and is gitignored, and these two files never reset and are
committed.

## Invocation

```
python3 tools/knowledge_ctl.py note TEXT --kind learning|mistake --phase PHASE [--tags a,b]
python3 tools/knowledge_ctl.py show [--kind KIND] [--phase PHASE] [--last N]
```

| Argument | Required | Accepted values |
|---|---|---|
| `note TEXT` | yes | The note itself. Empty or blank text is refused |
| `note --kind` | yes | `learning` or `mistake` |
| `note --phase` | yes | One of the twelve phase names |
| `note --tags` | no | Comma-separated, default empty |
| `show --kind` | no | `learning` or `mistake`. Absent reads both files |
| `show --phase` | no | One of the twelve phase names |
| `show --last N` | no | The most recent `N` entries per file |

| Exit code | Condition |
|---|---|
| 0 | The entry was appended, or the requested entries were printed |
| 1 | A problem, printed to standard error as `error: <message>` |
| 2 | A usage error from the argument parser |

`note` prints the kind, the phase and the note text cut to 60 characters, then
the path it wrote. `show` prints one block per file headed by the file name and
its entry count, and prints `no notes recorded yet` when nothing matched.

## Entry format

An entry is a Markdown heading, an optional tag line, and the body.

```
## 2026-03-14T09:21:07+00:00 — triage
Tags: nvidia_uvm, abi
UVM ioctl numbering does not follow the RM escape convention.
```

| Part | Content |
|---|---|
| Heading | An ISO-8601 UTC timestamp to the second, an em-dash separator, and the phase |
| `Tags:` | The tags, comma-separated. Omitted when `--tags` is empty |
| Body | The note text |

`_entries` parses the format back by splitting on the heading, so a hand edit
breaks the parse the tool depends on. Both file headers say so, and state the
public-repository constraint, so a reader who opens the file directly sees it
without reading the tool.

## Responsibility

The module owns the two knowledge files and their entry format. It is the sole
writer of `knowledge/`.

| Invariant | Enforced by |
|---|---|
| A committed file carries no finding data | A crash id, or a path under `artifacts/crashes`, `artifacts/pocs` or `artifacts/rca`, is refused |
| An entry is never torn by a panic | The append is a read-modify-write through a temporary file and a rename |
| Two agents appending at once do not interleave | An exclusive `flock` for the whole append |
| A file always carries its header | When the file is empty or absent, the header is written with the entry |
| The two kinds stay separate | `KINDS` and `FILENAME` map each kind to its own file |
| An entry is machine-timestamped | `cmd_note` stamps the heading, and the files are not hand-edited |

## Callers

- `pipeline_ctl.cmd_brief` imports this module for `KINDS`, `FILENAME` and
  `_entries`, inside a `try`, so an unreadable knowledge file leaves the state
  summary above it intact.
- This module imports `pipeline_state.py`, for `PHASES`, `REPO_ROOT` and
  `_fix_root_ownership`.

## Failure modes

Six conditions are reported, and the file on disk survives every one of them.

| Condition | Behaviour |
|---|---|
| Note text contains a crash id or an artifact path | `ValueError` from `_check_disclosure`, and `cmd_note` exits 1 with a message naming where the specifics belong |
| Note text empty | Exits 1 with `error: a note needs text` |
| Knowledge file unreadable | `ValueError` naming the file and the error, and exit 1 |
| File empty or missing | The header is written with the entry |
| Write performed as root | The file and its lock are handed back to `$SUDO_USER` |
| Temporary file write fails | The temporary file is removed and the exception propagates, leaving the existing file untouched |

## Concurrency and durability

Four mechanisms carry the append, one lock and three write properties.

| Property | Mechanism |
|---|---|
| Mutual exclusion | `flock(LOCK_EX)` on a sibling `.lock` file, held across read, modify and rename |
| Write atomicity | Temporary file, `fsync`, `os.replace`, then `fsync` of the directory |
| Failure cleanup | The temporary file is unlinked on any exception before the rename |
| Root handover | `pipeline_state._fix_root_ownership` runs on the file and its lock after the append |

This matches the durability guarantee the state file has, for the same reason:
the machine panics by design and `AGENTS.md` allows parallel sub-agents.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never carry finding data into a committed file | The generalised form of the same note is publishable and more useful to the next agent, which is looking at a different crash. The refusal is hard, and the message names where the specifics belong |
| Never append without a lock | A plain append leaves a torn entry on a panic, and two agents appending at once interleave their lines |
| Never write without the durability idiom | Read, add the block, write a temporary file, `fsync`, rename, `fsync` the directory |
| Never leave a file headerless | A deleted file recovers its shape, and every entry follows a header |
| Never mix the two kinds | A learning is about the target, and a mistake is about the pipeline's own operation. The test is stated in the module and repeated in every sub-agent definition |

## Design notes

`GSPWN_KNOWLEDGE` redirects the directory so the test suite can point it at a
temporary directory. It has no per-run use, because knowledge is
machine-independent and campaign-independent by design.

`cmd_note` prints a repository-relative path when the file is inside the
repository, and the absolute path otherwise, because a redirected directory
would print a run of `..` segments.
