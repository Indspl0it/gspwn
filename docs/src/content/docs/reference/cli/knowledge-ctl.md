---
title: knowledge_ctl.py
description: Appending to the committed knowledge files, and the content they refuse.
---

Appends to `knowledge/`, the facts that persist across campaigns, machines and
agent sessions.

## Synopsis

```
python3 tools/knowledge_ctl.py <note|show> [options]
```

Root is never required. `GSPWN_KNOWLEDGE` redirects the directory, and exists
so the test suite can point it at a temporary directory.

## note

Appends one timestamped entry to one of the two files.

```
python3 tools/knowledge_ctl.py note --kind learning --phase describe \
  --tags abi,uvm "UVM has its own ioctl numbering scheme..."
```

| Argument | Accepted values |
|---|---|
| `text` | The note itself, positional and required |

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--kind` | `learning`, `mistake` | Required | Which file to append to |
| `--phase` | One of the twelve phase names | Required | The phase the note came from |
| `--tags` | Comma-separated list | Empty | For example `nvidia_uvm,abi` |

```
recorded learning (describe): UVM has its own ioctl numbering scheme and doe...
  knowledge/learnings.md
```

Entries are appended as a timestamped block:

```markdown
## 2026-08-15T07:36:41+00:00 — describe
Tags: abi, uvm
UVM has its own ioctl numbering scheme and does not follow the convention the
RM escapes use.
```

The append is atomic and locked: read the file, add the block, write a
temporary file, `fsync` it, rename it into place, and `fsync` the directory.
This machine panics by design and allows parallel sub-agents, so a plain append
would leave a torn entry or interleave two agents' lines.

The file header is written when the file is empty, so a deleted file recovers
its shape on the next note.

### Disclosure refusal

`knowledge/` is committed to a public repository, so two patterns are refused:

| Pattern | Example |
|---|---|
| A crash id | `crash-0001`, case-insensitive |
| A path under the finding directories | `artifacts/crashes/`, `artifacts/pocs/`, `artifacts/rca/` |

```
python3 tools/knowledge_ctl.py note --kind mistake --phase triage \
  "crash-0001 was marked a duplicate too early"
```

```
error: refusing to record a note naming 'crash-0001': knowledge/ is committed to a public repo, and anything tied to a specific crash is finding data. Record the general form instead — the lesson that applies to the next crash of that shape — and keep the specifics in the crash registry (`pipeline_ctl.py crash-set <id> --notes`) or its research record (`pipeline_ctl.py finding-set`).
```

The note is refused outright, because the generalised form is publishable and
applies to the crash the next agent is looking at.

## show

Prints matching entries from one or both files.

```
python3 tools/knowledge_ctl.py show [options]
```

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--kind` | `learning`, `mistake` | Both | Which file to read |
| `--phase` | One of the twelve phase names | All | Filter by the phase the note came from |
| `--last` | `N` | All | Only the most recent N entries per file |

```
== learnings.md (7)
  2026-08-15T07:36:41+00:00  [provision]  {gpu, scope}
      open-gpu-kernel-modules supports Turing and later only: those carry the
      GSP microcontroller the open modules depend on.
```

Prints `no notes recorded yet` when nothing matches.

## The two files

| File | About | Audience |
|---|---|---|
| `knowledge/learnings.md` | The target: ABI facts, driver behaviour, tooling quirks | The `describe`, `seeds` and `rca` sub-agents of later rounds |
| `knowledge/mistakes.md` | The process: what cost a round, produced a wrong number, or would repeat | The next agent running that phase |

The test: "UVM ioctl numbering does not follow the RM escape convention" is a
learning. "The phase was marked done before the smoke log was read" is a
mistake.

These files are separate from `state/pipeline.json`. The state file records
where this campaign stands, resets its round phases every round, and is
gitignored. The knowledge files record what is known, never reset, and are
committed.

## Knowledge entries in `brief`

`pipeline_ctl.py brief` prints the first line of the most recent
`agent.brief_knowledge_entries` entries per file, cut to
`agent.brief_knowledge_line_chars`, and points at this tool for the full text.

## Do not hand-edit

The tool timestamps and locks. A hand-edited file loses the format the parser
depends on, and `brief` and `show` read through the parser.

## Public repository

`knowledge/` is committed. It carries ABI and process facts and never findings.
Vulnerability detail lives in the crash registry and its research record, both
of which are gitignored.

Unlike the state file, this directory has no per-run use. Knowledge is machine-
and campaign-independent by design.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | A problem, including a refused disclosure |
| 2 | Usage error |

## Files

| Path | Contents |
|---|---|
| `knowledge/learnings.md` | Facts about the target |
| `knowledge/mistakes.md` | Facts about the process |

## See also

- [Security and disclosure](/gspwn/project/security/)
- [Overview](/gspwn/architecture/overview/)
</content>
</invoke>
