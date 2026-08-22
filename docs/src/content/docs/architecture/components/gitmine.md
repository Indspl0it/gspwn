---
title: gitmine.py
description: The git-mining mechanism the two patch miners share, the deletion rule that a naive parser gets wrong, and the diff-format pinning that stops a silent empty result.
---

Holds the git mechanics both patch miners need, in one implementation.
`patch_mine.py` mines the container stack for Track U and `cve_patch_map.py`
mines the driver for Track K. The two miners stay separate because their
repositories, their fix signals and their output schemas all differ. Both
duplicated a git wrapper, hunk-header parsing, function attribution from a
`-U0` diff, and release-tag mapping.

This is a library. It has no subcommands and no entry point.

## Responsibility

The module owns four operations. It holds no path filter, no keyword table and
no output schema, so nothing in it is specific to a repository.

| Invariant | Enforced by |
|---|---|
| A non-default git configuration cannot silence the parse | Every invocation passes `diff.noprefix=false`, `diff.mnemonicPrefix=false` and `core.quotepath=false` as `-c` overrides |
| The user's own git configuration is untouched | The overrides last for one command and are written nowhere |
| A git failure is never read as an empty result | A non-zero exit or a timeout raises the caller's error class, with the command, the repository and the limit in the message |
| A deleted file is reported as deleted | `/dev/null` on either side maps to `None`, and `status` carries `added`, `deleted` or `modified` |
| A hunk body ends where its header says it ends | The body consumes exactly `old_count` removed and `new_count` added lines, so a body line beginning `++` is never read as a file header |
| One git invocation cannot hang the miner | `timeout` defaults to `GIT_TIMEOUT_SECONDS`, 300 seconds |
| A release-candidate tag is not a release | `RELEASE_TAG_RE` matches three dot-separated numbers, optionally `v`-prefixed, and nothing else |

## Interface

Errors and configuration:

| Name | Signature | Returns |
|---|---|---|
| `GitError` | `class GitError(RuntimeError)` | Raised on a non-zero exit or a timeout |
| `GIT_TIMEOUT_SECONDS` | `int` | `GSPWN_GIT_TIMEOUT_SECONDS`, default 300 |
| `GIT_CONFIG_ARGS` | `tuple[str, ...]` | The three pinned `-c` overrides |

Git invocation:

| Signature | Returns |
|---|---|
| `run_git(repo, args, error=GitError, timeout=None)` | stdout as `str`. `args` holds the arguments after the global options, `error` is the exception class raised on failure, and `timeout` is seconds |
| `list_tags(repo, error=GitError)` | `list[str]` in git's own order, blank lines dropped |

Release tags:

| Signature | Returns |
|---|---|
| `version_key(tag)` | `tuple[int, ...]`, placing `v1.9.0` below `v1.17.0` |
| `first_release_tag(repo, sha, pattern=RELEASE_TAG_RE, error=GitError)` | The earliest tag matching `pattern` that contains `sha`, or `None` |
| `previous_tag(repo, ref, error=GitError)` | `git describe --tags --abbrev=0 <ref>`, stripped. Raises `error` when `ref` has no tagged ancestor |
| `RELEASE_TAG_RE` | `re.Pattern`, `^v?\d+\.\d+\.\d+$` |

Diff parsing:

| Signature | Returns |
|---|---|
| `parse_unified_diff(text)` | `list[DiffFile]` |
| `parse_hunk_header(line)` | A `Hunk` with empty `added` and `removed`, or `None` |
| `HUNK_HEADER_RE` | `re.Pattern` with five groups: old start, old count, new start, new count, trailing context |

Function attribution:

| Signature | Returns |
|---|---|
| `context_function(context)` | The last identifier before an open parenthesis in a hunk header's trailing context, or `None` |
| `function_ranges(text)` | `list[tuple[str, int, int]]` of name, first line and last line, 1-based and inclusive, for one C translation unit |
| `declarator_name(lines, brace_index)` | The name in the declarator above a column-zero opening brace, or `None`. `lines` is the file split on newlines and `brace_index` is 0-based |
| `enclosing(ranges, line)` | The innermost range holding a 1-based line, or `None` |

## Record shapes

`DiffFile` is a namedtuple of `old_path`, `new_path`, `status` and `hunks`.
`old_path` is `None` for an added file and `new_path` is `None` for a deleted
one. A rename is `modified` with the two paths differing.

`Hunk` is a namedtuple of `old_start`, `old_count`, `new_start`, `new_count`,
`context`, `added` and `removed`. A count absent from the header is 1, per the
unified diff format. `context` is the header's trailing text, stripped. `added`
and `removed` hold the line texts with the leading `+` or `-` removed.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | `tools/patch_mine.py`, `tools/cve_patch_map.py` |
| This module imports | Nothing in `tools/`. It uses `collections`, `logging`, `os`, `re` and `subprocess` |

`cve_patch_map` binds `function_ranges`, `declarator_name` and `enclosing` as
module-level names, so the existing tests that call
`cve_patch_map.function_ranges(...)` still resolve.

The module imports neither `fcntl` nor `pipeline_state`, so it runs on the
Windows workstation. `surface_cov.py` documents the same choice at its own
import block.

## Failure modes

| Condition | Behaviour | Raises |
|---|---|---|
| `git` exits non-zero | Message naming the command, the repository and the exit status | The caller's `error` class |
| `git` exceeds the timeout | Message naming the command, the repository, the limit and the environment variable that raises it | The caller's `error` class |
| `previous_tag` finds no tagged ancestor | Message naming the ref | The caller's `error` class |
| A diff entry carries no `---` and `+++` pair | No record. Covers a mode-only change, a pure rename and a binary file | None |
| A combined diff from a merge shown against both parents | The whole entry is dropped, and any record its file header already produced is removed | None |
| A declarator that matches no identifier | `None`, and the hunk carries no function attribution | None |

## Concurrency and durability

The module writes no file and takes no lock. Every function is a read against a
git repository or a pure parse, so concurrent callers do not interact.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never test for `+++ b//dev/null` | Git writes a deleted file's post-image as the bare string `/dev/null` with no prefix, so that test never matches and the deletion's hunks accumulate against the file named before it |
| Never end a hunk body by looking ahead for a file header | A committed line whose own text begins `++` is then read as a file header, and a path the commit never touched enters the result |
| Never run git without the diff-format overrides | A checkout with `diff.noprefix=true` produces an empty file list, which reads as a clean run with no hot spots |
| Never run git without a timeout | `git tag --contains` is O(tags x history) and runs once per fix candidate |
| Never decide here what a deletion means for a ranking | `patch_mine` skips a deleted file because its ranking lists campaign targets, and `cve_patch_map` attributes to the pre-image because its question is which hunk of a shipped release carries a fix. The module reports the status and each miner decides |
| Never recognise a combined diff by its hunk header alone | The file entry is then left behind with no hunks, and a body line removed from both parents whose own text begins `- ` is read as a `---` file header, which invents a second entry |

## Combined diffs

A merge commit shown against both parents produces a combined diff, which uses
the `@@@` hunk form. `gitmine` does not parse it. Diff a merge against one
parent.

Two markers name a combined entry, and both are checked.

| Marker | Pattern | Input it catches |
|---|---|---|
| Entry header | `^diff --(cc\|combined) ` | A whole `git show -c`, recognised on the way in, because git writes this line above the entry |
| Hunk header | `^@@@+ ` | Hunks fed on their own, with no entry header above them |

Recognition at the entry header resets the file name, the hunk list and the
line budget, and every subsequent line of the entry is skipped, including its
`---` and `+++` pair. Recognition at the hunk header arrives after the file
header has already produced a record, so that record is popped. Either route
drops the whole entry. A caller that reaches this with combined input gets no
record at all.

## Design notes

The deletion rule closes the defect the extraction was written around.
`patch_mine.changed_functions` tested `line.startswith("+++ b/")` and then
compared the remainder against `/dev/null`. The line never matched the prefix
test, so the remainder was never compared, the guard branch was unreachable,
and the current file name kept pointing at the previous entry.

The fix moves no mined number on either container repository today. A
whole-file deletion hunk starts at pre-image line 1, and git derives a hunk
header's trailing context by scanning backwards from the line above the hunk,
so every deletion hunk carries an empty context. The old loop skipped an empty
context before it reached the function regex, so the wrong file name was in
hand and no function name was derived from it. All 11 fix candidates across the
two repositories that delete a file were run through both attribution rules,
and no file list and no function map differs.

The guard held only by accident, because it depended on a property of git's
output that nothing in the parser asserted.

The line-budget parser closes a second defect in the same class. Neither old
parser tracked where a hunk body ends: `patch_mine` treated any line beginning
`+++ b/` as a file header, and `cve_patch_map` dropped any body line beginning
`+++` or `---` from its added and removed lists. A test fixture committing a
line whose own text is `++ b/injected.c` produced a file list holding
`injected.c`, a path the commit never touched, ranked as a hot spot.

The timeout default is 300 seconds, where `surface_verify.py` uses 30.
`open-gpu-kernel-modules` carries 216 tags and `git tag --contains` runs once
per fix candidate, so a lower ceiling turns a working run into a failure.

## Verified against the miners

Every subcommand of both tools was run against the committed checkouts before
and after the extraction.

| Command | Scale | Result |
|---|---|---|
| `patch_mine --repo artifacts/src/libnvidia-container` | 963 commits, 46 fix candidates | stdout identical, JSON identical record by record |
| `patch_mine --repo artifacts/src/nvidia-container-toolkit` | 247 fix candidates | stdout identical, JSON identical record by record |
| `cve_patch_map resolve` | 61 kernel-mode CVEs, 53 bracketed | stdout and stderr identical |
| `cve_patch_map map` | 32 tag pairs, 270 functions | JSON identical key by key |
| `cve_patch_map hotspots` | 30 rows | Identical |
| `cve_patch_map diff` on three release pairs | 122, 288 and 685 output lines | Identical |

## See also

- [patch_mine.py](/gspwn/architecture/components/patch-mine/)
- [cve_patch_map.py](/gspwn/architecture/components/cve-patch-map/)
- [Historical targeting](/gspwn/architecture/historical-targeting/)
