---
title: gitmine.py
description: The git-mining mechanism the two patch miners share, the deletion rule that a naive parser gets wrong, and the diff-format pinning that stops a silent empty result.
---

`gitmine.py` holds the git mechanics both patch miners need, in one
implementation. `patch_mine.py` mines the container stack for Track U and
`cve_patch_map.py` mines the driver for Track K. The two miners stay separate
because their repositories, their fix signals and their output schemas all
differ. Both need a git wrapper, hunk-header parsing, function attribution from
a `-U0` diff, and release-tag mapping.

The module is a library. It declares no argument parser and no `main`.

## Public functions

| Function | Returns |
|---|---|
| `run_git(repo, args, error=GitError, timeout=None)` | git's standard output as text, decoded UTF-8 with undecodable bytes replaced |
| `list_tags(repo, error=GitError)` | Every tag in the checkout, in git's order, with blank lines dropped |
| `version_key(tag)` | A numeric sort key per dot-separated component, placing `v1.9.0` below `v1.17.0` |
| `first_release_tag(repo, sha, pattern=RELEASE_TAG_RE, error=GitError)` | The earliest release tag containing `sha`, or `None` when it is unreleased |
| `previous_tag(repo, ref, error=GitError)` | The nearest tag reachable from `ref`, from `git describe --tags --abbrev=0` |
| `parse_hunk_header(line)` | One `@@` line as a `Hunk` with empty `added` and `removed`, or `None` |
| `parse_unified_diff(text)` | Every file entry in one unified diff, as a list of `DiffFile` |
| `context_function(context)` | The last identifier before an open parenthesis in a hunk header's trailing context, or `None` |
| `function_ranges(text)` | `[(name, first_line, last_line)]` for one C translation unit, 1-based and inclusive |
| `declarator_name(lines, brace_index)` | The function name in the declarator above a column-0 opening brace, or `None` |
| `enclosing(ranges, line)` | The innermost function range holding a 1-based line, or `None` |

`GSPWN_GIT_TIMEOUT_SECONDS` sets the ceiling on one git invocation, and
defaults to 300. `run_git` raises the caller's `error` class on a non-zero exit
or a timeout, so no failure returns an empty string.

## Record shapes

`Hunk` is a namedtuple of seven fields, and `DiffFile` one of four.

| `Hunk` field | Content |
|---|---|
| `old_start`, `old_count` | Pre-image line span, 1-based. A count of 0 means the hunk adds lines and removes none, and git then writes `old_start` as the line the addition follows |
| `new_start`, `new_count` | Post-image line span, 1-based. A count of 0 means the hunk only removes lines, and `new_start` can be 0 when the removal covers the head of the file |
| `context` | The hunk header's trailing text, stripped. Git fills it with its own function heuristic |
| `added`, `removed` | The line texts, with the leading `+` or `-` removed |

| `DiffFile` field | Content |
|---|---|
| `old_path` | Pre-image path, `None` when the file is added |
| `new_path` | Post-image path, `None` when the file is deleted |
| `status` | `added`, `deleted` or `modified`. A rename is `modified` with `old_path` and `new_path` differing |
| `hunks` | The file's hunks, in file order |

An absent count in a hunk header is read as 1, per the unified diff format.

## Responsibility

The module owns four operations: the git wrapper, hunk parsing, function
attribution and tag mapping. It holds no path filter, no keyword table and no
output schema, so nothing in it is specific to a repository.

| Invariant | Enforced by |
|---|---|
| A non-default git configuration cannot silence the parse | Every invocation passes `diff.noprefix=false`, `diff.mnemonicPrefix=false` and `core.quotepath=false` as `-c` overrides |
| The user's own git configuration is untouched | The overrides last for one command and are written nowhere |
| A git failure is never read as an empty result | A non-zero exit or a timeout raises the caller's error class, with the command, the repository and the limit in the message |
| A deleted file is reported as deleted | `/dev/null` on either side maps to `None`, and `status` carries `added`, `deleted` or `modified` |
| A hunk body ends where its header says it ends | The body consumes exactly `old_count` removed and `new_count` added lines, so a body line beginning `++` is never read as a file header |
| One git invocation cannot hang the miner | `timeout` defaults to `GIT_TIMEOUT_SECONDS`, 300 seconds |
| A release tag is three dot-separated numbers | `RELEASE_TAG_RE` matches that form, optionally `v`-prefixed, so a release-candidate or dated tag is skipped |

## Callers

Two production modules import it, `tools/patch_mine.py` and
`tools/cve_patch_map.py`, and `tools/selftest.py` imports it as well. It
imports no module in `tools/` and uses `collections`, `logging`, `os`, `re`
and `subprocess`.

`cve_patch_map` binds `function_ranges`, `declarator_name` and `enclosing` as
module-level names, because that module is where the three are called and
tested from.

The module imports neither `fcntl` nor `pipeline_state`, so it runs on the
Windows workstation. `surface_cov.py` documents the same choice at its own
import block.

## Failure modes

Three conditions raise the caller's error class, and three more continue with
a record or an attribution missing.

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

Six rules cover file-header handling, the diff-format overrides, the timeout
and the split of responsibility with the miners.

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
the `@@@` hunk form. `gitmine` parses no combined diff. Diff a merge against
one parent.

Two markers name a combined entry, and both are checked.

- The entry header, `^diff --(cc|combined) `, catches a whole `git show -c` on
  the way in, because git writes this line above the entry.
- The hunk header, `^@@@+ `, catches hunks fed on their own, with no entry
  header above them.

Recognition at the entry header resets the file name, the hunk list and the
line budget, and every subsequent line of the entry is skipped, including its
`---` and `+++` pair. Recognition at the hunk header arrives after the file
header has already produced a record, so that record is popped. Either route
drops the whole entry.

## Attribution and the timeout ceiling

Both miners diff with `-U0`, so a hunk carries no context line and the function
name comes from one of two places. `context_function` reads the trailing text
git writes on the `@@` line, which finds C and Go definitions and misses a
definition that opens its brace on a line of its own, so a count taken that way
is a floor. `function_ranges` and `enclosing` scan the file itself, pairing
each column-0 opening brace with the declarator above it, over a lookback of
30 lines.

A whole-file deletion hunk starts at pre-image line 1, and git derives a hunk
header's trailing context by scanning backwards from the line above the hunk,
so every deletion hunk carries an empty context and yields no name through
`context_function`.

The timeout ceiling is 300 seconds, where `surface_verify.py` uses 30.
`open-gpu-kernel-modules` carries 216 tags, `git tag --contains` is
O(tags x history), and it runs once per fix candidate.

## See also

- [patch_mine.py](/gspwn/architecture/components/patch-mine/)
- [cve_patch_map.py](/gspwn/architecture/components/cve-patch-map/)
- [Historical targeting](/gspwn/architecture/historical-targeting/)
