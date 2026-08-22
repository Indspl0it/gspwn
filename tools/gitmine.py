#!/usr/bin/env python3
"""The git-mining mechanism shared by the two patch miners.

`tools/patch_mine.py` mines the container stack for Track U and
`tools/cve_patch_map.py` mines the driver for Track K. The repositories differ,
the fix signals differ, and the output schemas differ, so the miners stay
separate. What both need is the same four operations, and this module is their
single implementation:

  git wrapper        one subprocess call with the diff-format configuration
                     pinned and a timeout set
  hunk parsing       a unified diff split into files and hunks, each hunk
                     carrying its line numbers, its trailing context and its
                     added and removed lines
  attribution        the enclosing function of a changed line, from the hunk
                     context that git supplies and from the C declarators of
                     the file itself
  tag mapping        the earliest release tag containing a commit, and the tag
                     that precedes another in ancestry

Two things this module deliberately does not do. It imports no
`tools/pipeline_state.py`, so it carries no `fcntl` dependency and runs on the
Windows workstation, matching the choice `tools/surface_cov.py` documents. It
holds no repository-specific knowledge: no path filters, no keyword tables, no
output schema. Those stay with the miner that owns them.

Diff-format pinning. Git's diff output shape is user-configurable. A parser
keyed on the default shape matches nothing under a non-default configuration
and reports an empty result, which reads as a clean run. Every invocation passes
`diff.noprefix=false`, `diff.mnemonicPrefix=false` and `core.quotepath=false`,
which fixes the `a/` and `b/` prefixes and the encoding of non-ASCII paths for
the duration of the call and leaves the user's own configuration alone.

The `/dev/null` rule. A unified diff names the pre-image on the `---` line and
the post-image on the `+++` line. For a file the commit deletes, git writes the
post-image name as the bare string `/dev/null` with no `b/` prefix, and for a
file the commit adds it writes the pre-image the same way. A parser testing for
`b//dev/null` never matches, so the deletion's hunks keep accumulating against
the file named before it. `parse_unified_diff` reads both sides and reports the
status, so the caller decides what a deletion means for its own ranking.

Hunk bodies are read by line budget. A hunk header declares how many pre-image
and post-image lines follow, and this module consumes exactly that many. The
count separates the file header `+++ b/path` from an added line whose own text
begins with `++`, and it ends a hunk body without lookahead.

Limits. Combined diffs from a merge commit shown against both parents use the
`@@@` form and are not parsed; diff a merge against one parent instead. Such an
entry is recognised by its `diff --cc` or `diff --combined` header and by the
`@@@` hunk header, and the whole entry is dropped. Recognising only the hunk
header would leave the file entry behind with no hunks, and a body line removed
from both parents whose own text begins with `- ` would then be read as a `---`
file header and produce a second, invented entry. An entry with no content
change, a mode change or a pure rename, carries no `---` and `+++` pair and
produces no record. A binary file produces none either.

Environment:
  GSPWN_GIT_TIMEOUT_SECONDS   ceiling on one git invocation, default 300.
                              `git tag --contains` is O(tags x history) and is
                              the call that reaches it first.
"""
import collections
import logging
import os
import re
import subprocess

logger = logging.getLogger(__name__)

GIT_TIMEOUT_SECONDS = int(os.environ.get("GSPWN_GIT_TIMEOUT_SECONDS", "300"))

# Configuration pinned for the duration of every invocation. Passed as `-c`
# overrides, so nothing is written to the checkout or to the user's config.
GIT_CONFIG_ARGS = ("-c", "diff.noprefix=false",
                   "-c", "diff.mnemonicPrefix=false",
                   "-c", "core.quotepath=false")

# A release tag: three dot-separated numbers, optionally v-prefixed.
# Release-candidate and dated tags are excluded because the bulletin column
# these are checked against names shipped versions.
RELEASE_TAG_RE = re.compile(r"^v?\d+\.\d+\.\d+$")

# Hunk header: @@ -a,b +c,d @@ trailing-context. An absent count means 1.
HUNK_HEADER_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@ ?(.*)$")

# A combined diff, from a merge shown against both parents. Two markers name
# one: the `diff --cc` or `diff --combined` header git writes above the entry,
# and the `@@@` hunk header, which is the only marker present when the caller
# passes a fragment with no `diff` line. Both are recognised because a caller
# reaching this with combined input has to get no record and not a wrong one.
COMBINED_HEADER_RE = re.compile(r"^diff --(cc|combined) ")
COMBINED_HUNK_RE = re.compile(r"^@@@+ ")
DIFF_HEADER_RE = re.compile(r"^diff --")

# A function name in a hunk header's trailing context: the last identifier
# before an open parenthesis. Matches "static int\nfoo(struct error *err"
# reduced to one line and matches "func (c *Client) Do(" through the same rule.
CONTEXT_FUNC_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")

# A function name in a C declarator: the first identifier followed by an open
# parenthesis that is not a keyword.
FUNC_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
C_KEYWORDS = frozenset((
    "if", "for", "while", "switch", "return", "sizeof", "do", "else",
    "defined", "case", "typedef", "struct", "union", "enum", "static",
    "inline", "const", "volatile", "extern", "unsigned", "signed",
))
DECLARATOR_LOOKBACK = 30

#: One hunk of a unified diff.
#:
#: old_start, old_count   pre-image line span, 1-based. A count of 0 means the
#:                        hunk adds lines and removes none, and git then writes
#:                        old_start as the line the addition follows.
#: new_start, new_count   post-image line span, 1-based. A count of 0 means the
#:                        hunk only removes lines, and new_start can be 0 when
#:                        the removal is at the head of the file.
#: context                the hunk header's trailing text, stripped. Git fills
#:                        it with its own function heuristic.
#: added, removed         the line texts, with the leading +/- removed.
Hunk = collections.namedtuple(
    "Hunk", "old_start old_count new_start new_count context added removed")

#: One file's entry in a unified diff.
#:
#: old_path   pre-image path, None when the file is added
#: new_path   post-image path, None when the file is deleted
#: status     "added", "deleted" or "modified". A rename is "modified" with
#:            old_path and new_path differing
#: hunks      [Hunk], in file order
DiffFile = collections.namedtuple("DiffFile", "old_path new_path status hunks")


# Sentinel for "no `---` line seen yet", because None is a real path value
# meaning /dev/null.
_NO_PATH = object()


class GitError(RuntimeError):
    """A git invocation failed, timed out, or printed something unparsable."""


def run_git(repo, args, error=GitError, timeout=None):
    """Run one git command in repo and return its stdout as text.

    repo     path to the checkout, passed to `git -C`
    args     the argument list after the global options, as a list of str
    error    exception class raised on failure, so a caller can keep its own
             error type without wrapping every call site
    timeout  seconds, defaulting to GIT_TIMEOUT_SECONDS

    Raises `error` on a non-zero exit or a timeout, with the command, the exit
    status and git's stderr in the message. A silent empty result would read as
    an empty diff, which is why nothing here returns one.
    """
    args = list(args)
    limit = GIT_TIMEOUT_SECONDS if timeout is None else timeout
    cmd = ["git", "-C", repo] + list(GIT_CONFIG_ARGS) + args
    logger.debug("running %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=limit)
    except subprocess.TimeoutExpired as exc:
        raise error(
            "git %s timed out in %s after %d seconds. Raise the ceiling with "
            "GSPWN_GIT_TIMEOUT_SECONDS if the checkout is genuinely this large"
            % (" ".join(args), repo, limit)) from exc
    if proc.returncode != 0:
        raise error(
            "git %s failed in %s with exit %d: %s"
            % (" ".join(args), repo, proc.returncode, proc.stderr.strip()))
    return proc.stdout


def list_tags(repo, error=GitError):
    """Every tag in the checkout, in git's order, blank lines dropped."""
    return [t.strip() for t in run_git(repo, ["tag"], error=error).splitlines()
            if t.strip()]


def version_key(tag):
    """Sort key placing v1.9.0 below v1.17.0."""
    return tuple(int(p) for p in tag.lstrip("v").split("."))


def first_release_tag(repo, sha, pattern=RELEASE_TAG_RE, error=GitError):
    """The earliest release tag containing sha, or None when it is unreleased.

    Ordering is numeric per component, so v1.9.0 sorts below v1.17.0. Tags that
    do not match `pattern` are ignored.
    """
    out = run_git(repo, ["tag", "--contains", sha], error=error)
    tags = [t.strip() for t in out.splitlines() if pattern.match(t.strip())]
    if not tags:
        return None
    return sorted(tags, key=version_key)[0]


def previous_tag(repo, ref, error=GitError):
    """The nearest tag reachable from ref, from `git describe --abbrev=0`.

    The answer comes from ancestry and never from a version sort. A project
    maintaining its branches as separate lines of history has a numerically
    previous tag that frequently sits on another branch, and a diff against it
    reports a whole branch divergence as one release.

    Raises `error` when ref has no tagged ancestor. Git exits non-zero in that
    case and prints its reason to stderr.
    """
    return run_git(repo, ["describe", "--tags", "--abbrev=0", ref],
                   error=error).strip()


def parse_hunk_header(line):
    """One `@@` line as a Hunk with empty added and removed lists, or None.

    An absent count is 1, per the unified diff format.
    """
    match = HUNK_HEADER_RE.match(line)
    if match is None:
        return None
    old_start, old_count, new_start, new_count, context = match.groups()
    return Hunk(old_start=int(old_start),
                old_count=1 if old_count is None else int(old_count),
                new_start=int(new_start),
                new_count=1 if new_count is None else int(new_count),
                context=context.strip(), added=[], removed=[])


def _diff_path(field, prefix):
    """One path as written on a `---` or `+++` line, or None for /dev/null.

    prefix is the one git writes on that side, "a/" or "b/". A path that lacks
    it is taken as-is, so a diff produced under `diff.noprefix` still parses.
    """
    field = field.rstrip("\r")
    if field.startswith('"') and field.endswith('"') and len(field) > 1:
        # Git quotes a path holding a control character, a quote or a
        # backslash. Non-ASCII is unquoted because core.quotepath is pinned off.
        field = field[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    else:
        # A trailing tab introduces the timestamp field POSIX diff writes and
        # git does not. A path holding a tab would have been quoted above.
        field = field.split("\t")[0]
    if field == "/dev/null":
        return None
    if field.startswith(prefix):
        return field[len(prefix):]
    return field


def parse_unified_diff(text):
    """Every file entry in one unified diff, as [DiffFile].

    Hunk bodies are read by the line budget the hunk header declares, so an
    added line whose text begins with "++" is a line and not a file header, and
    the end of a body needs no lookahead. A `\\ No newline at end of file`
    marker is skipped and counts against nothing.

    An entry with no `---` and `+++` pair produces no record: a mode-only
    change, a pure rename and a binary file all fall in that class.
    """
    files = []
    pending_old = _NO_PATH
    hunks = None
    hunk = None
    remaining_old = 0
    remaining_new = 0
    # True from the `diff --cc` header, or from the `@@@` hunk header when the
    # caller passed a fragment with no `diff` line, until the next `diff --`
    # header. Every line of a combined entry is skipped, including its `---`
    # and `+++` pair, because a body line removed from both parents can begin
    # with `- ` and would otherwise read as a file header.
    combined = False

    for line in text.split("\n"):
        if hunk is not None and (remaining_old > 0 or remaining_new > 0):
            if line.startswith("\\"):
                continue
            if line.startswith("+"):
                hunk.added.append(line[1:])
                remaining_new -= 1
                continue
            if line.startswith("-"):
                hunk.removed.append(line[1:])
                remaining_old -= 1
                continue
            if line.startswith(" ") or line == "":
                remaining_old -= 1
                remaining_new -= 1
                continue
            # The body ended before its budget. Git does not write this, and a
            # truncated diff read from a file does. Close the hunk and read the
            # line as structure.
            logger.debug("hunk body ended %d/%d lines short at %r",
                         remaining_old, remaining_new, line[:80])
            remaining_old = remaining_new = 0

        # Read after the hunk body, so a body line is never taken for
        # structure. A combined entry resets the budget on the way in, so the
        # block above is inert for every line of one.
        if DIFF_HEADER_RE.match(line):
            combined = bool(COMBINED_HEADER_RE.match(line))
            if combined:
                pending_old = _NO_PATH
                hunks = hunk = None
                remaining_old = remaining_new = 0
                logger.debug("combined diff entry skipped: %r", line[:80])
            continue
        if combined:
            continue
        if COMBINED_HUNK_RE.match(line):
            # The entry announced itself only here, so its file header has
            # already produced a record. Drop it: a combined entry parses to
            # nothing, and an entry left behind with no hunks reads as a file
            # the commit did not change.
            combined = True
            if files and files[-1].hunks is hunks:
                files.pop()
            pending_old = _NO_PATH
            hunks = hunk = None
            remaining_old = remaining_new = 0
            logger.debug("combined hunk header, entry dropped: %r", line[:80])
            continue

        if line.startswith("--- "):
            pending_old = _diff_path(line[4:], "a/")
            continue
        if line.startswith("+++ ") and pending_old is not _NO_PATH:
            new_path = _diff_path(line[4:], "b/")
            old_path = pending_old
            pending_old = _NO_PATH
            if old_path is None:
                status = "added"
            elif new_path is None:
                status = "deleted"
            else:
                status = "modified"
            hunks = []
            hunk = None
            files.append(DiffFile(old_path=old_path, new_path=new_path,
                                  status=status, hunks=hunks))
            continue
        header = parse_hunk_header(line)
        if header is None:
            continue
        if hunks is None:
            logger.debug("hunk before any file header, ignored: %r", line[:80])
            continue
        hunk = header
        hunks.append(hunk)
        remaining_old = hunk.old_count
        remaining_new = hunk.new_count

    return files



def context_function(context):
    """The function name in a hunk header's trailing context, or None.

    Git derives that context with its own heuristic, which finds C and Go
    definitions well and misses a definition whose opening brace sits on its
    own line. A function count taken this way is a floor.
    """
    if not context:
        return None
    names = CONTEXT_FUNC_RE.findall(context)
    return names[-1] if names else None


def function_ranges(text):
    """Return [(name, first_line, last_line)] for one C translation unit.

    Lines are 1-based and inclusive. A definition is recognised by its opening
    brace in column 0; the declarator above it supplies the name.
    """
    lines = text.split("\n")
    ranges = []
    n = 0
    while n < len(lines):
        if lines[n][:1] != "{" or lines[n].strip() != "{":
            n += 1
            continue
        name = declarator_name(lines, n)
        if name is None:
            n += 1
            continue
        end = n
        for m in range(n + 1, len(lines)):
            if lines[m][:1] == "}":
                end = m
                break
        else:
            end = len(lines) - 1
        ranges.append((name, n + 1, end + 1))
        n = end + 1
    return ranges


def declarator_name(lines, brace_index):
    """The function name in the declarator above a column-0 opening brace.

    lines is the file split on newlines and brace_index is 0-based. Returns
    None when the lines above hold no declarator, which is the case for a
    struct initialiser and for an unbraced control block.
    """
    collected = []
    for n in range(brace_index - 1, max(-1, brace_index - DECLARATOR_LOOKBACK),
                   -1):
        line = lines[n]
        stripped = line.strip()
        if not stripped:
            if collected:
                break
            continue
        if stripped in ("}", "};") or stripped.endswith(";"):
            break
        if stripped.startswith("#"):
            continue
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        collected.append(stripped)
    if not collected:
        return None
    declarator = " ".join(reversed(collected))
    if "=" in declarator.split("(")[0]:
        return None
    for match in FUNC_NAME_RE.finditer(declarator):
        candidate = match.group(1)
        if candidate not in C_KEYWORDS:
            return candidate
    return None


def enclosing(ranges, line):
    """The innermost function range holding a 1-based line, or None."""
    for name, first, last in ranges:
        if first <= line <= last:
            return name
    return None
