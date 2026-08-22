#!/usr/bin/env python3
"""Security-fix miner: the empirical hot spots the harness phase should target.

`agents/harness.md` names `libnvidia-container` as the Track U primary target
and says the CVE-2024-0132 class of bugs lives adjacent to it. It does not say
where. Choosing entry points by judgement on a live system produces a target
list derived from where bugs might be. The fix history says where they were.

Both NVIDIA container repositories carry that history in a machine-readable
form. This tool reads it.

Two signals identify a fix commit, and they differ in strength:

  fork merge      A merge whose subject is exactly "Merge commit from fork".
                  GitHub renders the merge of a private security-advisory fork
                  this way, so the subject is a structural marker placed by the
                  forge and not by a commit author. Every one of these is a
                  coordinated security fix.
  keyword         A subject or body matching one of KEYWORDS. This is a
                  heuristic. It catches fixes that never went through an
                  advisory and it also catches unrelated commits, so each hit
                  carries the keyword that matched and is reviewed by hand.

For each commit the tool records the files touched and the enclosing functions,
taken from the hunk headers of a zero-context diff. Git derives that trailing
context with its own function heuristic, which finds C and Go definitions well
and misses a definition whose opening brace sits on its own line. A function
count from this tool is a floor.

Release mapping uses `git tag --contains`. The earliest release tag containing a
commit is the first version that shipped the fix, and an NVIDIA bulletin's
Updated Version column can be checked against it. The tool reports that
tag and never asserts a CVE mapping: a version match plus a plausible diff is
evidence a human states, and this tool supplies the version.

The hot-spot ranking counts distinct fix commits per file and per function
across the window. Weighting is deliberately absent. A file touched by four fix
commits ranks above one touched by two, and nothing here decides whether that
difference matters.

This runs entirely off a git checkout. No GPU, no SUT, no network.

Arguments:
  --repo DIR      the checkout to mine, defaulting to libnvidia-container
  --since DATE    ISO date bounding the window, defaulting to the whole history
  --out PATH      JSON destination; stdout carries the summary either way

Exit codes: 0 success, 1 bad argument or unusable checkout, 2 git failed.
"""
import argparse
import collections
import datetime
import json
import logging
import os
import re
import sys
import tempfile

import gitmine

logger = logging.getLogger(__name__)

DEFAULT_REPO = os.path.join("artifacts", "src", "libnvidia-container")

# The forge-placed marker. GitHub writes this subject when a private security
# advisory fork is merged back, so it identifies a coordinated fix without
# depending on what the author wrote.
FORK_MERGE_SUBJECT = "Merge commit from fork"

# Keyword -> the bug class the keyword suggests. The class is a hint for the
# human review pass and is never treated as a classification. Each pattern is
# matched with word boundaries, because substring matching pulled in every
# commit whose body happened to contain "valid" inside "valid targets".
#
# "capabilit" is deliberately absent. In this codebase the word almost always
# means NVIDIA_DRIVER_CAPABILITIES, the image-supplied capability string, and
# matching it returned the whole MIG capability-mount history. POSIX
# capability handling is caught by "privilege" and "seccomp".
KEYWORDS = {
    r"cve-\d{4}": "disclosed vulnerability",
    r"symlink\w*": "link following",
    r"toctou": "time-of-check to time-of-use",
    r"time-of-check": "time-of-check to time-of-use",
    r"race condition": "race condition",
    r"path travers\w*": "path traversal",
    r"container escape": "isolation escape",
    r"out[- ]of[- ]bounds": "memory safety",
    r"overflow": "memory safety",
    r"use[- ]after[- ]free": "memory safety",
    r"double free": "memory safety",
    r"out of scope": "memory safety",
    r"memory leak": "resource leak",
    r"leak": "resource leak",
    r"null (pointer )?deref\w*": "null pointer dereference",
    r"sanitiz\w+": "input validation",
    r"validat\w+": "input validation",
    r"invalid": "input validation",
    r"hardening": "hardening",
    r"privilege\w*": "privilege handling",
    r"seccomp": "privilege handling",
    r"user namespace": "isolation",
    r"fexecve": "execution path",
    r"ldconfig": "execution path",
    r"ldcache": "execution path",
}
KEYWORD_RE = {re.compile(r"\b" + k + r"\b"): v for k, v in KEYWORDS.items()}

# Vendored dependencies, packaging and build scaffolding. A fix commit that
# bumps a vendored module or edits a changelog says nothing about where this
# project's own bugs are, and a Debian changelog produces phantom function
# names because its stanza header parses like a call.
IGNORED_PREFIXES = ("vendor/", "third_party/", "deployments/", "docs/",
                    "pkg/", "mk/", "tests/", "tools/", ".github/")

ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# The shared miner raises this class, and every git failure in this tool is
# one of its invocations, so the two names are the same class.
GitError = gitmine.GitError


def run_git(repo, args):
    """Run one git command in repo and return its stdout as text.

    Diff-format configuration and the timeout come from `gitmine.run_git`.
    """
    return gitmine.run_git(repo, args)


def validate_repo(repo):
    """Reject a path that is not a git checkout, loudly and before any work."""
    if not os.path.isdir(repo):
        raise ValueError(
            "repo path is not a directory: %s (pass --repo with a checkout "
            "of libnvidia-container or nvidia-container-toolkit)" % repo)
    try:
        top = run_git(repo, ["rev-parse", "--show-toplevel"]).strip()
    except GitError as exc:
        raise ValueError("not a git checkout: %s (%s)" % (repo, exc)) from exc
    shallow = run_git(repo, ["rev-parse", "--is-shallow-repository"]).strip()
    if shallow == "true":
        raise ValueError(
            "checkout is shallow: %s. A shallow clone holds one commit and no "
            "tags, so the fix history it would report is empty. Deepen it "
            "with: git -C %s fetch --unshallow --tags" % (repo, repo))
    ntags = len(gitmine.list_tags(repo))
    if ntags == 0:
        raise ValueError(
            "checkout has no tags: %s. Release mapping needs them. Fetch them "
            "with: git -C %s fetch --tags" % (repo, repo))
    logger.info("mining %s (%d tags)", top, ntags)
    return top


def validate_since(since):
    """Reject a --since value git would silently reinterpret."""
    if since is None:
        return None
    if not ISO_DATE.match(since):
        raise ValueError(
            "--since must be an ISO date, YYYY-MM-DD, and was %r. Git accepts "
            "loose date words and resolves them differently across versions, "
            "so this tool refuses them." % since)
    try:
        datetime.date.fromisoformat(since)
    except ValueError as exc:
        raise ValueError("--since is not a real date: %r (%s)"
                         % (since, exc)) from exc
    return since


def validate_out(out):
    """Reject an output path whose directory does not exist."""
    if out is None:
        return None
    parent = os.path.dirname(os.path.abspath(out))
    if not os.path.isdir(parent):
        raise ValueError(
            "--out directory does not exist: %s (create it first)" % parent)
    return out


def list_commits(repo, since):
    """Every commit in the window, as (sha, iso date, author, subject, body)."""
    sep = "\x1e"
    rec = "\x1d"
    fmt = sep.join(["%H", "%ad", "%an", "%s", "%b"]) + rec
    args = ["log", "--all", "--date=short", "--format=" + fmt]
    if since:
        args.append("--since=" + since)
    out = run_git(repo, args)
    commits = []
    for chunk in out.split(rec):
        chunk = chunk.strip("\n")
        if not chunk:
            continue
        fields = chunk.split(sep)
        if len(fields) != 5:
            raise GitError(
                "unparsable git log record with %d fields, expected 5: %r"
                % (len(fields), chunk[:200]))
        sha, date, author, subject, body = fields
        commits.append({
            "sha": sha.strip(),
            "date": date.strip(),
            "author": author.strip(),
            "subject": subject.strip(),
            "body": body.strip(),
        })
    logger.info("%d commits in window", len(commits))
    return commits


def classify(commit):
    """Why this commit is a fix candidate, or None if it is not one."""
    if commit["subject"] == FORK_MERGE_SUBJECT:
        return {"signal": "fork merge", "matched": FORK_MERGE_SUBJECT,
                "class_hint": "coordinated security fix"}
    haystack = (commit["subject"] + "\n" + commit["body"]).lower()
    for pattern, hint in KEYWORD_RE.items():
        found = pattern.search(haystack)
        if found:
            return {"signal": "keyword", "matched": found.group(0),
                    "class_hint": hint}
    return None


def changed_functions(repo, sha):
    """Files touched and the enclosing functions, from a zero-context diff.

    A merge commit is diffed against its first parent, so a fork merge reports
    the fix it brought in and not the whole branch.

    A file the commit deletes is reported nowhere. Its post-image is
    `/dev/null`, the hot-spot ranking below this produces a list of campaign
    targets, and a removed file cannot be one. `cve_patch_map.diff_file`
    attributes a deletion to the pre-image, because its question is which hunk
    of a shipped release carries a fix.
    """
    parents = run_git(repo, ["log", "-1", "--format=%P", sha]).split()
    if not parents:
        # A root commit has nothing to diff against. Report the tree as added.
        names = run_git(repo, ["show", "--format=", "--name-only", sha])
        return sorted(set(n for n in names.splitlines() if n.strip())), {}
    diff = run_git(repo, ["diff", "--no-color", "-U0", parents[0], sha])
    files = []
    funcs = collections.defaultdict(set)
    for entry in gitmine.parse_unified_diff(diff):
        if entry.status == "deleted":
            continue
        files.append(entry.new_path)
        for hunk in entry.hunks:
            name = gitmine.context_function(hunk.context)
            if name:
                funcs[entry.new_path].add(name)
    return sorted(set(files)), {f: sorted(v) for f, v in funcs.items()}


def first_release_tag(repo, sha):
    """The earliest release tag containing sha, or None when it is unreleased."""
    return gitmine.first_release_tag(repo, sha)


def interesting(path):
    """Does a change to this path say anything about this project's own bugs?"""
    norm = path.replace(os.sep, "/")
    return not norm.startswith(IGNORED_PREFIXES)


def mine(repo, since):
    """Every fix candidate in the window, with its files, functions and tag."""
    records = []
    for commit in list_commits(repo, since):
        signal = classify(commit)
        if signal is None:
            continue
        files, funcs = changed_functions(repo, commit["sha"])
        kept = [f for f in files if interesting(f)]
        record = dict(commit)
        record.update(signal)
        record["files"] = kept
        record["files_ignored"] = [f for f in files if not interesting(f)]
        record["functions"] = {f: v for f, v in funcs.items()
                               if interesting(f)}
        record["first_release_tag"] = first_release_tag(repo, commit["sha"])
        records.append(record)
    records.sort(key=lambda r: (r["date"], r["sha"]), reverse=True)
    logger.info("%d fix candidates (%d fork merges)", len(records),
                sum(1 for r in records if r["signal"] == "fork merge"))
    return records


def hotspots(records):
    """Files and functions ranked by how many fix commits touched them."""
    per_file = collections.Counter()
    per_func = collections.Counter()
    file_commits = collections.defaultdict(list)
    func_commits = collections.defaultdict(list)
    for rec in records:
        short = rec["sha"][:7]
        for path in rec["files"]:
            per_file[path] += 1
            file_commits[path].append(short)
        for path, names in rec["functions"].items():
            for name in names:
                key = "%s:%s" % (path, name)
                per_func[key] += 1
                func_commits[key].append(short)
    return {
        "files": [{"path": p, "fix_commits": n, "commits": file_commits[p]}
                  for p, n in per_file.most_common()],
        "functions": [{"function": f, "fix_commits": n,
                       "commits": func_commits[f]}
                      for f, n in per_func.most_common()],
    }


def write_json(out, payload):
    """Write payload to out atomically, so an interrupted run leaves no half file."""
    parent = os.path.dirname(os.path.abspath(out))
    tmp = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=parent,
                                         suffix=".tmp", delete=False) as fh:
            tmp = fh.name
            json.dump(payload, fh, indent=2, sort_keys=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, out)
        tmp = None
    finally:
        if tmp is not None and os.path.exists(tmp):
            os.unlink(tmp)
            logger.error("removed partial output %s", tmp)


def print_summary(payload, stream):
    """Print the fix list and both rankings as plain tables."""
    records = payload["commits"]
    spots = payload["hotspots"]
    print("repo: %s" % payload["repo"], file=stream)
    print("window: %s" % (payload["since"] or "whole history"), file=stream)
    print("fix candidates: %d (%d fork merges, %d keyword)"
          % (payload["counts"]["total"], payload["counts"]["fork_merge"],
             payload["counts"]["keyword"]), file=stream)
    print(file=stream)
    print("commit  date        release   signal      subject", file=stream)
    for rec in records:
        print("%-7s %-11s %-9s %-11s %s"
              % (rec["sha"][:7], rec["date"], rec["first_release_tag"] or "-",
                 rec["signal"], rec["subject"][:70]), file=stream)
    print(file=stream)
    print("files by fix commits", file=stream)
    for row in spots["files"][:20]:
        print("  %2d  %s" % (row["fix_commits"], row["path"]), file=stream)
    print(file=stream)
    print("functions by fix commits", file=stream)
    for row in spots["functions"][:25]:
        print("  %2d  %s" % (row["fix_commits"], row["function"]), file=stream)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Mine security fix commits and rank the files and "
                    "functions they touch.")
    parser.add_argument("--repo", default=DEFAULT_REPO,
                        help="checkout to mine (default: %s)" % DEFAULT_REPO)
    parser.add_argument("--since", default=None,
                        help="ISO date bounding the window, YYYY-MM-DD")
    parser.add_argument("--out", default=None,
                        help="write the full record as JSON to this path")
    parser.add_argument("--verbose", action="store_true",
                        help="log every git invocation")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")

    try:
        top = validate_repo(args.repo)
        since = validate_since(args.since)
        out = validate_out(args.out)
    except ValueError as exc:
        logger.error("%s", exc)
        return 1
    except GitError as exc:
        logger.error("%s", exc)
        return 2

    try:
        records = mine(args.repo, since)
    except GitError as exc:
        logger.error("%s", exc)
        return 2

    payload = {
        "repo": top,
        "since": since,
        "counts": {
            "total": len(records),
            "fork_merge": sum(1 for r in records
                              if r["signal"] == "fork merge"),
            "keyword": sum(1 for r in records if r["signal"] == "keyword"),
        },
        "commits": records,
        "hotspots": hotspots(records),
    }

    if out:
        write_json(out, payload)
        logger.info("wrote %s", out)
    print_summary(payload, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
