#!/usr/bin/env python3
"""Append to knowledge/ — what the campaigns have taught, across all of them.

This is the Knowledge plane, and it is deliberately not part of pipeline.json.
The state file answers "where is this campaign", resets its round phases every
round, and is gitignored. These files answer "what do we know", never reset,
and are committed. A fact belongs to exactly one of them: putting execution
position here produces a file that looks authoritative and drifts, and putting
knowledge in the state file loses it when the box is rebuilt.

Two files, split by who the fact is about:

  knowledge/learnings.md  — about the target. Audience: describe, seeds, rca.
  knowledge/mistakes.md   — about us. Audience: the next agent doing that job.

The test: "UVM ioctl numbering does not follow the RM escape convention" is a
learning. "I marked the phase done before reading the smoke log" is a mistake.

PUBLIC REPO. These files are committed, so they carry ABI facts and process
notes and never findings. Vulnerability detail lives in the crash registry
(state/pipeline.json, gitignored) and its research record. `note` refuses text
that names a crash id for that reason — see _check_disclosure.

Subcommands:
  note --kind learning|mistake --phase P "text" [--tags a,b]
  show [--kind K] [--phase P] [--last N]

Exit codes: 0 ok, 1 problem, 2 usage error.
"""
import argparse
import fcntl
import os
import re
import sys
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_state as ps

# GSPWN_KNOWLEDGE redirects the directory (tools/selftest.py points it at a
# tempdir). Unlike the state file this has no per-run use: knowledge is
# machine- and campaign-independent by design.
KNOWLEDGE_DIR = os.environ.get("GSPWN_KNOWLEDGE") or os.path.join(
    ps.REPO_ROOT, "knowledge")

KINDS = ("learning", "mistake")
FILENAME = {"learning": "learnings.md", "mistake": "mistakes.md"}
KIND_OF = {v: k for k, v in FILENAME.items()}

HEADER = {
    "learning": """# Learnings

What the campaigns have established about the target: ABI facts, driver
behaviour, tooling quirks. Carried across every campaign, on every box.

Audience: the `describe`, `seeds` and `rca` agents of later rounds. Write for
someone who has the source open and does not have your context.

PUBLIC REPO: ABI and behaviour only, never findings. A specific vulnerability
belongs in the crash registry and its research record, both gitignored.

Appended by `tools/knowledge_ctl.py note --kind learning`. Do not hand-edit:
the tool timestamps and locks, and hand-edits are how the format rots.
""",
    "mistake": """# Mistakes

Process errors and what avoids them next time. About us, not about the driver.

Audience: the next agent running that phase. A mistake worth recording is one
that cost a round, produced a wrong number, or would repeat.

Generalise. "Marked the phase done on the subagent's assertion without reading
the smoke log" is reusable; the same sentence naming one crash is not.

PUBLIC REPO: process notes only, never findings.

Appended by `tools/knowledge_ctl.py note --kind mistake`. Do not hand-edit:
the tool timestamps and locks, and hand-edits are how the format rots.
""",
}

# A crash id in a committed file is finding data by definition. The generalised
# form of the same note is both publishable and more useful to the next agent,
# so this refuses rather than warns.
CRASH_REF_RE = re.compile(r"\bcrash-\d{3,}\b", re.I)
ARTIFACT_REF_RE = re.compile(r"artifacts/(?:crashes|pocs|rca)/", re.I)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _path(kind):
    return os.path.join(KNOWLEDGE_DIR, FILENAME[kind])


def _check_disclosure(text):
    """Refuse text that carries finding data into a committed file."""
    hit = CRASH_REF_RE.search(text) or ARTIFACT_REF_RE.search(text)
    if not hit:
        return
    raise ValueError(
        "refusing to record a note naming %r: knowledge/ is committed to a "
        "public repo, and anything tied to a specific crash is finding data. "
        "Record the general form instead — the lesson that applies to the "
        "next crash of that shape — and keep the specifics in the crash "
        "registry (`pipeline_ctl.py crash-set <id> --notes`) or its research "
        "record (`pipeline_ctl.py finding-set`)." % hit.group(0))


def _atomic_append(path, block):
    """Append one entry, atomically, under an exclusive lock.

    Plain `open(path, "a")` would be shorter, but this pipeline runs on a
    machine that panics on purpose and allows parallel phase agents. A panic
    mid-append leaves a torn entry, and two agents appending at once interleave
    their lines. Read-modify-write through a tempfile and rename gives the same
    durability guarantee the state file has.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    lock = path + ".lock"
    fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        existing = ""
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                existing = f.read()
        if not existing.strip():
            existing = HEADER[KIND_OF[os.path.basename(path)]]
        text = existing.rstrip("\n") + "\n\n" + block.strip("\n") + "\n"
        d = os.path.dirname(path) or "."
        tfd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
        try:
            with os.fdopen(tfd, "w", encoding="utf-8") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        dfd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    ps._fix_root_ownership([path, lock])


def _entries(kind):
    """Parse a knowledge file back into [(timestamp, phase, tags, body)]."""
    path = _path(kind)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        text = f.read()
    out = []
    for chunk in text.split("\n## ")[1:]:
        head, _, body = chunk.partition("\n")
        ts, _, phase = head.partition(" — ")
        tags = ""
        lines = body.strip("\n").split("\n")
        if lines and lines[0].startswith("Tags: "):
            tags = lines[0][len("Tags: "):].strip()
            lines = lines[1:]
        out.append((ts.strip(), phase.strip(), tags,
                    "\n".join(lines).strip("\n")))
    return out


def cmd_note(a):
    text = (a.text or "").strip()
    if not text:
        sys.exit("error: a note needs text")
    try:
        _check_disclosure(text)
    except ValueError as e:
        sys.exit("error: %s" % e)
    tags = [t.strip() for t in (a.tags or "").split(",") if t.strip()]
    block = "## %s — %s\n" % (_now(), a.phase)
    if tags:
        block += "Tags: %s\n" % ", ".join(tags)
    block += text + "\n"
    path = _path(a.kind)
    _atomic_append(path, block)
    print("recorded %s (%s): %s"
          % (a.kind, a.phase, text if len(text) <= 60 else text[:57] + "..."))
    # Relative only when it actually is inside the repo: a redirected
    # GSPWN_KNOWLEDGE otherwise prints a path of ".." segments.
    shown = os.path.relpath(path, ps.REPO_ROOT)
    print("  %s" % (path if shown.startswith("..") else shown))
    return 0


def cmd_show(a):
    kinds = [a.kind] if a.kind else list(KINDS)
    shown = 0
    for kind in kinds:
        rows = _entries(kind)
        if a.phase:
            rows = [r for r in rows if r[1] == a.phase]
        if a.last:
            rows = rows[-a.last:]
        if not rows:
            continue
        print("== %s (%d)" % (FILENAME[kind], len(rows)))
        for ts, phase, tags, body in rows:
            print("  %s  [%s]%s" % (ts, phase,
                                    "  {%s}" % tags if tags else ""))
            for line in body.split("\n"):
                print("      %s" % line)
        shown += len(rows)
    if not shown:
        print("no notes recorded yet")
    return 0


def build_parser():
    ap = argparse.ArgumentParser(
        prog="knowledge_ctl.py",
        description="Append to knowledge/ (facts that outlive the campaign).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("note", help="record a learning or a mistake")
    p.add_argument("text", help="the note. Learnings are about the target, "
                                "mistakes are about us. Generalise: it is "
                                "read by a later campaign on another box.")
    p.add_argument("--kind", required=True, choices=KINDS)
    p.add_argument("--phase", required=True, choices=ps.PHASES,
                   help="the phase this came out of")
    p.add_argument("--tags", default="",
                   help="comma-separated, e.g. nvidia_uvm,abi")
    p.set_defaults(fn=cmd_note)

    p = sub.add_parser("show", help="read the knowledge files back")
    p.add_argument("--kind", choices=KINDS)
    p.add_argument("--phase", choices=ps.PHASES)
    p.add_argument("--last", type=int, metavar="N",
                   help="only the most recent N entries per file")
    p.set_defaults(fn=cmd_show)
    return ap


def main():
    a = build_parser().parse_args()
    try:
        sys.exit(a.fn(a))
    except ValueError as e:
        sys.exit("error: %s" % e)


if __name__ == "__main__":
    main()
