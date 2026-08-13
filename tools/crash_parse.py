#!/usr/bin/env python3
"""Harvest crashes from both tracks and dedup into state/pipeline.json.

Dedup (spec Phase 4): primary key = normalized report title (syzkaller
'description' file / ASan summary line). Secondary = stack hash (sha1 of
top-3 function frames). Collisions in either direction are flagged for
manual review.
"""
import argparse
import glob
import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
FRAME_RE = re.compile(r"#\d+\s+(?:0x[0-9a-f]+\s+)?(?:in\s+)?([\w.~]+)\s*\+?")
ASAN_RE = re.compile(r"^(?:==\d+==)?\s*(ERROR: (?:Address|Memory|Leak)?Sanitizer[^\n]*|SUMMARY: [^\n]*)", re.M)
NVRM_RE = re.compile(r"NVRM: (Xid[^\n]*|GPU at[^\n]*error[^\n]*)", re.I)
KERN_RE = re.compile(r"(BUG: [^\n]*|KASAN: [^\n]*|Kernel panic[^\n]*|Oops[^\n]*)")


def norm_title(t):
    return re.sub(r"\s+", " ", t.strip())


def stack_hash(report_text):
    frames = FRAME_RE.findall(report_text)[:3]
    return hashlib.sha1("|".join(frames).encode()).hexdigest()[:16]


def existing_keys(state):
    """-> (title->cid, hash->cid)"""
    by_title, by_hash = {}, {}
    for cid, c in state["crashes"].items():
        by_title[c["title"]] = cid
        by_hash.setdefault(c["stack_hash"], cid)
    return by_title, by_hash


def register(state, track, title, shash, srcdir):
    by_title, by_hash = existing_keys(state)
    if title in by_title:
        other = state["crashes"][by_title[title]]
        if other["stack_hash"] != shash:
            print("FLAG same-title-different-stack: %s vs %s"
                  % (by_title[title], title))
        print("DUP %s -> %s" % (title, by_title[title]))
        return
    if shash in by_hash:
        print("FLAG same-stack-different-title: %s vs %s"
              % (title, state["crashes"][by_hash[shash]]["title"]))
    cid = ps.register_crash(state, {
        "track": track, "title": title, "stack_hash": shash,
        "status": "unique", "dir": srcdir, "repro_rate": None,
        "duplicate_of": None, "disclosure": "pending"})
    print("NEW %s %s" % (cid, title))


def scan_syz(state, workdir):
    for cdir in sorted(glob.glob(os.path.join(workdir, "crashes", "*"))):
        desc = os.path.join(cdir, "description")
        report = os.path.join(cdir, "report")
        if not os.path.exists(desc):
            continue
        title = norm_title(read_text(desc))
        rtext = read_text(report) if os.path.exists(report) else ""
        register(state, "K", title, stack_hash(rtext), cdir)


def scan_track_u(state, udir):
    for f in sorted(glob.glob(os.path.join(udir, "*"))):
        if not os.path.isfile(f):
            continue
        text = read_text(f)
        m = ASAN_RE.search(text)
        title = norm_title(m.group(1)) if m else \
            "libfuzzer-crash:" + os.path.basename(f)
        register(state, "U", title, stack_hash(text), f)


def read_text(path):
    with open(path, errors="replace") as f:
        return f.read()


def scan_dmesg(state, path):
    text = read_text(path)
    for m in NVRM_RE.finditer(text):
        register(state, "K", norm_title("NVRM " + m.group(1)),
                 hashlib.sha1(m.group(1).encode()).hexdigest()[:16], path)
    for m in KERN_RE.finditer(text):
        register(state, "K", norm_title("kernel " + m.group(1)),
                 hashlib.sha1(m.group(1).encode()).hexdigest()[:16], path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--syz-workdir",
                    default=os.path.join(REPO_ROOT, "artifacts", "syz-workdir"))
    ap.add_argument("--track-u-dir",
                    default=os.path.join(REPO_ROOT, "artifacts", "harnesses",
                                         "crashes"))
    ap.add_argument("--dmesg", default=None)
    a = ap.parse_args()
    # One locked read-modify-write: triage may run while the fuzz monitor and
    # other phase agents are also touching the registry.
    with ps.transaction() as state:
        if os.path.isdir(os.path.join(a.syz_workdir, "crashes")):
            scan_syz(state, a.syz_workdir)
        if os.path.isdir(a.track_u_dir):
            scan_track_u(state, a.track_u_dir)
        if a.dmesg and os.path.exists(a.dmesg):
            scan_dmesg(state, a.dmesg)
        total = len(state["crashes"])
    print("registry now holds %d crashes" % total)


if __name__ == "__main__":
    main()
