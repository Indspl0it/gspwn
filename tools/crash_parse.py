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
    """Add a crash to the registry, or explain why it was not added.

    A collision in one key but not the other may be a second bug or the same
    bug reported twice; distinguishing them requires reading both reports.
    Such a crash is registered as `flagged`, so it persists in the registry
    and `crash-list --status flagged` serves as the review queue. A crash
    reported only in log output would not be addressable once that output is
    gone.
    """
    by_title, by_hash = existing_keys(state)
    other_cid = None
    if title in by_title:
        other_cid = by_title[title]
        if state["crashes"][other_cid]["stack_hash"] == shash:
            # Same title AND same stack: the same crash, already registered.
            # Re-scans must be idempotent — harvest runs after every reboot.
            print("DUP %s -> %s" % (title, other_cid))
            return None
        reason = "same title as %s, different stack" % other_cid
    elif shash in by_hash:
        other_cid = by_hash[shash]
        reason = "same stack as %s, different title" % other_cid
    status = "flagged" if other_cid else "unique"
    cid = ps.register_crash(state, {
        "track": track, "title": title, "stack_hash": shash,
        "status": status, "dir": srcdir, "repro_rate": None,
        "duplicate_of": None, "disclosure": "pending",
        "notes": reason if other_cid else ""})
    if other_cid:
        print("FLAG %s %s (%s) — decide with: pipeline_ctl.py crash-set %s "
              "--duplicate-of %s | --status unique"
              % (cid, title, reason, cid, other_cid))
    else:
        print("NEW %s %s" % (cid, title))
    return cid


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


def resolve_workdir(a, state):
    """Per-run workdir: explicit path, else --run-id, else this round's last run."""
    if a.syz_workdir:
        return a.syz_workdir
    rid = a.run_id
    if not rid:
        run_ids = ps.current_round(state)["run_ids"]
        rid = run_ids[-1] if run_ids else None
    if not rid:
        return None
    return os.path.join(REPO_ROOT, "artifacts", "runs", rid, "workdir")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", dest="run_id",
                    help="scan artifacts/runs/<id>/workdir (default: the last "
                         "run registered in the current round)")
    ap.add_argument("--syz-workdir", default=None,
                    help="explicit workdir path, overriding --run-id")
    ap.add_argument("--track-u-dir",
                    default=os.path.join(REPO_ROOT, "artifacts", "harnesses",
                                         "crashes"))
    ap.add_argument("--dmesg", default=None)
    a = ap.parse_args()
    # One locked read-modify-write: triage may run while the fuzz monitor and
    # other phase agents are also touching the registry.
    with ps.transaction() as state:
        wd = resolve_workdir(a, state)
        if wd is None:
            print("WARN: no run id given and none registered in this round — "
                  "skipping the syzkaller workdir. Pass --run-id, or register "
                  "the run with pipeline_ctl.py round-add-run.")
        elif not os.path.isdir(os.path.join(wd, "crashes")):
            print("WARN: no crashes dir under %s — nothing scanned for Track "
                  "K. Check the run id." % wd)
        else:
            scan_syz(state, wd)
        if os.path.isdir(a.track_u_dir):
            scan_track_u(state, a.track_u_dir)
        elif not a.dmesg:
            print("WARN: %s missing — nothing scanned for Track U."
                  % a.track_u_dir)
        if a.dmesg and os.path.exists(a.dmesg):
            scan_dmesg(state, a.dmesg)
        total = len(state["crashes"])
        flagged = sum(1 for c in state["crashes"].values()
                      if c["status"] == "flagged")
    print("registry now holds %d crashes" % total)
    if flagged:
        print("%d flagged — every one needs a decision before the triage gate "
              "holds: python3 tools/pipeline_ctl.py crash-list --status flagged"
              % flagged)


if __name__ == "__main__":
    main()
