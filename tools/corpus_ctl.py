#!/usr/bin/env python3
"""Promote programs from a finished run's corpus into the persistent seed bank.

The outer improvement loop needs a memory. syzkaller's corpus.db lives inside
one run's workdir and dies with it; artifacts/seeds/ is the bank that outlives
rounds and is what later rounds (and the seeded ablation arm) start from.

Promotion is deliberately additive and deduplicated by content hash: a program
already in the bank is never written twice, so repeated promotion across rounds
converges instead of growing without bound.

Promotion honours loop.promote_seeds in config/campaign.yaml: when the config
freezes the bank (e.g. to hold an ablation baseline stable), promote refuses.

Subcommands:
  promote --run-id ID [--seeds DIR] [--limit N] [--dry-run]
                                  unpack the run's corpus and add new programs
  stats [--seeds DIR]             size and provenance of the seed bank

Requires syz-db from the pinned syzkaller build (artifacts/src/syzkaller/bin).
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gspwn_config
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
SEEDS_DIR = os.path.join(REPO_ROOT, "artifacts", "seeds")
RUNS_DIR = os.path.join(REPO_ROOT, "artifacts", "runs")
SYZ_DB = os.path.join(REPO_ROOT, "artifacts", "src", "syzkaller", "bin",
                      "syz-db")
LEDGER = "promoted.json"


def corpus_db(run_id):
    return os.path.join(RUNS_DIR, run_id, "workdir", "corpus.db")


def prog_hash(text):
    """Content hash over the normalized program text."""
    norm = "\n".join(ln.strip() for ln in text.strip().splitlines()
                     if ln.strip() and not ln.strip().startswith("#"))
    return hashlib.sha1(norm.encode()).hexdigest()[:16]


def load_ledger(seeds):
    path = os.path.join(seeds, LEDGER)
    if not os.path.exists(path):
        return {"hashes": {}}
    try:
        with open(path) as f:
            data = json.load(f)
        data.setdefault("hashes", {})
        return data
    except (ValueError, OSError):
        print("WARN: %s unreadable; rebuilding from the .syz files present"
              % path)
        return {"hashes": {}}


def save_ledger(seeds, ledger):
    path = os.path.join(seeds, LEDGER)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(ledger, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def existing_hashes(seeds, ledger):
    """Ledger plus anything on disk it does not know about."""
    known = dict(ledger["hashes"])
    if not os.path.isdir(seeds):
        return known
    for name in os.listdir(seeds):
        if not name.endswith(".syz"):
            continue
        path = os.path.join(seeds, name)
        try:
            with open(path, errors="replace") as f:
                h = prog_hash(f.read())
        except OSError:
            continue
        known.setdefault(h, {"file": name, "source": "pre-existing"})
    return known


def unpack_corpus(db, dest):
    if not os.path.exists(SYZ_DB):
        sys.exit("syz-db not found at %s — build syzkaller first (provision "
                 "phase step 6)" % SYZ_DB)
    r = subprocess.run([SYZ_DB, "unpack", db, dest], capture_output=True,
                       text=True)
    if r.returncode != 0:
        sys.exit("syz-db unpack failed: %s" % (r.stderr.strip() or
                                               r.stdout.strip()))
    return sorted(os.listdir(dest))


def cmd_promote(a):
    try:
        promote_allowed = gspwn_config.load()["loop"]["promote_seeds"]
    except gspwn_config.ConfigError as e:
        sys.exit("error: %s" % e)
    if not promote_allowed:
        sys.exit("loop.promote_seeds is false in config/campaign.yaml: the "
                 "seed bank is frozen (e.g. to hold an ablation baseline "
                 "stable), so promotion is refused. Set it to true to "
                 "promote this run's corpus.")
    db = corpus_db(a.run_id)
    if not os.path.exists(db):
        sys.exit("no corpus.db for run %s (looked at %s)" % (a.run_id, db))
    seeds = a.seeds or SEEDS_DIR
    os.makedirs(seeds, exist_ok=True)
    ledger = load_ledger(seeds)
    known = existing_hashes(seeds, ledger)

    with tempfile.TemporaryDirectory() as tmp:
        names = unpack_corpus(db, tmp)
        added = skipped = 0
        for name in names:
            if a.limit and added >= a.limit:
                break
            src = os.path.join(tmp, name)
            if not os.path.isfile(src):
                continue
            with open(src, errors="replace") as f:
                text = f.read()
            if not text.strip():
                continue
            h = prog_hash(text)
            if h in known:
                skipped += 1
                continue
            out_name = "promoted-%s-%s.syz" % (a.run_id, h)
            if not a.dry_run:
                shutil.copy(src, os.path.join(seeds, out_name))
                ledger["hashes"][h] = {"file": out_name, "source": a.run_id}
            known[h] = {"file": out_name, "source": a.run_id}
            added += 1

    if not a.dry_run:
        save_ledger(seeds, ledger)
    print("%s: %d new program(s) %s %s, %d already known (corpus held %d)"
          % (a.run_id, added, "would be added to" if a.dry_run else "added to",
             seeds, skipped, len(names)))
    if a.limit and added >= a.limit:
        print("NOTE: stopped at --limit %d; %d corpus entries were not "
              "considered. The bank is now a truncated sample of this run, "
              "not all of it." % (a.limit, len(names) - a.limit - skipped))
    if added == 0:
        print("The run produced nothing the bank did not already have — that "
              "is the corpus-level signal that this round stopped learning.")
    return 0


def cmd_stats(a):
    seeds = a.seeds or SEEDS_DIR
    if not os.path.isdir(seeds):
        print("no seed bank at %s" % seeds)
        return 1
    files = {f for f in os.listdir(seeds) if f.endswith(".syz")}
    ledger = load_ledger(seeds)
    # Reconcile the ledger against what is actually on disk: entries whose
    # file was since deleted must not count toward any source, or the
    # untracked figure (files minus ledger) goes negative/wrong.
    by_source = {}
    tracked = set()
    stale = 0
    for meta in ledger["hashes"].values():
        name = meta.get("file")
        if name not in files:
            stale += 1
            continue
        src = meta.get("source", "?")
        by_source[src] = by_source.get(src, 0) + 1
        tracked.add(name)
    print("seed bank %s: %d program(s)" % (seeds, len(files)))
    for src, n in sorted(by_source.items()):
        print("  %-24s %d" % (src, n))
    untracked = len(files) - len(tracked)
    if untracked > 0:
        print("  %-24s %d (trace-derived or hand-added)"
              % ("untracked", untracked))
    if stale:
        print("  (%d ledger entrie(s) reference deleted files; not counted)"
              % stale)
    return 0


def build_parser():
    ap = argparse.ArgumentParser(prog="corpus_ctl.py",
                                 description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("promote")
    p.add_argument("--run-id", required=True)
    p.add_argument("--seeds")
    p.add_argument("--limit", type=int, default=0,
                   help="cap programs added this call (0 = no cap)")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_promote)

    p = sub.add_parser("stats")
    p.add_argument("--seeds")
    p.set_defaults(fn=cmd_stats)
    return ap


def main():
    a = build_parser().parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
