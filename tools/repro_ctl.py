#!/usr/bin/env python3
"""Reproducer extraction and reproduction-rate verification.

Subcommands:
  extract <crash-id>            copy repro from syz workdir -> artifacts/pocs/<id>/,
                                generate repro.c via syz-prog2c when only
                                repro.syz exists
  verify <crash-id> [--runs N]  compile repro.c, run N times, detect the crash
                                via dmesg delta on the registry title keyword,
                                record repro_rate + classification in state
                                [--restart] discard partial progress first

Classification (spec Phase 5): reliable >= 80%, flaky = reproduces but < 80%,
unreproducible = 0/N. Clean-boot verification is orchestrated by the poc agent
(it reboots between runs); this tool provides the per-run mechanics.

Panic durability: a good kernel reproducer will often take the machine down
mid-verification. Progress is persisted before and after every run, so a run
that panics the box is recovered (and counted) on the next invocation instead
of being lost — which would otherwise make the most severe bugs look
unreproducible.
"""
import argparse
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
SYZKALLER = os.path.join(REPO_ROOT, "artifacts", "src", "syzkaller")
SYZ_WORKDIR = os.path.join(REPO_ROOT, "artifacts", "syz-workdir")

# Signatures that count as a reproduction, checked against the dmesg delta.
CRASH_PATTERNS = ("KASAN:", "BUG:", "Kernel panic", "general protection fault",
                  "Oops")


def crash_entry(cid):
    c = ps.load()["crashes"].get(cid)
    if not c:
        sys.exit("unknown crash id: " + cid)
    return c


def cmd_extract(cid):
    src = crash_entry(cid)["dir"]
    dest = os.path.join(REPO_ROOT, "artifacts", "pocs", cid)
    os.makedirs(dest, exist_ok=True)
    copied = []
    for name in ("repro.syz", "repro.cprog", "repro.c", "repro0", "report",
                 "description", "log"):
        p = os.path.join(src, name)
        if os.path.exists(p):
            shutil.copy(p, dest)
            copied.append(name)
    syz = os.path.join(dest, "repro.syz")
    c_out = os.path.join(dest, "repro.c")
    if os.path.exists(syz) and not os.path.exists(c_out):
        prog2c = os.path.join(SYZKALLER, "bin", "syz-prog2c")
        exe = os.path.join(SYZKALLER, "bin", "syz-execprog")
        with open(c_out, "w") as f:
            subprocess.run([prog2c, "-prog", syz, "-repeat", "1",
                            "-procs", "1", "-sandbox", "namespace",
                            "-exe", exe], check=True, stdout=f)
        copied.append("repro.c (generated)")
    print("extracted to %s: %s" % (dest, ", ".join(copied) or "NOTHING"))


def dmesg_text():
    r = subprocess.run(["dmesg"], capture_output=True, text=True)
    return r.stdout


def dmesg_delta(before, after):
    """New dmesg text in `after` relative to `before`.

    dmesg is a ring buffer: under KASAN spam the old head gets evicted, so a
    plain length-slice can silently return the wrong window and miss the
    reproduction. Anchor on the tail of `before` instead; if that anchor is
    gone the ring wrapped, and we return the whole buffer (conservative — a
    false 'looks like a crash' gets read by a human, a missed one does not).
    """
    if after.startswith(before):
        return after[len(before):]
    anchor = before[-512:]
    if anchor:
        i = after.rfind(anchor)
        if i != -1:
            return after[i + len(anchor):]
    return after


def matched_signature(delta, title_kw):
    """Return the signature that fired, or None. One predicate for both the
    hit count and the printed log line — they must never disagree."""
    if title_kw and title_kw in delta:
        return title_kw
    for pat in CRASH_PATTERNS:
        if pat in delta:
            return pat
    return None


def _progress(c):
    return c.get("repro_progress") or {"runs_done": 0, "hits": 0,
                                       "in_flight": False}


def cmd_verify(cid, runs, restart):
    dest = os.path.join(REPO_ROOT, "artifacts", "pocs", cid)
    src = os.path.join(dest, "repro.c")
    exe = os.path.join(dest, "repro")
    if not os.path.exists(exe):
        if not os.path.exists(src):
            sys.exit("no repro.c in " + dest + " (run extract first)")
        subprocess.run(["gcc", "-pthread", "-static", "-o", exe, src],
                       check=True)

    with ps.transaction() as st:
        if cid not in st["crashes"]:
            sys.exit("unknown crash id: " + cid)
        c = st["crashes"][cid]
        title_kw = c["title"].split(" in ")[0][:40]
        if restart:
            c["repro_progress"] = {"runs_done": 0, "hits": 0,
                                   "in_flight": False}
        prog = _progress(c)
        # A run marked in_flight that we are now re-entering means the machine
        # went down during it. That is a reproduction, not a lost run.
        recovered = prog["in_flight"]
        if recovered:
            prog = {"runs_done": prog["runs_done"], "hits": prog["hits"] + 1,
                    "in_flight": False}
            c["repro_progress"] = prog
        c["repro_progress"] = prog

    if recovered:
        print("recovered run %d: machine went down mid-run -> counted as CRASH"
              % prog["runs_done"])
    done, hits = prog["runs_done"], prog["hits"]
    if done >= runs:
        print("already completed %d/%d runs; use --restart to redo"
              % (done, runs))

    for i in range(done, runs):
        with ps.transaction() as st:
            st["crashes"][cid]["repro_progress"] = {
                "runs_done": i + 1, "hits": hits, "in_flight": True}
        before = dmesg_text()
        try:
            subprocess.run([exe], timeout=120, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
        after = dmesg_text()
        sig = matched_signature(dmesg_delta(before, after), title_kw)
        if sig:
            hits += 1
        with ps.transaction() as st:
            st["crashes"][cid]["repro_progress"] = {
                "runs_done": i + 1, "hits": hits, "in_flight": False}
        print("run %d/%d: %s%s" % (
            i + 1, runs,
            "CRASH (%s)" % sig if sig else "clean",
            " [repro timed out]" if timed_out else ""))

    rate = hits / runs if runs else 0.0
    status = ("reliable" if rate >= 0.8
              else "flaky" if hits > 0 else "unreproducible")
    with ps.transaction() as st:
        c = st["crashes"][cid]
        c["repro_rate"] = rate
        c["status"] = status
        c["repro_progress"] = {"runs_done": runs, "hits": hits,
                               "in_flight": False}
    print("%s: %d/%d (%.0f%%) -> %s" % (cid, hits, runs, rate * 100, status))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("extract"); p.add_argument("crash_id")
    p = sub.add_parser("verify"); p.add_argument("crash_id")
    p.add_argument("--runs", type=int, default=10)
    p.add_argument("--restart", action="store_true",
                   help="discard partial progress and start from run 1")
    a = ap.parse_args()
    if a.cmd == "extract":
        cmd_extract(a.crash_id)
    else:
        if a.runs < 1:
            sys.exit("--runs must be >= 1")
        cmd_verify(a.crash_id, a.runs, a.restart)


if __name__ == "__main__":
    main()
