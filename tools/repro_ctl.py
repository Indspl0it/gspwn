#!/usr/bin/env python3
"""Reproducer extraction and reproduction-rate verification.

Subcommands:
  extract <crash-id>            copy repro from syz workdir -> artifacts/pocs/<id>/,
                                generate repro.c via syz-prog2c when only
                                repro.syz exists
  verify <crash-id> [--runs N]  compile repro.c, run N times, detect the crash
                                via dmesg delta on the registry title keyword,
                                record repro_rate + classification in state

Classification (spec Phase 5): reliable >= 80%, flaky = reproduces but < 80%,
unreproducible = 0/N. Clean-boot verification is orchestrated by the poc agent
(it reboots between runs); this tool provides the per-run mechanics.
"""
import argparse
import glob
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
SYZKALLER = os.path.join(REPO_ROOT, "artifacts", "src", "syzkaller")
SYZ_WORKDIR = os.path.join(REPO_ROOT, "artifacts", "syz-workdir")


def crash_dir(cid):
    c = ps.load()["crashes"].get(cid)
    if not c:
        sys.exit("unknown crash id: " + cid)
    return c["dir"]


def cmd_extract(cid):
    src = crash_dir(cid)
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


def cmd_verify(cid, runs):
    dest = os.path.join(REPO_ROOT, "artifacts", "pocs", cid)
    src = os.path.join(dest, "repro.c")
    exe = os.path.join(dest, "repro")
    if not os.path.exists(exe):
        if not os.path.exists(src):
            sys.exit("no repro.c in " + dest + " (run extract first)")
        subprocess.run(["gcc", "-pthread", "-static", "-o", exe, src],
                       check=True)
    state = ps.load()
    title_kw = state["crashes"][cid]["title"].split(" in ")[0][:40]
    hits = 0
    for i in range(runs):
        before = dmesg_text()
        subprocess.run([exe], timeout=120,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        after = dmesg_text()
        delta = after[len(before):]
        if title_kw in delta or "KASAN" in delta or "BUG:" in delta:
            hits += 1
        print("run %d/%d: %s" % (i + 1, runs,
                                 "CRASH" if title_kw in delta else "clean"))
    rate = hits / runs
    status = ("reliable" if rate >= 0.8
              else "flaky" if hits > 0 else "unreproducible")
    state["crashes"][cid]["repro_rate"] = rate
    state["crashes"][cid]["status"] = status
    ps.save(state)
    print("%s: %d/%d (%.0f%%) -> %s" % (cid, hits, runs, rate * 100, status))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("extract"); p.add_argument("crash_id")
    p = sub.add_parser("verify"); p.add_argument("crash_id")
    p.add_argument("--runs", type=int, default=10)
    a = ap.parse_args()
    if a.cmd == "extract":
        cmd_extract(a.crash_id)
    else:
        cmd_verify(a.crash_id, a.runs)


if __name__ == "__main__":
    main()
