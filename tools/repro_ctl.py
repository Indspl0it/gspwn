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
that panics the box is recovered on the next invocation instead of being lost
— which would otherwise make the most severe bugs look unreproducible. The
recovered run counts as a reproduction only if the boot id changed, i.e. the
machine actually went down; a verification process that merely died on the
same boot is void.

The rate is hits / counted runs. Void runs — those that produced no usable
verdict — are excluded from both the numerator and the denominator, and are
re-run rather than resolved by assumption.
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
    """New dmesg text in `after` relative to `before`, and whether the ring
    buffer wrapped past our anchor.

    dmesg is a ring buffer: under KASAN spam the old head gets evicted, so a
    plain length-slice can silently return the wrong window and miss the
    reproduction. Anchor on the tail of `before` instead. If that anchor is
    gone, the ring wrapped and no delta can be computed — the remaining buffer
    holds crash reports from *earlier* runs, so scanning it would score a hit
    on every subsequent run and turn an unreproducible crash into a 10/10.
    Report the wrap so the caller can void the run.
    """
    if after.startswith(before):
        return after[len(before):], False
    anchor = before[-512:]
    if anchor:
        i = after.rfind(anchor)
        if i != -1:
            return after[i + len(anchor):], False
    return after, True


def matched_signature(delta, title_kw):
    """Return the signature that fired, or None. One predicate for both the
    hit count and the printed log line — they must never disagree."""
    if title_kw and title_kw in delta:
        return title_kw
    for pat in CRASH_PATTERNS:
        if pat in delta:
            return pat
    return None


PROGRESS_DEFAULT = {"runs_done": 0, "hits": 0, "inconclusive": 0,
                    "in_flight": False, "boot_id": None}


def boot_id():
    """Identifier of the running kernel boot, or None if unavailable.

    Used to tell a machine that panicked (new boot id) from a verification
    process that merely died locally (same boot id).
    """
    try:
        with open("/proc/sys/kernel/random/boot_id") as f:
            return f.read().strip() or None
    except OSError:
        return None


def _progress(c):
    return dict(PROGRESS_DEFAULT, **(c.get("repro_progress") or {}))


def cmd_verify(cid, runs, restart):
    dest = os.path.join(REPO_ROOT, "artifacts", "pocs", cid)
    src = os.path.join(dest, "repro.c")
    exe = os.path.join(dest, "repro")
    if not os.path.exists(exe):
        if not os.path.exists(src):
            sys.exit("no repro.c in " + dest + " (run extract first)")
        subprocess.run(["gcc", "-pthread", "-static", "-o", exe, src],
                       check=True)

    now_boot = boot_id()
    with ps.transaction() as st:
        if cid not in st["crashes"]:
            sys.exit("unknown crash id: " + cid)
        c = st["crashes"][cid]
        title_kw = c["title"].split(" in ")[0][:40]
        if restart:
            c["repro_progress"] = dict(PROGRESS_DEFAULT)
        prog = _progress(c)
        # A run left in_flight ended without recording a verdict. Only a
        # reboot proves the kernel went down; if we are still on the boot that
        # started the run, the verification process itself died (Ctrl-C, OOM
        # kill, a repro that will not exec) and counting that as a
        # reproduction would inflate the rate that gates disclosure.
        recovery = None
        if prog["in_flight"]:
            was_boot = prog.get("boot_id")
            if now_boot and was_boot and now_boot != was_boot:
                prog["hits"] += 1
                recovery = ("run %d: machine rebooted mid-run "
                            "-> counted as CRASH" % prog["runs_done"])
            else:
                prog["inconclusive"] += 1
                recovery = ("run %d: ended without a verdict on the same boot "
                            "-> VOID (not counted either way)"
                            % prog["runs_done"])
            prog["in_flight"] = False
        c["repro_progress"] = prog

    if recovery:
        print("recovered " + recovery)
    hits, runs_done, inconclusive = (prog["hits"], prog["runs_done"],
                                     prog["inconclusive"])

    def counted_now():
        return max(runs_done - inconclusive, 0)

    if counted_now() >= runs:
        print("already have %d counted run(s) (>= %d requested); "
              "use --restart to redo" % (counted_now(), runs))

    # Void runs do not advance the count, so keep going until `runs` verdicts
    # land — but cap total attempts so a persistently wrapping ring buffer
    # cannot loop forever.
    attempt_cap = runs_done + 2 * max(runs - counted_now(), 0) + 5
    while counted_now() < runs:
        if runs_done >= attempt_cap:
            print("giving up after %d attempts: too many void runs"
                  % runs_done)
            break
        runs_done += 1
        with ps.transaction() as st:
            st["crashes"][cid]["repro_progress"] = {
                "runs_done": runs_done, "hits": hits,
                "inconclusive": inconclusive, "in_flight": True,
                "boot_id": now_boot}
        before = dmesg_text()
        timed_out = exec_failed = False
        try:
            subprocess.run([exe], timeout=120, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            timed_out = True
        except OSError as e:
            # The repro never ran, so the run says nothing about the bug.
            # Left uncaught this exits mid-run with in_flight set, which the
            # next invocation would have to reason about.
            exec_failed = str(e)
        after = dmesg_text()
        delta, wrapped = dmesg_delta(before, after)
        sig = None if (wrapped or exec_failed) else matched_signature(delta,
                                                                     title_kw)
        if exec_failed:
            inconclusive += 1
            verdict = "VOID (repro would not run: %s)" % exec_failed
        elif wrapped:
            inconclusive += 1
            verdict = "VOID (dmesg ring wrapped; delta not computable)"
        elif sig:
            hits += 1
            verdict = "CRASH (%s)" % sig
        else:
            verdict = "clean"
        with ps.transaction() as st:
            st["crashes"][cid]["repro_progress"] = {
                "runs_done": runs_done, "hits": hits,
                "inconclusive": inconclusive, "in_flight": False,
                "boot_id": now_boot}
        print("run %d (%d/%d counted): %s%s" % (
            runs_done, counted_now(), runs, verdict,
            " [repro timed out]" if timed_out else ""))

    counted = counted_now()
    if not counted:
        print("%s: 0 counted runs (%d void) — no rate recorded"
              % (cid, inconclusive))
        return 1
    rate = hits / counted
    status = ("reliable" if rate >= 0.8
              else "flaky" if hits > 0 else "unreproducible")
    with ps.transaction() as st:
        c = st["crashes"][cid]
        c["repro_rate"] = rate
        c["status"] = status
        c["repro_progress"] = {"runs_done": runs_done, "hits": hits,
                               "inconclusive": inconclusive,
                               "in_flight": False, "boot_id": now_boot}
    print("%s: %d/%d (%.0f%%) -> %s%s"
          % (cid, hits, counted, rate * 100, status,
             " [%d void run(s) excluded]" % inconclusive if inconclusive
             else ""))
    return 0


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
        sys.exit(cmd_verify(a.crash_id, a.runs, a.restart) or 0)


if __name__ == "__main__":
    main()
