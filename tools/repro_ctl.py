#!/usr/bin/env python3
"""Reproducer extraction and reproduction-rate verification.

Subcommands:
  extract <crash-id> [--force]  Track K: copy repro from the syz workdir ->
                                artifacts/pocs/<id>/, generating repro.c via
                                syz-prog2c when only repro.syz exists.
                                Track U: copy the registry crash input file ->
                                artifacts/pocs/<id>/input (atomic; refuses to
                                clobber different existing content without
                                --force).
  verify <crash-id> [--runs N]  Track K: compile repro.c, run N times, detect
                                the crash via a dmesg-delta match on this
                                crash's signature.
                                Track U: replay artifacts/pocs/<id>/input
                                through --cmd '<template with {input}>' and
                                detect sanitizer signatures in its output.
                                Records repro_rate + classification in state.
                                [--restart] discard partial progress first

The track is read from the registry entry; --track only cross-checks it.

Exit codes (verify): 0 = protocol satisfied (>= --runs counted runs);
1 = precondition failure, or no counted runs so no rate was recorded;
2 = a rate was recorded on fewer counted runs than --runs requested (the
attempt cap fired — the denominator is short, and stdout says so).

Classification (spec Phase 5): reliable >= 80%, flaky = reproduces but < 80%,
unreproducible = 0/N. Clean-boot verification is orchestrated by the poc agent
(it reboots between runs); this tool provides the per-run mechanics.

What counts as a reproduction — and what does not. A run is a hit only when
the evidence ties to *this* crash:

- Track K derives a signature at verify start (normalized title phrases with
  volatile fields removed, plus top stack frames from the registered report)
  and requires it in the dmesg delta. A generic BUG:/Oops in the window never
  scores on its own — the fuzzer panics this box by design, so any-crash
  matching would inflate the rate that gates disclosure.
- On the reboot recovery path, a boot-id change plus a harvested crash log
  (pstore/kdump/console) containing this crash's signature is a hit; a
  boot-id change whose harvested logs show a *different* crash is void (the
  reason is recorded); a boot-id change with no recoverable logs is a hit
  only because the run process died mid-execution — the panic killed it —
  and that weaker evidence class is recorded in repro_progress. A Track U
  replay cannot take the kernel down, so for track U an unexplained reboot
  is void, never a hit.
- A run that times out is never "clean": it is a hit when the crash title
  marks it hang-class (hung task, watchdog, soft lockup, RCU stall,
  deadlock), otherwise void with the reason recorded. Timeouts are counted
  separately (repro_progress["timeouts"]) and broken down in the summary.
- Track U scores on sanitizer signatures in the harness output (ERROR:
  AddressSanitizer / SUMMARY: AddressSanitizer / runtime error: / SEGV /
  ABORTING) or on the --crash-exit condition; harness infrastructure
  failures (command not runnable) are void.

Panic durability: a kernel reproducer will often take the machine down
mid-verification. Progress is persisted before and after every run, so a run
that panics the box is recovered on the next invocation rather than lost.

The rate is hits / counted runs. Void runs — those that produced no usable
verdict — are excluded from both the numerator and the denominator, and are
re-run rather than resolved by assumption. repro_runs_counted and
repro_runs_requested are recorded next to the rate so a short denominator is
visible to any consumer, and every classification is appended to the crash's
history trail instead of silently overwriting the previous status.

Mutual exclusion: verify holds an flock on state/repro.lock for the whole
session. Two concurrent verifiers share one dmesg ring and would corrupt
each other's delta windows, so a second session exits immediately.
"""
import argparse
import fcntl
import glob
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
SYZKALLER = os.path.join(REPO_ROOT, "artifacts", "src", "syzkaller")

REPRO_TIMEOUT = 120          # seconds per run before we call it a hang
REPRO_LOCK = "repro.lock"    # in the state dir, next to .pipeline.lock

# Generic kernel-crash markers. These NEVER score a hit on their own — any
# BUG/Oops in the window is not evidence that *this* crash reproduced. They
# remain useful to describe what a harvested log does show.
CRASH_PATTERNS = ("KASAN:", "BUG:", "Kernel panic", "general protection fault",
                  "Oops")

# Titles of this class describe a hang, so a repro run that itself hangs
# (timeout) is positive evidence rather than no evidence.
HANG_PATTERNS = ("hung task", "task hung", "watchdog", "soft lockup",
                 "softlockup", "rcu_sched", "rcu_preempt", "deadlock")

# Track U: sanitizer output that counts as a reproduction.
SANITIZER_RE = re.compile(r"ERROR: AddressSanitizer|SUMMARY: AddressSanitizer"
                          r"|runtime error:|SEGV|ABORTING")

# Stack frames in report text: syzkaller-style "#2 in nv_foo+0x12/0x34" and
# bare kernel call-trace lines "nv_foo+0x12/0x34 [nvidia]" (incl. RIP lines).
FRAME_RE = re.compile(r"#\d+\s+(?:0x[0-9a-f]+\s+)?(?:in\s+)?([\w.~]+)\s*\+?")
TRACE_RE = re.compile(r"(?:^|\s)(?:in\s+)?([A-Za-z_][\w.~]*)"
                      r"\+0x[0-9a-f]+/0x[0-9a-f]+")

# Fields that change between two reports of the same crash: hex addresses,
# pids, long bare numbers, printk timestamps.
VOLATILE_RE = re.compile(r"0x[0-9a-fA-F]+|\bpid=\d+|\b\d{6,}\b"
                         r"|\[\s*\d+\.\d+\]")


def crash_entry(cid):
    c = ps.load()["crashes"].get(cid)
    if not c:
        sys.exit("unknown crash id: " + cid)
    return c


def _check_track(c, cid, track):
    """The registry is authoritative for the track; --track cross-checks."""
    if track and track.upper() != c["track"]:
        sys.exit("--track %s disagrees with the registry (track %s for %s)"
                 % (track, c["track"], cid))
    return c["track"]


def _atomic_copy(src, dst):
    """Crash-durable copy: temp file + fsync + atomic rename, matching the
    state-file idiom — this pipeline panics the machine by design."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dst), suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f, open(src, "rb") as s:
            shutil.copyfileobj(s, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dst)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _same_file(a, b):
    if os.path.getsize(a) != os.path.getsize(b):
        return False
    with open(a, "rb") as fa, open(b, "rb") as fb:
        return fa.read() == fb.read()


def _generate_repro_c(syz, c_out):
    """syz-prog2c into a temp file; rename into place only on a non-empty
    result. Opening repro.c for writing before prog2c runs leaves an empty
    stub behind on failure, and every later run then trusts the stub."""
    prog2c = os.path.join(SYZKALLER, "bin", "syz-prog2c")
    exe = os.path.join(SYZKALLER, "bin", "syz-execprog")
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(c_out), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            r = subprocess.run([prog2c, "-prog", syz, "-repeat", "1",
                                "-procs", "1", "-sandbox", "namespace",
                                "-exe", exe], stdout=f)
            f.flush()
            os.fsync(f.fileno())
        if r.returncode != 0:
            sys.exit("syz-prog2c failed (rc %d) on %s — repro.c NOT written"
                     % (r.returncode, syz))
        if os.path.getsize(tmp) == 0:
            sys.exit("syz-prog2c produced an empty repro.c from %s — NOT "
                     "writing it" % syz)
        os.replace(tmp, c_out)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _extract_k(cid, c):
    src = c["dir"]
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
    # A zero-byte repro.c is the residue of a failed syz-prog2c, not a real
    # artifact: treat it as missing and regenerate.
    stale = os.path.exists(c_out) and os.path.getsize(c_out) == 0
    if os.path.exists(syz) and (not os.path.exists(c_out) or stale):
        if stale:
            print("existing repro.c is empty (a failed syz-prog2c left a "
                  "stub) — regenerating")
        _generate_repro_c(syz, c_out)
        copied.append("repro.c (generated)")
    print("extracted to %s: %s" % (dest, ", ".join(copied) or "NOTHING"))


def _extract_u(cid, c, force):
    src = c["dir"]
    if not os.path.isfile(src):
        sys.exit("track U crash input is not a file: %s" % src)
    dest = os.path.join(REPO_ROOT, "artifacts", "pocs", cid)
    os.makedirs(dest, exist_ok=True)
    dst = os.path.join(dest, "input")
    if os.path.exists(dst):
        if _same_file(src, dst):
            print("extracted to %s: input (already present, identical)" % dest)
            return
        if not force:
            sys.exit("%s already exists with different content — refusing "
                     "to clobber it without --force" % dst)
        _atomic_copy(src, dst)
        print("extracted to %s: input (overwrote different existing content "
              "via --force)" % dest)
        return
    _atomic_copy(src, dst)
    print("extracted to %s: input" % dest)


def cmd_extract(cid, force=False, track=None):
    c = crash_entry(cid)
    if _check_track(c, cid, track) == "U":
        _extract_u(cid, c, force)
    else:
        _extract_k(cid, c)


def dmesg_text():
    r = subprocess.run(["dmesg"], capture_output=True, text=True)
    return r.stdout


def probe_dmesg():
    """Fail loudly when the ring buffer is unreadable, BEFORE any run is
    scored. With kernel.dmesg_restrict=1 a non-root dmesg yields empty
    stdout (rc varies by util-linux version, so empty output is the reliable
    signal); before == after == "" would score every run 'clean' and
    manufacture repro_rate 0.0 for a real bug. Returns the probed text so
    the caller can reuse it as the first run's baseline."""
    try:
        text = dmesg_text()
    except OSError as e:
        sys.exit("cannot run dmesg: %s — reproduction is verified against "
                 "the kernel ring buffer, so there is nothing to score "
                 "against. Re-run via sudo." % e)
    if not text.strip():
        sys.exit("dmesg returned no output — refusing to verify: with an "
                 "unreadable ring buffer every run would score 'clean' and "
                 "the crash would be misclassified unreproducible. Re-run "
                 "via sudo, or allow non-root reads with 'sudo sysctl -w "
                 "kernel.dmesg_restrict=0'.")
    return text


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


def _report_texts(c, cid):
    """Report/dmesg text registered for this crash, when available: the
    extracted PoC copy first, then the syz crash dir, then the registry
    path itself (a file for dmesg-harvested and Track U entries)."""
    texts = []
    dest = os.path.join(REPO_ROOT, "artifacts", "pocs", cid)
    candidates = [os.path.join(dest, "report"), os.path.join(dest, "log")]
    d = c.get("dir") or ""
    if os.path.isdir(d):
        candidates += [os.path.join(d, "report"), os.path.join(d, "log")]
    elif os.path.isfile(d):
        candidates.append(d)
    for p in candidates:
        try:
            if os.path.getsize(p) > 8 * 1024 * 1024:
                continue
            with open(p, errors="replace") as f:
                texts.append(f.read())
        except OSError:
            continue
    return texts


def crash_signature(c, cid):
    """Derive the signature a dmesg delta (or a harvested crash log) must
    contain for a run to count as a reproduction of *this* crash.

    -> {"phrases": [...], "funcs": [...]}

    phrases: the registry title split on volatile fields (pids, addresses,
             timestamps), keeping stable runs long enough to be meaningful.
             scan_dmesg's "kernel "/"NVRM " prefixes never appear verbatim
             in a fresh delta, so they are stripped first.
    funcs:   top stack frames from the registered report (the strongest
             evidence), plus identifier-like title tokens — driver
             functions nearly always carry '_' or '.'.
    """
    title = re.sub(r"^(?:kernel|NVRM)\s+", "", (c.get("title") or "").strip())
    funcs = []
    for text in _report_texts(c, cid):
        for f in FRAME_RE.findall(text) + TRACE_RE.findall(text):
            f = f.strip(".~")
            if len(f) >= 3 and f not in funcs:
                funcs.append(f)
    funcs = funcs[:5]
    for tok in re.findall(r"[A-Za-z_][\w.~]*", title):
        if len(tok) >= 4 and ("_" in tok or "." in tok) and tok not in funcs:
            funcs.append(tok)
    phrases = []
    for part in VOLATILE_RE.split(title):
        part = re.sub(r"\s+", " ", part).strip(" ,:;-")
        if len(part) >= 12 and part not in phrases:
            phrases.append(part)
    return {"phrases": phrases, "funcs": funcs}


def matched_signature(delta, sig):
    """Return the element of this crash's signature found in `delta`, or
    None. One predicate for both the hit count and the printed log line —
    they must never disagree. Generic CRASH_PATTERNS are deliberately not
    consulted: any BUG:/Oops in the window is not evidence that *this*
    crash reproduced."""
    for f in sig["funcs"]:
        if f in delta:
            return f
    for p in sig["phrases"]:
        if p in delta:
            return p
    return None


def hang_class(title):
    """The hang-class marker in the title, or None. A timeout is positive
    evidence only for crashes whose title says the bug *is* a hang."""
    t = (title or "").lower()
    return next((p for p in HANG_PATTERNS if p in t), None)


def _boot_epoch():
    """Epoch time the running kernel booted, or None if unavailable."""
    try:
        with open("/proc/uptime") as f:
            up = float(f.read().split()[0])
        return time.time() - up
    except (OSError, ValueError, IndexError):
        return None


def harvested_logs():
    """Text of the newest harvested crash logs (pstore/kdump/console), or
    None when nothing usable was harvested.

    The orchestrator's post-panic resume sequence runs crashlog_ctl.py
    harvest before anything else, so the newest harvest dir holds the
    previous boot's last words. A harvest dir older than the current boot
    cannot describe the run that just killed the machine — treat it as
    absent rather than score against a stale log. vmcore files are far too
    large to scan and are skipped; the dmesg/console text alongside them is
    what carries the signature.
    """
    base = os.path.join(REPO_ROOT, "artifacts", "crashes")
    dirs = [d for d in glob.glob(os.path.join(base, "pstore-*"))
            if os.path.isdir(d)]

    def mtime(p):
        try:
            return os.path.getmtime(p)
        except OSError:
            return 0

    if not dirs:
        return None
    newest = max(dirs, key=mtime)
    boot = _boot_epoch()
    if boot is not None and mtime(newest) < boot:
        return None
    texts = []
    for root, _subdirs, files in os.walk(newest):
        for name in sorted(files):
            if name.startswith("vmcore"):
                continue
            p = os.path.join(root, name)
            try:
                if os.path.getsize(p) > 32 * 1024 * 1024:
                    continue
                with open(p, errors="replace") as f:
                    texts.append(f.read())
            except OSError:
                continue
    return "\n".join(texts) if texts else None


def _log_summary(text):
    """What a harvested log actually shows, for void-run explanations."""
    for line in text.splitlines():
        if any(p in line for p in CRASH_PATTERNS):
            return "log shows: " + line.strip()[:120]
    return "no recognizable crash marker in the log"


PROGRESS_DEFAULT = {"runs_done": 0, "hits": 0, "inconclusive": 0,
                    "in_flight": False, "boot_id": None,
                    "timeouts": 0, "timeout_hits": 0, "weak_hits": 0,
                    "evidence": None}


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


def _recover(prog, now_boot, logs, c, cid):
    """Resolve a run left in_flight when the previous verify process died.
    Mutates prog; returns the human-readable recovery line.

    Only a reboot proves the kernel went down; if we are still on the boot
    that started the run, the verification process itself died (Ctrl-C, OOM
    kill, a repro that will not exec) and counting that as a reproduction
    would inflate the rate that gates disclosure. A reboot is not proof
    either, on its own: this box panics by design, so the harvested logs
    decide whether *this* crash did it.
    """
    n = prog["runs_done"]
    prog["in_flight"] = False
    was_boot = prog.get("boot_id")
    if not (now_boot and was_boot and now_boot != was_boot):
        prog["inconclusive"] += 1
        return ("run %d: ended without a verdict on the same boot -> VOID "
                "(not counted either way)" % n)
    if logs:
        m = matched_signature(logs, crash_signature(c, cid))
        if m:
            prog["hits"] += 1
            prog["evidence"] = "harvested-log-signature"
            return ("run %d: machine rebooted mid-run and the harvested "
                    "crash log contains this crash's signature (%s) -> "
                    "counted as CRASH" % (n, m))
        prog["inconclusive"] += 1
        return ("run %d: machine rebooted mid-run but the harvested crash "
                "log shows a different crash (%s) -> VOID (not counted "
                "either way)" % (n, _log_summary(logs)))
    if c["track"] == "U":
        # A userspace replay cannot take the kernel down, and no logs tie
        # the reboot to this crash — the run says nothing about the bug.
        prog["inconclusive"] += 1
        return ("run %d: machine rebooted mid-run; a track U replay cannot "
                "panic the kernel and no crash logs were recoverable -> "
                "VOID (not counted either way)" % n)
    # No logs recoverable: the run process died mid-execution on a machine
    # that then came back on a new boot, so the panic killed it. Count it,
    # but record the weaker evidence class alongside the hit.
    prog["hits"] += 1
    prog["weak_hits"] += 1
    prog["evidence"] = "boot-id-change-only"
    return ("run %d: machine rebooted mid-run and no crash logs were "
            "recoverable; the run died mid-execution, so the panic killed "
            "it -> counted as CRASH (weak evidence: boot-id change only)"
            % n)


def _prepare_k(cid, c):
    """Track K preconditions; returns (run_one, first_baseline)."""
    dest = os.path.join(REPO_ROOT, "artifacts", "pocs", cid)
    src = os.path.join(dest, "repro.c")
    exe = os.path.join(dest, "repro")
    if not os.path.exists(exe):
        if not os.path.exists(src) or os.path.getsize(src) == 0:
            sys.exit("no usable repro.c in %s (run extract first — an empty "
                     "repro.c is the residue of a failed syz-prog2c and "
                     "extract will regenerate it)" % dest)
        r = subprocess.run(["gcc", "-pthread", "-static", "-o", exe, src])
        if r.returncode != 0:
            sys.exit("gcc failed (rc %d) building repro.c in %s — re-run "
                     "extract to regenerate it" % (r.returncode, dest))
    sig = crash_signature(c, cid)
    if not sig["funcs"] and not sig["phrases"]:
        sys.exit("cannot derive a crash-specific signature for %s from "
                 "title %r, and no stack frames are registered under %s — "
                 "refusing to score runs against generic BUG:/Oops patterns, "
                 "which any crash in the window would trip"
                 % (cid, c.get("title"), c.get("dir")))
    print("%s: crash signature funcs=%s phrases=%s"
          % (cid, sig["funcs"], sig["phrases"]))
    # Probe before anything is scored; the probed text doubles as the first
    # run's baseline so no ring-buffer read is wasted.
    baseline = probe_dmesg()

    def run_one(before=None):
        if before is None:
            try:
                before = dmesg_text()
            except OSError:
                before = None
        timed_out = False
        exec_failed = None
        try:
            subprocess.run([exe], timeout=REPRO_TIMEOUT,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            timed_out = True
        except OSError as e:
            # The repro never ran, so the run says nothing about the bug.
            # Left uncaught this exits mid-run with in_flight set, which the
            # next invocation would have to reason about.
            exec_failed = str(e)
        try:
            after = dmesg_text()
        except OSError:
            after = None
        if exec_failed:
            return {"verdict": "void", "timed_out": timed_out,
                    "detail": "repro would not run: %s" % exec_failed}
        if before is None or after is None or not before.strip() \
                or not after.strip():
            # Never score on empty dmesg: an empty before/after pair reads
            # as a clean run and manufactures a 0% rate.
            return {"verdict": "void", "timed_out": timed_out,
                    "detail": "dmesg returned no output mid-run — refusing "
                              "to score an empty ring buffer"}
        delta, wrapped = dmesg_delta(before, after)
        sig_hit = None if wrapped else matched_signature(delta, sig)
        if sig_hit:
            return {"verdict": "hit", "detail": sig_hit,
                    "evidence": "dmesg-signature", "timed_out": timed_out}
        if timed_out:
            marker = hang_class(c.get("title"))
            if marker:
                return {"verdict": "hit", "timed_out": True,
                        "evidence": "timeout-hang-class",
                        "detail": "repro hung past %ds and the crash is "
                                  "hang-class (%s)" % (REPRO_TIMEOUT, marker)}
            return {"verdict": "void", "timed_out": True,
                    "detail": "repro timed out after %ds; the title has no "
                              "hang-class marker, so a hang here is not "
                              "evidence for this crash" % REPRO_TIMEOUT}
        if wrapped:
            return {"verdict": "void", "timed_out": False,
                    "detail": "dmesg ring wrapped; delta not computable"}
        return {"verdict": "clean", "timed_out": False, "detail": ""}

    return run_one, baseline


def _prepare_u(cid, c, cmd, crash_exit):
    """Track U preconditions; returns the run_one closure."""
    dest = os.path.join(REPO_ROOT, "artifacts", "pocs", cid)
    input_path = os.path.join(dest, "input")
    if not os.path.exists(input_path):
        sys.exit("no input file in %s (run extract first)" % dest)
    if not cmd:
        sys.exit("track U verify needs --cmd '<command template>' with "
                 "{input} where the crash input goes, e.g. --cmd "
                 "'/opt/harness/run {input}'")
    if "{input}" not in cmd:
        sys.exit("--cmd must contain the {input} placeholder")
    run_cmd = cmd.replace("{input}", shlex.quote(input_path))
    print("%s: track U replay: %s" % (cid, run_cmd))

    def run_one(before=None):
        timed_out = False
        try:
            r = subprocess.run(run_cmd, shell=True, timeout=REPRO_TIMEOUT,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               text=True, errors="replace")
            out = (r.stdout or "") + "\n" + (r.stderr or "")
            rc = r.returncode
        except subprocess.TimeoutExpired as e:
            timed_out = True
            out = "%s\n%s" % (_text(e.output), _text(e.stderr))
            rc = None
        except OSError as e:
            return {"verdict": "void", "timed_out": False,
                    "detail": "harness infra failure: %s" % e}
        # Keep the last run's output for the poc agent's README (expected
        # sanitizer signature, exit code).
        try:
            with open(os.path.join(dest, "last-run.log"), "w") as f:
                f.write("%s\n[exit %s]\n" % (out, rc))
        except OSError:
            pass
        m = SANITIZER_RE.search(out)
        if m:
            return {"verdict": "hit", "detail": m.group(0),
                    "evidence": "sanitizer-signature", "timed_out": timed_out}
        if rc in (126, 127):
            return {"verdict": "void", "timed_out": False,
                    "detail": "harness infra failure (exit %d: command not "
                              "runnable)" % rc}
        if timed_out:
            marker = hang_class(c.get("title"))
            if marker:
                return {"verdict": "hit", "timed_out": True,
                        "evidence": "timeout-hang-class",
                        "detail": "harness hung past %ds and the crash is "
                                  "hang-class (%s)" % (REPRO_TIMEOUT, marker)}
            return {"verdict": "void", "timed_out": True,
                    "detail": "harness timed out after %ds; the title has "
                              "no hang-class marker, so a hang here is not "
                              "evidence for this crash" % REPRO_TIMEOUT}
        if crash_exit is not None and rc == crash_exit:
            return {"verdict": "hit", "detail": "exit %d matched "
                                                "--crash-exit" % rc,
                    "evidence": "exit-condition", "timed_out": False}
        return {"verdict": "clean", "timed_out": False,
                "detail": "exit %d" % rc}

    return run_one


def _text(b):
    if b is None:
        return ""
    return b if isinstance(b, str) else b.decode(errors="replace")


def _acquire_lock():
    """Exclusive, non-blocking session lock. Concurrent verifiers share one
    dmesg ring and one machine, so a second session corrupts both runs'
    delta windows. Fail fast instead of queueing — a queued verify would
    start against a ring full of the other session's crashes anyway."""
    d = os.path.dirname(ps.STATE_PATH)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, REPRO_LOCK)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        sys.exit("another repro_ctl verify session holds %s — concurrent "
                 "verifiers share one dmesg ring and would corrupt each "
                 "other's windows; wait for it to finish" % path)
    return fd


def _verify_session(cid, entry, runs, restart, run_one, first_before=None):
    """The durable progress loop shared by both tracks. `run_one` returns a
    dict: verdict (hit|clean|void), detail, evidence (for hits), timed_out.
    """
    now_boot = boot_id()
    logs = harvested_logs()
    with ps.transaction() as st:
        if cid not in st["crashes"]:
            sys.exit("unknown crash id: " + cid)
        c = st["crashes"][cid]
        if restart:
            c["repro_progress"] = dict(PROGRESS_DEFAULT)
        prog = _progress(c)
        recovery = _recover(prog, now_boot, logs, c, cid) \
            if prog["in_flight"] else None
        c["repro_progress"] = dict(prog)

    if recovery:
        print("recovered " + recovery)

    def counted_now():
        return max(prog["runs_done"] - prog["inconclusive"], 0)

    def persist():
        with ps.transaction() as st:
            st["crashes"][cid]["repro_progress"] = dict(prog)

    if counted_now() >= runs:
        print("already have %d counted run(s) (>= %d requested); "
              "use --restart to redo" % (counted_now(), runs))

    # Void runs do not advance the count, so keep going until `runs` verdicts
    # land — but cap total attempts so a persistently wrapping ring buffer
    # cannot loop forever.
    attempt_cap = prog["runs_done"] + 2 * max(runs - counted_now(), 0) + 5
    while counted_now() < runs:
        if prog["runs_done"] >= attempt_cap:
            print("giving up after %d attempts: too many void runs"
                  % prog["runs_done"])
            break
        prog["runs_done"] += 1
        prog["in_flight"] = True
        prog["boot_id"] = now_boot
        persist()
        r = run_one(before=first_before)
        first_before = None
        prog["in_flight"] = False
        if r.get("timed_out"):
            prog["timeouts"] += 1
        if r["verdict"] == "hit":
            prog["hits"] += 1
            prog["evidence"] = r.get("evidence")
            if r.get("evidence") == "timeout-hang-class":
                prog["timeout_hits"] += 1
            verdict = "CRASH (%s)" % r["detail"]
        elif r["verdict"] == "void":
            prog["inconclusive"] += 1
            verdict = "VOID (%s)" % r["detail"]
        else:
            verdict = "clean" + (" (%s)" % r["detail"]
                                 if r.get("detail") else "")
        persist()
        print("run %d (%d/%d counted): %s"
              % (prog["runs_done"], counted_now(), runs, verdict))

    counted = counted_now()
    if not counted:
        print("%s: 0 counted runs (%d void) — no rate recorded"
              % (cid, prog["inconclusive"]))
        return 1
    rate = prog["hits"] / counted
    status = ("reliable" if rate >= 0.8
              else "flaky" if prog["hits"] > 0 else "unreproducible")
    with ps.transaction() as st:
        c = st["crashes"][cid]
        # Append-only classification trail: reclassifying a crash (e.g.
        # overwriting the rca_done marker) must not lose that it happened.
        history = list(c.get("history") or [])
        history.append({"ts": ps._now(), "from": c.get("status"),
                        "to": status, "tool": "repro_ctl"})
        c["history"] = history
        c["repro_rate"] = rate
        c["status"] = status
        c["repro_runs_counted"] = counted
        c["repro_runs_requested"] = runs
        c["repro_progress"] = dict(prog)
    notes = []
    if prog["inconclusive"]:
        notes.append("%d void run(s) excluded" % prog["inconclusive"])
    if prog["timeouts"]:
        notes.append("%d timeout(s): %d hang-class hit(s), %d void"
                     % (prog["timeouts"], prog["timeout_hits"],
                        prog["timeouts"] - prog["timeout_hits"]))
    if prog["weak_hits"]:
        notes.append("%d hit(s) on weak boot-id-only evidence"
                     % prog["weak_hits"])
    print("%s: %d/%d (%.0f%%) -> %s%s"
          % (cid, prog["hits"], counted, rate * 100, status,
             " [" + "; ".join(notes) + "]" if notes else ""))
    if counted < runs:
        print("%s: protocol shortfall — %d of %d requested runs counted "
              "(attempt cap); the rate above is recorded on a short "
              "denominator" % (cid, counted, runs))
        return 2
    return 0


def cmd_verify(cid, runs, restart, cmd=None, crash_exit=None, track=None):
    c = crash_entry(cid)
    trk = _check_track(c, cid, track)
    if trk == "K" and (cmd or crash_exit is not None):
        sys.exit("--cmd/--crash-exit are track U options; %s is track K"
                 % cid)
    lock_fd = _acquire_lock()
    try:
        if trk == "K":
            run_one, first_before = _prepare_k(cid, c)
        else:
            run_one, first_before = _prepare_u(cid, c, cmd, crash_exit), None
        return _verify_session(cid, c, runs, restart, run_one, first_before)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("extract"); p.add_argument("crash_id")
    p.add_argument("--force", action="store_true",
                   help="track U: overwrite an existing input file whose "
                        "content differs")
    p.add_argument("--track", choices=("K", "U", "k", "u"), default=None,
                   help="cross-check the track against the registry (the "
                        "registry is authoritative)")
    p = sub.add_parser("verify"); p.add_argument("crash_id")
    p.add_argument("--runs", type=int, default=10)
    p.add_argument("--restart", action="store_true",
                   help="discard partial progress and start from run 1")
    p.add_argument("--cmd", default=None,
                   help="track U: command template run once per run; {input} "
                        "is replaced by the shell-quoted crash input path")
    p.add_argument("--crash-exit", type=int, default=None,
                   help="track U: this harness exit code also counts as a "
                        "reproduction")
    p.add_argument("--track", choices=("K", "U", "k", "u"), default=None,
                   help="cross-check the track against the registry (the "
                        "registry is authoritative)")
    a = ap.parse_args()
    if a.cmd == "extract":
        cmd_extract(a.crash_id, a.force, a.track)
    else:
        if a.runs < 1:
            sys.exit("--runs must be >= 1")
        sys.exit(cmd_verify(a.crash_id, a.runs, a.restart, a.cmd,
                            a.crash_exit, a.track) or 0)


if __name__ == "__main__":
    main()
