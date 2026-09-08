#!/usr/bin/env python3
"""Reproducer extraction and reproduction-rate verification.

Subcommands:
  extract <crash-id> [--force]  Track K: copy repro from the syz workdir ->
                                artifacts/pocs/<id>/, taking repro.c from
                                syzkaller's own repro.cprog when it has one
                                and generating it with syz-prog2c from
                                repro.prog otherwise.
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

Classification: reliable at or above poc.reliable_threshold, flaky =
reproduces below it, unreproducible = 0/N. The threshold, the per-run timeout
and the default run count live in config/campaign.yaml, because a reliable
label is what a disclosure package is built on. Clean-boot verification is
orchestrated by the poc agent (it reboots between runs); this tool provides
the per-run mechanics.

Track K verification refuses to run while gspwn-k is still fuzzing. A run
counts as a reproduction partly because the box went down during it, and that
only means anything when the reproducer is the only thing that could have
panicked it.

What counts as a reproduction — and what does not. A run is a hit only when
the evidence ties to *this* crash:

- Track K derives a signature at verify start (the top stack frames of the
  registered report that name this crash, or normalized title phrases when
  the report carries no frames) and requires *every* member of it in the
  dmesg delta. triage.signature_frames is how many frames that is. A generic
  BUG:/Oops in the window never scores, because the fuzzer panics this box
  by design and any-crash matching would inflate the rate that gates
  disclosure. One frame out of five is any-crash matching, because every
  KASAN report contains dump_stack_lvl.
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
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import atomic_write
import crash_parse
import gspwn_config
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
SYZKALLER = os.path.join(REPO_ROOT, "artifacts", "src", "syzkaller")

REPRO_LOCK = "repro.lock"    # in the state dir, next to .pipeline.lock


def _env_int(name, default):
    """A positive integer read from environment variable `name`, or `default`.

    Validated at this boundary so a mistyped value is a message naming the
    variable, the value and the default, and not a TypeError inside a
    subprocess call part way through a verification session.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        sys.exit("%s=%r is not an integer. Unset it to use the default of %d "
                 "seconds." % (name, raw, default))
    if value <= 0:
        sys.exit("%s=%d must be greater than zero. Unset it to use the "
                 "default of %d seconds." % (name, value, default))
    return value


# Bounds on the tools this module shells out to. These are tool mechanics and
# live here, unlike poc.repro_timeout_sec, which decides how long a
# reproducer may run and is a research decision in config/campaign.yaml. Each
# default states how long the operation takes on a working machine, and each
# carries an environment override for a machine where it takes longer.
#
# Every one of these calls sits on a path that ends in a recorded verdict. A
# call with no bound does not fail, it stops, and a verification that stopped
# is indistinguishable from one still running.
PROG2C_TIMEOUT_SEC = _env_int("GSPWN_PROG2C_TIMEOUT_SEC", 120)
DMESG_TIMEOUT_SEC = _env_int("GSPWN_DMESG_TIMEOUT_SEC", 30)
GCC_TIMEOUT_SEC = _env_int("GSPWN_GCC_TIMEOUT_SEC", 300)
SYSTEMCTL_TIMEOUT_SEC = _env_int("GSPWN_SYSTEMCTL_TIMEOUT_SEC", 30)
# Seconds a timed-out run's process group has to leave on SIGTERM before the
# group is SIGKILLed. Long enough for a harness to close its files, short
# enough that the next run does not start while the last one is still
# printing.
GROUP_TERM_GRACE_SEC = _env_int("GSPWN_GROUP_TERM_GRACE_SEC", 5)


def _signal_group(pgid, sig):
    try:
        os.killpg(pgid, sig)
    except OSError:
        pass


def _kill_group(proc):
    """SIGTERM a timed-out run's whole process group, then SIGKILL it.

    subprocess's own timeout handling kills the direct child. A --cmd
    template that spawns anything (a shell pipeline, a wrapper script, a
    harness that forks a worker) leaves those children running past the run
    that started them. They go on printing, and what they print to the kernel
    log lands inside a LATER run's dmesg delta, which scores that run as a
    reproduction of output it did not produce. Under --runs 10 with
    poc.void_retry_factor 2 up to 25 such groups accumulate in one session.

    The SIGKILL is sent whether or not the direct child has already exited,
    because the orphans are the point.
    """
    try:
        pgid = os.getpgid(proc.pid)
    except OSError:
        proc.kill()
        return
    _signal_group(pgid, signal.SIGTERM)
    try:
        proc.wait(timeout=GROUP_TERM_GRACE_SEC)
    except subprocess.TimeoutExpired:
        pass
    _signal_group(pgid, signal.SIGKILL)


def _run_isolated(cmd, timeout, shell=False, capture=False):
    """Run one measured run in its own process group.

    -> (returncode or None on timeout, combined output text, timed_out)

    start_new_session puts the child in a session and process group of its
    own, so _kill_group reaches every process it started. Nothing this
    function runs may outlive the run it belongs to: the delta window a
    verdict is read from has to hold only what the run under measurement
    produced.

    Output is collected only when `capture` is set. Track K reads its verdict
    from the kernel ring buffer and discards the reproducer's own stdout;
    Track U reads its verdict from the harness output and keeps it.
    """
    stream = subprocess.PIPE if capture else subprocess.DEVNULL
    proc = subprocess.Popen(cmd, shell=shell, start_new_session=True,
                            stdout=stream, stderr=stream,
                            text=True if capture else None,
                            errors="replace" if capture else None)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc)
        # The second communicate returns what the first one had already read
        # off the pipes, so the pre-timeout output is not lost.
        out, err = proc.communicate()
    text = "%s\n%s" % (out or "", err or "") if capture else ""
    return (None if timed_out else proc.returncode), text, timed_out


def _poc_cfg():
    """How long a run may take, and what counts as reliable.

    In config rather than in this module because a reliable classification is
    what a disclosure package is built on: the threshold is a research
    decision, not a tool internal. Falls back to the shipped defaults only if
    the config cannot be read at all, so verification still runs on a box
    whose config is mid-edit.
    """
    try:
        return gspwn_config.poc()
    except Exception:
        return dict(gspwn_config.DEFAULTS["poc"])


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

# Frames every report of its class carries whoever crashed: the report
# printer, the sanitizer runtime thunks, the syscall entry stubs, the
# unwinder and the panic/oops printers. They are dropped before the
# signature_frames cap is applied, so the cap spends its slots on frames that
# name *this* crash. A KASAN report of a use-after-free in nv_uvm_free opens
# with nv_uvm_free, dump_stack_lvl, print_report, kasan_report and
# __x64_sys_ioctl; four of those five are true of every KASAN report ever
# printed, and taking the first five unfiltered leaves one frame of evidence
# in a five-frame signature.
#
# Matched by subsystem prefix and not by an exact name list, because each of
# these is a whole file's worth of functions and a kernel release renames
# some of them: mm/kasan/report.c and the __kasan_/__asan_/__ubsan_ thunks,
# lib/dump_stack.c, kernel/stacktrace.c and the arch unwinder,
# arch/x86/entry's syscall stubs, and kernel/panic.c. A function added to one
# of those files matches its prefix and is dropped with the rest.
#
# A machinery frame in none of these subsystems costs one cap slot and
# nothing else: matched_signature requires every frame, and a frame present
# in every report is satisfied by every delta, so an unfiltered one can
# produce no false hit. It is also visible, because _prepare_k prints the
# derived signature before the first run of every verification.
UBIQUITOUS_FRAME_RE = re.compile(
    r"^(?:"
    # Sanitizer runtime, with or without the compiler's leading underscores:
    # kasan_report, __kasan_slab_free and __asan_report_load8_noabort are one
    # subsystem written three ways.
    r"_{0,2}(?:kasan|asan|ubsan|msan|kmsan|kcsan|tsan)_"
    r"|print_report|print_address_description|print_memory_metadata"
    r"|report_bug|__report_bug"
    r"|(?:__)?dump_stack|show_stack|show_trace_log_lvl"   # lib/dump_stack.c
    r"|stack_trace_save|save_stack_trace|arch_stack_walk|unwind_"
    r"|__x64_sys_|__ia32_sys_|__se_sys_|__do_sys_|do_syscall_|entry_SYSCALL"
    r"|do_int80_syscall|syscall_exit_to_user_mode|ret_from_fork"
    r"|panic$|nmi_panic|__die|die_addr|oops_end|__warn$|warn_slowpath"
    r"|asm_exc_|error_entry$|rewind_stack"
    r")")


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
    """Crash-durable copy: temp file, fsync, atomic rename, directory fsync.

    The binary counterpart of atomic_write.atomic_write_text, which takes
    text and cannot carry a reproducer or a pstore record. The directory
    fsync comes from that module, so both writers commit a directory entry
    the same way: os.replace publishes the name and the file fsync commits
    the bytes, and neither commits the entry itself. This pipeline panics the
    machine by design, so the window after the rename is one a panic lands
    in.
    """
    dst_dir = os.path.dirname(os.path.abspath(dst))
    fd, tmp = tempfile.mkstemp(dir=dst_dir, suffix=".tmp")
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
    atomic_write._fsync_directory(dst_dir)


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
            try:
                r = subprocess.run([prog2c, "-prog", syz, "-repeat", "1",
                                    "-procs", "1", "-sandbox", "namespace",
                                    "-exe", exe], stdout=f,
                                   timeout=PROG2C_TIMEOUT_SEC)
            except subprocess.TimeoutExpired:
                sys.exit("syz-prog2c did not finish within %ds on %s, so "
                         "repro.c was NOT written. Raise "
                         "GSPWN_PROG2C_TIMEOUT_SEC where the program is "
                         "legitimately this large."
                         % (PROG2C_TIMEOUT_SEC, syz))
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
    # The same directory commit _atomic_copy takes, for the same reason.
    atomic_write._fsync_directory(os.path.dirname(os.path.abspath(c_out)))


# The reproducer syzkaller writes into workdir/crashes/<hash>/.
# pkg/manager/crash.go names it repro.prog. `repro.syz` is kept as a second
# candidate for a directory assembled by hand or by syz-repro run directly,
# which is the only way that name ever appears.
SYZ_PROG_NAMES = ("repro.prog", "repro.syz")


def _oldest_indexed(src, stem):
    """<stem>0 in a syzkaller crash dir, or a bare <stem>, or None.

    syzkaller indexes the per-sighting files (report0, log0, tag0,
    machineInfo0) and writes no unsuffixed form. Index 0 is the lowest index
    written, not necessarily the first sighting: once the directory holds
    MaxCrashLogs entries syzkaller overwrites the oldest slot by modification
    time. Nothing in the directory records which sighting `description` was
    derived from, so index 0 is the only stable selection available. The bare
    name is accepted after the numbered ones so a hand-assembled directory
    resolves.
    """
    best = None
    for p in glob.glob(os.path.join(src, stem + "*")):
        if not os.path.isfile(p):
            continue
        suffix = os.path.basename(p)[len(stem):]
        if suffix == "":
            key = (1, 0)
        elif suffix.isdigit():
            key = (0, int(suffix))
        else:
            continue
        if best is None or key < best[0]:
            best = (key, p)
    return best[1] if best else None


def _extract_k(cid, c):
    """Copy a syzkaller crash directory into artifacts/pocs/<cid>/.

    The PoC directory normalises what it stores: the numbered report and log
    land under `report` and `log`, which is where _report_texts looks for the
    stack frames a crash signature is built from, and the reproducer program
    lands under `repro.prog` whichever of the two source names it carried.
    """
    src = c["dir"]
    # scan_dmesg registers a harvested kernel report as track K with the log
    # *file* it was read out of as `dir`. syz-manager never saw that crash, so
    # there is no crash directory to extract and no reproducer to find; the
    # generic "syz-manager found no reproducer" message below would blame the
    # manager for a crash it was never shown.
    if not os.path.isdir(src):
        sys.exit("%s was harvested from the kernel log %s, not from a "
                 "syzkaller crash directory, so there is nothing to extract "
                 "and no reproducer exists. A log-harvested crash reaches a "
                 "PoC only by writing one: build a reproducer by hand into "
                 "artifacts/pocs/%s/repro.c, then run verify."
                 % (cid, src, cid))
    dest = os.path.join(REPO_ROOT, "artifacts", "pocs", cid)
    os.makedirs(dest, exist_ok=True)
    copied = []

    def take(path, as_name):
        # _atomic_copy and not shutil.copy: this pipeline panics the machine
        # by design, and a panic during extract leaves a truncated repro.c or
        # report behind. A truncated repro.c is non-empty, so the zero-byte
        # check below passes it, _prepare_k compiles it, gcc fails, and the
        # message sends the operator back to extract to copy the same
        # truncated file again.
        if not path or not os.path.isfile(path):
            return
        _atomic_copy(path, os.path.join(dest, as_name))
        copied.append(as_name)

    prog = None
    for name in SYZ_PROG_NAMES:
        p = os.path.join(src, name)
        if os.path.isfile(p):
            prog = p
            break
    take(prog, "repro.prog")
    for name in ("repro.cprog", "repro.report", "repro.log", "repro.stats",
                 "repro.c", "description"):
        take(os.path.join(src, name), name)
    take(_oldest_indexed(src, "report"), "report")
    take(_oldest_indexed(src, "log"), "log")

    prog_out = os.path.join(dest, "repro.prog")
    cprog_out = os.path.join(dest, "repro.cprog")
    c_out = os.path.join(dest, "repro.c")
    # A zero-byte repro.c is the residue of a failed syz-prog2c, not a real
    # artifact: treat it as missing and regenerate.
    stale = os.path.exists(c_out) and os.path.getsize(c_out) == 0
    if not os.path.exists(c_out) or stale:
        if stale:
            print("existing repro.c is empty (a failed syz-prog2c left a "
                  "stub) — regenerating")
        if os.path.isfile(cprog_out) and os.path.getsize(cprog_out) > 0:
            # syz-manager already translated this program and reproduced the
            # crash with the result on the machine that faulted. That C file
            # is better evidence than a fresh translation of the same program
            # by a possibly different syz-prog2c build.
            _atomic_copy(cprog_out, c_out)
            copied.append("repro.c (from repro.cprog)")
        elif os.path.isfile(prog_out) and os.path.getsize(prog_out) > 0:
            _generate_repro_c(prog_out, c_out)
            copied.append("repro.c (generated)")
        else:
            print("WARN: %s holds neither a reproducer program nor a "
                  "non-empty repro.cprog — syz-manager found no reproducer "
                  "for this crash, so no repro.c can be built and `verify` "
                  "has nothing to run." % src)
    print("extracted to %s: %s" % (dest, ", ".join(copied) or "NOTHING"))


def _registered_on_its_report(c):
    """Is this Track U entry registered on a report whose input is gone?

    crash_parse.track_u_pairs registers a .sanlog on its own path when the
    input beside it has been deleted, because losing the finding is worse
    than registering it against a path verify cannot replay. What it cannot
    do is make that path replayable: the file holds the sanitizer's report,
    not the bytes that produced it.
    """
    d = c.get("dir") or ""
    return c.get("track") == "U" and d.endswith(crash_parse.REPORT_SUFFIX)


NO_INPUT_MSG = (
    "%s is registered on its sanitizer report %s, and the crash input beside "
    "it has been deleted. The report is the output of the crash, not the "
    "bytes that caused it, so there is nothing to replay. Copying it in as "
    "`input` would replay report text through the harness, score every run "
    "clean, and record this crash unreproducible, which writes off a real "
    "finding. Restore the input file next to the report, or re-run "
    "harnesses/replay_crashes.sh over a corpus that still holds it, then "
    "extract again.")


def _extract_u(cid, c, force):
    src = c["dir"]
    if not os.path.isfile(src):
        sys.exit("track U crash input is not a file: %s" % src)
    if _registered_on_its_report(c):
        sys.exit(NO_INPUT_MSG % (cid, src))
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
        if force:
            # Track K extraction has nothing to clobber: it regenerates
            # repro.c whenever syz-prog2c has something better to say and
            # copies everything else unconditionally. Accepting the flag
            # silently reads as "the overwrite was authorised".
            print("WARN: --force applies to track U extraction, which refuses "
                  "to overwrite a differing input file. %s is track K and "
                  "extract already refreshes every artefact it copies, so "
                  "the flag changed nothing." % cid)
        _extract_k(cid, c)


def dmesg_text():
    """The kernel ring buffer as text.

    Bounded: every verdict in this module is read from the difference between
    two of these, and a dmesg that never returns leaves a run marked
    in_flight with no verdict and no error. A timeout raises OSError, which
    every caller here already handles as an unreadable ring buffer.
    """
    try:
        r = subprocess.run(["dmesg"], capture_output=True, text=True,
                           timeout=DMESG_TIMEOUT_SEC)
    except subprocess.TimeoutExpired:
        raise OSError("dmesg did not return within %ds" % DMESG_TIMEOUT_SEC)
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
    path itself (a file for dmesg-harvested and Track U entries).

    The PoC directory holds `report` and `log`, because _extract_k normalises
    the names on the way in. The syzkaller crash directory does not: its
    per-sighting files are report<N> and log<N>, and joining the bare names
    there opened two paths that never exist and were swallowed by the OSError
    handler below, leaving a signature built from title tokens alone. A Track
    U entry names the crash input, whose sanitizer output sits beside it under
    crash_parse.REPORT_SUFFIX.
    """
    texts = []
    dest = os.path.join(REPO_ROOT, "artifacts", "pocs", cid)
    candidates = [os.path.join(dest, "report"), os.path.join(dest, "log")]
    d = c.get("dir") or ""
    if os.path.isdir(d):
        candidates += [p for p in (_oldest_indexed(d, "report"),
                                   _oldest_indexed(d, "log")) if p]
    elif os.path.isfile(d):
        candidates.append(d + crash_parse.REPORT_SUFFIX)
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

    funcs:   the top stack frames of the registered report that name this
             crash, capped at triage.signature_frames. Frames matching
             UBIQUITOUS_FRAME_RE are dropped before the cap: they are true of
             every report of their class, so counting them toward the cap
             spends the signature on evidence that distinguishes nothing.
             Where a report carries no crash-specific frame at all, which is
             the case for a title-only registration such as an NVRM Xid line
             or a trace-less panic, identifier-like title tokens stand in,
             since driver functions nearly always carry '_' or '.'. Tokens are
             fallback and not an addition, because matched_signature requires
             every member of funcs and a token naming a module the delta
             never prints would void a genuine reproduction.
    phrases: the registry title split on volatile fields (pids, addresses,
             timestamps), keeping stable runs long enough to be meaningful.
             scan_dmesg's "kernel "/"NVRM " prefixes never appear verbatim
             in a fresh delta, so they are stripped first. Consulted only
             when funcs is empty.
    """
    title = re.sub(r"^(?:kernel|NVRM)\s+", "", (c.get("title") or "").strip())
    funcs = []
    for text in _report_texts(c, cid):
        for f in FRAME_RE.findall(text) + TRACE_RE.findall(text):
            f = f.strip(".~")
            if len(f) < 3 or f in funcs or UBIQUITOUS_FRAME_RE.match(f):
                continue
            funcs.append(f)
    # How many frames a run has to match to count as a reproduction of this
    # crash, rather than as some other crash the same workload also triggers.
    funcs = funcs[:gspwn_config.triage()["signature_frames"]]
    if not funcs:
        for tok in re.findall(r"[A-Za-z_][\w.~]*", title):
            if len(tok) >= 4 and ("_" in tok or "." in tok) \
                    and tok not in funcs:
                funcs.append(tok)
    phrases = []
    for part in VOLATILE_RE.split(title):
        part = re.sub(r"\s+", " ", part).strip(" ,:;-")
        if len(part) >= 12 and part not in phrases:
            phrases.append(part)
    return {"phrases": phrases, "funcs": funcs}


def matched_signature(delta, sig):
    """Describe this crash's signature in `delta`, or return None.

    Every frame in sig["funcs"] has to be present. config/campaign.yaml calls
    triage.signature_frames "frames a reproduction must match to count as a
    hit", and any one of five frames is not that: frames 2 to 5 of a
    sanitizer report are the sanitizer's own machinery, so a delta holding
    only an unrelated KASAN report matches on dump_stack_lvl and scores as a
    reproduction of this crash. crash_signature drops those frames, and this
    predicate requires the rest of them together.

    Phrases are consulted only for a crash whose report carries no frames at
    all, where the title wording is the only evidence there is. A frameful
    crash never falls back to them: a phrase from the title is weaker
    evidence than the stack that produced it, and admitting it as an
    alternative would restore the single-element match this function exists
    to remove.

    One predicate for both the hit count and the printed log line, which must
    never disagree. Generic CRASH_PATTERNS are deliberately not consulted:
    any BUG:/Oops in the window is not evidence that *this* crash reproduced.
    """
    for kind, members in (("frame", sig["funcs"]), ("title phrase",
                                                    sig["phrases"])):
        if not members:
            continue
        if all(m in delta for m in members):
            return "all %d %s(s): %s" % (len(members), kind,
                                         ", ".join(members))
        return None
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


# timeout_hits counts the timeouts scored on the hang-class rule alone.
# timeout_voids counts the timeouts that produced no verdict. A timed-out run
# whose delta also carried this crash's signature is in neither, so the
# breakdown reports it as the difference. A progress dict written before
# timeout_voids existed carries 0 for it and over-reports that middle group
# in the printed note; no rate is derived from any of the three.
PROGRESS_DEFAULT = {"runs_done": 0, "hits": 0, "inconclusive": 0,
                    "in_flight": False, "boot_id": None,
                    "timeouts": 0, "timeout_hits": 0, "timeout_voids": 0,
                    "weak_hits": 0, "evidence": None}


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
        # Void, not clean: the log carries a different crash, or it carries
        # this one truncated past part of its signature. Both are "no usable
        # verdict", and a void run is re-run and not scored.
        return ("run %d: machine rebooted mid-run but the harvested crash "
                "log does not carry this crash's full signature (%s) -> VOID "
                "(not counted either way)" % (n, _log_summary(logs)))
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


def needs_rebuild(src, exe):
    """Is the compiled reproducer older than the source it came from?

    `extract` regenerates repro.c whenever syz-prog2c has something better to
    say. A build-if-absent check then verifies the previous binary against the
    new source, and neither file looks wrong on its own, so the mismatch is
    invisible in the recorded rate.
    """
    if not (os.path.exists(exe) and os.path.exists(src)):
        return False
    try:
        return os.path.getmtime(src) > os.path.getmtime(exe)
    except OSError:
        return False


def _prepare_k(cid, c):
    """Track K preconditions; returns run_one."""
    timeout = _poc_cfg()["repro_timeout_sec"]
    dest = os.path.join(REPO_ROOT, "artifacts", "pocs", cid)
    src = os.path.join(dest, "repro.c")
    exe = os.path.join(dest, "repro")
    outdated = needs_rebuild(src, exe)
    if not os.path.exists(exe) or outdated:
        if not os.path.exists(src) or os.path.getsize(src) == 0:
            sys.exit("no usable repro.c in %s (run extract first — an empty "
                     "repro.c is the residue of a failed syz-prog2c and "
                     "extract will regenerate it)" % dest)
        if outdated:
            print("repro.c is newer than the compiled reproducer; rebuilding")
        try:
            r = subprocess.run(["gcc", "-pthread", "-static", "-o", exe, src],
                               timeout=GCC_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            sys.exit("gcc did not finish within %ds building repro.c in %s. "
                     "Raise GSPWN_GCC_TIMEOUT_SEC where the machine is "
                     "legitimately this slow." % (GCC_TIMEOUT_SEC, dest))
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
    # Probe before anything is scored, and discard the probed text. Reusing
    # it as the first run's baseline saved one ring-buffer read and put
    # everything the kernel printed between the probe and the run into run
    # 1's delta: _verify_session opens a state transaction and
    # harvested_logs() walks up to 32 MB of harvested crash logs after this
    # point. Each run reads its own baseline immediately before executing.
    probe_dmesg()

    def run_one():
        try:
            before = dmesg_text()
        except OSError:
            before = None
        exec_failed = None
        try:
            _rc, _out, timed_out = _run_isolated([exe], timeout)
        except OSError as e:
            # The repro never ran, so the run says nothing about the bug.
            # Left uncaught this exits mid-run with in_flight set, which the
            # next invocation would have to reason about.
            exec_failed, timed_out = str(e), False
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
                                  "hang-class (%s)" % (timeout, marker)}
            return {"verdict": "void", "timed_out": True,
                    "detail": "repro timed out after %ds; the title has no "
                              "hang-class marker, so a hang here is not "
                              "evidence for this crash" % timeout}
        if wrapped:
            return {"verdict": "void", "timed_out": False,
                    "detail": "dmesg ring wrapped; delta not computable"}
        return {"verdict": "clean", "timed_out": False, "detail": ""}

    return run_one


def _prepare_u(cid, c, cmd, crash_exit):
    """Track U preconditions; returns the run_one closure."""
    timeout = _poc_cfg()["repro_timeout_sec"]
    dest = os.path.join(REPO_ROOT, "artifacts", "pocs", cid)
    input_path = os.path.join(dest, "input")
    if not os.path.exists(input_path):
        sys.exit("no input file in %s (run extract first)" % dest)
    # An extract from before this refusal leaves the report itself sitting
    # there as `input`. Replaying it scores every run clean and records
    # unreproducible, so it is refused here too, and only where the file on
    # disk is that report: an operator who wrote a real input in by hand is
    # replaying something else.
    if _registered_on_its_report(c) and os.path.isfile(c["dir"]) \
            and _same_file(c["dir"], input_path):
        sys.exit(NO_INPUT_MSG % (cid, c["dir"])
                 + " Delete the copied report at %s first." % input_path)
    if not cmd:
        sys.exit("track U verify needs --cmd '<command template>' with "
                 "{input} where the crash input goes, e.g. --cmd "
                 "'/opt/harness/run {input}'")
    if "{input}" not in cmd:
        sys.exit("--cmd must contain the {input} placeholder")
    run_cmd = cmd.replace("{input}", shlex.quote(input_path))
    print("%s: track U replay: %s" % (cid, run_cmd))

    def run_one():
        try:
            # In its own process group: a compound template ('a | b', a
            # wrapper script, a harness that forks) leaves children behind a
            # plain timeout kill, and on Track K those orphans go on printing
            # into later runs' delta windows.
            rc, out, timed_out = _run_isolated(run_cmd, timeout, shell=True,
                                               capture=True)
        except OSError as e:
            return {"verdict": "void", "timed_out": False,
                    "detail": "harness infra failure: %s" % e}
        # Keep the last run's output for the poc agent's README (expected
        # sanitizer signature, exit code).
        try:
            atomic_write.atomic_write_text(
                os.path.join(dest, "last-run.log"),
                "%s\n[exit %s]\n" % (out, rc))
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
                                  "hang-class (%s)" % (timeout, marker)}
            return {"verdict": "void", "timed_out": True,
                    "detail": "harness timed out after %ds; the title has "
                              "no hang-class marker, so a hang here is not "
                              "evidence for this crash" % timeout}
        if crash_exit is not None and rc == crash_exit:
            return {"verdict": "hit", "detail": "exit %d matched "
                                                "--crash-exit" % rc,
                    "evidence": "exit-condition", "timed_out": False}
        return {"verdict": "clean", "timed_out": False,
                "detail": "exit %d" % rc}

    return run_one


def _acquire_lock():
    """Exclusive, non-blocking session lock. Concurrent verifiers share one
    dmesg ring and one machine, so a second session corrupts both runs'
    delta windows. Fail fast instead of queueing — a queued verify would
    start against a ring full of the other session's crashes anyway.

    The lock lives in the machine's own state dir and does not follow
    GSPWN_STATE: what it protects is the one dmesg ring, so two runs with
    separate registries must still exclude each other."""
    d = ps.STATE_DIR
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


def _verify_session(cid, runs, restart, run_one):
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
    # cannot loop forever. The factor is poc.void_retry_factor; the small
    # fixed slack keeps a one-run verification from giving up after a single
    # unlucky attempt.
    attempt_cap = (prog["runs_done"]
                   + _poc_cfg()["void_retry_factor"]
                   * max(runs - counted_now(), 0) + 5)
    while counted_now() < runs:
        if prog["runs_done"] >= attempt_cap:
            print("giving up after %d attempts: too many void runs"
                  % prog["runs_done"])
            break
        prog["runs_done"] += 1
        prog["in_flight"] = True
        prog["boot_id"] = now_boot
        persist()
        r = run_one()
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
            if r.get("timed_out"):
                prog["timeout_voids"] += 1
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
    threshold = _poc_cfg()["reliable_threshold"]
    status = ("reliable" if rate >= threshold
              else "flaky" if prog["hits"] > 0 else "unreproducible")
    with ps.transaction() as st:
        c = st["crashes"][cid]
        # set_crash_status keeps the append-only trail and, when the crash was
        # already rca_done, the stamp that says so. Writing the reproduction
        # class straight over `status` used to retire validate's "analysed but
        # no finding/impact" checks, because they keyed on a value this line
        # overwrites and poc always runs after rca.
        ps.set_crash_status(c, status, "repro_ctl")
        c["repro_rate"] = rate
        c["repro_runs_counted"] = counted
        c["repro_runs_requested"] = runs
        c["repro_progress"] = dict(prog)
    notes = []
    if prog["inconclusive"]:
        notes.append("%d void run(s) excluded" % prog["inconclusive"])
    if prog["timeouts"]:
        # Three groups, not two. A run can time out and still carry this
        # crash's signature in its delta, which scores it a hit on the
        # dmesg-signature evidence class. Deriving the void count as
        # timeouts - timeout_hits printed that run as void while it counted
        # toward the rate, so the breakdown contradicted the figure above it.
        sig_hits = max(prog["timeouts"] - prog["timeout_hits"]
                       - prog["timeout_voids"], 0)
        notes.append("%d timeout(s): %d hang-class hit(s), %d also matched "
                     "the signature, %d void"
                     % (prog["timeouts"], prog["timeout_hits"], sig_hits,
                        prog["timeout_voids"]))
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


def _refuse_live_campaign(allow):
    """Track K verification is only meaningful with the fuzzer stopped.

    A reproduction is scored partly on "the box rebooted while the run was
    executing, so the reproducer killed it". That inference holds only when
    the reproducer is the only thing capable of panicking the machine. With a
    campaign still running, the fuzzer panics this box by design and every
    such panic lands as a hit — inflating exactly the rate that decides
    whether a finding is reliable enough to disclose.
    """
    if allow:
        return
    try:
        r = subprocess.run(["systemctl", "is-active", "gspwn-k"],
                           capture_output=True, text=True,
                           timeout=SYSTEMCTL_TIMEOUT_SEC)
    except OSError:
        return          # no systemd here; nothing to assert either way
    except subprocess.TimeoutExpired:
        # systemd is present and did not answer, so whether the fuzzer is
        # running is unknown. Refusing is the safe reading: if it is running,
        # its panics score as reproductions of this crash.
        sys.exit("systemctl did not answer within %ds, so whether gspwn-k is "
                 "still fuzzing could not be established. A campaign panics "
                 "this box by design and every one of its panics would count "
                 "as a hit for this crash. Stop the campaign first, or pass "
                 "--allow-live-campaign if you accept the inflated rate."
                 % SYSTEMCTL_TIMEOUT_SEC)
    if r.stdout.strip() in ("active", "activating"):
        sys.exit("refusing to verify while gspwn-k is still fuzzing: a run "
                 "is scored as a reproduction when the box goes down during "
                 "it, and the fuzzer panics this machine by design, so every "
                 "one of its panics would count as a hit for this crash. "
                 "Stop the campaign first (sudo python3 "
                 "tools/campaign_ctl.py stop k), or pass "
                 "--allow-live-campaign if you accept the inflated rate.")


def cmd_verify(cid, runs, restart, cmd=None, crash_exit=None, track=None,
               allow_live=False):
    c = crash_entry(cid)
    trk = _check_track(c, cid, track)
    if trk == "K" and (cmd or crash_exit is not None):
        sys.exit("--cmd/--crash-exit are track U options; %s is track K"
                 % cid)
    if trk == "K":
        _refuse_live_campaign(allow_live)
    lock_fd = _acquire_lock()
    try:
        if trk == "K":
            run_one = _prepare_k(cid, c)
        else:
            run_one = _prepare_u(cid, c, cmd, crash_exit)
        return _verify_session(cid, runs, restart, run_one)
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
    p.add_argument("--runs", type=int, default=_poc_cfg()["default_runs"],
                   help="counted runs to reach (default poc.default_runs)")
    p.add_argument("--allow-live-campaign", dest="allow_live",
                   action="store_true",
                   help="track K: verify even while gspwn-k is fuzzing. The "
                        "fuzzer's own panics then score as reproductions of "
                        "this crash, so the recorded rate is an overestimate")
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
                            a.crash_exit, a.track, a.allow_live) or 0)


if __name__ == "__main__":
    main()
