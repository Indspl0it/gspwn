#!/usr/bin/env python3
"""Persistent kernel-crash log capture: ramoops/pstore + kdump (bare metal)
or kdump + EC2 console output (cloud).

Subcommands:
  setup    - install kdump-tools, ensure pstore mount (bare metal only), set
             crashkernel= param
  verify   - check pstore/kdump readiness; print sysrq test instructions
  harvest  - copy /sys/fs/pstore/* and every new /var/crash dump into
             artifacts/; on EC2 also save `aws ec2 get-console-output`
             output. Exits 0 when no new crash logs are found, and non-zero
             when it could not read a source — "nothing to harvest" and
             "could not look" must not be the same answer, because the
             orchestrator runs this unattended after every panic.

Harvest exit codes: 0 nothing to harvest and every source read; 1 nothing
harvested and at least one source unread; 2 evidence harvested and at least
one source unread or deferred, with the harvest dir printed on the last line.
2 is separate from 0 because a partial harvest that reports success is how a
panic's only record gets treated as collected.
  prune [--keep N]
           - delete the oldest harvest dirs beyond the newest N (default 10).
             Never automatic: harvested logs are evidence. kdump writes
             hundreds of MB per panic and this pipeline panics by design, so
             reclaiming the space has to be one command rather than a
             hand-written find.

Global flag: --env ec2|baremetal|auto overrides environment auto-detection
(default: auto-detect via the EC2 instance metadata service, IMDSv2 with
an IMDSv1 fallback).

Must run as root for setup, harvest and prune. Debian-family (apt) only.
"""
import glob
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)
# The crash-durable copy idiom (temp file, fsync, atomic rename) and the
# environment-override reader, imported from repro_ctl and not restated here,
# so both copy paths on a machine that panics by design stay one
# implementation and both modules validate an override the same way.
from repro_ctl import _atomic_copy, _env_int  # noqa: E402  (path set above)
import atomic_write                           # noqa: E402

CRASHES_DIR = os.path.join(REPO_ROOT, "artifacts", "crashes")
GRUB_DEFAULT = "/etc/default/grub"
IMDS_BASE = "http://169.254.169.254/latest"
IMDS_TIMEOUT = 2

# Harvest exit code for "evidence collected, at least one source unread or
# deferred". Separate from 1 ("collected nothing and a source was unread")
# because the harvest dir exists and is named on stdout, and separate from 0
# because a partial harvest reported as success is how the only record of a
# panic gets treated as collected.
HARVEST_PARTIAL = 2

# Names kdump-tools and kexec-tools give a dump they are still writing.
KDUMP_INCOMPLETE_MARKERS = ("vmcore-incomplete", "dump-incomplete")
KDUMP_INCOMPLETE_SUFFIX = ".incomplete"
# Suffix on a harvested dump directory while its copy is in progress.
# harvested_kdumps() reads the finished names only, so a copy interrupted by
# a second panic is retried on the next harvest.
PARTIAL_SUFFIX = ".partial"


# Seconds a shelled-out command may take before it is killed. The longest
# thing sh() runs is `apt-get install -y kdump-tools` on a fresh instance,
# which pulls the crash-kernel tooling; ten minutes covers that on a slow
# mirror. Without a bound, setup on an instance whose apt mirror hangs never
# returns and never says why.
CMD_TIMEOUT_SEC = _env_int("GSPWN_CRASHLOG_CMD_TIMEOUT_SEC", 600)

# `aws ec2 get-console-output` runs on the post-panic path, where
# orchestrator_ctl.harvest gives the whole harvest 300 seconds. A console
# fetch that outlives that budget is killed by the caller with the harvest
# dir half written, so it is bounded here first, at well under the caller's
# budget, leaving room for the /var/crash copies that follow it.
CONSOLE_TIMEOUT_SEC = _env_int("GSPWN_CONSOLE_TIMEOUT_SEC", 120)


def sh(cmd, check=True, capture=False, timeout=None):
    """Run `cmd`, bounded by CMD_TIMEOUT_SEC unless `timeout` overrides it.

    Every caller runs a program that can block indefinitely: apt against a
    hung mirror, update-grub against a stuck device probe, and the AWS CLI
    against an endpoint the panic just made unreachable. An unbounded call on
    the unattended post-panic path holds the orchestrator until its own
    timeout fires, and the evidence is lost with no diagnostic.
    """
    return subprocess.run(cmd, check=check, text=True,
                          capture_output=capture,
                          timeout=CMD_TIMEOUT_SEC if timeout is None
                          else timeout)


def _fsync_dir(path):
    """Commit a directory's entries to disk.

    os.replace publishes a new name and fsync on the file commits its bytes,
    and neither commits the directory entry that carries the name. After a
    panic in that window the record is on disk with nothing pointing at it.
    Raises OSError, which every caller has to handle before it deletes the
    only other copy.

    Delegates to the shared writer's implementation, so the harvest commits a
    directory the same way every artefact writer does.
    """
    atomic_write._fsync_directory(path)


def _imds_token():
    """Fetch an IMDSv2 session token, or None when the token endpoint does
    not answer (IMDSv1-only instance, or not EC2 at all)."""
    req = urllib.request.Request(
        IMDS_BASE + "/api/token", method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"})
    try:
        with urllib.request.urlopen(req, timeout=IMDS_TIMEOUT) as r:
            return r.read().decode().strip()
    except Exception:
        return None


def imds_get(path):
    """GET an instance-metadata path, preferring IMDSv2 and falling back
    to IMDSv1 only when the token endpoint is unavailable. Raises on
    failure; bounded by IMDS_TIMEOUT on non-EC2 hosts."""
    token = _imds_token()
    headers = {"X-aws-ec2-metadata-token": token} if token else {}
    req = urllib.request.Request(IMDS_BASE + "/meta-data/" + path,
                                 headers=headers)
    with urllib.request.urlopen(req, timeout=IMDS_TIMEOUT) as r:
        return r.read().decode().strip()


def detect_env():
    """Return "ec2" if the instance metadata service answers, else
    "baremetal"."""
    try:
        imds_get("instance-id")
        return "ec2"
    except Exception:
        return "baremetal"


def get_instance_id():
    return imds_get("instance-id")


def cmd_setup(env):
    if os.geteuid() != 0:
        sys.exit("setup must run as root")
    sh(["apt-get", "update"])
    if env == "ec2":
        # No pstore on EC2: kdump still works; hard-hang capture falls back
        # to the EC2 console output.
        sh(["apt-get", "install", "-y", "kdump-tools"])
    else:
        sh(["apt-get", "install", "-y", "kdump-tools", "pstore-tools"])
    # crashkernel param
    with open(GRUB_DEFAULT) as f:
        grub = f.read()
    if "crashkernel=" not in grub:
        # The backup is the operator's way back from a bad boot parameter, so
        # it is on disk durably before the original is replaced.
        _atomic_copy(GRUB_DEFAULT, GRUB_DEFAULT + ".bak-gspwn")
        anchor = None
        for cand in ('GRUB_CMDLINE_LINUX_DEFAULT="', 'GRUB_CMDLINE_LINUX="'):
            if cand in grub:
                anchor = cand
                break
        if anchor is None:
            sys.exit(
                "ERROR: neither GRUB_CMDLINE_LINUX_DEFAULT nor "
                "GRUB_CMDLINE_LINUX found in %s; crashkernel= NOT added.\n"
                "Add the crashkernel parameter manually, e.g.:\n"
                '  GRUB_CMDLINE_LINUX_DEFAULT="crashkernel=256M"\n'
                "then run update-grub and reboot." % GRUB_DEFAULT)
        grub = grub.replace(anchor, anchor + "crashkernel=256M ", 1)
        # Replaced, never truncated in place: a failure part way through a
        # direct write leaves /etc/default/grub half a file, and the next
        # update-grub reads it. The .bak-gspwn copy above is the operator's
        # way back, not the writer's.
        atomic_write.atomic_write_text(GRUB_DEFAULT, grub)
        sh(["update-grub"])
        print("added crashkernel=256M to " + anchor.rstrip('"')
              + "; reboot required")
    if env != "ec2":
        # pstore mount (usually automatic via systemd)
        if not os.path.ismount("/sys/fs/pstore"):
            sh(["mount", "-t", "pstore", "pstore", "/sys/fs/pstore"],
               check=False)
    sh(["systemctl", "enable", "kdump-tools"], check=False)
    if env == "ec2":
        print("NOTE (EC2): pstore skipped — hard-hang capture uses the EC2 "
              "console output instead. The instance needs an IAM instance "
              "profile allowing ec2:GetConsoleOutput.")
    print("setup done. Next: reboot, then run: crashlog_ctl.py verify")


def cmd_verify(env):
    ok = True
    if env != "ec2" and not os.path.isdir("/sys/fs/pstore"):
        print("FAIL: /sys/fs/pstore missing (pstore not supported/mounted)")
        ok = False
    r = sh(["systemctl", "is-active", "kdump-tools"], check=False,
           capture=True)
    if r.stdout.strip() != "active":
        print("WARN: kdump-tools not active: " + r.stdout.strip())
    with open("/proc/cmdline") as f:
        if "crashkernel=" not in f.read():
            print("FAIL: crashkernel= not in kernel cmdline; reboot needed")
            ok = False
    if env == "ec2":
        if shutil.which("aws") is None:
            print("FAIL: aws CLI not found (needed for console-output "
                  "harvest)")
            ok = False
        print("NOTE (EC2): console-output capture requires an IAM instance "
              "profile allowing ec2:GetConsoleOutput.")
    if ok:
        print("READY. Now validate capture with a deliberate panic:")
        print("  1. sync")
        print("  2. echo c > /proc/sysrq-trigger   # machine panics, reboots")
        print("  3. after boot: crashlog_ctl.py harvest")
        if env == "ec2":
            print("     (must produce a /var/crash kdump dump; hard hangs "
                  "are captured via console-output.log in the harvest dir)")
        else:
            print("     (must produce a dmesg/ramoops dump containing the "
                  "panic)")
    sys.exit(0 if ok else 1)


def _dir_bytes(path):
    total = 0
    for root, _subdirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                continue
    return total


def report_disk():
    """Say what the crash logs are costing, and warn when space runs short.

    kdump writes hundreds of megabytes per panic and this pipeline panics on
    purpose, so /var/crash and the harvested copies are the fastest-growing
    things on the box. A full disk stops the fuzzer, the sampler and every
    state write at once, which is a far worse outcome than losing an old dump.
    """
    free_mb, warning = None, ""
    try:
        import coverage_ctl
    except ImportError as e:
        # `except Exception: pass` here hid the one thing this function is
        # for. coverage_ctl reaches pipeline_state, which imports fcntl, so
        # the import fails on any host without it and the low-space warning
        # then never prints on the machine whose disk is filling.
        print("WARN: free space is not being checked (cannot import "
              "coverage_ctl: %s). A full disk stops the fuzzer, the sampler "
              "and every state write at once." % e)
    else:
        free_mb = coverage_ctl.disk_free_mb()
        warning = coverage_ctl.disk_warning(free_mb)
        if free_mb is None:
            print("WARN: free space is not being checked: statvfs did not "
                  "answer for %s." % REPO_ROOT)
    parts = []
    for label, path in (("harvested", CRASHES_DIR), ("/var/crash",
                                                     "/var/crash")):
        if os.path.isdir(path):
            parts.append("%s %.1f GB" % (label, _dir_bytes(path) / 1073741824.0))
    if free_mb is not None:
        parts.append("%.1f GB free" % (free_mb / 1024.0))
    if parts:
        print("disk: " + ", ".join(parts))
    if warning:
        print(warning)
        print("      prune old harvests with: sudo python3 "
              "tools/crashlog_ctl.py prune --keep 10")


def cmd_prune(env, keep):
    """Delete the oldest harvest dirs beyond --keep. Explicit, never automatic.

    Harvested crash logs are evidence, so nothing removes them on its own.
    This exists so that reclaiming the space is one command rather than a
    hand-written find, and so the count that is kept is a stated decision.
    """
    if os.geteuid() != 0:
        sys.exit("prune must run as root: the harvest dirs are written by the "
                 "root harvester")
    dirs = sorted((d for d in glob.glob(os.path.join(CRASHES_DIR, "pstore-*"))
                   if os.path.isdir(d)), key=os.path.getmtime)
    doomed = dirs[:-keep] if keep else dirs
    if not doomed:
        print("nothing to prune: %d harvest dir(s), keeping %d"
              % (len(dirs), keep))
        report_disk()
        return
    freed = 0
    for d in doomed:
        freed += _dir_bytes(d)
        shutil.rmtree(d, ignore_errors=True)
        print("removed " + d)
    print("pruned %d of %d harvest dir(s), freeing %.1f GB"
          % (len(doomed), len(dirs), freed / 1073741824.0))
    report_disk()


def harvested_kdumps():
    """Basenames of /var/crash dumps already copied by a previous harvest.

    A directory still carrying PARTIAL_SUFFIX is a copy that did not finish,
    so its name is not reported as harvested and the dump is copied again.
    """
    seen = set()
    for d in glob.glob(os.path.join(CRASHES_DIR, "*", "kdump-*")):
        base = os.path.basename(d)
        if base.endswith(PARTIAL_SUFFIX):
            continue
        seen.add(base[len("kdump-"):])
    return seen


def kdump_incomplete(src):
    """The in-progress marker inside a /var/crash dump dir, or None.

    kexec-tools writes vmcore-incomplete and renames it to vmcore once
    makedumpfile finishes; Debian's kdump-tools writes dump-incomplete and
    dump.<stamp>.incomplete the same way. A directory holding one of those
    names is not a dump yet.

    An unreadable directory is reported as in-progress and not as complete:
    the two are indistinguishable from here, and treating it as complete
    copies whatever is readable and retires the name.
    """
    try:
        names = os.listdir(src)
    except OSError as e:
        return "not readable: %s" % e
    for name in sorted(names):
        if name in KDUMP_INCOMPLETE_MARKERS \
                or name.endswith(KDUMP_INCOMPLETE_SUFFIX):
            return name
    return None


def cmd_harvest(env):
    # /sys/fs/pstore and /var/crash are root-only. Run as anyone else the
    # globs come back empty, the copies raise PermissionError, and the old
    # code turned both into a WARN, found nothing, printed "no new crash logs
    # found" and exited 0 — so the automated post-panic path reported success
    # while the evidence stayed on the machine until pstore filled up and
    # started dropping later panics. Refusing is the only honest answer.
    if os.geteuid() != 0:
        sys.exit("harvest must run as root: /sys/fs/pstore and /var/crash are "
                 "root-only, and a non-root harvest reads nothing while "
                 "looking like it found nothing. Re-run with sudo. (The "
                 "orchestrator uses `sudo -n`, so the unit's user needs a "
                 "passwordless rule for this command — see "
                 "orchestrator_ctl.py preflight.)")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(CRASHES_DIR, "pstore-" + stamp)
    os.makedirs(dest, exist_ok=True)
    found = False
    failures = []
    deferred = []
    if env == "ec2":
        console_log = os.path.join(dest, "console-output.log")
        try:
            instance_id = get_instance_id()
            r = sh(["aws", "ec2", "get-console-output",
                    "--instance-id", instance_id,
                    "--latest", "--output", "text"], check=False,
                   capture=True, timeout=CONSOLE_TIMEOUT_SEC)
            if r.returncode == 0 and r.stdout.strip():
                # On EC2 the console is the only record of a hard hang, so it
                # goes down the same durable path as every other artefact:
                # temporary, fsync, rename, directory fsync.
                atomic_write.atomic_write_text(console_log, r.stdout)
                found = True
                print("saved console output: " + console_log)
            elif r.returncode == 0:
                # The API answered and the buffer is empty. On a machine that
                # has not panicked since its console buffer was cleared this
                # is the normal answer, and it is not an unread source.
                print("console output is empty; nothing to save")
            else:
                print("WARN: get-console-output exited %d: %s"
                      % (r.returncode, r.stderr.strip()))
                failures.append("aws ec2 get-console-output")
        except (OSError, subprocess.SubprocessError,
                urllib.error.URLError) as e:
            # On EC2 the console is the only record of a hard hang, where
            # pstore never ran and kdump never got a chance. A fetch that
            # failed is a source that was not read, so it is counted as one
            # and reaches the exit code.
            print("WARN: console-output harvest failed: %s" % e)
            failures.append("aws ec2 get-console-output")
    else:
        copied = []
        for src in sorted(glob.glob("/sys/fs/pstore/*")):
            try:
                # _atomic_copy and not shutil.copy: the record is unlinked
                # from pstore a few lines below, and between an unflushed
                # copy and its writeback the only durable copy of the report
                # is the one about to be deleted. This host panics by design,
                # so a second panic in that window is expected, not
                # hypothetical, and it takes the first panic's report with
                # it.
                _atomic_copy(src, os.path.join(dest, os.path.basename(src)))
            except (OSError, shutil.Error) as e:
                print("WARN: could not copy %s (%s); continuing" % (src, e))
                failures.append(src)
                continue
            copied.append(src)
            found = True
        # pstore is a small fixed-size backend that only frees a record when
        # the file is deleted. Leaving records in place means the NEXT panic
        # has nowhere to write — on a machine that panics by design, that is
        # lost findings — and every later harvest re-copies the same records.
        #
        # The directory entries are committed before the first unlink. Every
        # copy is fsynced, and the names pointing at them are not, so a panic
        # between the two loses records that pstore no longer holds either.
        # A directory that will not sync keeps its pstore originals: a full
        # pstore drops later panics, and clearing it here would drop this one.
        try:
            if copied:
                _fsync_dir(dest)
        except OSError as e:
            print("WARN: could not commit %s (%s); leaving %d pstore record(s) "
                  "in place. pstore may fill and drop later panics; re-run "
                  "harvest once the filesystem is writable."
                  % (dest, e, len(copied)))
            failures.append("/sys/fs/pstore (%d record(s) not cleared)"
                            % len(copied))
            copied = []
        for src in copied:
            try:
                os.unlink(src)
            except OSError as e:
                print("WARN: could not clear %s (%s); pstore may fill and drop "
                      "later panics" % (src, e))
    # Every unharvested dump, not just the newest: several panics can land
    # between two harvests, and taking only the last one silently discards the
    # earlier crashes. Files can vanish mid-harvest (kdump-tools is writing
    # to /var/crash at the same time), so stat and copy per-file and keep
    # going past individual failures.
    already = harvested_kdumps()

    def mtime(path):
        try:
            return os.path.getmtime(path)
        except OSError:
            return 0

    for src in sorted(glob.glob("/var/crash/*"), key=mtime):
        name = os.path.basename(src)
        if name in already or not os.path.isdir(src):
            continue
        marker = kdump_incomplete(src)
        if marker:
            # A dump still being written is a prefix of a vmcore, and
            # harvested_kdumps() keys on the name, so copying it now retires
            # that name for good and the finished dump is never collected.
            # Deferring costs one more harvest, and copying costs the dump.
            print("WARN: %s is still being written (%s); left for the next "
                  "harvest" % (src, marker))
            deferred.append(src)
            continue
        # Copied under a .partial name and renamed on completion, so a
        # harvest interrupted by a second panic leaves a name
        # harvested_kdumps() does not count and the dump is copied again.
        staging = os.path.join(dest, "kdump-" + name + PARTIAL_SUFFIX)
        try:
            shutil.copytree(src, staging, dirs_exist_ok=True)
            _fsync_dir(staging)
            os.replace(staging, os.path.join(dest, "kdump-" + name))
        except (OSError, shutil.Error) as e:
            print("WARN: could not copy %s (%s); continuing" % (src, e))
            failures.append(src)
            continue
        found = True
    report_disk()
    if not found:
        shutil.rmtree(dest, ignore_errors=True)
        if failures or deferred:
            # Nothing was harvested AND something could not be read. That is
            # not "no crashes"; it is a harvest that did not work, and the
            # caller has to be able to tell the two apart.
            sys.exit("harvest read nothing and left %d source(s) unread: %s. "
                     "This is not evidence that no crash occurred — fix the "
                     "cause and re-run before treating the panic as "
                     "unrecorded." % (len(failures) + len(deferred),
                                      ", ".join((failures + deferred)[:5])))
        print("no new crash logs found (checked %s and /var/crash)"
              % ("EC2 console output" if env == "ec2" else "pstore"))
        sys.exit(0)
    if failures:
        print("WARN: %d source(s) could not be read and are missing from this "
              "harvest: %s" % (len(failures), ", ".join(failures[:5])))
    if deferred:
        print("WARN: %d dump(s) were still being written and are missing from "
              "this harvest: %s. Re-run harvest once they finish."
              % (len(deferred), ", ".join(deferred[:5])))
    print(dest)  # last line = artifact path, consumed by callers
    if failures or deferred:
        # Evidence was collected and a source was not read. The docstring
        # promises non-zero for that, and an unattended caller that reads
        # only the exit code has no other way to learn the harvest is
        # incomplete. The path is on the last line either way.
        sys.exit(HARVEST_PARTIAL)


def main():
    args = sys.argv[1:]
    env = None
    keep = 10
    if "--env" in args:
        i = args.index("--env")
        try:
            env = args[i + 1]
        except IndexError:
            sys.exit(__doc__)
        if env not in ("ec2", "baremetal", "auto"):
            sys.exit(__doc__)
        del args[i:i + 2]
    if "--keep" in args:
        i = args.index("--keep")
        try:
            keep = int(args[i + 1])
        except (IndexError, ValueError):
            sys.exit("--keep needs a non-negative integer")
        if keep < 0:
            sys.exit("--keep needs a non-negative integer")
        del args[i:i + 2]
    if len(args) != 1 or args[0] not in ("setup", "verify", "harvest",
                                         "prune"):
        sys.exit(__doc__)
    if args[0] == "prune":
        return cmd_prune(env, keep)
    if env is None or env == "auto":
        env = detect_env()
    {"setup": cmd_setup, "verify": cmd_verify,
     "harvest": cmd_harvest}[args[0]](env)


if __name__ == "__main__":
    main()
