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
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRASHES_DIR = os.path.join(REPO_ROOT, "artifacts", "crashes")
GRUB_DEFAULT = "/etc/default/grub"
IMDS_BASE = "http://169.254.169.254/latest"
IMDS_TIMEOUT = 2


def sh(cmd, check=True, capture=False):
    return subprocess.run(cmd, check=check, text=True,
                          capture_output=capture)


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
        shutil.copy(GRUB_DEFAULT, GRUB_DEFAULT + ".bak-gspwn")
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
        with open(GRUB_DEFAULT, "w") as f:
            f.write(grub)
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
    sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))
    try:
        import coverage_ctl
        free_mb = coverage_ctl.disk_free_mb()
        warning = coverage_ctl.disk_warning(free_mb)
    except Exception:
        free_mb, warning = None, ""
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
    """Basenames of /var/crash dumps already copied by a previous harvest."""
    seen = set()
    for d in glob.glob(os.path.join(CRASHES_DIR, "*", "kdump-*")):
        seen.add(os.path.basename(d)[len("kdump-"):])
    return seen


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
    if env == "ec2":
        console_log = os.path.join(dest, "console-output.log")
        try:
            instance_id = get_instance_id()
            r = sh(["aws", "ec2", "get-console-output",
                    "--instance-id", instance_id,
                    "--latest", "--output", "text"], check=False, capture=True)
            if r.returncode == 0 and r.stdout.strip():
                with open(console_log, "w") as f:
                    f.write(r.stdout)
                found = True
                print("saved console output: " + console_log)
            else:
                print("WARN: get-console-output failed: " + r.stderr.strip())
        except Exception as e:
            print("WARN: console-output harvest failed: %s" % e)
    else:
        copied = []
        for src in glob.glob("/sys/fs/pstore/*"):
            try:
                shutil.copy(src, dest)
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
        try:
            shutil.copytree(src, os.path.join(dest, "kdump-" + name),
                            dirs_exist_ok=True)
        except (OSError, shutil.Error) as e:
            print("WARN: could not copy %s (%s); continuing" % (src, e))
            failures.append(src)
            continue
        found = True
    report_disk()
    if not found:
        shutil.rmtree(dest, ignore_errors=True)
        if failures:
            # Nothing was harvested AND something could not be read. That is
            # not "no crashes"; it is a harvest that did not work, and the
            # caller has to be able to tell the two apart.
            sys.exit("harvest read nothing and failed on %d source(s): %s. "
                     "This is not evidence that no crash occurred — fix the "
                     "cause and re-run before treating the panic as "
                     "unrecorded." % (len(failures), ", ".join(failures[:5])))
        print("no new crash logs found (checked %s and /var/crash)"
              % ("EC2 console output" if env == "ec2" else "pstore"))
        sys.exit(0)
    if failures:
        print("WARN: %d source(s) could not be read and are missing from this "
              "harvest: %s" % (len(failures), ", ".join(failures[:5])))
    print(dest)  # last line = artifact path, consumed by callers


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
