#!/usr/bin/env python3
"""Persistent kernel-crash log capture: ramoops/pstore + kdump (bare metal)
or kdump + EC2 console output (cloud).

Subcommands:
  setup    - install kdump-tools, ensure pstore mount (bare metal only), set
             crashkernel= param
  verify   - check pstore/kdump readiness; print sysrq test instructions
  harvest  - copy /sys/fs/pstore/* and newest /var/crash dump into artifacts/;
             on EC2 also save `aws ec2 get-console-output` output

Global flag: --env ec2|baremetal overrides environment auto-detection
(default: auto-detect via the EC2 instance metadata service).

Must run as root for setup/harvest. Debian-family (apt) only.
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
METADATA_URL = "http://169.254.169.254/latest/meta-data/instance-id"


def sh(cmd, check=True, capture=False):
    return subprocess.run(cmd, check=check, text=True,
                          capture_output=capture)


def detect_env():
    """Return "ec2" if the instance metadata service answers, else
    "baremetal"."""
    try:
        urllib.request.urlopen(METADATA_URL, timeout=2)
        return "ec2"
    except Exception:
        return "baremetal"


def get_instance_id():
    with urllib.request.urlopen(METADATA_URL, timeout=2) as r:
        return r.read().decode().strip()


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
        grub = grub.replace(
            'GRUB_CMDLINE_LINUX_DEFAULT="',
            'GRUB_CMDLINE_LINUX_DEFAULT="crashkernel=256M ')
        with open(GRUB_DEFAULT, "w") as f:
            f.write(grub)
        sh(["update-grub"])
        print("added crashkernel=256M; reboot required")
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


def harvested_kdumps():
    """Basenames of /var/crash dumps already copied by a previous harvest."""
    seen = set()
    for d in glob.glob(os.path.join(CRASHES_DIR, "*", "kdump-*")):
        seen.add(os.path.basename(d)[len("kdump-"):])
    return seen


def cmd_harvest(env):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(CRASHES_DIR, "pstore-" + stamp)
    os.makedirs(dest, exist_ok=True)
    found = False
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
            shutil.copy(src, dest)
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
    # earlier crashes.
    already = harvested_kdumps()
    for src in sorted(glob.glob("/var/crash/*"), key=os.path.getmtime):
        name = os.path.basename(src)
        if name in already or not os.path.isdir(src):
            continue
        shutil.copytree(src, os.path.join(dest, "kdump-" + name),
                        dirs_exist_ok=True)
        found = True
    if not found:
        shutil.rmtree(dest, ignore_errors=True)
        print("no crash logs found")
        sys.exit(1)
    print(dest)  # last line = artifact path, consumed by callers


def main():
    args = sys.argv[1:]
    env = None
    if "--env" in args:
        i = args.index("--env")
        try:
            env = args[i + 1]
        except IndexError:
            sys.exit(__doc__)
        if env not in ("ec2", "baremetal"):
            sys.exit(__doc__)
        del args[i:i + 2]
    if len(args) != 1 or args[0] not in ("setup", "verify", "harvest"):
        sys.exit(__doc__)
    if env is None:
        env = detect_env()
    {"setup": cmd_setup, "verify": cmd_verify,
     "harvest": cmd_harvest}[args[0]](env)


if __name__ == "__main__":
    main()
