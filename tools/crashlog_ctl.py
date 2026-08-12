#!/usr/bin/env python3
"""Persistent kernel-crash log capture: ramoops/pstore + kdump.

Subcommands:
  setup    - install kdump-tools, ensure pstore mount, set crashkernel= param
  verify   - check pstore/kdump readiness; print sysrq test instructions
  harvest  - copy /sys/fs/pstore/* and newest /var/crash dump into artifacts/

Must run as root for setup/harvest. Debian-family (apt) only.
"""
import glob
import os
import shutil
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRASHES_DIR = os.path.join(REPO_ROOT, "artifacts", "crashes")
GRUB_DEFAULT = "/etc/default/grub"


def sh(cmd, check=True, capture=False):
    return subprocess.run(cmd, check=check, text=True,
                          capture_output=capture)


def cmd_setup():
    if os.geteuid() != 0:
        sys.exit("setup must run as root")
    sh(["apt-get", "update"])
    sh(["apt-get", "install", "-y", "kdump-tools", "pstore-tools"])
    # crashkernel param
    with open(GRUB_DEFAULT) as f:
        grub = f.read()
    if "crashkernel=" not in grub:
        shutil.copy(GRUB_DEFAULT, GRUB_DEFAULT + ".bak-cuda-fuzzing")
        grub = grub.replace(
            'GRUB_CMDLINE_LINUX_DEFAULT="',
            'GRUB_CMDLINE_LINUX_DEFAULT="crashkernel=256M ')
        with open(GRUB_DEFAULT, "w") as f:
            f.write(grub)
        sh(["update-grub"])
        print("added crashkernel=256M; reboot required")
    # pstore mount (usually automatic via systemd)
    if not os.path.ismount("/sys/fs/pstore"):
        sh(["mount", "-t", "pstore", "pstore", "/sys/fs/pstore"], check=False)
    sh(["systemctl", "enable", "kdump-tools"], check=False)
    print("setup done. Next: reboot, then run: crashlog_ctl.py verify")


def cmd_verify():
    ok = True
    if not os.path.isdir("/sys/fs/pstore"):
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
    if ok:
        print("READY. Now validate capture with a deliberate panic:")
        print("  1. sync")
        print("  2. echo c > /proc/sysrq-trigger   # machine panics, reboots")
        print("  3. after boot: crashlog_ctl.py harvest")
        print("     (must produce a dmesg/ramoops dump containing the panic)")
    sys.exit(0 if ok else 1)


def cmd_harvest():
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(CRASHES_DIR, "pstore-" + stamp)
    os.makedirs(dest, exist_ok=True)
    found = False
    for src in glob.glob("/sys/fs/pstore/*"):
        shutil.copy(src, dest)
        found = True
    crashes = sorted(glob.glob("/var/crash/*"), key=os.path.getmtime)
    if crashes:
        newest = crashes[-1]
        out = os.path.join(dest, "kdump-" + os.path.basename(newest))
        shutil.copytree(newest, out, dirs_exist_ok=True)
        found = True
    if not found:
        os.rmdir(dest)
        print("no crash logs found")
        sys.exit(1)
    print(dest)  # last line = artifact path, consumed by callers


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("setup", "verify", "harvest"):
        sys.exit(__doc__)
    {"setup": cmd_setup, "verify": cmd_verify,
     "harvest": cmd_harvest}[sys.argv[1]]()


if __name__ == "__main__":
    main()
