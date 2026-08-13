#!/usr/bin/env python3
"""EC2 cost guardrails: idle auto-stop.

Subcommands:
  check-idle         - stop the instance if idle (both fuzz units inactive,
                       no syz-manager process) longer than IDLE_MINUTES
  install-watchdog   - install a systemd timer running check-idle every 30 min
Idle override: if state/KEEP_ALIVE exists, never stop (long agent sessions).
EC2 default shutdown behavior for EBS instances is 'stop', so shutdown -h
preserves the volume and artifacts.
"""
import os
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_DIR = os.path.join(REPO_ROOT, "state")
KEEP_ALIVE = os.path.join(STATE_DIR, "KEEP_ALIVE")
IDLE_FILE = os.path.join(STATE_DIR, "idle_since")
try:
    IDLE_MINUTES = int(os.environ.get("IDLE_MINUTES", "120"))
except ValueError:
    IDLE_MINUTES = 120

TIMER_UNIT = """[Unit]
Description=gspwn idle auto-stop

[Timer]
OnBootSec=30min
OnUnitActiveSec=30min

[Install]
WantedBy=timers.target
"""
SERVICE_UNIT = """[Unit]
Description=gspwn idle auto-stop check

[Service]
Type=oneshot
Environment=IDLE_MINUTES={idle}
ExecStart=/usr/bin/python3 {root}/tools/cost_ctl.py check-idle
"""


def is_idle():
    for unit in ("gspwn-k", "gspwn-u"):
        r = subprocess.run(["systemctl", "is-active", unit],
                           capture_output=True, text=True)
        if r.stdout.strip() == "active":
            return False
    r = subprocess.run(["pgrep", "-f", "syz-manager"], capture_output=True)
    return r.returncode != 0


def cmd_check_idle():
    # The watchdog runs from a systemd timer on a machine that reboots after
    # panics; state/ may not exist yet on a fresh clone.
    os.makedirs(STATE_DIR, exist_ok=True)
    if os.path.exists(KEEP_ALIVE):
        print("KEEP_ALIVE present; not stopping")
        return
    if is_idle():
        if os.path.exists(IDLE_FILE):
            try:
                with open(IDLE_FILE) as f:
                    since = float(f.read().strip())
            except (ValueError, OSError):
                # Corrupt marker (e.g. truncated by a panic): restart the clock
                # rather than crash the watchdog or stop the box early.
                os.remove(IDLE_FILE)
                print("idle marker unreadable; timer restarted")
                return
            idle_min = (time.time() - since) / 60
            if idle_min >= IDLE_MINUTES:
                print("idle %.0f min >= %d; stopping instance"
                      % (idle_min, IDLE_MINUTES))
                subprocess.run(["shutdown", "-h", "now"])
                return
            print("idle %.0f min; threshold %d" % (idle_min, IDLE_MINUTES))
        else:
            with open(IDLE_FILE, "w") as f:
                f.write(str(time.time()))
            print("now idle; timer started")
    else:
        if os.path.exists(IDLE_FILE):
            os.remove(IDLE_FILE)
        print("active campaign; not idle")


def cmd_install_watchdog():
    if os.geteuid() != 0:
        sys.exit("install-watchdog must run as root")
    with open("/etc/systemd/system/gspwn-idlestop.service", "w") as f:
        f.write(SERVICE_UNIT.format(root=REPO_ROOT, idle=IDLE_MINUTES))
    with open("/etc/systemd/system/gspwn-idlestop.timer", "w") as f:
        f.write(TIMER_UNIT)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now",
                    "gspwn-idlestop.timer"], check=True)
    print("idle watchdog installed (every 30 min, threshold %d min baked "
          "into the unit)" % IDLE_MINUTES)
    print("to change the threshold later: systemctl edit "
          "gspwn-idlestop.service")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("check-idle",
                                                 "install-watchdog"):
        sys.exit(__doc__)
    {"check-idle": cmd_check_idle,
     "install-watchdog": cmd_install_watchdog}[sys.argv[1]]()


if __name__ == "__main__":
    main()
