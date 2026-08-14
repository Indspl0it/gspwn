#!/usr/bin/env python3
"""EC2 cost guardrails: idle auto-stop.

Subcommands:
  check-idle         - stop the instance if idle (both fuzz units inactive,
                       no syz-manager process) longer than IDLE_MINUTES
  install-watchdog   - install a systemd timer running check-idle every 30 min
  keepalive [--hours N] [--clear]
                     - hold the watchdog off for N hours (default 4) during
                       long interactive/agent sessions; --clear removes the
                       hold immediately

Idle override: state/KEEP_ALIVE contains an ISO-8601 UTC expiry timestamp.
While it is unexpired the instance is never stopped AND the idle clock is
reset, so the box gets a full fresh idle window once the hold lapses. An
expired or malformed KEEP_ALIVE is treated as absent and deleted — a stale
kill-switch must never permanently disable the only automated stop.

EC2 default shutdown behavior for EBS instances is 'stop', so shutdown -h
preserves the volume and artifacts.
"""
import argparse
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gspwn_config

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_DIR = os.path.join(REPO_ROOT, "state")
KEEP_ALIVE = os.path.join(STATE_DIR, "KEEP_ALIVE")
IDLE_FILE = os.path.join(STATE_DIR, "idle_since")

KEEPALIVE_DEFAULT_HOURS = 4


def _cost_cfg():
    try:
        return gspwn_config.cost()
    except gspwn_config.ConfigError as e:
        sys.exit("error: %s" % e)


# The installed unit pins the value it was installed with (below), so an
# already-running watchdog keeps its cap until reinstalled; a bare run falls
# back to the configured one.
try:
    IDLE_MINUTES = int(os.environ["IDLE_MINUTES"])
except (KeyError, ValueError):
    IDLE_MINUTES = int(_cost_cfg()["idle_stop_minutes"])

TIMER_UNIT = """[Unit]
Description=gspwn idle auto-stop

[Timer]
OnBootSec={every}min
OnUnitActiveSec={every}min

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


def read_keepalive(path=KEEP_ALIVE, now=None):
    """Return (active, expiry) for the KEEP_ALIVE sentinel.

    active is True only when the file holds an unexpired ISO-8601 expiry
    (a timezone-aware datetime). An absent file yields (False, None); an
    expired or malformed sentinel is deleted and also yields (False, None),
    so a leftover from a crashed session or a reboot cannot disable the
    watchdog forever. Pure over injectable path/now for offline testing.
    """
    if not os.path.exists(path):
        return False, None
    try:
        with open(path) as f:
            expiry = datetime.fromisoformat(f.read().strip())
        if expiry.tzinfo is None:
            raise ValueError("naive timestamp")
    except (ValueError, OSError):
        expiry = None
    now = now if now is not None else datetime.now(timezone.utc)
    if expiry is None or expiry <= now:
        try:
            os.remove(path)
        except OSError:
            pass
        return False, None
    return True, expiry


def is_idle():
    for unit in ("gspwn-k", "gspwn-u"):
        r = subprocess.run(["systemctl", "is-active", unit],
                           capture_output=True, text=True)
        # 'activating' is the RestartSec backoff of the Restart=always fuzz
        # units after a syz-manager crash — a unit mid-restart is a running
        # campaign, not an idle box.
        if r.stdout.strip() in ("active", "activating"):
            return False
    # Exact comm match: 'pgrep -f' would also match any stray cmdline
    # containing the substring (tail -f on the log, a grep, an editor) and
    # suppress the idle stop indefinitely.
    r = subprocess.run(["pgrep", "-x", "syz-manager"], capture_output=True)
    return r.returncode != 0


def cmd_check_idle(state_dir=STATE_DIR):
    # The watchdog runs from a systemd timer on a machine that reboots after
    # panics; state/ may not exist yet on a fresh clone.
    os.makedirs(state_dir, exist_ok=True)
    keep_alive = os.path.join(state_dir, "KEEP_ALIVE")
    idle_file = os.path.join(state_dir, "idle_since")
    held, expiry = read_keepalive(keep_alive)
    if held:
        # Reset the idle clock for the whole hold: the moment the sentinel
        # expires or is cleared, the box must get a full fresh idle window,
        # never an instant shutdown from a stale marker.
        try:
            os.remove(idle_file)
        except FileNotFoundError:
            pass
        print("KEEP_ALIVE active until %s; not stopping"
              % expiry.isoformat())
        return
    if is_idle():
        if os.path.exists(idle_file):
            try:
                with open(idle_file) as f:
                    since = float(f.read().strip())
            except (ValueError, OSError):
                # Corrupt marker (e.g. truncated by a panic): restart the clock
                # rather than crash the watchdog or stop the box early. The
                # removal is best-effort — the file may already be gone, and
                # raising here would produce the traceback this handler prevents.
                try:
                    os.remove(idle_file)
                except OSError:
                    pass
                print("idle marker unreadable; timer restarted")
                return
            idle_min = (time.time() - since) / 60
            if idle_min >= IDLE_MINUTES:
                print("idle %.0f min >= %d; stopping instance"
                      % (idle_min, IDLE_MINUTES))
                r = subprocess.run(["shutdown", "-h", "now"],
                                   capture_output=True, text=True)
                if r.returncode != 0:
                    # Leave idle state intact so the next timer tick retries.
                    print("error: shutdown failed (rc %d): %s; will retry "
                          "on next check"
                          % (r.returncode, r.stderr.strip() or "no output"),
                          file=sys.stderr)
                    return
                print("shutdown issued")
                return
            print("idle %.0f min; threshold %d" % (idle_min, IDLE_MINUTES))
        else:
            with open(idle_file, "w") as f:
                f.write(str(time.time()))
            print("now idle; timer started")
    else:
        if os.path.exists(idle_file):
            os.remove(idle_file)
        print("active campaign; not idle")


def cmd_keepalive(argv, state_dir=STATE_DIR):
    p = argparse.ArgumentParser(prog="cost_ctl.py keepalive")
    p.add_argument("--hours", type=float, default=KEEPALIVE_DEFAULT_HOURS,
                   help="hold the watchdog off this long (default %(default)s)")
    p.add_argument("--clear", action="store_true",
                   help="remove the hold immediately")
    a = p.parse_args(argv)
    os.makedirs(state_dir, exist_ok=True)
    keep_alive = os.path.join(state_dir, "KEEP_ALIVE")
    idle_file = os.path.join(state_dir, "idle_since")
    if a.clear:
        try:
            os.remove(keep_alive)
            print("KEEP_ALIVE cleared")
        except FileNotFoundError:
            print("no KEEP_ALIVE present")
        return
    if a.hours <= 0:
        sys.exit("error: --hours must be positive")
    expiry = datetime.now(timezone.utc) + timedelta(hours=a.hours)
    with open(keep_alive, "w") as f:
        f.write(expiry.isoformat() + "\n")
    # Fresh idle window once the hold lapses (see cmd_check_idle).
    try:
        os.remove(idle_file)
    except FileNotFoundError:
        pass
    print("KEEP_ALIVE until %s (%g hours)" % (expiry.isoformat(), a.hours))


def cmd_install_watchdog():
    if os.geteuid() != 0:
        sys.exit("install-watchdog must run as root")
    every = int(_cost_cfg()["idle_check_minutes"])
    with open("/etc/systemd/system/gspwn-idlestop.service", "w") as f:
        f.write(SERVICE_UNIT.format(root=REPO_ROOT, idle=IDLE_MINUTES))
    with open("/etc/systemd/system/gspwn-idlestop.timer", "w") as f:
        f.write(TIMER_UNIT.format(every=every))
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now",
                    "gspwn-idlestop.timer"], check=True)
    print("idle watchdog installed (checks every %d min, threshold %d min "
          "baked into the unit)" % (every, IDLE_MINUTES))
    print("to change either, edit config/campaign.yaml (cost:) and re-run "
          "install-watchdog")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    if sys.argv[1] == "check-idle":
        cmd_check_idle()
    elif sys.argv[1] == "install-watchdog":
        cmd_install_watchdog()
    elif sys.argv[1] == "keepalive":
        cmd_keepalive(sys.argv[2:])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
