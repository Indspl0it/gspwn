#!/usr/bin/env python3
"""Keep the orchestrating agent alive across panics, with a circuit breaker.

Everything else in this pipeline already survives a kernel panic. The fuzz
units are Restart=always, the coverage sampler is a timer, the campaign
deadline is a timer, and the state file is written atomically. The agent
driving all of them was the one thing that did not come back: after a panic
its session was gone and AGENTS.md's resume procedure sat waiting for a human
to SSH in and type it. That is not an unattended pipeline.

The hard part was already solved. A fresh agent needs no memory of the old
session, because `pipeline_ctl.py next` tells it where the pipeline is. The
state machine IS the durable orchestrator memory. What was missing is only a
process supervisor, which is what this installs.

  gspwn-orchestrator.service   Restart=always, runs `orchestrator_ctl.py run`

## The circuit breaker

An always-restarting agent is a token bill with no ceiling, so `run` refuses
to launch under two distinct conditions, counted separately because they mean
different things:

  same-boot starts   The agent keeps exiting and being restarted without the
                     machine going down. Nothing is progressing and each
                     restart costs tokens. Low threshold.
  reboots            The machine keeps going down. Kernel fuzzing panics the
                     box by design, so this is NOT inherently wrong, and a
                     single counter would trip on a healthy campaign. It is
                     only a problem when reboots come faster than a round can
                     make progress between them. Higher threshold.

Counting both against one limit would either stop a healthy panicky campaign
or let a same-boot loop run all night. Both windows come from
config/campaign.yaml (`orchestrator:`).

When a breaker trips the run is recorded as blocked and `run` exits
BLOCKED_EXIT, which the unit lists in RestartPreventExitStatus so systemd
stops rather than restarting into the same wall. A human clears it with
`reset` after fixing whatever caused it.

`run` also stops the unit, the same way, when the pipeline is complete or a
phase is blocked. A finished pipeline that keeps relaunching an agent is the
same unbounded token loop by a different route.

Subcommands:
  install [--command 'CMD']   write and enable gspwn-orchestrator.service
  run                         breaker check, harvest, then exec the agent
  status                      breaker state and recent starts
  reset                       clear a tripped breaker (after fixing the cause)
  remove                      stop, disable and delete the unit

Requires root for install/remove. `run` is what the unit calls; running it by
hand does the same thing in the foreground.
"""
import argparse
import json
import os
import pwd
import subprocess
import sys
import time
from contextlib import contextmanager

import fcntl

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gspwn_config
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
UNIT_NAME = "gspwn-orchestrator"
UNIT_PATH = "/etc/systemd/system/%s.service" % UNIT_NAME
# Machine-global, like the spend ledger and for the same reason: a run that
# redirects GSPWN_STATE must not also get a fresh, empty breaker. GSPWN_ORCH
# exists only so the test suite can point it at a tempdir.
ORCH_PATH = os.environ.get("GSPWN_ORCH") or os.path.join(
    ps.STATE_DIR, "orchestrator.json")
# systemd stops instead of restarting when the unit exits with this. Anything
# outside 0-255 is not expressible as a process exit status; 78 is sysexits.h
# EX_CONFIG, which is close enough in meaning and not something python or a
# shell produces on its own.
BLOCKED_EXIT = 78

UNIT_TMPL = """[Unit]
Description=gspwn orchestrator (drives the pipeline across panics)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# A system unit runs as root unless told otherwise, and a coding agent keeps
# its login under the invoking user's HOME. Left as root the agent would look
# in /root, find no credentials, fail, and be restarted until the breaker
# trips. Both lines are load-bearing: User= alone does not set HOME.
User={user}
Environment=HOME={home}
Environment=XDG_CONFIG_HOME={home}/.config
WorkingDirectory={root}
ExecStart=/usr/bin/python3 {root}/tools/orchestrator_ctl.py run
Restart=always
RestartSec={restart_sec}
# The breaker in `run` is the real guard. This is the backstop for the case
# the breaker cannot see: a crash before its own state file can be written.
StartLimitIntervalSec={limit_interval}
StartLimitBurst={limit_burst}
# A tripped breaker, a complete pipeline and a blocked phase all exit with
# this. Restarting into any of them would spend tokens to reach the same wall.
RestartPreventExitStatus={blocked_exit}

[Install]
WantedBy=multi-user.target
"""


def cfg():
    try:
        return gspwn_config.load()
    except gspwn_config.ConfigError as e:
        sys.exit("error: %s" % e)


def require_root(what):
    if os.geteuid() != 0:
        sys.exit("%s must run as root" % what)


def boot_id():
    """Current boot's id, or None when it cannot be read.

    None is a real answer: a start whose boot is unidentifiable is counted
    against the same-boot limit rather than being treated as a fresh boot,
    because assuming a reboot is what would let a same-boot loop run forever.
    """
    try:
        with open("/proc/sys/kernel/random/boot_id") as f:
            return f.read().strip() or None
    except OSError:
        return None


@contextmanager
def _breaker_lock():
    """Exclusive read-modify-write on the breaker file, on its own lock.

    `status` and `reset` can run while the unit is starting, and the start
    record is a read-modify-write like the spend ledger's.
    """
    os.makedirs(os.path.dirname(ORCH_PATH) or ".", exist_ok=True)
    lock = ORCH_PATH + ".lock"
    fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    ps._fix_root_ownership([lock])


def _read():
    """Breaker state, or a fresh one. A corrupt file is not silently reset.

    Resetting it on a parse error would clear a trip the operator has not seen,
    which is the one thing this file exists to prevent.
    """
    if not os.path.exists(ORCH_PATH):
        return {"starts": [], "blocked": None}
    with open(ORCH_PATH) as f:
        try:
            raw = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(
                "%s is not valid JSON (%s). Restore it from %s.bak, or "
                "delete it deliberately if you accept losing the restart "
                "history the breaker counts." % (ORCH_PATH, e, ORCH_PATH))
    if not isinstance(raw, dict):
        raise ValueError("%s must contain a JSON object" % ORCH_PATH)
    raw.setdefault("starts", [])
    raw.setdefault("blocked", None)
    if not isinstance(raw["starts"], list):
        raise ValueError("%s: 'starts' must be a list" % ORCH_PATH)
    return raw


def _write(state):
    ps.save(state, ORCH_PATH)


def _recent(starts, window_min, now):
    cutoff = now - window_min * 60
    return [s for s in starts if (s.get("ts") or 0) >= cutoff]


def check(state, conf, now, this_boot):
    """-> (reason, None) if a breaker has tripped, else (None, counts).

    Pure: takes the state it judges rather than reading the file, so the
    thresholds can be exercised without a machine that reboots.
    """
    o = conf["orchestrator"]
    recent = _recent(state["starts"], o["window_min"], now)
    same_boot = [s for s in recent if s.get("boot_id") == this_boot]
    boots = {s.get("boot_id") for s in recent}
    counts = {"window_min": o["window_min"], "recent": len(recent),
              "same_boot": len(same_boot), "boots": len(boots)}
    if len(same_boot) > o["max_same_boot_starts"]:
        return ("the agent has started %d times on this boot within %d min "
                "(limit %d). It is exiting and being restarted without the "
                "machine going down, so nothing is progressing and every "
                "restart costs tokens. Read the unit's journal, fix the "
                "cause, then `orchestrator_ctl.py reset`."
                % (len(same_boot), o["window_min"],
                   o["max_same_boot_starts"]), None)
    if len(boots) > o["max_reboots"]:
        return ("the machine has booted %d times within %d min (limit %d). "
                "This pipeline panics the box by design, so reboots are "
                "expected — this many means they are arriving faster than a "
                "round can progress between them. Harvest the crash logs and "
                "look at what is panicking on boot before resuming, then "
                "`orchestrator_ctl.py reset`."
                % (len(boots), o["window_min"], o["max_reboots"]), None)
    return None, counts


def _block(state, reason, now):
    state["blocked"] = {"at": int(now), "reason": reason}
    _write(state)


def harvest():
    """Best-effort crash harvest before resuming, per AGENTS.md.

    A harvest failure must not stop the pipeline: the crash evidence matters,
    but so does the campaign, and refusing to resume because pstore was empty
    would trade a whole run for a log. It is reported loudly instead.
    """
    tool = os.path.join(REPO_ROOT, "tools", "crashlog_ctl.py")
    cmd = ["python3", tool, "harvest"]
    if os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd
    try:
        r = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True,
                           timeout=300)
    except (OSError, subprocess.TimeoutExpired) as e:
        print("WARN: crash harvest did not complete (%s). Resuming anyway; "
              "run `crashlog_ctl.py harvest` by hand to recover whatever a "
              "panic left behind." % e)
        return
    if r.returncode != 0:
        print("WARN: crash harvest exited %d: %s. Resuming anyway; run it by "
              "hand to recover whatever a panic left behind."
              % (r.returncode, (r.stderr or r.stdout or "").strip()[:400]))
    else:
        print(r.stdout.strip())


def pipeline_stop_reason():
    """Why the agent should NOT be launched, or None to go ahead."""
    try:
        st = ps.load()
    except ValueError as e:
        # A corrupt state file is not something to relaunch an agent into: it
        # would read the same broken file and stop again, once per restart.
        return "pipeline state cannot be read: %s" % e
    blocked = sorted(p for p in ps.PHASES
                     if st["phases"][p]["status"] == "blocked")
    if blocked:
        return ("phase(s) %s are blocked. A blocked gate is a stop by "
                "design, not something to retry — resolve it, then "
                "`orchestrator_ctl.py reset`." % ", ".join(blocked))
    kind, _ = ps.next_action(st)
    if kind == "done":
        return ("the pipeline is complete. Nothing left to drive, so the "
                "unit stops instead of relaunching an agent that would read "
                "the same answer.")
    return None


def cmd_run(a):
    conf = cfg()
    command = a.command or conf["orchestrator"]["command"]
    if not command:
        # Exit BLOCKED_EXIT, not 1: restarting every 60s against a config
        # value that only a human can supply is the loop this tool exists to
        # prevent.
        print("orchestrator.command is not set in config/campaign.yaml. This "
              "repo does not guess which coding-agent CLI is installed; set "
              "the headless invocation explicitly, e.g.\n"
              "  orchestrator:\n"
              "    command: \"claude -p 'run the pipeline'\"")
        return BLOCKED_EXIT
    now = time.time()
    this_boot = boot_id()
    with _breaker_lock():
        try:
            state = _read()
        except ValueError as e:
            sys.exit("refusing to start: %s" % e)
        if state["blocked"]:
            print("orchestrator is blocked (since %s): %s"
                  % (_ts(state["blocked"]["at"]), state["blocked"]["reason"]))
            return BLOCKED_EXIT
        state["starts"] = _recent(state["starts"],
                                  conf["orchestrator"]["window_min"], now)
        state["starts"].append({"ts": int(now), "boot_id": this_boot})
        reason, counts = check(state, conf, now, this_boot)
        if reason:
            _block(state, reason, now)
            print("circuit breaker tripped: %s" % reason)
            return BLOCKED_EXIT
        _write(state)
    print("orchestrator start: %d in the last %d min (%d on this boot, "
          "%d distinct boot(s))"
          % (counts["recent"], counts["window_min"], counts["same_boot"],
             counts["boots"]))

    stop = pipeline_stop_reason()
    if stop:
        print("not launching the agent: %s" % stop)
        return BLOCKED_EXIT

    harvest()
    print("launching: %s" % command)
    sys.stdout.flush()
    # shell=True because the configured value is a command line the operator
    # wrote, not an argv this tool assembled. Nothing user-controlled reaches
    # it at runtime: it comes from a config file only root can install a unit
    # from, and it is the whole point of the setting.
    r = subprocess.run(command, shell=True, cwd=REPO_ROOT)
    print("agent exited %d" % r.returncode)
    return r.returncode


def _ts(v):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(v)) if v else "?"


def cmd_status(a):
    conf = cfg()
    o = conf["orchestrator"]
    try:
        state = _read()
    except ValueError as e:
        sys.exit(str(e))
    now = time.time()
    recent = _recent(state["starts"], o["window_min"], now)
    boots = {s.get("boot_id") for s in recent}
    print("unit:      %s" % ("installed" if os.path.exists(UNIT_PATH)
                             else "not installed"))
    print("command:   %s" % (o["command"] or "(unset — install will refuse)"))
    print("window:    %d min; limits: %d same-boot start(s), %d reboot(s)"
          % (o["window_min"], o["max_same_boot_starts"], o["max_reboots"]))
    print("in window: %d start(s) across %d boot(s)" % (len(recent),
                                                        len(boots)))
    for s in recent[-10:]:
        print("  %s  boot %s" % (_ts(s.get("ts")),
                                 (s.get("boot_id") or "unknown")[:8]))
    if state["blocked"]:
        print("BLOCKED since %s: %s" % (_ts(state["blocked"]["at"]),
                                        state["blocked"]["reason"]))
        print("Clear with: python3 tools/orchestrator_ctl.py reset")
        return 1
    print("not blocked")
    return 0


def cmd_reset(a):
    with _breaker_lock():
        try:
            state = _read()
        except ValueError:
            # reset is the documented way out of a corrupt breaker file, so
            # it is the one command allowed to start over.
            state = {"starts": [], "blocked": None}
        was = state["blocked"]
        state["blocked"] = None
        # Clearing the trip without clearing the history would re-trip on the
        # very next start, since the counted window has not moved.
        state["starts"] = []
        _write(state)
    print("breaker cleared%s" % (" (was: %s)" % was["reason"] if was else ""))
    if os.path.exists(UNIT_PATH):
        print("start it again with: sudo systemctl start %s" % UNIT_NAME)
    return 0


def cmd_install(a):
    require_root("install")
    conf = cfg()
    o = conf["orchestrator"]
    command = a.command or o["command"]
    if not command:
        sys.exit("refusing to install: no agent command. This repo is not "
                 "tied to one coding-agent CLI, so it will not guess which "
                 "is installed. Pass --command, or set it in "
                 "config/campaign.yaml:\n"
                 "  orchestrator:\n"
                 "    command: \"claude -p 'run the pipeline'\"")
    if a.command and a.command != o["command"]:
        # The unit is generated from config on every install; a --command that
        # is not also in the file silently disappears on the next reinstall.
        print("NOTE: --command was used but config/campaign.yaml still says "
              "%r. Put it in the config file too, or the next install will "
              "write the config value into the unit."
              % (o["command"] or ""))
    user = a.user or os.environ.get("SUDO_USER") or ""
    if not user or user == "root":
        sys.exit(
            "refusing to install: no non-root user to run the agent as. "
            "A system unit runs as root, and a coding agent keeps its login "
            "under the invoking user's HOME — as root it would look in "
            "/root, find no credentials, fail, and be restarted until the "
            "breaker trips. Pass --user <name> (or install with sudo from "
            "that user's shell, which sets SUDO_USER).")
    try:
        home = pwd.getpwnam(user).pw_dir
    except KeyError:
        sys.exit("refusing to install: no such user %r" % user)
    if not os.path.isdir(os.path.join(home, ".claude")) and not a.force:
        print("NOTE: %s/.claude does not exist. If the agent keeps its "
              "credentials elsewhere this is fine; if not, log it in as %s "
              "before starting the unit." % (home, user))
    if os.environ.get("ANTHROPIC_API_KEY"):
        print("WARNING: ANTHROPIC_API_KEY is set in this environment. If it "
              "is also set for the unit (via /etc/environment or a drop-in) "
              "it takes precedence over a subscription login and bills the "
              "API instead. The unit written here does not set it.")
    text = UNIT_TMPL.format(root=REPO_ROOT, restart_sec=a.restart_sec,
                            user=user, home=home,
                            limit_interval=o["window_min"] * 60,
                            limit_burst=o["max_same_boot_starts"] * 4,
                            blocked_exit=BLOCKED_EXIT)
    # The command lives in config, not in the unit: editing campaign.yaml then
    # rebooting must not silently keep running the old invocation baked into
    # a unit file nobody re-generated.
    with open(UNIT_PATH, "w") as f:
        f.write(text)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", UNIT_NAME], check=True)
    print("installed and enabled %s" % UNIT_NAME)
    print("  runs as:  %s (HOME=%s)" % (user, home))
    print("  command:  %s" % command)
    print("  restart:  every %ss, blocked at %d same-boot start(s) or %d "
          "reboot(s) per %d min"
          % (a.restart_sec, o["max_same_boot_starts"], o["max_reboots"],
             o["window_min"]))
    print("start it now with: sudo systemctl start %s" % UNIT_NAME)
    return 0


def cmd_remove(a):
    require_root("remove")
    subprocess.run(["systemctl", "disable", "--now", UNIT_NAME], check=False)
    if os.path.exists(UNIT_PATH):
        os.unlink(UNIT_PATH)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    print("removed %s (breaker state in %s is kept; `reset` clears it)"
          % (UNIT_NAME, ORCH_PATH))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="orchestrator_ctl.py",
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("install")
    q.add_argument("--command", default=None,
                   help="headless agent invocation (default: "
                        "orchestrator.command from config/campaign.yaml)")
    q.add_argument("--restart-sec", dest="restart_sec", type=int, default=60,
                   help="systemd RestartSec (default 60)")
    q.add_argument("--user", default=None,
                   help="user to run the agent as (default: $SUDO_USER). Its "
                        "HOME is where the agent's credentials live.")
    q.add_argument("--force", action="store_true",
                   help="install even if the user has no ~/.claude")
    q.set_defaults(fn=cmd_install)

    q = sub.add_parser("run")
    q.add_argument("--command", default=None)
    q.set_defaults(fn=cmd_run)

    q = sub.add_parser("status")
    q.set_defaults(fn=cmd_status)

    q = sub.add_parser("reset")
    q.set_defaults(fn=cmd_reset)

    q = sub.add_parser("remove")
    q.set_defaults(fn=cmd_remove)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
