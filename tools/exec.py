#!/usr/bin/env python3
"""Logged local command runner with retries. Stdlib only.

Usage: python3 tools/exec.py --log NAME [--retries N] [--timeout S] -- CMD [ARGS...]

NAME is reduced to its basename so the log always lands in artifacts/logs/.
Timeout maps to rc 124; a command that does not exist maps to rc 127, with
the attempt logged like any other failure.

--timeout defaults to GSPWN_EXEC_TIMEOUT_SEC or four hours, which is a
backstop over a kernel build and not a working limit. Pass 0 to run
unbounded.
"""
import argparse
import os
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGDIR = os.path.join(REPO_ROOT, "artifacts", "logs")

TIMEOUT_ENV = "GSPWN_EXEC_TIMEOUT_SEC"


def default_timeout_sec(default=14400):
    """The default --timeout, from TIMEOUT_ENV or `default`.

    The longest thing this runner wraps is a kernel build, which takes hours
    on the smaller instances, so four hours is a backstop and not a working
    limit. It exists because the default was None: a build that wedged on a
    stuck device probe held the retry loop with no log line and no exit, and
    the phase it belonged to reported nothing at all. `--timeout 0` runs
    unbounded where that is the deliberate choice.
    """
    raw = os.environ.get(TIMEOUT_ENV)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        sys.exit("%s=%r is not an integer. Unset it to use the default of %d "
                 "seconds." % (TIMEOUT_ENV, raw, default))
    if value < 0:
        sys.exit("%s=%d cannot be negative. Unset it to use the default of "
                 "%d seconds, or pass --timeout 0 to run unbounded."
                 % (TIMEOUT_ENV, value, default))
    return value


def run(cmd, log_name, retries=0, timeout=None):
    os.makedirs(LOGDIR, exist_ok=True)
    # --log is agent-supplied: strip any path components so '../../x' cannot
    # escape artifacts/logs/.
    log_name = os.path.basename(log_name) or "exec"
    logpath = os.path.join(LOGDIR, log_name + ".log")
    attempt = 0
    while True:
        attempt += 1
        with open(logpath, "a") as log:
            log.write("\n=== %s attempt %d: %s\n"
                      % (time.strftime("%Y-%m-%dT%H:%M:%S"), attempt,
                         " ".join(cmd)))
            log.flush()
            try:
                proc = subprocess.run(cmd, stdout=log,
                                      stderr=subprocess.STDOUT,
                                      timeout=timeout)
                rc = proc.returncode
            except subprocess.TimeoutExpired:
                log.write("TIMEOUT after %ss\n" % timeout)
                rc = 124
            except FileNotFoundError:
                # Typo'd/missing binary: record the attempt like any other
                # failure instead of losing it to an uncaught traceback.
                log.write("command not found: %s\n" % cmd[0])
                rc = 127
        if rc == 0 or attempt > retries:
            return rc
        time.sleep(2)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--log", required=True)
    p.add_argument("--retries", type=int, default=0)
    p.add_argument("--timeout", type=int, default=default_timeout_sec(),
                   help="seconds one attempt may take (default %d, or "
                        "%s); 0 runs unbounded"
                        % (default_timeout_sec(), TIMEOUT_ENV))
    p.add_argument("cmd", nargs=argparse.REMAINDER)
    a = p.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        p.error("no command given")
    if a.timeout < 0:
        p.error("--timeout cannot be negative; pass 0 to run unbounded")
    sys.exit(run(cmd, a.log, a.retries, a.timeout or None))


if __name__ == "__main__":
    main()
