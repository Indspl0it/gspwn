#!/usr/bin/env python3
"""Logged local command runner with retries. Stdlib only.

Usage: python3 tools/exec.py --log NAME [--retries N] [--timeout S] -- CMD [ARGS...]

NAME is reduced to its basename so the log always lands in artifacts/logs/.
Timeout maps to rc 124; a command that does not exist maps to rc 127, with
the attempt logged like any other failure.
"""
import argparse
import os
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGDIR = os.path.join(REPO_ROOT, "artifacts", "logs")


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
    p.add_argument("--timeout", type=int, default=None)
    p.add_argument("cmd", nargs=argparse.REMAINDER)
    a = p.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        p.error("no command given")
    sys.exit(run(cmd, a.log, a.retries, a.timeout))


if __name__ == "__main__":
    main()
