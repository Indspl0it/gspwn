#!/usr/bin/env python3
"""Install/manage fuzz campaigns as systemd units (survive panics/reboots).

Subcommands: install-k | install-u | start <k|u> | stop <k|u> | status
Requires root for install/start/stop. Reads config/campaign.yaml.
"""
import os
import subprocess
import sys

import yaml  # python3-yaml (apt)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
CFG_PATH = os.path.join(REPO_ROOT, "config", "campaign.yaml")
UNIT_K = "/etc/systemd/system/cuda-fuzz-k.service"
UNIT_U = "/etc/systemd/system/cuda-fuzz-u.service"

UNIT_K_TMPL = """[Unit]
Description=CUDA-Fuzzing Track K (syzkaller)
After=multi-user.target

[Service]
Type=simple
WorkingDirectory={root}
ExecStart={syzkaller}/bin/syz-manager -config {root}/artifacts/syz-manager.cfg
Restart=always
RestartSec=30
MemoryMax={memory_max}

[Install]
WantedBy=multi-user.target
"""

UNIT_U_TMPL = """[Unit]
Description=CUDA-Fuzzing Track U (NCT userspace fuzzers)
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/docker run --rm --name cuda-fuzz-u \\
  --memory={memory_max} \\
  --pids-limit=512 \\
  -v {root}/artifacts:/artifacts {image} \\
  /artifacts/harnesses/run_all.sh
Restart=always
RestartSec=30
MemoryMax={memory_max}

[Install]
WantedBy=multi-user.target
"""


def cfg():
    with open(CFG_PATH) as f:
        return yaml.safe_load(f)


def sh(cmd, check=True, capture=False):
    return subprocess.run(cmd, check=check, text=True, capture_output=capture)


def write_unit(path, text):
    if os.geteuid() != 0:
        sys.exit("install/start/stop must run as root")
    with open(path, "w") as f:
        f.write(text)
    sh(["systemctl", "daemon-reload"])


def cmd_install_k():
    c = cfg()["track_k"]
    syzkaller = os.path.join(REPO_ROOT, "artifacts", "src", "syzkaller")
    write_unit(UNIT_K, UNIT_K_TMPL.format(
        root=REPO_ROOT, syzkaller=syzkaller, memory_max=c["memory_max"]))
    sh(["systemctl", "enable", "cuda-fuzz-k"])
    print("installed cuda-fuzz-k.service (MemoryMax=%s)" % c["memory_max"])


def cmd_install_u():
    c = cfg()["track_u"]
    write_unit(UNIT_U, UNIT_U_TMPL.format(
        root=REPO_ROOT, image=c["docker_image"], memory_max=c["memory_max"]))
    sh(["systemctl", "enable", "cuda-fuzz-u"])
    print("installed cuda-fuzz-u.service (MemoryMax=%s)" % c["memory_max"])


def unit(track):
    return {"k": "cuda-fuzz-k", "u": "cuda-fuzz-u"}[track]


def cmd_start_stop(verb, track):
    if os.geteuid() != 0:
        sys.exit("start/stop must run as root")
    sh(["systemctl", verb, unit(track)])
    st = ps.load()
    st["campaigns"].append({"track": track, "action": verb})
    ps.save(st)
    print("%s %s" % (verb, unit(track)))


def cmd_status():
    for t in ("k", "u"):
        r = sh(["systemctl", "is-active", unit(t)], check=False, capture=True)
        print("track %s: %s" % (t, r.stdout.strip()))
    stats = os.path.join(REPO_ROOT, "artifacts", "syz-workdir", "stats")
    # syz-manager HTTP stats are canonical; fall back to corpus size
    corpus = os.path.join(REPO_ROOT, "artifacts", "syz-workdir", "corpus.db")
    if os.path.exists(corpus):
        print("corpus.db size: %d bytes" % os.path.getsize(corpus))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "install-k":
        cmd_install_k()
    elif cmd == "install-u":
        cmd_install_u()
    elif cmd in ("start", "stop") and len(sys.argv) == 3:
        cmd_start_stop(cmd, sys.argv[2])
    elif cmd == "status":
        cmd_status()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
