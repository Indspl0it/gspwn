#!/usr/bin/env python3
"""Install/manage fuzz campaigns as systemd units (survive panics/reboots).

Every campaign runs in its own directory under artifacts/runs/<run-id>/ with
its own workdir, corpus and generated syz-manager config. That isolation is
not cosmetic: the eval protocol reports variance across independent runs, and
runs that share a workdir share an evolved corpus, which makes them not
independent and the variance meaningless. The same applies to ablation arms —
a "without seeds" arm sharing a workdir is still fuzzing the seeded corpus.

Corpus policy is therefore explicit per run:
  --corpus fresh            empty corpus; seeds imported only if --seeds given
  --corpus carry --from-run ID
                            start from a previous run's corpus (the outer
                            improvement loop: round N+1 builds on round N)

Subcommands:
  gen-config --run-id ID [--seeds DIR]   write the run's syz-manager.cfg
  install-k --run-id ID [--corpus fresh|carry] [--from-run ID] [--seeds DIR]
  install-u --run-id ID
  start <k|u> | stop <k|u>
  status [--run-id ID]
Requires root for install/start/stop. Reads config/campaign.yaml.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

import yaml  # python3-yaml (apt)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
CFG_PATH = os.path.join(REPO_ROOT, "config", "campaign.yaml")
RUNS_DIR = os.path.join(REPO_ROOT, "artifacts", "runs")
UNIT_K = "/etc/systemd/system/gspwn-k.service"
UNIT_U = "/etc/systemd/system/gspwn-u.service"

UNIT_K_TMPL = """[Unit]
Description=gspwn Track K (syzkaller) run {run_id}
After=multi-user.target

[Service]
Type=simple
WorkingDirectory={root}
ExecStart={syzkaller}/bin/syz-manager -config {cfg}
Restart=always
RestartSec=30
MemoryMax={memory_max}

[Install]
WantedBy=multi-user.target
"""

UNIT_U_TMPL = """[Unit]
Description=gspwn Track U (NCT userspace fuzzers) run {run_id}
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/docker run --rm --name gspwn-u \\
  --memory={memory_max} \\
  --pids-limit=512 \\
  -v {root}/artifacts:/artifacts \\
  -e RUN_ID={run_id} {image} \\
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


def run_dir(run_id):
    return os.path.join(RUNS_DIR, run_id)


def workdir(run_id):
    return os.path.join(run_dir(run_id), "workdir")


def cfg_path(run_id):
    return os.path.join(run_dir(run_id), "syz-manager.cfg")


def require_root(what):
    if os.geteuid() != 0:
        sys.exit("%s must run as root" % what)


def write_unit(path, text):
    with open(path, "w") as f:
        f.write(text)
    sh(["systemctl", "daemon-reload"])


def cmd_gen_config(a):
    """Generate the run's syz-manager config. Deterministic — not hand-written.

    syz-manager validates this at startup and exits loudly on a bad field, so
    a version mismatch surfaces immediately rather than mid-campaign.
    """
    c = cfg()["track_k"]
    wd = workdir(a.run_id)
    os.makedirs(wd, exist_ok=True)
    conf = {
        "target": "linux/amd64",
        "http": c["http"],
        "workdir": wd,
        "kernel_obj": os.path.join(REPO_ROOT, "artifacts", "src", "linux"),
        "syzkaller": os.path.join(REPO_ROOT, "artifacts", "src", "syzkaller"),
        "sandbox": c["sandbox"],
        "procs": c["procs"],
        "type": "none",
        "vm": {"count": 1},
    }
    if c.get("enabled_syscalls"):
        conf["enable_syscalls"] = c["enabled_syscalls"]
    path = cfg_path(a.run_id)
    with open(path, "w") as f:
        json.dump(conf, f, indent=2)
    print("wrote %s (workdir %s)" % (path, wd))
    return 0


def seed_corpus(run_id, corpus, from_run, seeds):
    """Apply the corpus policy before the campaign starts."""
    wd = workdir(run_id)
    os.makedirs(wd, exist_ok=True)
    dest_db = os.path.join(wd, "corpus.db")
    if corpus == "carry":
        if not from_run:
            sys.exit("--corpus carry requires --from-run <previous-run-id>")
        src_db = os.path.join(workdir(from_run), "corpus.db")
        if not os.path.exists(src_db):
            sys.exit("no corpus.db in run %s (looked at %s)"
                     % (from_run, src_db))
        shutil.copy(src_db, dest_db)
        print("carried corpus from run %s (%d bytes)"
              % (from_run, os.path.getsize(dest_db)))
    elif os.path.exists(dest_db):
        sys.exit("run %s already has a corpus.db but --corpus fresh was "
                 "requested; use a new run id rather than reusing this one"
                 % run_id)
    else:
        print("fresh corpus for run %s" % run_id)
    if seeds:
        if not os.path.isdir(seeds):
            sys.exit("seed dir not found: " + seeds)
        dest = os.path.join(wd, "seeds")
        os.makedirs(dest, exist_ok=True)
        n = 0
        for name in sorted(os.listdir(seeds)):
            if name.endswith(".syz"):
                shutil.copy(os.path.join(seeds, name), dest)
                n += 1
        print("staged %d seed program(s) from %s into %s" % (n, seeds, dest))
        if n == 0:
            print("WARN: --seeds given but no .syz files found — the run will "
                  "start from an empty corpus, which is an ablation arm, not "
                  "a seeded run. Fix this before treating it as seeded.")
    return dest_db


def cmd_install_k(a):
    require_root("install")
    c = cfg()["track_k"]
    seed_corpus(a.run_id, a.corpus, a.from_run, a.seeds)
    cmd_gen_config(a)
    syzkaller = os.path.join(REPO_ROOT, "artifacts", "src", "syzkaller")
    write_unit(UNIT_K, UNIT_K_TMPL.format(
        root=REPO_ROOT, syzkaller=syzkaller, cfg=cfg_path(a.run_id),
        memory_max=c["memory_max"], run_id=a.run_id))
    sh(["systemctl", "enable", "gspwn-k"])
    print("installed gspwn-k.service for run %s (MemoryMax=%s)"
          % (a.run_id, c["memory_max"]))
    return 0


def cmd_install_u(a):
    require_root("install")
    c = cfg()["track_u"]
    os.makedirs(run_dir(a.run_id), exist_ok=True)
    write_unit(UNIT_U, UNIT_U_TMPL.format(
        root=REPO_ROOT, image=c["docker_image"], memory_max=c["memory_max"],
        run_id=a.run_id))
    sh(["systemctl", "enable", "gspwn-u"])
    print("installed gspwn-u.service for run %s (MemoryMax=%s)"
          % (a.run_id, c["memory_max"]))
    return 0


def unit(track):
    return {"k": "gspwn-k", "u": "gspwn-u"}[track]


def cmd_start_stop(a):
    require_root("start/stop")
    sh(["systemctl", a.cmd, unit(a.track)])
    with ps.transaction() as st:
        st["campaigns"].append({"track": a.track, "action": a.cmd,
                                "run_id": a.run_id, "at": ps._now()})
    print("%s %s%s" % (a.cmd, unit(a.track),
                       " (run %s)" % a.run_id if a.run_id else ""))
    return 0


def cmd_status(a):
    for t in ("k", "u"):
        r = sh(["systemctl", "is-active", unit(t)], check=False, capture=True)
        print("track %s: %s" % (t, r.stdout.strip()))
    if a.run_id:
        db = os.path.join(workdir(a.run_id), "corpus.db")
        if os.path.exists(db):
            print("run %s corpus.db: %d bytes"
                  % (a.run_id, os.path.getsize(db)))
        else:
            print("run %s: no corpus.db yet" % a.run_id)
        print("coverage: python3 tools/coverage_ctl.py series --run-id %s"
              % a.run_id)
    return 0


def build_parser():
    ap = argparse.ArgumentParser(prog="campaign_ctl.py",
                                 description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("gen-config")
    p.add_argument("--run-id", required=True)
    p.set_defaults(fn=cmd_gen_config)

    p = sub.add_parser("install-k")
    p.add_argument("--run-id", required=True)
    p.add_argument("--corpus", choices=["fresh", "carry"], default="fresh")
    p.add_argument("--from-run", help="source run id for --corpus carry")
    p.add_argument("--seeds", help="seed dir to stage (e.g. artifacts/seeds)")
    p.set_defaults(fn=cmd_install_k)

    p = sub.add_parser("install-u")
    p.add_argument("--run-id", required=True)
    p.set_defaults(fn=cmd_install_u)

    for verb in ("start", "stop"):
        p = sub.add_parser(verb)
        p.add_argument("track", choices=["k", "u"])
        p.add_argument("--run-id")
        p.set_defaults(fn=cmd_start_stop)

    p = sub.add_parser("status")
    p.add_argument("--run-id")
    p.set_defaults(fn=cmd_status)
    return ap


def main():
    a = build_parser().parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
