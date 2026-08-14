#!/usr/bin/env python3
"""Install/manage fuzz campaigns as systemd units (survive panics/reboots).

Every campaign runs in its own directory under artifacts/runs/<run-id>/ with
its own workdir, corpus and generated syz-manager config. The eval protocol
reports variance across independent runs, and runs sharing a workdir share an
evolved corpus, so they are not independent. The same applies to ablation
arms: a "without seeds" arm sharing a workdir fuzzes the seeded corpus.

Corpus policy is therefore explicit per run:
  --corpus fresh            empty corpus; seeds imported only if --seeds given
  --corpus carry --from-run ID
                            start from a previous run's corpus (the outer
                            improvement loop: round N+1 builds on round N)

Seeds are packed into the run's corpus.db with `syz-db pack`, because that
database is syz-manager's only corpus input.

Each campaign carries a deadline (loop.campaign_hours) written to disk, so an
unattended round ends on time even across the panics this pipeline expects.
`install-k` installs `gspwn-deadline.timer`, which runs `check-deadline`.

Subcommands:
  gen-config --run-id ID                 write the run's syz-manager.cfg
  install-k --run-id ID [--corpus fresh|carry] [--from-run ID] [--seeds DIR]
            [--hours H]
  install-u --run-id ID
  check-deadline --run-id ID             stop the campaign if its window is up
  start <k|u> | stop <k|u>
  status [--run-id ID]
Requires root for install/start/stop. All tunables come from
config/campaign.yaml via tools/gspwn_config.py.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import corpus_ctl
import gspwn_config
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
CFG_PATH = gspwn_config.CONFIG_PATH
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
    """Effective configuration — defaults merged with config/campaign.yaml."""
    try:
        return gspwn_config.load()
    except gspwn_config.ConfigError as e:
        sys.exit("error: %s" % e)


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


def install_seeds(dest_db, seeds_dir):
    """Pack the seed bank INTO the run's corpus.db, merging what is there.

    syz-manager's only corpus input is workdir/corpus.db, so seeds must be
    packed into it with `syz-db pack`. Programs placed in a directory beside
    the database are never loaded: the run starts empty, and a seeded and an
    unseeded arm become the same configuration.
    """
    files = sorted(f for f in os.listdir(seeds_dir) if f.endswith(".syz"))
    if not files:
        print("WARN: --seeds %s holds no .syz files — this run is NOT seeded "
              "and is equivalent to an unseeded ablation arm." % seeds_dir)
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        staged = os.path.join(tmp, "progs")
        os.makedirs(staged)
        carried = 0
        if os.path.exists(dest_db):
            # Merge: unpack what the corpus already holds so packing the seeds
            # in does not discard a carried corpus.
            carried = len(corpus_ctl.unpack_corpus(dest_db, staged))
        for i, name in enumerate(files):
            shutil.copy(os.path.join(seeds_dir, name),
                        os.path.join(staged, "seed-%04d-%s" % (i, name)))
        r = subprocess.run([corpus_ctl.SYZ_DB, "pack", staged, dest_db],
                           capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit("syz-db pack failed: %s"
                     % (r.stderr.strip() or r.stdout.strip()))
    print("packed %d seed program(s) from %s into %s (%d carried program(s) "
          "preserved)" % (len(files), seeds_dir, dest_db, carried))
    return len(files)


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
        install_seeds(dest_db, seeds)
    return dest_db


def check_budget(hours, cap):
    """Refuse to start a campaign that the run-hour budget cannot cover.

    round-decide enforces the cap between rounds, but eval and ablation
    campaigns are started directly by the fuzz phase and never pass through
    it, so without this check the budget can be overshot by an arbitrary
    number of extra runs. Raising the cap is a deliberate edit to
    config/campaign.yaml, not something a tool does to keep a campaign alive.
    """
    spent = ps.total_run_hours(ps.load())
    if spent + hours > cap:
        sys.exit("refusing to start: %.1f h already recorded + %.1f h for this "
                 "campaign exceeds loop.max_total_run_hours (%s). Raise the "
                 "cap in config/campaign.yaml to allow it."
                 % (spent, hours, cap))
    return spent


def cmd_install_k(a):
    require_root("install")
    conf = cfg()
    c = conf["track_k"]
    hours = a.hours if a.hours is not None else conf["loop"]["campaign_hours"]
    spent = check_budget(hours, conf["loop"]["max_total_run_hours"])
    seed_corpus(a.run_id, a.corpus, a.from_run, a.seeds)
    at = write_deadline(a.run_id, hours)
    install_deadline_timer(a.run_id, int(conf["loop"]["coverage_sample_min"]))
    print("campaign window: %s h (stops at epoch %d, enforced by %s.timer); "
          "budget %.1f of %s run-hours used before this campaign"
          % (hours, int(at), DEADLINE_NAME, spent,
             conf["loop"]["max_total_run_hours"]))
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


DEADLINE_NAME = "gspwn-deadline"
DEADLINE_SERVICE_TMPL = """[Unit]
Description=gspwn campaign deadline enforcement ({run_id})

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {root}/tools/campaign_ctl.py check-deadline \\
  --run-id {run_id}
"""
DEADLINE_TIMER_TMPL = """[Unit]
Description=gspwn campaign deadline enforcement

[Timer]
OnBootSec={every}min
OnUnitActiveSec={every}min

[Install]
WantedBy=timers.target
"""


def deadline_path(run_id):
    return os.path.join(run_dir(run_id), "deadline")


def install_deadline_timer(run_id, every_min):
    """Enforce the campaign window from its own timer.

    The spend ceiling must not depend on a separate command being run
    afterwards: the fuzz units are Restart=always, so a campaign whose
    deadline nothing checks never ends. install-k owns this because
    install-k is what starts the clock.
    """
    with open("/etc/systemd/system/%s.service" % DEADLINE_NAME, "w") as f:
        f.write(DEADLINE_SERVICE_TMPL.format(root=REPO_ROOT, run_id=run_id))
    with open("/etc/systemd/system/%s.timer" % DEADLINE_NAME, "w") as f:
        f.write(DEADLINE_TIMER_TMPL.format(every=every_min))
    sh(["systemctl", "daemon-reload"])
    sh(["systemctl", "enable", "--now", "%s.timer" % DEADLINE_NAME])


def write_deadline(run_id, hours):
    """Record when this campaign must stop, as an absolute epoch second.

    A deadline on disk, rather than a one-shot timer, survives the panics this
    pipeline expects: after a reboot the check reads the same deadline and
    still stops on time. Without it nothing ever ends
    a campaign — the units are Restart=always — and an unattended loop would
    fuzz until the budget alert or the instance bill noticed.
    """
    os.makedirs(run_dir(run_id), exist_ok=True)
    at = time.time() + hours * 3600.0
    with open(deadline_path(run_id), "w") as f:
        f.write("%d\n" % int(at))
        f.flush()
        os.fsync(f.fileno())
    return at


def read_deadline(run_id):
    path = deadline_path(run_id)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return float(f.read().strip())
    except (ValueError, OSError):
        return None


def cmd_check_deadline(a):
    """Stop the campaign if its configured hours are up. Idempotent."""
    at = read_deadline(a.run_id)
    if at is None:
        print("run %s: no deadline recorded; nothing to enforce" % a.run_id)
        return 0
    left_h = (at - time.time()) / 3600.0
    if left_h > 0:
        print("run %s: %.1f h left of its campaign window" % (a.run_id, left_h))
        return 0
    stopped = []
    for track in ("k", "u"):
        r = subprocess.run(["systemctl", "is-active", unit(track)],
                           capture_output=True, text=True)
        if r.stdout.strip() != "active":
            continue
        subprocess.run(["systemctl", "stop", unit(track)], check=False)
        stopped.append(track)
    if stopped:
        with ps.transaction() as st:
            for track in stopped:
                st["campaigns"].append({"track": track, "action": "stop",
                                        "run_id": a.run_id, "at": ps._now(),
                                        "note": "campaign window elapsed"})
    print("run %s: campaign window elapsed; stopped %s"
          % (a.run_id, ", ".join(stopped) or "nothing (already inactive)"))
    return 0


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
    p.add_argument("--seeds", help="seed dir to pack in (e.g. artifacts/seeds)")
    p.add_argument("--hours", type=float,
                   help="campaign window; default loop.campaign_hours")
    p.set_defaults(fn=cmd_install_k)

    p = sub.add_parser("check-deadline",
                       help="stop the campaign if its window has elapsed")
    p.add_argument("--run-id", required=True)
    p.set_defaults(fn=cmd_check_deadline)

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
