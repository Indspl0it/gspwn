#!/usr/bin/env python3
"""Install/manage fuzz campaigns as systemd units (survive panics/reboots).

Every campaign runs in its own directory under artifacts/runs/<run-id>/ with
its own workdir, corpus and generated syz-manager config. The eval protocol
reports variance across independent runs, and runs sharing a workdir share an
evolved corpus, so they are not independent. The same applies to ablation
arms: a "without seeds" arm sharing a workdir fuzzes the seeded corpus.

Corpus policy is explicit per run, with the config supplying the default:
  --corpus fresh            empty corpus; seeds imported only if --seeds given
  --corpus carry --from-run ID
                            start from a previous run's corpus (the outer
                            improvement loop: round N+1 builds on round N)
  (flag omitted)            loop.corpus_policy from config/campaign.yaml

Seeds are packed into the run's corpus.db with `syz-db pack`, because that
database is syz-manager's only corpus input.

Each campaign carries a deadline (loop.campaign_hours, or --hours) written to
disk, so an unattended round ends on time even across the panics this
pipeline expects. install-k and install-u both install a per-run
gspwn-deadline@<run-id>.timer (fixed 2-minute cadence, independent of the
coverage sampling interval) which runs `check-deadline`; when the window is
up the campaign units are stopped AND disabled, so they cannot come back on
the next panic/reboot.

Only one run's campaign may be live at a time: install-k/install-u refuse
while another run's units are active or its deadline timer is still
installed. --replace retires the old run first (stops and disables its units
and its deadline timer), then installs the new one.

When a campaign that is not part of a pipeline round stops — by deadline, by
a manual `stop`, or already finished when `status` looks at it — its
measured hours are billed to the machine-global spend ledger
(state/spend.json, which GSPWN_STATE does not redirect). Round campaigns are
billed per run by round-end instead; eval and ablation campaigns never pass
through round-end, so their stop is the only place their hours can reach the
budget.

Subcommands:
  gen-config --run-id ID                 write the run's syz-manager.cfg
  install-k --run-id ID [--corpus fresh|carry] [--from-run ID] [--seeds DIR]
            [--hours H] [--replace]
  install-u --run-id ID [--hours H] [--replace]
  check-deadline --run-id ID             stop the campaign if its window is up
  start <k|u> | stop <k|u>
  status [--run-id ID]
Requires root for install/start/stop. All tunables come from
config/campaign.yaml via tools/gspwn_config.py.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import corpus_ctl
import coverage_ctl
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
            sys.exit("corpus policy 'carry' requires --from-run "
                     "<previous-run-id>")
        src_db = os.path.join(workdir(from_run), "corpus.db")
        if not os.path.exists(src_db):
            sys.exit("no corpus.db in run %s (looked at %s)"
                     % (from_run, src_db))
        shutil.copy(src_db, dest_db)
        print("carried corpus from run %s (%d bytes)"
              % (from_run, os.path.getsize(dest_db)))
    elif os.path.exists(dest_db):
        sys.exit("run %s already has a corpus.db but the corpus policy is "
                 "'fresh'; use a new run id rather than reusing this one"
                 % run_id)
    else:
        print("fresh corpus for run %s" % run_id)
    if seeds:
        if not os.path.isdir(seeds):
            sys.exit("seed dir not found: " + seeds)
        install_seeds(dest_db, seeds)
    return dest_db


def check_budget(hours, cap, cost=None):
    """Refuse to start a campaign that the spend budget cannot cover.

    round-decide enforces the cap between rounds, but eval and ablation
    campaigns are started directly by the fuzz phase and never pass through
    it, so without this check the budget can be overshot by an arbitrary
    number of extra runs. Raising the cap is a deliberate edit to
    config/campaign.yaml, not something a tool does to keep a campaign alive.

    Spend is read from the spend ledger (state/spend.json), which — unlike
    pipeline.json — does NOT follow GSPWN_STATE: an ablation run redirecting
    its state file gets a fresh, empty pipeline.json and must not get a
    fresh, empty budget along with it. A missing ledger that contradicts
    recorded hours refuses the campaign rather than reading as $0 spent.

    When cost.monthly_budget_usd is set, the projected dollar spend is
    checked too, priced at cost.estimated_hourly_usd. Both checks refuse only
    what is strictly over budget — exact equality is admitted, matching
    round-decide's enforcement point.
    """
    try:
        spent = ps.spend_for_budget()
    except ps.SpendLedgerMissing as e:
        sys.exit("refusing to start: %s" % e)
    if spent + hours > cap:
        sys.exit("refusing to start: %.1f h already spent + %.1f h for this "
                 "campaign exceeds loop.max_total_run_hours (%s). Raise the "
                 "cap in config/campaign.yaml to allow it."
                 % (spent, hours, cap))
    if cost:
        budget = cost["monthly_budget_usd"]
        if budget > 0:
            hourly = cost["estimated_hourly_usd"]
            if hourly > 0:
                projected = (spent + hours) * hourly
                if projected > budget:
                    sys.exit("refusing to start: projected spend $%.2f "
                             "((%.1f h spent + %.1f h for this campaign) x "
                             "$%.2f/h) exceeds cost.monthly_budget_usd "
                             "($%.2f). Raise the budget in "
                             "config/campaign.yaml to allow it."
                             % (projected, spent, hours, hourly, budget))
            else:
                print("WARN: cost.monthly_budget_usd is set ($%.2f) but "
                      "cost.estimated_hourly_usd is 0 — the dollar cap "
                      "cannot be estimated; only run-hours are enforced."
                      % budget)
    return spent


def register_campaign(run_id, track, hours):
    """Record the install in state, making the run id a registered run.

    The coverage sampler refuses unknown run ids (a typo would otherwise
    create a root-owned artifacts/runs/<id>/), so installing a campaign is
    what registers it. Under GSPWN_STATE the entry lands in the redirected
    state file — the same registry that run's sampler is pointed at. The
    configured window is recorded too: if the run leaves no usable coverage
    samples, it is what the spend ledger falls back to at billing time.
    """
    with ps.transaction() as st:
        st["campaigns"].append({"track": track, "action": "install",
                                "run_id": run_id, "at": ps._now(),
                                "hours": hours,
                                "note": "campaign window %.1f h" % hours})


def unit(track):
    return {"k": "gspwn-k", "u": "gspwn-u"}[track]


def unit_active(name):
    r = subprocess.run(["systemctl", "is-active", name],
                       capture_output=True, text=True)
    return r.stdout.strip() == "active"


def unit_run_id(name):
    """The run id baked into an installed campaign unit, if any."""
    try:
        with open("/etc/systemd/system/%s.service" % name) as f:
            m = re.search(r"\brun (\S+)", f.read())
            return m.group(1) if m else None
    except OSError:
        return None


def enabled_deadline_runs():
    """Run ids with an enabled gspwn-deadline@<run-id>.timer instance."""
    wants = "/etc/systemd/system/timers.target.wants"
    ids = []
    if os.path.isdir(wants):
        for name in os.listdir(wants):
            m = re.match(r"%s@(.+)\.timer$" % re.escape(DEADLINE_NAME), name)
            if m:
                ids.append(m.group(1))
    return sorted(ids)


def check_overlap(a):
    """Refuse to install while another run's campaign is still live.

    The campaign units are single global names, so installing run B over a
    live run A would repoint them while A keeps fuzzing — with A's deadline
    enforcement gone, an unbounded spend path. Reinstalling the SAME run is
    fine; anything else needs --replace, which retires the old run first.
    """
    others = [r for r in enabled_deadline_runs() if r != a.run_id]
    busy = []   # (track, unit name, run id) belonging to a different run
    for t in ("k", "u"):
        name = unit(t)
        if unit_active(name):
            rid = unit_run_id(name)
            if rid != a.run_id:
                busy.append((t, name, rid))
    if not others and not busy:
        return
    what = []
    if busy:
        what.append("active unit(s) %s" % ", ".join(
            "%s (run %s)" % (n, r or "?") for _, n, r in busy))
    if others:
        what.append("deadline timer(s) for run(s) %s" % ", ".join(others))
    if not a.replace:
        sys.exit("refusing to install run %s: another campaign is still live "
                 "(%s). Overlapping campaigns are not independent runs, and "
                 "installing over one retires its deadline enforcement. Stop "
                 "the old campaign first, or re-run with --replace to retire "
                 "it (stops and disables its units and its deadline timer)."
                 % (a.run_id, "; ".join(what)))
    for t, name, rid in busy:
        r = subprocess.run(["systemctl", "stop", name],
                           capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit("--replace: could not stop %s: %s — leaving the old "
                     "campaign alone; nothing was installed"
                     % (name, r.stderr.strip() or r.stdout.strip()))
        subprocess.run(["systemctl", "disable", name], check=False,
                       capture_output=True)
        print("--replace: stopped and disabled %s (run %s)"
              % (name, rid or "?"))
        with ps.transaction() as st:
            st["campaigns"].append({"track": t, "action": "stop",
                                    "run_id": rid, "at": ps._now(),
                                    "note": "retired by --replace install of "
                                            "run %s" % a.run_id})
    for rid in others:
        subprocess.run(["systemctl", "disable", "--now",
                        deadline_unit(rid, "timer")], check=False,
                       capture_output=True)
        print("--replace: retired deadline timer for run %s" % rid)


def cmd_install_k(a):
    require_root("install")
    conf = cfg()
    c = conf["track_k"]
    hours = a.hours if a.hours is not None else conf["loop"]["campaign_hours"]
    spent = check_budget(hours, conf["loop"]["max_total_run_hours"],
                         conf["cost"])
    check_overlap(a)
    corpus = a.corpus or conf["loop"]["corpus_policy"]
    seed_corpus(a.run_id, corpus, a.from_run, a.seeds)
    at = write_deadline(a.run_id, hours)
    install_deadline_timer(a.run_id)
    print("campaign window: %s h (stops at epoch %d, enforced by %s); "
          "budget %.1f of %s run-hours spent before this campaign"
          % (hours, int(at), deadline_unit(a.run_id, "timer"), spent,
             conf["loop"]["max_total_run_hours"]))
    cmd_gen_config(a)
    syzkaller = os.path.join(REPO_ROOT, "artifacts", "src", "syzkaller")
    write_unit(UNIT_K, UNIT_K_TMPL.format(
        root=REPO_ROOT, syzkaller=syzkaller, cfg=cfg_path(a.run_id),
        memory_max=c["memory_max"], run_id=a.run_id))
    sh(["systemctl", "enable", "gspwn-k"])
    register_campaign(a.run_id, "k", hours)
    print("installed gspwn-k.service for run %s (MemoryMax=%s)"
          % (a.run_id, c["memory_max"]))
    return 0


def cmd_install_u(a):
    require_root("install")
    conf = cfg()
    c = conf["track_u"]
    hours = a.hours if a.hours is not None else conf["loop"]["campaign_hours"]
    spent = check_budget(hours, conf["loop"]["max_total_run_hours"],
                         conf["cost"])
    check_overlap(a)
    os.makedirs(run_dir(a.run_id), exist_ok=True)
    at = write_deadline(a.run_id, hours)
    install_deadline_timer(a.run_id)
    print("campaign window: %s h (stops at epoch %d, enforced by %s); "
          "budget %.1f of %s run-hours spent before this campaign"
          % (hours, int(at), deadline_unit(a.run_id, "timer"), spent,
             conf["loop"]["max_total_run_hours"]))
    write_unit(UNIT_U, UNIT_U_TMPL.format(
        root=REPO_ROOT, image=c["docker_image"], memory_max=c["memory_max"],
        run_id=a.run_id))
    sh(["systemctl", "enable", "gspwn-u"])
    register_campaign(a.run_id, "u", hours)
    print("installed gspwn-u.service for run %s (MemoryMax=%s)"
          % (a.run_id, c["memory_max"]))
    return 0


DEADLINE_NAME = "gspwn-deadline"
# Fixed cadence, deliberately decoupled from loop.coverage_sample_min:
# raising the sampling interval must not also delay every deadline stop
# past the campaign window.
DEADLINE_CHECK_MIN = 2
# Template units, instantiated per run as gspwn-deadline@<run-id>.timer, so
# installing run B never retires run A's enforcement — the pre-template
# single global unit did exactly that.
DEADLINE_SERVICE_TMPL = """[Unit]
Description=gspwn campaign deadline enforcement (%i)

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {root}/tools/campaign_ctl.py check-deadline \\
  --run-id %i
"""
DEADLINE_TIMER_TMPL = """[Unit]
Description=gspwn campaign deadline enforcement (%i)

[Timer]
OnBootSec={every}min
OnUnitActiveSec={every}min

[Install]
WantedBy=timers.target
"""


def deadline_unit(run_id, suffix):
    return "%s@%s.%s" % (DEADLINE_NAME, run_id, suffix)


def deadline_path(run_id):
    return os.path.join(run_dir(run_id), "deadline")


def install_deadline_timer(run_id):
    """Enforce the campaign window from its own per-run timer instance.

    The spend ceiling must not depend on a separate command being run
    afterwards: the fuzz units are Restart=always, so a campaign whose
    deadline nothing checks never ends. install-k/install-u own this because
    they are what starts the clock.
    """
    # Retire the pre-template global units left by older installs: one shared
    # gspwn-deadline.timer can only ever enforce one run's deadline.
    legacy = ["/etc/systemd/system/%s%s" % (DEADLINE_NAME, s)
              for s in (".timer", ".service")]
    if any(os.path.exists(p) for p in legacy):
        sh(["systemctl", "disable", "--now", "%s.timer" % DEADLINE_NAME],
           check=False)
        for p in legacy:
            if os.path.exists(p):
                os.remove(p)
    with open("/etc/systemd/system/%s@.service" % DEADLINE_NAME, "w") as f:
        f.write(DEADLINE_SERVICE_TMPL.format(root=REPO_ROOT))
    with open("/etc/systemd/system/%s@.timer" % DEADLINE_NAME, "w") as f:
        f.write(DEADLINE_TIMER_TMPL.format(every=DEADLINE_CHECK_MIN))
    # An ablation run installed under GSPWN_STATE keeps its own pipeline.json;
    # a per-instance drop-in points its deadline service at that same state
    # file (the template itself is shared across runs and cannot carry it).
    dropin = "/etc/systemd/system/%s.service.d" % deadline_unit(run_id,
                                                                "service")
    if os.environ.get("GSPWN_STATE"):
        os.makedirs(dropin, exist_ok=True)
        with open(os.path.join(dropin, "gspwn-state.conf"), "w") as f:
            f.write("[Service]\nEnvironment=GSPWN_STATE=%s\n" % ps.STATE_PATH)
    elif os.path.isdir(dropin):
        shutil.rmtree(dropin)
    sh(["systemctl", "daemon-reload"])
    sh(["systemctl", "enable", "--now", deadline_unit(run_id, "timer")])


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


def configured_hours(run_id):
    """The campaign window this run was installed with, if recoverable."""
    try:
        st = ps.load()
    except ValueError:
        st = None
    if st is not None:
        for c in reversed(st.get("campaigns", [])):
            if (c.get("run_id") == run_id and c.get("action") == "install"
                    and c.get("hours")):
                return float(c["hours"])
    # Installs pre-dating the structured "hours" event left none; the
    # deadline file is written at install time, so its mtime is the window's
    # start.
    path = deadline_path(run_id)
    if os.path.exists(path):
        at = read_deadline(run_id)
        if at is not None:
            return max((at - os.path.getmtime(path)) / 3600.0, 0.0)
    return None


def measured_run_hours(run_id):
    """-> (hours, basis): what a finished campaign actually consumed.

    Wall-clock from the first to the last coverage sample on either track —
    the same derivation round-end uses — because a run that died after 3 h
    must not bill its configured 24. Only when no usable samples exist does
    the configured window stand in.
    """
    stamps = [r["ts"] for t in coverage_ctl.TRACKS
              for r in coverage_ctl.read_rows(run_id, t) if r.get("ts")]
    if len(stamps) > 1:
        return (round((max(stamps) - min(stamps)) / 3600.0, 2),
                "coverage samples")
    hours = configured_hours(run_id)
    if hours is not None:
        return hours, "configured window (no usable coverage samples)"
    return None, "no coverage samples and no recorded window"


def bill_run(run_id, why):
    """Bill a finished non-round campaign to the machine-global spend ledger.

    Round campaigns are billed by round-end (each --from-run is measured and
    recorded there); eval and ablation campaigns never pass through
    round-end, so their stop is the only place their hours reach the budget.
    The ledger does not follow GSPWN_STATE, and record_run_hours is
    idempotent per run id, so recording at every reliable stop detection
    cannot double-count.
    """
    if not run_id:
        return
    try:
        st = ps.load()
    except ValueError:
        return
    if any(run_id in (r.get("run_ids") or []) for r in st.get("rounds", [])):
        return          # a round campaign: round-end bills it
    hours, basis = measured_run_hours(run_id)
    if not hours:
        print("run %s: nothing billed (%s)" % (run_id, basis))
        return
    try:
        ps.record_run_hours(run_id, hours, path=ps.SPEND_PATH)
    except OSError as e:
        print("WARN: could not bill %.2f h for run %s to %s (%s); re-run as "
              "root" % (hours, run_id, ps.SPEND_PATH, e))
        return
    print("billed %.2f run-hours for run %s (%s; %s)" % (hours, run_id, basis,
                                                         why))


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
    failed = []
    for track in ("k", "u"):
        name = unit(track)
        if not unit_active(name):
            # Inactive is not enough: an enabled Restart=always unit comes
            # back on the next boot, and this pipeline panics by design. The
            # campaign is over, so the unit must not be enabled anymore.
            subprocess.run(["systemctl", "disable", name], check=False,
                           capture_output=True)
            continue
        r = subprocess.run(["systemctl", "stop", name],
                           capture_output=True, text=True)
        if r.returncode != 0:
            failed.append(name)
            print("ERROR: systemctl stop %s failed: %s — NOT recording a "
                  "stop; the deadline timer will retry"
                  % (name, r.stderr.strip() or r.stdout.strip()))
            continue
        subprocess.run(["systemctl", "disable", name], check=False,
                       capture_output=True)
        stopped.append(track)
    if stopped:
        # Only stops that actually succeeded are recorded: the campaign log
        # must never claim a stop that did not happen.
        with ps.transaction() as st:
            for track in stopped:
                st["campaigns"].append({"track": track, "action": "stop",
                                        "run_id": a.run_id, "at": ps._now(),
                                        "note": "campaign window elapsed"})
    if not failed:
        # Enforcement is done. Bill the consumed hours (no-op for round
        # campaigns — round-end bills those), then retire this run's own
        # timer so it does not fire every interval forever (or trip the
        # install overlap guard).
        bill_run(a.run_id, "campaign window elapsed")
        subprocess.run(["systemctl", "disable", "--now",
                        deadline_unit(a.run_id, "timer")], check=False,
                       capture_output=True)
    print("run %s: campaign window elapsed; stopped %s"
          % (a.run_id, ", ".join(stopped) or "nothing (already inactive)"))
    return 1 if failed else 0


def cmd_start_stop(a):
    require_root("start/stop")
    name = unit(a.track)
    sh(["systemctl", a.cmd, name])
    with ps.transaction() as st:
        st["campaigns"].append({"track": a.track, "action": a.cmd,
                                "run_id": a.run_id, "at": ps._now()})
    print("%s %s%s" % (a.cmd, name,
                       " (run %s)" % a.run_id if a.run_id else ""))
    if a.cmd == "stop":
        bill_run(a.run_id or unit_run_id(name), "manual stop")
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
        at = read_deadline(a.run_id)
        if at is not None and time.time() >= at:
            # Finished campaigns found after the fact (a missed timer, a
            # manual stop without this tool) still owe their hours to the
            # budget.
            bill_run(a.run_id, "campaign window already elapsed")
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
    p.add_argument("--corpus", choices=["fresh", "carry"], default=None,
                   help="corpus policy; default loop.corpus_policy from "
                        "config/campaign.yaml")
    p.add_argument("--from-run", help="source run id for --corpus carry")
    p.add_argument("--seeds", help="seed dir to pack in (e.g. artifacts/seeds)")
    p.add_argument("--hours", type=float,
                   help="campaign window; default loop.campaign_hours")
    p.add_argument("--replace", action="store_true",
                   help="retire a still-live older campaign (stop+disable "
                        "its units and deadline timer) before installing")
    p.set_defaults(fn=cmd_install_k)

    p = sub.add_parser("check-deadline",
                       help="stop the campaign if its window has elapsed")
    p.add_argument("--run-id", required=True)
    p.set_defaults(fn=cmd_check_deadline)

    p = sub.add_parser("install-u")
    p.add_argument("--run-id", required=True)
    p.add_argument("--hours", type=float,
                   help="campaign window; default loop.campaign_hours")
    p.add_argument("--replace", action="store_true",
                   help="retire a still-live older campaign (stop+disable "
                        "its units and deadline timer) before installing")
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
