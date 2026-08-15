"""Shared pipeline.json state helpers. Stdlib only; imported by other tools.

Durability: this pipeline runs on a machine that panics by design. Writes go
through a tempfile + fsync + atomic rename, and the parent directory is
fsynced too, so a panic mid-write leaves the previous good state rather than a
truncated file.

Concurrency: AGENTS.md allows parallel subagents (describe/seeds/harness) and
a background fuzz monitor, all of which touch this file. Every
read-modify-write must go through transaction(), which holds an exclusive
flock for the whole cycle. Bare load()/save() pairs lose updates and are a bug.
"""
import fcntl
import json
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_DIR = os.path.join(REPO_ROOT, "state")
# GSPWN_STATE redirects the state file (used by tools/selftest.py; also lets
# a side run keep its own pipeline.json without touching the main one).
DEFAULT_STATE_PATH = os.path.join(STATE_DIR, "pipeline.json")
STATE_PATH = os.environ.get("GSPWN_STATE") or DEFAULT_STATE_PATH
# The spend ledger is machine-global on purpose: it does NOT follow
# GSPWN_STATE, so a run with its own pipeline.json still bills the
# one true ledger (redirecting the state file must not redirect the budget).
# GSPWN_SPEND exists only so tools/selftest.py can point it at a tempdir.
SPEND_PATH = os.environ.get("GSPWN_SPEND") or os.path.join(STATE_DIR,
                                                           "spend.json")

SCHEMA_VERSION = 2

# Setup runs once for the machine; the round phases re-run every round of the
# improvement loop; report runs once, after the loop stops.
SETUP_PHASES = ["provision", "build"]
ROUND_PHASES = ["describe", "seeds", "harness", "fuzz", "triage", "rca",
                "poc", "eval", "refine"]
FINAL_PHASES = ["report"]
PHASES = SETUP_PHASES + ROUND_PHASES + FINAL_PHASES

PHASE_STATUS = {"pending", "in_progress", "done", "blocked", "failed"}
CRASH_SIGNAL = ("signal", "review", "health", "noise", "unclassified")

# The research record rca produces per analysed crash. It is the only path by
# which a finding steers the next round: without it the loop can only follow
# coverage, which says where the fuzzer has not been, never where the bugs are.
# Closed vocabularies so refine can group across rounds; free text alone would
# make "uaf", "UAF" and "use-after-free" three different subsystems to it.
BUG_CLASS = ("uaf", "double-free", "oob-read", "oob-write", "race",
             "refcount", "null-deref", "uninit", "deadlock", "leak",
             "type-confusion", "integer-overflow", "other")
TRIGGER = ("single-ioctl", "ioctl-sequence", "mmap-touch", "concurrency",
           "fd-lifecycle", "other")
CONFIDENCE = ("low", "medium", "high")
CRASH_STATUS = {"unique", "duplicate", "flagged", "reliable", "flaky",
                "unreproducible", "rca_done", "reported"}
DISCLOSURE_STATUS = {"pending", "submitted", "resolved", "not_applicable"}
TRACKS = {"K", "U"}
COVERAGE_VERDICT = {"growing", "plateaued", "unknown"}
ROUND_DECISION = {"continue", "stop"}

# Phases that may run concurrently once `build` is done (AGENTS.md).
PARALLEL_AFTER_BUILD = {"describe", "seeds", "harness"}

DEFAULT_PHASE = {"status": "pending", "updated": None, "notes": ""}
# signal: how a crash reads against the campaign's own noise floor. Set from
# the Xid classification for NVRM entries (crash_parse.xid_class); everything
# else stays "unclassified", which is not a verdict, just an absence of one.
# See CRASH_SIGNAL for the values.
DEFAULT_CRASH = {"track": "K", "title": "", "stack_hash": "",
                 "status": "unique", "dir": "", "repro_rate": None,
                 "duplicate_of": None, "disclosure": "pending", "notes": "",
                 "signal": "unclassified",
                 # When rca finished with this crash. Stamped once and never
                 # cleared, because `status` is not durable: the poc phase
                 # overwrites `rca_done` with the reproduction class, so an
                 # invariant keyed on the current status would expire exactly
                 # when the pipeline reaches the phase that should notice it.
                 # See was_analysed().
                 "rca_done_at": None,
                 # finding: the research record from rca, or None when the
                 # crash has not been analysed. See DEFAULT_FINDING.
                 "finding": None,
                 # impact: what the fault gives an attacker, or None. See
                 # DEFAULT_IMPACT. Separate from finding because they answer
                 # to different readers: finding steers the next round, impact
                 # is what lets the report argue a severity.
                 "impact": None}

# The fields rca fills in. ioctls/preconditions/adjacent are what describe and
# seeds consume; source_refs/hypothesis/confidence are what the report and the
# next round's rca read. Both halves matter: a record with only a taxonomy
# ("uaf in nvidia_uvm") tells the next round nothing it can act on.
DEFAULT_FINDING = {"subsystem": "", "bug_class": "other", "trigger": "other",
                   "ioctls": [], "preconditions": [], "adjacent": [],
                   "source_refs": [], "hypothesis": "", "confidence": "low",
                   # Why `adjacent` is empty, when it is. Required in that
                   # case: see finding_target_gap.
                   "no_adjacent_reason": ""}
FINDING_LISTS = ("ioctls", "preconditions", "adjacent", "source_refs")
FINDING_TEXT = ("subsystem", "hypothesis", "no_adjacent_reason")
# At least one of these must be non-empty. A finding that names no call and no
# state cannot steer describe or seeds, and silently accepting one would let
# the feedback edge look wired while carrying nothing. Not ioctls alone:
# Track U findings are userspace and have none.
FINDING_TARGETING = ("ioctls", "preconditions", "adjacent")

# ---------------------------------------------------------------- impact ---
# The second half of what rca produces. The finding says where to look next;
# this says what the fault is worth.
#
# A reproducer proves a crash condition. That is a bug report: the software
# faulted, here is the input. It is not yet a vulnerability report, which has
# to name the weakness and say what the fault hands an attacker. Without that
# second half a severity is an assertion, and an asserted severity that a
# vendor engineer disproves costs the credibility of every other finding in
# the same report.
#
# This record deliberately stops at the primitive. Describing that a UAF gives
# a controlled write into a reclaimable allocation is analysis; building the
# escalation is not, and is out of scope for this campaign.

# Weakness class per bug_class. Derived rather than typed in: the mapping is
# mechanical, and a free-text CWE field invites a plausible wrong number that
# nobody re-checks. `cwe` on the record overrides it, for `other` and for the
# cases where a more specific child class is right.
CWE_OF_BUG_CLASS = {
    "uaf": "CWE-416", "double-free": "CWE-415", "oob-read": "CWE-125",
    "oob-write": "CWE-787", "race": "CWE-362", "refcount": "CWE-911",
    "null-deref": "CWE-476", "uninit": "CWE-908", "deadlock": "CWE-833",
    "leak": "CWE-401", "type-confusion": "CWE-843",
    "integer-overflow": "CWE-190", "other": "",
}
CWE_RE = re.compile(r"^CWE-\d+$")

# What the memory-safety violation actually hands an attacker. The field the
# whole record exists for; everything else is evidence for this one.
PRIMITIVE = ("none", "info-leak", "uncontrolled-write", "controlled-write",
             "controlled-free", "refcount-imbalance", "type-confusion",
             "undetermined")
# The highest outcome the evidence supports — not a guess at the worst case
# imaginable. `dos-only` is a complete answer for most kernel faults.
CONSEQUENCE = ("dos-only", "info-disclosure", "privilege-escalation",
               "container-escape", "undetermined")
# What the sanitizer said about the bad access. KASAN reports all of this
# verbatim, so it is transcription rather than judgement.
ACCESS_TYPE = ("read", "write", "free", "unknown")
# Which field the corruption lands on. This is what sets the ceiling: an
# overwritten function pointer and an overwritten flags byte are the same
# memory-safety bug and very different vulnerabilities.
OVERWRITE_TARGET = ("function-pointer", "length-or-size", "refcount",
                    "index-or-offset", "list-pointer", "flags-or-state",
                    "data-buffer", "unknown", "not-applicable")
# What an attacker influences. Closed so the report can group findings by it.
ATTACKER_CONTROL = ("allocation-timing", "allocation-size", "written-data",
                    "written-offset", "freed-pointer", "object-lifetime",
                    "call-ordering", "none", "unknown")

DEFAULT_IMPACT = {
    "primitive": "undetermined",
    "consequence": "undetermined",
    # Empty means "derive from the finding's bug_class"; see cwe_of.
    "cwe": "",
    "corrupted_object": "",     # the struct or allocation the fault touches
    "cache": "",                # slab cache / size class it comes from
    "access_type": "unknown",
    "access_size": None,        # bytes, from the sanitizer report
    "overwrite_target": "unknown",
    "reclaim_path": "",         # how a freed allocation can be re-occupied
    "race_window": "",          # for race/UAF: what has to interleave
    "allocation_site": "",      # file.c:line
    "free_site": "",
    "access_site": "",
    "attacker_control": [],
    "evidence": [],             # file.c:line or report refs behind the claim
    "unverified": [],           # the specific claims not checked against source
    "confidence": "low",
    # Why the primitive or the consequence is undetermined. Required in that
    # case: see impact_support_gap.
    "undetermined_reason": "",
}
IMPACT_LISTS = ("attacker_control", "evidence", "unverified")
IMPACT_TEXT = ("cwe", "corrupted_object", "cache", "reclaim_path",
               "race_window", "allocation_site", "free_site", "access_site",
               "undetermined_reason")
IMPACT_VOCAB = (("primitive", PRIMITIVE), ("consequence", CONSEQUENCE),
                ("access_type", ACCESS_TYPE),
                ("overwrite_target", OVERWRITE_TARGET),
                ("confidence", CONFIDENCE))
# Consequences that require the attacker to influence something. An outcome
# above denial of service argued from an attacker who controls nothing is the
# claim that gets challenged first.
CONSEQUENCE_NEEDS_CONTROL = ("privilege-escalation", "container-escape")
# Primitives that are a claim about code rather than an absence of one, so
# they need a source reference behind them.
PRIMITIVE_NEEDS_EVIDENCE = tuple(p for p in PRIMITIVE
                                 if p not in ("none", "undetermined"))

DEFAULT_ROUND = {"round": 1, "status": "in_progress", "started": None,
                 "ended": None, "run_ids": [], "coverage_verdict": "unknown",
                 "edges_start": None, "edges_end": None, "new_crashes": 0,
                 "run_hours": 0.0, "decision": None, "decision_reason": "",
                 # worklist: what this round's refine produced.
                 # worklist_in: what this round's describe/seeds must execute,
                 # carried from the previous round. The learning handoff is
                 # state, not a filename convention two prompts have to agree
                 # on — otherwise the next agent has to guess the run id.
                 "worklist": None, "worklist_in": None,
                 # Per-run billing for this round: run id -> measured hours.
                 # run_hours is their sum, accumulated across round-end calls
                 # (one per campaign), never a single campaign standing in for
                 # the whole round.
                 "run_hours_by_run": {},
                 "notes": ""}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_round(entry=None, **kw):
    """A round dict with the defaults filled in and no shared mutables.

    dict(DEFAULT_ROUND) would alias the module-level run_ids list and
    run_hours_by_run dict into every round created in this process; the copies
    below keep each round's bookkeeping its own.
    """
    if entry is not None and not isinstance(entry, dict):
        raise ValueError("pipeline state: round entries must be objects, got "
                         "%s" % type(entry).__name__)
    r = dict(DEFAULT_ROUND)
    r["run_ids"] = []
    r["run_hours_by_run"] = {}
    for src in (entry or {}, kw):
        for k, v in src.items():
            if k == "run_ids":
                v = list(v or [])
            elif k == "run_hours_by_run":
                v = dict(v or {})
            r[k] = v
    return r


def default_state():
    return {
        "version": SCHEMA_VERSION,
        "phases": {p: dict(DEFAULT_PHASE) for p in PHASES},
        "crashes": {},
        "campaigns": [],
        "rounds": [_new_round(round=1, started=_now())],
        "manifest": "artifacts/builds/manifest.json",
        # The dedup settings the registry's hashes were produced under.
        # Stamped on the first registration; see triage_drift().
        "triage_settings": {},
    }


def _fill(defaults, entry, what):
    """defaults overlaid with entry; a non-dict entry is a corrupt state file,
    so say so as a ValueError (pipeline_ctl.main catches those) rather than
    letting the raw TypeError from dict(**entry) escape as a traceback."""
    if entry is None:
        return dict(defaults)
    if not isinstance(entry, dict):
        raise ValueError("pipeline state: %s must be an object, got %s"
                         % (what, type(entry).__name__))
    return dict(defaults, **entry)


def normalize(state):
    """Fill in anything a older/hand-edited state file is missing.

    Keeps unknown top-level keys (forward compatibility) but guarantees every
    phase and every crash carries the full key set callers expect.
    """
    if not isinstance(state, dict):
        raise ValueError("pipeline state must be a JSON object")
    out = default_state()
    out.update(state)
    phases = out.get("phases") or {}
    if not isinstance(phases, dict):
        raise ValueError("pipeline state 'phases' must be an object")
    out["phases"] = {p: _fill(DEFAULT_PHASE, phases.get(p), "phase %s" % p)
                     for p in PHASES}
    crashes = out.get("crashes") or {}
    if not isinstance(crashes, dict):
        raise ValueError("pipeline state 'crashes' must be an object")
    out["crashes"] = {cid: _fill(DEFAULT_CRASH, c, "crash %s" % cid)
                      for cid, c in crashes.items()}
    if not isinstance(out.get("campaigns"), list):
        out["campaigns"] = []
    # v1 -> v2: pre-loop state files have no rounds; treat their work as round 1.
    rounds = out.get("rounds")
    if not isinstance(rounds, list) or not rounds:
        rounds = [dict(DEFAULT_ROUND, round=1, started=_now())]
    out["rounds"] = [_new_round(r) for r in rounds]
    out["version"] = SCHEMA_VERSION
    return out


def load(path=None):
    path = path or STATE_PATH
    if not os.path.exists(path):
        return default_state()
    with open(path) as f:
        try:
            raw = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError("%s is not valid JSON (%s). Restore it from "
                             "%s.bak or re-init." % (path, e, path))
    return normalize(raw)


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fix_root_ownership(paths):
    """Undo root poisoning after a sudo run.

    campaign_ctl start/stop run as root and write state through save(); left
    alone, the state file (mkstemp mode 0600, owner root) and the lock file
    become root-owned and every subsequent non-root agent command dies with
    PermissionError. When we are root via sudo, hand the files back to the
    invoking user.
    """
    if os.geteuid() != 0:
        return
    user = os.environ.get("SUDO_USER")
    if not user:
        return
    import pwd
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return
    for p in paths:
        try:
            os.chown(p, pw.pw_uid, pw.pw_gid)
        except OSError:
            pass


def save(state, path=None):
    """Atomic, panic-durable write."""
    path = path or STATE_PATH
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    # Keep the previous good file as <path>.bak: the corrupt-state error
    # message in load() tells the operator to restore from it, so it has to
    # actually exist.
    if os.path.exists(path):
        shutil.copyfile(path, path + ".bak")
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_dir(d)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    _fix_root_ownership([path, path + ".bak"])


def _lock_path(path):
    return os.path.join(os.path.dirname(path) or ".", ".pipeline.lock")


@contextmanager
def transaction(path=None):
    """Exclusive read-modify-write on the state file.

        with ps.transaction() as st:
            st["crashes"][cid]["status"] = "reliable"

    The state is saved on clean exit; an exception inside the block aborts
    the write, leaving the file untouched.
    """
    path = path or STATE_PATH
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    lock = _lock_path(path)
    fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        state = load(path)
        yield state
        save(state, path)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    _fix_root_ownership([lock])


@contextmanager
def _ledger_transaction(path):
    """Exclusive read-modify-write on the spend ledger (own lock file, so it
    is safe to call while a state transaction() is open)."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    lock = path + ".lock"
    fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    _fix_root_ownership([lock])


def _read_ledger(path):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        try:
            raw = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError("%s is not valid JSON (%s). Restore it from "
                             "%s.bak or delete it to re-seed from the state "
                             "file." % (path, e, path))
    if not isinstance(raw, dict):
        raise ValueError("%s must contain a JSON object mapping run id to "
                         "billed hours" % path)
    return {str(k): float(v) for k, v in raw.items()}


def _seed_spend_ledger(path):
    """One-time migration: attribute hours the state file already recorded.

    Runs before the first ledger write, so spend billed before the ledger
    existed still counts against the budget. Per-run hours are taken from
    run_hours_by_run where present; a round whose aggregate run_hours is not
    fully attributed lands under its single run id, or under a "round-N" key
    when the split across several runs is unknowable — the hours must not be
    lost, but a per-run split must not be invented either.

    Seeds from the DEFAULT state file, never STATE_PATH, for the same reason
    spend_for_budget() does: a run redirecting GSPWN_STATE would
    otherwise seed the machine-global ledger from its own empty registry, and
    every hour recorded before it would drop off the budget.
    """
    if os.path.exists(path):
        return
    st = load(DEFAULT_STATE_PATH)
    entries = {}
    for r in st.get("rounds", []):
        by_run = r.get("run_hours_by_run") or {}
        for rid, h in by_run.items():
            if h:
                entries[rid] = round(entries.get(rid, 0.0) + h, 2)
        unattributed = round((r.get("run_hours") or 0.0)
                             - sum(by_run.values()), 2)
        if unattributed <= 0:
            continue
        ids = r.get("run_ids") or []
        key = ids[0] if len(ids) == 1 else "round-%s" % r.get("round", "?")
        entries[key] = round(entries.get(key, 0.0) + unattributed, 2)
    save(entries, path)


def record_run_hours(run_id, hours, path=None):
    """Bill a run's measured hours to the spend ledger.

    Idempotent per run id: re-recording the same run overwrites its entry, so
    a retried round-end never double-counts a campaign.

    `path` resolves at call time, not import time: a default of SPEND_PATH
    would freeze the module value into the signature, so redirecting the
    ledger (tests, and any future per-machine override) would silently keep
    writing the real one.
    """
    path = path or SPEND_PATH
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("run_id must be a non-empty string")
    hours = float(hours)
    if hours < 0:
        raise ValueError("hours must be >= 0, got %r" % hours)
    with _ledger_transaction(path):
        _seed_spend_ledger(path)
        entries = _read_ledger(path)
        entries[run_id] = round(hours, 2)
        save(entries, path)


def total_spend_hours(path=None):
    """Total billed run-hours across every recorded campaign (0.0 if none)."""
    path = path or SPEND_PATH
    with _ledger_transaction(path):
        return round(sum(_read_ledger(path).values()), 2)


class SpendLedgerMissing(Exception):
    """The ledger is gone while billed hours are still on record.

    Carries its own remediation: callers surface `str(e)` to the operator
    rather than inventing a spend figure.
    """


def seed_spend_ledger(path=None):
    """Create the ledger from the state file's recorded hours, if absent.

    The explicit remediation for SpendLedgerMissing. No-op when the ledger
    already exists, so re-running it can never double-bill.
    """
    path = path or SPEND_PATH
    with _ledger_transaction(path):
        _seed_spend_ledger(path)
        return round(sum(_read_ledger(path).values()), 2)


def spent_hours(state):
    """Authoritative spend, or raise when it cannot be established.

    The ledger is the authority. When it is absent but the state file still
    records billed hours, the ledger was lost or predates this version —
    falling back to zero would silently hand the loop a fresh budget, which
    on a $200 ceiling is the expensive direction to be wrong in. Refuse, and
    make re-seeding an explicit act (`pipeline_ctl.py spend-init`).

    A genuinely fresh machine — no ledger, no recorded hours — is 0.0 and
    starts normally.
    """
    if os.path.exists(SPEND_PATH):
        return total_spend_hours()
    recorded = total_run_hours(state)
    if recorded > 0:
        raise SpendLedgerMissing(
            "spend ledger %s is missing, but the state file records %.1f "
            "billed run-hours. Refusing to treat the budget as unspent. "
            "Re-seed it from the state file with: python3 "
            "tools/pipeline_ctl.py spend-init" % (SPEND_PATH, recorded))
    return 0.0


def spend_for_budget():
    """Machine-global spend for the campaign-start guard.

    Falls back to the DEFAULT state file, not STATE_PATH: the ledger is
    machine-global, so its fallback must be too. Reading the redirected file
    would let a run with a fresh GSPWN_STATE reopen the very
    bypass the ledger closes.
    """
    if os.path.exists(SPEND_PATH):
        return total_spend_hours()
    return spent_hours(load(DEFAULT_STATE_PATH))


def update_phase(state, phase, status, notes=""):
    if phase not in PHASES:
        raise ValueError("unknown phase: %s (expected one of %s)"
                         % (phase, ", ".join(PHASES)))
    if status not in PHASE_STATUS:
        raise ValueError("unknown phase status: %s (expected one of %s)"
                         % (status, ", ".join(sorted(PHASE_STATUS))))
    # Notes describe *this* status change, so they are replaced, not inherited:
    # carrying "gate ok" forward onto a later `failed` produces a state file
    # that reads as the opposite of what happened, and leaves no way to clear
    # a stale note.
    state["phases"][phase] = {
        "status": status,
        "updated": _now(),
        "notes": notes or "",
    }


def next_phase(state):
    """First phase not yet done, or None when the pipeline is complete.

    Blocked/failed phases stop the walk: they are the phase that needs
    attention, not something to skip past.
    """
    for p in PHASES:
        if state["phases"][p]["status"] != "done":
            return p
    return None


def current_round(state):
    return state["rounds"][-1]


def round_number(state):
    return current_round(state)["round"]


def total_run_hours(state):
    return sum(r.get("run_hours") or 0.0 for r in state["rounds"])


def next_action(state):
    """What the orchestrator should do next, as (kind, value).

    kind is one of:
      "phase"          -> run this phase
      "decide"         -> round phases are done; record a loop decision
      "advance-round"  -> decision was continue; open the next round
      "done"           -> pipeline complete
    """
    def pending(p):
        return state["phases"][p]["status"] != "done"

    for p in SETUP_PHASES:
        if pending(p):
            return ("phase", p)
    for p in ROUND_PHASES:
        if pending(p):
            return ("phase", p)
    r = current_round(state)
    if r["decision"] is None:
        return ("decide", None)
    if r["decision"] == "continue":
        return ("advance-round", None)
    for p in FINAL_PHASES:
        if pending(p):
            return ("phase", p)
    return ("done", None)


def end_round(state, verdict=None, new_crashes=None, edges_start=None,
              edges_end=None, run_hours=None, notes=None, worklist=None,
              billed=None):
    """Record the measured outcome of the current round.

    run_hours ACCUMULATES: a round routinely spans several campaigns, and
    round-end is called once per run, so each call adds its hours to the
    round total instead of overwriting it. `billed` is the per-run mapping
    {run_id: hours} those hours came from; re-billing a run id corrects its
    entry (and the total by the delta) rather than double-counting. Every
    other field is last-write-wins.
    """
    r = current_round(state)
    if verdict is not None:
        if verdict not in COVERAGE_VERDICT:
            raise ValueError("unknown coverage verdict: %s (expected one of "
                             "%s)" % (verdict, ", ".join(sorted(
                                 COVERAGE_VERDICT))))
        r["coverage_verdict"] = verdict
    for key, val in (("new_crashes", new_crashes), ("edges_start", edges_start),
                     ("edges_end", edges_end),
                     ("notes", notes), ("worklist", worklist)):
        if val is not None:
            r[key] = val
    if billed:
        by_run = r.setdefault("run_hours_by_run", {})
        for rid, h in billed.items():
            r["run_hours"] = round((r["run_hours"] or 0.0)
                                   + (h - by_run.get(rid, 0.0)), 2)
            by_run[rid] = h
    if run_hours is not None:
        r["run_hours"] = round((r["run_hours"] or 0.0) + run_hours, 2)
    r["ended"] = _now()
    r["status"] = "complete"
    return r


def record_decision(state, decision, reason=""):
    if decision not in ROUND_DECISION:
        raise ValueError("unknown round decision: %s (expected one of %s)"
                         % (decision, ", ".join(sorted(ROUND_DECISION))))
    r = current_round(state)
    r["decision"] = decision
    r["decision_reason"] = reason
    return r


def hard_cap_reason(state, max_rounds, max_total_run_hours=None):
    """The non-overridable stop reason, or None when no hard cap has tripped.

    Round-cap and budget stops are the spend ceiling: AGENTS.md forbids
    overriding them, so round-decide recomputes this before accepting an
    explicit --decision continue.
    """
    r = current_round(state)
    if r["round"] >= max_rounds:
        return "round cap reached (%d of %d)" % (r["round"], max_rounds)
    if max_total_run_hours is not None:
        spent = spent_hours(state)
        if spent >= max_total_run_hours:
            return ("run-hour budget spent (%.1f of %.1f h)"
                    % (spent, max_total_run_hours))
    return None


def loop_decision(state, max_rounds, max_total_run_hours=None,
                  stop_on_plateau=True):
    """Apply the configured caps to the current round -> (decision, reason).

    Caps are checked before the coverage verdict: a plateau is a reason to
    stop, but so is running out of the budget the user authorised, and the
    budget must win even while coverage is still growing.
    """
    hard = hard_cap_reason(state, max_rounds, max_total_run_hours)
    if hard:
        return ("stop", hard)
    r = current_round(state)
    if stop_on_plateau and r["coverage_verdict"] == "plateaued":
        return ("stop", "coverage plateaued in round %d" % r["round"])
    if r["coverage_verdict"] == "unknown":
        return ("stop", "no coverage verdict recorded for round %d — refusing "
                        "to spend another campaign blind" % r["round"])
    return ("continue", "coverage still growing after round %d" % r["round"])


def advance_round(state):
    """Open the next round: reset the round phases, keep setup and crashes."""
    r = current_round(state)
    if r["decision"] != "continue":
        raise ValueError("current round decision is %r, not 'continue' — "
                         "record a continue decision before advancing"
                         % r["decision"])
    not_done = [p for p in ROUND_PHASES
                if state["phases"][p]["status"] != "done"]
    if not_done:
        # Deliberately not satisfiable by marking a phase blocked: a blocked
        # gate is a stopping point, and carrying one into a new round would
        # bury it. The two real ways out are finishing the phase or stopping
        # the loop, so say those rather than one that does not work.
        raise ValueError(
            "cannot advance to round %d: round phase(s) not done: %s. Finish "
            "them, or stop the loop instead of advancing (round-decide "
            "--decision stop --reason \"...\") and run the report phase. "
            "Marking a phase blocked does not satisfy this check"
            % (r["round"] + 1, ", ".join(not_done)))
    if not r.get("ended") or r.get("run_hours") is None:
        raise ValueError("cannot advance to round %d: round %d has no "
                         "recorded round-end — measure it first: "
                         "pipeline_ctl.py round-end --from-run <run-id>"
                         % (r["round"] + 1, r["round"]))
    for p in ROUND_PHASES:
        state["phases"][p] = dict(DEFAULT_PHASE)
    # Carry the worklist forward: besides the corpus, it is the only state the
    # new round inherits from the last one.
    state["rounds"].append(_new_round(round=r["round"] + 1, started=_now(),
                                      worklist_in=r.get("worklist")))
    return current_round(state)


def next_crash_id(state):
    n = len(state["crashes"]) + 1
    while "crash-%04d" % n in state["crashes"]:
        n += 1
    return "crash-%04d" % n


def register_crash(state, crash):
    """crash dict keys: track(K|U), title, stack_hash, status, dir,
    repro_rate(None), duplicate_of(None), disclosure('pending')."""
    if crash.get("status") not in CRASH_STATUS:
        raise ValueError("unknown crash status: %s" % crash.get("status"))
    if crash.get("track") not in TRACKS:
        raise ValueError("unknown track: %s (expected K or U)"
                         % crash.get("track"))
    cid = next_crash_id(state)
    state["crashes"][cid] = dict(DEFAULT_CRASH, **crash)
    return cid


def set_crash_status(crash, status, tool="pipeline_ctl"):
    """Set a crash's status, keeping the trail and the rca stamp.

    Every status write goes through here. Two things have to happen alongside
    the assignment and both were previously done in only one of the two places
    that write it:

    - the append-only history trail, so a reclassification does not erase that
      the earlier one happened;
    - the `rca_done_at` stamp, because `rca_done` is transient. The poc phase
      writes reliable/flaky/unreproducible straight over it, so `validate`
      checking `status == "rca_done"` stops seeing an unanalysed crash the
      moment poc runs, which is the one phase guaranteed to run afterwards.
    """
    if status not in CRASH_STATUS:
        raise ValueError("unknown crash status: %s (expected one of %s)"
                         % (status, ", ".join(sorted(CRASH_STATUS))))
    prev = crash.get("status")
    if prev != status:
        history = list(crash.get("history") or [])
        history.append({"ts": _now(), "from": prev, "to": status, "tool": tool})
        crash["history"] = history
    crash["status"] = status
    if status == "rca_done" and not crash.get("rca_done_at"):
        crash["rca_done_at"] = _now()
    return crash


def was_analysed(crash):
    """Has rca ever finished with this crash?

    The stamp first, the current status second: a registry written before the
    stamp existed still reports correctly while a crash sits at `rca_done`.
    """
    return bool(crash.get("rca_done_at")) or crash.get("status") == "rca_done"


def _finding_strings(value, field, kind="finding"):
    """A record's list field, cleaned: non-empty strings, deduped, in order.

    Order is preserved because rca writes the ioctl sequence in the order the
    reproducer calls them, and describe models a sequence, not a set.
    """
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise ValueError("%s field %r must be a list of strings, got %s"
                         % (kind, field, type(value).__name__))
    out = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError("%s field %r must contain strings, got %s"
                             % (kind, field, type(item).__name__))
        item = item.strip()
        if item and item not in out:
            out.append(item)
    return out


def normalize_finding(finding):
    """Validate and fill in a research record -> the stored dict.

    Rejects unknown keys rather than dropping them: a misspelled `ioctl` would
    otherwise be accepted, leave `ioctls` empty, and hand the next round a
    finding with nothing to model while every command reported success.
    """
    if not isinstance(finding, dict):
        raise ValueError("a finding must be a JSON object, got %s"
                         % type(finding).__name__)
    unknown = sorted(set(finding) - set(DEFAULT_FINDING))
    if unknown:
        raise ValueError("unknown finding field(s): %s (expected one of %s)"
                         % (", ".join(unknown),
                            ", ".join(sorted(DEFAULT_FINDING))))
    out = dict(DEFAULT_FINDING)
    for k in FINDING_LISTS:
        out[k] = []
    out.update({k: v for k, v in finding.items() if v is not None})
    for k in FINDING_LISTS:
        out[k] = _finding_strings(out[k], k)
    for k in FINDING_TEXT:
        if not isinstance(out[k], str):
            raise ValueError("finding field %r must be a string, got %s"
                             % (k, type(out[k]).__name__))
        out[k] = out[k].strip()
    for k, vocab in (("bug_class", BUG_CLASS), ("trigger", TRIGGER),
                     ("confidence", CONFIDENCE)):
        if out[k] not in vocab:
            raise ValueError("unknown %s: %r (expected one of %s)"
                             % (k, out[k], ", ".join(vocab)))
    if not out["subsystem"]:
        raise ValueError("a finding needs a subsystem — it is the key refine "
                         "groups by, so a finding without one cannot raise "
                         "any target's priority")
    if not any(out[k] for k in FINDING_TARGETING):
        raise ValueError("a finding needs at least one of %s — a record that "
                         "names no call and no state cannot steer describe or "
                         "seeds, and the feedback edge would carry nothing"
                         % ", ".join(FINDING_TARGETING))
    return out


def finding_target_gap(finding):
    """Why this record steers nothing new, or None when it steers something.

    `adjacent` is the only field that carries information the crash does not
    already contain. `ioctls` is transcribed from the reproducer and
    `preconditions` largely from the same place; a round can act on neither to
    look anywhere it has not already looked. So a record whose `adjacent` is
    empty, or whose `adjacent` only repeats calls already in `ioctls`, adds
    nothing to the next round's worklist even though every other field is
    filled in and `finding-list` prints it happily.

    That is the failure this whole path is most likely to die of, and it is
    invisible: the edge stays wired, the records accumulate, and the campaign
    quietly goes back to following coverage alone. So an empty `adjacent` is
    allowed only when rca says why — a bug with no siblings on its lock or
    teardown path is a real answer, and writing that down is cheap. Guessing a
    neighbouring call to fill the field would be worse than either.
    """
    adjacent = set(finding.get("adjacent") or [])
    if not adjacent:
        if (finding.get("no_adjacent_reason") or "").strip():
            return None
        return ("no adjacent calls, and no no_adjacent_reason explaining why. "
                "This record cannot send the next round anywhere it has not "
                "already been")
    if adjacent <= set(finding.get("ioctls") or []):
        return ("every adjacent call is already in ioctls, so the record "
                "names no call the reproducer did not already make and adds "
                "nothing to the next round's worklist")
    return None


def findings_steering_nothing(state):
    """[(crash_id, finding, why)] for records that cannot steer a next round."""
    out = []
    for cid, f in findings(state):
        why = finding_target_gap(f)
        if why:
            out.append((cid, f, why))
    return out


def set_finding(state, cid, finding):
    """Attach rca's research record to a crash (replaces any previous one)."""
    if cid not in state["crashes"]:
        raise ValueError("unknown crash id: %s" % cid)
    state["crashes"][cid]["finding"] = normalize_finding(finding)
    return state["crashes"][cid]["finding"]


def findings(state, subsystem=None, bug_class=None):
    """Every recorded research record, as [(crash_id, finding)].

    Duplicates are skipped: they describe the same bug as their surviving
    entry, and counting both would inflate a subsystem's weight in refine by
    however many times the fuzzer happened to rediscover it.
    """
    out = []
    for cid in sorted(state["crashes"]):
        c = state["crashes"][cid]
        f = c.get("finding")
        if not f or c.get("status") == "duplicate":
            continue
        if subsystem and f.get("subsystem") != subsystem:
            continue
        if bug_class and f.get("bug_class") != bug_class:
            continue
        out.append((cid, f))
    return out


def normalize_impact(impact):
    """Validate and fill in an impact record -> the stored dict.

    Same contract as normalize_finding: unknown keys are refused rather than
    dropped, so a misspelled field cannot leave the real one at its default
    while the command reports success.
    """
    if not isinstance(impact, dict):
        raise ValueError("an impact must be a JSON object, got %s"
                         % type(impact).__name__)
    unknown = sorted(set(impact) - set(DEFAULT_IMPACT))
    if unknown:
        raise ValueError("unknown impact field(s): %s (expected one of %s)"
                         % (", ".join(unknown),
                            ", ".join(sorted(DEFAULT_IMPACT))))
    out = dict(DEFAULT_IMPACT)
    for k in IMPACT_LISTS:
        out[k] = []
    out.update({k: v for k, v in impact.items() if v is not None})
    for k in IMPACT_LISTS:
        out[k] = _finding_strings(out[k], k, kind="impact")
    for k in IMPACT_TEXT:
        if not isinstance(out[k], str):
            raise ValueError("impact field %r must be a string, got %s"
                             % (k, type(out[k]).__name__))
        out[k] = out[k].strip()
    for k, vocab in IMPACT_VOCAB:
        if out[k] not in vocab:
            raise ValueError("unknown %s: %r (expected one of %s)"
                             % (k, out[k], ", ".join(vocab)))
    for item in out["attacker_control"]:
        if item not in ATTACKER_CONTROL:
            raise ValueError("unknown attacker_control: %r (expected one of "
                             "%s)" % (item, ", ".join(ATTACKER_CONTROL)))
    if out["cwe"] and not CWE_RE.match(out["cwe"]):
        raise ValueError("cwe must look like 'CWE-416', got %r. Leave it "
                         "empty to derive it from the finding's bug_class"
                         % out["cwe"])
    size = out["access_size"]
    if size is not None and not (isinstance(size, int)
                                 and not isinstance(size, bool) and size > 0):
        raise ValueError("access_size must be a positive integer of bytes or "
                         "absent, got %r" % (size,))
    return out


def cwe_of(crash):
    """The weakness class for a crash: the impact's override, else derived.

    Derived from the finding's bug_class, which is already a closed
    vocabulary, so the two cannot disagree by drift. Returns "" when the crash
    has no finding, or when bug_class is 'other' and nothing was recorded — an
    empty CWE is honest, a guessed one is not.
    """
    impact = crash.get("impact") or {}
    if impact.get("cwe"):
        return impact["cwe"]
    finding = crash.get("finding") or {}
    return CWE_OF_BUG_CLASS.get(finding.get("bug_class") or "", "")


def impact_support_gap(impact):
    """Why this record does not support its own conclusion, or None.

    Three ways an impact record goes wrong, in rising order of what they cost:

    1. It concludes nothing and does not say why. The same escape hatch as
       no_adjacent_reason, for the same reason: "the consequence cannot be
       determined from outside GSP firmware" is a real answer and has to stay
       cheap to give, or the agent invents an impact story instead. That is
       the worst available outcome here, so undetermined is never penalised —
       only unexplained undetermined is.
    2. It claims a primitive with no evidence. A primitive is a claim about
       code, and a claim about code with no file:line behind it is a guess
       wearing a vocabulary.
    3. Its consequence outruns its primitive, or rests on an attacker who
       controls nothing. This is the expensive one. A privilege-escalation
       conclusion drawn from an undetermined primitive is exactly the finding
       a vendor engineer disproves in ten minutes, and it takes the
       credibility of every other finding in the report with it.

    Deliberately not flagged: a consequence weaker than the primitive would
    support. Under-claiming costs nothing and flagging it would push the agent
    towards escalating, which is the direction that does cost something.
    """
    primitive = impact.get("primitive") or "undetermined"
    consequence = impact.get("consequence") or "undetermined"
    reason = (impact.get("undetermined_reason") or "").strip()
    evidence = impact.get("evidence") or []
    control = set(impact.get("attacker_control") or [])

    if (primitive == "undetermined" or consequence == "undetermined") \
            and not reason:
        return ("primitive=%s consequence=%s, and no undetermined_reason "
                "saying what blocked the analysis. Undetermined is a valid "
                "answer here; an unexplained one is not, because nobody "
                "later can tell it apart from an analysis that was skipped"
                % (primitive, consequence))
    if primitive in PRIMITIVE_NEEDS_EVIDENCE and not evidence:
        return ("claims primitive=%s with no evidence. That is a claim about "
                "code, so it needs the file:line it rests on before a report "
                "can put a severity on it" % primitive)
    if consequence in CONSEQUENCE_NEEDS_CONTROL:
        if primitive in ("none", "undetermined"):
            return ("consequence=%s argued from primitive=%s. The conclusion "
                    "outruns the mechanism: name what the fault actually "
                    "gives an attacker, or lower the consequence"
                    % (consequence, primitive))
        if not control or control <= {"none", "unknown"}:
            return ("consequence=%s with attacker_control=%s. An outcome "
                    "above denial of service needs the attacker to influence "
                    "something; if they influence nothing, the defensible "
                    "answer is dos-only"
                    % (consequence, ", ".join(sorted(control)) or "empty"))
    return None


def impacts_unsupported(state):
    """[(crash_id, impact, why)] for records that do not support themselves."""
    out = []
    for cid, im in impacts(state):
        why = impact_support_gap(im)
        if why:
            out.append((cid, im, why))
    return out


def set_impact(state, cid, impact):
    """Attach rca's impact record to a crash (replaces any previous one)."""
    if cid not in state["crashes"]:
        raise ValueError("unknown crash id: %s" % cid)
    state["crashes"][cid]["impact"] = normalize_impact(impact)
    return state["crashes"][cid]["impact"]


def impacts(state, primitive=None, consequence=None):
    """Every recorded impact record, as [(crash_id, impact)].

    Duplicates are skipped for the same reason findings() skips them: they
    describe the same bug as their surviving entry, and counting both would
    report one vulnerability as several.
    """
    out = []
    for cid in sorted(state["crashes"]):
        c = state["crashes"][cid]
        im = c.get("impact")
        if not im or c.get("status") == "duplicate":
            continue
        if primitive and im.get("primitive") != primitive:
            continue
        if consequence and im.get("consequence") != consequence:
            continue
        out.append((cid, im))
    return out


def stamp_triage_settings(state, settings):
    """Record the dedup settings the registry's hashes were produced under.

    Written once, at the first registration, and never overwritten. The point
    is to remember what the stored hashes mean; rewriting it later would erase
    exactly the evidence that they were produced under something else.
    """
    if not state.get("triage_settings"):
        state["triage_settings"] = dict(settings)
    return state["triage_settings"]


def triage_drift(state, settings):
    """[(key, recorded, current)] for dedup settings changed since stamping.

    Changing frame depths or the frameless signature mid-campaign does not
    recompute the hashes already in the registry, so across the change the
    same bug can register twice and two different bugs can merge into one that
    never reaches rca. The config comments say to change them between
    campaigns; this is what makes ignoring that visible instead of silent,
    which is the difference between a caveat and a check.
    """
    was = state.get("triage_settings") or {}
    return [(k, was[k], settings[k]) for k in sorted(was)
            if k in settings and was[k] != settings[k]]


def validate(state, triage_settings=None):
    """Return a list of human-readable integrity problems (empty == clean).

    `triage_settings` is the current dedup config. Optional because this
    module deliberately does not read config — the caller that has it passes
    it in, and the drift check is simply skipped for one that does not.
    """
    problems = []
    if triage_settings:
        for key, was, now in triage_drift(state, triage_settings):
            problems.append(
                "triage.%s is %r now but the registry's hashes were built "
                "with %r. Hashes are not recomputed, so across this change "
                "one bug can register twice and two bugs can merge into one "
                "that never reaches rca. Restore it for the rest of this "
                "campaign, or start a fresh registry" % (key, now, was))
    for p in PHASES:
        st = state["phases"][p]["status"]
        if st not in PHASE_STATUS:
            problems.append("phase %s has invalid status %r" % (p, st))
    # A phase marked done while something it depends on is not is a real
    # inconsistency: gates are ordered. The parallel trio only depends on build.
    done = {p for p in PHASES if state["phases"][p]["status"] == "done"}
    for i, p in enumerate(PHASES):
        if p not in done:
            continue
        for earlier in PHASES[:i]:
            if earlier in done:
                continue
            if {p, earlier} <= PARALLEL_AFTER_BUILD:
                continue  # describe/seeds/harness are order-independent
            problems.append("phase %s is done but earlier phase %s is %s"
                            % (p, earlier, state["phases"][earlier]["status"]))
    for cid, c in state["crashes"].items():
        if c.get("status") not in CRASH_STATUS:
            problems.append("%s has invalid status %r" % (cid, c.get("status")))
        if c.get("track") not in TRACKS:
            problems.append("%s has invalid track %r" % (cid, c.get("track")))
        if c.get("disclosure") not in DISCLOSURE_STATUS:
            problems.append("%s has invalid disclosure %r"
                            % (cid, c.get("disclosure")))
        dup = c.get("duplicate_of")
        if dup is not None:
            if dup == cid:
                problems.append("%s is marked a duplicate of itself" % cid)
            elif dup not in state["crashes"]:
                problems.append("%s duplicates unknown crash %s" % (cid, dup))
            elif c.get("status") != "duplicate":
                problems.append("%s has duplicate_of=%s but status=%s"
                                % (cid, dup, c.get("status")))
            elif state["crashes"][dup].get("status") == "duplicate":
                # Chains (A->B->C) and cycles are both caught here: every
                # member of either is itself a duplicate, so its inbound
                # links point at a duplicate and get flagged. duplicate_of
                # must reference the surviving, non-duplicate entry.
                problems.append("%s duplicates %s, which is itself a "
                                "duplicate — link directly to the surviving "
                                "entry (chains and cycles are not allowed)"
                                % (cid, dup))
        elif c.get("status") == "duplicate":
            problems.append("%s has status 'duplicate' but no duplicate_of "
                            "link" % cid)
        rate = c.get("repro_rate")
        if rate is not None and not (isinstance(rate, (int, float))
                                     and 0.0 <= rate <= 1.0):
            problems.append("%s has out-of-range repro_rate %r" % (cid, rate))
        if c.get("finding") is not None:
            try:
                f = normalize_finding(c["finding"])
            except ValueError as e:
                problems.append("%s has an invalid finding: %s" % (cid, e))
            else:
                # Duplicates are excluded from findings() and from the
                # worklist, so a duplicate that steers nothing costs nothing.
                gap = (None if c.get("status") == "duplicate"
                       else finding_target_gap(f))
                if gap:
                    problems.append("%s has a finding that steers nothing: %s"
                                    % (cid, gap))
        elif c.get("status") != "duplicate" and was_analysed(c):
            # rca_done without a research record is the failure this whole
            # edge exists to prevent: the analysis happened and nothing
            # survived it for the next round to act on. Keyed on the stamp,
            # so the poc phase writing a reproduction class over the status
            # does not retire the check.
            problems.append("%s was analysed by rca but has no finding — the "
                            "round learned nothing from it (record one with: "
                            "pipeline_ctl.py finding-set %s --json ...)"
                            % (cid, cid))
        if c.get("impact") is not None:
            try:
                im = normalize_impact(c["impact"])
            except ValueError as e:
                problems.append("%s has an invalid impact: %s" % (cid, e))
            else:
                gap = (None if c.get("status") == "duplicate"
                       else impact_support_gap(im))
                if gap:
                    problems.append("%s has an impact record that does not "
                                    "support its conclusion: %s" % (cid, gap))
        elif c.get("status") != "duplicate" and was_analysed(c):
            # A crash analysed but never assessed reaches the report as a
            # reproducer with no severity behind it, which is a bug report
            # rather than a vulnerability report.
            problems.append("%s was analysed by rca but has no impact record "
                            "— the report would carry a reproducer with no "
                            "argued severity (record one with: "
                            "pipeline_ctl.py impact-set %s --json ...)"
                            % (cid, cid))
    for i, r in enumerate(state.get("rounds", []), start=1):
        if r.get("round") != i:
            problems.append("round %d is numbered %r (rounds must be "
                            "sequential from 1)" % (i, r.get("round")))
        if r.get("coverage_verdict") not in COVERAGE_VERDICT:
            problems.append("round %d has invalid coverage verdict %r"
                            % (i, r.get("coverage_verdict")))
        if r.get("decision") is not None and r["decision"] not in ROUND_DECISION:
            problems.append("round %d has invalid decision %r"
                            % (i, r.get("decision")))
    # Every round but the last must be closed out, or the history is unusable
    # for the eval write-up.
    for r in state.get("rounds", [])[:-1]:
        if r.get("decision") != "continue":
            problems.append("round %d was superseded but its decision is %r "
                            "(expected 'continue')"
                            % (r.get("round"), r.get("decision")))
    return problems
