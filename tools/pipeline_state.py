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
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_DIR = os.path.join(REPO_ROOT, "state")
# GSPWN_STATE redirects the state file (used by tools/selftest.py; also lets
# an ablation run keep its own pipeline.json without touching the main one).
STATE_PATH = os.environ.get("GSPWN_STATE") or os.path.join(STATE_DIR,
                                                           "pipeline.json")

SCHEMA_VERSION = 2

# Setup runs once for the machine; the round phases re-run every round of the
# improvement loop; report runs once, after the loop stops.
SETUP_PHASES = ["provision", "build"]
ROUND_PHASES = ["describe", "seeds", "harness", "fuzz", "triage", "rca",
                "poc", "eval", "refine"]
FINAL_PHASES = ["report"]
PHASES = SETUP_PHASES + ROUND_PHASES + FINAL_PHASES

PHASE_STATUS = {"pending", "in_progress", "done", "blocked", "failed"}
CRASH_STATUS = {"unique", "duplicate", "flagged", "reliable", "flaky",
                "unreproducible", "rca_done", "reported"}
DISCLOSURE_STATUS = {"pending", "submitted", "resolved", "not_applicable"}
TRACKS = {"K", "U"}
COVERAGE_VERDICT = {"growing", "plateaued", "unknown"}
ROUND_DECISION = {"continue", "stop"}

# Phases that may run concurrently once `build` is done (AGENTS.md).
PARALLEL_AFTER_BUILD = {"describe", "seeds", "harness"}

DEFAULT_PHASE = {"status": "pending", "updated": None, "notes": ""}
DEFAULT_CRASH = {"track": "K", "title": "", "stack_hash": "",
                 "status": "unique", "dir": "", "repro_rate": None,
                 "duplicate_of": None, "disclosure": "pending", "notes": ""}
DEFAULT_ROUND = {"round": 1, "status": "in_progress", "started": None,
                 "ended": None, "run_ids": [], "coverage_verdict": "unknown",
                 "edges_start": None, "edges_end": None, "new_crashes": 0,
                 "run_hours": 0.0, "decision": None, "decision_reason": "",
                 "notes": ""}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_state():
    return {
        "version": SCHEMA_VERSION,
        "phases": {p: dict(DEFAULT_PHASE) for p in PHASES},
        "crashes": {},
        "campaigns": [],
        "rounds": [dict(DEFAULT_ROUND, round=1, started=_now())],
        "manifest": "artifacts/builds/manifest.json",
    }


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
    out["phases"] = {p: dict(DEFAULT_PHASE, **(phases.get(p) or {}))
                     for p in PHASES}
    crashes = out.get("crashes") or {}
    if not isinstance(crashes, dict):
        raise ValueError("pipeline state 'crashes' must be an object")
    out["crashes"] = {cid: dict(DEFAULT_CRASH, **(c or {}))
                      for cid, c in crashes.items()}
    if not isinstance(out.get("campaigns"), list):
        out["campaigns"] = []
    # v1 -> v2: pre-loop state files have no rounds; treat their work as round 1.
    rounds = out.get("rounds")
    if not isinstance(rounds, list) or not rounds:
        rounds = [dict(DEFAULT_ROUND, round=1, started=_now())]
    out["rounds"] = [dict(DEFAULT_ROUND, **(r or {})) for r in rounds]
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


def save(state, path=None):
    """Atomic, panic-durable write."""
    path = path or STATE_PATH
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
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


def _lock_path(path):
    return os.path.join(os.path.dirname(path), ".pipeline.lock")


@contextmanager
def transaction(path=None):
    """Exclusive read-modify-write on the state file.

        with ps.transaction() as st:
            st["crashes"][cid]["status"] = "reliable"

    The state is saved on clean exit; an exception inside the block aborts
    the write, leaving the file untouched.
    """
    path = path or STATE_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
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


def update_phase(state, phase, status, notes=""):
    if phase not in PHASES:
        raise ValueError("unknown phase: %s (expected one of %s)"
                         % (phase, ", ".join(PHASES)))
    if status not in PHASE_STATUS:
        raise ValueError("unknown phase status: %s (expected one of %s)"
                         % (status, ", ".join(sorted(PHASE_STATUS))))
    prev = state["phases"].get(phase, DEFAULT_PHASE)
    state["phases"][phase] = {
        "status": status,
        "updated": _now(),
        "notes": notes if notes else prev.get("notes", ""),
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
              edges_end=None, run_hours=None, notes=None):
    """Record the measured outcome of the current round."""
    r = current_round(state)
    if verdict is not None:
        if verdict not in COVERAGE_VERDICT:
            raise ValueError("unknown coverage verdict: %s (expected one of "
                             "%s)" % (verdict, ", ".join(sorted(
                                 COVERAGE_VERDICT))))
        r["coverage_verdict"] = verdict
    for key, val in (("new_crashes", new_crashes), ("edges_start", edges_start),
                     ("edges_end", edges_end), ("run_hours", run_hours),
                     ("notes", notes)):
        if val is not None:
            r[key] = val
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


def loop_decision(state, max_rounds, max_total_run_hours=None,
                  stop_on_plateau=True):
    """Apply the configured caps to the current round -> (decision, reason).

    Caps are checked before the coverage verdict: a plateau is a reason to
    stop, but so is running out of the budget the user authorised, and the
    budget must win even while coverage is still growing.
    """
    r = current_round(state)
    if r["round"] >= max_rounds:
        return ("stop", "round cap reached (%d of %d)"
                % (r["round"], max_rounds))
    if max_total_run_hours is not None:
        spent = total_run_hours(state)
        if spent >= max_total_run_hours:
            return ("stop", "run-hour budget spent (%.1f of %.1f h)"
                    % (spent, max_total_run_hours))
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
    for p in ROUND_PHASES:
        state["phases"][p] = dict(DEFAULT_PHASE)
    state["rounds"].append(dict(DEFAULT_ROUND, round=r["round"] + 1,
                                started=_now()))
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


def validate(state):
    """Return a list of human-readable integrity problems (empty == clean)."""
    problems = []
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
        rate = c.get("repro_rate")
        if rate is not None and not (isinstance(rate, (int, float))
                                     and 0.0 <= rate <= 1.0):
            problems.append("%s has out-of-range repro_rate %r" % (cid, rate))
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
