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

SCHEMA_VERSION = 1

PHASES = ["provision", "build", "describe", "seeds", "harness", "fuzz",
          "triage", "rca", "poc", "eval", "report"]
PHASE_STATUS = {"pending", "in_progress", "done", "blocked", "failed"}
CRASH_STATUS = {"unique", "duplicate", "flagged", "reliable", "flaky",
                "unreproducible", "rca_done", "reported"}
DISCLOSURE_STATUS = {"pending", "submitted", "resolved", "not_applicable"}
TRACKS = {"K", "U"}

# Phases that may run concurrently once `build` is done (AGENTS.md).
PARALLEL_AFTER_BUILD = {"describe", "seeds", "harness"}

DEFAULT_PHASE = {"status": "pending", "updated": None, "notes": ""}
DEFAULT_CRASH = {"track": "K", "title": "", "stack_hash": "",
                 "status": "unique", "dir": "", "repro_rate": None,
                 "duplicate_of": None, "disclosure": "pending", "notes": ""}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_state():
    return {
        "version": SCHEMA_VERSION,
        "phases": {p: dict(DEFAULT_PHASE) for p in PHASES},
        "crashes": {},
        "campaigns": [],
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
    return problems
