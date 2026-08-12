"""Shared pipeline.json state helpers. Stdlib only; imported by other tools."""
import json
import os
import tempfile
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_PATH = os.path.join(REPO_ROOT, "state", "pipeline.json")

PHASES = ["provision", "build", "describe", "seeds", "harness", "fuzz",
          "triage", "rca", "poc", "eval", "report"]
PHASE_STATUS = {"pending", "in_progress", "done", "blocked", "failed"}
CRASH_STATUS = {"unique", "duplicate", "flagged", "reliable", "flaky",
                "unreproducible", "rca_done", "reported"}


def default_state():
    return {
        "version": 1,
        "phases": {p: {"status": "pending", "updated": None, "notes": ""}
                   for p in PHASES},
        "crashes": {},
        "campaigns": [],
        "manifest": "artifacts/builds/manifest.json",
    }


def load(path=STATE_PATH):
    if not os.path.exists(path):
        return default_state()
    with open(path) as f:
        return json.load(f)


def save(state, path=STATE_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def update_phase(state, phase, status, notes=""):
    if phase not in PHASES:
        raise ValueError(f"unknown phase: {phase}")
    if status not in PHASE_STATUS:
        raise ValueError(f"unknown phase status: {status}")
    state["phases"][phase] = {"status": status, "updated": _now(), "notes": notes}


def next_crash_id(state):
    n = len(state["crashes"]) + 1
    while f"crash-{n:04d}" in state["crashes"]:
        n += 1
    return f"crash-{n:04d}"


def register_crash(state, crash):
    """crash dict keys: track(K|U), title, stack_hash, status, dir,
    repro_rate(None), duplicate_of(None), disclosure('pending')."""
    if crash.get("status") not in CRASH_STATUS:
        raise ValueError(f"unknown crash status: {crash.get('status')}")
    cid = next_crash_id(state)
    state["crashes"][cid] = crash
    return cid
