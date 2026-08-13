#!/usr/bin/env python3
"""Drive state/pipeline.json — the pipeline state machine.

This is how the orchestrator and phase agents record progress. Nothing should
hand-edit pipeline.json: every write here is atomic, locked, and validated.

Subcommands:
  init [--force]                 create state/pipeline.json (idempotent)
  show [--json]                  phase table + crash summary
  next                           print the first phase not marked done
  set-phase <phase> <status> [--notes TEXT]
                                 status: pending|in_progress|done|blocked|failed
  crash-list [--status S] [--track K|U] [--json]
  crash-set <id> [--status S] [--duplicate-of ID|none] [--disclosure S]
            [--repro-rate F] [--notes TEXT]
  campaign-add --track k|u --note TEXT
  validate                       check integrity; exit 1 if problems found

Exit codes: 0 ok, 1 problem/not-found, 2 usage error.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_state as ps

STATUS_MARK = {"done": "+", "in_progress": ">", "blocked": "!",
               "failed": "!", "pending": "."}


def cmd_init(a):
    if os.path.exists(ps.STATE_PATH) and not a.force:
        st = ps.load()
        print("%s already exists (%d crashes, next phase: %s). "
              "Use --force to reset."
              % (ps.STATE_PATH, len(st["crashes"]),
                 ps.next_phase(st) or "complete"))
        return 0
    ps.save(ps.default_state())
    print("initialized " + ps.STATE_PATH)
    return 0


def cmd_show(a):
    st = ps.load()
    if a.json:
        json.dump(st, sys.stdout, indent=2, sort_keys=True)
        print()
        return 0
    print("pipeline: %s" % ps.STATE_PATH)
    for p in ps.PHASES:
        ph = st["phases"][p]
        line = "  %s %-10s %-12s" % (STATUS_MARK.get(ph["status"], "?"), p,
                                     ph["status"])
        if ph["updated"]:
            line += " %s" % ph["updated"]
        if ph["notes"]:
            line += "  %s" % ph["notes"]
        print(line)
    nxt = ps.next_phase(st)
    print("next phase: %s" % (nxt or "complete — all phases done"))
    crashes = st["crashes"]
    if crashes:
        by_status = {}
        for c in crashes.values():
            by_status[c["status"]] = by_status.get(c["status"], 0) + 1
        print("crashes: %d total (%s)"
              % (len(crashes),
                 ", ".join("%s=%d" % kv for kv in sorted(by_status.items()))))
    else:
        print("crashes: none registered")
    problems = ps.validate(st)
    if problems:
        print("INTEGRITY: %d problem(s) — run: pipeline_ctl.py validate"
              % len(problems))
    return 0


def cmd_next(a):
    nxt = ps.next_phase(ps.load())
    print(nxt or "complete")
    return 0


def cmd_set_phase(a):
    with ps.transaction() as st:
        try:
            ps.update_phase(st, a.phase, a.status, a.notes or "")
        except ValueError as e:
            sys.exit("error: %s" % e)
    print("%s -> %s" % (a.phase, a.status))
    return 0


def cmd_crash_list(a):
    st = ps.load()
    rows = []
    for cid in sorted(st["crashes"]):
        c = st["crashes"][cid]
        if a.status and c["status"] != a.status:
            continue
        if a.track and c["track"] != a.track:
            continue
        rows.append((cid, c))
    if a.json:
        json.dump({cid: c for cid, c in rows}, sys.stdout, indent=2,
                  sort_keys=True)
        print()
        return 0
    if not rows:
        print("no crashes match")
        return 0
    for cid, c in rows:
        rate = "" if c["repro_rate"] is None else " %.0f%%" % (
            c["repro_rate"] * 100)
        dup = " dup_of=%s" % c["duplicate_of"] if c["duplicate_of"] else ""
        print("%s [%s] %-14s%s%s  %s"
              % (cid, c["track"], c["status"], rate, dup, c["title"][:70]))
    return 0


def cmd_crash_set(a):
    with ps.transaction() as st:
        if a.crash_id not in st["crashes"]:
            sys.exit("error: unknown crash id: %s" % a.crash_id)
        c = st["crashes"][a.crash_id]
        if a.status:
            if a.status not in ps.CRASH_STATUS:
                sys.exit("error: unknown crash status: %s (expected one of %s)"
                         % (a.status, ", ".join(sorted(ps.CRASH_STATUS))))
            c["status"] = a.status
        if a.duplicate_of is not None:
            if a.duplicate_of.lower() in ("none", ""):
                c["duplicate_of"] = None
            else:
                if a.duplicate_of == a.crash_id:
                    sys.exit("error: a crash cannot duplicate itself")
                if a.duplicate_of not in st["crashes"]:
                    sys.exit("error: unknown crash id: %s" % a.duplicate_of)
                c["duplicate_of"] = a.duplicate_of
                c["status"] = "duplicate"
        if a.disclosure:
            if a.disclosure not in ps.DISCLOSURE_STATUS:
                sys.exit("error: unknown disclosure status: %s (expected one "
                         "of %s)" % (a.disclosure,
                                     ", ".join(sorted(ps.DISCLOSURE_STATUS))))
            c["disclosure"] = a.disclosure
        if a.repro_rate is not None:
            if not 0.0 <= a.repro_rate <= 1.0:
                sys.exit("error: --repro-rate must be between 0.0 and 1.0")
            c["repro_rate"] = a.repro_rate
        if a.notes:
            c["notes"] = a.notes
        summary = "%s: status=%s disclosure=%s" % (a.crash_id, c["status"],
                                                   c["disclosure"])
    print(summary)
    return 0


def cmd_campaign_add(a):
    with ps.transaction() as st:
        st["campaigns"].append({"track": a.track, "action": "record",
                                "note": a.note, "at": ps._now()})
        n = len(st["campaigns"])
    print("recorded campaign entry #%d (track %s)" % (n, a.track))
    return 0


def cmd_validate(a):
    problems = ps.validate(ps.load())
    if not problems:
        print("state is consistent")
        return 0
    for p in problems:
        print("PROBLEM: " + p)
    return 1


def build_parser():
    ap = argparse.ArgumentParser(
        prog="pipeline_ctl.py",
        description="Drive state/pipeline.json (the pipeline state machine).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create state/pipeline.json")
    p.add_argument("--force", action="store_true",
                   help="overwrite an existing state file")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("show", help="phase table + crash summary")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("next", help="first phase not marked done")
    p.set_defaults(fn=cmd_next)

    p = sub.add_parser("set-phase", help="set a phase status")
    p.add_argument("phase", choices=ps.PHASES)
    p.add_argument("status", choices=sorted(ps.PHASE_STATUS))
    p.add_argument("--notes", default="")
    p.set_defaults(fn=cmd_set_phase)

    p = sub.add_parser("crash-list", help="list registered crashes")
    p.add_argument("--status")
    p.add_argument("--track", choices=sorted(ps.TRACKS))
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_crash_list)

    p = sub.add_parser("crash-set", help="update a crash registry entry")
    p.add_argument("crash_id")
    p.add_argument("--status")
    p.add_argument("--duplicate-of", dest="duplicate_of",
                   help="crash id, or 'none' to clear")
    p.add_argument("--disclosure")
    p.add_argument("--repro-rate", dest="repro_rate", type=float)
    p.add_argument("--notes")
    p.set_defaults(fn=cmd_crash_set)

    p = sub.add_parser("campaign-add", help="record a campaign event")
    p.add_argument("--track", required=True, choices=["k", "u"])
    p.add_argument("--note", required=True)
    p.set_defaults(fn=cmd_campaign_add)

    p = sub.add_parser("validate", help="check state integrity")
    p.set_defaults(fn=cmd_validate)
    return ap


def main():
    a = build_parser().parse_args()
    try:
        sys.exit(a.fn(a))
    except ValueError as e:
        sys.exit("error: %s" % e)


if __name__ == "__main__":
    main()
