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
import gspwn_config
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
    cfg = _loop_cfg()
    print("pipeline: %s" % ps.STATE_PATH)
    print("round %d of max %d (%.1f run-hours of %s used)"
          % (ps.round_number(st), cfg["max_rounds"], ps.total_run_hours(st),
             cfg["max_total_run_hours"]))
    for p in ps.PHASES:
        ph = st["phases"][p]
        line = "  %s %-10s %-12s" % (STATUS_MARK.get(ph["status"], "?"), p,
                                     ph["status"])
        if ph["updated"]:
            line += " %s" % ph["updated"]
        if ph["notes"]:
            line += "  %s" % ph["notes"]
        print(line)
    kind, val = ps.next_action(st)
    print("next: %s" % {"phase": lambda: "run phase %s" % val,
                        "decide": lambda: "round-decide (round phases done)",
                        "advance-round": lambda: "round-advance",
                        "done": lambda: "complete — all phases done"}[kind]())
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


def _loop_cfg():
    """Loop caps from config/campaign.yaml (validated, defaults applied).

    A bad cap stops the pipeline rather than falling back to a default: this
    loop spends money unattended, so 'the config was wrong and we guessed' is
    not an acceptable outcome.
    """
    try:
        return gspwn_config.loop()
    except gspwn_config.ConfigError as e:
        sys.exit("error: %s" % e)


def cmd_next(a):
    st = ps.load()
    kind, val = ps.next_action(st)
    if kind == "phase":
        print(val)
    elif kind == "decide":
        print("decide  (round %d phases are done — run: pipeline_ctl.py "
              "round-decide)" % ps.round_number(st))
    elif kind == "advance-round":
        print("advance-round  (run: pipeline_ctl.py round-advance)")
    else:
        print("complete")
    return 0


def cmd_round_show(a):
    st = ps.load()
    cfg = _loop_cfg()
    if a.json:
        json.dump(st["rounds"], sys.stdout, indent=2, sort_keys=True)
        print()
        return 0
    print("rounds: %d of max %d   run-hours: %.1f of %s"
          % (ps.round_number(st), cfg["max_rounds"], ps.total_run_hours(st),
             cfg["max_total_run_hours"]))
    for r in st["rounds"]:
        edges = ""
        if r["edges_start"] is not None and r["edges_end"] is not None:
            edges = "  edges %s->%s" % (r["edges_start"], r["edges_end"])
        print("  round %-3d %-10s %-10s crashes=%-4s run_h=%-6.1f%s"
              % (r["round"], r["status"], r["coverage_verdict"],
                 r["new_crashes"], r["run_hours"] or 0.0, edges))
        if r["decision"]:
            print("            decision: %s — %s"
                  % (r["decision"], r["decision_reason"]))
        if r["run_ids"]:
            print("            runs: %s" % ", ".join(r["run_ids"]))
        if r.get("worklist_in"):
            print("            executing: %s" % r["worklist_in"])
        if r.get("worklist"):
            print("            produced:  %s" % r["worklist"])
    return 0


def _derive_round(st, run_id, cfg):
    """Measure this round's outcome from the recorded curve and the registry.

    These four numbers decide whether the loop spends another campaign, and
    run_hours is the spend ceiling itself. Typing them in by hand puts a
    transcription step in front of a budget: the sampler already wrote every
    one of them to artifacts/runs/<id>/coverage.csv, so read them from there.
    """
    import coverage_ctl
    verdict, detail, _per = coverage_ctl.run_verdict(
        run_id, cfg["plateau_window_min"], cfg["plateau_min_growth"])
    out = {"coverage_verdict": verdict, "notes": "run %s: %s" % (run_id, detail)}
    # Edge totals are reported for Track K, the instrumented-kernel number the
    # paper cites; Track U's per-harness bitmaps are not comparable to it.
    rows = coverage_ctl.metric_rows(run_id, "edges", "k")
    if rows:
        # Peak, not the last sample: a fuzzer restart zeroes the counter, and
        # recording edges_end below edges_start would show the round losing
        # coverage in the history the paper's progression table cites.
        out["edges_start"] = rows[0]["edges"]
        out["edges_end"] = max(r["edges"] for r in rows)
    # Wall-clock of the campaign, from the first to the last sample on any
    # track — a run that died after 3 h must not bill the configured 24.
    stamps = [r["ts"] for t in coverage_ctl.TRACKS
              for r in coverage_ctl.read_rows(run_id, t) if r.get("ts")]
    if len(stamps) > 1:
        out["run_hours"] = round((max(stamps) - min(stamps)) / 3600.0, 2)
    # Crashes registered since the previous rounds accounted for theirs.
    counted = sum(r.get("new_crashes") or 0 for r in st["rounds"][:-1])
    out["new_crashes"] = max(len(st["crashes"]) - counted, 0)
    return out


def cmd_round_end(a):
    explicit = {"coverage_verdict": a.coverage_verdict,
                "new_crashes": a.new_crashes, "edges_start": a.edges_start,
                "edges_end": a.edges_end, "run_hours": a.run_hours,
                "notes": a.notes, "worklist": a.worklist}
    with ps.transaction() as st:
        vals = dict(explicit)
        if a.from_run:
            derived = _derive_round(st, a.from_run, _loop_cfg())
            # An explicit flag still wins, so a measurement can be overridden
            # when the operator knows better — but never silently.
            for k, v in derived.items():
                if vals.get(k) is None:
                    vals[k] = v
        try:
            r = ps.end_round(st, verdict=vals["coverage_verdict"],
                             new_crashes=vals["new_crashes"],
                             edges_start=vals["edges_start"],
                             edges_end=vals["edges_end"],
                             run_hours=vals["run_hours"], notes=vals["notes"],
                             worklist=vals["worklist"])
        except ValueError as e:
            sys.exit("error: %s" % e)
        summary = "round %d closed: %s, crashes=%s, run_h=%s" % (
            r["round"], r["coverage_verdict"], r["new_crashes"],
            r["run_hours"])
        note = r["notes"]
    print(summary)
    if a.from_run:
        print("  measured from run %s: %s" % (a.from_run, note))
    return 0


def cmd_worklist(a):
    """Print the worklist this round's describe/seeds agents must execute."""
    st = ps.load()
    r = ps.current_round(st)
    path = r.get("worklist_in")
    if not path:
        print("none — round %d has no inherited worklist (first round, or the "
              "previous round's refine recorded none)" % r["round"])
        return 1
    full = path if os.path.isabs(path) else os.path.join(ps.REPO_ROOT, path)
    if not os.path.exists(full):
        print("%s (MISSING — refine recorded it but the file is not there)"
              % path)
        return 1
    print(path)
    return 0


def cmd_round_add_run(a):
    with ps.transaction() as st:
        r = ps.current_round(st)
        if a.run_id not in r["run_ids"]:
            r["run_ids"].append(a.run_id)
        rnd, n = r["round"], len(r["run_ids"])
    print("round %d now has %d run(s); added %s" % (rnd, n, a.run_id))
    return 0


def cmd_round_decide(a):
    cfg = _loop_cfg()
    with ps.transaction() as st:
        if a.decision:
            decision, reason = a.decision, (a.reason or "set explicitly")
        else:
            decision, reason = ps.loop_decision(
                st, max_rounds=cfg["max_rounds"],
                max_total_run_hours=cfg["max_total_run_hours"],
                stop_on_plateau=cfg["stop_on_plateau"])
        try:
            ps.record_decision(st, decision, reason)
        except ValueError as e:
            sys.exit("error: %s" % e)
        rnd = ps.round_number(st)
    print("round %d: %s — %s" % (rnd, decision, reason))
    print("next: %s" % ("pipeline_ctl.py round-advance"
                        if decision == "continue" else "run the report phase"))
    return 0


def cmd_round_advance(a):
    with ps.transaction() as st:
        try:
            r = ps.advance_round(st)
        except ValueError as e:
            sys.exit("error: %s" % e)
        n = r["round"]
    print("opened round %d; round phases reset to pending (setup and crash "
          "registry kept)" % n)
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
                # Clearing the link has to clear the verdict too, or the crash
                # keeps status=duplicate with nothing to duplicate and stays
                # excluded from the unique/RCA queue forever. An explicit
                # --status in the same command still wins.
                if c["status"] == "duplicate" and not a.status:
                    c["status"] = "unique"
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
    p.add_argument("--status", choices=sorted(ps.CRASH_STATUS))
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

    p = sub.add_parser("round-show", help="round history and loop budget")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_round_show)

    p = sub.add_parser("round-add-run", help="attach a run id to this round")
    p.add_argument("--run-id", required=True, dest="run_id")
    p.set_defaults(fn=cmd_round_add_run)

    p = sub.add_parser("round-end", help="record this round's measured outcome")
    p.add_argument("--from-run", dest="from_run",
                   help="measure verdict/edges/run-hours/crashes from this "
                        "run's coverage.csv instead of passing them by hand")
    p.add_argument("--coverage-verdict", dest="coverage_verdict",
                   choices=sorted(ps.COVERAGE_VERDICT),
                   help="from: coverage_ctl.py plateau --run-id ID")
    p.add_argument("--new-crashes", dest="new_crashes", type=int)
    p.add_argument("--edges-start", dest="edges_start", type=int)
    p.add_argument("--edges-end", dest="edges_end", type=int)
    p.add_argument("--run-hours", dest="run_hours", type=float)
    p.add_argument("--notes")
    p.add_argument("--worklist",
                   help="path to this round's worklist.md; the next round's "
                        "describe/seeds agents read it via `worklist`")
    p.set_defaults(fn=cmd_round_end)

    p = sub.add_parser("worklist",
                       help="print the worklist this round must execute")
    p.set_defaults(fn=cmd_worklist)

    p = sub.add_parser("round-decide",
                       help="apply the configured loop caps -> continue|stop")
    p.add_argument("--decision", choices=sorted(ps.ROUND_DECISION),
                   help="override the computed decision (states the reason)")
    p.add_argument("--reason", default="")
    p.set_defaults(fn=cmd_round_decide)

    p = sub.add_parser("round-advance", help="open the next round")
    p.set_defaults(fn=cmd_round_advance)

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
