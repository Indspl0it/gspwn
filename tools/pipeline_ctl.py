#!/usr/bin/env python3
"""Drive state/pipeline.json — the pipeline state machine.

This is how the orchestrator and phase agents record progress. Nothing should
hand-edit pipeline.json: every write here is atomic, locked, and validated.

Subcommands:
  init [--force]                 create state/pipeline.json (idempotent)
  show [--json]                  phase table + crash summary
  next                           print the first phase not marked done
  brief [--last N]               derived handoff for a fresh or compacted
                                 session: position, crashes, findings, and the
                                 tail of knowledge/
  set-phase <phase> <status> [--notes TEXT]
                                 status: pending|in_progress|done|blocked|failed
  crash-list [--status S] [--track K|U] [--json]
  crash-set <id> [<id> ...] [--status S] [--duplicate-of ID|none]
            [--disclosure S] [--repro-rate F] [--notes TEXT]
                                 several ids apply the same edit to each, for
                                 working a flagged queue down in one call
  finding-set <id> --json PATH|-  attach rca's research record to a crash
  finding-list [--subsystem S] [--bug-class C] [--json]
                                 the records refine and describe steer from
  impact-set <id> --json PATH|-   attach rca's impact record: what the fault
                                 gives an attacker, which is what lets the
                                 report argue a severity rather than assert one
  impact-list [--primitive P] [--consequence C] [--json]
                                 the impact records, with the CWE rollup and
                                 the count that can carry a severity
  surface-account --json PATH|-   record why one command-surface target will
                                 not be exercised. Completion is exercised
                                 plus accounted-for equal to the whole
                                 denominator, so every target the campaign
                                 will not reach needs a written reason here
  surface-unaccount --variant NAME | --key KEY
                                 remove one accounted row, reopening its
                                 target. The way out of a reason written in
                                 error, including one the completion stop is
                                 now resting on
  surface-ledger [--json]        the accounted targets, grouped by reason
  campaign-add --track k|u --note TEXT
  round-show [--json]            round history + loop budget
  round-add-run --run-id ID      attach a campaign run to the current round
  round-end --from-run ID [--from-run ID ...] [--worklist PATH] [--force]
                                 measure this round's outcome from each run's
                                 coverage.csv and record it (one call per run,
                                 or several runs in one call; hours accumulate).
                                 Refuses while a run's campaign window is still
                                 open — measuring a live campaign gets every
                                 column wrong at once
  worklist                       print the worklist this round must execute
  round-decide [--decision continue|stop] [--reason TEXT]
                                 apply the configured loop caps; an explicit
                                 continue cannot override a completion, budget
                                 or round-cap stop, and overriding a
                                 plateau/unknown stop requires --reason
  round-advance                  open the next round (requires all round
                                 phases done and a recorded round-end)
  validate                       check integrity; exit 1 if problems found

Exit codes: 0 ok, 1 problem/not-found, 2 usage error.
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gspwn_config
import pipeline_state as ps

STATUS_MARK = {"done": "+", "in_progress": ">", "blocked": "!",
               "failed": "!", "pending": "."}


def _repo_rel(path):
    """Repo-relative when it is inside the repo, absolute otherwise.

    A redirected GSPWN_STATE lives outside the tree, where relpath produces a
    run of '..' segments that is longer and less useful than the real path.
    """
    rel = os.path.relpath(path, ps.REPO_ROOT)
    return path if rel.startswith("..") else rel


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
          % (ps.round_number(st), cfg["max_rounds"], ps.spent_hours(st),
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
    kind, val = _next_action(st)
    print("next: %s" % {"phase": lambda: "run phase %s" % val,
                        "wait": lambda: _wait_line(*val),
                        "decide": lambda: "round-decide (round phases done)",
                        "advance-round": lambda: "round-advance",
                        "done": lambda: "complete: all phases done"}[kind]())
    crashes = st["crashes"]
    if crashes:
        by_status = {}
        for c in crashes.values():
            by_status[c["status"]] = by_status.get(c["status"], 0) + 1
        print("crashes: %d total (%s)"
              % (len(crashes),
                 ", ".join("%s=%d" % kv for kv in sorted(by_status.items()))))
        _print_noise_line(crashes)
    else:
        print("crashes: none registered")
    problems = ps.validate(st, _triage_cfg())
    if problems:
        print("INTEGRITY: %d problem(s). Run: pipeline_ctl.py validate"
              % len(problems))
    return 0


def _print_noise_line(crashes):
    """Say how many registered entries are the fuzzer's own exhaust.

    They stay in the registry as an audit trail but are not findings, so the
    headline count has to say how much of it they are. Without the line a
    reader sees "crashes: 412" and has no way to tell it is mostly Xid 13.
    """
    noise = sum(1 for c in crashes.values() if c.get("signal") == "noise")
    if noise:
        print("  of these %d are noise Xids (the fuzzer causes them by "
              "design, and they are not counted as findings)" % noise)


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


def _agent_cfg():
    """How much `brief` and `crash-list` put in front of the agent.

    Same rule as _loop_cfg: a broken config stops the tool rather than
    quietly reverting to a default, because the whole point of these keys is
    that an operator can tune what a resumed agent sees.
    """
    try:
        return gspwn_config.agent()
    except gspwn_config.ConfigError as e:
        sys.exit("error: %s" % e)


def _next_action(st):
    """ps.next_action, refusing to run ahead of a campaign still fuzzing.

    Returns the same (kind, value) pairs plus ("wait", (run_id, hours_left)).
    The fuzz phase itself is exempt: it is what starts the campaign.
    """
    kind, val = ps.next_action(st)
    if kind == "phase" and val == "fuzz":
        return kind, val
    if st["phases"]["fuzz"]["status"] != "done":
        return kind, val
    live = _live_runs(st)
    return ("wait", live[-1]) if live else (kind, val)


def _wait_line(run_id, left_h):
    return ("wait  (run %s has %.1f h left of its campaign window, and the "
            "round cannot be measured until it ends: python3 "
            "tools/campaign_ctl.py wait --run-id %s)" % (run_id, left_h, run_id))


def cmd_next(a):
    st = ps.load()
    kind, val = _next_action(st)
    if kind == "wait":
        print(_wait_line(*val))
        return 0
    if kind == "phase":
        print(val)
    elif kind == "decide":
        print("decide  (round %d phases are done. Run: pipeline_ctl.py "
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
          % (ps.round_number(st), cfg["max_rounds"], ps.spent_hours(st),
             cfg["max_total_run_hours"]))
    for r in st["rounds"]:
        edges = ""
        if r["edges_start"] is not None and r["edges_end"] is not None:
            edges = "  edges %s->%s" % (r["edges_start"], r["edges_end"])
        print("  round %-3d %-10s %-10s crashes=%-4s run_h=%-6.1f%s"
              % (r["round"], r["status"], r["coverage_verdict"],
                 r["new_crashes"], r["run_hours"] or 0.0, edges))
        if r.get("surface_total"):
            print("            surface:  %s (%s exercised + %s accounted of "
                  "%s)%s" % (r.get("surface_verdict"),
                             r.get("surface_exercised"),
                             r.get("surface_accounted"), r.get("surface_total"),
                             ", %s deferred and still open"
                             % r["surface_deferred"]
                             if r.get("surface_deferred") else ""))
        if r["decision"]:
            print("            decision: %s (%s)"
                  % (r["decision"], r["decision_reason"]))
        if r["run_ids"]:
            print("            runs: %s" % ", ".join(r["run_ids"]))
        if r.get("worklist_in"):
            print("            executing: %s" % r["worklist_in"])
        if r.get("worklist"):
            print("            produced:  %s" % r["worklist"])
        if r.get("surface_ledger"):
            print("            ledger:    %s" % r["surface_ledger"])
    return 0


def _derive_run(run_id, cfg):
    """Measure one run's outcome from its own coverage.csv.

    These numbers decide whether the loop spends another campaign, and
    run_hours is the spend ceiling itself. Typing them in by hand puts a
    transcription step in front of a budget: the sampler already wrote every
    one of them to artifacts/runs/<id>/coverage.csv, so read them from there.
    Each run is measured independently — a round's several campaigns never
    share a single measurement.
    """
    import coverage_ctl
    verdict, detail, _per = coverage_ctl.run_verdict(
        run_id, cfg["plateau_window_min"], cfg["plateau_min_growth"])
    out = {"run_id": run_id, "coverage_verdict": verdict, "detail": detail,
           "run_hours": None}
    # Edge totals are reported for Track K, the instrumented-kernel number
    # the report cites; Track U's per-harness bitmaps are not comparable.
    rows = coverage_ctl.metric_rows(run_id, "edges", "k")
    if rows:
        # Peak, not the last sample: a fuzzer restart zeroes the counter, and
        # recording edges_end below edges_start would show the round losing
        # coverage in the per-round history the report is built from.
        out["edges_start"] = rows[0]["edges"]
        out["edges_end"] = max(r["edges"] for r in rows)
    # Wall-clock of the campaign, from the first to the last sample on any
    # track — a run that died after 3 h must not bill the configured 24.
    stamps = [r["ts"] for t in coverage_ctl.TRACKS
              for r in coverage_ctl.read_rows(run_id, t) if r.get("ts")]
    if len(stamps) > 1:
        out["run_hours"] = round((max(stamps) - min(stamps)) / 3600.0, 2)
    return out


def _is_finding(c):
    """Does this registry entry count as a bug the campaign found?

    Three things are registered but are not findings:
    duplicates (the same bug sighted twice), still-unresolved flagged
    collisions (nobody has decided yet whether they are one bug or two), and
    Xids the fuzzer produces by design. A campaign that reports its own
    exhaust as findings has reported noise, which is exactly what the Xid
    classification exists to prevent — it was just never applied here, so
    every `new_crashes` figure carried it.

    Post-triage statuses (reliable, flaky, rca_done, ...) started life as
    unique findings, so they count.
    """
    return (c.get("status") not in ("duplicate", "flagged")
            and c.get("signal") != "noise")


def _derived_new_crashes(st):
    """Crashes registered since the previous rounds accounted for theirs."""
    findings = sum(1 for c in st["crashes"].values() if _is_finding(c))
    counted = sum(r.get("new_crashes") or 0 for r in st["rounds"][:-1])
    return max(findings - counted, 0)


def _live_runs(st):
    """-> [(run_id, hours_left)] for this round's campaigns still inside their
    window, newest deadline last.

    The fuzz phase's gate used to be the smoke window, so the pipeline
    advanced roughly half an hour into a 24-hour campaign: triage scanned a
    workdir holding almost nothing, every later gate was trivially satisfied,
    and round-end measured a curve three samples long while the campaign kept
    running behind it with nobody reading its output. Everything downstream
    inherited that — the plateau verdict, the edge counts, the billed hours
    and the crash counts the report is built from.
    """
    import campaign_ctl
    out = []
    now = time.time()
    for rid in ps.current_round(st).get("run_ids") or []:
        at = campaign_ctl.read_deadline(rid)
        if at is not None and at > now:
            out.append((rid, (at - now) / 3600.0))
    return sorted(out, key=lambda p: p[1])


def cmd_round_end(a):
    from_runs = a.from_run
    if isinstance(from_runs, str):
        from_runs = [from_runs]      # tolerate a scalar from programmatic callers
    if not from_runs:
        sys.exit("error: round-end needs at least one --from-run to measure "
                 "(pass one per campaign this round, and hours accumulate)")
    # Measuring a campaign that is still running is the wrong number in every
    # column at once: the curve stops where the sampler happens to be, the
    # billed hours are the elapsed ones rather than the campaign's, and the
    # crash count is whatever had landed by then. Refusing is cheap; the
    # measurement it prevents is what the whole round is for.
    import campaign_ctl
    import coverage_ctl
    now = time.time()
    still_live = [(rid, (campaign_ctl.read_deadline(rid) - now) / 3600.0)
                  for rid in from_runs
                  if campaign_ctl.read_deadline(rid) is not None
                  and campaign_ctl.read_deadline(rid) > now]
    if still_live and not a.force:
        sys.exit("error: refusing to measure a live campaign: %s. The curve, "
                 "the billed hours and the crash count would all describe the "
                 "part of the run that happened to be over. Wait it out with "
                 "`python3 tools/campaign_ctl.py wait --run-id <id>`, or pass "
                 "--force if the campaign really is finished and only its "
                 "deadline file is stale."
                 % "; ".join("run %s has %.1f h left" % (r, h)
                             for r, h in still_live))
    explicit = {"coverage_verdict": a.coverage_verdict,
                "new_crashes": a.new_crashes, "edges_start": a.edges_start,
                "edges_end": a.edges_end, "run_hours": a.run_hours,
                "notes": a.notes, "worklist": a.worklist}
    # The completion reading, measured from the runs' own corpora rather than
    # the seed bank, so it does not depend on corpus_ctl.py promote having run
    # first. It decides the primary stop, so it is recorded on every round-end
    # and never carried over: an unmeasurable one lands as "unknown", which
    # stops the loop rather than ending it.
    #
    # Taken before the transaction opens. It unpacks and rescans one corpus
    # per run, each bounded at coverage.unpack_timeout_sec, and the
    # transaction holds the exclusive flock on the state file that every other
    # pipeline_ctl and campaign_ctl command waits on. What it costs is a
    # reading of a state one instant older, against several minutes of every
    # other command blocking.
    #
    # --ledger names which ledger this round accounts against and pins the
    # round's pointer to it. Without it the pointer the round already carries
    # wins, and a round that has been ended once cannot be re-pointed at all.
    ledger = (getattr(a, "ledger", None)
              or ps.current_round(ps.load()).get("surface_ledger"))
    completion = coverage_ctl.completion_status(run_ids=from_runs,
                                                ledger_path=ledger)
    ledger_rel = _repo_rel(ps.surface_ledger_path(ledger))
    with ps.transaction() as st:
        cfg = _loop_cfg()
        derived = [_derive_run(rid, cfg) for rid in from_runs]
        vals = dict(explicit)
        # Combined verdict: growing on any run means the round is still
        # learning — the same rule run_verdict applies across tracks.
        # Unknown unless at least one run produced a verdict, so a broken
        # sampler still stops the loop.
        verdicts = [d["coverage_verdict"] for d in derived]
        combined = ("growing" if "growing" in verdicts
                    else "plateaued" if "plateaued" in verdicts
                    else "unknown")
        if vals["coverage_verdict"] is None:
            vals["coverage_verdict"] = combined
        if vals["notes"] is None:
            vals["notes"] = "; ".join("run %s: %s" % (d["run_id"], d["detail"])
                                      for d in derived)
        # Edges: the first run's baseline plus every run's peak-over-start
        # gain (counters reset between campaigns, so raw peaks don't add).
        measured = [d for d in derived if "edges_start" in d]
        if measured:
            if vals["edges_start"] is None:
                vals["edges_start"] = measured[0]["edges_start"]
            if vals["edges_end"] is None:
                vals["edges_end"] = measured[0]["edges_start"] + sum(
                    max(0, d["edges_end"] - d["edges_start"]) for d in measured)
        if vals["new_crashes"] is None:
            vals["new_crashes"] = _derived_new_crashes(st)
        surface = {"verdict": completion["verdict"],
                   "exercised": completion["exercised"],
                   "accounted": completion["accounted"],
                   "deferred": completion["deferred"],
                   "closed": completion["closed"],
                   "total": completion["total"],
                   "ledger": ledger_rel}
        billed = {d["run_id"]: d["run_hours"] for d in derived
                  if d["run_hours"] is not None}
        unbilled = [d["run_id"] for d in derived if d["run_hours"] is None]
        try:
            r = ps.end_round(st, verdict=vals["coverage_verdict"],
                             new_crashes=vals["new_crashes"],
                             edges_start=vals["edges_start"],
                             edges_end=vals["edges_end"],
                             run_hours=vals["run_hours"], notes=vals["notes"],
                             worklist=vals["worklist"], billed=billed,
                             surface=surface)
        except ValueError as e:
            sys.exit("error: %s" % e)
        # Bill every derived run to the machine-global spend ledger — the
        # budget the loop checks against. Idempotent per run id, so a retried
        # round-end cannot double-count a campaign.
        for rid, hours in billed.items():
            ps.record_run_hours(rid, hours)
        # Hours entered by hand (--run-hours) belong to no single run, so they
        # bill under the round's own key. Without this they would raise the
        # round total while the budget kept reading the ledger and never saw
        # them. Recording the round's current unattributed total (not the
        # increment) keeps a repeated round-end idempotent.
        manual = round(r["run_hours"] - sum(
            (r.get("run_hours_by_run") or {}).values()), 2)
        if manual > 0:
            ps.record_run_hours("round-%d" % r["round"], manual)
        summary = "round %d closed: %s, crashes=%s, run_h=%s" % (
            r["round"], r["coverage_verdict"], r["new_crashes"],
            r["run_hours"])
    print(summary)
    for d in derived:
        print("  measured from run %s: %s" % (d["run_id"], d["detail"]))
    print("  surface %s: %s" % (completion["verdict"], completion["detail"]))
    if completion["verdict"] == "unknown":
        print("  WARNING: the completion reading failed, so the loop cannot "
              "stop on completion this round and will fall back to the "
              "plateau rule. Fix it with: python3 tools/coverage_ctl.py "
              "completion --run-id %s" % from_runs[0])
    if unbilled:
        print("  WARNING: run(s) %s had no usable coverage samples and billed "
              "0.0 h. Check the sampler, because unmeasured spend must not "
              "pass silently" % ", ".join(unbilled))
    return 0


def cmd_worklist(a):
    """Print the worklist this round's describe/seeds agents must execute."""
    st = ps.load()
    r = ps.current_round(st)
    path = r.get("worklist_in")
    if not path:
        print("none: round %d has no inherited worklist (first round, or the "
              "previous round's refine recorded none)" % r["round"])
        return 1
    full = path if os.path.isabs(path) else os.path.join(ps.REPO_ROOT, path)
    if not os.path.exists(full):
        print("%s (MISSING: refine recorded it but the file is not there)"
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
    print("round %d now has %d run(s) after adding %s" % (rnd, n, a.run_id))
    return 0


def cmd_round_decide(a):
    cfg = _loop_cfg()
    with ps.transaction() as st:
        computed, computed_reason = ps.loop_decision(
            st, max_rounds=cfg["max_rounds"],
            max_total_run_hours=cfg["max_total_run_hours"],
            stop_on_plateau=cfg["stop_on_plateau"])
        if a.decision:
            if a.decision == "continue" and computed == "stop":
                # Three stops sit behind hard_cap_reason. The budget and the
                # round cap are the spend ceiling and AGENTS.md forbids
                # overriding them. Completion says the work is done, and the
                # way past a wrong one is to correct the ledger it was
                # computed from, so the refusal names that route instead of
                # leaving the operator to hand edit the ledger file.
                hard = ps.hard_cap_reason(st, cfg["max_rounds"],
                                          cfg["max_total_run_hours"])
                if hard:
                    out = ("error: computed decision is stop (%s). A "
                           "completion, budget or round-cap stop cannot be "
                           "overridden" % hard)
                    if ps.surface_stop_reason(st):
                        out += (". The completion verdict is recomputed from "
                                "the ledger on every round-end, so a target "
                                "closed by a row that should not have been "
                                "written is reopened by removing the row "
                                "(pipeline_ctl.py surface-unaccount --variant "
                                "NAME) and running round-end again")
                    sys.exit(out)
                if not (a.reason or "").strip():
                    sys.exit("error: computed decision is stop (%s). "
                             "Overriding it requires --reason"
                             % computed_reason)
            decision, reason = a.decision, (a.reason or "set explicitly")
        else:
            decision, reason = computed, computed_reason
        try:
            ps.record_decision(st, decision, reason)
        except ValueError as e:
            sys.exit("error: %s" % e)
        rnd = ps.round_number(st)
    print("round %d: %s (%s)" % (rnd, decision, reason))
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
    print("opened round %d. Round phases reset to pending (setup and crash "
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
        if a.signal and c.get("signal", "unclassified") != a.signal:
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
    title_chars = _agent_cfg()["crash_title_chars"]
    for cid, c in rows:
        rate = "" if c["repro_rate"] is None else " %.0f%%" % (
            c["repro_rate"] * 100)
        dup = " dup_of=%s" % c["duplicate_of"] if c["duplicate_of"] else ""
        sig = c.get("signal", "unclassified")
        sig = "" if sig == "unclassified" else " <%s>" % sig
        print("%s [%s] %-14s%s%s%s  %s"
              % (cid, c["track"], c["status"], rate, dup, sig,
                 c["title"][:title_chars]))
    return 0


def _apply_crash_set(st, cid, a):
    """Apply one crash-set operation. Raises ValueError on a rejected edit."""
    if cid not in st["crashes"]:
        raise ValueError("unknown crash id: %s" % cid)
    c = st["crashes"][cid]
    if a.status:
        if a.status not in ps.CRASH_STATUS:
            raise ValueError("unknown crash status: %s (expected one of %s)"
                             % (a.status, ", ".join(sorted(ps.CRASH_STATUS))))
        ps.set_crash_status(c, a.status)
    if a.duplicate_of is not None:
        if a.duplicate_of.lower() in ("none", ""):
            c["duplicate_of"] = None
            # Clearing the link has to clear the verdict too, or the crash
            # keeps status=duplicate with nothing to duplicate and stays
            # excluded from the unique/RCA queue forever. An explicit
            # --status in the same command still wins.
            if c["status"] == "duplicate" and not a.status:
                ps.set_crash_status(c, "unique")
        else:
            if a.status and a.status != "duplicate":
                raise ValueError("--duplicate-of implies status 'duplicate', "
                                 "so it cannot be combined with --status %s"
                                 % a.status)
            if a.duplicate_of == cid:
                raise ValueError("a crash cannot duplicate itself")
            if a.duplicate_of not in st["crashes"]:
                raise ValueError("unknown crash id: %s" % a.duplicate_of)
            if st["crashes"][a.duplicate_of]["status"] == "duplicate":
                raise ValueError("%s is itself a duplicate. Link directly to "
                                 "the surviving entry (chains and cycles are "
                                 "not allowed)" % a.duplicate_of)
            c["duplicate_of"] = a.duplicate_of
            ps.set_crash_status(c, "duplicate")
    if c["status"] == "duplicate" and not c.get("duplicate_of"):
        raise ValueError("status 'duplicate' requires --duplicate-of <id>. An "
                         "unlinked duplicate is excluded from the RCA queue "
                         "with nothing pointing at the surviving entry")
    if a.disclosure:
        if a.disclosure not in ps.DISCLOSURE_STATUS:
            raise ValueError("unknown disclosure status: %s (expected one of "
                             "%s)" % (a.disclosure,
                                      ", ".join(sorted(ps.DISCLOSURE_STATUS))))
        c["disclosure"] = a.disclosure
    if a.repro_rate is not None:
        if not 0.0 <= a.repro_rate <= 1.0:
            raise ValueError("--repro-rate must be between 0.0 and 1.0")
        c["repro_rate"] = a.repro_rate
    if a.notes is not None:
        # argparse gives None when the flag is absent, so --notes '' is a
        # deliberate clear, not a no-op.
        c["notes"] = a.notes
    return "%s: status=%s disclosure=%s" % (cid, c["status"], c["disclosure"])


def cmd_crash_set(a):
    """Apply one edit to one or more crashes.

    Several ids because the triage gate is "the flagged queue is empty", and
    one generic panic title with a varying stack flags every distinct stack.
    Resolving forty of those one command at a time is the kind of work that
    stalls an unattended round; `crash-set a b c --duplicate-of X` is one
    call. All-or-nothing: a rejected id aborts the transaction so the queue is
    never left half-decided.
    """
    summaries = []
    with ps.transaction() as st:
        for cid in a.crash_id:
            try:
                summaries.append(_apply_crash_set(st, cid, a))
            except ValueError as e:
                sys.exit("error: %s (nothing was changed)" % e)
    for line in summaries:
        print(line)
    return 0


def _read_json_arg(src, what):
    """The JSON object at PATH, or on stdin when src is '-'."""
    try:
        raw = sys.stdin.read() if src == "-" else open(src).read()
    except OSError as e:
        sys.exit("error: cannot read %s from %s: %s" % (what, src, e))
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        sys.exit("error: %s from %s is not valid JSON: %s" % (what, src, e))


def cmd_finding_set(a):
    """Attach rca's research record to a crash.

    JSON rather than a flag per field: the record is nine fields, four of them
    lists, and rca authors it as a whole. A dozen repeatable flags would be
    filled in one call at a time, and a half-written record is the one thing
    this must not store.
    """
    finding = _read_json_arg(a.json_path, "finding")
    with ps.transaction() as st:
        try:
            f = ps.set_finding(st, a.crash_id, finding)
        except ValueError as e:
            sys.exit("error: %s" % e)
        targets = sorted(set(f["ioctls"]) | set(f["adjacent"]))
    print("%s: %s %s/%s (confidence %s)"
          % (a.crash_id, f["subsystem"], f["bug_class"], f["trigger"],
             f["confidence"]))
    print("  next round can target: %s" % (", ".join(targets) or
                                           "(preconditions only)"))
    return 0


def _print_finding(cid, f):
    print("%s [%s] %s/%s  confidence=%s"
          % (cid, f["subsystem"], f["bug_class"], f["trigger"],
             f["confidence"]))
    for label, key in (("ioctls", "ioctls"), ("preconditions", "preconditions"),
                       ("adjacent", "adjacent"), ("source", "source_refs")):
        if f[key]:
            print("    %-14s %s" % (label + ":", ", ".join(f[key])))
    for label, key in (("hypothesis:", "hypothesis"),
                       ("no adjacent:", "no_adjacent_reason")):
        if f.get(key):
            print("    %-14s %s" % (label, f[key]))
    gap = ps.finding_target_gap(f)
    if gap:
        print("    %-14s %s" % ("STEERS NOTHING:", gap))


def cmd_finding_list(a):
    """The research records, plus the per-subsystem rollup refine steers from.

    The rollup is the target register: it is what says nvidia_uvm has produced
    three findings and nvidia_rm none, which is the only evidence the loop has
    for where to look next that is not coverage.
    """
    st = ps.load()
    rows = ps.findings(st, subsystem=a.subsystem, bug_class=a.bug_class)
    if a.json:
        json.dump({cid: f for cid, f in rows}, sys.stdout, indent=2,
                  sort_keys=True)
        print()
        return 0
    if not rows:
        print("no findings recorded: rca has not produced a research record "
              "yet, so this round can only steer on coverage")
        return 0
    for cid, f in rows:
        _print_finding(cid, f)
    by_sub = {}
    for _cid, f in rows:
        by_sub.setdefault(f["subsystem"], []).append(f["bug_class"])
    print("\nby subsystem (what refine raises priority from):")
    for sub in sorted(by_sub, key=lambda s: (-len(by_sub[s]), s)):
        classes = by_sub[sub]
        print("  %-24s %d finding(s)  %s"
              % (sub, len(classes), ", ".join(sorted(set(classes)))))
    # The count that says whether the feedback edge is carrying anything. A
    # record with no usable `adjacent` looks identical to a good one in the
    # rollup above, which is exactly how this path would fail quietly.
    dead = [(cid, why) for cid, f, why in ps.findings_steering_nothing(st)
            if not a.subsystem or f["subsystem"] == a.subsystem]
    live = len(rows) - len(dead)
    print("\n%d of %d record(s) can send the next round somewhere new."
          % (live, len(rows)))
    if dead:
        print("These cannot, and rca should revisit them:")
        for cid, why in dead:
            print("  %s: %s" % (cid, why))
    return 0


def _surface_targets():
    """-> (targets by variant, driver version). Exits with the tool's message.

    surface_cov is imported here rather than at module scope for the same
    reason coverage_ctl is: pipeline_ctl runs on a box where the inventories
    may not have been generated yet, and `show` must not die because of it.
    """
    import surface_cov
    try:
        targets, _excluded, meta = surface_cov.load_targets()
    except surface_cov.SurfaceError as e:
        sys.exit("error: %s" % e)
    return targets, meta["driver_version"], len(targets)


def cmd_surface_account(a):
    """Record why one command-surface target will not be exercised.

    JSON rather than a flag per field, mirroring finding-set: the record is
    authored as a whole and a half-written one is the thing that must not be
    stored. This one closes a target out of the campaign permanently, so it is
    validated harder than it is convenient — the reason is a closed
    vocabulary, the detail is required, and a reason asserting something about
    driver source needs the file:line behind it.

    The record names its target by `variant`, which is what
    `surface_cov.py gaps` prints. The ledger stores it under the composite ABI
    key that variant resolves to, because a control variant carries the C
    handler function name and a driver refactor renames those freely: keyed on
    the variant, every accounted row would silently disappear at the next
    driver bump while the file still looked full.
    """
    record = _read_json_arg(a.json_path, "accounting record")
    if not isinstance(record, dict):
        sys.exit("error: an accounting record must be a JSON object, got %s"
                 % type(record).__name__)
    variant = record.get("variant")
    if not variant or not isinstance(variant, str):
        sys.exit("error: an accounting record needs a variant. The variant is "
                 "the name surface_cov.py gaps prints in brackets, and the "
                 "only handle the ledger can resolve to a target")
    # The inventories key on the part after `ioctl$`, which is what a corpus
    # program's call name reduces to. An agent copying the full syzlang call
    # name is naming the same target, so accept both spellings rather than
    # refusing one of them on a prefix.
    variant = record["variant"] = variant.strip()
    if variant.startswith("ioctl$"):
        variant = record["variant"] = variant[len("ioctl$"):]
    targets, driver, total = _surface_targets()
    target = targets.get(variant)
    if target is None:
        sys.exit("error: %s is not one of the %d targetable command(s) for "
                 "driver %s. Accounting for something outside the denominator "
                 "would close the ledger against a target it never counted. "
                 "Check the name against: python3 tools/surface_cov.py gaps"
                 % (variant, total, driver or "unknown"))
    with ps.transaction() as st:
        r = ps.current_round(st)
        record.setdefault("round", r["round"])
        record["key"] = target["abi_key"]
        record["family"] = target["family"]
        try:
            row = ps.set_surface_account(record, path=a.ledger,
                                         driver_version=driver,
                                         targets_total=total)
        except (ValueError, ps.SurfaceLedgerMismatch) as e:
            sys.exit("error: %s" % e)
        r["surface_ledger"] = _repo_rel(ps.surface_ledger_path(a.ledger))
    print("%s: %s (%s)" % (row["variant"], row["reason"], row["detail"]))
    print("  key %s (recorded %s, first %s)"
          % (row["key"], row["recorded"], row["first_recorded"]))
    print("  ledger %s" % _repo_rel(ps.surface_ledger_path(a.ledger)))
    return 0


def cmd_surface_unaccount(a):
    """Remove one accounting row, reopening its target.

    The way out of a reason written in error. A row closes its target out of
    the campaign, and once the union reaches the denominator the completion
    stop is one round-decide refuses to override, so without a removal the
    only recovery is a hand edit of the ledger file. Reopening a target moves
    the campaign back towards fuzzing it, so this refuses nothing but a name
    it cannot resolve.

    --variant resolves through the inventories, the same handle
    surface-account takes. --key names the stored key directly and is the only
    handle on a row whose target no inventory contains any more.
    """
    if bool(a.variant) == bool(a.key):
        sys.exit("error: name the row with --variant (as surface_cov.py gaps "
                 "prints it) or with --key (as surface-ledger --json stores "
                 "it), and not with both")
    key, driver = a.key, None
    if a.variant:
        variant = a.variant.strip()
        if variant.startswith("ioctl$"):
            variant = variant[len("ioctl$"):]
        targets, driver, total = _surface_targets()
        target = targets.get(variant)
        if target is None:
            sys.exit("error: %s is not one of the %d targetable command(s) "
                     "for driver %s. A row whose target no inventory contains "
                     "any more has no variant to resolve and is removed by "
                     "its stored key: --key <key>, as surface-ledger --json "
                     "prints it" % (variant, total, driver or "unknown"))
        key = target["abi_key"]
    try:
        row = ps.clear_surface_account(key, path=a.ledger,
                                       driver_version=driver)
    except (ValueError, ps.SurfaceLedgerMismatch) as e:
        sys.exit("error: %s" % e)
    if row is None:
        print("%s: no accounted row, so nothing was removed" % key)
        return 1
    print("removed %s: %s (%s)" % (row.get("variant") or key,
                                   row.get("reason"), row.get("detail")))
    print("  key %s (first recorded %s)" % (key, row.get("first_recorded")))
    print("  ledger %s" % _repo_rel(ps.surface_ledger_path(a.ledger)))
    print("  the target is open again. The round still carries the verdict it "
          "was measured with, so re-measure before the loop reads it: python3 "
          "tools/pipeline_ctl.py round-end --from-run <run-id>")
    return 0


def cmd_surface_ledger(a):
    """The accounted rows and what is still open, grouped by reason."""
    targets, driver, total = _surface_targets()
    try:
        ledger = ps.load_surface_ledger(a.ledger, driver, targets_total=total)
    except (ValueError, ps.SurfaceLedgerMismatch) as e:
        sys.exit("error: %s" % e)
    rows = ledger["accounted"]
    if a.json:
        json.dump(ledger, sys.stdout, indent=2, sort_keys=True)
        print()
        return 0
    print("ledger %s" % _repo_rel(ps.surface_ledger_path(a.ledger)))
    print("driver %s, %d of %d target(s) accounted for"
          % (ledger.get("driver_version") or "unknown", len(rows), total))
    if not rows:
        print("nothing accounted for yet. Completion is exercised plus "
              "accounted-for equal to %d, so until a reason is written for "
              "every unreachable target the loop cannot stop on completion."
              % total)
        return 0
    by_reason = {}
    for row in rows.values():
        by_reason.setdefault(row.get("reason", "?"), []).append(row)
    for reason in sorted(by_reason, key=lambda k: (-len(by_reason[k]), k)):
        print("  %-24s %d%s"
              % (reason, len(by_reason[reason]),
                 "   does not close the target"
                 if reason in ps.SURFACE_REASON_DEFERRED else ""))
    deferred = sum(len(v) for k, v in by_reason.items()
                   if k in ps.SURFACE_REASON_DEFERRED)
    if deferred:
        print("%d row(s) record a target as reachable and put aside, so they "
              "are counted here and not towards completion. The campaign "
              "either fuzzes those targets or writes a reason that says why "
              "they cannot be reached." % deferred)
    keys = {t["abi_key"] for t in targets.values()}
    stale = sorted(set(rows) - keys)
    if stale:
        print("%d row(s) name a target no inventory contains and are not "
              "counted (a driver bump, or a hand-edited ledger):" % len(stale))
        for key in stale[:10]:
            print("  %s" % key)
    return 0


def cmd_impact_set(a):
    """Attach rca's impact record to a crash.

    Separate from finding-set because the two answer to different readers and
    fail in different ways. A finding is refused when it can steer nothing;
    an impact is refused when it cannot argue what it concludes. Merging them
    would mean one record that has to satisfy both, and in practice that means
    one that satisfies neither.
    """
    raw = _read_json_arg(a.json_path, "impact")
    with ps.transaction() as st:
        try:
            im = ps.set_impact(st, a.crash_id, raw)
        except ValueError as e:
            sys.exit("error: %s" % e)
        cwe = ps.cwe_of(st["crashes"][a.crash_id])
    print("%s: %s -> %s%s (confidence %s)"
          % (a.crash_id, im["primitive"], im["consequence"],
             "  %s" % cwe if cwe else "", im["confidence"]))
    gap = ps.impact_support_gap(im)
    print("  %s" % (("UNSUPPORTED: %s" % gap) if gap else
                    "the record supports its own conclusion"))
    return 0


def _print_impact(cid, im, cwe=""):
    print("%s %s -> %s%s  confidence=%s"
          % (cid, im["primitive"], im["consequence"],
             "  [%s]" % cwe if cwe else "", im["confidence"]))
    access = im["access_type"]
    if im["access_size"]:
        access += " of %d byte(s)" % im["access_size"]
    print("    %-16s %s onto %s" % ("access:", access,
                                    im["overwrite_target"]))
    for label, key in (("object", "corrupted_object"), ("cache", "cache"),
                       ("reclaim", "reclaim_path"), ("race window",
                                                     "race_window")):
        if im[key]:
            print("    %-16s %s" % (label + ":", im[key]))
    sites = [(k.split("_")[0], im[k]) for k in
             ("allocation_site", "free_site", "access_site") if im[k]]
    if sites:
        print("    %-16s %s" % ("sites:", ", ".join("%s %s" % s
                                                    for s in sites)))
    for label, key in (("attacker ctrl", "attacker_control"),
                       ("evidence", "evidence"), ("unverified", "unverified")):
        if im[key]:
            print("    %-16s %s" % (label + ":", ", ".join(im[key])))
    if im["undetermined_reason"]:
        print("    %-16s %s" % ("undetermined:", im["undetermined_reason"]))
    gap = ps.impact_support_gap(im)
    if gap:
        print("    %-16s %s" % ("UNSUPPORTED:", gap))


def cmd_impact_list(a):
    """The impact records, plus the rollup a report's severity table needs."""
    st = ps.load()
    rows = ps.impacts(st, primitive=a.primitive, consequence=a.consequence)
    if a.json:
        json.dump({cid: dict(im, cwe=ps.cwe_of(st["crashes"][cid]))
                   for cid, im in rows}, sys.stdout, indent=2, sort_keys=True)
        print()
        return 0
    if not rows:
        print("no impact records: rca has analysed no crash for what the "
              "fault gives an attacker, so the report can describe crashes "
              "and argue no severity for any of them")
        return 0
    for cid, im in rows:
        _print_impact(cid, im, ps.cwe_of(st["crashes"][cid]))
    by_cons = {}
    for cid, im in rows:
        by_cons.setdefault(im["consequence"], []).append(
            ps.cwe_of(st["crashes"][cid]) or "CWE-unmapped")
    print("\nby consequence (what the report's severity table rests on):")
    for cons in sorted(by_cons, key=lambda c: (-len(by_cons[c]), c)):
        print("  %-22s %d  %s" % (cons, len(by_cons[cons]),
                                  ", ".join(sorted(set(by_cons[cons])))))
    # The same honesty line finding-list carries, for the same reason: an
    # unsupported record reads identically to a supported one in the rollup
    # above, and that is exactly how an over-claimed severity reaches a vendor.
    bad = [(cid, why) for cid, im, why in ps.impacts_unsupported(st)
           if (not a.primitive or im["primitive"] == a.primitive)
           and (not a.consequence or im["consequence"] == a.consequence)]
    print("\n%d of %d record(s) can carry a severity into the report."
          % (len(rows) - len(bad), len(rows)))
    if bad:
        print("These cannot, and rca should revisit them:")
        for cid, why in bad:
            print("  %s: %s" % (cid, why))
    return 0


def cmd_brief(a):
    """Everything a replacement agent needs, derived from state at read time.

    This is what a fresh session reads after a panic, and what an agent whose
    context was compacted reads to recover. It is deliberately *derived*: a
    hand-maintained handoff file drifts the moment a phase changes without it
    being rewritten, and a stale file that looks authoritative is worse than
    none. This one cannot be stale, only old, and it stamps its own time so
    that is visible.

    Keep it short. It is read into a context window that has just been
    truncated, and every line here displaces something else.
    """
    st = ps.load()
    cfg = _loop_cfg()
    ag = _agent_cfg()
    # --last is the override for a reader who wants more than the campaign's
    # configured depth right now. Unset means "whatever the config says", so
    # the anchor a resumed agent gets is tunable in one place rather than by
    # editing the command in the systemd unit.
    last = a.last if a.last is not None else ag["brief_knowledge_entries"]
    r = ps.current_round(st)
    print("# gspwn brief, generated %s" % ps._now())
    print("Derived from %s at read time. Re-run it for a current answer, "
          "because\nnothing here stays authoritative once the state file "
          "moves on."
          % _repo_rel(ps.STATE_PATH))

    print("\n## Where the pipeline is")
    print("round %d of max %d, %.1f of %s run-hours spent"
          % (r["round"], cfg["max_rounds"], ps.spent_hours(st),
             cfg["max_total_run_hours"]))
    kind, val = _next_action(st)
    print("next action: %s" % {
        "phase": lambda: "run phase %s (see agents/%s.md)" % (val, val),
        "wait": lambda: _wait_line(*val),
        "decide": lambda: "pipeline_ctl.py round-decide",
        "advance-round": lambda: "pipeline_ctl.py round-advance",
        "done": lambda: "complete: all phases done"}[kind]())
    for label, sel in (("done", "done"), ("in progress", "in_progress"),
                       ("blocked", "blocked"), ("failed", "failed")):
        names = [p for p in ps.PHASES if st["phases"][p]["status"] == sel]
        if names:
            print("%-12s %s" % (label + ":", ", ".join(names)))
    for p in ps.PHASES:
        ph = st["phases"][p]
        if ph["status"] in ("blocked", "failed") and ph["notes"]:
            print("  %s %s: %s" % (p, ph["status"], ph["notes"]))

    if r.get("surface_total"):
        # The primary stop rests on this line, so a resumed agent has to see
        # it in the same place it sees the round and the budget.
        print("command surface: %s, %s of %s exercised, %s accounted for%s"
              % (r.get("surface_verdict"), r.get("surface_exercised"),
                 r.get("surface_total"), r.get("surface_accounted"),
                 ", %s deferred and still open" % r["surface_deferred"]
                 if r.get("surface_deferred") else ""))
    if r.get("worklist_in"):
        print("\nthis round executes: %s" % r["worklist_in"])
    prev = st["rounds"][-2] if len(st["rounds"]) > 1 else None
    if prev and prev.get("decision"):
        print("previous round %d: %s (%s)"
              % (prev["round"], prev["decision"], prev["decision_reason"]))

    print("\n## Crashes")
    crashes = st["crashes"]
    if not crashes:
        print("none registered")
    else:
        by_status = {}
        for c in crashes.values():
            by_status[c["status"]] = by_status.get(c["status"], 0) + 1
        print("%d total: %s" % (len(crashes),
                                ", ".join("%s=%d" % kv
                                          for kv in sorted(by_status.items()))))
        _print_noise_line(crashes)
        flagged = by_status.get("flagged", 0)
        if flagged:
            print("%d flagged. Triage cannot pass its gate until that queue "
                  "is empty" % flagged)

    print("\n## Findings (what steers the next round)")
    rows = ps.findings(st)
    if not rows:
        print("none recorded: the loop can only steer on coverage")
    else:
        by_sub = {}
        for _cid, f in rows:
            by_sub.setdefault(f["subsystem"], []).append(f["bug_class"])
        for sub in sorted(by_sub, key=lambda s: (-len(by_sub[s]), s)):
            print("  %-24s %d  %s" % (sub, len(by_sub[sub]),
                                      ", ".join(sorted(set(by_sub[sub])))))
        dead = ps.findings_steering_nothing(st)
        if dead:
            print("  %d of %d steer nothing new (finding-list says which). "
                  "The loop is back on coverage alone for those"
                  % (len(dead), len(rows)))

    print("\n## Impact (what the report can argue)")
    imps = ps.impacts(st)
    if not imps:
        print("none assessed: the report would carry reproducers with no "
              "argued severity")
    else:
        by_cons = {}
        for _cid, im in imps:
            by_cons[im["consequence"]] = by_cons.get(im["consequence"], 0) + 1
        print("%d assessed: %s"
              % (len(imps), ", ".join("%s=%d" % kv
                                      for kv in sorted(by_cons.items()))))
        weak = ps.impacts_unsupported(st)
        if weak:
            print("  %d of %d cannot carry a severity (impact-list says "
                  "which)" % (len(weak), len(imps)))

    print("\n## Recent knowledge (cross-campaign)")
    try:
        import knowledge_ctl
        for kind_ in knowledge_ctl.KINDS:
            entries = knowledge_ctl._entries(kind_)[-last:]
            if not entries:
                continue
            print("%s:" % knowledge_ctl.FILENAME[kind_])
            for _ts, phase, _tags, body in entries:
                first = body.split("\n")[0]
                print("  [%s] %s"
                      % (phase, first[:ag["brief_knowledge_line_chars"]]))
        print("full text: python3 tools/knowledge_ctl.py show")
    except Exception as e:
        # The brief is a recovery tool. An unreadable knowledge file must not
        # cost the reader the state summary above it, which is the part they
        # cannot get anywhere else.
        print("(knowledge unavailable: %s)" % e)

    problems = ps.validate(st, _triage_cfg())
    if problems:
        print("\n## Integrity: %d problem(s)" % len(problems))
        for p in problems[:ag["brief_max_problems"]]:
            print("  " + p)
        print("  full list: python3 tools/pipeline_ctl.py validate")
    return 0


def cmd_campaign_add(a):
    track = a.track.upper()
    if track not in ps.TRACKS:
        sys.exit("error: unknown track: %s (expected k or u)" % a.track)
    with ps.transaction() as st:
        st["campaigns"].append({"track": track, "action": "record",
                                "note": a.note, "at": ps._now()})
        n = len(st["campaigns"])
    print("recorded campaign entry #%d (track %s)" % (n, track))
    return 0


def _triage_cfg():
    """Current dedup settings, or None when config cannot be read.

    None rather than an exit: validate's job is to report on the registry, and
    it must still do that when the config is broken. The drift check is simply
    one of the things it cannot answer then.
    """
    try:
        return gspwn_config.triage()
    except gspwn_config.ConfigError:
        return None


def cmd_validate(a):
    problems = ps.validate(ps.load(), _triage_cfg())
    if not problems:
        print("state is consistent")
        return 0
    for p in problems:
        print("PROBLEM: " + p)
    return 1


def cmd_spend_init(a):
    """Rebuild a lost spend ledger from the hours the state file records.

    The deliberate act that clearing SpendLedgerMissing requires. It never
    lowers recorded spend: with a ledger already present this is a no-op, so
    it cannot be used to wipe the budget.
    """
    existed = os.path.exists(ps.SPEND_PATH)
    total = ps.seed_spend_ledger()
    print("%s %s: %.1f run-hours billed"
          % ("ledger already present at" if existed else "seeded ledger",
             ps.SPEND_PATH, total))
    if existed:
        print("(no change. Delete the ledger first to rebuild it from the "
              "state file)")
    return 0


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
    p.add_argument("--signal", choices=sorted(ps.CRASH_SIGNAL),
                   help="filter by Xid classification (crash_parse.XID_CLASS)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_crash_list)

    p = sub.add_parser("crash-set", help="update crash registry entries")
    p.add_argument("crash_id", nargs="+", metavar="CRASH_ID",
                   help="one or more crash ids. The same edit is applied to "
                        "each, and a rejected id aborts the whole call")
    p.add_argument("--status")
    p.add_argument("--duplicate-of", dest="duplicate_of",
                   help="crash id, or 'none' to clear")
    p.add_argument("--disclosure")
    p.add_argument("--repro-rate", dest="repro_rate", type=float)
    p.add_argument("--notes")
    p.set_defaults(fn=cmd_crash_set)

    p = sub.add_parser("brief",
                       help="derived handoff: state + findings + knowledge")
    p.add_argument("--last", type=int, default=None, metavar="N",
                   help="knowledge entries per file. Defaults to "
                        "agent.brief_knowledge_entries in campaign.yaml")
    p.set_defaults(fn=cmd_brief)

    p = sub.add_parser("finding-set",
                       help="attach rca's research record to a crash")
    p.add_argument("crash_id")
    p.add_argument("--json", dest="json_path", required=True, metavar="PATH",
                   help="file holding the research record, or - for stdin. "
                        "Fields: subsystem (required), bug_class %s, "
                        "trigger %s, ioctls[], preconditions[], adjacent[], "
                        "source_refs[], hypothesis, confidence %s"
                        % ("|".join(ps.BUG_CLASS), "|".join(ps.TRIGGER),
                           "|".join(ps.CONFIDENCE)))
    p.set_defaults(fn=cmd_finding_set)

    p = sub.add_parser("finding-list",
                       help="research records + the per-subsystem rollup")
    p.add_argument("--subsystem")
    p.add_argument("--bug-class", dest="bug_class", choices=ps.BUG_CLASS)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_finding_list)

    p = sub.add_parser("surface-account",
                       help="record why a command-surface target will not be "
                            "exercised")
    p.add_argument("--json", dest="json_path", required=True, metavar="PATH",
                   help="file holding the accounting record, or - for stdin. "
                        "Fields: variant (required, as surface_cov.py gaps "
                        "prints it), reason (required, one of %s), detail "
                        "(required), evidence[] (file:line, required for %s), "
                        "round"
                        % ("|".join(sorted(ps.SURFACE_REASON)),
                           "|".join(ps.SURFACE_REASON_NEEDS_EVIDENCE)))
    p.add_argument("--ledger", default=None,
                   help="ledger path (default %s)" % ps.SURFACE_LEDGER_PATH)
    p.set_defaults(fn=cmd_surface_account)

    p = sub.add_parser("surface-unaccount",
                       help="remove one accounted row, reopening its target")
    p.add_argument("--variant",
                   help="the target's variant, as surface_cov.py gaps prints "
                        "it")
    p.add_argument("--key",
                   help="the stored ABI key, for a row whose target no "
                        "inventory contains any more")
    p.add_argument("--ledger", default=None,
                   help="ledger path (default %s)" % ps.SURFACE_LEDGER_PATH)
    p.set_defaults(fn=cmd_surface_unaccount)

    p = sub.add_parser("surface-ledger",
                       help="the accounted targets, grouped by reason")
    p.add_argument("--ledger", default=None)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_surface_ledger)

    p = sub.add_parser("impact-set",
                       help="attach rca's impact record to a crash")
    p.add_argument("crash_id")
    p.add_argument("--json", dest="json_path", required=True, metavar="PATH",
                   help="file holding the impact record, or - for stdin. "
                        "Fields: primitive %s, consequence %s, access_type "
                        "%s, overwrite_target %s, attacker_control[] %s, "
                        "corrupted_object, cache, access_size, reclaim_path, "
                        "race_window, allocation_site, free_site, "
                        "access_site, evidence[], unverified[], confidence "
                        "%s, cwe (derived from bug_class when empty), "
                        "undetermined_reason"
                        % ("|".join(ps.PRIMITIVE), "|".join(ps.CONSEQUENCE),
                           "|".join(ps.ACCESS_TYPE),
                           "|".join(ps.OVERWRITE_TARGET),
                           "|".join(ps.ATTACKER_CONTROL),
                           "|".join(ps.CONFIDENCE)))
    p.set_defaults(fn=cmd_impact_set)

    p = sub.add_parser("impact-list",
                       help="impact records + the consequence/CWE rollup")
    p.add_argument("--primitive", choices=ps.PRIMITIVE)
    p.add_argument("--consequence", choices=ps.CONSEQUENCE)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_impact_list)

    p = sub.add_parser("campaign-add", help="record a campaign event")
    p.add_argument("--track", required=True,
                   help="k or u (case-insensitive, stored as K/U)")
    p.add_argument("--note", required=True)
    p.set_defaults(fn=cmd_campaign_add)

    p = sub.add_parser("round-show", help="round history and loop budget")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_round_show)

    p = sub.add_parser("round-add-run", help="attach a run id to this round")
    p.add_argument("--run-id", required=True, dest="run_id")
    p.set_defaults(fn=cmd_round_add_run)

    p = sub.add_parser("round-end", help="record this round's measured outcome")
    p.add_argument("--from-run", dest="from_run", action="append",
                   metavar="RUN_ID",
                   help="measure verdict/edges/run-hours from this run's "
                        "coverage.csv, so they need not be passed by hand. "
                        "Repeatable: pass every campaign this round ran, and "
                        "each is measured and billed independently")
    p.add_argument("--coverage-verdict", dest="coverage_verdict",
                   choices=sorted(ps.COVERAGE_VERDICT),
                   help="from: coverage_ctl.py plateau --run-id ID")
    p.add_argument("--new-crashes", dest="new_crashes", type=int)
    p.add_argument("--edges-start", dest="edges_start", type=int)
    p.add_argument("--edges-end", dest="edges_end", type=int)
    p.add_argument("--run-hours", dest="run_hours", type=float,
                   help="bill these hours to the round (added to the round "
                        "total, and derived per-run hours are preferred)")
    p.add_argument("--notes")
    p.add_argument("--worklist",
                   help="path to this round's worklist.md. The next round's "
                        "describe/seeds agents read it via `worklist`")
    p.add_argument("--ledger", default=None,
                   help="completion ledger to measure against, pinned onto "
                        "the round. Omit to use the one the round already "
                        "names, or %s" % ps.SURFACE_LEDGER_PATH)
    p.add_argument("--force", action="store_true",
                   help="measure a run whose campaign window has not elapsed "
                        "(only when the campaign really is finished and its "
                        "deadline file is stale)")
    p.set_defaults(fn=cmd_round_end)

    p = sub.add_parser("worklist",
                       help="print the worklist this round must execute")
    p.set_defaults(fn=cmd_worklist)

    p = sub.add_parser("round-decide",
                       help="apply the configured loop caps -> continue|stop")
    p.add_argument("--decision", choices=sorted(ps.ROUND_DECISION),
                   help="override the computed decision (a completion, "
                        "budget or round-cap stop cannot be overridden, and a "
                        "plateau or unknown stop requires --reason)")
    p.add_argument("--reason", default="")
    p.set_defaults(fn=cmd_round_decide)

    p = sub.add_parser("round-advance", help="open the next round")
    p.set_defaults(fn=cmd_round_advance)

    p = sub.add_parser("spend-init",
                       help="re-seed the spend ledger from the state file")
    p.set_defaults(fn=cmd_spend_init)

    p = sub.add_parser("validate", help="check state integrity")
    p.set_defaults(fn=cmd_validate)
    return ap


def main():
    a = build_parser().parse_args()
    try:
        sys.exit(a.fn(a))
    except ValueError as e:
        sys.exit("error: %s" % e)
    except ps.SpendLedgerMissing as e:
        # Every command that reads spend fails closed through here; the
        # exception already carries the spend-init remediation.
        sys.exit("error: %s" % e)


if __name__ == "__main__":
    main()
