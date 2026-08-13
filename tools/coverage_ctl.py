#!/usr/bin/env python3
"""Coverage tracking for a fuzzing run: sample, summarize, detect plateau.

syzkaller already runs the inner coverage-guided loop (mutate, measure via
KCOV, keep corpus-advancing inputs). This tool serves the OUTER loop: it
records the coverage curve so the pipeline can tell whether a round is still
buying new edges, and compare configurations in the eval.

Subcommands:
  sample --run-id ID [--url URL]       append one row to the run's coverage.csv
  install-timer --run-id ID [--url URL] [--interval-min N]
                                       systemd timer that samples unattended
                                       (survives panics; sampling must outlive
                                       the agent session)
  remove-timer                         stop and remove the sampling timer
  series --run-id ID                   summary of the recorded curve
  plateau --run-id ID [--window-min N] [--min-growth F]
                                       verdict: growing | plateaued | unknown
                                       exit 0 growing, 3 plateaued, 1 unknown
  compare --run-id A --run-id B        side-by-side endpoints (ablation diff)

Coverage is kernel-side reachable code only. GSP firmware is not instrumented
(spec §3); every consumer of these numbers must say so.

NOTE ON THE STATS ENDPOINT: syz-manager's HTTP surface has changed across
syzkaller versions. This tool tries the known JSON endpoints, then falls back
to scraping the dashboard HTML, then to corpus.db size. Confirm on the pinned
syzkaller commit during the fuzz phase and record which source was used —
`sample` prints it, and it is written into every CSV row.
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
RUNS_DIR = os.path.join(REPO_ROOT, "artifacts", "runs")
FIELDS = ["ts", "uptime_s", "edges", "corpus", "crashes", "execs", "source"]
TIMER_NAME = "gspwn-coverage"

# Candidate JSON endpoints, newest-style first.
JSON_PATHS = ("/stats?format=json", "/api/stats", "/stats.json")
# Dashboard HTML labels -> our field names.
HTML_FIELDS = {"edges": ("coverage", "cover", "signal", "edges"),
               "corpus": ("corpus",),
               "crashes": ("crashes",),
               "execs": ("exec total", "execs", "total execs")}


def run_dir(run_id):
    return os.path.join(RUNS_DIR, run_id)


def csv_path(run_id):
    return os.path.join(run_dir(run_id), "coverage.csv")


def _to_int(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return int(v)
    m = re.search(r"\d[\d,]*", str(v))
    return int(m.group(0).replace(",", "")) if m else None


def _dig(obj, names):
    """Find the first matching metric anywhere in a nested dict/list.

    Handles both shapes syz-manager has used: direct {"corpus": 421} mappings,
    and {"name": "corpus", "value": 421} records inside a stats list.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower().replace("_", " ")
            if kl in names and _to_int(v) is not None:
                return _to_int(v)
        name = obj.get("name") or obj.get("Name")
        if name is not None and str(name).lower().replace("_", " ") in names:
            for vk in ("value", "Value", "val", "count"):
                if vk in obj and _to_int(obj[vk]) is not None:
                    return _to_int(obj[vk])
        for v in obj.values():
            got = _dig(v, names)
            if got is not None:
                return got
    elif isinstance(obj, list):
        for v in obj:
            got = _dig(v, names)
            if got is not None:
                return got
    return None


def fetch_json(url, timeout=5):
    for path in JSON_PATHS:
        try:
            with urllib.request.urlopen(url.rstrip("/") + path,
                                        timeout=timeout) as r:
                return json.loads(r.read().decode(errors="replace")), path
        except Exception:
            continue
    return None, None


def fetch_html(url, timeout=5):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode(errors="replace")
    except Exception:
        return None


def parse_html(html):
    """Scrape 'label ... number' pairs out of the syz-manager dashboard."""
    text = re.sub(r"<[^>]+>", " ", html).lower()
    out = {}
    for field, labels in HTML_FIELDS.items():
        for label in labels:
            m = re.search(re.escape(label) + r"[^0-9]{0,40}(\d[\d,]*)", text)
            if m:
                out[field] = _to_int(m.group(1))
                break
    return out


def corpus_fallback(run_id):
    db = os.path.join(run_dir(run_id), "workdir", "corpus.db")
    if os.path.exists(db):
        return {"corpus": os.path.getsize(db)}
    return {}


def collect(run_id, url):
    """-> (row_dict, source). Never raises; a failed sample still records."""
    data, path = fetch_json(url)
    if data is not None:
        row = {"edges": _dig(data, {"coverage", "cover", "signal", "edges"}),
               "corpus": _dig(data, {"corpus"}),
               "crashes": _dig(data, {"crashes"}),
               "execs": _dig(data, {"exec total", "execs", "total execs"}),
               "uptime_s": _dig(data, {"uptime", "fuzzing time"})}
        if any(v is not None for v in row.values()):
            return row, "json:" + path
    html = fetch_html(url)
    if html:
        row = parse_html(html)
        if row:
            return row, "html"
    row = corpus_fallback(run_id)
    return row, "corpus.db-size" if row else "unreachable"


def cmd_sample(a):
    d = run_dir(a.run_id)
    os.makedirs(d, exist_ok=True)
    row, source = collect(a.run_id, a.url)
    row = {k: row.get(k) for k in FIELDS}
    row["ts"] = int(time.time())
    row["source"] = source
    path = csv_path(a.run_id)
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerow(row)
        f.flush()
        os.fsync(f.fileno())
    print("%s edges=%s corpus=%s crashes=%s (source: %s)"
          % (path, row["edges"], row["corpus"], row["crashes"], source))
    if source == "unreachable":
        print("WARN: syz-manager stats unreachable at %s — the sample was "
              "recorded empty. Check the unit is running and the http address "
              "in the campaign config." % a.url)
        return 1
    return 0


def read_rows(run_id):
    path = csv_path(run_id)
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        rows = []
        for r in csv.DictReader(f):
            rows.append({k: (_to_int(r.get(k)) if k != "source"
                             else r.get(k)) for k in FIELDS})
        return rows


def metric_rows(run_id, metric="edges"):
    """Rows carrying a usable value for the metric, oldest first."""
    return [r for r in read_rows(run_id) if r.get(metric) is not None]


def cmd_series(a):
    rows = read_rows(a.run_id)
    if not rows:
        print("no samples recorded for run %s (expected %s)"
              % (a.run_id, csv_path(a.run_id)))
        return 1
    cov = metric_rows(a.run_id)
    span_h = (rows[-1]["ts"] - rows[0]["ts"]) / 3600.0 if len(rows) > 1 else 0.0
    print("run %s: %d samples over %.1f h" % (a.run_id, len(rows), span_h))
    print("  sources: %s" % ", ".join(sorted({r["source"] or "?"
                                              for r in rows})))
    if cov:
        print("  edges: %s -> %s (+%s)"
              % (cov[0]["edges"], cov[-1]["edges"],
                 cov[-1]["edges"] - cov[0]["edges"]))
    else:
        print("  edges: never recorded — coverage claims cannot be made from "
              "this run")
    for m in ("corpus", "crashes"):
        vals = metric_rows(a.run_id, m)
        if vals:
            print("  %s: %s -> %s" % (m, vals[0][m], vals[-1][m]))
    print("  NOTE: kernel-side reachable coverage only; GSP firmware is not "
          "instrumented.")
    return 0


def plateau_verdict(rows, window_min, min_growth):
    """-> (verdict, detail). Growth is measured over the trailing window.

    'unknown' is a real answer: too few samples, too short a window, or no
    edge data means we must not claim a plateau. The loop treats unknown as a
    stop, so a broken sampler cannot silently authorise more spend.
    """
    if len(rows) < 3:
        return "unknown", "only %d usable sample(s); need >= 3" % len(rows)
    span_min = (rows[-1]["ts"] - rows[0]["ts"]) / 60.0
    if span_min < window_min:
        return "unknown", ("samples span %.0f min, shorter than the %d min "
                           "window" % (span_min, window_min))
    cutoff = rows[-1]["ts"] - window_min * 60
    window = [r for r in rows if r["ts"] >= cutoff]
    if len(window) < 2:
        return "unknown", "only %d sample(s) inside the window" % len(window)
    start, end = window[0]["edges"], window[-1]["edges"]
    if not start:
        return "unknown", "no non-zero edge baseline in the window"
    growth = (end - start) / float(start)
    detail = ("edges %d -> %d over %.0f min = %.3f%% growth (threshold %.3f%%)"
              % (start, end, window_min, growth * 100, min_growth * 100))
    return ("plateaued" if growth < min_growth else "growing"), detail


def cmd_plateau(a):
    rows = metric_rows(a.run_id)
    verdict, detail = plateau_verdict(rows, a.window_min, a.min_growth)
    print("%s: %s (%s)" % (a.run_id, verdict, detail))
    return {"growing": 0, "unknown": 1, "plateaued": 3}[verdict]


def cmd_compare(a):
    for rid in (a.run_id, a.against):
        rows = metric_rows(rid)
        if not rows:
            print("%-20s no edge samples" % rid)
            continue
        span_h = (rows[-1]["ts"] - rows[0]["ts"]) / 3600.0
        print("%-20s edges %6s -> %6s  (+%-6s) over %.1f h"
              % (rid, rows[0]["edges"], rows[-1]["edges"],
                 rows[-1]["edges"] - rows[0]["edges"], span_h))
    print("Comparing runs is only meaningful when each had its own workdir and "
          "corpus policy — see campaign_ctl.py --corpus.")
    return 0


SERVICE_UNIT = """[Unit]
Description=gspwn coverage sampler ({run_id})

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {root}/tools/coverage_ctl.py sample \\
  --run-id {run_id} --url {url}
"""
TIMER_UNIT = """[Unit]
Description=gspwn coverage sampler

[Timer]
OnBootSec={interval}min
OnUnitActiveSec={interval}min

[Install]
WantedBy=timers.target
"""


def _systemctl(*args, check=True):
    return subprocess.run(["systemctl"] + list(args), check=check)


def cmd_install_timer(a):
    if os.geteuid() != 0:
        sys.exit("install-timer must run as root")
    os.makedirs(run_dir(a.run_id), exist_ok=True)
    with open("/etc/systemd/system/%s.service" % TIMER_NAME, "w") as f:
        f.write(SERVICE_UNIT.format(root=REPO_ROOT, run_id=a.run_id,
                                    url=a.url))
    with open("/etc/systemd/system/%s.timer" % TIMER_NAME, "w") as f:
        f.write(TIMER_UNIT.format(interval=a.interval_min))
    _systemctl("daemon-reload")
    _systemctl("enable", "--now", "%s.timer" % TIMER_NAME)
    print("sampling run %s every %d min into %s"
          % (a.run_id, a.interval_min, csv_path(a.run_id)))
    return 0


def cmd_remove_timer(a):
    if os.geteuid() != 0:
        sys.exit("remove-timer must run as root")
    _systemctl("disable", "--now", "%s.timer" % TIMER_NAME, check=False)
    for suffix in (".timer", ".service"):
        p = "/etc/systemd/system/%s%s" % (TIMER_NAME, suffix)
        if os.path.exists(p):
            os.remove(p)
    _systemctl("daemon-reload", check=False)
    print("coverage sampler removed")
    return 0


def build_parser():
    ap = argparse.ArgumentParser(prog="coverage_ctl.py",
                                 description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    default_url = "http://127.0.0.1:56744"

    p = sub.add_parser("sample")
    p.add_argument("--run-id", required=True)
    p.add_argument("--url", default=default_url)
    p.set_defaults(fn=cmd_sample)

    p = sub.add_parser("install-timer")
    p.add_argument("--run-id", required=True)
    p.add_argument("--url", default=default_url)
    p.add_argument("--interval-min", type=int, default=10)
    p.set_defaults(fn=cmd_install_timer)

    p = sub.add_parser("remove-timer")
    p.set_defaults(fn=cmd_remove_timer)

    p = sub.add_parser("series")
    p.add_argument("--run-id", required=True)
    p.set_defaults(fn=cmd_series)

    p = sub.add_parser("plateau")
    p.add_argument("--run-id", required=True)
    p.add_argument("--window-min", type=int, default=240,
                   help="trailing window to measure growth over (default 4h)")
    p.add_argument("--min-growth", type=float, default=0.02,
                   help="fractional edge growth below which the run has "
                        "plateaued (default 0.02 = 2%%)")
    p.set_defaults(fn=cmd_plateau)

    p = sub.add_parser("compare")
    p.add_argument("--run-id", required=True)
    p.add_argument("--against", required=True)
    p.set_defaults(fn=cmd_compare)
    return ap


def main():
    a = build_parser().parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
