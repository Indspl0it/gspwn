#!/usr/bin/env python3
"""Coverage tracking for a fuzzing run: sample, summarize, detect plateau.

syzkaller already runs the inner coverage-guided loop (mutate, measure via
KCOV, keep corpus-advancing inputs). This tool serves the OUTER loop: it
records the coverage curve so the pipeline can tell whether a round is still
buying new edges, and compare configurations in the eval.

Both tracks are sampled. Track K reads syz-manager's stats endpoint; Track U
sums AFL++ `fuzzer_stats` across the run's harness output dirs
(artifacts/runs/<id>/u/<harness>/). They are recorded separately —
coverage.csv and coverage-u.csv — and the loop's verdict combines them: a
round is still learning if EITHER track is still finding edges.

Subcommands:
  sample --run-id ID [--track k|u] [--url URL] [--force]
                                       append one row to the track's CSV;
                                       skipped once the campaign window is up
  install-timer --run-id ID [--url URL] [--interval-min N]
                                       systemd timer that samples both tracks
                                       (survives panics; sampling must outlive
                                       the agent session). The campaign
                                       deadline is enforced separately by
                                       gspwn-deadline@<run-id>.timer, which
                                       campaign_ctl install-k/install-u set up
  remove-timer                         stop and remove the sampling timer
  series --run-id ID [--track k|u]     summary of the recorded curve
  plateau --run-id ID [--track k|u] [--window-min N] [--min-growth F]
          [--horizon-hours H]
                                       verdict: growing | plateaued | unknown
                                       (omit --track for the combined view)
                                       exit 0 growing, 3 plateaued, 1 unknown
                                       The verdict extrapolates a fitted
                                       species-accumulation curve: plateaued
                                       means another H hours is expected to
                                       find fewer than
                                       coverage.plateau_new_edges new edges.
  compare --run-id A --against B [--track k|u]
                                       side-by-side endpoints (two runs)
  gpu-health                           probe the GPU now; exit 0 healthy, 1 not

Coverage is kernel-side reachable code only. GSP firmware is not instrumented
(spec §3); every consumer of these numbers must say so.

Every sample records the GPU's state alongside the counters. A GPU that has
fallen off the bus does not stop the fuzzer: the curve simply flattens, and
without that column a plateau verdict cannot tell a finished round from a dead
card. `plateau` refuses to call a flat window a plateau when the GPU was not
healthy across it.

NOTE ON THE STATS ENDPOINT: syz-manager's HTTP surface has changed across
syzkaller versions. This tool tries the known JSON endpoints, then falls back
to scraping the dashboard HTML, then to corpus.db size. Confirm on the pinned
syzkaller commit during the fuzz phase and record which source was used —
`sample` prints it, and it is written into every CSV row.
"""
import argparse
import csv
import json
import math
import os
import re
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gspwn_config
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
RUNS_DIR = os.path.join(REPO_ROOT, "artifacts", "runs")
# corpus is a program count; corpus_bytes is a file size. They were once the
# same column, which made any comparison spanning a source change meaningless.
FIELDS = ["ts", "uptime_s", "edges", "corpus", "corpus_bytes", "crashes",
          "execs", "source", "gpu"]
# Columns holding text, not counts: read_rows must not run them through
# _to_int, which would turn "ok" into None and silently un-record a healthy GPU.
TEXT_FIELDS = ("source", "gpu")
TIMER_NAME = "gspwn-coverage"
TRACKS = ("k", "u")
# How long to wait for nvidia-smi before calling the driver wedged. A dead GPU
# usually fails fast; a hung one blocks, which is the case this bounds.
GPU_PROBE_TIMEOUT_S = int(os.environ.get("GSPWN_GPU_PROBE_TIMEOUT_S", "20"))
# The one GPU status that permits a plateau claim. Everything else means the
# curve cannot be trusted to say why it flattened.
GPU_OK = "ok"

# Candidate JSON endpoints, newest-style first.
JSON_PATHS = ("/stats?format=json", "/api/stats", "/stats.json")
# Dashboard HTML labels -> our field names.
HTML_FIELDS = {"edges": ("coverage", "cover", "signal", "edges"),
               "corpus": ("corpus",),
               "crashes": ("crashes",),
               "execs": ("exec total", "execs", "total execs")}


def run_dir(run_id):
    return os.path.join(RUNS_DIR, run_id)


def csv_path(run_id, track="k"):
    # Track K keeps the original name so existing runs stay readable.
    name = "coverage.csv" if track == "k" else "coverage-%s.csv" % track
    return os.path.join(run_dir(run_id), name)


def track_u_dir(run_id):
    """Where run_all.sh puts each harness's fuzzer output for this run."""
    return os.path.join(run_dir(run_id), "u")


def parse_fuzzer_stats(text):
    """AFL++ fuzzer_stats: 'key : value' lines."""
    out = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip()
    return out


def collect_u(run_id):
    """-> (row, source) for Track U, summed across the run's harnesses.

    Each harness keeps its own coverage bitmap, so edge counts are summed
    across harnesses rather than being one global number — the sum is a
    per-run trend line, not a claim about a single target's coverage.
    """
    base = track_u_dir(run_id)
    if not os.path.isdir(base):
        return {}, "unreachable"
    edges = execs = crashes = corpus = 0
    found_stats = harnesses = 0
    for name in sorted(os.listdir(base)):
        d = os.path.join(base, name)
        if not os.path.isdir(d):
            continue
        harnesses += 1
        counted_corpus = False
        stats_path = os.path.join(d, "fuzzer_stats")
        if os.path.exists(stats_path):
            try:
                with open(stats_path, errors="replace") as f:
                    st = parse_fuzzer_stats(f.read())
            except OSError:
                continue
            found_stats += 1
            edges += _to_int(st.get("edges_found")) or 0
            execs += _to_int(st.get("execs_done")) or 0
            crashes += _to_int(st.get("unique_crashes")) or 0
            n = _to_int(st.get("corpus_count"))
            if n is not None:
                corpus += n
                counted_corpus = True
        # libFuzzer harnesses write no fuzzer_stats; the corpus dir is then the
        # only signal, and it gives no edge count. AFL++ keeps its queue in the
        # same directory it writes fuzzer_stats to, so counting both would
        # double every AFL++ harness's corpus.
        if not counted_corpus:
            for sub in ("queue", "corpus"):
                p = os.path.join(d, sub)
                if os.path.isdir(p):
                    corpus += len([f for f in os.listdir(p)
                                   if os.path.isfile(os.path.join(p, f))])
    if not harnesses:
        return {}, "unreachable"
    row = {"corpus": corpus or None, "crashes": crashes or None,
           "execs": execs or None}
    if found_stats:
        row["edges"] = edges or None
        return row, "afl-fuzzer_stats:%d" % found_stats
    # No edge data: say so rather than letting corpus size stand in for it.
    return row, "corpus-count-only"


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
        # A byte size, not a program count — kept in its own column so it can
        # never be charted as if it were coverage.
        return {"corpus_bytes": os.path.getsize(db)}
    return {}


def collect(run_id, url, track="k"):
    """-> (row_dict, source). Never raises; a failed sample still records."""
    if track == "u":
        return collect_u(run_id)
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


def gpu_health(timeout=None):
    """-> (status, detail). Only GPU_OK lets a plateau verdict be claimed.

    A GPU that falls off the bus (Xid 79) does not stop the fuzzer. syz-manager
    keeps executing, the sampler keeps appending rows, the edge count stops
    moving, and `plateau` reports "plateaued" — so the loop stops and the
    write-up records a plateau that never happened. That is a broken
    measurement path producing a well-formed wrong number, the same shape as
    the dmesg_restrict bug. Recording the GPU's state next to every sample is
    what lets `plateau` refuse to make the claim.

    Statuses: ok | dead | hung | missing | error. The probe reports; it does
    not attempt recovery. `nvidia-smi -r`, a module reload and a reboot can all
    be tried by hand, and a GPU that survives none of them needs a stop/start
    from the AWS console, which nothing in this repo can do.
    """
    timeout = GPU_PROBE_TIMEOUT_S if timeout is None else timeout
    cmd = ["nvidia-smi", "--query-gpu=name,pci.bus_id", "--format=csv,noheader"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return "missing", "nvidia-smi is not on PATH"
    except subprocess.TimeoutExpired:
        return "hung", ("nvidia-smi did not return within %ds; the driver is "
                        "not answering" % timeout)
    except OSError as e:
        return "error", "could not run nvidia-smi: %s" % e
    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()
    if r.returncode != 0:
        return "dead", ("nvidia-smi exit %d: %s"
                        % (r.returncode, err or out or "no output"))
    if not out:
        return "dead", "nvidia-smi returned no GPU"
    return GPU_OK, "; ".join(line.strip() for line in out.splitlines())


def cmd_gpu_health(a):
    status, detail = gpu_health()
    print("GPU: %s (%s)" % (status, detail))
    if status != GPU_OK:
        print("A plateau verdict will read 'unknown' while the GPU is in this "
              "state, so the loop stops rather than recording a plateau the "
              "fuzzer did not actually reach.")
    return 0 if status == GPU_OK else 1


def campaign_finished(run_id):
    """True once the campaign's deadline has passed.

    The sampler timer outlives the campaign, and without this it appends an
    'unreachable' row every interval forever, padding the run's sample count
    and its apparent duration long after the fuzzing stopped.
    """
    path = os.path.join(run_dir(run_id), "deadline")
    if not os.path.exists(path):
        return False
    try:
        with open(path) as f:
            return time.time() >= float(f.read().strip())
    except (ValueError, OSError):
        return False


def registered_runs(state):
    """Run ids the pipeline knows about.

    campaign_ctl registers a run when its campaign is installed; the fuzz
    phase additionally attaches it to the round with round-add-run. Sampling
    an id outside this set is a typo, and the unattended sampler runs as
    root — it would leave a root-owned artifacts/runs/<id>/ behind that
    later confuses series/status.
    """
    ids = set()
    for r in state.get("rounds", []):
        ids.update(r.get("run_ids") or [])
    for c in state.get("campaigns", []):
        if c.get("run_id"):
            ids.add(c["run_id"])
    return ids


def cmd_sample(a):
    if a.run_id not in registered_runs(ps.load()):
        print("run %s is not registered in %s (no campaign install or "
              "round-add-run names it). Refusing to sample: a typo here "
              "would create a root-owned artifacts/runs/%s/ that later "
              "confuses series/status. Fix the id or register the run "
              "first. (A run with its own registry: use the same "
              "GSPWN_STATE its install used.)" % (a.run_id, ps.STATE_PATH, a.run_id))
        return 1
    d = run_dir(a.run_id)
    os.makedirs(d, exist_ok=True)
    if campaign_finished(a.run_id) and not a.force:
        print("run %s: campaign window has elapsed; not sampling "
              "(--force to override)" % a.run_id)
        return 0
    row, source = collect(a.run_id, a.url, a.track)
    row = {k: row.get(k) for k in FIELDS}
    row["ts"] = int(time.time())
    row["source"] = source
    gpu, gpu_detail = gpu_health()
    row["gpu"] = gpu
    path = csv_path(a.run_id, a.track)
    new = not os.path.exists(path)
    # Append under the header the file already has, not the one this version
    # would write. A run that started before the gpu column existed keeps an
    # 8-column file: writing 9 values into it would misalign every later read.
    # Those rows carry no GPU status, so plateau reads 'unknown' for them,
    # which is the safe direction.
    fields = FIELDS if new else existing_fields(path)
    try:
        with open(path, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            if new:
                w.writeheader()
            w.writerow(row)
            f.flush()
            os.fsync(f.fileno())
    except PermissionError:
        # The unattended sampler runs as root and owns the CSV, so a manual
        # check as a normal user cannot append to it. Say that instead of
        # dying with a traceback the agent has to interpret.
        print("cannot write %s — it is owned by the root sampler. Re-run this "
              "check with sudo, or read the curve with `series` instead."
              % path)
        return 1
    print("%s edges=%s corpus=%s crashes=%s (source: %s, gpu: %s)"
          % (path, row["edges"], row["corpus"], row["crashes"], source, gpu))
    if gpu != GPU_OK:
        print("WARN: GPU is %s (%s). The fuzzer keeps running on a dead GPU "
              "and the curve flattens, so plateau will report 'unknown' for "
              "any window holding this sample rather than calling it a "
              "plateau." % (gpu, gpu_detail))
    if "gpu" not in fields:
        print("WARN: %s predates the gpu column, so this sample's GPU status "
              "was not recorded. Plateau will read 'unknown' for windows over "
              "these rows." % path)
    if source == "unreachable":
        if a.track == "u":
            print("WARN: no Track U harness output under %s — the sample was "
                  "recorded empty. Confirm run_all.sh writes each harness's "
                  "output there." % track_u_dir(a.run_id))
        else:
            print("WARN: syz-manager stats unreachable at %s — the sample was "
                  "recorded empty. Check the unit is running and the http "
                  "address in the campaign config." % a.url)
        return 1
    return 0


def existing_fields(path):
    """The header a CSV already carries, or FIELDS if it has none."""
    try:
        with open(path, newline="") as f:
            header = next(csv.reader(f), None)
    except OSError:
        return FIELDS
    return header or FIELDS


def read_rows(run_id, track="k"):
    path = csv_path(run_id, track)
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        rows = []
        for r in csv.DictReader(f):
            rows.append({k: (r.get(k) if k in TEXT_FIELDS
                             else _to_int(r.get(k))) for k in FIELDS})
        return rows


def metric_rows(run_id, metric="edges", track="k"):
    """Rows carrying a usable value for the metric, oldest first."""
    return [r for r in read_rows(run_id, track) if r.get(metric) is not None]


def cmd_series(a):
    rows = read_rows(a.run_id, a.track)
    if not rows:
        print("no samples recorded for run %s track %s (expected %s)"
              % (a.run_id, a.track, csv_path(a.run_id, a.track)))
        return 1
    cov = metric_rows(a.run_id, "edges", a.track)
    span_h = (rows[-1]["ts"] - rows[0]["ts"]) / 3600.0 if len(rows) > 1 else 0.0
    print("run %s track %s: %d samples over %.1f h"
          % (a.run_id, a.track, len(rows), span_h))
    print("  sources: %s" % ", ".join(sorted({r["source"] or "?"
                                              for r in rows})))
    bad = unhealthy_gpu_samples(rows)
    if bad:
        print("  gpu: %d of %d sample(s) not healthy (%s)"
              % (sum(bad.values()), len(rows),
                 ", ".join("%s x%d" % (k, v) for k, v in sorted(bad.items()))))
    else:
        print("  gpu: healthy across all %d sample(s)" % len(rows))
    if cov:
        print("  edges: %s -> %s (+%s)"
              % (cov[0]["edges"], cov[-1]["edges"],
                 cov[-1]["edges"] - cov[0]["edges"]))
    else:
        print("  edges: never recorded — coverage claims cannot be made from "
              "this run")
    for m in ("corpus", "corpus_bytes", "crashes"):
        vals = metric_rows(a.run_id, m, a.track)
        if vals:
            print("  %s: %s -> %s" % (m, vals[0][m], vals[-1][m]))
    print("  NOTE: kernel-side reachable coverage only; GSP firmware is not "
          "instrumented.")
    return 0


def since_last_reset(rows):
    """-> (rows since the fuzzer last restarted, whether it restarted).

    Edge counts only ever climb within one fuzzer process. A drop means the
    process restarted and its counter went back to zero — which this pipeline
    causes routinely, since the units are Restart=always and the machine
    panics by design. Samples either side of that are two different counters:
    subtracting across the reset produces large negative 'growth', which reads
    as a plateau and stops a loop that is in fact climbing fast.
    """
    start = 0
    for i in range(1, len(rows)):
        if rows[i]["edges"] < rows[i - 1]["edges"]:
            start = i
    return rows[start:], start > 0


def unhealthy_gpu_samples(window):
    """-> {status: count} for every sample in the window not recording GPU_OK.

    A row from a CSV written before the gpu column existed reports None, which
    counts as unhealthy: absence of evidence that the GPU was alive is not
    evidence that it was.
    """
    bad = {}
    for r in window:
        status = r.get("gpu") or "unrecorded"
        if status != GPU_OK:
            bad[status] = bad.get(status, 0) + 1
    return bad


# ------------------------------------------------------------- discovery ---
# Coverage growth is a species-discovery process: each edge is a species, each
# executed input a sampled individual, and distinct-edges-against-inputs is a
# species accumulation curve. That framing is Böhme's (STADS: Software Testing
# as Species Discovery, TOSEM 2018) and it is what makes the question
# answerable rather than a matter of taste.
#
# What it buys here and what it does not. The estimators the framing is known
# for — Good-Turing discovery probability, Chao1 richness — need per-species
# frequency counts: how many edges were hit exactly once (f1), exactly twice
# (f2). syz-manager's stats endpoint reports an aggregate edge count and
# nothing per-edge, so those estimators cannot be computed from this data and
# this module does not pretend to. Anything claiming "we have covered X% of
# the driver" would need f1 and f2 and would be invented here.
#
# What the aggregate series does support is a fitted accumulation curve and an
# extrapolation from it, which is the question the loop actually asks: not
# "how much is left" but "is another campaign of this length worth running".
#
# Two corrections to the obvious approach, both of which changed verdicts on
# real-shaped data:
#
# 1. The x axis is executions, not wall-clock. Fuzzing progress is driven by
#    inputs executed. This box panics by design, so a fixed wall-clock window
#    can contain wildly different amounts of actual testing, and a slow or
#    frequently-restarting hour looks exactly like saturation.
#
# 2. The y axis is the running maximum, not the reported count. syzkaller
#    reloads and re-executes its corpus after every restart, so the edge count
#    climbs steeply back towards where it was. That climb is replay, not
#    discovery. Measured naively, a run that has genuinely saturated reports
#    tens of percent of growth after each panic — which on this machine means
#    a dead campaign can keep itself alive indefinitely through its own
#    crashes. Accumulating with max() makes replay contribute exactly zero.
#
#    max() is a conservative estimate of the union: a post-restart process
#    could cover an edge the earlier one missed while its total is still
#    lower, and that edge is not counted. The bias is towards under-reporting
#    discovery, which is the direction that stops a campaign early rather than
#    running one forever, and it is stated here because it is a real limit of
#    working from an aggregate counter.


def _coverage_cfg():
    """The stopping rule's tunables, or the defaults if config is unreadable.

    Unlike the loop caps, a missing config here must not stop the tool: this
    is called from plateau_verdict, which several other tools call in turn,
    and the defaults are the same values the shipped config carries.
    """
    try:
        return gspwn_config.coverage()
    except Exception:
        return dict(gspwn_config.DEFAULTS["coverage"])


def accumulate(rows):
    """-> [(cum_execs|None, cum_edges)], the species accumulation curve.

    Both counters reset when the fuzzer restarts. Executions are work done, so
    they accumulate: a reset means the delta is the new reading itself, not a
    negative number. Edges are a set, not an amount of work, so they
    accumulate as a running maximum — see the note above on replay.
    """
    out = []
    cum_execs = 0
    prev_execs = None
    best = 0
    have_execs = True
    for r in rows:
        edges = r.get("edges")
        if edges is None:
            continue
        best = max(best, edges)
        execs = r.get("execs")
        if execs is None:
            have_execs = False
        elif have_execs:
            if prev_execs is None or execs < prev_execs:
                cum_execs += execs      # first sample, or a counter reset
            else:
                cum_execs += execs - prev_execs
            prev_execs = execs
        out.append((cum_execs if have_execs else None, best))
    return out


def _ols(xs, ys):
    """Least-squares fit of y = slope*x + intercept -> (slope, intercept, r2).

    Returns None when the fit is degenerate (fewer than three points, or no
    spread in x or y), rather than a slope of zero that would read as a
    perfectly flat and perfectly trusted curve.
    """
    n = len(xs)
    if n < 3:
        return None
    mx = sum(xs) / n
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    if sxx <= 0 or syy <= 0:
        return None
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    slope = sxy / sxx
    intercept = my - slope * mx
    r2 = (sxy * sxy) / (sxx * syy)
    return slope, intercept, r2


def fit_tail(points, fraction):
    """The last `fraction` of the run measured in executions, not samples.

    The decision is about what the next campaign will find, so it has to
    reflect the regime the fuzzer is in now. A power law fitted over a whole
    run is dominated by the early steep phase, where syzkaller is still
    working through the seeds, and a run that climbed hard and then went
    completely flat would still report a healthy exponent. Cutting by
    executions rather than by sample count means a stretch where the box was
    panicking and doing little work does not count as recent history.
    """
    pts = [(n, s) for n, s in points if n and n > 0 and s and s > 0]
    if not pts or not (0 < fraction < 1):
        return pts
    cutoff = pts[-1][0] * (1.0 - fraction)
    return [p for p in pts if p[0] >= cutoff] or pts


def heaps_fit(points):
    """Fit S(n) = K * n**beta to (executions, edges) -> dict, or None.

    Heaps' law rather than an exponential saturation curve, because an
    exponential assumes a finite asymptote and reporting one from this data
    would be exactly the over-claim this module avoids. beta is the discovery
    exponent: near 1 the run finds edges about as fast as it executes them,
    near 0 it has saturated. Fitted by least squares on log S against log n,
    which needs no dependency beyond the standard library.
    """
    pts = [(n, s) for n, s in points if n and n > 0 and s and s > 0]
    if len(pts) < 3:
        return None
    fit = _ols([math.log(n) for n, _ in pts], [math.log(s) for _, s in pts])
    if fit is None:
        return None
    beta, log_k, r2 = fit
    return {"beta": beta, "k": math.exp(log_k), "r2": r2,
            "n": pts[-1][0], "s": pts[-1][1], "points": len(pts)}


def expected_new_edges(fit, extra_execs):
    """Edges the fitted curve expects from `extra_execs` more executions.

    K((n + dn)**beta - n**beta). This is the number the loop decides on: it is
    in the same units as the thing being predicted, unlike a growth
    percentage, whose meaning changes with how much coverage there already is.
    """
    if not fit or extra_execs <= 0:
        return 0.0
    n, k, b = fit["n"], fit["k"], fit["beta"]
    return max(0.0, k * ((n + extra_execs) ** b - n ** b))


def exec_rate_per_hour(rows):
    """Executions per hour over the sampled span, or None if unmeasurable."""
    acc = accumulate(rows)
    if len(acc) < 2 or acc[-1][0] is None:
        return None
    span_h = (rows[-1]["ts"] - rows[0]["ts"]) / 3600.0
    if span_h <= 0:
        return None
    return acc[-1][0] / span_h


def _legacy_window_verdict(rows, acc, window_min, min_growth, why):
    """The pre-model test, on the accumulation curve, for runs with no execs.

    Kept because a source that does not report an execution count still has to
    produce a verdict, and because the accumulation curve alone already fixes
    the replay error. It is reported as a degraded measurement: a wall-clock
    window cannot tell a slow hour from a saturated one, which is the whole
    reason the model path exists.
    """
    span_min = (rows[-1]["ts"] - rows[0]["ts"]) / 60.0
    if span_min < window_min:
        return "unknown", ("%.0f min of samples, shorter than the %d min "
                           "window" % (span_min, window_min))
    cutoff = rows[-1]["ts"] - window_min * 60
    window = [(r, s) for (r, (_n, s)) in zip(rows, acc) if r["ts"] >= cutoff]
    if len(window) < 2:
        return "unknown", "only %d sample(s) inside the window" % len(window)
    start, end = window[0][1], window[-1][1]
    if not start:
        return "unknown", "no non-zero edge baseline in the window"
    growth = (end - start) / float(start)
    detail = ("%s: distinct edges %d -> %d over %.0f min = %.3f%% growth "
              "(threshold %.3f%%)"
              % (why, start, end, window_min, growth * 100, min_growth * 100))
    return ("growing" if growth >= min_growth else "plateaued"), detail


def plateau_verdict(rows, window_min, min_growth, horizon_hours=None,
                    cov=None):
    """-> (verdict, detail). The decision is an extrapolation, not a threshold.

    The question is whether another campaign is worth running, so the answer
    is the number of new edges the fitted discovery curve expects from another
    campaign's worth of executions. That number is in the units of the thing
    being predicted; a growth percentage is not, because the same percentage
    means ten edges early in a run and a thousand late in one.

    'unknown' is a real answer and the loop treats it as a stop, so a broken
    sampler cannot silently authorise more spend. It is returned for too few
    samples, no edge data, no execution data plus too short a span, and — the
    case a threshold rule has no way to express — a curve the model does not
    describe well enough to extrapolate from.

    A flat curve over a window where the GPU was not healthy is also
    'unknown'. A GPU that has fallen off the bus flattens the curve exactly
    like a genuine plateau, and only the plateau reading gets written into the
    report as a finding about the target. The GPU check gates that reading
    alone: 'growing' needs no such guard, because coverage cannot climb on a
    GPU that is not answering, so growth is its own evidence the probe was
    only having a bad moment.
    """
    cov = cov if cov is not None else _coverage_cfg()
    if len(rows) < 3:
        return "unknown", "only %d usable sample(s); need >= 3" % len(rows)
    acc = accumulate(rows)
    if not acc:
        return "unknown", "no edge data in any sample"
    _seg, restarted = since_last_reset(rows)
    note = "; the fuzzer restarted during this run, so replay is excluded " \
           "and only edges beyond the previous high-water mark count" \
        if restarted else ""

    # Still recovering. After a restart syzkaller re-executes its corpus, and
    # until the reported count climbs back to where it was, every edge it
    # reports is one already covered. The accumulation curve is flat through
    # that phase, but flat-because-replaying is not the same as
    # flat-because-saturated and must not be reported as a plateau. It is also
    # not growth. The honest answer is that the round ended before the fuzzer
    # got back to where it had been, and no verdict is available.
    high_water = acc[-1][1]
    latest = rows[-1].get("edges")
    if latest is not None and high_water and latest < high_water:
        return "unknown", (
            "the fuzzer is still replaying its corpus after a restart: it "
            "reports %d edges against a high-water mark of %d for this run, "
            "so it has rediscovered nothing new yet. A flat accumulation "
            "curve here means recovery, not saturation. Let the run reach %d "
            "again before asking, or treat the round as unmeasured"
            % (latest, high_water, high_water))

    tail = fit_tail(acc, cov["fit_tail_fraction"])
    rate = exec_rate_per_hour(rows)
    horizon_h = horizon_hours if horizon_hours else cov["horizon_hours"]

    # No new edge at all across the recent stretch of work. This is the
    # clearest plateau there is, and it has to be handled before the fit,
    # because a curve with no variance in S cannot be fitted at all and would
    # otherwise fall through to the weaker clock-based test.
    #
    # `rate is not None` is what makes "the recent stretch" mean the end of the
    # run. accumulate() stops carrying an execution axis at the first sample
    # that reports no exec count and never resumes, so if the source stopped
    # reporting them mid-run the tail covers only the prefix. Without this
    # guard a run whose first hours were flat and whose last hours quadrupled
    # its coverage reports a plateau, quoting the flat prefix as though it were
    # the whole run — and the loop stops a campaign that is still learning.
    flat_tail = (rate is not None and len(tail) >= cov["min_fit_samples"]
                 and tail[-1][0] and len({s for _n, s in tail}) == 1)
    fit = None if flat_tail else heaps_fit(tail)

    if flat_tail:
        verdict = "plateaued"
        detail = ("no new edge in the last %.3g executions (%d distinct "
                  "edges throughout, over %d samples). Not one input in that "
                  "stretch reached code the run had not already reached%s"
                  % (tail[-1][0] - tail[0][0], tail[-1][1], len(tail), note))
    elif fit is None or rate is None:
        # rate is None exactly when the run recorded no usable execution
        # counts, which is also when heaps_fit has nothing to fit, so this one
        # branch covers both.
        verdict, detail = _legacy_window_verdict(
            rows, acc, window_min, min_growth,
            "no execution counts recorded, so growth is measured against the "
            "clock rather than against work done")
        detail += note
    elif fit["points"] < cov["min_fit_samples"]:
        return "unknown", ("only %d sample(s) usable for a discovery fit; "
                           "need >= %d before extrapolating%s"
                           % (fit["points"], cov["min_fit_samples"], note))
    elif fit["r2"] < cov["model_min_r2"]:
        # The curve is not a discovery curve: a stuck sampler, a source
        # change mid-run, or a phase the model does not cover. Extrapolating
        # anyway is how a confident wrong number gets into a report.
        return "unknown", ("the discovery curve does not fit the model well "
                           "enough to extrapolate from (R2 %.3f, need %.2f; "
                           "beta %.3f over %d sample(s)). Plot the series "
                           "before trusting any verdict here%s"
                           % (fit["r2"], cov["model_min_r2"], fit["beta"],
                              fit["points"], note))
    elif not (0 < fit["beta"] <= 1.0 + cov["beta_tolerance"]):
        return "unknown", ("discovery exponent beta=%.3f is outside (0, 1]; "
                           "the series is not behaving like an accumulation "
                           "curve, so no extrapolation from it is "
                           "meaningful%s" % (fit["beta"], note))
    else:
        horizon_execs = rate * horizon_h
        expected = expected_new_edges(fit, horizon_execs)
        # The relative figure is reported alongside because the absolute
        # threshold is the one number here still uncalibrated: what counts as
        # enough new edges to justify another campaign is a judgement, and
        # 2.5% of a run's coverage reads very differently from 37%.
        share = (100.0 * expected / fit["s"]) if fit["s"] else 0.0
        detail = ("%d distinct edges after %.3g executions; beta %.3f, R2 "
                  "%.3f over %d samples. At %.3g exec/h another %.0f h is "
                  "expected to find ~%.0f new edge(s), %.1f%% more (plateau "
                  "below %d)%s"
                  % (fit["s"], fit["n"], fit["beta"], fit["r2"],
                     fit["points"], rate, horizon_h, expected, share,
                     cov["plateau_new_edges"], note))
        verdict = ("growing" if expected >= cov["plateau_new_edges"]
                   else "plateaued")

    if verdict != "plateaued":
        return verdict, detail
    cutoff = rows[-1]["ts"] - window_min * 60
    window = [r for r in rows if r["ts"] >= cutoff] or rows
    bad = unhealthy_gpu_samples(window)
    if bad:
        return "unknown", (
            "%s, but the GPU was not healthy for %d of %d sample(s) in the "
            "window (%s). A dead GPU flattens the curve the same way a real "
            "plateau does, so this is not reported as a plateau. Check "
            "`coverage_ctl.py gpu-health` and the run's Xid entries before "
            "deciding the round is done."
            % (detail, sum(bad.values()), len(window),
               ", ".join("%s x%d" % (k, v) for k, v in sorted(bad.items()))))
    return "plateaued", detail


def run_verdict(run_id, window_min, min_growth, tracks=TRACKS,
                horizon_hours=None):
    """Per-track verdicts plus the combined one for the loop decision.

    A round is still learning if ANY track is still finding edges: stopping
    because Track K flattened while the container-toolkit harnesses were
    still growing would end the campaign early. Tracks with no edge data at
    all are ignored rather than forcing 'unknown' — but if no track has data,
    the answer is 'unknown', which stops the loop.
    """
    per = {}
    for t in tracks:
        rows = metric_rows(run_id, "edges", t)
        if not read_rows(run_id, t):
            continue          # track not sampled at all: not evidence either way
        per[t] = plateau_verdict(rows, window_min, min_growth,
                                 horizon_hours=horizon_hours)
    decided = [v for v, _ in per.values() if v != "unknown"]
    if "growing" in decided:
        combined = "growing"
    elif "plateaued" in decided:
        combined = "plateaued"
    else:
        combined = "unknown"
    detail = "; ".join("%s: %s (%s)" % (t, v, d)
                       for t, (v, d) in sorted(per.items())) or "no samples"
    return combined, detail, per


def cmd_plateau(a):
    if a.track:
        rows = metric_rows(a.run_id, "edges", a.track)
        verdict, detail = plateau_verdict(rows, a.window_min, a.min_growth,
                                          horizon_hours=a.horizon_hours)
        print("%s track %s: %s (%s)" % (a.run_id, a.track, verdict, detail))
    else:
        verdict, detail, _ = run_verdict(a.run_id, a.window_min, a.min_growth,
                                         horizon_hours=a.horizon_hours)
        print("%s: %s (%s)" % (a.run_id, verdict, detail))
    print("Coverage is kernel-side reachable code only; GSP firmware is not "
          "instrumented, so no verdict here says anything about it.")
    return {"growing": 0, "unknown": 1, "plateaued": 3}[verdict]


def cmd_compare(a):
    for rid in (a.run_id, a.against):
        rows = metric_rows(rid, "edges", a.track)
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


# Samples both tracks on one timer. The campaign deadline is enforced by its
# own per-run timer (gspwn-deadline@<run-id>.timer, installed by campaign_ctl
# install-k/install-u), so the spend ceiling holds even if the sampler is
# never installed or is removed mid-run.
# `-` prefixes mean a failure sampling one track does not suppress the other.
SERVICE_UNIT = """[Unit]
Description=gspwn coverage sampler ({run_id})

[Service]
Type=oneshot
{env}ExecStart=-/usr/bin/python3 {root}/tools/coverage_ctl.py sample \\
  --run-id {run_id} --url {url}
ExecStart=-/usr/bin/python3 {root}/tools/coverage_ctl.py sample \\
  --run-id {run_id} --track u
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
    if a.run_id not in registered_runs(ps.load()):
        sys.exit("run %s is not registered in %s — install the campaign "
                 "first (campaign_ctl install-k/install-u registers it). A "
                 "typo here would create a root-owned run dir the sampler "
                 "then pads with empty rows." % (a.run_id, ps.STATE_PATH))
    os.makedirs(run_dir(a.run_id), exist_ok=True)
    # A run may keep its own pipeline.json via GSPWN_STATE; the
    # unattended sampler must validate and record against that same registry,
    # so the unit carries the setting the install was made with.
    env = ""
    if os.environ.get("GSPWN_STATE"):
        env = "Environment=GSPWN_STATE=%s\n" % ps.STATE_PATH
    with open("/etc/systemd/system/%s.service" % TIMER_NAME, "w") as f:
        f.write(SERVICE_UNIT.format(root=REPO_ROOT, run_id=a.run_id,
                                    url=a.url, env=env))
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
    # Derived from track_k.http rather than repeated here: a sampler holding
    # its own copy of the address kept polling the old port after the config
    # changed and recorded the whole campaign as unreachable.
    try:
        conf = gspwn_config.load()
    except gspwn_config.ConfigError as e:
        sys.exit("error: %s" % e)
    default_url = gspwn_config.manager_url()
    loop_cfg = conf["loop"]

    p = sub.add_parser("sample")
    p.add_argument("--run-id", required=True)
    p.add_argument("--url", default=default_url)
    p.add_argument("--track", choices=TRACKS, default="k")
    p.add_argument("--force", action="store_true",
                   help="sample even after the campaign window has elapsed")
    p.set_defaults(fn=cmd_sample)

    p = sub.add_parser("install-timer")
    p.add_argument("--run-id", required=True)
    p.add_argument("--url", default=default_url)
    p.add_argument("--interval-min", type=int,
                   default=loop_cfg["coverage_sample_min"])
    p.set_defaults(fn=cmd_install_timer)

    p = sub.add_parser("remove-timer")
    p.set_defaults(fn=cmd_remove_timer)

    p = sub.add_parser("series")
    p.add_argument("--run-id", required=True)
    p.add_argument("--track", choices=TRACKS, default="k")
    p.set_defaults(fn=cmd_series)

    p = sub.add_parser("plateau")
    p.add_argument("--run-id", required=True)
    p.add_argument("--track", choices=TRACKS,
                   help="one track; omit to combine both (the loop's view)")
    p.add_argument("--window-min", type=int,
                   default=loop_cfg["plateau_window_min"],
                   help="trailing window to measure growth over "
                        "(default loop.plateau_window_min)")
    p.add_argument("--min-growth", type=float,
                   default=loop_cfg["plateau_min_growth"],
                   help="fractional edge growth below which the run has "
                        "plateaued. Only used for runs whose source records "
                        "no execution count; otherwise the verdict comes "
                        "from the fitted discovery curve "
                        "(default loop.plateau_min_growth)")
    p.add_argument("--horizon-hours", dest="horizon_hours", type=float,
                   default=None,
                   help="how far ahead to extrapolate: the run has plateaued "
                        "when this many more hours is expected to find fewer "
                        "than coverage.plateau_new_edges new edges "
                        "(default coverage.horizon_hours)")
    p.set_defaults(fn=cmd_plateau)

    p = sub.add_parser("gpu-health")
    p.set_defaults(fn=cmd_gpu_health)

    p = sub.add_parser("compare")
    p.add_argument("--run-id", required=True)
    p.add_argument("--against", required=True)
    p.add_argument("--track", choices=TRACKS, default="k")
    p.set_defaults(fn=cmd_compare)
    return ap


def main():
    a = build_parser().parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
