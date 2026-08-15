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
                                       verdict: growing | plateaued | unknown
                                       (omit --track for the combined view)
                                       exit 0 growing, 3 plateaued, 1 unknown
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


def plateau_verdict(rows, window_min, min_growth):
    """-> (verdict, detail). Growth is measured over the trailing window.

    'unknown' is a real answer: too few samples, too short a window, no edge
    data, or not enough data since a restart means we must not claim a
    plateau. The loop treats unknown as a stop, so a broken sampler cannot
    silently authorise more spend.

    A flat curve over a window where the GPU was not healthy is also
    'unknown'. A GPU that has fallen off the bus flattens the curve exactly
    like a genuine plateau, and only the plateau reading gets written into the
    report as a finding about the target. The GPU check gates that reading
    alone: 'growing' needs no such guard, because coverage cannot climb on a
    GPU that is not answering, so growth is its own evidence the probe was
    only having a bad moment.
    """
    if len(rows) < 3:
        return "unknown", "only %d usable sample(s); need >= 3" % len(rows)
    rows, restarted = since_last_reset(rows)
    if restarted and len(rows) < 3:
        return "unknown", ("only %d usable sample(s) since the fuzzer last "
                           "restarted; need >= 3 since the restart to "
                           "measure growth" % len(rows))
    span_min = (rows[-1]["ts"] - rows[0]["ts"]) / 60.0
    if span_min < window_min:
        return "unknown", ("%s%.0f min of samples, shorter than the %d min "
                           "window"
                           % ("the fuzzer restarted and there is only "
                              if restarted else "samples span ",
                              span_min, window_min))
    cutoff = rows[-1]["ts"] - window_min * 60
    window = [r for r in rows if r["ts"] >= cutoff]
    if len(window) < 2:
        return "unknown", "only %d sample(s) inside the window" % len(window)
    start, end = window[0]["edges"], window[-1]["edges"]
    if not start:
        return "unknown", "no non-zero edge baseline in the window"
    growth = (end - start) / float(start)
    detail = ("edges %d -> %d over %.0f min = %.3f%% growth (threshold %.3f%%)"
              "%s" % (start, end, window_min, growth * 100, min_growth * 100,
                      "; measured since a fuzzer restart" if restarted else ""))
    if growth >= min_growth:
        return "growing", detail
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


def run_verdict(run_id, window_min, min_growth, tracks=TRACKS):
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
        per[t] = plateau_verdict(rows, window_min, min_growth)
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
        verdict, detail = plateau_verdict(rows, a.window_min, a.min_growth)
        print("%s track %s: %s (%s)" % (a.run_id, a.track, verdict, detail))
    else:
        verdict, detail, _ = run_verdict(a.run_id, a.window_min, a.min_growth)
        print("%s: %s (%s)" % (a.run_id, verdict, detail))
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
                        "plateaued (default loop.plateau_min_growth)")
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
