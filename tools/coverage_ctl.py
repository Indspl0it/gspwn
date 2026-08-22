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
  sample --run-id ID [--track k|u] [--url URL] [--force] [--skip-surface]
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
  completion [--run-id ID ...] [--corpus DIR] [--ledger PATH] [--top N]
                                       the ledger identity: is every target
                                       either exercised or accounted for?
                                       exit 0 complete, 3 incomplete, 1 unknown
  migrate-csv --run-id ID [--track k|u]
                                       add the columns a CSV's header lacks to
                                       it, so a run that started before a
                                       column existed can record one. Rewrites
                                       the file, so stop the sampler first
  compare --run-id A --against B [--track k|u]
                                       side-by-side endpoints (two runs)
  gpu-health                           probe the GPU now; exit 0 healthy, 1 not

TWO CURVES, NOT ONE. The edge curve answers whether the fuzzer is still
finding code. It cannot answer whether the commands it was told about have
been tried, because the driver's edge space has no known size. The surface
curve does: `tools/surface_cov.py` counts how many of the 764 enumerated
targets a corpus names, and that denominator is counted rather than estimated.
Both are sampled here, and the loop's stop rule reads them together with the
completion ledger:

  edge flat, surface climbing    not a plateau; the round is still reaching
                                 commands it had not reached
  both flat, ledger open         the corpus is stuck: the fuzzer stopped
                                 finding edges while modelled targets remain
                                 unreached, which is a resource-chain problem
  both flat, ledger closed       complete; nothing is left to fuzz

The surface column carries no fitted curve. Heaps' law is fitted to the edge
series because the edge space has no known asymptote; the surface series has
a counted one, at 764, and an unbounded power law fitted to a bounded quantity
predicts more new targets than remain. The surface reading is subtraction.

Coverage is kernel-side reachable code only. GSP firmware is not instrumented;
every consumer of these numbers must say so.

Every Track K sample records the GPU's state alongside the counters. A GPU that
has fallen off the bus does not stop the fuzzer: the curve simply flattens, and
without that column a plateau verdict cannot tell a finished round from a dead
card. `plateau` refuses to call a flat window a plateau when the GPU was not
healthy across it. Track U records the column as `n/a`, because those harnesses
run in a container and never touch the GPU, so gating their verdict on its
health would report a real plateau as unknown.

Every sample also records free disk space. Kernel dumps, the corpus, these
CSVs and the agent's transcript share one filesystem, and a full disk stops the
fuzzer, the sampler and every state write at the same moment.

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
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gspwn_config
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
RUNS_DIR = os.path.join(REPO_ROOT, "artifacts", "runs")
# corpus is a program count; corpus_bytes is a file size. They were once the
# same column, which made any comparison spanning a source change meaningless.
# surface is appended, never inserted: the column order of every file already
# on disk has to survive, because anything reading one with `cut -d,` counts
# positions. It is an integer, so it stays out of TEXT_FIELDS.
FIELDS = ["ts", "uptime_s", "edges", "corpus", "corpus_bytes", "crashes",
          "execs", "source", "gpu", "disk_free_mb", "surface"]
# Columns holding text, not counts: read_rows must not run them through
# _to_int, which would turn "ok" into None and silently un-record a healthy GPU.
TEXT_FIELDS = ("source", "gpu")
# The surface column's two knobs live in config/campaign.yaml's coverage
# section as surface_sample_min and surface_min_samples. See _int_env and
# surface_sample_min() below for how they are read.
TIMER_NAME = "gspwn-coverage"
TRACKS = ("k", "u")
# The one GPU status that permits a plateau claim. Everything else means the
# curve cannot be trusted to say why it flattened.
GPU_OK = "ok"
# Recorded instead of a status for Track U. The container-toolkit harnesses
# never touch the GPU, so gating their plateau verdict on its health reports a
# genuine Track U plateau as 'unknown' for a reason that has nothing to do
# with the target being measured.
GPU_NOT_APPLICABLE = "n/a"

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


def collect_surface(run_id):
    """-> (count, note). How many of the enumerated targets this run reaches.

    Same contract as collect(): never raises, so a failed surface read still
    lets the row be written with every other column intact. A missing syz-db,
    a corpus.db syz-manager is midway through rewriting and an unpack failure
    all yield None, and None is dropped from the curve rather than charted as
    a fall to zero.

    syz-manager's stats endpoint cannot answer this. It holds no model of the
    764 targets, so the count comes from the corpus text itself: unpack the
    run's corpus.db and match variant names against the inventories.
    """
    try:
        import surface_cov
    except ImportError as exc:
        return None, "surface_cov unavailable: %s" % exc
    try:
        targets, _excluded, meta, _modelled, exercised = surface_cov.measure(
            surface_cov.DEFAULT_DESC, run_id=run_id)
    except Exception as exc:
        return None, "surface not measured: %s" % exc
    return (len([v for v in targets if v in exercised]),
            "%d program(s) in %s" % (meta["corpus_programs"], meta["corpus"]))


def surface_due(run_id, track, path, interval_min=None):
    """-> (should sample, why not). The cadence gate for the surface column.

    The CSV is its own memory here: the last row carrying a surface value is
    the last time it was measured, so the cadence survives a sampler restart
    and a reboot without any state of its own.
    """
    if track != "k":
        # Track U produces no syzlang programs, so it has no surface to
        # measure. Recording a 0 would put an absence of evidence into the
        # curve as a measurement, the same error GPU_NOT_APPLICABLE avoids.
        return False, "track u produces no syzlang programs"
    # Storability before cadence. A CSV written before the surface column
    # existed keeps its own header for the rest of the run, so a value
    # measured now is written into a DictWriter that drops it. Measuring
    # anyway costs an unpack and a full rescan of a corpus.db syz-manager is
    # concurrently rewriting, every sample, for nothing. `migrate-csv` adds
    # the column to such a file; until it is run there is nothing to measure
    # into.
    if os.path.exists(path) and "surface" not in existing_fields(path):
        return False, ("%s predates the surface column, so a measurement "
                       "cannot be stored in it. Add the column with: python3 "
                       "tools/coverage_ctl.py migrate-csv --run-id %s"
                       % (path, run_id))
    interval = surface_sample_min() if interval_min is None else interval_min
    if interval <= 0:
        return True, ""
    if not os.path.exists(path):
        return True, ""
    rows = [r for r in read_rows(run_id, "k") if r.get("surface") is not None]
    if not rows:
        return True, ""
    age_min = (time.time() - (rows[-1]["ts"] or 0)) / 60.0
    if age_min >= interval:
        return True, ""
    return False, ("last measured %.0f min ago, under the %d min surface "
                   "interval" % (age_min, interval))


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
    if timeout is None:
        timeout = _coverage_cfg()["gpu_probe_timeout_sec"]
    cmd = ["nvidia-smi", "--query-gpu=name,pci.bus_id", "--format=csv,noheader"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return "missing", "nvidia-smi is not on PATH"
    except subprocess.TimeoutExpired:
        return "hung", ("nvidia-smi did not return within %ds, so the driver "
                        "is not answering" % timeout)
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


def disk_free_mb(path=None):
    """Free megabytes on the filesystem holding the artifacts, or None.

    Everything this pipeline produces lands on one disk: kernel dumps copied
    out of /var/crash, the corpus, the coverage CSVs and the agent's own
    transcript. A full disk stops the fuzzer, the sampler and every state
    write at the same moment, and nothing else here would notice until they
    all started failing at once.
    """
    try:
        st = os.statvfs(path or REPO_ROOT)
    except (OSError, AttributeError):
        return None
    return int(st.f_bavail * st.f_frsize / 1048576)


def disk_warning(free_mb=None):
    """A warning line when free space is under loop.min_free_disk_gb, else ''."""
    free_mb = disk_free_mb() if free_mb is None else free_mb
    if free_mb is None:
        return ""
    try:
        floor_gb = gspwn_config.loop()["min_free_disk_gb"]
    except Exception:
        floor_gb = gspwn_config.DEFAULTS["loop"]["min_free_disk_gb"]
    if not floor_gb or free_mb >= floor_gb * 1024:
        return ""
    return ("WARN: %.1f GB free, under loop.min_free_disk_gb (%s GB). A full "
            "disk stops the fuzzer, the sampler and every state write at "
            "once. Prune harvested crash dirs (crashlog_ctl.py prune) or "
            "grow the volume before it runs out."
            % (free_mb / 1024.0, floor_gb))


def cmd_gpu_health(a):
    status, detail = gpu_health()
    print("GPU: %s (%s)" % (status, detail))
    if status != GPU_OK:
        print("A plateau verdict will read 'unknown' while the GPU is in this "
              "state, so the loop stops without recording a plateau the "
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
        print("run %s: campaign window has elapsed, so this call is not "
              "sampling (--force to override)" % a.run_id)
        return 0
    row, source = collect(a.run_id, a.url, a.track)
    row = {k: row.get(k) for k in FIELDS}
    row["ts"] = int(time.time())
    row["source"] = source
    # Track U harnesses run in a container and never touch the GPU, so its
    # health says nothing about why their curve flattened. Probing anyway also
    # spends the probe timeout on every sample of a track that cannot use the
    # answer.
    if a.track == "k":
        gpu, gpu_detail = gpu_health()
    else:
        gpu, gpu_detail = GPU_NOT_APPLICABLE, "track u does not use the GPU"
    row["gpu"] = gpu
    row["disk_free_mb"] = disk_free_mb()
    path = csv_path(a.run_id, a.track)
    new = not os.path.exists(path)
    surface_note = ""
    # getattr, not attribute access: cmd_sample is called programmatically as
    # well as from the parser, and a caller built before this flag existed must
    # keep working rather than dying on a missing attribute.
    if getattr(a, "skip_surface", False):
        surface_note = "skipped (--skip-surface)"
    else:
        due, why = surface_due(a.run_id, a.track, path)
        if due:
            row["surface"], surface_note = collect_surface(a.run_id)
        else:
            surface_note = why
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
        print("cannot write %s, which is owned by the root sampler. Re-run "
              "this check with sudo, or read the curve with `series`."
              % path)
        return 1
    print("%s edges=%s surface=%s corpus=%s crashes=%s (source: %s, gpu: %s)"
          % (path, row["edges"], row["surface"], row["corpus"], row["crashes"],
             source, gpu))
    if surface_note:
        print("  surface: %s" % surface_note)
    warning = disk_warning(row["disk_free_mb"])
    if warning:
        print(warning)
    if gpu not in (GPU_OK, GPU_NOT_APPLICABLE):
        print("WARN: GPU is %s (%s). The fuzzer keeps running on a dead GPU "
              "and the curve flattens, so plateau will report 'unknown' for "
              "any window holding this sample and will not call it a plateau." % (gpu, gpu_detail))
    if "gpu" not in fields:
        print("WARN: %s predates the gpu column, so this sample's GPU status "
              "was not recorded. Plateau will read 'unknown' for windows over "
              "these rows." % path)
    if "surface" not in fields:
        # The writer appends under the header the file has, so a value
        # measured for such a file is dropped. surface_due refuses the
        # measurement for that reason, and `migrate-csv` is the one path that
        # adds the column: it rewrites the file, so it is an operator step run
        # once and not something a sample does under the root sampler.
        print("WARN: %s predates the surface column, so this run has no "
              "surface curve and the two-curve stop rule reads 'unknown' for "
              "it. Add the column with: python3 tools/coverage_ctl.py "
              "migrate-csv --run-id %s" % (path, a.run_id))
    if source == "unreachable":
        if a.track == "u":
            print("WARN: no Track U harness output under %s, so the sample "
                  "was recorded empty. Confirm run_all.sh writes each "
                  "harness's output there." % track_u_dir(a.run_id))
        else:
            print("WARN: syz-manager stats unreachable at %s, so the sample "
                  "was recorded empty. Check the unit is running and the http "
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


def migrate_csv(path, fields=None):
    """Add the columns `path`'s header lacks -> (columns added, rows kept).

    A sample only ever appends, and it appends under the header the file
    already carries, so a run started before a column existed records nothing
    in that column for the rest of its life. This is the one operation on a
    coverage.csv that is not an append: it rewrites the file with the missing
    columns and every existing row padded.

    Existing columns keep their positions and their values, so a header this
    version does not know about survives untouched and anything reading the
    file by column index still reads the same numbers.

    A sample landing mid-rewrite would be dropped, because the rows were read
    before it arrived. The window is the length of one rewrite against a
    cadence in minutes, and it is closed rather than argued about: the file's
    size is read before and after, and a change aborts with the file
    untouched. It is an operator step for that reason and never something a
    sample does on its own.
    """
    fields = fields or FIELDS
    existing = existing_fields(path)
    missing = [f for f in fields if f not in existing]
    if not missing:
        return [], 0
    size = os.path.getsize(path)
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    header = list(existing) + missing
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", newline="") as out:
            w = csv.DictWriter(out, fieldnames=header, extrasaction="ignore")
            w.writeheader()
            for row in rows:
                w.writerow({k: ("" if row.get(k) is None else row[k])
                            for k in header})
            out.flush()
            os.fsync(out.fileno())
        if os.path.getsize(path) != size:
            raise RuntimeError(
                "%s grew while it was being rewritten, so a sample landed "
                "that this rewrite would drop. Nothing was changed. Stop the "
                "sampler (systemctl stop gspwn-coverage.timer) and run this "
                "again" % path)
        # The sampler owns the file and appends to it as root; mkstemp makes
        # its file 0600 and owned by whoever ran this, so the mode has to be
        # carried over or the next sample writes into a file it cannot read
        # back.
        os.chmod(tmp, stat.S_IMODE(os.stat(path).st_mode))
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    ps._fix_root_ownership([path])
    return missing, len(rows)


def cmd_migrate_csv(a):
    for track in (TRACKS if a.track is None else [a.track]):
        path = csv_path(a.run_id, track)
        if not os.path.exists(path):
            print("%s: no file" % path)
            continue
        try:
            added, kept = migrate_csv(path)
        except (OSError, RuntimeError) as e:
            print("%s: %s" % (path, e))
            return 1
        if added:
            print("%s: added %s over %d row(s), which record no value for "
                  "them" % (path, ", ".join(added), kept))
        else:
            print("%s: already carries every column" % path)
    return 0


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
    elif all(r.get("gpu") == GPU_NOT_APPLICABLE for r in rows):
        print("  gpu: not applicable (these harnesses do not use the GPU)")
    else:
        print("  gpu: healthy across all %d sample(s)" % len(rows))
    free = [r["disk_free_mb"] for r in rows if r.get("disk_free_mb")]
    if free:
        print("  disk free: %.1f GB -> %.1f GB (low water %.1f GB)"
              % (free[0] / 1024.0, free[-1] / 1024.0, min(free) / 1024.0))
        warning = disk_warning(min(free))
        if warning:
            print("  " + warning)
    if cov:
        print("  edges: %s -> %s (+%s)"
              % (cov[0]["edges"], cov[-1]["edges"],
                 cov[-1]["edges"] - cov[0]["edges"]))
    else:
        print("  edges: never recorded, so coverage claims cannot be made "
              "from this run")
    surf = metric_rows(a.run_id, "surface", a.track)
    if surf:
        state, why = surface_growth(rows)
        print("  surface: %s -> %s target(s) over %d sample(s) [%s: %s]"
              % (surf[0]["surface"], surf[-1]["surface"], len(surf), state,
                 why))
    elif a.track == "k":
        print("  surface: never recorded, so this run has no second curve and "
              "a flat edge curve cannot be told from a finished one")
    for m in ("corpus", "corpus_bytes", "crashes"):
        vals = metric_rows(a.run_id, m, a.track)
        if vals:
            print("  %s: %s -> %s" % (m, vals[0][m], vals[-1][m]))
    print("  NOTE: kernel-side reachable coverage only. GSP firmware is not "
          "instrumented.")
    return 0


def since_last_reset(rows):
    """-> (rows since the fuzzer last restarted, whether it restarted).

    Edge counts only ever climb within one fuzzer process. A drop means the
    process restarted and its counter went back to zero, which this pipeline
    causes routinely, since the units are Restart=always and the machine
    panics by design. Samples either side of that are two different counters:
    subtracting across the reset produces large negative 'growth', which reads
    as a plateau and stops a loop that is in fact climbing fast.

    Edges only. The surface column falls for a different cause: syzkaller
    minimises its corpus, so a surface count drops with no restart behind it,
    and surface_growth reads that curve through `accumulate`, a running
    maximum, which makes a minimisation dip contribute nothing without
    attributing it to a fuzzer that never restarted.
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
    evidence that it was. Track U rows record GPU_NOT_APPLICABLE and are
    excluded, because those harnesses never touch the GPU and gating their
    verdict on it would report a real plateau as unknown.
    """
    bad = {}
    for r in window:
        status = r.get("gpu") or "unrecorded"
        if status not in (GPU_OK, GPU_NOT_APPLICABLE):
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


def _int_env(name, fallback):
    """int(os.environ[name]), or `fallback` when the variable is unset.

    The environment wins over config/campaign.yaml, so one run can be given a
    different cadence without editing config every campaign reads.
    """
    raw = os.environ.get(name)
    if raw is None:
        return fallback
    try:
        return int(raw)
    except ValueError:
        raise ValueError(
            "%s=%r is not an integer. Unset it to use the configured value."
            % (name, raw))


def surface_sample_min():
    """Minutes between surface samples: coverage.surface_sample_min.

    Unlike the other columns this one is not an HTTP GET: it unpacks the run's
    corpus.db and rescans every program in it, so it runs on its own coarser
    cadence and the rows in between record None. metric_rows drops those,
    which is exactly the coarser series wanted. Read per call, so a config
    edit between runs is picked up.
    """
    return _int_env("GSPWN_SURFACE_SAMPLE_MIN",
                    _coverage_cfg()["surface_sample_min"])


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


def accumulate(rows, metric="edges"):
    """-> [(cum_execs|None, cum_metric)], the species accumulation curve.

    Both counters reset when the fuzzer restarts. Executions are work done, so
    they accumulate: a reset means the delta is the new reading itself, not a
    negative number. Edges are a set, not an amount of work, so they
    accumulate as a running maximum — see the note above on replay.

    The running maximum is correct for the surface metric too, for a different
    reason: syzkaller minimises its corpus, so an unpacked surface count can
    genuinely drop, and max() gives the same conservative union of what the
    run has reached that it gives for edges.
    """
    out = []
    cum_execs = 0
    prev_execs = None
    best = 0
    have_execs = True
    for r in rows:
        edges = r.get(metric)
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


def surface_growth(rows, cov=None, min_samples=None):
    """-> (state, detail): growing | flat | unknown for the surface curve.

    No fit and no threshold. heaps_fit is deliberately not reused: it fits an
    unbounded power law, which is right for an edge space whose size is
    unknown and wrong for a counter bounded at 764, where it would predict
    more new targets than exist. The dynamic range makes the fit worse still —
    a 400-to-410 series has one target as a full percent of its spread, so the
    R2 gate would accept or reject it close to arbitrarily.

    What the curve is asked here is only whether it moved, which is
    subtraction. The answer modifies the edge verdict and never produces a
    stop on its own: a flat edge curve against a climbing surface curve means
    the round is still reaching commands it had not reached, whatever the edge
    count did.
    """
    cov = cov if cov is not None else _coverage_cfg()
    # Read out of `cov` and not out of config again, so a caller that
    # injected a configuration gets the floor that belongs to it.
    floor = (min_samples if min_samples is not None
             else _int_env("GSPWN_SURFACE_MIN_SAMPLES",
                           cov["surface_min_samples"]))
    samples = [r for r in rows if r.get("surface") is not None]
    if len(samples) < floor:
        return "unknown", ("%d surface sample(s) recorded; need >= %d before "
                           "the curve's shape means anything"
                           % (len(samples), floor))
    acc = accumulate(samples, "surface")
    if not acc:
        return "unknown", "no surface value in any sample"
    tail = fit_tail(acc, cov["fit_tail_fraction"])
    if len(tail) < floor:
        # Either the run records no execution axis to cut by, or the tail is
        # shorter than the floor. Reading the whole series is the conservative
        # direction: it can only report growth that a shorter window missed.
        tail = acc
    first, last = tail[0][1], tail[-1][1]
    if last > first:
        return "growing", ("surface %d -> %d target(s) across the last %d "
                           "sample(s)" % (first, last, len(tail)))
    return "flat", ("no new target reached across the last %d sample(s), and "
                    "the corpus names %d target(s) throughout" % (len(tail), last))


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
                    cov=None, surface=None):
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

    `surface` is the second curve, as the (state, detail) pair surface_growth
    returns. A flat edge curve against a climbing surface curve is not a
    plateau: the round is still reaching commands it had not reached, and the
    edge count is flat because those commands fail early rather than because
    the search is finished. It is applied after the GPU gate, not before,
    because a dead GPU does not flatten the surface count the way it flattens
    the edge count — programs still execute and still enter the corpus — so a
    climbing surface curve is not evidence the card is alive.
    """
    cov = cov if cov is not None else _coverage_cfg()
    if len(rows) < 3:
        return "unknown", "only %d usable sample(s); need >= 3" % len(rows)
    acc = accumulate(rows)
    if not acc:
        return "unknown", "no edge data in any sample"
    _seg, restarted = since_last_reset(rows)
    note = (". The fuzzer restarted during this run, so replay is excluded "
            "and only edges beyond the previous high-water mark count") \
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
            "no execution counts recorded, so growth is measured over elapsed "
            "time with no measure of work done")
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
        return "unknown", ("discovery exponent beta=%.3f is outside (0, 1]. "
                           "The series is not behaving like an accumulation "
                           "curve, so no extrapolation from it is meaningful%s" % (fit["beta"], note))
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
    if surface and surface[0] == "growing":
        return "growing", (
            "%s. The edge curve is flat but the surface curve is not (%s), so "
            "the round is still reaching commands it had not reached and this "
            "is not a plateau. A command whose handler rejects the call early "
            "adds a target and almost no edges."
            % (detail, surface[1]))
    if surface:
        detail += ". Surface curve: %s (%s)" % (surface[0], surface[1])
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
        all_rows = read_rows(run_id, t)
        if not all_rows:
            continue          # track not sampled at all: not evidence either way
        rows = metric_rows(run_id, "edges", t)
        # The surface curve is read from every row, not from the edge-carrying
        # subset: a sample whose stats fetch failed still records a surface
        # count, and dropping it would shorten the second curve for a reason
        # belonging to the first.
        per[t] = plateau_verdict(rows, window_min, min_growth,
                                 horizon_hours=horizon_hours,
                                 surface=surface_growth(all_rows))
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
        verdict, detail = plateau_verdict(
            rows, a.window_min, a.min_growth, horizon_hours=a.horizon_hours,
            surface=surface_growth(read_rows(a.run_id, a.track)))
        print("%s track %s: %s (%s)" % (a.run_id, a.track, verdict, detail))
    else:
        verdict, detail, _ = run_verdict(a.run_id, a.window_min, a.min_growth,
                                         horizon_hours=a.horizon_hours)
        print("%s: %s (%s)" % (a.run_id, verdict, detail))
    print("Coverage is kernel-side reachable code only. GSP firmware is not "
          "instrumented, so no verdict here says anything about it.")
    return {"growing": 0, "unknown": 1, "plateaued": 3}[verdict]


# ------------------------------------------------------- the ledger check ---


def completion_status(run_ids=None, corpus=None, ledger_path=None):
    """-> dict. Is every enumerated target either exercised or accounted for?

    The campaign's primary termination, and it is a ledger identity rather
    than a threshold: the denominator is counted from the inventories, so the
    operation is a set union and a comparison. No percentage is computed
    anywhere, because a percentage would invite a number to be chosen for it.

    A union and not a sum. A target can be exercised in a later round after an
    earlier one wrote a reason for it, and adding the two counts would then
    close the ledger while targets remained.

    A row written under a deferring reason is counted and reported and does
    not close its target: see ps.SURFACE_REASON_DEFERRED.

    Never raises. Anything that stops the corpus or the ledger being read
    yields verdict 'unknown', which never satisfies the stop: a broken
    measurement must not be able to end a campaign by claiming it is finished.
    """
    out = {"verdict": "unknown", "exercised": None, "accounted": None,
           "deferred": None, "closed": None, "total": None, "remaining": [],
           "detail": "", "driver_version": None,
           "ledger": ps.surface_ledger_path(ledger_path),
           "corpora": []}
    try:
        import surface_cov
        targets = None
        reached = set()
        for run_id in (run_ids or [None]):
            t, _excluded, meta, _modelled, exercised = surface_cov.measure(
                surface_cov.DEFAULT_DESC,
                corpus=None if run_id else corpus, run_id=run_id)
            targets = t
            out["driver_version"] = meta["driver_version"]
            out["corpora"].append("%s (%d program(s), modified %s)"
                                  % (meta["corpus"], meta["corpus_programs"],
                                     meta["corpus_mtime"] or "unknown"))
            reached |= {v for v in t if v in exercised}
        # The denominator is recounted from the inventories on every call, and
        # a truncated one is not an error anywhere upstream: an
        # rm-control-inventory.json whose `methods` list is empty loads
        # cleanly and yields 233 instead of 764, which a corpus already naming
        # the escape, UVM and alloc families closes outright. Requiring every
        # family to contribute puts a floor under it that needs no expected
        # count and no constant to drift.
        present = {t["family"] for t in (targets or {}).values()}
        empty = [f for f in surface_cov.FAMILIES if f not in present]
        if empty:
            raise surface_cov.SurfaceError(
                "the inventories enumerate no target in family %s, so the "
                "denominator (%d) is not the command surface. A truncated "
                "inventory reads as a smaller surface that a corpus can "
                "close, which fires the completion stop over commands nobody "
                "counted. Regenerate the inventories, then re-run "
                "surface_verify.py check"
                % (", ".join(empty), len(targets or {})))
        keys = {t["abi_key"] for t in targets.values()}
        exercised_keys = {targets[v]["abi_key"] for v in reached}
        accounted, deferred = ps.surface_ledger_keys(out["ledger"],
                                                     out["driver_version"])
        # Rows for targets the inventories no longer contain are reported and
        # not counted. A ledger outliving a driver bump would otherwise close
        # the surface with reasons written for commands that no longer exist.
        stale = accounted - keys
        accounted &= keys
        deferred &= keys
        verdict, counts, closed = ps.surface_completion(
            exercised_keys, accounted, len(keys), deferred=deferred)
        out.update(counts)
        out["verdict"] = verdict
        if closed is None:
            # surface_completion could not measure the union, so nothing is
            # known to be addressed. Reading `not in closed` against None
            # raises TypeError into the catch-all below and replaces this
            # detail with a Python error string.
            out["remaining"] = sorted(targets.values(),
                                      key=lambda t: (t["family"],
                                                     t["variant"]))
            out["detail"] = ("the exercised set could not be measured over %d "
                             "target(s), so no target is known to be closed"
                             % len(keys))
            return out
        out["remaining"] = sorted(
            (t for t in targets.values() if t["abi_key"] not in closed),
            key=lambda t: (t["family"], t["variant"]))
        out["detail"] = ("%d of %d target(s) closed: %d exercised, %d "
                         "accounted for, %d left"
                         % (counts["closed"], counts["total"],
                            counts["exercised"], counts["accounted"],
                            counts["total"] - counts["closed"]))
        if counts["deferred"]:
            out["detail"] += (", %d of them deliberately deferred and so not "
                              "closed" % counts["deferred"])
        if stale:
            out["detail"] += (". %d ledger row(s) name a target no inventory "
                              "contains and are not counted" % len(stale))
    except Exception as exc:
        out["detail"] = "completion not measured: %s" % exc
    return out


def cmd_completion(a):
    # The two name two different corpora and the measurement can only be of
    # one of them. Passing both used to measure the run and never read the
    # directory, which is the same silent wrong answer surface_cov.py refuses.
    if a.corpus and a.run_id:
        sys.exit("coverage_ctl: --run-id and --corpus name two different "
                 "corpora; pass one of them")
    st = completion_status(run_ids=a.run_id, corpus=a.corpus,
                           ledger_path=a.ledger)
    print("driver %s" % (st["driver_version"] or "unknown"))
    for line in st["corpora"]:
        print("corpus %s" % line)
    print("ledger %s" % st["ledger"])
    print("%s: %s" % (st["verdict"], st["detail"]))
    if not a.run_id and not a.corpus:
        # `exercised` means a program's text names the variant, and the seed
        # bank holds one generated program per target whether or not anything
        # ever ran it. Measured against the bank the identity can read
        # complete with no execution behind it.
        print()
        print("NOTE: measured against the seed bank, where a target counts as "
              "exercised because a generated program names it and not "
              "because a fuzzer ran it. The bank also holds this round's "
              "programs only after `python3 tools/corpus_ctl.py promote`. For "
              "the reading the stop rule uses, pass --run-id <id> and measure "
              "the run's own corpus.db.")
    if st["remaining"]:
        print()
        print("neither exercised nor accounted for (%d):" % len(st["remaining"]))
        top = max(a.top, 0)
        for target in st["remaining"][:top]:
            print("- [surface] %s %s  [%s]" % (target["family"],
                                               target["label"],
                                               target["variant"]))
        if len(st["remaining"]) > top:
            # "raise --top" reads as an offer to see the rest, so it belongs
            # only where some were shown. At --top 0 nothing was named and the
            # count is the whole finding.
            print("... %d more (raise --top)" % (len(st["remaining"]) - top)
                  if top else
                  "%d target(s) not listed (--top %d)"
                  % (len(st["remaining"]), a.top))
        print()
        print("Each one is either fuzzed next round or given a written reason: "
              "python3 tools/pipeline_ctl.py surface-account --json -")
    return {"complete": 0, "unknown": 1, "incomplete": 3}[st["verdict"]]


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
    print("Comparing runs is only meaningful when each had its own workdir "
          "and corpus policy. See campaign_ctl.py --corpus.")
    return 0


# Samples both tracks on one timer. The campaign deadline is enforced by its
# own per-run timer (gspwn-deadline@<run-id>.timer, installed by campaign_ctl
# install-k/install-u), so the spend ceiling holds even if the sampler is
# never installed or is removed mid-run.
# `-` prefixes mean a failure sampling one track does not suppress the other.
# Track U passes --skip-surface: those harnesses produce no syzlang programs,
# so there is no surface to measure and the run would only pay the unpack.
SERVICE_UNIT = """[Unit]
Description=gspwn coverage sampler ({run_id})

[Service]
Type=oneshot
{env}ExecStart=-/usr/bin/python3 {root}/tools/coverage_ctl.py sample \\
  --run-id {run_id} --url {url}
ExecStart=-/usr/bin/python3 {root}/tools/coverage_ctl.py sample \\
  --run-id {run_id} --track u --skip-surface
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
        sys.exit("run %s is not registered in %s. Install the campaign first "
                 "(campaign_ctl install-k/install-u registers it). A typo "
                 "here would create a root-owned run dir the sampler then "
                 "pads with empty rows." % (a.run_id, ps.STATE_PATH))
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


def _nonneg_int(value):
    """argparse type for a count. A negative one slices from the end."""
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("%r is not an integer" % value)
    if n < 0:
        raise argparse.ArgumentTypeError(
            "%d is negative; a negative count reads as a slice from the end "
            "of the list and prints something nobody asked for" % n)
    return n


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
    p.add_argument("--skip-surface", dest="skip_surface", action="store_true",
                   help="do not measure the surface column on this sample. "
                        "It unpacks the run's corpus and rescans every "
                        "program, which is not comparable in cost to the "
                        "HTTP fetch the other columns come from")
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
                   help="one track. Omit to combine both (the loop's view)")
    p.add_argument("--window-min", type=int,
                   default=loop_cfg["plateau_window_min"],
                   help="trailing window to measure growth over "
                        "(default loop.plateau_window_min)")
    p.add_argument("--min-growth", type=float,
                   default=loop_cfg["plateau_min_growth"],
                   help="fractional edge growth below which the run has "
                        "plateaued. Only used for runs whose source records "
                        "no execution count. Every other run takes its "
                        "verdict from the fitted discovery curve (default "
                        "loop.plateau_min_growth)")
    p.add_argument("--horizon-hours", dest="horizon_hours", type=float,
                   default=None,
                   help="how far ahead to extrapolate: the run has plateaued "
                        "when this many more hours is expected to find fewer "
                        "than coverage.plateau_new_edges new edges "
                        "(default coverage.horizon_hours)")
    p.set_defaults(fn=cmd_plateau)

    p = sub.add_parser("completion")
    p.add_argument("--run-id", dest="run_id", action="append",
                   metavar="RUN_ID",
                   help="measure the exercised set from this run's own "
                        "corpus.db; repeatable, and the sets are unioned. "
                        "Omit to read the seed bank")
    p.add_argument("--corpus",
                   help="a directory of programs to measure. The seed bank is "
                        "not read (not combinable with --run-id)")
    p.add_argument("--ledger", default=None,
                   help="completion ledger path (default %s)"
                        % ps.SURFACE_LEDGER_PATH)
    p.add_argument("--top", type=_nonneg_int, default=40,
                   help="how many unaddressed targets to list (0 lists none "
                        "and reports the count)")
    p.set_defaults(fn=cmd_completion)

    p = sub.add_parser("migrate-csv",
                       help="add the columns a run's CSV header lacks")
    p.add_argument("--run-id", dest="run_id", required=True)
    p.add_argument("--track", choices=TRACKS, default=None,
                   help="omit to migrate both tracks")
    p.set_defaults(fn=cmd_migrate_csv)

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
