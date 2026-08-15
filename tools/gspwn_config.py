"""Single source of truth for every tunable in the pipeline.

Every tool reads its tunables from here rather than defining its own, so a
value cannot drift between the config file and the code that uses it.

Read the effective configuration (defaults merged with config/campaign.yaml,
fully validated) before starting a campaign:

    python3 tools/gspwn_config.py

Unknown keys are rejected rather than ignored, so a misspelled key fails
loudly instead of leaving the default value in force.
"""
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.environ.get("GSPWN_CONFIG") or os.path.join(
    REPO_ROOT, "config", "campaign.yaml")

# Every knob, with the default applied when campaign.yaml omits it. The shape
# here is the schema: load() rejects keys that do not appear in it.
DEFAULTS = {
    "track_k": {
        "enabled_syscalls": [],
        "sandbox": "namespace",
        "procs": 2,
        "memory_max": "12G",
        "http": "127.0.0.1:56744",
        "smoke_window_minutes": 30,
    },
    "track_u": {
        "docker_image": "aflplusplus/aflplusplus:latest",
        "memory_max": "8G",
        "targets": [],
    },
    "loop": {
        "max_rounds": 3,
        "max_total_run_hours": 216,
        "campaign_hours": 24,
        "stop_on_plateau": True,
        "plateau_window_min": 240,
        "plateau_min_growth": 0.02,
        "coverage_sample_min": 10,
        "corpus_policy": "carry",
        "promote_seeds": True,
    },
    "orchestrator": {
        # The headless agent invocation the supervisor launches. Empty on
        # purpose: this repo is not tied to one coding-agent CLI, and a
        # default here would be a guess about what is installed on the SUT.
        # orchestrator_ctl.py install refuses until it is set.
        "command": "",
        # The invocation for a restart that reuses the previous session, with
        # {session} substituted for the assigned id. Empty keeps every start
        # fresh, which is always correct: the state file, not the transcript,
        # is what says where the pipeline is. Setting it carries the previous
        # session's reasoning across a panic as well.
        "resume_command": "",
        # Rotation is primarily by transcript SIZE, because that is what
        # actually drives auto-compaction. Restart count does not: a campaign
        # that panics twenty times in an hour writes almost nothing, while one
        # that panics twice in three days writes a great deal.
        #
        # Measured on one real 20-hour session: compaction fired three times,
        # after 1.66, 2.01 and 2.54 MB of new transcript, so roughly every
        # 2 MB. One compaction is survivable — its summary is decent. The
        # damage is compound: the third summarises the second's summary. 6 MB
        # is about three compactions, which is where re-anchoring from `brief`
        # starts beating another lossy pass. n=1, so treat it as a starting
        # point and not a constant of nature.
        #
        # 0 disables the size check and leaves max_resumes as the only bound.
        "max_session_mb": 6,
        # Where the agent's transcript lives, with {session} substituted. Empty
        # means the size check cannot run, and the tool says so rather than
        # silently falling back to counting. For Claude Code:
        #   "~/.claude/projects/*/{session}.jsonl"
        "session_transcript_glob": "",
        # Backstop for when the transcript cannot be measured at all. Kept
        # deliberately loose: it is a poor proxy and should rarely be what
        # rotates a session.
        "max_resumes": 40,
        # Circuit-breaker window and its two limits. Same-boot restarts and
        # reboots are counted separately because they mean different things:
        # kernel fuzzing panics the box by design, so reboots are expected and
        # a single shared limit would stop a healthy campaign.
        "window_min": 60,
        "max_same_boot_starts": 5,
        "max_reboots": 10,
        # Substituted for {anchor} in resume_command. This is the first thing a
        # resumed agent reads after a panic, and what stops it from continuing
        # a half-finished tool call issued at the moment the kernel died — so
        # it is a tuning knob, not a string constant.
        #
        # It must contain no apostrophe or double quote: it is substituted into
        # a shell command line the operator has already quoted, and a quote in
        # it would end that quoting and hand the rest to the shell. Validation
        # refuses one rather than letting a config edit break the launch.
        "resume_anchor": (
            "This session has resumed after an interruption. Your most recent "
            "turn predates a kernel panic, a reboot or a restart, so anything "
            "it says about what is running or what phase you were in is "
            "stale. Do not act on it. Run: python3 tools/pipeline_ctl.py "
            "brief -- its output is authoritative and your memory is not. "
            "Then continue from the phase it reports, following AGENTS.md. "
            "Your earlier reasoning about the target is still useful; your "
            "earlier belief about the machine is not."),
    },
    # What the agent actually reads. `brief` is the resume anchor: after a
    # panic it is the whole of what a fresh context knows, so how much it
    # carries is a tuning knob for the agent's effectiveness, not a display
    # preference. Too little and the agent re-derives what an earlier round
    # already settled; too much and the anchor itself costs the context it was
    # meant to save.
    "agent": {
        # Knowledge entries shown per file (learnings, mistakes).
        "brief_knowledge_entries": 3,
        # Each entry is summarised by its first line, cut to this many
        # characters. `knowledge_ctl.py show` always has the full text.
        "brief_knowledge_line_chars": 100,
        # Integrity problems listed before deferring to `validate`.
        "brief_max_problems": 5,
        # Crash titles in `crash-list`. Kernel report titles put the
        # distinguishing part at the end often enough that cutting too early
        # makes two different bugs look like one line of output.
        "crash_title_chars": 70,
    },
    # How the plateau decision is made. Coverage is the only signal that
    # decides whether to run another round, so these are the numbers the
    # campaign's stopping rule actually rests on.
    #
    # The verdict is an extrapolation from a fitted species-accumulation
    # curve, not a growth threshold: the question is how many new edges
    # another campaign is expected to find, which is in the units of the thing
    # being predicted. A growth percentage is not — the same percentage means
    # ten edges early in a run and a thousand late in one.
    "coverage": {
        # Below this many expected new edges over one more campaign, the run
        # has plateaued. Set it to what would actually be worth another
        # campaign of machine time, because that is the decision it makes.
        "plateau_new_edges": 50,
        # How far ahead to extrapolate. Matches loop.campaign_hours by
        # default, since that is the unit of spend the decision authorises.
        "horizon_hours": 24,
        # Fit quality below which no extrapolation is reported at all and the
        # verdict is unknown. A curve the model does not describe is how a
        # confident wrong number reaches a report.
        "model_min_r2": 0.90,
        # Points needed before extrapolating from the fit.
        "min_fit_samples": 8,
        # How much of the run to fit, measured in executions rather than in
        # samples. The decision is about the regime the fuzzer is in now: a
        # fit over the whole run is dominated by the early steep phase, so a
        # run that climbed hard and then went flat would still report a
        # healthy exponent. 1.0 fits everything.
        "fit_tail_fraction": 0.5,
        # beta above 1 means the series is not an accumulation curve. A small
        # tolerance absorbs sampling noise early in a run without accepting a
        # genuinely wrong shape.
        "beta_tolerance": 0.05,
    },
    # Dedup depth. These decide whether two reports are the same bug, which
    # decides what reaches `rca` and what the next round hunts, so they are
    # research knobs rather than parser internals.
    #
    # CAUTION: change them between campaigns, not during one. Already
    # registered hashes are not recomputed, so across a mid-campaign change
    # one bug can register twice and two bugs can merge into one that never
    # reaches rca. pipeline_state stamps the settings in force at the first
    # registration and `pipeline_ctl.py validate` reports it when they move.
    "triage": {
        # Frames hashed for the secondary dedup key. Fewer merges distinct
        # bugs that share a common caller; more splits one bug whose stack
        # varies by an inlined frame.
        "stack_hash_frames": 3,
        # Frames a reproduction must match to count as the same crash.
        "signature_frames": 5,
        # The two below govern the fallback identity for a report with no
        # usable stack at all — a lone "BUG: unable to handle ..." or a
        # trace-less panic. With no frames to hash, the evidence is the
        # faulting function plus the wording around the report's start line,
        # normalized so timestamps, addresses and per-occurrence detail do not
        # make every sighting unique. These two bound the wording only: the
        # faulting function is matched by pattern wherever it sits and is
        # always part of the identity, because without it two different faults
        # behind the same fault type merge and the second never reaches rca.
        #
        # They fail in opposite directions: too narrow and one panic registers
        # as many bugs, burying the real ones in the queue; too wide and the
        # signature picks up detail that varies per occurrence.
        #
        # Report lines that form the signature. Small on purpose: later lines
        # of a trace-less report are usually register dumps.
        "frameless_signature_lines": 5,
        # Characters of that normalized wording actually hashed.
        "frameless_signature_chars": 300,
    },
}

# (section, key, predicate, message) — checked on every load.
_POSITIVE = ("must be a positive number", lambda v: _num(v) and v > 0)
# Caps that count things (rounds, processes, minutes) are integers: a float
# like max_rounds: 2.5 must fail loudly, not silently truncate in one place
# and compare as 2.5 in another. bool is an int subclass — exclude it.
_POSITIVE_INT = ("must be a positive integer",
                 lambda v: isinstance(v, int) and not isinstance(v, bool)
                 and v > 0)
_BOOL = ("must be true or false (unquoted — a quoted string is truthy and "
         "silently keeps the default behavior)", lambda v: isinstance(v, bool))
_RULES = [
    ("track_k", "procs", _POSITIVE_INT),
    ("track_k", "smoke_window_minutes", _POSITIVE_INT),
    ("loop", "max_rounds", _POSITIVE_INT),
    ("loop", "max_total_run_hours", _POSITIVE),
    ("loop", "campaign_hours", _POSITIVE),
    ("loop", "plateau_window_min", _POSITIVE_INT),
    ("loop", "coverage_sample_min", _POSITIVE_INT),
    ("loop", "plateau_min_growth",
     ("must be a fraction between 0 and 1 exclusive (0.02 = 2%; 0 would "
      "silently disable the plateau stop)",
      lambda v: _num(v) and 0 < v < 1)),
    ("loop", "stop_on_plateau", _BOOL),
    ("loop", "promote_seeds", _BOOL),
    ("orchestrator", "window_min", _POSITIVE_INT),
    ("orchestrator", "max_same_boot_starts", _POSITIVE_INT),
    ("orchestrator", "max_reboots", _POSITIVE_INT),
    ("orchestrator", "max_resumes", _POSITIVE_INT),
    ("orchestrator", "max_session_mb",
     ("must be a number >= 0 (0 disables the size check)",
      lambda v: _num(v) and v >= 0)),
    ("orchestrator", "resume_anchor",
     ("must be a non-empty string containing no apostrophe or double quote. "
      "It is substituted into a shell command line the operator has already "
      "quoted, so a quote here would end that quoting and hand the rest of "
      "the anchor to the shell",
      lambda v: isinstance(v, str) and v.strip() and "'" not in v
      and '"' not in v)),
    ("agent", "brief_knowledge_entries", _POSITIVE_INT),
    ("agent", "brief_knowledge_line_chars", _POSITIVE_INT),
    ("agent", "brief_max_problems", _POSITIVE_INT),
    ("agent", "crash_title_chars", _POSITIVE_INT),
    ("triage", "stack_hash_frames", _POSITIVE_INT),
    ("triage", "signature_frames", _POSITIVE_INT),
    ("triage", "frameless_signature_lines", _POSITIVE_INT),
    ("triage", "frameless_signature_chars",
     ("must be an integer >= 32. Below that the hash covers little more than "
      "the report's first few words, and unrelated trace-less panics sharing "
      "a prologue would merge into one bug",
      lambda v: isinstance(v, int) and not isinstance(v, bool) and v >= 32)),
    ("coverage", "plateau_new_edges", _POSITIVE_INT),
    ("coverage", "horizon_hours", _POSITIVE),
    ("coverage", "min_fit_samples",
     ("must be an integer >= 3 (a least-squares fit of two points is exact "
      "and says nothing about the curve)",
      lambda v: isinstance(v, int) and not isinstance(v, bool) and v >= 3)),
    ("coverage", "model_min_r2",
     ("must be a fraction between 0 and 1 exclusive (0 would accept any "
      "curve as a discovery curve and extrapolate from noise)",
      lambda v: _num(v) and 0 < v < 1)),
    ("coverage", "fit_tail_fraction",
     ("must be a fraction in (0, 1] — the share of the run's executions the "
      "fit covers, where 1.0 fits the whole run",
      lambda v: _num(v) and 0 < v <= 1)),
    ("coverage", "beta_tolerance",
     ("must be a number between 0 and 1 (how far above beta=1 to tolerate "
      "before calling the series something other than an accumulation curve)",
      lambda v: _num(v) and 0 <= v < 1)),
]

# Substituted into orchestrator.command and resume_command. Not str.format:
# an agent invocation routinely carries a prompt containing braces, and
# format() would raise or mangle it.
SESSION_PLACEHOLDER = "{session}"


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


class ConfigError(ValueError):
    """Raised for anything that would make an unattended run misbehave."""


def _merge(defaults, given, path=""):
    """Deep-merge `given` over `defaults`, rejecting unknown keys."""
    out = {}
    for key, dflt in defaults.items():
        if key not in given:
            out[key] = dict(dflt) if isinstance(dflt, dict) else dflt
            continue
        val = given[key]
        if isinstance(dflt, dict):
            if not isinstance(val, dict):
                raise ConfigError("%s%s must be a mapping" % (path, key))
            out[key] = _merge(dflt, val, path + key + ".")
        else:
            out[key] = val
    unknown = sorted(set(given) - set(defaults))
    if unknown:
        raise ConfigError(
            "unknown key(s) in %s: %s. Valid keys here: %s"
            % (path.rstrip(".") or "campaign.yaml", ", ".join(
                path + u for u in unknown), ", ".join(sorted(defaults))))
    return out


def validate(cfg):
    """Return cfg, or raise ConfigError listing everything that is wrong."""
    problems = []
    for section, key, (msg, ok) in _RULES:
        val = cfg[section][key]
        if not ok(val):
            problems.append("%s.%s = %r %s" % (section, key, val, msg))
    policy = cfg["loop"]["corpus_policy"]
    if policy not in ("fresh", "carry"):
        problems.append("loop.corpus_policy = %r must be 'fresh' or 'carry'"
                        % policy)
    # Empty is valid (nothing installed yet); a non-string is not, and would
    # otherwise reach subprocess as whatever YAML parsed it into.
    orch = cfg["orchestrator"]
    for key in ("command", "resume_command", "session_transcript_glob"):
        if not isinstance(orch[key], str):
            problems.append("orchestrator.%s must be a string (quote it if "
                            "it contains a colon)" % key)
    if (isinstance(orch.get("session_transcript_glob"), str)
            and orch["session_transcript_glob"]
            and SESSION_PLACEHOLDER not in orch["session_transcript_glob"]):
        problems.append(
            "orchestrator.session_transcript_glob must contain %s — without "
            "it the pattern matches every session's transcript, and the size "
            "check would rotate on some other run's history"
            % SESSION_PLACEHOLDER)
    # Session resume needs the id to reach BOTH invocations. The id is
    # assigned here and passed in, never discovered afterwards: parsing it out
    # of the agent's stdout, or globbing for the newest transcript, is a race
    # against any other agent running on the box.
    if isinstance(orch.get("resume_command"), str) and orch["resume_command"]:
        for key in ("command", "resume_command"):
            val = orch[key]
            if isinstance(val, str) and SESSION_PLACEHOLDER not in val:
                problems.append(
                    "orchestrator.%s must contain %s when resume_command is "
                    "set — the session id has to be assigned on the first "
                    "launch and passed back on every resume, and without the "
                    "placeholder each restart would silently open a new "
                    "session while the resume counter believed otherwise"
                    % (key, SESSION_PLACEHOLDER))
    # A per-campaign duration longer than the total budget can never complete a
    # round, so the loop would spend the whole ceiling on run 1 and stop.
    if (_num(cfg["loop"]["campaign_hours"])
            and _num(cfg["loop"]["max_total_run_hours"])
            and cfg["loop"]["campaign_hours"] > cfg["loop"][
                "max_total_run_hours"]):
        problems.append(
            "loop.campaign_hours (%s) exceeds loop.max_total_run_hours (%s) — "
            "no round could finish inside the budget"
            % (cfg["loop"]["campaign_hours"],
               cfg["loop"]["max_total_run_hours"]))
    if (_num(cfg["loop"]["plateau_window_min"])
            and _num(cfg["loop"]["coverage_sample_min"])
            and cfg["loop"]["plateau_window_min"] < cfg["loop"][
                "coverage_sample_min"] * 3):
        problems.append(
            "loop.plateau_window_min (%s) is under 3 sampling intervals of "
            "%s min — the plateau test needs >= 3 samples in the window and "
            "would always report 'unknown', which stops the loop"
            % (cfg["loop"]["plateau_window_min"],
               cfg["loop"]["coverage_sample_min"]))
    if problems:
        raise ConfigError("invalid configuration in %s:\n  - %s"
                          % (CONFIG_PATH, "\n  - ".join(problems)))
    return cfg


def load(path=None):
    """Effective configuration: defaults, overlaid with the YAML, validated."""
    path = path or CONFIG_PATH
    given = {}
    if os.path.exists(path):
        try:
            import yaml
        except ImportError:
            raise ConfigError(
                "PyYAML is required to read %s (apt install python3-yaml)"
                % path)
        with open(path) as f:
            try:
                given = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise ConfigError("%s is not valid YAML: %s" % (path, e))
        # An empty file means "defaults in force"; a top-level scalar or list
        # ([], false, 0) is a malformed config and must not become one.
        if given is None:
            given = {}
        if not isinstance(given, dict):
            raise ConfigError("%s must contain a mapping at the top level"
                              % path)
    return validate(_merge(DEFAULTS, given))


# One-entry memo for callers on a hot path. Crash dedup asks for its frame
# count once per report block, and re-reading plus re-validating the YAML
# thousands of times per harvest is pure waste. Keyed on the file's identity,
# so an edit between runs is picked up rather than pinned for the process.
_CACHE = {}


def cached(path=None):
    """load(), memoised until config/campaign.yaml changes on disk."""
    path = path or CONFIG_PATH
    try:
        stat = os.stat(path)
        key = (path, stat.st_mtime_ns, stat.st_size)
    except OSError:
        key = (path, None, None)
    if key not in _CACHE:
        cfg = load(path)
        _CACHE.clear()
        _CACHE[key] = cfg
    return _CACHE[key]


def loop(path=None):
    return load(path)["loop"]


def agent(path=None):
    """What `brief` and `crash-list` put in front of the agent."""
    return cached(path)["agent"]


def triage(path=None):
    """Dedup depths. See the CAUTION in DEFAULTS before changing them."""
    return cached(path)["triage"]


def coverage(path=None):
    """How the plateau decision is made — the campaign's stopping rule."""
    return cached(path)["coverage"]


def manager_url(path=None):
    """syz-manager HTTP base URL, derived from track_k.http.

    Derived here rather than duplicated into the sampler, so a port change in
    config cannot leave the sampler polling a stale address and recording the
    campaign as 'unreachable'.
    """
    http = str(load(path)["track_k"]["http"])
    return http if http.startswith("http") else "http://" + http


def main():
    try:
        cfg = load()
    except ConfigError as e:
        sys.exit("error: %s" % e)
    import json
    print("effective configuration (%s):" % CONFIG_PATH)
    print(json.dumps(cfg, indent=2, sort_keys=True))
    lp, orch = cfg["loop"], cfg["orchestrator"]
    print("\nstopping rules: at most %d round(s) x campaigns of %s h, "
          "total <= %s run-hours"
          % (lp["max_rounds"], lp["campaign_hours"],
             lp["max_total_run_hours"]))
    print("orchestrator: %s; breaker blocks at %d same-boot start(s) or %d "
          "reboot(s) per %d min"
          % (orch["command"] or "command unset (supervisor not installable)",
             orch["max_same_boot_starts"], orch["max_reboots"],
             orch["window_min"]))
    if not orch["resume_command"]:
        print("session resume: off — every restart starts a fresh session")
    else:
        print("session resume: %s" % orch["resume_command"])
        print("  rotates at %s MB of transcript%s; backstop %d resume(s)"
              % (orch["max_session_mb"] or "(size check off)",
                 "" if orch["session_transcript_glob"]
                 else " — but session_transcript_glob is unset, so the size "
                      "cannot be measured and only the backstop applies",
                 orch["max_resumes"]))
    ag, tr = cfg["agent"], cfg["triage"]
    print("brief carries: %d knowledge entr(ies) per file at %d chars, "
          "%d integrity problem(s)"
          % (ag["brief_knowledge_entries"], ag["brief_knowledge_line_chars"],
             ag["brief_max_problems"]))
    print("dedup: %d stack frame(s) hashed, %d frame(s) matched on repro; "
          "with no stack at all, %d report line(s) cut to %d chars"
          % (tr["stack_hash_frames"], tr["signature_frames"],
             tr["frameless_signature_lines"],
             tr["frameless_signature_chars"]))
    cv = cfg["coverage"]
    print("plateau: fit the last %.0f%% of executions (>= %d samples, R2 >= "
          "%.2f); plateaued when another %.0f h is expected to find < %d new "
          "edge(s)"
          % (cv["fit_tail_fraction"] * 100, cv["min_fit_samples"],
             cv["model_min_r2"], cv["horizon_hours"],
             cv["plateau_new_edges"]))
    if cv["horizon_hours"] != lp["campaign_hours"]:
        print("  note: horizon %.0f h differs from loop.campaign_hours %.0f h, "
              "so the verdict answers a different question than the one the "
              "next campaign asks" % (cv["horizon_hours"],
                                      lp["campaign_hours"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
