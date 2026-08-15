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
        # Rotate to a fresh session after this many resumes. A transcript that
        # grows forever is re-read on every restart and eventually auto-
        # compacts, which drops detail unpredictably; a bounded one is re-
        # anchored from `pipeline_ctl.py brief` instead.
        "max_resumes": 20,
        # Circuit-breaker window and its two limits. Same-boot restarts and
        # reboots are counted separately because they mean different things:
        # kernel fuzzing panics the box by design, so reboots are expected and
        # a single shared limit would stop a healthy campaign.
        "window_min": 60,
        "max_same_boot_starts": 5,
        "max_reboots": 10,
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
    for key in ("command", "resume_command"):
        if not isinstance(orch[key], str):
            problems.append("orchestrator.%s must be a string (quote it if "
                            "it contains a colon)" % key)
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


def loop(path=None):
    return load(path)["loop"]


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
    print("session resume: %s"
          % ("off — every restart starts a fresh session"
             if not orch["resume_command"] else
             "%s, rotating after %d resume(s)"
             % (orch["resume_command"], orch["max_resumes"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
