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
    "eval": {
        # Run length is loop.campaign_hours; it is not duplicated here.
        "runs_per_config": 3,
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
    "cost": {
        "idle_stop_minutes": 120,
        "idle_check_minutes": 30,
        "monthly_budget_usd": 0,
        "budget_alerts_usd": [50, 150],
    },
}

# (section, key, predicate, message) — checked on every load.
_POSITIVE = ("must be a positive number", lambda v: _num(v) and v > 0)
_NON_NEGATIVE = ("must be zero or a positive number",
                 lambda v: _num(v) and v >= 0)
_RULES = [
    ("track_k", "procs", _POSITIVE),
    ("track_k", "smoke_window_minutes", _POSITIVE),
    ("eval", "runs_per_config", _POSITIVE),
    ("loop", "max_rounds", _POSITIVE),
    ("loop", "max_total_run_hours", _POSITIVE),
    ("loop", "campaign_hours", _POSITIVE),
    ("loop", "plateau_window_min", _POSITIVE),
    ("loop", "coverage_sample_min", _POSITIVE),
    ("loop", "plateau_min_growth",
     ("must be a fraction between 0 and 1 (0.02 = 2%)",
      lambda v: _num(v) and 0 <= v < 1)),
    ("cost", "idle_stop_minutes", _POSITIVE),
    ("cost", "idle_check_minutes", _POSITIVE),
    ("cost", "monthly_budget_usd", _NON_NEGATIVE),
]


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
    if not isinstance(cfg["cost"]["budget_alerts_usd"], list):
        problems.append("cost.budget_alerts_usd must be a list of amounts")
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
                given = yaml.safe_load(f) or {}
            except yaml.YAMLError as e:
                raise ConfigError("%s is not valid YAML: %s" % (path, e))
        if not isinstance(given, dict):
            raise ConfigError("%s must contain a mapping at the top level"
                              % path)
    return validate(_merge(DEFAULTS, given))


def loop(path=None):
    return load(path)["loop"]


def cost(path=None):
    return load(path)["cost"]


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
    lp, cs = cfg["loop"], cfg["cost"]
    print("\nspend ceiling: %d round(s) x campaigns of %s h, "
          "total <= %s run-hours"
          % (lp["max_rounds"], lp["campaign_hours"],
             lp["max_total_run_hours"]))
    print("idle auto-stop after %s min; monthly budget %s USD (alerts at %s)"
          % (cs["idle_stop_minutes"], cs["monthly_budget_usd"] or "unset",
             ", ".join(str(a) for a in cs["budget_alerts_usd"]) or "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
