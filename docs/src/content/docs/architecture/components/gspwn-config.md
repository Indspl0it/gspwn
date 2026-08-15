---
title: gspwn_config.py
description: The single source of truth for every tunable.
---

Both a command and a library. Every tool reads its tunables from here, so a
value cannot drift between the configuration file and the code that uses it.

The effective configuration is `DEFAULTS` overlaid with `config/campaign.yaml`
and validated. `GSPWN_CONFIG` redirects the file that is overlaid.

## Responsibility

The module owns the schema, the validation rules, the merge, the memo, and the
one derived value.

| Invariant | Enforced by |
|---|---|
| The shape of `DEFAULTS` is the schema | `_merge` walks the defaults and refuses any key they do not name |
| A configuration is either fully valid or rejected | `validate` collects every failure and raises once |
| A caller on a hot path does not re-read the file | `cached` keys on the file's path, modification time and size |
| The syz-manager address exists in one place | `manager_url` derives it from `track_k.http` |
| A boolean setting is a real `bool` | The boolean rule refuses a quoted string, which is truthy |
| A cap that counts things is an integer | The integer rules exclude `bool`, which is an `int` subclass in Python |

Sections: `track_k`, `track_u`, `loop`, `orchestrator`, `agent`, `coverage`,
`poc`, `triage`.

## Interface

| Function | Returns | Raises |
|---|---|---|
| `load(path=None)` | The whole effective configuration, validated | `ConfigError` |
| `cached(path=None)` | The same, memoised until the file changes on disk | `ConfigError` |
| `validate(cfg)` | `cfg` | `ConfigError` listing every problem |
| `loop(path=None)` | The `loop` section | `ConfigError` |
| `agent(path=None)` | The `agent` section, read by `brief` and `crash-list` | `ConfigError` |
| `triage(path=None)` | The `triage` section, the dedup depths | `ConfigError` |
| `coverage(path=None)` | The `coverage` section, the plateau tunables | `ConfigError` |
| `poc(path=None)` | The `poc` section, the reproduction tunables | `ConfigError` |
| `manager_url(path=None)` | The syz-manager base URL derived from `track_k.http` | `ConfigError` |

Exported constants: `DEFAULTS`, `CONFIG_PATH`, `SESSION_PLACEHOLDER`,
`ConfigError`.

The command form prints the effective configuration as JSON, then the
behaviour that configuration produces.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | `pipeline_ctl.py`, `campaign_ctl.py`, `coverage_ctl.py`, `crash_parse.py`, `repro_ctl.py`, `orchestrator_ctl.py`, `corpus_ctl.py` |
| This module imports | Nothing in `tools/` |

## Failure modes

| Condition | Behaviour |
|---|---|
| Key absent from `DEFAULTS` | `ConfigError` naming the key and listing the valid keys for that section |
| Section holds a scalar where a mapping belongs | `ConfigError` naming the path |
| Top level is `[]`, `false` or `0` | `ConfigError`; an empty file is accepted and means defaults are in force |
| File is not valid YAML | `ConfigError` carrying the parser error |
| Any rule violation | `ConfigError` listing every violation from one pass |
| Command form raises `ConfigError` | Exits 1 with the message on stderr |

## Concurrency and durability

The module reads only. It writes no file, takes no lock, and holds no state
beyond the one-entry memo in `cached`. The memo keys on path, modification time
and size, so a change between runs is picked up. Callers that need a consistent
snapshot across a long operation read once and pass the dict down.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never accept an unknown key | A misspelled key leaves the default silently in force, which on a cap is a budget nobody set |
| Never raise on the first problem | `validate` collects every failure before raising, so one run reports the whole list |
| Never hold a derived value in two places | A sampler holding its own copy of the address polls the old port after a configuration change and records the campaign as `unreachable` |
| Never memoise across an edit | `cached` re-reads when path, modification time or size changes |
| Never accept a top-level scalar | An empty file means defaults are in force; a top-level scalar is a malformed configuration |
| Never treat a quoted boolean as false | `loop.stop_on_plateau: "false"` is a truthy string; the rule requires an actual `bool` and its message says so |

## Design notes

`bool` is an `int` subclass in Python, so every numeric predicate excludes it
explicitly. `loop.max_rounds: true` would otherwise validate as the integer 1.

Caps that count things are integers. `loop.max_rounds: 2.5` fails validation; a
float truncates in one place and compares as 2.5 in another.

The systemd byte-spec rule exists because an unvalidated `12GB` is accepted by
YAML and fails only when systemd refuses to load the unit on the target
machine.

The `{session}` placeholder is substituted with `str.replace`. An agent
invocation routinely carries a prompt containing braces, which `str.format`
raises on or mangles.

`orchestrator.resume_anchor` is refused if it contains an apostrophe or a
double quote. It is substituted into a shell command line the operator has
already quoted, and a quote in it would end that quoting and hand the rest to
the shell.

`main` prints the effective configuration and then the behaviour it produces.
The JSON dump reports the settings; the summary reports their effect. The
horizon note fires when `coverage.horizon_hours` and `loop.campaign_hours`
differ, because the verdict then covers a different window from the one the
next campaign runs for.

## See also

- [gspwn_config.py reference](/gspwn/reference/cli/gspwn-config/)
- [Configuration keys](/gspwn/reference/configuration/)
