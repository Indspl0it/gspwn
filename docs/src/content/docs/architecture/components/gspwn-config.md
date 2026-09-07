---
title: gspwn_config.py
description: The single source of truth for every tunable.
---

`gspwn_config.py` is both a command and a library. Every tool reads its
tunables from here, so a value cannot drift between the configuration file and
the code that uses it.

The effective configuration is `DEFAULTS` overlaid with `config/campaign.yaml`
and validated. `GSPWN_CONFIG` redirects the file that is overlaid.
`DEFAULTS` holds 52 keys across eight sections: `track_k`, `track_u`, `loop`,
`orchestrator`, `agent`, `coverage`, `poc` and `triage`.
[Configuration keys](/gspwn/reference/configuration/) states every key, its
type, its accepted values, its default and the tool that reads it.

## Invocation

The command form takes no argument and declares no subcommand.

```
python3 tools/gspwn_config.py
```

It prints the effective configuration as JSON, then a summary carrying the
stopping rules, the orchestrator command and its breaker limits, the session
resume settings, what `brief` carries, the dedup depths, the plateau rule, the
surface curve, the reproduction settings and the disk and deadline guards. A
final note is printed when `coverage.horizon_hours` differs from
`loop.campaign_hours`, because the verdict then covers a different window from
the one the next campaign runs for.

| Exit code | Condition |
|---|---|
| 0 | The configuration merged and validated |
| 1 | A `ConfigError`, printed to standard error as `error: <message>` |

## Public functions

| Function | Returns |
|---|---|
| `load(path=None)` | The effective configuration, read and validated on every call |
| `cached(path=None)` | `load()`, memoised until the file's path, modification time or size changes |
| `validate(cfg)` | `cfg`, or raises `ConfigError` listing every problem found in one pass |
| `loop(path=None)` | The `loop` section, through `load` |
| `agent(path=None)` | The `agent` section, through `cached` |
| `triage(path=None)` | The `triage` section, through `cached` |
| `coverage(path=None)` | The `coverage` section, through `cached` |
| `poc(path=None)` | The `poc` section, through `cached` |
| `manager_url(path=None)` | The syz-manager HTTP base URL, derived from `track_k.http` |

The memo exists for callers on a hot path. Crash dedup asks for its frame count
once per report block, and re-reading and re-validating the YAML thousands of
times per harvest costs the harvest.

## Responsibility

The module owns the schema, the validation rules, the merge, the memo, and the
one derived value.

| Invariant | Enforced by |
|---|---|
| The shape of `DEFAULTS` is the schema | `_merge` walks the defaults and refuses any key they do not name |
| A configuration is either fully valid or rejected | `validate` collects every failure and raises once |
| A caller on a hot path re-reads the file only when it changes | `cached` keys on the file's path, modification time and size |
| The syz-manager address exists in one place | `manager_url` derives it from `track_k.http` |
| A boolean setting is a real `bool` | The boolean rule refuses a quoted string, which is truthy |
| A cap that counts things is an integer | The integer rules exclude `bool`, which is an `int` subclass in Python |

## Validation

Forty-eight rules check one key each, against a type, a bound or a closed set. Seven
further checks read more than one key, and reject a configuration whose keys
are each valid alone.

| Check | Rejected when |
|---|---|
| Corpus policy | `loop.corpus_policy` is neither `fresh` nor `carry` |
| Orchestrator string types | `orchestrator.command`, `resume_command` or `session_transcript_glob` holds a non-string value. An empty string is valid and means nothing is installed yet |
| Transcript glob placeholder | `orchestrator.session_transcript_glob` is non-empty and holds no `{session}`, which would match every session's transcript and rotate on another run's history |
| Session id round trip | `orchestrator.resume_command` is set and either it or `orchestrator.command` holds no `{session}`, which would open a new session on every restart while the resume counter believed otherwise |
| Campaign inside the budget | `loop.campaign_hours` exceeds `loop.max_total_run_hours`, so no round could finish inside the budget |
| Agent timeout above the campaign window | `orchestrator.max_agent_hours` is a number above `loop.campaign_hours`. A bound longer than a whole campaign fires only after the campaign has ended, so it bounds nothing. `orchestrator_ctl.launch_hours` adds the campaign window for the `fuzz` launch alone, so the setting is the headroom a launch gets beyond the work it waits on |
| Plateau window against the sampling interval | `loop.plateau_window_min` is under three intervals of `loop.coverage_sample_min`. The plateau test needs at least three samples in the window and otherwise always reports `unknown`, which stops the loop |

`{session}` is substituted with `str.replace` and never with `str.format`, and
`SESSION_PLACEHOLDER` names it. An agent invocation routinely carries a prompt
containing braces, which `str.format` raises on or mangles.

## Callers

- `pipeline_ctl.py`, `campaign_ctl.py`, `coverage_ctl.py`, `crash_parse.py`,
  `repro_ctl.py`, `orchestrator_ctl.py`, `corpus_ctl.py`,
  `regression_check.py` and `selftest.py` import this module, and
  `surface_cov.py` imports it inside a function for the unpack timeout.
- This module imports no module in `tools/`.

## Failure modes

Every failure is a `ConfigError`, and the command form turns it into exit 1
with the message on standard error.

| Condition | Behaviour |
|---|---|
| Key absent from `DEFAULTS` | `ConfigError` naming the key and listing the valid keys for that section |
| Section holds a scalar where a mapping belongs | `ConfigError` naming the path |
| Top level is `[]`, `false` or `0` | `ConfigError`. An empty file is accepted and means defaults are in force |
| File is not valid YAML | `ConfigError` carrying the parser error |
| PyYAML absent and the file exists | `ConfigError` naming the file and the package to install |
| Any rule violation | `ConfigError` listing every violation from one pass |

An absent configuration file is a valid state. `load` then returns the
defaults, validated.

## Concurrency and durability

The module reads only. It writes no file, takes no lock, and holds one entry of
state in the `cached` memo. The memo keys on path, modification time and size,
so a change between runs is picked up. A caller that needs a consistent
snapshot across a long operation reads once and passes the dict down.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never accept an unknown key | A misspelled key leaves the default silently in force, which on a cap is a budget nobody set |
| Never raise on the first problem | `validate` collects every failure before raising, so one run reports the whole list |
| Never hold a derived value in two places | A sampler holding its own copy of the address polls the old port after a configuration change and records the campaign as `unreachable` |
| Never memoise across an edit | `cached` re-reads when path, modification time or size changes |
| Never accept a top-level scalar | An empty file means defaults are in force, and a top-level scalar is a malformed configuration |
| Never treat a quoted boolean as false | `loop.stop_on_plateau: "false"` is a truthy string, and the rule requires an actual `bool` and says so in its message |

## Design notes

`bool` is an `int` subclass in Python, so every numeric predicate excludes it
explicitly. `loop.max_rounds: true` would otherwise validate as the integer 1.

`loop.max_rounds: 2.5` fails validation, because a float truncates in one place
and compares as 2.5 in another.

The systemd byte-spec rule accepts a number with an optional `K`, `M`, `G` or
`T` suffix, or `infinity`. An unvalidated `12GB` passes YAML and fails only
when systemd refuses to load the unit on the target machine, hours later.

`orchestrator.resume_anchor` is refused when it contains an apostrophe or a
double quote. It is substituted into a shell command line the operator has
already quoted, and a quote in it would end that quoting and hand the rest to
the shell.

## See also

- [Configuration keys](/gspwn/reference/configuration/)
