---
title: Extending gspwn
description: The five extension points, the steps and gate for each, the changes that are not extension points, and the checks CI runs afterwards.
---

Mutation belongs to the inner loop. syzkaller owns it on Track K, and AFL++ or
libFuzzer owns it on Track U. That loop mutates, measures edges through KCOV,
and keeps corpus-advancing inputs. gspwn does not modify it, and exposes no
mutator plugin API.

The outer loop supplies what the fuzzer cannot produce for itself: models for
ioctls it has no description for, and valid object-chain seeds. Every extension
point below serves one of those two.

| Extension point | Cost | Files touched |
|---|---|---|
| 1. A syzlang description | Low, largest effect on results | `artifacts/descriptions/*.txt` |
| 2. A Track U harness | Medium | `artifacts/harnesses/<target>/`, `config/campaign.yaml` |
| 3. A configuration key | Low | `tools/gspwn_config.py`, the reference docs |
| 4. An Xid classification | Low, research decision | `tools/crash_parse.py` |
| 5. A phase and its sub-agent | High. It touches the state machine | `tools/pipeline_state.py`, `agents/`, `AGENTS.md` |

## 1. A syzlang description

Fuzzing quality is decided in the `describe` phase. Every coverage number and
every crash is downstream of the grammar.

| Step | Detail |
|---|---|
| Where | `artifacts/descriptions/*.txt`, generated at runtime. The repository carries no committed copy |
| Derive from | The driver source. Never from memory or a blog post: the ABI shifts between branches |
| Compile with | `syz-compile`, after extracting constants with `syz-extract` |
| Chain handles | With syzkaller resources, so generated programs build valid object trees |
| Gate | A smoke run whose dmesg shows programs reaching the driver, plus an audit of five sampled descriptions against source |

A description that compiles and never reaches the driver is a failure. The
symptom is one device node early-outing uniformly in the smoke run, and the
usual cause is missing resource chaining.

Adding a description for a device node the threat model excludes is a scope
change, recorded in [Threat model](/gspwn/architecture/threat-model/) first.

## 2. A Track U harness and its replay command

| Step | Detail |
|---|---|
| Where | `artifacts/harnesses/<target>/`, with the source, a `seeds/` directory and a `build.sh` |
| Drives | Exactly one entry point, taking the fuzzer buffer |
| Must be | Deterministic, free of global state between runs, with no network and no writes outside a temporary directory |
| Output goes to | `artifacts/runs/$RUN_ID/u/<harness-name>/`, which is where `coverage_ctl.py sample --track u` looks |
| Registered in | `track_u.targets` in `config/campaign.yaml`, and `artifacts/harnesses/run_all.sh` |
| Replay command | Recorded in `artifacts/harnesses/TARGETS.md` with `{input}` where the path goes |

The replay command is required. Without it a Track U crash from that harness
cannot be scored for reproduction rate, and the `poc` phase blocks the crash on
the `harness` phase. No invocation is guessed.

```
./build/parse_cfg {input}
```

| Sanitizer setting | Stated per harness because |
|---|---|
| Whether `detect_leaks` is in scope | A leak-detecting harness and a non-leak-detecting one classify the same input differently |
| `halt_on_error=1` for UBSan | Without it the process continues past the first error and the crashing input no longer matches the report |

An entry point that only works as root is noted in `TARGETS.md`. The campaign
does not run privileged. The code under test normally runs as root, and the
harness runs unprivileged.

## 3. A configuration key

| Step | Detail |
|---|---|
| Add the default | To the `DEFAULTS` dictionary in `tools/gspwn_config.py`, under the section it belongs to. The shape of that dictionary is the schema |
| Add a validator | An entry in `_RULES`, as `(section, key, (message, predicate))` |
| Add a cross-field rule | In `validate()`, when the key constrains another |
| Read it | Through the section accessor, never by re-reading the file |
| Document it | In [Configuration keys](/gspwn/reference/configuration/) |

The message is the whole error a researcher sees, so it states what the value
must be and what goes wrong otherwise:

```python
("must be an integer >= 32. Below that the hash covers little more than "
 "the report's first few words, and unrelated trace-less panics sharing "
 "a prologue would merge into one bug",
 lambda v: isinstance(v, int) and not isinstance(v, bool) and v >= 32)
```

| Condition | Consequence |
|---|---|
| A key with no validator | Accepted as any type, and reaches the consumer as whatever YAML parsed it into |
| A numeric predicate without an explicit `bool` exclusion | `bool` is an `int` subclass, so `true` passes a `> 0` check |
| A key absent from `DEFAULTS` | `load()` raises `ConfigError` naming the offending key and the valid keys at that level |

A key no tool reads is documented the same way, because a researcher edits it.
The "Read by" column in the reference carries the difference.

## 4. An Xid classification

`XID_CLASS` in `tools/crash_parse.py` maps an Xid number to a class and a
one-line meaning.

```python
121: ("signal", "an Xid this branch introduced"),
```

| Class | Effect on the registry |
|---|---|
| `noise` | Excluded from every derived crash count. Kept as an audit trail |
| `signal` | Queued for RCA |
| `health` | Not a finding. The measurement path is degraded |
| `review` | The default for any unlisted number |

Adding an entry is a research decision. Confirm the number against NVIDIA's Xid
documentation for the driver branch under test, and prefer `review` to `noise`
when unsure. A wrongly-classified `noise` entry drops signal crashes from every
derived count with no warning.

## 5. A phase and its sub-agent

| Step | Detail |
|---|---|
| Add the phase name | To `SETUP_PHASES`, `ROUND_PHASES` or `FINAL_PHASES` in `tools/pipeline_state.py`, in dependency order |
| Write the sub-agent | `agents/<phase>.md`, following the shape every other one has |
| Define the gate | Evidence the orchestrator can confirm on disk |
| Record it | In the phase table in `AGENTS.md` |
| Consider parallelism | Add it to `PARALLEL_AFTER_BUILD` only when it depends on nothing beyond `build` |

| Property | Behaviour |
|---|---|
| A round phase | Resets to `pending` on `round-advance` |
| A setup phase | Persists across rounds |
| A state file predating the new phase | `normalize()` fills the phase in, so an added phase does not break an existing registry |

The sub-agent file carries four sections every other one has: State, Gate
evidence, Errors, and Knowledge. The Knowledge section names what a learning
looks like for that phase, and repeats the public-repository constraint. See
[Sub-agents](/gspwn/architecture/sub-agents/).

## Non-extension points

| Change | Why it is refused |
|---|---|
| Editing `state/pipeline.json` by hand | The tool validates, locks and writes atomically |
| Adding a phase that skips a gate | A gate makes the phase's evidence checkable on disk |
| Widening `track_k.enabled_syscalls` past the threat model | Scope is a threat-model decision, recorded first |
| A tool reading a tunable it defines itself | Every tool reads from `gspwn_config`, so a value cannot drift between the file and the code |
| A second writer for `state/spend.json` | Two derivations of the same figure would disagree |

## Verification after a change

```
python3 tools/selftest.py
python3 -m pyflakes tools/*.py
bash -n tools/build_kernel.sh
python3 tools/gspwn_config.py
```

| Command | Checks |
|---|---|
| `selftest.py` | The tool behaviour `AGENTS.md` requires before the tools are trusted |
| `pyflakes` | Undefined names and unused imports across every tool |
| `bash -n` | Syntax of the build script, which runs unattended for hours |
| `gspwn_config.py` | The effective configuration, defaults merged and fully validated |

CI runs all four, plus a check that every command example in the prose files
matches the tools' real `--help` output.

## See also

- [Components](/gspwn/architecture/components/)
- [Development](/gspwn/project/development/)
- [Contributing](/gspwn/project/contributing/)
