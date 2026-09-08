---
title: Extending gspwn
description: The five extension points, the steps and gate for each, the changes that are not extension points, and the checks that run afterwards.
---

Mutation belongs to the inner loop. syzkaller owns it on Track K, and AFL++ or
libFuzzer owns it on Track U. That loop mutates, measures edges through KCOV,
and keeps corpus-advancing inputs. gspwn does not modify it, and exposes no
mutator plugin API.

The outer loop supplies what the fuzzer cannot produce for itself: models for
ioctls it has no description for, and valid object-chain seeds.

| Extension point | Cost | Files touched |
|---|---|---|
| 1. A syzlang description | Low, largest effect on results | `tools/syzlang_gen.py`, `descriptions/` |
| 2. A Track U harness | Medium | `harnesses/<target>/`, `config/campaign.yaml`, `harnesses/run_all.sh`, `harnesses/TARGETS.md` |
| 3. A configuration key | Low | `tools/gspwn_config.py`, [Configuration keys](/gspwn/reference/configuration/) |
| 4. An Xid classification | Low, research decision | `tools/crash_parse.py` |
| 5. A phase and its sub-agent | High. It touches the state machine | `tools/pipeline_state.py`, `agents/`, `AGENTS.md` |

## 1. A syzlang description

Fuzzing quality is decided in the `describe` phase. See
[Scope and oracle](/gspwn/architecture/scope-and-oracle/).

The description set is generated, and the generated set is committed.
`descriptions/` holds eight files: six `.txt` files, the `_IOWR` header
`descriptions/nvidia_gspwn.h`, and `descriptions/generation.json`, which
records the sha256 of the nine surface artefacts the set was emitted from.
`python3 tools/syzlang_gen.py emit` writes all of them, so a hand edit is
overwritten by the next emission, and `regression_check.py pins` reports one
that survives.

Five requirements apply to a description.

- It is emitted by `tools/syzlang_gen.py` from the surface inventories, and
  the whole regenerated set is committed together with the reference pages
  under `docs/src/content/docs/reference/surface/`.
- It derives from the driver source, never from memory or a blog post, because
  the ABI shifts between branches.
- It compiles under `python3 tools/syzlang_gen.py compile`. syzkaller ships no
  `syz-compile` binary, so the gate builds `tools/gspwn-check` against the
  pinned syzkaller revision `1e72964b0111319984575e60f266d1fa0a98abb5` and
  calls `ast.ParseGlob` then `compiler.Compile` over `descriptions/*.txt`
  together with `tools/syz-stub/*`. Request numbers are literals in the
  emitted set, because the syzkaller tree carrying `syz-extract` is absent
  from this repository. `descriptions/nvidia_gspwn.h` carries the same numbers
  as `_IOWR` macros for `syz-extract` to consume on the machine under test.
- It chains handles with syzkaller resources, so generated programs build valid
  object trees.
- Its gate is the four mandatory checks in `agents/describe.md`.

| Check | Evidence it produces |
|---|---|
| `syzlang_gen.py compile` exits 0 | The set parses and compiles. Quote the verdict line, of the form `compile: OK, 4 const(s) loaded, 957 syscall(s), ...` |
| A smoke campaign, five minutes minimum | dmesg shows programs reaching the driver and doing more than executing. Record the excerpt |
| Reachability | No device node returns an error immediately for every ioctl. A node that does has wrong descriptions, and they are fixed before the gate is reported |
| A manual audit of five sampled descriptions | Direction, struct layout and handle semantics agree with the driver source. Verdicts, failures included, go in `artifacts/eval/description-audit.md` |

A description that compiles and never reaches the driver shows one device node
early-outing uniformly in the smoke run, and the usual cause is missing
resource chaining.

Adding a description for a device node the threat model excludes is a scope
change, recorded in [Threat model](/gspwn/architecture/threat-model/) first.

## 2. A Track U harness and its replay command

A harness is a directory and three registrations, and all four exist before its
crashes can be scored. `regression_check.py harnesses` compares the four.

Six requirements apply to a harness.

- Its directory is `harnesses/<target>/`, holding the source, a `seeds/`
  directory and a `build.sh`.
- It drives exactly one entry point, taking the fuzzer buffer.
- It is deterministic, free of global state between runs, with no network and
  no writes outside a temporary directory, cleaning up per input.
- Its output goes to `/artifacts/runs/$RUN_ID/u/<harness-name>/`, where
  `coverage_ctl.py sample --track u` looks.
- It is registered in `track_u.targets` in `config/campaign.yaml` and in the
  `C_TARGETS` array in `harnesses/run_all.sh`.
- Its replay command is recorded in `harnesses/TARGETS.md`, with `{input}`
  where the path goes, and every path relative to the repository root.

Without a replay command a Track U crash from that harness cannot be scored for
reproduction rate, and the `poc` phase blocks the crash on the `harness` phase.
No invocation is guessed. The `poc` phase passes the recorded command to
`repro_ctl.py verify --track u --cmd`. The six C harnesses take a file path as
a single positional argument:

```
harnesses/fuzz_ldcache/build/fuzz_ldcache {input}
```

Four settings decide what reaches the crash queue, and each is set explicitly
per harness in its `build.sh`.

| Setting | Consequence of leaving it implicit |
|---|---|
| `detect_leaks` under ASan | A leak-detecting harness and a non-leak-detecting one classify the same input differently, and leak findings then reach the report as memory-safety bugs |
| `halt_on_error=1` under UBSan | The process continues past the first error and the crashing input no longer matches the report |
| Whether a crash came from the harness itself | A harness's own buffer handling or temp files reach triage as a driver finding. Every crash is reproduced against the harness first, and the harness-induced ones are discarded with a note |
| Privilege | The code under test normally runs as root, and the harness runs unprivileged. An entry point that only works as root is noted in `TARGETS.md`, and the campaign still does not run privileged |

## 3. A configuration key

A new key is added in five places. The YAML file itself is none of them,
because `config/campaign.yaml` carries values and `tools/gspwn_config.py`
carries the schema.

1. Add the default to the `DEFAULTS` dictionary in `tools/gspwn_config.py`,
   under the section it belongs to. The shape of that dictionary is the schema.
2. Add a validator, an entry in `_RULES` of the form
   `(section, key, (message, predicate))`.
3. Add a cross-field rule in `validate()`, when the key constrains another.
4. Read it through `tools/gspwn_config.py`, by the section accessor where one
   exists (`loop()`, `agent()`, `triage()`, `coverage()`, `poc()`) and through
   `load()` otherwise. No tool re-reads the YAML file for itself.
5. Document it in [Configuration keys](/gspwn/reference/configuration/).

The message is the whole error a researcher sees, so it states what the value
must be and what goes wrong otherwise:

```python
("must be an integer >= 32. Below that the hash covers little more than "
 "the report's first few words, and unrelated trace-less panics sharing "
 "a prologue would merge into one bug",
 lambda v: isinstance(v, int) and not isinstance(v, bool) and v >= 32)
```

Three conditions follow from what a key declares.

| Condition | Consequence |
|---|---|
| A key with no validator | Accepted as any type, and reaches the consumer as whatever YAML parsed it into |
| A numeric predicate without an explicit `bool` exclusion | `bool` is an `int` subclass, so `true` passes a `> 0` check |
| A key absent from `DEFAULTS` | `load()` raises `ConfigError` naming the offending key and the valid keys at that level |

A key no tool reads is documented the same way, because a researcher edits it.
The "Read by" column in [Configuration keys](/gspwn/reference/configuration/)
carries the difference.

## 4. An Xid classification

`XID_CLASS` in `tools/crash_parse.py` maps an Xid number to a class and a
one-line meaning. It holds 22 numbers across four classes. Adding one is a
single line:

```python
121: ("signal", "an Xid this branch introduced"),
```

| Class | Numbers listed | Effect on the registry |
|---|---|---|
| `noise` | 6 | Excluded from every derived crash count. Kept as an audit trail |
| `signal` | 11 | Queued for RCA |
| `health` | 4 | Not a finding. The measurement path is degraded |
| `review` | 1, plus every unlisted number | `xid_class()` returns `review` for any number absent from the table, so a new signal is never silently discarded |

Adding an entry is a research decision. Confirm the number against NVIDIA's Xid
documentation for the driver branch under test, and prefer `review` to `noise`
when unsure. A wrongly-classified `noise` entry drops signal crashes from every
derived count with no warning.

## 5. A phase and its sub-agent

A phase is five edits, and the list it joins decides whether it resets each
round.

1. Add the phase name to `SETUP_PHASES`, `ROUND_PHASES` or `FINAL_PHASES` in
   `tools/pipeline_state.py`, in dependency order. `PHASES` is their
   concatenation.
2. Write the sub-agent at `agents/<phase>.md`, following the shape every other
   one has.
3. Define the gate as evidence the orchestrator can confirm on disk.
4. Record it in the phase table in `AGENTS.md`.
5. Add it to `PARALLEL_AFTER_BUILD` only when it depends on nothing beyond
   `build`. That set currently holds `describe`, `seeds` and `harness`.

| Property | Behaviour |
|---|---|
| A round phase | Resets to `pending` on `round-advance` |
| A setup phase | Persists across rounds |
| A state file predating the new phase | `normalize()` fills the phase in from `DEFAULT_PHASE`, so an added phase does not break an existing registry |

Two sections appear in all twelve sub-agent files: `## Gate evidence` and
`## Knowledge (cross-campaign)`. The Knowledge section names what a learning
looks like for that phase, and repeats the public-repository constraint. A
`## State` section appears in eleven of the twelve, and `## Errors` in four.
See [Sub-agents](/gspwn/architecture/sub-agents/).

## Non-extension points

Seven changes are refused. Each one moves a decision out of the tool that owns
it.

| Change | Reason for refusal |
|---|---|
| Editing `state/pipeline.json` by hand | The tool validates, locks and writes atomically |
| Adding a phase that skips a gate | A gate makes the phase's evidence checkable on disk |
| Widening `track_k.enabled_syscalls` past the threat model | Scope is a threat-model decision, recorded first |
| A tool reading a tunable it defines itself | Every tool reads from `gspwn_config`, so a value cannot drift between the file and the code |
| A second writer for `state/spend.json` | Two derivations of the same figure would disagree |
| Editing a committed artefact under `surface/` by hand | The producing tool is the schema, and `regression_check.py` compares the artefacts against each other on every push to `main` and every pull request |
| Recording a target as covered without a ledger entry or a corpus program | The surface curve is read by subtraction, so an unsupported entry lowers the remaining count and can stop the loop |

## Verification after a change

Seven commands verify a change, and every one of them also runs on a push to
`main` and on a pull request. `syzlang_gen.py compile` runs on a pull request
only when it touches `descriptions/`, `tools/syzlang_gen.py`,
`tools/gspwn-check/`, `tools/syz-stub/` or its own workflow file. The thirteen
`regression_check.py` checks run as thirteen separate steps there.

| Command | Failure it catches |
|---|---|
| `python3 tools/selftest.py` | The tool behaviour `AGENTS.md` requires before the tools are trusted |
| `python3 -m pyflakes tools/*.py` | Undefined names and unused imports |
| `bash -n tools/build_kernel.sh` | A script that runs unattended for hours failing at hour three |
| `python3 tools/gspwn_config.py` | An invalid shipped configuration, defaults merged and fully validated |
| `python3 tools/regression_check.py all` | The committed artefacts no longer agreeing with each other |
| `python3 tools/register_check.py` | Question-shaped headings and table column headers, which scan as labels and survive a read-through |
| `python3 tools/syzlang_gen.py compile` | A description set syzkaller's own compiler rejects |

`regression_check.py all` is itself thirteen checks, run in this order:
`names`, `pins`, `coverage`, `derived`, `reach`, `families`, `pages`, `stale`,
`harnesses`, `agents`, `figures`, `citations` and `commands`. `reach` joins the
allocation chain the chain artefact reports for an owning class against the
handle type the description set gives that class's commands. The other checks
read both artefacts and compare neither statement against the other.
`figures` asserts every
published surface figure against the committed artefacts, so a denominator that
moves in the inventories fails the build until every figure derived from it
moves with it. `commands` parses every documented command line against its
tool's own argparse parser. `citations` reports that it settled nothing where
the vendored source trees under `artifacts/` are absent, which is the case in
CI. `regression_check.py` also fails on a surface artefact edited by hand
without a corresponding edit to the tool that writes it.

## See also

- [Components](/gspwn/architecture/components/)
