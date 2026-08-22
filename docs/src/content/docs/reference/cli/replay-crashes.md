---
title: replay_crashes.sh
description: Replays every harvested Track U crash input under its own harness and writes the sanitizer output beside it, so the crash can be registered.
---

Replays every harvested Track U crash input under its own harness and writes
the sanitizer output to `<input>.sanlog`.

## Synopsis

```
bash harnesses/replay_crashes.sh
```

Takes no arguments. Everything is set through the environment.

## Purpose

AFL++ and libFuzzer save the bytes that reproduced a crash and not the report
the sanitizer printed. AFL++ names them `id:NNNNNN,sig:NN,...` and libFuzzer
names them `crash-<sha1>`, and `run_all.sh` copies those bytes into
`$ARTIFACT_ROOT/u-crashes/<harness-name>/`.

`crash_parse.py` registers a Track U crash from a sanitizer signature, being an
`ERROR: ...Sanitizer`, `ERROR: libFuzzer:`, `SUMMARY:`, `runtime error:` or
`SEGV` line. A raw input carries none of those, so without this step every
finding is skipped with a warning and the registry stays empty. Track U has
never registered a crash without it.

## Environment

| Variable | Default | Effect |
|---|---|---|
| `ARTIFACT_ROOT` | `/artifacts` | Artifact tree root |
| `CRASH_ROOT` | `$ARTIFACT_ROOT/u-crashes` | Crash root to replay |
| `HARNESS_ROOT` | The script's own directory | Where `<harness>/build/<harness>` is looked for |
| `REPLAY_TIMEOUT` | `60` | Seconds per input |
| `REPLAY_MAX_INPUTS` | `200` | Inputs replayed per harness |
| `REPLAY_FORCE` | `0` | `1` re-replays inputs that already carry a report |

`HARNESS_ROOT` is overridable because a crash root can be carried to a triage
box on its own, where the binaries that produced it live somewhere else.

## Output layout

| Path | Contents |
|---|---|
| `crashes/<harness>/<input>` | The bytes, as the fuzzer saved them |
| `crashes/<harness>/<input>.sanlog` | That input's sanitizer output |

Each report opens with `# replay of <input>` and `# harness <binary>`, carries
the harness's merged stdout and stderr, and closes with `# exit <rc>`. A run
`timeout` killed also carries `# killed at REPLAY_TIMEOUT=Ns`.

Pairing is by name, so `crash_parse.py` tells an input from its report without
a manifest, the report reads next to the bytes that produced it, and a
directory copied or a single input moved by hand stays consistent.
`crash_parse.REPORT_SUFFIX` and the script's own `REPORT_SUFFIX` are asserted
equal by a test, because a drift on either side returns Track U to registering
nothing.

Each report is written to `<input>.sanlog.part` and renamed, so an interrupted
replay never leaves a half report that `crash_parse.py` would read as the whole
of what the sanitizer said.

## Input selection

The harnesses are read off the crash root: a directory under it is named for
the harness that produced it, so the binary path is derivable, and a target
neither `build_all.sh` nor `run_all.sh` has heard of is still replayed.

The walk runs three levels below each harness directory, which covers the
layouts a wholesale copy of a fuzzer output tree produces:
`<harness>/<input>`, `<harness>/crashes/<input>` under libFuzzer, and
`<harness>/default/crashes/<input>` under AFL++. The bound matches the one
`crash_parse.track_u_inputs` walks.

`README`, `README.txt` and any file already ending `.sanlog` are excluded.

An input sitting in the crash root itself names no harness, so no binary can be
chosen for it. The script counts those and says so, and `crash_parse.py` warns
about them once per scan.

## Bounds

| Bound | Behaviour at the limit |
|---|---|
| `REPLAY_TIMEOUT` | `timeout --signal=KILL`, and the report records the kill |
| `REPLAY_MAX_INPUTS` | Stops and prints which harness was capped and that its remaining inputs will not register |
| Harness binary absent | Reported by name with its input count, skipped, exit stays 0 |
| Input already carries a non-empty report | Skipped, unless `REPLAY_FORCE=1` |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The replay ran, whatever the harnesses did |
| 2 | The crash root does not exist, or `REPLAY_TIMEOUT` or `REPLAY_MAX_INPUTS` is not a whole number |

A crashing input is the expected outcome, and `run_all.sh` calls this script
during its harvest, so a non-zero status here would fail a campaign over a
finding. `run_all.sh` sets `status=1` only when the script itself fails.

## Callers

| Caller | When |
|---|---|
| `harnesses/run_all.sh` | At the end of the harvest step |
| An operator | On a crash root carried to another box, or on a campaign that ran under an older `run_all.sh` |

The replay is a separate script because the two jobs have different
preconditions. `run_all.sh` needs a `RUN_ID` and hours of wall clock, and the
replay needs only the crash root and the binaries.

`crash_parse.py` was the wrong home for it. That tool runs at triage, which is
not necessarily where the harness binaries are, and making registration depend
on executing a fuzz target would put arbitrary code execution inside the tool
that writes the registry. `repro_ctl.py verify` was the other candidate, and it
runs after registration on a crash id that registration never created.

## Replay outcomes

| Outcome | Registration |
|---|---|
| The report carries a sanitizer signature | Registered against the input path, with the title and frames read from the report |
| The report carries none | Not registered, and warned. The input did not crash this build |
| No report beside the input | Not registered, and warned, naming this script |
| A `.sanlog` whose input is gone | Registered as itself, because losing the finding is worse than a path `verify` cannot replay |

The registered path is always the input. `repro_ctl._extract_u` copies it to
`artifacts/pocs/<cid>/input` and `verify --track u --cmd` replays that file, so
registering the report would hand `verify` a text log to replay.

An input that does not crash on replay is reported and not registered. Either
the harness was rebuilt since the run that saved it, or the crash depends on
state the replay does not reproduce, and
`harnesses/TARGETS.md` carries the per-target replay command to check
by hand.

## Verified and unverified

Verified in this repository: the reading half end to end against a stub
harness, across the AFL++, libFuzzer and nested layouts; the bounds,
idempotency, the cap, the missing binary, the missing root and a bad timeout;
the pairing, the warnings, the registered path and the frames; and that the
script parses under `bash -n`.

Unverified, because it is decided on the system under test: whether the real
harness binaries replay a file argument, whether real sanitizer output matches
the signature patterns, and whether 60 seconds and 200 inputs are the right
bounds for a 24 hour round. `common/build_common.sh` documents
`./build/<name> <file>` for libFuzzer and links AFL++'s `libAFLDriver.a`, whose
`main()` takes the same form; the stub reproduces that interface and not the
binaries themselves.

## See also

- [crash_parse.py](/gspwn/reference/cli/crash-parse/)
- [repro_ctl.py](/gspwn/reference/cli/repro-ctl/)
- [Environment variables](/gspwn/reference/environment/)
- [Results and triage](/gspwn/guides/results-and-triage/)
