---
title: Environment variables
description: Every variable the tools read, what it redirects, and which are test-only.
---

## Path redirects

| Variable | Redirects | Default | Intended use |
|---|---|---|---|
| `GSPWN_CONFIG` | The configuration file | `config/campaign.yaml` | An alternate configuration |
| `GSPWN_STATE` | The pipeline state file | `state/pipeline.json` | A side run keeping its own registry, and the test suite |
| `GSPWN_SPEND` | The spend ledger | `state/spend.json` | The test suite only |
| `GSPWN_ORCH` | The orchestrator breaker state | `state/orchestrator.json` | The test suite only |
| `GSPWN_KNOWLEDGE` | The knowledge directory | `knowledge/` | The test suite only |
| `GSPWN_SURFACE_LEDGER` | The completion ledger | `surface/completion-ledger.json` | A side run accounting against its own ledger, and the test suite |

```
GSPWN_STATE=/tmp/scratch/pipeline.json python3 tools/pipeline_ctl.py show
```

A campaign installed under `GSPWN_STATE` carries the setting into the units it
writes, so the unattended sampler and the deadline service record against the
same registry the install used.

## Paths GSPWN_STATE does not redirect

| Path | Why |
|---|---|
| `state/spend.json` | A run with its own state file still counts against the single run-hour cap. The budget stays machine-global |
| `state/orchestrator.json` | A run redirecting its state shares the machine's circuit breaker counts |
| `state/repro.lock` | It protects the single dmesg ring on the machine, so two runs with separate registries still exclude each other |

The spend ledger's fallback reads the **default** state file, for the same
reason: a run with a fresh `GSPWN_STATE` would otherwise seed the
machine-global ledger from its own empty registry, and every hour recorded
before it would drop off the budget.

The ledger sits beside the inventories it is counted against and not in the
state file, because `pipeline_state.save()` rewrites the whole state under a
lock on every phase transition, and the ledger carries 764 targets against a
state file of about 1200 bytes.

## Configured values one variable overrides

Each of these has a `coverage.*` key in `config/campaign.yaml`. The variable
overrides the configured value for one invocation, and a config edit is the
durable change.

| Variable | Overrides | Read by | Default |
|---|---|---|---|
| `GSPWN_SURFACE_SAMPLE_MIN` | `coverage.surface_sample_min` | `coverage_ctl.surface_sample_min`, the minutes between surface samples | `60` |
| `GSPWN_SURFACE_MIN_SAMPLES` | `coverage.surface_min_samples` | `coverage_ctl.surface_growth`, the samples needed before the curve's shape is read | `5` |
| `GSPWN_UNPACK_TIMEOUT_SEC` | `coverage.unpack_timeout_sec` | `surface_cov.unpack_timeout_sec`, the seconds `syz-db` may take to unpack one corpus | `300` |

A non-integer `GSPWN_UNPACK_TIMEOUT_SEC` raises `SurfaceError` naming the value
and the fix, so a typo is never read as the configured value.

## Ceilings with no configuration key

| Variable | Read by | Effect | Default |
|---|---|---|---|
| `GSPWN_GIT_TIMEOUT_SECONDS` | `gitmine.GIT_TIMEOUT_SECONDS` | Seconds one git invocation may take, for both patch miners | `300` |
| `GSPWN_HTTP_TIMEOUT_SECONDS` | `cve_patch_map.HTTP_TIMEOUT_SECONDS` | Seconds one PSIRT bulletin fetch may take | `45` |
| `GSPWN_SEED_MAX_CALLS` | `trace2seed.MAX_CALLS` | Calls per emitted program, above which a chain's commands are split across programs that each repeat the prologue | `40` |

`GSPWN_SEED_MAX_CALLS` exists because syzkaller refuses a program above
`prog.MaxCalls`. The default of 40 is unverified: the source records it as
syzkaller's own default taken from memory, no syzkaller tree in this checkout
carries the constant to read, and no emitted program has been through
`prog.Deserialize`. A machine with a syzkaller tree should read `prog.MaxCalls`
there and set this variable to it.

The variable is read once at import and does not raise there, because a bad
value used to end the process in a traceback before argparse had printed a
usage line. `chains` raises it as a `SeedError` and exits 2:

```
trace2seed: GSPWN_SEED_MAX_CALLS must be a whole number of calls per program, and was 'forty'. Unset it to use the default of 40, or pass --max-calls.
```

`convert` does not read the variable and is not failed by it. `--max-calls`
below 3 is refused by `chains` for the same reason: three calls is one
`openat`, one allocation and one control command, and below that every path is
dropped and the run writes an empty bank while exiting 0.

## Read from the environment

| Variable | Read by | Effect |
|---|---|---|
| `SUDO_USER` | `pipeline_state._fix_root_ownership`, `orchestrator_ctl.py install` | After a root write, the state file, the ledger and the lock files are handed back to this user. `install` uses it as the default agent user |
| `ANTHROPIC_API_KEY` | `orchestrator_ctl.py install`, as a warning only | Never read as configuration. `install` warns when it is set, because in the unit's environment it takes precedence over a subscription login and bills the API |

`_fix_root_ownership` exists because `campaign_ctl` start and stop run as root
and write state. Left alone, the state file and the lock file become
root-owned, and every subsequent non-root command fails with a permission
error.

The generated orchestrator unit does not set `ANTHROPIC_API_KEY`. It can still
reach the unit through `/etc/environment` or a drop-in.

## Container-side only

| Variable | Set by | Read by | Default |
|---|---|---|---|
| `RUN_ID` | `gspwn-u.service` | `harnesses/run_all.sh`, to write output under `artifacts/runs/$RUN_ID/u/<harness>/` | (none) |
| `FUZZ_HOURS` | The harness phase's own convention | `run_all.sh`, for how long to run each harness | `24` |

Neither is read by any tool in `tools/`.

## replay_crashes.sh

`harnesses/replay_crashes.sh` runs inside the Track U container and
takes no arguments, so every input it has is an environment variable.

| Variable | Effect | Default |
|---|---|---|
| `ARTIFACT_ROOT` | Artifact tree root | `/artifacts` |
| `CRASH_ROOT` | The crash root to replay | `$ARTIFACT_ROOT/u-crashes` |
| `HARNESS_ROOT` | Where `<harness>/build/<harness>` is looked for | The script's own directory |
| `REPLAY_TIMEOUT` | Seconds one input may run | `60` |
| `REPLAY_MAX_INPUTS` | Inputs replayed per harness | `200` |
| `REPLAY_FORCE` | `1` re-replays inputs that already carry a report | `0` |

`HARNESS_ROOT` is separable from `CRASH_ROOT` because a crash root can be
carried to a triage box on its own, where the binaries that produced it live
somewhere else.

A non-numeric `REPLAY_TIMEOUT` or `REPLAY_MAX_INPUTS` exits 2 before any
harness runs. Full contract:
[replay_crashes.sh](/gspwn/reference/cli/replay-crashes/).

## build_kernel.sh

| Variable | Required | Default |
|---|---|---|
| `LINUX_SRC` | Yes | (none) |
| `NVIDIA_SRC` | Yes | (none) |
| `RUNG` | Yes | (none) |
| `JOBS` | No | `$(nproc)` |
| `BASE_CONFIG` | No | `/boot/config-$(uname -r)` |
| `SKIP_KERNEL` | No | `0` |

Full contract: [build_kernel.sh](/gspwn/reference/cli/build-kernel/).

## systemd unit environment

| Unit | Variables set |
|---|---|
| `gspwn-u.service` | `RUN_ID` |
| `gspwn-orchestrator.service` | `HOME`, `XDG_CONFIG_HOME` |
| `gspwn-coverage.service` | `GSPWN_STATE`, only when the install was made under it |
| `gspwn-deadline@<run-id>.service` | `GSPWN_STATE`, through a per-instance drop-in, only when the install was made under it |

## See also

- [Configuration keys](/gspwn/reference/configuration/)
- [systemd units](/gspwn/reference/systemd-units/)
