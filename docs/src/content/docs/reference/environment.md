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
| `RUN_ID` | `gspwn-u.service` | `artifacts/harnesses/run_all.sh`, to write output under `artifacts/runs/$RUN_ID/u/<harness>/` | (none) |
| `FUZZ_HOURS` | The harness phase's own convention | `run_all.sh`, for how long to run each harness | `24` |

Neither is read by any tool in `tools/`.

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

| Unit | Sets |
|---|---|
| `gspwn-u.service` | `RUN_ID` |
| `gspwn-orchestrator.service` | `HOME`, `XDG_CONFIG_HOME` |
| `gspwn-coverage.service` | `GSPWN_STATE`, only when the install was made under it |
| `gspwn-deadline@<run-id>.service` | `GSPWN_STATE`, through a per-instance drop-in, only when the install was made under it |

## See also

- [Configuration keys](/gspwn/reference/configuration/)
- [systemd units](/gspwn/reference/systemd-units/)
