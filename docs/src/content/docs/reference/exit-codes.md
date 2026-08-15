---
title: Exit codes
description: Every non-standard exit code, per tool.
---

Zero means success everywhere. The table lists the codes that carry a meaning
beyond failure.

| Tool | Command | Code | Meaning |
|---|---|---|---|
| `build_kernel.sh` | | 1 | A gate check failed: missing instrumentation, Secure Boot enabled, or no GRUB entry for the built kernel |
| `build_kernel.sh` | | 2 | Bad input: `RUNG` outside 1 to 3, or `SKIP_KERNEL=1` with no existing `.config` |
| `campaign_ctl.py` | `check-deadline` | 0 | Either the window is still open, or it elapsed and every stop succeeded |
| `campaign_ctl.py` | `check-deadline` | 1 | A `systemctl stop` failed. No stop was recorded, and the timer will retry |
| `campaign_ctl.py` | `wait` | 0 | The window has elapsed |
| `campaign_ctl.py` | `wait` | 1 | `--check` was passed and the campaign is still inside its window |
| `corpus_ctl.py` | `stats` | 1 | No bank at the given path |
| `corpus_ctl.py` | `promote` | non-zero | Refused: `loop.promote_seeds` is false, the corpus is missing, or `syz-db` failed |
| `coverage_ctl.py` | `plateau` | 0 | Verdict `growing` |
| `coverage_ctl.py` | `plateau` | 1 | Verdict `unknown` |
| `coverage_ctl.py` | `plateau` | 3 | Verdict `plateaued` |
| `coverage_ctl.py` | `sample`, `series` | 0 | The sample was recorded, or the series was printed |
| `coverage_ctl.py` | `sample`, `series` | 1 | The source was unreachable, the run is not registered, the CSV could not be written, or no samples exist |
| `coverage_ctl.py` | `gpu-health` | 0 | Status `ok` |
| `coverage_ctl.py` | `gpu-health` | 1 | Any other status |
| `crashlog_ctl.py` | `verify` | 1 | At least one readiness check failed |
| `crashlog_ctl.py` | `harvest` | 0 | No new crash logs found, and every source was readable |
| `crashlog_ctl.py` | `harvest` | non-zero | A source could not be read. Not evidence that no crash occurred |
| `crashlog_ctl.py` | `setup`, `harvest`, `prune` | non-zero | Run as a non-root user |
| `exec.py` | | The command's own code | Normal completion |
| `exec.py` | | 124 | The attempt exceeded `--timeout` |
| `exec.py` | | 127 | The command does not exist |
| `knowledge_ctl.py` | | 0 | Success |
| `knowledge_ctl.py` | | 1 | A problem, or a lookup that found nothing |
| `knowledge_ctl.py` | | 2 | A usage error |
| `orchestrator_ctl.py` | `run` | 78 | The agent was not launched, and restarting would reach the same wall |
| `orchestrator_ctl.py` | `run` | 124 | The launch exceeded `orchestrator.max_agent_hours` and was killed |
| `orchestrator_ctl.py` | `run` | The agent's own code | Otherwise |
| `orchestrator_ctl.py` | `status`, `preflight` | 0 | Not blocked, or preflight clean |
| `orchestrator_ctl.py` | `status`, `preflight` | 1 | The breaker is tripped, or preflight found problems |
| `pipeline_ctl.py` | | 0 | Success |
| `pipeline_ctl.py` | | 1 | A problem, or a lookup that found nothing |
| `pipeline_ctl.py` | | 2 | A usage error |
| `repro_ctl.py` | `verify` | 0 | The protocol was satisfied: at least `--runs` counted runs landed |
| `repro_ctl.py` | `verify` | 1 | A precondition failed, or no counted runs landed so no rate was recorded |
| `repro_ctl.py` | `verify` | 2 | A rate was recorded on fewer counted runs than requested, because the attempt cap fired |

## Code assignments

| Code | Rule |
|---|---|
| 3 | `coverage_ctl.py plateau` uses 3 for `plateaued`, which keeps it distinct from the shell convention of 2 for a usage error |
| 78 | `EX_CONFIG` from `sysexits.h`. `gspwn-orchestrator.service` lists it in `RestartPreventExitStatus`, so systemd stops the unit. Four situations produce it: a tripped breaker, an unset `orchestrator.command`, a blocked phase, and a complete pipeline |

## Notes on specific verdicts

`unknown` from `plateau` is a recorded verdict, and the loop treats it as a
stop, so a broken sampler cannot silently authorise more spend.

Exit 2 from `repro_ctl.py verify` is a result. The rate is recorded and stored
with `repro_runs_counted` beside it, and the message states that the
denominator is short.

`pipeline_ctl.py validate` exits 1 when it reports any integrity problem.
`pipeline_ctl.py worklist` exits 1 when the round has no inherited work list,
or when the recorded file is missing.

## See also

- [Command line overview](/gspwn/reference/cli/)
- [Troubleshooting](/gspwn/guides/troubleshooting/)
