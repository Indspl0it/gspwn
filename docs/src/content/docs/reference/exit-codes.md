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
| `coverage_ctl.py` | `completion` | 0 | Verdict `complete` |
| `coverage_ctl.py` | `completion` | 1 | Verdict `unknown` |
| `coverage_ctl.py` | `completion` | 3 | Verdict `incomplete` |
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
| `refgen.py` | | 0 | Every page was written |
| `refgen.py` | | 2 | An artefact this tool needs is absent, unreadable, empty, or carries a schema stamp it does not read |
| `regression_check.py` | `names`, `pins`, `coverage`, `derived`, `pages`, `all` | 0 | The check passed |
| `regression_check.py` | `names`, `pins`, `coverage`, `derived`, `pages`, `all` | 1 | The check found an offending entry |
| `regression_check.py` | `names`, `pins`, `coverage`, `derived`, `pages`, `all` | 2 | An artefact the check needs is absent, unparseable, or shaped in a way the check did not anticipate, or a check raised an unexpected exception |
| `surface_cov.py` | | 1 | An inventory is absent, does not parse, names a different driver release, a `--run-id` corpus could not be unpacked, or `--corpus` and `--run-id` were both given |
| `surface_cov.py` | | 2 | An argparse usage error, including no subcommand |
| `surface_verify.py` | `check` | 0 | Two or more independent source groups agree, or one group with `--allow-single-source` |
| `surface_verify.py` | `check` | 1 | An input named a file whose format is wrong |
| `surface_verify.py` | `check` | 3 | `DISAGREE`. Source groups disagree |
| `surface_verify.py` | `check` | 4 | `INSUFFICIENT`. Fewer than two independent source groups answered. The committed artefacts are one group |
| `trace2seed.py` | `convert`, `chains` | 0 | At least one program was written |
| `trace2seed.py` | `chains` | 1 | No program was written, so the seed bank is empty |
| `trace2seed.py` | `chains` | 2 | `--max-calls` below the floor of 3, or a non-integer `GSPWN_SEED_MAX_CALLS` |
| `ioctl_inventory.py` | | 1 | An input is absent or does not parse, or the run measured fewer struct sizes than the inventory it would replace |
| `replay_crashes.sh` | | 0 | The replay ran, whatever the harnesses did |
| `replay_crashes.sh` | | 2 | The crash root does not exist, or a bound is not numeric |
| `syzlang_gen.py` | `emit` | 1 | An input is absent, two flags contradict each other, or an emitted selector renders free |
| `syzlang_gen.py` | `emit --strict` | 2 | A derived struct layout disagrees with its measured size |

## Code assignments

| Code | Rule |
|---|---|
| 3 | `coverage_ctl.py plateau` uses 3 for `plateaued` and `completion` uses it for `incomplete`, which keeps both distinct from the shell convention of 2 for a usage error. `surface_verify.py check` uses 3 for a version disagreement |
| 4 | `surface_verify.py check` uses 4 for a verdict reached from fewer than two independent source groups. The value avoids argparse's 2, so a mistyped flag cannot be read as a verdict |
| 78 | `EX_CONFIG` from `sysexits.h`. `gspwn-orchestrator.service` lists it in `RestartPreventExitStatus`, so systemd stops the unit. Four situations produce it: a tripped breaker, an unset `orchestrator.command`, a blocked phase, and a complete pipeline |

## Notes on specific verdicts

`unknown` from `plateau` is a recorded verdict, and the loop treats it as a
stop, so a broken sampler cannot silently authorise more spend. `unknown` from
`completion` never satisfies the completion stop, so a failed corpus read
cannot end a campaign by claiming it is done.

`surface_verify.py check` keeps 3 and 4 apart because the operator does
different work for each. Exit 3 means the artefacts model a release the target
is not running, and the fix is to regenerate them. Exit 4 means the guard
compared nothing, and the fix is to bring a second group up.

An unreadable artefact takes `regression_check.py` to exit 2, and exit 1 is
reserved for an offending entry the check actually found. An unexpected
exception inside a check is exit 2 as well, and under `all` the remaining
checks still run. A checkout missing the committed artefacts therefore never reads
as a real regression in the description set. CI fails on both codes.

Exit 2 from `repro_ctl.py verify` is a result. The rate is recorded and stored
with `repro_runs_counted` beside it, and the message states that the
denominator is short.

`pipeline_ctl.py validate` exits 1 when it reports any integrity problem.
`pipeline_ctl.py worklist` exits 1 when the round has no inherited work list,
or when the recorded file is missing.

## See also

- [Command line overview](/gspwn/reference/cli/)
- [Troubleshooting](/gspwn/guides/troubleshooting/)
