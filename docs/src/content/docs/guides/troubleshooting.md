---
title: Troubleshooting
description: Symptom to cause to fix, for the failure modes the tools guard against.
---

## Coverage and measurement

| Symptom | Cause | Action |
|---|---|---|
| Coverage flat across the whole smoke window | The GPU has fallen off the bus, so the fuzzer runs against nothing | `python3 tools/coverage_ctl.py gpu-health`. Recover with `nvidia-smi -r`, a module reload, a guest reboot, then an instance stop and start |
| Coverage flat across the whole smoke window, GPU healthy | Descriptions bounce off the driver's argument validation | Check the smoke run's dmesg for uniform early-out per device node. Missing resource chaining is the usual cause |
| `sample` reports `source: unreachable` on Track K | syz-manager's stats endpoint is not answering at `track_k.http` | Confirm the unit is running with `systemctl is-active gspwn-k`, and confirm the address and the endpoint shape for the pinned syzkaller commit |
| `sample` reports `source: unreachable` on Track U | No harness output under `artifacts/runs/<id>/u/` | Confirm `run_all.sh` writes each harness's output there, and that `$RUN_ID` reached the container |
| `sample` reports `source: corpus-count-only` on Track U | The harnesses are libFuzzer, which writes no `fuzzer_stats` | Track U contributes a corpus count and no edge curve for those harnesses. Add an AFL++ harness for an edge signal |
| `sample` fails with a permission error | The CSV is owned by the root sampler | Re-run with `sudo`, or read the curve with `series` |
| `series` prints `edges: never recorded` | No sample carried an edge count | The run cannot support a coverage claim. Exclude it from the round's numbers and say so |

## Plateau verdicts

`plateau` exits 0 for `growing`, 3 for `plateaued` and 1 for `unknown`. Each
`unknown` message has its own cause and its own response.

| Message | Cause | Action |
|---|---|---|
| `only N usable sample(s); need >= 3` | The run is too short, or the sampler started late | Install the sampler before the smoke window |
| `no edge data in any sample` | The source never reported an edge count | Fix the stats endpoint, then re-measure |
| `only N sample(s) usable for a discovery fit; need >= M` | Fewer points in the fitted tail than `coverage.min_fit_samples` | Lower `loop.coverage_sample_min`, or raise `coverage.fit_tail_fraction` |
| `the discovery curve does not fit the model well enough` | A stuck sampler, a source change mid-run, or a genuine regime change | Plot the series. The three look identical in the verdict and need different responses |
| `discovery exponent beta=... is outside (0, 1]` | The series is not behaving like an accumulation curve | Plot the series before concluding anything |
| `the fuzzer is still replaying its corpus after a restart` | The round ended before the fuzzer got back to its own high-water mark | Report the round as unmeasured. Nothing about saturation can be read from it |
| `the GPU was not healthy for N of M sample(s) in the window` | A dead GPU flattened the curve the same way a real plateau would | Recover the GPU and re-measure. Never record a plateau for a round whose GPU died |

An `unknown` verdict stops the loop by design, so a broken sampler cannot
authorise another campaign.

## Campaigns

| Symptom | Cause | Action |
|---|---|---|
| `refusing to install run X: another campaign is still live` | The single global units `gspwn-k` and `gspwn-u` belong to another run, or another run's deadline timer is enabled | Stop the old campaign, or pass `--replace` to retire it |
| `refusing to start: N h already spent + M h exceeds loop.max_total_run_hours` | The run-hour budget cannot cover this campaign | Raise `loop.max_total_run_hours` deliberately, or stop the loop |
| `corpus policy 'carry' requires --from-run` | `--corpus carry` with no source run | Name the previous run id |
| `run X already has a corpus.db but the corpus policy is 'fresh'` | The run id is being reused | Use a new run id |
| `run X is not registered` when sampling | The sampler was pointed at an id no campaign install or `round-add-run` names | Fix the id, or register the run. A typo would create a root-owned run directory that later confuses `series` and `status` |
| `run X: campaign window has elapsed; not sampling` | The sampler timer outlives the campaign | Expected. `--force` overrides it, at the cost of padding the run's sample count |
| The campaign never ends | The deadline file is gone and nothing enforces the window | `check-deadline` rebuilds it from the install record, and stops the units when it cannot |

## The round

| Symptom | Cause | Action |
|---|---|---|
| `next` prints `wait (run X has N h left ...)` | A campaign in this round is still inside its window | Block on `campaign_ctl.py wait --run-id X` |
| `refusing to measure a live campaign` | `round-end` was called while a run is still fuzzing | Wait it out. `--force` is for a campaign that really is finished with only a stale deadline file |
| `cannot advance to round N: round phase(s) not done` | A round phase is not `done` | Finish it, or stop the loop with `round-decide --decision stop --reason "..."` and run `report`. Marking a phase `blocked` does not satisfy the check |
| `cannot advance to round N: round M has no recorded round-end` | The round was never measured | Run `round-end --from-run <run-id>` |
| `a budget or round-cap stop cannot be overridden` | `--decision continue` against a hard cap | Raise the cap in the configuration, deliberately |
| `overriding it requires --reason` | `--decision continue` against a plateau or `unknown` stop | State the reason |

## Triage

| Symptom | Cause | Action |
|---|---|---|
| `WARN: no crashes dir under ...` | The run id is wrong, or the campaign wrote nowhere | Check the id. This means nothing was scanned, and says nothing about whether the run crashed |
| The flagged queue will not empty | A generic panic title with a varying stack flags every distinct stack | Read the reports, then group with one `crash-set a b c --duplicate-of X` call |
| `status 'duplicate' requires --duplicate-of <id>` | A crash was marked a duplicate with no link | Link it, or set `--status unique` |
| `X is itself a duplicate — link directly to the surviving entry` | A duplicate chain | Point at the surviving entry. Chains and cycles are refused |
| `crash-set` changed nothing | A rejected id aborted the whole call | The error names the id. Fix it and re-run |
| The crash count looks enormous | Noise Xids dominate the registry | `show` and `brief` print how many are noise. They are excluded from every derived count |
| `X carries no sanitizer signature — skipped, not registered` | A file in the Track U crash directory is a log, a manifest or a README | Expected. A file with no signature is not a crash |

## Reproduction

| Symptom | Cause | Action |
|---|---|---|
| `refusing to verify while gspwn-k is still fuzzing` | A Track K verification was started with the campaign live | Stop the campaign. `--allow-live-campaign` accepts an inflated rate |
| `dmesg returned no output — refusing to verify` | `kernel.dmesg_restrict=1` and a non-root read | Re-run under `sudo`, or `sudo sysctl -w kernel.dmesg_restrict=0`. Without this every run would score clean and manufacture a 0% rate |
| `another repro_ctl verify session holds state/repro.lock` | Two verifiers on one machine | Wait. They share one dmesg ring and would corrupt each other's delta windows |
| Every run comes back `VOID (dmesg ring wrapped)` | KASAN spam evicts the anchor between the before and after reads | Reduce concurrent noise, or verify on a quieter boot. The attempt cap ends the session once `poc.void_retry_factor` attempts are spent |
| `giving up after N attempts: too many void runs` | The attempt cap fired | Investigate the void reason. Raising `poc.void_retry_factor` only buys more attempts at the same failure |
| `0 counted runs (N void) — no rate recorded` | Every run was void | Exit 1. Investigate the void reason. No rate is available to report |
| `protocol shortfall — N of M requested runs counted` | Exit 2. The rate rests on a short denominator | Check `repro_runs_counted` against `repro_runs_requested` before citing the rate |
| `cannot derive a crash-specific signature` | The registry title yields no usable phrases and no stack frames are registered | Without a signature, runs would be scored against generic `BUG:` patterns any crash would trip |
| `no usable repro.c` | syz-prog2c failed and left an empty stub | Re-run `extract`, which detects the empty file and regenerates it |

## The state file

| Symptom | Cause | Action |
|---|---|---|
| `... is not valid JSON` | A truncated or hand-edited state file | Restore from `state/pipeline.json.bak`, or re-init |
| `spend ledger ... is missing, but the state file records N billed run-hours` | The ledger was lost or predates this version | `pipeline_ctl.py spend-init` |
| `X was analysed by rca but has no finding` | The analysis happened and nothing survived it for the next round | Record one with `finding-set` |
| `X has a finding that steers nothing` | `adjacent` is empty with no `no_adjacent_reason`, or repeats `ioctls` | Read the source for the object's other callers, or state why there are none |
| `X was analysed by rca but has no impact record` | The report would carry a reproducer with no argued severity | Record one with `impact-set` |
| `X has an impact record that does not support its conclusion` | Undetermined with no reason, a primitive with no evidence, or a consequence outrunning its primitive | The message names which of the three |
| `triage.X is N now but the registry's hashes were built with M` | Dedup depth changed mid-campaign | Restore the value for the rest of this campaign, or start a fresh registry |
| Permission errors on every state write | A `sudo` run left the state file root-owned | The tools hand the files back to `$SUDO_USER` after a sudo write. Check `SUDO_USER` was set |

## The orchestrator

| Symptom | Cause | Action |
|---|---|---|
| The unit stops and is not restarted | `run` exited 78, listed in `RestartPreventExitStatus` | The journal says which of the four causes: a tripped breaker, an unset command, a blocked phase, or a complete pipeline |
| `circuit breaker tripped` | Too many same-boot starts, or too many reboots in the window | Read the journal, fix the cause, then `orchestrator_ctl.py reset` |
| `orchestrator.command is not set` | No agent invocation configured | Set it in `config/campaign.yaml` |
| `refusing to install: no non-root user to run the agent as` | `install` had no `--user` and no `$SUDO_USER` | Pass `--user`, or install with `sudo` from that user's shell |
| The harvest captures nothing after a panic | The agent user has no passwordless sudo | `orchestrator_ctl.py preflight` names the remediation |
| `WARN: could not measure the previous transcript` | `orchestrator.session_transcript_glob` is unset or matches nothing | Rotation falls back to the resume count, which does not track transcript growth |
| The agent's usage is billed to the API account | `ANTHROPIC_API_KEY` is set in the unit environment | The variable takes precedence over a subscription login. Unset it for the unit. The generated unit does not set it |

## The build

| Symptom | Cause | Action |
|---|---|---|
| `ERROR: these did not survive olddefconfig: ...` | `olddefconfig` silently dropped an instrumentation option | The named symbols make coverage and symbolization work. Fix the base config |
| `WARNING: ... falling back to 'make defconfig'` | `/boot/config-$(uname -r)` is absent | A defconfig kernel usually lacks the storage and network drivers the machine boots with. Set `BASE_CONFIG` |
| `ERROR: Secure Boot is enabled` | Unsigned out-of-tree modules will not load | Disable it in firmware, or enrol a MOK and sign each `nvidia*.ko` |
| `WARNING: mokutil is not installed` | Secure Boot state is unknown | Install `mokutil`, or confirm Secure Boot is off in firmware |
| `ERROR: no GRUB menu entry for <kver>` | The kernel installed but nothing would boot it | The next reboot would come back on the old kernel and fail the build gate for a reason that looks like the build |
| The NVIDIA module build drops the instrumentation flags | `conftest.sh` strips unknown CFLAGS from the environment | Patch `kernel-open/conftest.sh` minimally to append them, log the patch, retry once per rung |

## Disk

| Symptom | Cause | Action |
|---|---|---|
| `WARN: N GB free, under loop.min_free_disk_gb` | kdump dumps and the corpus have grown | `sudo python3 tools/crashlog_ctl.py prune --keep 10`, or grow the volume |
| Everything fails at once | The disk is full | The fuzzer, the sampler and every state write stop together |

## See also

- [FAQ](/gspwn/project/faq/) answers the questions the code answers
  non-obviously.
- [Exit codes](/gspwn/reference/exit-codes/) lists every non-standard code.
