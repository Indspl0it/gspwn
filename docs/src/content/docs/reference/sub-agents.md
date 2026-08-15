---
title: Sub-agents
description: "One row per sub-agent: when it runs, what it reads and writes, its gate, and the tools it calls."
---

The twelve files in `agents/` are the sub-agent definitions. The orchestrator
dispatches one per phase, handing it the file's contents, both configuration
files, and the paths of the artifacts it needs.

## Sub-agent summary

| Sub-agent | Runs | Track | Produces |
|---|---|---|---|
| `provision` | Once per machine | Both | A prepared machine, `machine.yaml`, the build manifest |
| `build` | Once per machine | K | An instrumented kernel and NVIDIA modules |
| `describe` | Once per round | K | syzlang descriptions |
| `seeds` | Once per round | K | Seed programs from traces |
| `harness` | Once per round | U | libFuzzer and AFL++ harnesses |
| `fuzz` | Once per round | Both | A completed campaign |
| `triage` | Once per round | Both | A deduplicated registry |
| `rca` | Once per round | Both | RCA prose, research records, impact records |
| `poc` | Once per round | Both | Verified reproducers with rates |
| `eval` | Once per round | Both | The round's measurements |
| `refine` | Once per round | Both | `gaps.md` and `worklist.md` |
| `report` | Once, after the loop stops | Both | The report and disclosure packages |

`describe`, `seeds` and `harness` may run in parallel after `build`. In round 1
`seeds` consumes the `NV_*` header `describe` produces, so the trio is fully
independent only from round 2 on.

## provision

| Item | Detail |
|---|---|
| **Reads** | `config/machine.yaml`, `config/campaign.yaml` |
| **Writes** | `config/machine.yaml`, `artifacts/builds/manifest.json`, `/etc/sudoers.d/gspwn`, the orchestrator unit |
| **Tools** | `crashlog_ctl.py setup/verify/harvest`, `orchestrator_ctl.py preflight/install`, `pipeline_ctl.py init` |
| **Gate** | `manifest.json` written, `crashlog_ctl.py verify` prints READY, a test panic harvested, and a clean `orchestrator_ctl.py preflight` |
| **Rules** | On EC2 it installs the baseline NVIDIA driver before cloning, so `nvidia-smi` can supply the GPU and GSP firmware facts, and it skips the Secure Boot step |

## build

| Item | Detail |
|---|---|
| **Reads** | `config/machine.yaml`, `artifacts/src/linux`, `artifacts/src/open-gpu-kernel-modules` |
| **Writes** | The installed kernel and modules, `config/machine.yaml`, `artifacts/builds/manifest.json`, per-rung failure notes |
| **Tools** | `build_kernel.sh` through `exec.py`, `crashlog_ctl.py harvest` on a failed rung |
| **Gate** | Booted into the instrumented kernel, KASAN state matching the rung, `lsmod` showing the modules, `nvidia-smi` working |
| **Rules** | Walks the degradation ladder and stops at the first rung that passes. Rungs 2 and 3 pass `SKIP_KERNEL=1` |

## describe

| Item | Detail |
|---|---|
| **Reads** | The driver source, the syzkaller toolchain, the kernel tree, and from round 2 on the work list and `finding-list` |
| **Writes** | `artifacts/descriptions/*.txt`, `artifacts/eval/description-audit.md` |
| **Tools** | `pipeline_ctl.py worklist`, `pipeline_ctl.py finding-list`, `syz-extract`, `syz-compile` |
| **Gate** | syzlang compiles, a smoke run reaches the driver with dmesg evidence, no device node early-outs uniformly, and five sampled descriptions are audited against source |
| **Rules** | Descriptions are agent-authored and treated as untrusted until measured. All four gate checks are required, and their evidence goes in the gate. Every number and struct layout comes from the driver source: the ABI shifts between branches, and a wrong direction bit produces descriptions that compile, run and never reach the driver |

## seeds

| Item | Detail |
|---|---|
| **Reads** | The `NV_*` header from `describe`, the work list, `finding-list`, the seed bank |
| **Writes** | `artifacts/seeds/*.syz`, `tools/ioctl_map.json`, `artifacts/seeds/trace.txt` |
| **Tools** | `trace2seed.py`, `corpus_ctl.py stats`, `pipeline_ctl.py worklist` |
| **Gate** | Seeds exist and parse under syz-manager, with the mapped and unmapped counts reported |
| **Rules** | A precondition that cannot be reached from any available CUDA workload is reported as unreached |

## harness

| Item | Detail |
|---|---|
| **Reads** | `libnvidia-container` and `nvidia-container-toolkit` source, `track_u.docker_image` |
| **Writes** | `artifacts/harnesses/<target>/`, `run_all.sh`, `TARGETS.md`, `track_u.targets` |
| **Tools** | The container toolchain from `track_u.docker_image` |
| **Gate** | Harnesses build, each produces coverage on its seeds in a 60-second run, and `TARGETS.md` carries the ranked entry points with reachability justifications and a `{input}` replay command per harness |
| **Rules** | Entry points are enumerated from the checked-out source and ranked by how directly attacker-controlled bytes reach them. Sanitizer settings are explicit per harness: `detect_leaks` is a stated choice, and UBSan runs with `halt_on_error=1` so the crashing input still matches the report |

## fuzz

| Item | Detail |
|---|---|
| **Reads** | `config/campaign.yaml`, `track_u.targets`, the seed bank, the previous run's corpus |
| **Writes** | The campaign units, the deadline, the coverage series, campaign events |
| **Tools** | `campaign_ctl.py gen-config/install-k/install-u/start/status/wait`, `coverage_ctl.py install-timer/sample/series/gpu-health`, `pipeline_ctl.py round-add-run/campaign-add`, `crashlog_ctl.py harvest` |
| **Gate** | The campaign window has elapsed, both units have been stopped by the deadline timer, and the coverage series covers the whole campaign |
| **Rules** | The smoke window is an early abort check. The gate requires the full campaign window |

## triage

| Item | Detail |
|---|---|
| **Reads** | The syzkaller workdir, the Track U crash directory, every harvested crash log |
| **Writes** | The crash registry, `artifacts/crashes/QUEUE.md` |
| **Tools** | `crash_parse.py`, `pipeline_ctl.py crash-list/crash-set/validate` |
| **Gate** | Every raw crash registered, the flagged queue empty, and a clean `validate` |

## rca

| Item | Detail |
|---|---|
| **Reads** | The crash reports, the driver source, the build manifest |
| **Writes** | `artifacts/rca/<crash-id>.md`, a research record and an impact record per analysed crash |
| **Tools** | `pipeline_ctl.py finding-set/finding-list/impact-set/impact-list/crash-set` |
| **Gate** | An RCA file per crash selected for PoC, each with a research record and an impact record, plus both closing counts |
| **Rules** | Every claim about code behaviour that could not be verified against source is marked `[UNVERIFIED]`, and the `eval` phase samples from exactly that set. Reachability is determined by the `poc` phase: `rca` records what the fault is worth, and `poc` establishes who can reach it, with an experiment |

## poc

| Item | Detail |
|---|---|
| **Reads** | The registry, the syzkaller crash directories, `TARGETS.md` |
| **Writes** | `artifacts/pocs/<crash-id>/`, the reproduction rate and classification in the registry |
| **Tools** | `repro_ctl.py extract/verify`, `pipeline_ctl.py crash-list/validate` |
| **Gate** | A rate and classification per unique crash, and a profile-check outcome per Track K crash that reached reliable or flaky |
| **Rules** | The campaign must be stopped first. `repro_ctl.py verify` refuses while `gspwn-k` is active |

## eval

| Item | Detail |
|---|---|
| **Reads** | The coverage series, the registry, the round history, the RCA files |
| **Writes** | `artifacts/eval/`: coverage artifacts, the findings table, the round progression, `rca-audit.md`, `version-persistence.md` |
| **Tools** | `coverage_ctl.py series/compare`, `pipeline_ctl.py round-show/impact-list` |
| **Gate** | A listing of `artifacts/eval/` with a one-line description of each artifact, including `version-persistence.md` |
| **Rules** | Version persistence replays every reliable PoC against one newer driver branch. It has no tooling behind it, and its outcome is required: a recorded `skipped: <why>` satisfies the gate, and the gate fails when the file is absent. The impact audit re-reads the evidence for every record claiming `privilege-escalation` or `container-escape`, the two claims a vendor challenges first |

## refine

| Item | Detail |
|---|---|
| **Reads** | The coverage series, the syzkaller workdir, the descriptions, the seed bank, `finding-list`, the round history |
| **Writes** | `artifacts/eval/<run-id>/gaps.md`, `artifacts/eval/<run-id>/worklist.md` |
| **Tools** | `coverage_ctl.py series/plateau/gpu-health`, `pipeline_ctl.py finding-list/round-show/round-end`, `corpus_ctl.py promote` |
| **Gate** | Both files written, every item tagged, the plateau verdict with its detail line, the promotion count, the `round-end` summary, and the split of items by source |
| **Rules** | `refine` does not reimplement syzkaller's inner loop. It models ioctls syzkaller has no description for, and supplies valid object-chain seeds syzkaller cannot generate |

## report

| Item | Detail |
|---|---|
| **Reads** | The registry, the RCA files, the impact records, the PoC READMEs, the build manifest |
| **Writes** | `artifacts/report/<date>-report.md`, `artifacts/report/disclosure/<crash-id>/` |
| **Tools** | `pipeline_ctl.py finding-list/impact-list/crash-list/crash-set` |
| **Gate** | The report and the disclosure packages exist, and disclosure statuses are recorded |
| **Rules** | Penetration-test style, detailed vulnerability sections only, no executive summary. A severity is argued as an explicit chain: weakness, primitive, what it lands on, what the attacker controls, reachability, consequence. Findings whose impact record cannot carry a severity are reported with their mechanism and no severity claim. Nothing leaves the machine: the `report` sub-agent assembles the package and stops |

## Common structure

Every sub-agent file carries the same four sections at the end:

| Section | Contents |
|---|---|
| **State** | The `pipeline_ctl.py set-phase` call, and the instruction never to edit `state/pipeline.json` by hand |
| **Gate evidence** | What to return to the orchestrator |
| **Errors** | What one retry looks like, and when to mark the phase `blocked` |
| **Knowledge** | Read `knowledge_ctl.py show --phase <p>` before starting; record learnings and mistakes as they happen |

The knowledge section also carries the public-repository constraint: those
files hold ABI and process facts and never findings, and `note` refuses text
naming a crash id or a path under the finding directories.

## See also

- [Sub-agents](/gspwn/architecture/sub-agents/) covers the isolation model and
  the feedback edge.
- [Execution model](/gspwn/architecture/execution-model/) covers dispatch.
