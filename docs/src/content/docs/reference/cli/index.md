---
title: Command line overview
description: Every tool, what it owns, whether it needs root, and its exit codes.
---

Thirteen tools provide the pipeline's command-line surface, alongside a shared
state library and an offline test runner. Every state change goes through one
of them. Nothing hand-edits `state/pipeline.json`.

## Tools

Every tool accepts `--help`. `crashlog_ctl.py` is the exception: it has a
hand-rolled argument parser and prints its module docstring on a usage error.

| Tool | Owns | Root | Non-standard exits |
|---|---|---|---|
| [`pipeline_ctl.py`](/gspwn/reference/cli/pipeline-ctl/) | The pipeline state machine: phases, crash registry, findings, impacts, rounds, spend | No | 1 problem, 2 usage |
| [`campaign_ctl.py`](/gspwn/reference/cli/campaign-ctl/) | Campaigns as systemd units, deadlines, corpus policy, billing | Install, start, stop | 1 on a failed stop |
| [`coverage_ctl.py`](/gspwn/reference/cli/coverage-ctl/) | Coverage sampling, the series, the plateau verdict, the GPU probe | Timer install, sampling | `plateau`: 0 growing, 1 unknown, 3 plateaued |
| [`crash_parse.py`](/gspwn/reference/cli/crash-parse/) | Scanning crash sources into the deduplicated registry | No | None |
| [`crashlog_ctl.py`](/gspwn/reference/cli/crashlog-ctl/) | Persistent crash capture, harvesting, pruning | Setup, harvest, prune | 1 on an unreadable source |
| [`repro_ctl.py`](/gspwn/reference/cli/repro-ctl/) | Reproducer extraction and reproduction-rate verification | For dmesg reads | `verify`: 0 satisfied, 1 no rate, 2 short denominator |
| [`orchestrator_ctl.py`](/gspwn/reference/cli/orchestrator-ctl/) | The unattended supervisor and its circuit breaker | Install, remove | 78 blocked |
| [`corpus_ctl.py`](/gspwn/reference/cli/corpus-ctl/) | Promoting a run's corpus into the persistent seed bank | No | 1 on a missing bank |
| [`knowledge_ctl.py`](/gspwn/reference/cli/knowledge-ctl/) | Appending to the committed `knowledge/` files | No | 1 problem, 2 usage |
| [`trace2seed.py`](/gspwn/reference/cli/trace2seed/) | Converting an strace of a CUDA workload into seed programs | No | None |
| [`gspwn_config.py`](/gspwn/reference/cli/gspwn-config/) | The single source of truth for every tunable | No | 1 on an invalid configuration |
| [`exec.py`](/gspwn/reference/cli/exec/) | Running a command with logging, retries and a timeout | No | The command's code, 124 timeout, 127 not found |
| [`build_kernel.sh`](/gspwn/reference/cli/build-kernel/) | Building the instrumented kernel and the NVIDIA modules | Yes | 1 gate failure, 2 bad input |
| [`selftest.py`](/gspwn/reference/cli/selftest/) | The offline test suite | No | 1 on failure |

`tools/pipeline_state.py` is a library. Every other tool imports it for the
state-file schema, the atomic write, the transaction lock and the spend ledger.
See [pipeline_state.py](/gspwn/architecture/components/pipeline-state/).

`tools/ioctl_map.json` is data: the map from ioctl request numbers to syzlang
description names that `trace2seed.py` reads.

## Commands requiring root

| Command | Reason |
|---|---|
| `crashlog_ctl.py setup` | Installs packages and edits `/etc/default/grub` |
| `crashlog_ctl.py harvest` | Reads `/sys/fs/pstore` and `/var/crash` |
| `crashlog_ctl.py prune` | Removes directories written by the root harvester |
| `campaign_ctl.py install-k`, `install-u`, `start`, `stop` | Writes and controls systemd units |
| `coverage_ctl.py install-timer`, `remove-timer` | Writes and controls a systemd timer |
| `coverage_ctl.py sample` | Appends to a CSV owned by the root sampler |
| `orchestrator_ctl.py install`, `remove` | Writes and controls a systemd unit |
| `repro_ctl.py verify` on Track K | Reads the kernel ring buffer under `kernel.dmesg_restrict` |
| `build_kernel.sh` | Installs a kernel and modules, edits GRUB |

After a sudo run, the state file, the spend ledger and the lock files are
handed back to `$SUDO_USER`. Left root-owned, every subsequent non-root command
fails with a permission error.

## Command reference by task

| Task | Command |
|---|---|
| Create the state file | `python3 tools/pipeline_ctl.py init` |
| Recover after a panic or a compaction | `python3 tools/pipeline_ctl.py brief` |
| See where the pipeline stands | `python3 tools/pipeline_ctl.py show` |
| Ask which phase to run next | `python3 tools/pipeline_ctl.py next` |
| Advance or block a phase | `python3 tools/pipeline_ctl.py set-phase <phase> <status> --notes "..."` |
| Inspect the crash registry | `python3 tools/pipeline_ctl.py crash-list --status flagged` |
| Fix a triage decision | `python3 tools/pipeline_ctl.py crash-set <id> --duplicate-of <id>` |
| Record a disclosure status | `python3 tools/pipeline_ctl.py crash-set <id> --disclosure pending` |
| Attach a research record | `python3 tools/pipeline_ctl.py finding-set <id> --json -` |
| Read what the findings target | `python3 tools/pipeline_ctl.py finding-list` |
| Attach an impact record | `python3 tools/pipeline_ctl.py impact-set <id> --json -` |
| Read what the report can argue | `python3 tools/pipeline_ctl.py impact-list` |
| Check registry integrity | `python3 tools/pipeline_ctl.py validate` |
| Record a fact about the target | `python3 tools/knowledge_ctl.py note --kind learning --phase <p> "..."` |
| Record a process error | `python3 tools/knowledge_ctl.py note --kind mistake --phase <p> "..."` |
| Read the knowledge files | `python3 tools/knowledge_ctl.py show --kind learning` |
| See round history and budget | `python3 tools/pipeline_ctl.py round-show` |
| Rebuild a lost spend ledger | `python3 tools/pipeline_ctl.py spend-init` |
| Attach a run to this round | `python3 tools/pipeline_ctl.py round-add-run --run-id <id>` |
| Read this round's input worklist | `python3 tools/pipeline_ctl.py worklist` |
| Close a round | `python3 tools/pipeline_ctl.py round-end --from-run <run-id>` |
| Continue or stop the loop | `python3 tools/pipeline_ctl.py round-decide` |
| Open the next round | `python3 tools/pipeline_ctl.py round-advance` |

## See also

- [Exit codes](/gspwn/reference/exit-codes/)
- [Environment variables](/gspwn/reference/environment/)
</content>
</invoke>
