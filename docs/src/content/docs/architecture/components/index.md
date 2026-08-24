---
title: Components
description: The modules in tools/, what each owns, and the dependencies between them.
---

`tools/` holds two libraries, one test runner, two data files and the
commands below.

Fourteen of the commands read source trees and committed artefacts and never
touch a device. `ioctl_inventory.py`, `ctrl_surface.py`, `object_graph.py`,
`nvkms_inventory.py` and `drm_inventory.py` derive the ioctl surface, the
control command space, the object allocation DAG, the NVKMS command space and
the `/dev/dri` command space from a driver checkout, `value_families.py`
derives the value families that bind bare integer parameter fields, and
`syzlang_gen.py` turns them into a first description set. `ctrl_rank.py` orders the control commands on chain length,
fix history and parameter size. `surface_verify.py` confirms the artefacts
describe the driver actually under test, `surface_cov.py` counts how much of
the enumerated surface a description set and a corpus reach, `refgen.py`
renders the artefacts as the reference pages under `reference/surface/`, and
`regression_check.py` compares the committed artefacts against each other and
against those pages in CI. `cve_patch_map.py` and `patch_mine.py` read the fix
history of the driver and of the two container repositories, the only empirical
signal available before a campaign has run.

| Module | Kind | Owns |
|---|---|---|
| [`pipeline_state.py`](/gspwn/architecture/components/pipeline-state/) | Library | The state schema, the atomic write, the transaction lock, the spend ledger |
| [`pipeline_ctl.py`](/gspwn/architecture/components/pipeline-ctl/) | Command | The state machine's command surface |
| [`gspwn_config.py`](/gspwn/architecture/components/gspwn-config/) | Command and library | Every tunable, and its validation |
| [`campaign_ctl.py`](/gspwn/architecture/components/campaign-ctl/) | Command | Campaigns, deadlines, corpus policy, billing |
| [`coverage_ctl.py`](/gspwn/architecture/components/coverage-ctl/) | Command | Sampling, the curve, the plateau verdict, the GPU probe |
| [`crash_parse.py`](/gspwn/architecture/components/crash-parse/) | Command | Crash identity and registration |
| [`crashlog_ctl.py`](/gspwn/architecture/components/crashlog-ctl/) | Command | Persistent crash capture |
| [`repro_ctl.py`](/gspwn/architecture/components/repro-ctl/) | Command | Reproducer extraction and rate verification |
| [`orchestrator_ctl.py`](/gspwn/architecture/components/orchestrator-ctl/) | Command | The unattended supervisor and its breaker |
| [`corpus_ctl.py`](/gspwn/architecture/components/corpus-ctl/) | Command | The persistent seed bank |
| [`knowledge_ctl.py`](/gspwn/architecture/components/knowledge-ctl/) | Command | The committed knowledge files |
| [`trace2seed.py`](/gspwn/architecture/components/trace2seed/) | Command | strace to syz-program conversion |
| [`ioctl_inventory.py`](/gspwn/architecture/components/ioctl-inventory/) | Command | The escape and UVM ioctl inventory, and the request numbers |
| [`ctrl_surface.py`](/gspwn/architecture/components/ctrl-surface/) | Command | The RM control command space and its privilege classification |
| [`object_graph.py`](/gspwn/architecture/components/object-graph/) | Command | The RM object allocation DAG, its chaining depth, and the allocation chain per owning class |
| [`ctrl_rank.py`](/gspwn/architecture/components/ctrl-rank/) | Command | The measured ordering of the 531 targetable control commands |
| [`nvkms_inventory.py`](/gspwn/architecture/components/nvkms-inventory/) | Command | The NVKMS command space, reconciled between the declaring enum and the dispatch table |
| `drm_inventory.py` | Command | The `/dev/dri` command space, reconciled between `nv_drm_common_ioctl.h` and `nv_drm_ioctls[]` |
| `value_families.py` | Command and library | The value families derived for bare integer parameter fields, and the audit that accepts or rejects each one |
| [`syzlang_gen.py`](/gspwn/architecture/components/syzlang-gen/) | Command | The generated description set, and the per-struct size check on it |
| [`surface_verify.py`](/gspwn/architecture/components/surface-verify/) | Command | The version guard on every statically derived artefact |
| [`surface_cov.py`](/gspwn/architecture/components/surface-cov/) | Command | The share of the enumerated command surface a description set models and a corpus reaches |
| [`verify_tenant_surface.py`](/gspwn/architecture/components/verify-tenant-surface/) | Command | The measured device nodes a container receives, compared against the recorded tenant surface |
| [`cve_patch_map.py`](/gspwn/architecture/components/cve-patch-map/) | Command | The CVE to release-diff join, and the round-1 history worklist |
| [`patch_mine.py`](/gspwn/architecture/components/patch-mine/) | Command | The container-stack fix history, and the Track U target ranking |
| [`gitmine.py`](/gspwn/architecture/components/gitmine/) | Library | The git wrapper, the diff parser, the function attribution and the release-tag mapping both miners share |
| [`refgen.py`](/gspwn/architecture/components/refgen/) | Command and library | The six generated reference pages under `reference/surface/` and the index over them |
| [`regression_check.py`](/gspwn/architecture/components/regression-check/) | Command | The ten CI checks over the committed surface artefacts, the pages generated from them, and the phase briefs' command lines and figures |
| [`exec.py`](/gspwn/architecture/components/exec/) | Command | Logged command execution with retries |
| [`build_kernel.sh`](/gspwn/architecture/components/build-kernel/) | Script | The instrumented kernel build |
| [`selftest.py`](/gspwn/architecture/components/selftest/) | Test runner | The offline suite |

Two files in `tools/` are data. `ioctl_map.json` maps ioctl request
numbers to syzlang description names. `cve_fix_verdicts.json` records the
curated per-CVE fix verdict and the evidence behind each one.

## Dependencies

```mermaid
flowchart TB
  CFG["gspwn_config.py"]
  PS["pipeline_state.py"]

  PC["pipeline_ctl.py"] --> PS
  PC --> CFG
  PC -.->|"lazily, for measurement"| CC
  PC -.->|"lazily, for the live check"| CAM
  PC -.->|"lazily, for the surface reading"| SC
  PC -.->|"lazily, for the brief"| KC

  CAM["campaign_ctl.py"] --> PS
  CAM --> CFG
  CAM --> CC["coverage_ctl.py"]
  CAM --> CO["corpus_ctl.py"]

  CC --> PS
  CC --> CFG

  CP["crash_parse.py"] --> PS
  CP --> CFG

  RC["repro_ctl.py"] --> PS
  RC --> CFG
  RC --> CP

  OC["orchestrator_ctl.py"] --> PS
  OC --> CFG
  OC -.->|"for the disk check"| CC
  OC -->|"subprocess"| CL["crashlog_ctl.py"]

  CO --> PS
  CO --> CFG

  KC["knowledge_ctl.py"] --> PS

  CL -.->|"for the disk report"| CC

  TS["trace2seed.py"]
  EX["exec.py"]

  GM["gitmine.py"]
  PM["patch_mine.py"] --> GM
  CPM["cve_patch_map.py"] --> GM

  SC["surface_cov.py"]
  SC -.->|"lazily, for the unpack timeout"| CFG
  RG["refgen.py"] --> SC
  RCH["regression_check.py"] --> SC
  RCH --> RG
  RCH --> CFG
  CC -.->|"lazily, for the surface column"| SC

  SG["syzlang_gen.py"] -.->|"lazily, breaking the cycle"| VF
  VF["value_families.py"] --> SG
```

`gspwn_config.py` and `pipeline_state.py` are the two roots. Everything that
touches state imports the second, and everything with a tunable imports the
first.

`gitmine.py` is a third root and a library only. It imports nothing in `tools/`
and holds no repository-specific knowledge, so the two miners keep their own fix
signals, path filters and output schemas.

`surface_cov.py`, `refgen.py` and `regression_check.py` all refuse the
`pipeline_state.py` import on purpose. That module needs `fcntl`, and all three
run on the Windows workstation and in CI, where no GPU and no kernel exist.

`trace2seed.py` and `exec.py` import neither root. Both are self-contained, and
`exec.py` is stdlib-only by design because it wraps builds that may run before
anything else is installed.

Nine imports are performed inside a function. `syzlang_gen.py` defers
`value_families.py` because that module imports `syzlang_gen` back at module
scope. Elsewhere the deferral keeps a caller running where the dependency may
be missing or unusable, as `pipeline_ctl.py` does for a surface count on a box
where the inventories were never generated, `crashlog_ctl.py` for the disk
report on the post-panic path, and `surface_cov.py` for the unpack timeout when
the configuration cannot be read.

`selftest.py` imports almost every module in `tools/` and is left out of the
diagram.

## Layering rules

| Rule | Reason |
|---|---|
| `pipeline_state.py` imports no other module in `tools/` | It is the root. It does not read configuration; the caller that has a setting passes it in |
| Only `pipeline_state.py` writes the state file | The atomic write, the backup and the lock live in one place |
| Every tunable comes from `gspwn_config.py` | A value cannot drift between the file and the code that uses it |
| No tool holds a copy of a derived address | `manager_url()` is derived from `track_k.http`, so a port change cannot leave the sampler polling a stale address |
| A tool that spends money reads the ledger, never the state file's own total | The ledger is the authority, and it is machine-global |

## Behaviour on invalid configuration

| Module | Behaviour |
|---|---|
| `pipeline_ctl.py` loop and agent settings | Exits. An unattended loop spends machine time, so the cap must come from the configuration |
| `pipeline_ctl.py validate` drift check | Skips the check and still reports on the registry |
| `coverage_ctl.py` | Falls back to the shipped defaults, because several tools call the verdict path |
| `repro_ctl.py` | Falls back to the shipped defaults, so verification runs on a box mid-edit |
| `orchestrator_ctl.py` resume anchor | Falls back to the module default, because this runs on the post-panic recovery path |

## See also

- [Extending gspwn](/gspwn/architecture/extending/)
