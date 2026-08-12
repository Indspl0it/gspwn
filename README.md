# gspwn

Agentic fuzzing of the NVIDIA GPU kernel driver and NVIDIA Container Toolkit, orchestrated by Kimi Code agents.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3](https://img.shields.io/badge/python-3-blue.svg)](https://www.python.org/)

## What this is

An agentic fuzzing workflow that goes after two attack surfaces:

- Track K: the NVIDIA GPU kernel driver, fuzzed with Syzkaller against a
  KASAN/KCOV-instrumented kernel and open-gpu-kernel-modules build.
- Track U: the NVIDIA Container Toolkit, fuzzed with libFuzzer/AFL++
  harnesses against `libnvidia-container` (C, memory-safety surface) plus
  panic/DoS coverage of the Go components' privileged init path.

The workflow extends Interrupt Labs' internship research on
[fuzzing the NVIDIA GPU drivers](https://www.interruptlabs.co.uk/articles/fuzzing-the-nvidia-gpu-drivers).
Instead of a human driving each step, a Kimi Code session acts as the
orchestrator and dispatches one subagent per pipeline phase.

The goal is CVE-grade findings and a technical paper. Every reported claim is
backed by a replayable PoC with a measured reproduction rate from a clean boot.
Nothing makes it into the report on an agent's say-so.

## How it works

The pipeline runs as a resumable state machine:

```
provision → build → describe / seeds / harness → fuzz → triage → rca → poc → eval → report + disclosure
```

Architecture, in short:

- Orchestrator: a Kimi Code session in the repo root. `AGENTS.md` is the
  contract that turns the session into the orchestrator; it walks
  `state/pipeline.json` and advances only when each phase's gate holds.
- Subagents: one per phase, prompted from `agents/<phase>.md`. Subagents are
  isolated, with no peer messaging, and hand off paths rather than transcripts.
- Tools: subagents reason, but deterministic tools in `tools/` do the acting
  (builds, campaign control, crash parsing, repro verification).
- Blackboard state: everything lives on disk in `state/pipeline.json` and
  `artifacts/`. Nothing pipeline-relevant is held in conversation.
- Panic-proof fuzzing: the fuzzer runs as systemd units with auto-restart.
  The orchestrator runs on the same machine that panics, so a crash kills the
  session but not the campaign. Reboot, harvest the crash logs, resume.

```
                         ┌───────────────────────────┐
                         │  Kimi Code session        │
                         │  (orchestrator, AGENTS.md)│
                         └────────────┬──────────────┘
                                      │ dispatches
            ┌─────────────────────────┼─────────────────────────┐
            ▼                         ▼                         ▼
      phase subagent            phase subagent            phase subagent
      (agents/*.md)             (agents/*.md)             (agents/*.md)
            │                         │                         │
            └────────── calls deterministic tools (tools/) ─────┘
                                      │
                                      ▼
                  state/pipeline.json  +  artifacts/
                  (blackboard: phase gates, crash registry,
                   descriptions, seeds, crashes, PoCs, report)
                                      │
                                      ▼
                     systemd-managed fuzzers on the SUT
              (syz-manager Track K, Track U harness container)
```

## Quickstart (EC2)

Full runbook: [docs/cloud-setup.md](docs/cloud-setup.md). The short version:

1. Launch a spot `g4dn.2xlarge` (8 vCPU, 32 GB, one T4/Turing; Turing is
   GSP-based, so open-gpu-kernel-modules is supported) from the official
   Debian 12 AMI.
2. `git clone` this repo on the instance.
3. Open a Kimi Code session in the repo root. `AGENTS.md` makes the session
   the orchestrator.
4. Say "run the pipeline". The provision phase installs the baseline driver,
   crash capture, and build deps; the build phase swaps in the instrumented
   kernel.
5. Snapshot the provisioned instance to an AMI and launch every campaign from
   it. Re-provisioning cost after the first build is zero.

Cost guardrails come before campaigns: an idle watchdog
(`tools/cost_ctl.py install-watchdog`) auto-stops the instance when no fuzzer
is running, and AWS Budgets alerts fire at $50 and $150 against a $TBD/month
ceiling.

## Threat model

- Track K: the attacker is an unprivileged container tenant with access to
  `/dev/nvidiactl`, `/dev/nvidiaX`, `/dev/nvidia-uvm[-tools]`, `/dev/dri/*`,
  exactly what a GPU-enabled container gets. Syzkaller's `sandbox: namespace`
  approximates container privileges; the approximation and its limits are
  documented in the spec.
- Track U: the attacker controls the container image. The toolkit code under
  test runs privileged (root) during container initialization, before
  isolation is fully enforced. Attacker-controlled inputs are the OCI config,
  hooks, env vars, mounts, and CDI device specs.
- Disclosed blind spot: on GSP-based GPUs the Resource Manager runs in
  closed-source GSP firmware, which KASAN/KCOV cannot instrument. Coverage
  numbers are reported as kernel-side reachable code only, and `NVRM:`/GSP
  firmware errors are harvested as a secondary crash signal.

## Docs

- [docs/index.md](docs/index.md): index of the full documentation set
- [docs/cloud-setup.md](docs/cloud-setup.md): EC2 operational runbook
- [Design spec](docs/superpowers/specs/2026-08-12-nvidia-driver-fuzzing-workflow-design.md): architecture, phases, gates, threat model
- [Implementation plan](docs/superpowers/plans/2026-08-12-nvidia-fuzzing-workflow.md): task-by-task build record

## Responsible disclosure

Confirmed findings go through NVIDIA PSIRT before any publication. A
PSIRT-ready package (PoC, RCA, affected versions) is assembled per finding,
and disclosure status is tracked in `state/pipeline.json`. Nothing is
published before the PSIRT process completes.

This is authorized-security-research tooling. Run it only on systems you own
or have explicit permission to test. Kernel panics are an expected outcome.
That is the point.

## Status

Pre-publication research. The repo carries the orchestrator contract, phase
prompts, tools, and config templates; Syzlang descriptions, seeds, and
harnesses are agent-generated at runtime on the target and land in the
gitignored `artifacts/` tree.

## License

MIT. See [LICENSE](LICENSE).
