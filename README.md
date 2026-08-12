# CUDA-Fuzzing

Agentic fuzzing workflow for the NVIDIA GPU kernel driver (Track K, Syzkaller)
and NVIDIA Container Toolkit (Track U), driven by Kimi Code agents.

Spec: `docs/superpowers/specs/2026-08-12-nvidia-driver-fuzzing-workflow-design.md`

## Use

1. `git clone` this repo on the Debian-family target laptop (the SUT).
2. Install deps: `sudo apt install python3-yaml` (build deps installed by provision phase).
3. Open a Kimi Code session in the repo root. `AGENTS.md` makes the session the orchestrator.
4. Say "run the pipeline" — the orchestrator reads `state/pipeline.json` and proceeds.

Everything the pipeline produces lands in `artifacts/` (gitignored). The fuzzer
runs under systemd and survives orchestrator crashes and kernel panics.

## Layout

- `tools/` — deterministic CLI tools (the mechanical 80%)
- `agents/` — subagent prompt definitions, one per phase
- `AGENTS.md` — orchestrator contract
- `config/` — machine + campaign configuration
- `state/pipeline.json` — resumable pipeline state (gitignored)
- `artifacts/` — all outputs (gitignored)
