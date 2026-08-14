# Documentation

This directory holds the operational and design documentation for the
gspwn workflow: how to stand up a target, why the pipeline is built
the way it is, and how it was implemented. The README is the front door.

| Document | Contents |
|---|---|
| [architecture.md](architecture.md) | Reference for the level below the README: the state-file data model, phase and crash status machines, the durability and locking contract, the lifecycle of a crash from raw log to PSIRT package, run directory layout, how coverage sampling and plateau detection actually work, and how to extend the pipeline. Read before modifying the tools. |
| [cloud-setup.md](cloud-setup.md) | Operational runbook. EC2 instance recipe, golden-image flow, cost guardrails and actual numbers, crash capture on EC2, and learning-phase advice. Read before launching anything. |
| [Design spec](superpowers/specs/2026-08-12-nvidia-driver-fuzzing-workflow-design.md) | Design and rationale. Goals, threat model per track, blackboard architecture, every pipeline phase with its gate, the error-handling model, scope, and the paper framing. Covers the rationale behind the design. |
| [Implementation plan](superpowers/plans/2026-08-12-nvidia-fuzzing-workflow.md) | Implementation record. Task-by-task plan that built the repo: file map, global constraints, and how each tool and agent prompt came to be. Traces each file back to the decision that created it. |
