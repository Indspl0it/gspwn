# NVIDIA GPU Driver + Container Toolkit Fuzzing Workflow — Design v2

Date: 2026-08-12 (v2, incorporates security + academic critique)
Status: Approved architecture; critique revisions applied
Origin: Extends https://www.interruptlabs.co.uk/articles/fuzzing-the-nvidia-gpu-drivers
Intended output: working fuzzing pipeline + technical paper (approach, evaluation, findings)

> **Historical design document.** This is the dated design record — the
> paper's design history — not the current reference. Since it was approved:
>
> - The orchestrator is any `AGENTS.md`-aware coding agent — "Kimi Code"
>   below names the agent in use when the design was approved, not a
>   dependency.
> - The SUT pivoted from the Kali laptop described in §2 to an AWS EC2
>   g4dn.2xlarge (§2's "Cloud deployment" subsection, added at the pivot,
>   has the details; `docs/cloud-setup.md` is the operational runbook).
> - The phase numbering used here (0/1/2a/2b/2c/3/4/4.5/5/5b/6) is the
>   design-era numbering. The code has twelve phases — provision, build,
>   describe, seeds, harness, fuzz, triage, rca, poc, eval, refine, report —
>   defined in `tools/pipeline_state.py`, and the improvement loop
>   (`refine`, rounds, measured stop conditions) was added after this
>   document was written.
>
> For the current architecture, phases, gates and tool behavior, read
> `README.md`, `docs/architecture.md` and `AGENTS.md`. Where this document
> and those disagree, those win.

## 1. Goal

A portable, agentic fuzzing workflow, packaged as a Kimi Code agent repository, that:

1. Provisions a Debian-family Linux target machine (SUT), including persistent kernel-crash log capture.
2. Builds an instrumented kernel (KCOV + KASAN) and NVIDIA open-gpu-kernel-modules, with an explicit degradation ladder if full instrumentation fails.
3. Synthesizes Syzlang descriptions for the NVIDIA ioctl attack surface (agent-authored, validated).
4. Generates seed syz-programs from runtime traces of real CUDA workloads (trace-to-seed).
5. Runs Syzkaller campaigns against the GPU kernel driver (Track K), and in parallel fuzzes NVIDIA Container Toolkit userspace components (Track U).
6. Collects, deduplicates, and triages crashes from both tracks.
7. Performs root-cause analysis (RCA) per unique crash, with LLM-output verification methodology.
8. Produces replayable PoCs, graded by measured reproduction rate from a clean boot.
9. Evaluates the approach against baselines/ablations with metrics suitable for publication.
10. Generates a penetration-test-style report (detailed vulnerability sections with PoCs; **no executive summary**) and manages coordinated disclosure with NVIDIA PSIRT.

The repo is self-contained: `git clone` onto the target laptop, run Kimi Code locally on the target. No SSH, no second machine.

## 2. Hardware / Environment Constraints

- SUT: laptop, 32 GB RAM, NVIDIA GPU, 8 GB VRAM, 2022-era (Ampere/Ada, GSP-based → open-gpu-kernel-modules supported). Model recorded at provision time via `nvidia-smi`.
- OS: Debian-family (current install: Kali, rolling). Nothing Ubuntu-specific: no PPAs, no `ubuntu-*` packages. Distro detected via `/etc/os-release`; packages via `apt` with a Debian/Kali name-mapping table.
- Laptop fully dedicated to fuzzing. Kernel panics expected and acceptable.
- Orchestrator (Kimi Code session) runs on the same machine that panics → all state on disk; the fuzzer runs independently of any agent (§7).
- **Secure Boot:** provision must detect SB state; if enabled, either disable it or enroll a MOK and sign the custom kernel/modules. Unsigned modules will not load otherwise. Day-one blocker if skipped.

### Cloud deployment (current target)

- The SUT is now an AWS EC2 g4dn.2xlarge spot instance (8 vCPU, 32 GB RAM, NVIDIA T4/Turing, GSP-based → open-gpu-kernel-modules supported) running the official Debian 12 AMI. The bare-metal laptop is retired. Setup details: `docs/cloud-setup.md`.
- Crash capture on EC2 uses kdump plus EC2 console output instead of pstore; `tools/crashlog_ctl.py` auto-detects the environment (`--env` overrides) and harvests `aws ec2 get-console-output` alongside `/var/crash` dumps. Hard hangs are captured via console output, so the IAM instance profile allowing `ec2:GetConsoleOutput` is required.
- Cost guardrails: `tools/cost_ctl.py` idle auto-stop watchdog (systemd timer, `IDLE_MINUTES` threshold, `cost_ctl.py keepalive` override) plus AWS Budgets alerts at $50 and $150 against a $200/month ceiling.
- The bare-metal path (pstore, Secure Boot handling) is retained in the tooling as a fallback.

## 3. Threat Model (explicit, per track)

**Track K — kernel driver.** Attacker is an unprivileged process with access to `/dev/nvidiactl`, `/dev/nvidiaX`, `/dev/nvidia-uvm[-tools]`, and `/dev/dri/*` — exactly what a GPU-enabled container tenant receives. Syzkaller `sandbox: namespace` approximates container privileges; it is NOT identical (real containers add seccomp profiles, dropped capabilities, device cgroups). This approximation is stated in the paper, and confirmed PoCs are optionally re-verified inside a real container with GPU devices passed through.

**Track U — NVIDIA Container Toolkit.** Attacker controls the container image (malicious image in a multi-tenant GPU cloud). The code under test runs privileged (root) during container initialization, before full isolation is enforced. Attacker-controlled inputs: OCI `config.json`, hooks, env vars, mounts, CDI device specs.

**Instrumentation blind spot (stated, not hidden).** On GSP-based GPUs the Resource Manager executes in closed-source GSP firmware. KASAN/KCOV instrument only the open kernel-module code; GPU-side DMA corruption of ring buffers/mappings is NOT instrumented. Consequences: (a) `NVRM:`/GSP firmware error messages in `dmesg`/pstore are a secondary crash signal that triage must harvest; (b) all coverage numbers are reported as "reachable kernel-side code only"; (c) GSP firmware version is pinned in the manifest.

## 4. Architecture: Stage-Pipeline Orchestrator (Blackboard Model)

Top-level orchestrator (Kimi Code session driven by repo `AGENTS.md`) walks a resumable state machine in `state/pipeline.json`, dispatching one subagent per phase.

- Subagents are isolated; **no peer-to-peer messaging**. Coordination is blackboard-style via `artifacts/` + `state/pipeline.json`; handoffs pass paths, not transcripts.
- Async work uses background subagents (`run_in_background: true`) with completion notifications (e.g. campaign monitor in background while triage agents work).
- Timed-out subagents are resumed, not restarted.
- **Agents reason, tools act.** Subagents call deterministic tools in `tools/`; they never hand-type long command sequences.
- Phase gates: orchestrator advances only when phase artifacts validate (gates per phase, §6).

## 5. Repository Layout

```
gspwn/
├── AGENTS.md                  # orchestrator contract: phases, gates, conventions
├── agents/
│   ├── provision.md           # target prep: deps, Secure Boot/MOK, crash-log capture, clones
│   ├── build.md               # instrumented kernel + NVIDIA modules, degradation ladder
│   ├── describe.md            # Track K: Syzlang synthesis for nvidia*/uvm/drm ioctls
│   ├── seeds.md               # Track K: trace-to-seed generation from real CUDA workloads
│   ├── harness.md             # Track U: libnvidia-container (C) + Go panic-surface harnesses
│   ├── fuzz.md                # campaign manager, both tracks
│   ├── triage.md              # crash collection, dedup, classification
│   ├── rca.md                 # root cause analysis + verification sampling
│   ├── poc.md                 # repro minimization, clean-boot verification, repro-rate grading
│   ├── eval.md                # metrics, baselines, ablations, plots/tables for the paper
│   ├── refine.md              # coverage-gap classification -> next-round worklist (added with the loop)
│   └── report.md              # pentest-style report + PSIRT disclosure package
├── tools/
│   ├── exec.py                # local command runner with logging/retries
│   ├── pipeline_state.py      # state/pipeline.json load/save/lock + spend ledger (imported by all tools)
│   ├── pipeline_ctl.py        # state machine CLI: phases, rounds, crash registry, loop decisions
│   ├── gspwn_config.py        # loads/validates campaign.yaml; single source of truth for every cap
│   ├── crashlog_ctl.py        # ramoops/pstore + kdump setup; harvest after reboots (EC2: console output)
│   ├── build_kernel.sh        # KCOV+KASAN kernel + modules; grub default; signing if SB on
│   ├── trace2seed.py          # strace of CUDA workloads -> seed syz-programs
│   ├── campaign_ctl.py        # campaign systemd units, corpus policy, per-run deadline timers, budget check
│   ├── coverage_ctl.py        # coverage sampler (both tracks) + plateau verdicts
│   ├── corpus_ctl.py          # promote a run's corpus into the persistent seed bank
│   ├── cost_ctl.py            # EC2 idle auto-stop watchdog + keepalive override
│   ├── crash_parse.py         # parse syz workdir + ASan/libFuzzer artifacts + NVRM/dmesg signals
│   ├── repro_ctl.py           # syz-repro -> C reproducer; Track U replay; clean-boot verification
│   └── selftest.py            # offline test suite (no GPU, root or network)
├── config/
│   ├── machine.yaml           # paths, GPU model, distro, kernel/driver/firmware versions
│   └── campaign.yaml          # syscalls, procs, durations, sandbox, Track U targets, eval matrix
├── artifacts/
│   ├── src/                   # cloned linux, open-gpu-kernel-modules, syzkaller, NCT repos
│   ├── builds/                # builds + manifest.json (toolchain AND target version pins)
│   ├── descriptions/          # Syzlang (Track K)
│   ├── seeds/                 # trace-derived seed syz-programs
│   ├── harnesses/             # fuzz harnesses (Track U)
│   ├── corpus/
│   ├── crashes/<id>/          # raw log, pstore dump, repro candidates, metadata.json
│   ├── rca/<id>.md
│   ├── pocs/<id>/
│   ├── eval/                  # metrics, coverage series, ablation results, plots
│   └── report/
└── state/pipeline.json        # phase statuses, crash registry, resume points
```

## 6. Phases and Data Flow

### Phase 0 — provision (`agents/provision.md`)

- Detect distro, GPU, Secure Boot state; record in `config/machine.yaml`.
- **Crash-log capture (critical):** configure ramoops/pstore to persistent storage and kdump with a crash kernel, so KASAN reports survive hard hangs. Verify with a deliberate test panic (`echo c > /proc/sysrq-trigger`) and confirm a dump is harvested. Bare-metal fuzzing without this loses exactly the most severe findings.
- Handle Secure Boot: disable, or enroll MOK + plan module/kernel signing.
- Install build deps via `apt` (Debian/Kali mapping). Clone into `artifacts/src/`: upstream Linux, open-gpu-kernel-modules, Syzkaller, NCT repos (`nvidia-container-toolkit`, `libnvidia-container`).
- Pin toolchain AND target versions (kernel commit, driver commit, Syzkaller commit, GSP firmware version) into `artifacts/builds/manifest.json`.
- Gate: deps verified, clones present, manifest written, **test panic successfully captured via pstore/kdump**.

### Phase 1 — build (`agents/build.md`)

Degradation ladder, tried in order; the first that boots with GPU functional wins, and the chosen rung is recorded in the manifest:

1. **Full:** KCOV+KASAN kernel + KCOV+KASAN instrumented NVIDIA modules.
2. **Coverage-only modules:** KASAN kernel + KCOV-only modules (KASAN instrumentation of the modules breaks GPU init on some builds).
3. **Uninstrumented modules:** KASAN+KCOV kernel + stock modules (lose driver coverage; keep kernel-side detection on driver entry paths).

Known fragilities handled explicitly: NVIDIA's `conftest.sh` build system strips/ignores foreign CFLAGS (patch build invocation, don't rely on env vars); KASAN-instrumented module code can break GPU initialization. Install, set instrumented kernel as **default grub entry**, sign if SB enabled, reboot.

- Gate: `dmesg` shows expected sanitizer state for the chosen rung; `lsmod` shows nvidia modules loaded; GPU initializes (`nvidia-smi` works).

### Phase 2a — describe (Track K, `agents/describe.md`)

- Check whether Interrupt Labs published their Syzlang descriptions; import-and-extend if yes, author fresh from driver headers/source if no.
- Agent synthesizes descriptions for nvidiactl/nvidiaX/UVM/DRM ioctls: `nv_handle`/`client_nv_handle` resources, root-client allocation, RM object hierarchy, flag enums, argument constraints. Extract ioctl numbers via custom `_IOWR` header + `syz-extract`; compile with `syz-compile`.
- **Validation methodology (LLM-output control):** every agent-authored description must compile AND its ioctls must execute against the device in a smoke run (driver responses in `dmesg`). A sample of descriptions is manually audited against source for direction/struct correctness; audit results logged in `artifacts/eval/`.
- Gate: descriptions compile; smoke run reaches driver; audit sample recorded.

### Phase 2b — seeds (Track K, `agents/seeds.md`) — research contribution

- Trace real CUDA workloads (pytorch/CUDA samples) with strace over the NVIDIA device nodes; `trace2seed.py` converts observed ioctl sequences — including real RM object allocation chains — into seed syz-programs in `artifacts/seeds/`.
- Rationale: the blog traced workloads but never fed traces back as seeds; valid object-hierarchy sequences are exactly what random generation struggles to produce. Contribution is evaluated in Phase 5b (ablation: with/without seeds).
- Gate: seeds parse under syz-manager and execute without description errors.

### Phase 2c — harness (Track U, `agents/harness.md`)

- **Primary target: `libnvidia-container` (C).** libFuzzer/AFL++ harnesses with ASan/UBSan on config parsing, mount logic, container setup paths — the memory-safety surface, and where the CVE-2024-0132 class of bugs lives adjacent.
- **Go components (`nvidia-container-toolkit`, runtime):** Go is memory-safe; fuzzing here targets **panics/DoS in the privileged init path** and logic assertions (e.g. path-validation invariants), not memory corruption. Expectations calibrated accordingly in the report/paper.
- Acknowledged methodology limit: the highest-impact NCT bug class (symlink TOCTOU, mount escapes) is race/logic bugs that coverage-guided fuzzing finds poorly; those are noted as audit-guided future work, not a fuzzing claim.
- Every harness header records the Track U threat model.
- Gate: harnesses build, run on seeds, produce coverage.

### Phase 3 — fuzz (`agents/fuzz.md`)

- Track K: `campaign_ctl.py` installs syz-manager as a systemd service with auto-restart; `sandbox: namespace`; `procs` capped; enabled syscalls: `openat$nvidia*`, `mmap$nvidia*`, `ioctl$NV_*`, `ioctl$UVM_*`, `ioctl$DRM_IOCTL_NVIDIA_*`; cgroup memory limits so the fuzzer dies before system stability does.
- Track U: fuzzers in a Docker container (isolated; immune to Track K panics).
- After every reboot, `crashlog_ctl.py` harvests pstore/kdump output into `artifacts/crashes/` before the campaign resumes.
- Campaigns run unattended, hours to days; `pipeline.json` records config, start time, workdirs.
- Gate: coverage increasing over a defined smoke window.

### Phase 4 — triage (`agents/triage.md`)

- Signals harvested: syz-manager workdir reports, pstore/kdump dumps, ASan/libFuzzer artifacts, and `NVRM:`/GSP error patterns in dmesg (secondary, firmware-side signal).
- **Dedup primary key: syz-manager report title** (bug type + faulting function + key frames); stack hash secondary. Manual-review flag on collisions in BOTH directions (same title/different stacks beyond threshold; same stack/different titles).
- Registry in `pipeline.json`; raw artifacts under `artifacts/crashes/<id>/`.
- Gate: every raw crash registered unique, duplicate, or flagged.

### Phase 4.5 — rca (`agents/rca.md`)

- Per unique crash: agent reads sanitizer report + driver/NCT source; writes `artifacts/rca/<id>.md`: faulting function, root-cause hypothesis, affected versions, exploitability (Track K: privesc/container-escape; Track U: escape under malicious-image model).
- **Verification methodology:** RCA claims about code behavior are sampled for manual audit; audit verdicts logged. The ultimate ground truth is the Phase 5 replayable PoC — the paper states that every reported claim is backed by an executing artifact. Agent failure modes observed during audits are logged as paper data.

### Phase 5 — poc (`agents/poc.md`)

- Track K: `repro_ctl.py` minimizes the syz-program, generates the C reproducer, adds build/run instructions.
- **Verification (replaces naive 3/3 gate):** reproducer executed from a **clean boot** with configured repetition; **reproduction rate measured** (e.g. 7/10). Classification: `reliable` (≥8/10), `flaky` (reproduces <8/10 — races/UAF commonly land here; best-effort RCA retained, clearly labeled in report), `unreproducible`.
- Track U: minimal replayable input + invocation script with preconditions stated.
- Gate: every unique crash has a reproducer + measured repro rate, or an explicit unreproducible classification.

### Phase 5b — eval (`agents/eval.md`) — publication support

- Metrics: edge coverage over time (kernel-side only, per §3), unique crashes, time-to-first-crash, repro rates, agent audit outcomes.
- Baselines: vanilla Syzkaller without NVIDIA descriptions; blog's descriptions if published.
- Ablations: with/without trace-derived seeds; agent-authored vs manually-refined descriptions.
- Protocol: multiple independent runs per configuration (minimum 3 × 24h or as compute allows), variance reported — single-run results are not publishable.
- Version-persistence check: replay the verified PoC suite against one newer driver production branch to test whether findings persist.
- Outputs to `artifacts/eval/`: coverage series, tables, plots.

### Phase 6 — report + disclosure (`agents/report.md`)

- `artifacts/report/<date>-report.md`: pentest style, **detailed vulnerability sections only, no executive summary**. Per finding: description, technical detail, affected code/versions (incl. GSP firmware), severity, repro rate, PoC + reproduction steps, remediation notes. Flaky findings in a labeled subsection.
- **Coordinated disclosure:** per confirmed finding, a PSIRT-ready package (PoC, RCA, affected versions) is assembled in `artifacts/report/disclosure/<id>/`; disclosure status tracked in `pipeline.json`. Nothing is published before NVIDIA PSIRT process completes.

## 7. Resilience Model (orchestrator and target are the same machine)

- Panic kills the Kimi session — expected, not an error.
- syz-manager under systemd auto-restart; box reboots into the instrumented kernel; pstore/kdump preserves the panic report; campaign resumes with no agent involved.
- All state on disk (`pipeline.json` + `artifacts/`). After panic: boot, start Kimi Code, orchestrator resumes — including triaging crashes accumulated while no session ran.
- A reboot is also a *finding signal*: triage correlates reboots with fresh pstore dumps.

## 8. Error Handling

- **Build failures:** agent gets compiler log, one retry with fixes; second failure halts pipeline, diagnosis to `artifacts/builds/FAILED.md`, state `blocked`. Degradation ladder (Phase 1) is the first remedy, not an afterthought.
- **Instrumentation rung 1 unbootable:** fall to rung 2/3 automatically per ladder; record rung in manifest.
- **OOM during fuzzing:** capped `procs` + cgroup memory limits.
- **Non-reproducible crashes:** repro-rate classification (Phase 5).
- **False dedup:** bidirectional manual-review flags (Phase 4).
- **Lost crash logs:** prevented by the Phase 0 pstore/kdump gate — pipeline does not start without verified crash-log capture.

## 9. Scope

In scope: Track K (nvidiactl/nvidiaX/UVM/DRM ioctl fuzzing, Syzkaller, instrumented build, trace-derived seeds); Track U (libnvidia-container C fuzzing + Go panic-surface fuzzing, concurrent with Track K); full pipeline provision → build → describe/seeds/harness → fuzz → triage → rca → poc → eval → report+disclosure.

Out of scope (YAGNI):

- nvidia-modeset dispatcher modeling (future description pack).
- TOCTOU/symlink-race hunting in NCT (audit-guided future work — not a fuzzing capability claim).
- Exploit weaponization — PoCs stop at "reliably triggers the vulnerability."
- Multi-machine fuzzing farms. Windows orchestrator support.

## 10. Research Contributions (paper framing)

1. **LLM-agent-driven Syzlang synthesis** from driver source, with a compile+execute+audit validation methodology; evaluated against hand-refined descriptions.
2. **Trace-to-seed generation** for stateful ioctl fuzzing (strace → syz-programs with valid RM object chains); ablated against seedless runs.
3. **Agentic triage/RCA with execution-backed ground truth** — every claim backed by a replayable PoC; agent failure modes measured and reported.
4. **Methodology:** cloud (EC2 GPU spot) single-SUT kernel fuzzing with persistent crash capture (kdump + console output) and an LLM orchestrator, reproducible via released artifacts (manifest-pinned versions, descriptions, seeds, harnesses). The bare-metal path is retained as a fallback.

Related-work positioning to develop in the paper: existing Syzkaller DRM/ioctl descriptions; DIFUZE-style interface recovery; MoonShine-style seed distillation from traces (2 is the agentic-era counterpart); GPU-driver security analyses and NCT CVE history.

## 11. Open Questions (resolved during implementation)

- Whether Interrupt Labs published their Syzlang descriptions (import vs author).
- Exact GPU model, driver branch, GSP firmware version (recorded at provision).
- Which instrumentation rung the hardware tolerates (Phase 1 ladder).
