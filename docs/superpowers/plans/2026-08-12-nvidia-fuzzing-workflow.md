# NVIDIA Fuzzing Workflow — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the self-contained Kimi Code agent repo (tools, agent prompts, orchestrator contract, configs) that implements the fuzzing workflow in the approved spec.

**Architecture:** Stage-pipeline orchestrator with blackboard coordination. Deterministic Python/Bash tools in `tools/` do all mechanical work; Kimi Code subagents (prompt files in `agents/`) do reasoning; `AGENTS.md` turns any Kimi session in the repo into the orchestrator; state lives in `state/pipeline.json` + `artifacts/`. Everything runs locally on the Debian-family SUT — no SSH.

**Tech Stack:** Python 3 (stdlib only, except `python3-yaml` via apt), Bash, systemd, Syzkaller, upstream Linux kernel, open-gpu-kernel-modules, libFuzzer/AFL++, Docker (Track U only).

**Spec:** `docs/superpowers/specs/2026-08-12-nvidia-driver-fuzzing-workflow-design.md`

## Global Constraints

- **No TDD.** User global instruction overrides all skills: write implementation directly, verify by running, never write failing tests first, no test files unless the user explicitly asks.
- **Debian-family only.** No PPAs, no `ubuntu-*` packages; packages via `apt`; distro detected via `/etc/os-release`.
- **No SSH.** All tools execute locally on the SUT.
- **Python: stdlib only**, except PyYAML from the `python3-yaml` apt package (never pip).
- **Runtime data is not committed.** `artifacts/`, `state/pipeline.json`, and logs are gitignored; the repo carries code, prompts, and config templates only.
- **This plan builds the repo on the dev machine.** Phases that need the GPU/kernel (provision, build, fuzz, …) execute later on the SUT, driven by the orchestrator using these artifacts. Tools must be written so they are correct on Linux; on the dev machine we verify syntax, parsing logic with fixtures, and `--help` output only.
- Commit after every task. Conventional Commits (`feat:`, `docs:`, `chore:`).

## File Map

| File | Responsibility |
|---|---|
| `tools/pipeline_state.py` | Shared `state/pipeline.json` load/save/update helpers (imported by other tools) |
| `tools/exec.py` | Logged local command runner with retries/timeout |
| `tools/crashlog_ctl.py` | pstore/ramoops + kdump setup, verify, harvest (spec Phase 0 gate, A1 fix) |
| `tools/build_kernel.sh` | Instrumented kernel + NVIDIA modules build, degradation ladder rungs 1-3 (A3 fix) |
| `tools/campaign_ctl.py` | systemd units + cgroup limits for syz-manager (Track K) and Track U container |
| `tools/crash_parse.py` | Crash harvesting + dedup (report-title primary key, stack-hash secondary; A5 fix) |
| `tools/trace2seed.py` | strace of CUDA workloads → seed syz-programs (research contribution B2) |
| `tools/repro_ctl.py` | Reproducer extraction, clean-boot verification, repro-rate classification (A6 fix) |
| `tools/ioctl_map.json` | ioctl number → name mapping (placeholder schema; populated on SUT) |
| `AGENTS.md` | Orchestrator contract: state machine, dispatch rules, gates, resume protocol |
| `agents/*.md` | One prompt file per phase subagent (11 files) |
| `config/machine.yaml`, `config/campaign.yaml` | Config templates |
| `README.md` | Export/import + quickstart |
| `.gitignore`, directory `.gitkeep`s | Scaffolding |

---

### Task 1: Repo scaffolding, configs, shared state helper

**Files:**
- Create: `.gitignore`
- Create: `config/machine.yaml`, `config/campaign.yaml`
- Create: `state/pipeline.json` (initial), `tools/pipeline_state.py`
- Create: `.gitkeep` in `artifacts/`, `agents/`, and artifact subdirs
- Create: `README.md`

**Interfaces:**
- Produces: `pipeline_state` module with `load()`, `save(state)`, `update_phase(state, phase, status, notes="")`, `register_crash(state, crash_dict) -> str`, `next_crash_id(state) -> str`, `PHASES` list, `STATE_PATH`. All later Python tools import these.

- [ ] **Step 1: Write `.gitignore`**

```
artifacts/
!artifacts/.gitkeep
!artifacts/*/.gitkeep
state/pipeline.json
__pycache__/
*.pyc
```

- [ ] **Step 2: Create directory skeleton**

```bash
mkdir -p agents tools config state docs artifacts/{src,builds,descriptions,seeds,harnesses,corpus,crashes,rca,pocs,eval,report,logs}
for d in artifacts artifacts/src artifacts/builds artifacts/descriptions artifacts/seeds artifacts/harnesses artifacts/corpus artifacts/crashes artifacts/rca artifacts/pocs artifacts/eval artifacts/report artifacts/logs; do touch "$d/.gitkeep"; done
```

- [ ] **Step 3: Write `tools/pipeline_state.py`** (complete file)

```python
"""Shared pipeline.json state helpers. Stdlib only; imported by other tools."""
import json
import os
import tempfile
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_PATH = os.path.join(REPO_ROOT, "state", "pipeline.json")

PHASES = ["provision", "build", "describe", "seeds", "harness", "fuzz",
          "triage", "rca", "poc", "eval", "report"]
PHASE_STATUS = {"pending", "in_progress", "done", "blocked", "failed"}
CRASH_STATUS = {"unique", "duplicate", "flagged", "reliable", "flaky",
                "unreproducible", "rca_done", "reported"}


def default_state():
    return {
        "version": 1,
        "phases": {p: {"status": "pending", "updated": None, "notes": ""}
                   for p in PHASES},
        "crashes": {},
        "campaigns": [],
        "manifest": "artifacts/builds/manifest.json",
    }


def load(path=STATE_PATH):
    if not os.path.exists(path):
        return default_state()
    with open(path) as f:
        return json.load(f)


def save(state, path=STATE_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def update_phase(state, phase, status, notes=""):
    if phase not in PHASES:
        raise ValueError(f"unknown phase: {phase}")
    if status not in PHASE_STATUS:
        raise ValueError(f"unknown phase status: {status}")
    state["phases"][phase] = {"status": status, "updated": _now(), "notes": notes}


def next_crash_id(state):
    n = len(state["crashes"]) + 1
    while f"crash-{n:04d}" in state["crashes"]:
        n += 1
    return f"crash-{n:04d}"


def register_crash(state, crash):
    """crash dict keys: track(K|U), title, stack_hash, status, dir,
    repro_rate(None), duplicate_of(None), disclosure('pending')."""
    if crash.get("status") not in CRASH_STATUS:
        raise ValueError(f"unknown crash status: {crash.get('status')}")
    cid = next_crash_id(state)
    state["crashes"][cid] = crash
    return cid
```

- [ ] **Step 4: Write initial `state/pipeline.json`**

```bash
python3 -c "import sys; sys.path.insert(0,'tools'); import pipeline_state as ps; ps.save(ps.default_state())"
```

- [ ] **Step 5: Write `config/machine.yaml`**

```yaml
# Filled in by the provision phase on the SUT. All paths are local to the SUT.
distro: ""              # from /etc/os-release ID (e.g. kali, debian)
gpu_model: ""           # from nvidia-smi --query-gpu=name --format=csv,noheader
secure_boot: ""         # enabled | disabled (mokutil --sb-state)
kernel_version: ""      # upstream kernel built in the build phase
driver_branch: ""       # open-gpu-kernel-modules branch/commit
gsp_firmware: ""        # from nvidia-smi -q | grep -i firmware
syzkaller_commit: ""
instrumentation_rung: 0 # 0=undecided, 1=full KASAN+KCOV, 2=KCOV-only modules, 3=uninstrumented modules
paths:
  workdir: "artifacts"  # repo-relative
```

- [ ] **Step 6: Write `config/campaign.yaml`**

```yaml
track_k:
  enabled_syscalls:
    - "openat$nvidia*"
    - "mmap$nvidia*"
    - "ioctl$NV_*"
    - "ioctl$UVM_*"
    - "ioctl$DRM_IOCTL_NVIDIA_*"
  sandbox: "namespace"
  procs: 2                 # capped to protect 32GB RAM budget
  memory_max: "12G"        # systemd cgroup MemoryMax for syz-manager
  http: "127.0.0.1:56744"
  smoke_window_minutes: 30 # coverage must increase within this window
track_u:
  docker_image: "aflplusplus/aflplusplus:latest"
  memory_max: "8G"
  targets: []              # filled by harness phase: names of harness binaries
eval:
  runs_per_config: 3
  run_hours: 24
```

- [ ] **Step 7: Write `README.md`**

```markdown
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
```

- [ ] **Step 8: Verify**

Run: `python3 -c "import sys; sys.path.insert(0,'tools'); import pipeline_state as ps; s=ps.load(); ps.update_phase(s,'provision','in_progress'); ps.register_crash(s,{'track':'K','title':'t','stack_hash':'h','status':'unique','dir':'artifacts/crashes/x','repro_rate':None,'duplicate_of':None,'disclosure':'pending'}); ps.save(s); print(ps.next_crash_id(ps.load()))"`
Expected: prints `crash-0002`; `state/pipeline.json` exists and is valid JSON.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "chore: repo scaffolding, config templates, pipeline state helper"
```

---

### Task 2: `tools/exec.py` — logged command runner

**Files:**
- Create: `tools/exec.py`

**Interfaces:**
- Produces: CLI `python3 tools/exec.py --log NAME [--retries N] [--timeout S] -- CMD [ARGS...]`, exit code = command's exit code; logs appended to `artifacts/logs/NAME.log`.

- [ ] **Step 1: Write `tools/exec.py`** (complete file)

```python
#!/usr/bin/env python3
"""Logged local command runner with retries. Stdlib only.

Usage: python3 tools/exec.py --log NAME [--retries N] [--timeout S] -- CMD [ARGS...]
"""
import argparse
import os
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGDIR = os.path.join(REPO_ROOT, "artifacts", "logs")


def run(cmd, log_name, retries=0, timeout=None):
    os.makedirs(LOGDIR, exist_ok=True)
    logpath = os.path.join(LOGDIR, log_name + ".log")
    attempt = 0
    while True:
        attempt += 1
        with open(logpath, "a") as log:
            log.write("\n=== %s attempt %d: %s\n"
                      % (time.strftime("%Y-%m-%dT%H:%M:%S"), attempt,
                         " ".join(cmd)))
            log.flush()
            try:
                proc = subprocess.run(cmd, stdout=log,
                                      stderr=subprocess.STDOUT,
                                      timeout=timeout)
                rc = proc.returncode
            except subprocess.TimeoutExpired:
                log.write("TIMEOUT after %ss\n" % timeout)
                rc = 124
        if rc == 0 or attempt > retries:
            return rc
        time.sleep(2)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--log", required=True)
    p.add_argument("--retries", type=int, default=0)
    p.add_argument("--timeout", type=int, default=None)
    p.add_argument("cmd", nargs=argparse.REMAINDER)
    a = p.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        p.error("no command given")
    sys.exit(run(cmd, a.log, a.retries, a.timeout))


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify**

Run: `python3 tools/exec.py --log selftest -- python3 -c "print('ok')" && cat artifacts/logs/selftest.log`
Expected: exit 0; log contains `attempt 1` and `ok`.

Run: `python3 tools/exec.py --log selftest -- python3 -c "import sys; sys.exit(3)"; echo "rc=$?"`
Expected: `rc=3`.

- [ ] **Step 3: Commit**

```bash
git add tools/exec.py && git commit -m "feat: logged command runner tool"
```

---

### Task 3: `tools/crashlog_ctl.py` — persistent kernel crash capture (spec Phase 0 gate)

**Files:**
- Create: `tools/crashlog_ctl.py`

**Interfaces:**
- Produces: CLI subcommands `setup`, `verify`, `harvest`. `harvest` prints the created artifact directory path on the last line (consumed by triage agent and `campaign_ctl.py`).

- [ ] **Step 1: Write `tools/crashlog_ctl.py`** (complete file)

```python
#!/usr/bin/env python3
"""Persistent kernel-crash log capture: ramoops/pstore + kdump.

Subcommands:
  setup    - install kdump-tools, ensure pstore mount, set crashkernel= param
  verify   - check pstore/kdump readiness; print sysrq test instructions
  harvest  - copy /sys/fs/pstore/* and newest /var/crash dump into artifacts/

Must run as root for setup/harvest. Debian-family (apt) only.
"""
import glob
import os
import shutil
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRASHES_DIR = os.path.join(REPO_ROOT, "artifacts", "crashes")
GRUB_DEFAULT = "/etc/default/grub"


def sh(cmd, check=True, capture=False):
    return subprocess.run(cmd, check=check, text=True,
                          capture_output=capture)


def cmd_setup():
    if os.geteuid() != 0:
        sys.exit("setup must run as root")
    sh(["apt-get", "update"])
    sh(["apt-get", "install", "-y", "kdump-tools", "pstore-tools"])
    # crashkernel param
    with open(GRUB_DEFAULT) as f:
        grub = f.read()
    if "crashkernel=" not in grub:
        shutil.copy(GRUB_DEFAULT, GRUB_DEFAULT + ".bak-cuda-fuzzing")
        grub = grub.replace(
            'GRUB_CMDLINE_LINUX_DEFAULT="',
            'GRUB_CMDLINE_LINUX_DEFAULT="crashkernel=256M ')
        with open(GRUB_DEFAULT, "w") as f:
            f.write(grub)
        sh(["update-grub"])
        print("added crashkernel=256M; reboot required")
    # pstore mount (usually automatic via systemd)
    if not os.path.ismount("/sys/fs/pstore"):
        sh(["mount", "-t", "pstore", "pstore", "/sys/fs/pstore"], check=False)
    sh(["systemctl", "enable", "kdump-tools"], check=False)
    print("setup done. Next: reboot, then run: crashlog_ctl.py verify")


def cmd_verify():
    ok = True
    if not os.path.isdir("/sys/fs/pstore"):
        print("FAIL: /sys/fs/pstore missing (pstore not supported/mounted)")
        ok = False
    r = sh(["systemctl", "is-active", "kdump-tools"], check=False,
           capture=True)
    if r.stdout.strip() != "active":
        print("WARN: kdump-tools not active: " + r.stdout.strip())
    with open("/proc/cmdline") as f:
        if "crashkernel=" not in f.read():
            print("FAIL: crashkernel= not in kernel cmdline; reboot needed")
            ok = False
    if ok:
        print("READY. Now validate capture with a deliberate panic:")
        print("  1. sync")
        print("  2. echo c > /proc/sysrq-trigger   # machine panics, reboots")
        print("  3. after boot: crashlog_ctl.py harvest")
        print("     (must produce a dmesg/ramoops dump containing the panic)")
    sys.exit(0 if ok else 1)


def cmd_harvest():
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(CRASHES_DIR, "pstore-" + stamp)
    os.makedirs(dest, exist_ok=True)
    found = False
    for src in glob.glob("/sys/fs/pstore/*"):
        shutil.copy(src, dest)
        found = True
    crashes = sorted(glob.glob("/var/crash/*"), key=os.path.getmtime)
    if crashes:
        newest = crashes[-1]
        out = os.path.join(dest, "kdump-" + os.path.basename(newest))
        shutil.copytree(newest, out, dirs_exist_ok=True)
        found = True
    if not found:
        os.rmdir(dest)
        print("no crash logs found")
        sys.exit(1)
    print(dest)  # last line = artifact path, consumed by callers


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("setup", "verify", "harvest"):
        sys.exit(__doc__)
    {"setup": cmd_setup, "verify": cmd_verify,
     "harvest": cmd_harvest}[sys.argv[1]]()


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify (dev machine)**

Run: `python3 tools/crashlog_ctl.py`
Expected: prints the usage docstring, exits non-zero.

Run: `python3 -c "import ast; ast.parse(open('tools/crashlog_ctl.py').read())"`
Expected: no output (syntax valid).

- [ ] **Step 3: Commit**

```bash
git add tools/crashlog_ctl.py && git commit -m "feat: pstore/kdump crash capture tool"
```

---

### Task 4: `tools/build_kernel.sh` — instrumented build with degradation ladder

**Files:**
- Create: `tools/build_kernel.sh`

**Interfaces:**
- Consumes: `config/machine.yaml` values passed as env vars by the build agent: `LINUX_SRC` (path to kernel source), `NVIDIA_SRC` (path to open-gpu-kernel-modules), `RUNG` (1|2|3), `JOBS`.
- Produces: installed kernel + modules, grub default entry, `artifacts/builds/manifest.json` fields `instrumentation_rung` and build logs in `artifacts/logs/build-*.log`.

- [ ] **Step 1: Write `tools/build_kernel.sh`** (complete file)

```bash
#!/usr/bin/env bash
# Build instrumented kernel + NVIDIA open-gpu-kernel-modules.
# Degradation ladder (spec Phase 1):
#   RUNG=1  KASAN+KCOV kernel, KASAN+KCOV nvidia modules
#   RUNG=2  KASAN+KCOV kernel, KCOV-only nvidia modules
#   RUNG=3  KASAN+KCOV kernel, uninstrumented nvidia modules
# Required env: LINUX_SRC, NVIDIA_SRC, RUNG. Optional: JOBS (default nproc).
set -euo pipefail

: "${LINUX_SRC:?set to kernel source dir}"
: "${NVIDIA_SRC:?set to open-gpu-kernel-modules dir}"
: "${RUNG:?1|2|3}"
JOBS="${JOBS:-$(nproc)}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOGDIR="$REPO_ROOT/artifacts/logs"
mkdir -p "$LOGDIR"

[[ "$RUNG" =~ ^[123]$ ]] || { echo "RUNG must be 1, 2 or 3"; exit 2; }

echo "== kernel config (KASAN+KCOV) =="
cd "$LINUX_SRC"
make defconfig 2>&1 | tee "$LOGDIR/build-kernel-config.log"
scripts/config --enable CONFIG_KCOV \
               --enable CONFIG_KASAN \
               --enable CONFIG_KASAN_GENERIC \
               --enable CONFIG_UBSAN \
               --enable CONFIG_DEBUG_INFO \
               --enable CONFIG_PSTORE --enable CONFIG_PSTORE_RAM \
               --enable CONFIG_PSTORE_CONSOLE \
               --enable CONFIG_KEXEC_CORE --enable CONFIG_CRASH_DUMP \
               --disable CONFIG_RANDOMIZE_BASE   # stable stacks for dedup
make olddefconfig 2>&1 | tee -a "$LOGDIR/build-kernel-config.log"

echo "== kernel build (-j$JOBS) =="
make -j"$JOBS" 2>&1 | tee "$LOGDIR/build-kernel.log"

echo "== kernel install =="
sudo make modules_install 2>&1 | tee -a "$LOGDIR/build-kernel.log"
sudo make install        2>&1 | tee -a "$LOGDIR/build-kernel.log"

echo "== NVIDIA modules (rung $RUNG) =="
cd "$NVIDIA_SRC"
KVER="$(make -sC "$LINUX_SRC" kernelrelease)"
# NVIDIA's conftest.sh strips unknown CFLAGS from env; pass via
# KBUILD_EXTRA_CFLAGS and patch kernel-open/conftest.sh if rung 1 fails
# (build agent handles the patch; see agents/build.md).
case "$RUNG" in
  1) KBUILD_EXTRA_CFLAGS="-fsanitize=kernel-address" ;;
  2) KBUILD_EXTRA_CFLAGS="-fsanitize-coverage=trace-pc,trace-cmp" ;;
  3) KBUILD_EXTRA_CFLAGS="" ;;
esac
make -C kernel-open -j"$JOBS" \
     SYSSRC="$LINUX_SRC" \
     KBUILD_EXTRA_CFLAGS="$KBUILD_EXTRA_CFLAGS" \
     2>&1 | tee "$LOGDIR/build-nvidia.log"
sudo make -C kernel-open modules_install SYSSRC="$LINUX_SRC" \
     2>&1 | tee -a "$LOGDIR/build-nvidia.log"
sudo depmod "$KVER"

echo "== secure boot signing (if enabled) =="
if mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled"; then
  echo "Secure Boot enabled: sign modules with enrolled MOK before reboot."
  echo "  sbsign / kmodsign each nvidia*.ko, or disable SB in firmware."
fi

echo "== grub default =="
sudo grub-set-default "Advanced options>Linux $KVER" 2>/dev/null \
  || echo "set default boot entry manually to kernel $KVER"
sudo update-grub

echo "== manifest =="
python3 - "$REPO_ROOT" "$RUNG" "$KVER" <<'EOF'
import json, os, subprocess, sys
root, rung, kver = sys.argv[1], int(sys.argv[2]), sys.argv[3]
mpath = os.path.join(root, "artifacts", "builds", "manifest.json")
m = json.load(open(mpath)) if os.path.exists(mpath) else {}
m.update({
  "instrumentation_rung": rung,
  "kernel_release": kver,
  "gcc": subprocess.run(["gcc","--version"],capture_output=True,text=True)
         .stdout.splitlines()[0],
  "linux_commit": subprocess.run(["git","-C",os.environ["LINUX_SRC"],
         "rev-parse","HEAD"],capture_output=True,text=True).stdout.strip(),
  "nvidia_commit": subprocess.run(["git","-C",os.environ["NVIDIA_SRC"],
         "rev-parse","HEAD"],capture_output=True,text=True).stdout.strip(),
})
json.dump(m, open(mpath,"w"), indent=2)
print("manifest updated:", mpath)
EOF

echo "BUILD COMPLETE (rung $RUNG). Reboot into kernel $KVER."
```

- [ ] **Step 2: Verify syntax**

Run: `bash -n tools/build_kernel.sh`
Expected: no output (syntax valid).

- [ ] **Step 3: Verify shellcheck if available**

Run: `command -v shellcheck >/dev/null && shellcheck -S warning tools/build_kernel.sh || echo "shellcheck not installed, skipped"`
Expected: no warnings, or the skip message.

- [ ] **Step 4: Commit**

```bash
git add tools/build_kernel.sh && git commit -m "feat: instrumented kernel+module build with degradation ladder"
```

---

### Task 5: `tools/campaign_ctl.py` — systemd-managed fuzz campaigns

**Files:**
- Create: `tools/campaign_ctl.py`

**Interfaces:**
- Consumes: `config/campaign.yaml`; `tools/pipeline_state.py` (`load`, `save`).
- Produces: CLI subcommands `install-k`, `install-u`, `start <k|u>`, `stop <k|u>`, `status`. Writes systemd units `cuda-fuzz-k.service` / `cuda-fuzz-u.service`; `status` prints one line per track: `active|inactive|failed`, plus latest syz-manager stats if present.

- [ ] **Step 1: Write `tools/campaign_ctl.py`** (complete file)

```python
#!/usr/bin/env python3
"""Install/manage fuzz campaigns as systemd units (survive panics/reboots).

Subcommands: install-k | install-u | start <k|u> | stop <k|u> | status
Requires root for install/start/stop. Reads config/campaign.yaml.
"""
import os
import subprocess
import sys

import yaml  # python3-yaml (apt)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
CFG_PATH = os.path.join(REPO_ROOT, "config", "campaign.yaml")
UNIT_K = "/etc/systemd/system/cuda-fuzz-k.service"
UNIT_U = "/etc/systemd/system/cuda-fuzz-u.service"

UNIT_K_TMPL = """[Unit]
Description=CUDA-Fuzzing Track K (syzkaller)
After=multi-user.target

[Service]
Type=simple
WorkingDirectory={root}
ExecStart={syzkaller}/bin/syz-manager -config {root}/artifacts/syz-manager.cfg
Restart=always
RestartSec=30
MemoryMax={memory_max}

[Install]
WantedBy=multi-user.target
"""

UNIT_U_TMPL = """[Unit]
Description=CUDA-Fuzzing Track U (NCT userspace fuzzers)
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/docker run --rm --name cuda-fuzz-u \\
  -v {root}/artifacts:/artifacts {image} \\
  /artifacts/harnesses/run_all.sh
Restart=always
RestartSec=30
MemoryMax={memory_max}

[Install]
WantedBy=multi-user.target
"""


def cfg():
    with open(CFG_PATH) as f:
        return yaml.safe_load(f)


def sh(cmd, check=True, capture=False):
    return subprocess.run(cmd, check=check, text=True, capture_output=capture)


def write_unit(path, text):
    if os.geteuid() != 0:
        sys.exit("install/start/stop must run as root")
    with open(path, "w") as f:
        f.write(text)
    sh(["systemctl", "daemon-reload"])


def cmd_install_k():
    c = cfg()["track_k"]
    syzkaller = os.path.join(REPO_ROOT, "artifacts", "src", "syzkaller")
    write_unit(UNIT_K, UNIT_K_TMPL.format(
        root=REPO_ROOT, syzkaller=syzkaller, memory_max=c["memory_max"]))
    sh(["systemctl", "enable", "cuda-fuzz-k"])
    print("installed cuda-fuzz-k.service (MemoryMax=%s)" % c["memory_max"])


def cmd_install_u():
    c = cfg()["track_u"]
    write_unit(UNIT_U, UNIT_U_TMPL.format(
        root=REPO_ROOT, image=c["docker_image"], memory_max=c["memory_max"]))
    sh(["systemctl", "enable", "cuda-fuzz-u"])
    print("installed cuda-fuzz-u.service (MemoryMax=%s)" % c["memory_max"])


def unit(track):
    return {"k": "cuda-fuzz-k", "u": "cuda-fuzz-u"}[track]


def cmd_start_stop(verb, track):
    if os.geteuid() != 0:
        sys.exit("start/stop must run as root")
    sh(["systemctl", verb, unit(track)])
    st = ps.load()
    st["campaigns"].append({"track": track, "action": verb})
    ps.save(st)
    print("%s %s" % (verb, unit(track)))


def cmd_status():
    for t in ("k", "u"):
        r = sh(["systemctl", "is-active", unit(t)], check=False, capture=True)
        print("track %s: %s" % (t, r.stdout.strip()))
    stats = os.path.join(REPO_ROOT, "artifacts", "syz-workdir", "stats")
    # syz-manager HTTP stats are canonical; fall back to corpus size
    corpus = os.path.join(REPO_ROOT, "artifacts", "syz-workdir", "corpus.db")
    if os.path.exists(corpus):
        print("corpus.db size: %d bytes" % os.path.getsize(corpus))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "install-k":
        cmd_install_k()
    elif cmd == "install-u":
        cmd_install_u()
    elif cmd in ("start", "stop") and len(sys.argv) == 3:
        cmd_start_stop(cmd, sys.argv[2])
    elif cmd == "status":
        cmd_status()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify (dev machine)**

Run: `python3 tools/campaign_ctl.py status`
Expected: prints `track k: inactive` (or `failed`/`unknown`) and `track u: ...` — must not traceback. On Windows dev machine without systemctl, expect a `FileNotFoundError` — that is acceptable on dev; note it and confirm syntax instead:

Run: `python3 -c "import ast; ast.parse(open('tools/campaign_ctl.py').read())"`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add tools/campaign_ctl.py && git commit -m "feat: systemd fuzz campaign manager with cgroup memory caps"
```

---

### Task 6: `tools/crash_parse.py` — crash harvesting and dedup

**Files:**
- Create: `tools/crash_parse.py`

**Interfaces:**
- Consumes: `tools/pipeline_state.py` (`load`, `save`, `register_crash`); syz workdir at `artifacts/syz-workdir/crashes/*/`; Track U artifacts at `artifacts/harnesses/crashes/*`; optional dmesg dump files from `crashlog_ctl.py harvest`.
- Produces: CLI `scan [--syz-workdir PATH] [--track-u-dir PATH] [--dmesg PATH]`; registers crashes in `pipeline.json`; prints summary lines `NEW <id> <title>` / `DUP <title> -> <id>` / `FLAG <reason>`.

- [ ] **Step 1: Write `tools/crash_parse.py`** (complete file)

```python
#!/usr/bin/env python3
"""Harvest crashes from both tracks and dedup into state/pipeline.json.

Dedup (spec Phase 4): primary key = normalized report title (syzkaller
'description' file / ASan summary line). Secondary = stack hash (sha1 of
top-3 function frames). Collisions in either direction are flagged for
manual review.
"""
import argparse
import glob
import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
FRAME_RE = re.compile(r"#\d+\s+(?:0x[0-9a-f]+\s+)?(?:in\s+)?([\w.~]+)\s*\+?")
ASAN_RE = re.compile(r"^(?:==\d+==)?\s*(ERROR: (?:Address|Memory|Leak)?Sanitizer[^\n]*|SUMMARY: [^\n]*)", re.M)
NVRM_RE = re.compile(r"NVRM: (Xid[^\n]*|GPU at[^\n]*error[^\n]*)", re.I)


def norm_title(t):
    return re.sub(r"\s+", " ", t.strip())


def stack_hash(report_text):
    frames = FRAME_RE.findall(report_text)[:3]
    return hashlib.sha1("|".join(frames).encode()).hexdigest()[:16]


def existing_keys(state):
    """-> (title->cid, hash->cid)"""
    by_title, by_hash = {}, {}
    for cid, c in state["crashes"].items():
        by_title[c["title"]] = cid
        by_hash.setdefault(c["stack_hash"], cid)
    return by_title, by_hash


def register(state, track, title, shash, srcdir):
    by_title, by_hash = existing_keys(state)
    if title in by_title:
        other = state["crashes"][by_title[title]]
        if other["stack_hash"] != shash:
            print("FLAG same-title-different-stack: %s vs %s"
                  % (by_title[title], title))
        print("DUP %s -> %s" % (title, by_title[title]))
        return
    if shash in by_hash:
        print("FLAG same-stack-different-title: %s vs %s"
              % (title, state["crashes"][by_hash[shash]]["title"]))
    cid = ps.register_crash(state, {
        "track": track, "title": title, "stack_hash": shash,
        "status": "unique", "dir": srcdir, "repro_rate": None,
        "duplicate_of": None, "disclosure": "pending"})
    print("NEW %s %s" % (cid, title))


def scan_syz(state, workdir):
    for cdir in sorted(glob.glob(os.path.join(workdir, "crashes", "*"))):
        desc = os.path.join(cdir, "description")
        report = os.path.join(cdir, "report")
        if not os.path.exists(desc):
            continue
        title = norm_title(open(desc, errors="replace").read())
        rtext = open(report, errors="replace").read() \
            if os.path.exists(report) else ""
        register(state, "K", title, stack_hash(rtext), cdir)


def scan_track_u(state, udir):
    for f in sorted(glob.glob(os.path.join(udir, "*"))):
        if not os.path.isfile(f):
            continue
        text = open(f, errors="replace").read()
        m = ASAN_RE.search(text)
        title = norm_title(m.group(1)) if m else \
            "libfuzzer-crash:" + os.path.basename(f)
        register(state, "U", title, stack_hash(text), f)


def scan_dmesg(state, path):
    text = open(path, errors="replace").read()
    for m in NVRM_RE.finditer(text):
        register(state, "K", norm_title("NVRM " + m.group(1)),
                 hashlib.sha1(m.group(1).encode()).hexdigest()[:16], path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--syz-workdir",
                    default=os.path.join(REPO_ROOT, "artifacts", "syz-workdir"))
    ap.add_argument("--track-u-dir",
                    default=os.path.join(REPO_ROOT, "artifacts", "harnesses",
                                         "crashes"))
    ap.add_argument("--dmesg", default=None)
    a = ap.parse_args()
    state = ps.load()
    if os.path.isdir(os.path.join(a.syz_workdir, "crashes")):
        scan_syz(state, a.syz_workdir)
    if os.path.isdir(a.track_u_dir):
        scan_track_u(state, a.track_u_dir)
    if a.dmesg and os.path.exists(a.dmesg):
        scan_dmesg(state, a.dmesg)
    ps.save(state)
    print("registry now holds %d crashes" % len(state["crashes"]))


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify with fixtures (dev machine)**

```bash
mkdir -p /tmp/cf-fix/syz/crashes/c1 /tmp/cf-fix/u
printf 'KASAN: use-after-free in nv kms foo\n' > /tmp/cf-fix/syz/crashes/c1/description
printf '#0 0xffffffff in rm_ioctl+0x12\n#1 0xffffffff in nvidia_ioctl+0x34\n' > /tmp/cf-fix/syz/crashes/c1/report
printf '==1== ERROR: AddressSanitizer: heap-buffer-overflow in nvc_mount\n' > /tmp/cf-fix/u/crash-1
python3 tools/crash_parse.py --syz-workdir /tmp/cf-fix/syz --track-u-dir /tmp/cf-fix/u
python3 tools/crash_parse.py --syz-workdir /tmp/cf-fix/syz --track-u-dir /tmp/cf-fix/u
```

Expected: first run prints two `NEW` lines; second run prints two `DUP` lines (no new registry entries); final line reports `registry now holds 2 crashes`. Then restore clean state: `python3 -c "import sys; sys.path.insert(0,'tools'); import pipeline_state as ps; ps.save(ps.default_state())"` and `rm -rf /tmp/cf-fix`.

- [ ] **Step 3: Commit**

```bash
git add tools/crash_parse.py && git commit -m "feat: crash harvest + title/hash dedup with collision flags"
```

---

### Task 7: `tools/trace2seed.py` — strace → seed syz-programs (research contribution)

**Files:**
- Create: `tools/trace2seed.py`
- Create: `tools/ioctl_map.json` (schema placeholder, populated on SUT by the seeds agent from driver headers)

**Interfaces:**
- Consumes: strace output files produced on the SUT with `strace -v -f -P /dev/nvidiactl -P /dev/nvidia0 ... -o trace.txt <cuda workload>`; `tools/ioctl_map.json` mapping hex ioctl numbers to syzkaller ioctl description names.
- Produces: CLI `python3 tools/trace2seed.py --trace FILE --out-dir artifacts/seeds/`; writes `seed-NNNN.syz` files (syzkaller prog text).

- [ ] **Step 1: Write `tools/ioctl_map.json`**

```json
{
  "comment": "Populated on the SUT by the seeds agent: maps ioctl request numbers (hex string keys) to syzkaller description names from artifacts/descriptions/. Example entry below.",
  "0xc020462a": "ioctl$NV_ESC_RM_ALLOC"
}
```

- [ ] **Step 2: Write `tools/trace2seed.py`** (complete file)

```python
#!/usr/bin/env python3
"""Convert strace of a real CUDA workload into seed syz-programs.

Valid RM object allocation chains from real workloads are exactly what
random generation struggles to produce (spec Phase 2b). Seeds are text
prog files; syz-manager imports them via the corpus.

fd tracking: openat("/dev/nvidiaX") = N  ->  resource r<k>
             ioctl(N, 0x....)            ->  ioctl$NAME(r<k>, 0x...., ...)
"""
import argparse
import json
import os
import re
import sys

OPEN_RE = re.compile(r'openat\([^,]+,\s*"((?:/dev/nvidia|/dev/dri)[^"]*)"[^)]*\)\s*=\s*(\d+)')
IOCTL_RE = re.compile(r"ioctl\((\d+),\s*(0x[0-9a-fA-F]+|\w+)")
CLOSE_RE = re.compile(r"close\((\d+)")

DEV_TO_DESC = {
    "/dev/nvidiactl": "openat$nvidiactl",
    "/dev/nvidia-uvm": "openat$nvidia_uvm",
    "/dev/nvidia-uvm-tools": "openat$nvidia_uvm_tools",
    "/dev/nvidia-modeset": "openat$nvidia_modeset",
}


def dev_desc(path):
    if path in DEV_TO_DESC:
        return DEV_TO_DESC[path]
    if re.fullmatch(r"/dev/nvidia\d+", path):
        return "openat$nvidia"
    if path.startswith("/dev/dri/"):
        return "openat$dri"
    return None


def convert(trace_text, ioctl_map):
    lines = []
    fd_res = {}        # fd -> resource var name
    res_n = 0
    for raw in trace_text.splitlines():
        m = OPEN_RE.search(raw)
        if m:
            path, fd = m.group(1), m.group(2)
            desc = dev_desc(path)
            if desc is None:
                continue
            var = "r%d" % res_n
            res_n += 1
            fd_res[fd] = var
            lines.append('%s = %s(&AUTO=\'%s\\x00\', 0x2, 0x0)'
                         % (var, desc, path))
            continue
        m = IOCTL_RE.search(raw)
        if m and m.group(1) in fd_res:
            fd, num = m.group(1), m.group(2).lower()
            name = ioctl_map.get(num)
            if name:
                lines.append("%s(%s, %s, &AUTO)" % (name, fd_res[fd], num))
            else:
                lines.append("# unmapped ioctl %s on fd %s" % (num, fd))
            continue
        m = CLOSE_RE.search(raw)
        if m and m.group(1) in fd_res:
            lines.append("close(%s)" % fd_res.pop(m.group(1)))
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--map", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "ioctl_map.json"))
    a = ap.parse_args()
    with open(a.map) as f:
        ioctl_map = {k: v for k, v in json.load(f).items()
                     if not k.startswith("comment")}
    text = open(a.trace, errors="replace").read()
    prog = convert(text, ioctl_map)
    os.makedirs(a.out_dir, exist_ok=True)
    n = len([x for x in os.listdir(a.out_dir) if x.endswith(".syz")])
    out = os.path.join(a.out_dir, "seed-%04d.syz" % n)
    with open(out, "w") as f:
        f.write(prog)
    mapped = sum(1 for ln in prog.splitlines()
                 if ln.startswith("ioctl$"))
    unmapped = prog.count("# unmapped ioctl")
    print("wrote %s (%d mapped ioctls, %d unmapped)" % (out, mapped, unmapped))


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Verify with fixture (dev machine)**

```bash
mkdir -p /tmp/cf-seeds
cat > /tmp/cf-trace.txt <<'EOF'
1234  openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 9
1234  ioctl(9, 0xC020462A, 0x7ffd1234) = 0
1234  ioctl(9, 0xDEADBEEF, 0x7ffd1234) = 0
1234  close(9) = 0
EOF
python3 tools/trace2seed.py --trace /tmp/cf-trace.txt --out-dir /tmp/cf-seeds
cat /tmp/cf-seeds/seed-0000.syz
```

Expected output file content:
```
r0 = openat$nvidiactl(&AUTO='/dev/nvidiactl\x00', 0x2, 0x0)
ioctl$NV_ESC_RM_ALLOC(r0, 0xc020462a, &AUTO)
# unmapped ioctl 0xdeadbeef on fd 9
close(r0)
```
And stdout: `wrote /tmp/cf-seeds/seed-0000.syz (1 mapped ioctls, 1 unmapped)`. Then `rm -rf /tmp/cf-seeds /tmp/cf-trace.txt`.

- [ ] **Step 4: Commit**

```bash
git add tools/trace2seed.py tools/ioctl_map.json && git commit -m "feat: strace-to-seed syz-program converter"
```

---

### Task 8: `tools/repro_ctl.py` — reproducer extraction + repro-rate verification

**Files:**
- Create: `tools/repro_ctl.py`

**Interfaces:**
- Consumes: `tools/pipeline_state.py`; syz workdir crash dirs (`repro.syz`, `repro.cprog`); syzkaller checkout at `artifacts/src/syzkaller` (for `syz-prog2c`).
- Produces: CLI subcommands `extract <crash-id>` (copy reproducer into `artifacts/pocs/<crash-id>/`, generate C via syz-prog2c if needed) and `verify <crash-id> --runs N` (compile, run N times, measure reproduction rate from dmesg delta, classify `reliable|flaky|unreproducible` in `pipeline.json` per spec Phase 5: reliable ≥ 80%).

- [ ] **Step 1: Write `tools/repro_ctl.py`** (complete file)

```python
#!/usr/bin/env python3
"""Reproducer extraction and reproduction-rate verification.

Subcommands:
  extract <crash-id>            copy repro from syz workdir -> artifacts/pocs/<id>/,
                                generate repro.c via syz-prog2c when only
                                repro.syz exists
  verify <crash-id> [--runs N]  compile repro.c, run N times, detect the crash
                                via dmesg delta on the registry title keyword,
                                record repro_rate + classification in state

Classification (spec Phase 5): reliable >= 80%, flaky = reproduces but < 80%,
unreproducible = 0/N. Clean-boot verification is orchestrated by the poc agent
(it reboots between runs); this tool provides the per-run mechanics.
"""
import argparse
import glob
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
SYZKALLER = os.path.join(REPO_ROOT, "artifacts", "src", "syzkaller")
SYZ_WORKDIR = os.path.join(REPO_ROOT, "artifacts", "syz-workdir")


def crash_dir(cid):
    c = ps.load()["crashes"].get(cid)
    if not c:
        sys.exit("unknown crash id: " + cid)
    return c["dir"]


def cmd_extract(cid):
    src = crash_dir(cid)
    dest = os.path.join(REPO_ROOT, "artifacts", "pocs", cid)
    os.makedirs(dest, exist_ok=True)
    copied = []
    for name in ("repro.syz", "repro.cprog", "repro.c", "repro0", "report",
                 "description", "log"):
        p = os.path.join(src, name)
        if os.path.exists(p):
            shutil.copy(p, dest)
            copied.append(name)
    syz = os.path.join(dest, "repro.syz")
    c_out = os.path.join(dest, "repro.c")
    if os.path.exists(syz) and not os.path.exists(c_out):
        prog2c = os.path.join(SYZKALLER, "bin", "syz-prog2c")
        exe = os.path.join(SYZKALLER, "bin", "syz-execprog")
        with open(c_out, "w") as f:
            subprocess.run([prog2c, "-prog", syz, "-repeat", "1",
                            "-procs", "1", "-sandbox", "namespace",
                            "-exe", exe], check=True, stdout=f)
        copied.append("repro.c (generated)")
    print("extracted to %s: %s" % (dest, ", ".join(copied) or "NOTHING"))


def dmesg_text():
    r = subprocess.run(["dmesg"], capture_output=True, text=True)
    return r.stdout


def cmd_verify(cid, runs):
    dest = os.path.join(REPO_ROOT, "artifacts", "pocs", cid)
    src = os.path.join(dest, "repro.c")
    exe = os.path.join(dest, "repro")
    if not os.path.exists(exe):
        if not os.path.exists(src):
            sys.exit("no repro.c in " + dest + " (run extract first)")
        subprocess.run(["gcc", "-pthread", "-static", "-o", exe, src],
                       check=True)
    state = ps.load()
    title_kw = state["crashes"][cid]["title"].split(" in ")[0][:40]
    hits = 0
    for i in range(runs):
        before = dmesg_text()
        subprocess.run([exe], timeout=120,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        after = dmesg_text()
        delta = after[len(before):]
        if title_kw in delta or "KASAN" in delta or "BUG:" in delta:
            hits += 1
        print("run %d/%d: %s" % (i + 1, runs,
                                 "CRASH" if title_kw in delta else "clean"))
    rate = hits / runs
    status = ("reliable" if rate >= 0.8
              else "flaky" if hits > 0 else "unreproducible")
    state["crashes"][cid]["repro_rate"] = rate
    state["crashes"][cid]["status"] = status
    ps.save(state)
    print("%s: %d/%d (%.0f%%) -> %s" % (cid, hits, runs, rate * 100, status))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("extract"); p.add_argument("crash_id")
    p = sub.add_parser("verify"); p.add_argument("crash_id")
    p.add_argument("--runs", type=int, default=10)
    a = ap.parse_args()
    if a.cmd == "extract":
        cmd_extract(a.crash_id)
    else:
        cmd_verify(a.crash_id, a.runs)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify (dev machine)**

Run: `python3 tools/repro_ctl.py verify crash-9999`
Expected: exits non-zero with an error message (`no repro.c in .../artifacts/pocs/crash-9999 (run extract first)` — verify checks for the PoC dir before validating the id; `extract crash-9999` is the path that prints `unknown crash id: crash-9999`).

Run: `python3 -c "import ast; ast.parse(open('tools/repro_ctl.py').read())"`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add tools/repro_ctl.py && git commit -m "feat: reproducer extraction + repro-rate classification"
```

---

### Task 9: `AGENTS.md` — orchestrator contract

**Files:**
- Create: `AGENTS.md` (repo root)

**Interfaces:**
- Consumes: every agent prompt file in `agents/`, every tool in `tools/`, `state/pipeline.json` schema from Task 1.
- Produces: the contract any Kimi Code session in this repo follows. This is the file that makes a session "the orchestrator".

- [ ] **Step 1: Write `AGENTS.md`** (complete file)

```markdown
# CUDA-Fuzzing Orchestrator Contract

You are the orchestrator of an agentic fuzzing workflow targeting the NVIDIA
GPU kernel driver (Track K) and NVIDIA Container Toolkit (Track U).
Full design: `docs/superpowers/specs/2026-08-12-nvidia-driver-fuzzing-workflow-design.md`.

## Ground rules

- All state lives in `state/pipeline.json` and `artifacts/`. Never hold
  pipeline state in conversation.
- You coordinate; you do not do phase work yourself. Dispatch one subagent
  per phase using the prompt file in `agents/<phase>.md`.
- Subagents reason, tools act. Phase work goes through `tools/*.py` /
  `tools/*.sh`, never hand-typed command sequences.
- Phases run in dependency order (below). `describe`, `seeds`, `harness` may
  run in parallel with each other after `build`.
- After any interruption (session restart, kernel panic, reboot): read
  `state/pipeline.json`, run `python3 tools/crashlog_ctl.py harvest`, then
  resume at the first phase not marked `done`.

## Phase order and gates

Advance only when the gate holds. On gate failure, consult the phase's
agent file error-handling section; after one agent retry, mark the phase
`blocked` in pipeline.json and stop.

| Phase | Agent file | Gate to advance |
|---|---|---|
| provision | agents/provision.md | manifest.json written; `crashlog_ctl.py verify` prints READY; test panic harvested |
| build | agents/build.md | booted into instrumented kernel; KASAN state matches rung in manifest; `nvidia-smi` works |
| describe | agents/describe.md | Syzlang compiles; smoke run reaches driver (dmesg evidence); audit sample logged |
| seeds | agents/seeds.md | `artifacts/seeds/*.syz` exist; seeds parse under syz-manager |
| harness | agents/harness.md | Track U harnesses build and produce coverage on seeds |
| fuzz | agents/fuzz.md | both systemd units active; coverage increases within smoke window |
| triage | agents/triage.md | every raw crash registered unique/duplicate/flagged |
| rca | agents/rca.md | `artifacts/rca/<id>.md` complete for every unique crash selected for PoC |
| poc | agents/poc.md | every unique crash has repro rate + classification in pipeline.json |
| eval | agents/eval.md | `artifacts/eval/` contains metrics for all configured runs/ablations |
| report | agents/report.md | report + PSIRT packages exist; disclosure status recorded |

## Dispatching

For each phase, spawn a subagent whose prompt is: the full contents of
`agents/<phase>.md`, plus the current contents of `config/machine.yaml`,
`config/campaign.yaml`, and the paths of any artifacts it needs. Tell it to
write its outputs to the artifact paths the contract defines and to return
a one-paragraph summary plus gate evidence.

Background subagents are allowed for `fuzz` (long-running monitor) and for
parallel `describe`/`seeds`/`harness`. Resume timed-out subagents rather
than restarting them.

## Kernel panics

Expected. The fuzzer runs under systemd and survives you. After a reboot:
harvest crash logs, correlate with new registry entries via triage, resume.
```

- [ ] **Step 2: Verify**

Run: `ls AGENTS.md && grep -c "agents/" AGENTS.md`
Expected: file exists; at least 11 agent-file references.

- [ ] **Step 3: Commit**

```bash
git add AGENTS.md && git commit -m "docs: orchestrator contract"
```

---

### Task 10: Agent prompt files — provision, build

**Files:**
- Create: `agents/provision.md`, `agents/build.md`

**Interfaces:**
- Consumes: tools from Tasks 2-4; config files from Task 1.
- Produces: subagent prompts. Contract each must follow (stated inside each file): inputs listed at top, outputs/artifacts, gate evidence to return, error-handling limits.

- [ ] **Step 1: Write `agents/provision.md`**

```markdown
You are the provision-phase agent for the CUDA-Fuzzing pipeline. You run ON
the SUT (Debian-family, dedicated fuzzing laptop). Prepare the machine for
instrumented kernel fuzzing.

## Inputs
- config/machine.yaml (fill it in), config/campaign.yaml
- tools/exec.py, tools/crashlog_ctl.py

## Do
1. Record facts into config/machine.yaml: distro (`/etc/os-release` ID),
   GPU (`nvidia-smi --query-gpu=name --format=csv,noheader`),
   Secure Boot (`mokutil --sb-state`), GSP firmware (`nvidia-smi -q`).
2. If Secure Boot is enabled: STOP and report — the user must either disable
   it in firmware or enroll a MOK; do not improvise.
3. `sudo python3 tools/crashlog_ctl.py setup` (persistent crash capture —
   this is the pipeline's hard prerequisite), then reboot, then
   `sudo python3 tools/crashlog_ctl.py verify`. Guide the user through the
   sysrq test panic and confirm `crashlog_ctl.py harvest` produces a dump.
4. Install build deps via apt (use the Debian/Kali name mapping; never PPAs):
   build-essential bc flex bison libssl-dev libelf-dev dwarves rsync git
   python3-yaml docker.io kdump-tools pstore-tools.
5. Clone into artifacts/src/: upstream linux (stable branch matching the
   newest supported by open-gpu-kernel-modules), open-gpu-kernel-modules
   (latest production branch), syzkaller (master), nvidia-container-toolkit,
   libnvidia-container. Record all commits in artifacts/builds/manifest.json
   together with gcc version.
6. Build syzkaller (`make` in its dir) so bin/syz-manager exists.

## Gate evidence to return
manifest.json path, `crashlog_ctl.py verify` output, harvest output path.

## Errors
One retry per failed step with the error log. Second failure: write
artifacts/logs/provision-FAILED.md with the diagnosis and stop.
```

- [ ] **Step 2: Write `agents/build.md`**

```markdown
You are the build-phase agent. Build and install the instrumented kernel and
NVIDIA modules via tools/build_kernel.sh, walking the degradation ladder.

## Inputs
- config/machine.yaml (instrumentation_rung starts at 0)
- tools/build_kernel.sh, tools/exec.py
- artifacts/src/linux, artifacts/src/open-gpu-kernel-modules

## Do
For RUNG in 1, 2, 3 (stop at the first that passes the gate):
1. `sudo JOBS=$(nproc) LINUX_SRC=artifacts/src/linux \
   NVIDIA_SRC=artifacts/src/open-gpu-kernel-modules RUNG=$RUNG \
   bash tools/build_kernel.sh` (via tools/exec.py --log build-rung$RUNG).
2. If the NVIDIA module build fails because conftest.sh strips
   KBUILD_EXTRA_CFLAGS: patch kernel-open/conftest.sh minimally to append
   the flags, log the patch into artifacts/builds/, retry ONCE per rung.
3. Reboot into the new kernel.
4. Gate check: `dmesg | grep -i kasan` shows expected state for the rung;
   `lsmod | grep nvidia` non-empty; `nvidia-smi` works.
5. On gate success: set instrumentation_rung in config/machine.yaml and
   artifacts/builds/manifest.json, and stop walking the ladder.

## Gate evidence to return
chosen rung, uname -r, dmesg KASAN line, nvidia-smi output.

## Errors
Rung fails build or boot: harvest crash logs (`crashlog_ctl.py harvest`),
record findings in artifacts/builds/rung-N-failed.md, proceed to next rung.
All rungs fail: write artifacts/builds/FAILED.md, mark phase blocked.
```

- [ ] **Step 3: Verify**

Run: `ls agents/provision.md agents/build.md && grep -l "Gate evidence" agents/*.md`
Expected: both files listed, both contain the gate-evidence section.

- [ ] **Step 4: Commit**

```bash
git add agents/provision.md agents/build.md && git commit -m "docs: provision + build agent prompts"
```

---

### Task 11: Agent prompt files — describe, seeds, harness

**Files:**
- Create: `agents/describe.md`, `agents/seeds.md`, `agents/harness.md`

**Interfaces:**
- Consumes: `tools/trace2seed.py`, `tools/ioctl_map.json` (seeds); Syzkaller toolchain (describe); Docker/AFL++ (harness).
- Produces: `artifacts/descriptions/*.txt` (Syzlang), `artifacts/seeds/*.syz`, `artifacts/harnesses/` with buildable harnesses + `run_all.sh` (invoked by the Track U systemd unit from Task 5).

- [ ] **Step 1: Write `agents/describe.md`**

```markdown
You are the describe-phase agent (Track K). Author Syzlang descriptions for
the NVIDIA driver ioctl surface.

## Inputs
- artifacts/src/open-gpu-kernel-modules (headers + ioctl handlers)
- artifacts/src/syzkaller (toolchain: syz-extract, syz-compile)
- Spec §Phase 2a for the modeling approach (nv_handle / client_nv_handle
  resources, root-client allocation, RM object hierarchy, flags, constraints)

## Do
1. Check whether Interrupt Labs published their descriptions; if yes, import
   into artifacts/descriptions/ and extend instead of rewriting.
2. Coverage targets: /dev/nvidiactl, /dev/nvidiaX, /dev/nvidia-uvm[-tools],
   nvidia-drm ioctls. Model NV_ESC_RM_ALLOC root-client + object allocs with
   resources so handles chain. Skip nvidia-modeset (out of scope).
3. Create a header defining NV_* ioctl command numbers via _IOWR macros;
   extract constants with syz-extract; compile with syz-compile.
4. Validation (mandatory, LLM-output control): every description must
   compile; run a smoke campaign (5 min) and confirm via dmesg that programs
   reach the driver. Sample 5 descriptions and audit them manually against
   the driver source (direction, struct layout); record verdicts in
   artifacts/eval/description-audit.md.

## Outputs
artifacts/descriptions/*.txt, compiled corpus-ready descriptions, audit file.

## Gate evidence
syz-compile success output, smoke-run dmesg excerpt, audit file path.
```

- [ ] **Step 2: Write `agents/seeds.md`**

```markdown
You are the seeds-phase agent (Track K). Generate seed syz-programs from
runtime traces of real CUDA workloads using tools/trace2seed.py.

## Do
1. Populate tools/ioctl_map.json: map ioctl request numbers to the
   description names produced by the describe phase (parse the NV_* header
   from describe + `gcc -E` or a small C probe to compute _IOWR values).
2. Install a small CUDA workload (python3 + a minimal CUDA sample or
   pytorch if already present). Trace it:
   strace -v -f -P /dev/nvidiactl -P /dev/nvidia0 -P /dev/nvidia-uvm \
     -P /dev/nvidia-uvm-tools -o artifacts/seeds/trace.txt <workload>
3. Convert: python3 tools/trace2seed.py --trace artifacts/seeds/trace.txt \
   --out-dir artifacts/seeds/
4. Validate: every seed parses under syz-manager (add to corpus, watch for
   parse errors in the manager log during a 5-min smoke run).

## Outputs
artifacts/seeds/*.syz, populated tools/ioctl_map.json (commit it — it is
data, not runtime state), trace kept at artifacts/seeds/trace.txt.

## Gate evidence
seed count, mapped/unmapped ioctl counts, smoke-run log excerpt showing no
seed parse errors.
```

- [ ] **Step 3: Write `agents/harness.md`**

```markdown
You are the harness-phase agent (Track U: NVIDIA Container Toolkit).
Threat model: attacker controls the container image; the code under test
runs as root during container init before isolation is enforced.

## Targets (priority order)
1. libnvidia-container (C) — PRIMARY. libFuzzer harnesses with -fsanitize=
   address,undefined,fuzzer on: config file parsing, mount-spec handling,
   container setup paths. Build inside the AFL++/clang Docker image from
   config/campaign.yaml.
2. nvidia-container-toolkit (Go) — SECONDARY, panic/DoS surface only.
   `go test -fuzz` on OCI config.json handling, CDI spec parsing, env var
   processing. Go is memory-safe; do not claim memory-corruption coverage.

Out of scope (record in the report as future work): symlink TOCTOU / mount
escape logic bugs — fuzzing finds these poorly.

## Do
1. Write harnesses into artifacts/harnesses/ (one dir per target, each with
   the harness source, a seeds/ dir, and a build.sh).
2. Write artifacts/harnesses/run_all.sh that runs every harness with its
   seeds under the fuzzer for $FUZZ_HOURS (default 24) and copies crashes
   to /artifacts/harnesses/crashes/.
3. Every harness file header states the threat model above.
4. Build all harnesses in the container; run each 60s against seeds; confirm
   coverage output is produced.

## Gate evidence
build logs, per-harness 60s coverage output, run_all.sh path.
```

- [ ] **Step 4: Verify**

Run: `grep -c "Gate evidence" agents/describe.md agents/seeds.md agents/harness.md`
Expected: each file reports at least 1.

- [ ] **Step 5: Commit**

```bash
git add agents/describe.md agents/seeds.md agents/harness.md && git commit -m "docs: describe + seeds + harness agent prompts"
```

---

### Task 12: Agent prompt files — fuzz, triage

**Files:**
- Create: `agents/fuzz.md`, `agents/triage.md`

**Interfaces:**
- Consumes: `tools/campaign_ctl.py` (`install-k`, `install-u`, `start`, `stop`, `status`), `tools/crash_parse.py` (`scan`), `tools/crashlog_ctl.py` (`harvest`), `tools/pipeline_state.py`.
- Produces: running campaigns recorded in `pipeline.json` campaigns list; crash registry entries with the schema from Task 1.

- [ ] **Step 1: Write `agents/fuzz.md`**

```markdown
You are the fuzz-phase agent. Start and babysit both campaign tracks.

## Do
1. Generate artifacts/syz-manager.cfg: target linux/amd64, sandbox
   "namespace", procs and enabled_syscalls from config/campaign.yaml,
   workdir artifacts/syz-workdir, kernel_obj pointing at artifacts/src/linux,
   syzkaller dir artifacts/src/syzkaller, corpus seeded from artifacts/seeds/.
2. sudo python3 tools/campaign_ctl.py install-k && ... install-u
3. sudo python3 tools/campaign_ctl.py start k ; start u
4. Smoke window (config: smoke_window_minutes): poll
   `python3 tools/campaign_ctl.py status` and the syz-manager HTTP stats;
   coverage must increase. If Track K unit is failed, read
   `journalctl -u cuda-fuzz-k` and fix once.
5. After any reboot: `sudo python3 tools/crashlog_ctl.py harvest` BEFORE
   restarting the campaign; hand harvested paths to the triage phase.
6. Record campaign start/config in state/pipeline.json campaigns list.

Long-running monitoring is done by the orchestrator (background subagent),
not by you blocking.

## Gate evidence
`systemctl is-active cuda-fuzz-k cuda-fuzz-u` both active; coverage stats
showing increase over the smoke window.
```

- [ ] **Step 2: Write `agents/triage.md`**

```markdown
You are the triage-phase agent. Convert raw crash artifacts into a deduped
registry.

## Do
1. python3 tools/crash_parse.py                 # syz workdir + Track U dir
2. For each harvested pstore/kdump dir from the fuzz phase:
   python3 tools/crash_parse.py --dmesg <path>/dmesg-ramoops-*
3. Review every FLAG line from crash_parse output (title/stack collisions in
   either direction): read both reports, decide duplicate vs distinct,
   correct the registry in state/pipeline.json (set duplicate_of, or keep
   both unique with a note).
4. Prioritize unique crashes for RCA: KASAN UAF/OOB-write and Track U ASan
   heap-corruption first; then other KASAN; then NVRM Xid signals; panics
   without sanitizer reports last.
5. Correlate reboots with crashes: a reboot + fresh pstore dump with no
   syz-manager report is still a finding — register it via crash_parse
   --dmesg and mark notes in the registry.

## Gate evidence
registry counts (unique/dup/flagged), prioritized queue written to
artifacts/crashes/QUEUE.md.
```

- [ ] **Step 3: Verify + commit**

Run: `grep -l "crash_parse.py" agents/triage.md && grep -l "campaign_ctl.py" agents/fuzz.md`
Expected: both paths printed.

```bash
git add agents/fuzz.md agents/triage.md && git commit -m "docs: fuzz + triage agent prompts"
```

---

### Task 13: Agent prompt files — rca, poc, eval, report

**Files:**
- Create: `agents/rca.md`, `agents/poc.md`, `agents/eval.md`, `agents/report.md`

**Interfaces:**
- Consumes: `tools/repro_ctl.py` (`extract`, `verify`), crash registry, artifacts from all earlier phases.
- Produces: `artifacts/rca/<id>.md`, `artifacts/pocs/<id>/`, `artifacts/eval/`, `artifacts/report/<date>-report.md` + `artifacts/report/disclosure/<id>/`.

- [ ] **Step 1: Write `agents/rca.md`**

```markdown
You are the rca-phase agent. One root-cause analysis per unique crash, in
registry priority order (artifacts/crashes/QUEUE.md).

## Per crash <id>
1. Read the sanitizer report / pstore dump in artifacts/crashes/<id-raw>/ and
   the registry entry in state/pipeline.json.
2. Read the implicated source (open-gpu-kernel-modules for Track K;
   libnvidia-container / nvidia-container-toolkit for Track U).
3. Write artifacts/rca/<id>.md with: faulting function, root-cause
   hypothesis, affected versions (from manifest.json), exploitability
   (Track K: privilege escalation / container-escape; Track U: escape under
   the malicious-image threat model), and whether GSP firmware involvement
   limits visibility (say so explicitly when it does).
4. Flag every claim about code behavior that you could not verify against
   source with [UNVERIFIED] — the eval phase samples these for manual audit.

Do not invent certainty. A wrong RCA is worse than an honest "unknown".

## Gate evidence
paths of completed RCA files.
```

- [ ] **Step 2: Write `agents/poc.md`**

```markdown
You are the poc-phase agent. Turn unique crashes into verified, replayable
PoCs. PoCs stop at "reliably triggers the vulnerability" — no weaponization.

## Per unique crash <id> (priority order)
1. python3 tools/repro_ctl.py extract <id>
2. Track K: verify reproduction rate. Coordinate with the orchestrator for
   clean-boot runs (reboot between batches when the crash corrupts state):
   python3 tools/repro_ctl.py verify <id> --runs 10
   The tool classifies reliable (>=80%) / flaky (>0) / unreproducible in
   state/pipeline.json. Flaky is a valid, reportable outcome (races/UAF).
3. Track U: replay the minimal input against the harness binary in the
   container; same classification.
4. Write artifacts/pocs/<id>/README.md: build steps, run steps, expected
   sanitizer signature, reproduction rate, preconditions (Track U:
   attacker-controlled image; state the exact privileges required).
5. If syz-manager never produced a reproducer (no repro.syz in the workdir),
   say so in the README and mark the crash unreproducible — do not
   hand-craft one from scratch.

## Gate evidence
per-crash classification summary from the registry; PoC README paths.
```

- [ ] **Step 3: Write `agents/eval.md`**

```markdown
You are the eval-phase agent. Produce publication-grade measurements.

## Do
1. From syz-manager stats across campaigns: edge-coverage-over-time series
   (state clearly: coverage is kernel-side only; GSP firmware is not
   instrumented). Save CSV + plot to artifacts/eval/.
2. Metrics table: unique crashes, time-to-first-crash, repro rates,
   per-run variance. Protocol: >= config eval.runs_per_config independent
   runs of eval.run_hours each per configuration; report variance. Single
   runs are not publishable.
3. Ablations (each is a fresh campaign via the fuzz phase):
   a. with vs without artifacts/seeds/ (trace-derived seeds)
   b. agent-authored descriptions vs manually-refined descriptions
   c. baseline: vanilla syzkaller without NVIDIA descriptions
4. Version persistence: replay every reliable PoC against one newer NVIDIA
   production driver branch; record persist/fixed per PoC.
5. Audit sample: re-verify a sample of [UNVERIFIED] RCA claims against
   source; log outcomes (confirmed/refuted) to artifacts/eval/rca-audit.md.
   Agent failure modes observed here are paper data — keep them.

## Outputs
artifacts/eval/: coverage CSVs, plots, metrics table, ablation results,
rca-audit.md.

## Gate evidence
file listing of artifacts/eval/ with one-line description of each artifact.
```

- [ ] **Step 4: Write `agents/report.md`**

```markdown
You are the report-phase agent. Produce the pentest-style report and PSIRT
disclosure packages.

## Report
Write artifacts/report/<YYYY-MM-DD>-report.md. Penetration-test style,
detailed vulnerability sections ONLY — no executive summary. Per finding:
- title + track (K kernel driver / U container toolkit)
- description and technical detail (from the RCA file)
- affected code and versions (kernel, driver commit, GSP firmware — from
  manifest.json)
- severity with justification, reproduction rate, reliable/flaky label
- PoC: path, build/run steps, expected sanitizer signature (from the PoC
  README)
- remediation notes
Flaky findings go in a clearly labeled subsection. Unreproducible crashes
are listed in an appendix, one paragraph each, labeled as unverified.

## Disclosure
Per confirmed (reliable or flaky) finding, assemble
artifacts/report/disclosure/<id>/ containing the PoC, RCA, affected
versions, and a short impact statement — PSIRT-ready. Record disclosure
status per crash in state/pipeline.json (pending/submitted/resolved).
Nothing leaves this machine before the user explicitly approves submission.

## Gate evidence
report path, disclosure package paths, registry disclosure statuses.
```

- [ ] **Step 5: Verify + commit**

Run: `ls agents/`
Expected: 11 files — provision, build, describe, seeds, harness, fuzz, triage, rca, poc, eval, report.

```bash
git add agents/rca.md agents/poc.md agents/eval.md agents/report.md && git commit -m "docs: rca + poc + eval + report agent prompts"
```

---

## Self-Review Log (completed by plan author)

- **Spec coverage:** all 11 phases + resilience model + eval + disclosure mapped to tasks 1-13. Secure Boot handled in provision.md + build_kernel.sh. GSP blind spot acknowledged in rca.md/eval.md. Threat models in harness.md/report.md.
- **Interface consistency:** `pipeline_state` API (load/save/update_phase/register_crash/next_crash_id/PHASES/REPO_ROOT/STATE_PATH) used identically in crash_parse, repro_ctl, campaign_ctl. crash_parse prints NEW/DUP/FLAG — triage.md consumes exactly those. campaign_ctl unit names match fuzz.md. repro_ctl classification thresholds match poc.md and spec Phase 5.
- **Known deliberate deviations:** tools/templates dir not needed (run_all.sh written by harness agent); `ioctl_map.json` committed as data (stated in seeds.md, overrides the "runtime data not committed" constraint by explicit exception).

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-08-12-nvidia-fuzzing-workflow.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
