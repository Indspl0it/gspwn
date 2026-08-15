You are the provision-phase agent for the gspwn pipeline. You run ON
the SUT (Debian-family, dedicated fuzzing laptop). Prepare the machine for
instrumented kernel fuzzing.

## Inputs
- config/machine.yaml (fill it in), config/campaign.yaml
- tools/exec.py, tools/crashlog_ctl.py

## Do
0. Determine environment: query
   http://169.254.169.254/latest/meta-data/instance-id with a 2s timeout;
   if it responds you are on EC2. (Equivalent:
   `python3 tools/crashlog_ctl.py --env auto ...` auto-detects the same
   way.) On EC2:
   - Skip the Secure Boot step below (Nitro has no Secure Boot by default).
   - Install the baseline NVIDIA driver from Debian non-free repos FIRST
     (before step 5's cloning) — needed for the nvidia-smi GPU/model/GSP
     facts in step 1.
0a. Grant the agent passwordless sudo for the pipeline tools. This is a hard
   prerequisite, not a convenience: crash harvesting after a panic runs
   `sudo -n`, and campaign installs and the coverage sampler all need root
   from a headless session that cannot answer a password prompt. Without it
   the harvest captures nothing and every campaign install fails.

   Write /etc/sudoers.d/gspwn (via `visudo -f`, which validates it):
   ```
   <agent-user> ALL=(root) NOPASSWD: /usr/bin/python3 /path/to/repo/tools/*.py
   ```
   SECURITY: those scripts must not be writable by that user, or the rule is
   equivalent to unrestricted root. Keep the repo root-owned on the SUT and
   give the agent user read and execute only.

   Confirm the whole prerequisite set before going further:
   `python3 tools/orchestrator_ctl.py preflight`
0b. Install the orchestrator supervisor so the pipeline survives a panic
   without a human logging in:
   - set `orchestrator.command` in config/campaign.yaml to the headless
     invocation of the coding agent installed on this box (there is no
     default; the repo does not guess which one it is)
   - `sudo python3 tools/orchestrator_ctl.py install`
   - `sudo systemctl start gspwn-orchestrator`
   Without it every kernel panic ends the campaign until someone SSHes in.
   Check it later with `python3 tools/orchestrator_ctl.py status`.
1. Record facts into config/machine.yaml: distro (`/etc/os-release` ID),
   GPU (`nvidia-smi --query-gpu=name --format=csv,noheader`),
   Secure Boot (`mokutil --sb-state`), GSP firmware (`nvidia-smi -q`).
   Record environment (ec2|baremetal) from step 0's detection. On EC2, skip
   the Secure Boot fact.
2. If Secure Boot is enabled: STOP and report — the user must either disable
   it in firmware or enroll a MOK; do not improvise. (Bare metal only.)
3. `sudo python3 tools/crashlog_ctl.py setup` (persistent crash capture —
   this is the pipeline's hard prerequisite), then reboot, then
   `sudo python3 tools/crashlog_ctl.py verify`. Guide the user through the
   sysrq test panic and confirm `crashlog_ctl.py harvest` produces a dump.
   On EC2 the tool auto-detects the environment: setup skips pstore, and
   harvest also saves the EC2 console output. That needs an IAM instance
   profile granting `ec2:GetConsoleOutput` and nothing else, plus awscli
   installed (step 4).
   `harvest` must run as root — it reads /sys/fs/pstore and /var/crash, which
   are root-only, and it now refuses rather than reporting that it found no
   crashes when what happened is that it could not look.
4. Install build deps via apt (use the Debian/Kali name mapping; never PPAs):
   build-essential bc flex bison libssl-dev libelf-dev dwarves rsync git
   python3-yaml docker.io kdump-tools pstore-tools mokutil.
   On EC2 also install awscli — `crashlog_ctl.py verify` fails without it,
   because hard-hang capture there is the EC2 console output.
   On bare metal mokutil is what reports Secure Boot state; without it the
   build phase cannot tell whether its modules will be allowed to load.
5. Clone into artifacts/src/: upstream linux (stable branch matching the
   newest supported by open-gpu-kernel-modules), open-gpu-kernel-modules
   (latest production branch), syzkaller (master), nvidia-container-toolkit,
   libnvidia-container. Record all commits in artifacts/builds/manifest.json
   together with gcc version. Also write the GSP firmware version (from
   `nvidia-smi -q`) into the manifest; report.md consumes it from there.
6. Build syzkaller (`make` in its dir) so bin/syz-manager exists.

## State
Run `python3 tools/pipeline_ctl.py init` first — it creates
state/pipeline.json, which every later phase reads. Then record progress with
`python3 tools/pipeline_ctl.py set-phase provision in_progress|done|blocked
 --notes "<one line>"`. Never edit pipeline.json by hand.

## Gate evidence to return
manifest.json path, `crashlog_ctl.py verify` output, harvest output path, and
a clean `orchestrator_ctl.py preflight` (config valid, agent command set,
passwordless sudo working, disk headroom). A failing preflight is a blocked
gate: every one of those is something the unattended loop needs and cannot
report on for itself once it is running.

## Errors
One retry per failed step with the error log. Second failure: write
artifacts/logs/provision-FAILED.md with the diagnosis and stop.

## Knowledge (cross-campaign)

Read what earlier campaigns established before you start:

```
python3 tools/knowledge_ctl.py show --phase provision
```

Record what you learn **as you learn it**, not at the end from memory:

```
python3 tools/knowledge_ctl.py note --kind learning --phase provision "..."
python3 tools/knowledge_ctl.py note --kind mistake  --phase provision "..."
```

A **learning** is about the target — for this phase, typically instance and
driver facts: what a family actually provides, what a capability flag does or
does not grant.
A **mistake** is about us: something that cost time, produced a wrong number,
or would repeat. Both are read by whoever runs this phase next, on another box
months from now, so write for someone without your context. Recording nothing
across a whole phase is itself worth questioning.

`knowledge/` is committed to a **public repository**. It carries ABI and
process facts and never findings: `note` refuses text naming a crash id or a
path under `artifacts/crashes|pocs|rca`, and the specifics belong in the crash
registry instead. Record the general form — it is also the more useful one,
because the next agent is looking at a different crash.
