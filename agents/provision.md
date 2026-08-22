You are the provision-phase agent for the gspwn pipeline, running ON the SUT
(Debian-family, dedicated fuzzing laptop). Prepare the machine for
instrumented kernel fuzzing.

## Inputs
- config/machine.yaml (fill it in), config/campaign.yaml
- tools/exec.py, tools/crashlog_ctl.py

## Do
0. Determine environment. Query
   http://169.254.169.254/latest/meta-data/instance-id with a 2s timeout, and
   a response means the machine is on EC2. `python3 tools/crashlog_ctl.py
   --env auto ...` auto-detects the same way. On EC2:
   - Skip the Secure Boot step below (Nitro has no Secure Boot by default).
   - Install the baseline NVIDIA driver from Debian non-free repos FIRST,
     before step 5's cloning. Step 1 needs it for the nvidia-smi
     GPU/model/GSP facts.
0a. Grant the agent passwordless sudo for the pipeline tools. This is a hard
   prerequisite. Crash harvesting after a panic runs `sudo -n`, and campaign
   installs and the coverage sampler all need root from a headless session
   that cannot answer a password prompt. Without it the harvest captures
   nothing and every campaign install fails.

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
     default, and the repo does not guess)
   - `sudo python3 tools/orchestrator_ctl.py install`
   - `sudo systemctl start gspwn-orchestrator`
   Without it every kernel panic ends the campaign until someone SSHes in.
   Check it later with `python3 tools/orchestrator_ctl.py status`.
1. Record facts into config/machine.yaml: distro (`/etc/os-release` ID),
   GPU (`nvidia-smi --query-gpu=name --format=csv,noheader`),
   Secure Boot (`mokutil --sb-state`), GSP firmware (`nvidia-smi -q`).
   Record environment (ec2|baremetal) from step 0's detection. On EC2, skip
   the Secure Boot fact.
2. If Secure Boot is enabled, STOP and report. The user must either disable
   it in firmware or enroll a MOK. Do not improvise. This step applies to bare
   metal only.
3. `sudo python3 tools/crashlog_ctl.py setup` (persistent crash capture, a
   hard prerequisite of the pipeline), then reboot, then
   `sudo python3 tools/crashlog_ctl.py verify`. Guide the user through the
   sysrq test panic and confirm `crashlog_ctl.py harvest` produces a dump.
   On EC2 the tool auto-detects the environment: setup skips pstore, and
   harvest also saves the EC2 console output. That needs an IAM instance
   profile granting `ec2:GetConsoleOutput` and nothing else, plus awscli
   installed (step 4).
   `harvest` must run as root, because it reads /sys/fs/pstore and
   /var/crash, which are root-only. Without root it refuses, and it does not
   report zero crashes when it could not look.
4. Install build deps via apt, using the Debian/Kali name mapping and never
   a PPA:
   build-essential bc flex bison libssl-dev libelf-dev dwarves rsync git
   python3-yaml docker.io kdump-tools pstore-tools mokutil.
   On EC2 also install awscli. `crashlog_ctl.py verify` fails without it,
   because hard-hang capture there is the EC2 console output.
   On bare metal mokutil reports Secure Boot state, and without it the build
   phase cannot tell whether its modules will be allowed to load.
5. Clone into artifacts/src/: upstream linux (stable branch matching the
   newest supported by open-gpu-kernel-modules), open-gpu-kernel-modules,
   syzkaller (master), nvidia-container-toolkit, libnvidia-container. Record
   all commits in artifacts/builds/manifest.json together with gcc version.

   Check out open-gpu-kernel-modules at the release tag matching the driver
   that will actually run, and record that version in config/machine.yaml as
   `driver_branch`. The describe and seeds phases derive the whole ioctl
   surface from this checkout: escape numbers, parameter struct sizes, control
   command numbers and class privilege flags all move between releases, and a
   checkout that does not match the running driver produces descriptions that
   compile, run, and model a different driver. The build phase compiles the
   modules from this tree, so matching here makes the two agree. The tags are
   release versions:

   ```
   git -C artifacts/src/open-gpu-kernel-modules tag --sort=-creatordate | head
   ```

   Confirm the choice held:

   ```
   python3 tools/surface_verify.py show
   ```

   `show` reaches no verdict and always exits 0. The describe and seeds phases
   gate on `surface_verify.py check`, which needs two version sources and exits
   4 with fewer. Confirm here that `show` lists both the checkout version and
   `config/machine.yaml` `driver_branch`, so those phases have something to
   compare, then reach a verdict at provision time:

   ```
   python3 tools/surface_verify.py check --no-running
   ```

   `--no-running` skips the loaded-driver comparison, which is correct here
   because the driver is not loaded at provision time. Exit 3 means the
   checkout and the recorded branch disagree, and exit 4 means fewer than two
   sources answered. Both are a blocked gate. A wrong tag is otherwise caught
   two phases later, after the clone and the kernel build.

   Also write the GSP firmware version (from `nvidia-smi -q`) into the
   manifest, and report.md consumes it from there.
6. Build syzkaller (`make` in its dir) so bin/syz-manager exists.

## State
Run `python3 tools/pipeline_ctl.py init` first. It creates
state/pipeline.json, which every later phase reads. Then record progress with
`python3 tools/pipeline_ctl.py set-phase provision in_progress|done|blocked
 --notes "<one line>"`. Never edit pipeline.json by hand.

## Gate evidence
Manifest.json path, `crashlog_ctl.py verify` output, harvest output path, and
a clean `orchestrator_ctl.py preflight` (config valid, agent command set,
passwordless sudo working, disk headroom). A failing preflight is a blocked
gate. The unattended loop needs every one of those and cannot report on them
for itself once it is running.

Also the verdict and exit status of `surface_verify.py check --no-running`
from step 5, with the versions it printed. Exit 3 and exit 4 are both a
blocked gate here, and without the verdict in the evidence nothing records
that the comparison was made. A wrong tag is otherwise caught two phases
later, after the clone and the kernel build.

## Errors
One retry per failed step with the error log. On a second failure, write
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

A **learning** is about the target. For this phase, typically instance and
driver facts: what a family actually provides, what a capability flag does
or does not grant. A **mistake** is about us: something that cost time,
produced a wrong number, or would repeat. Both are read by whoever runs this
phase next, on another box months from now, so write for someone without
your context. Recording nothing across a whole phase is itself worth
questioning.

`knowledge/` is committed to a **public repository**. It carries ABI and
process facts and never findings: `note` refuses text naming a crash id or a
path under `artifacts/crashes|pocs|rca`, and the specifics belong in the
crash registry. Record the general form. It is also the more useful one,
because the next agent is looking at a different crash.
