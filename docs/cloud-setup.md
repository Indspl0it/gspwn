# EC2 cloud setup

The project has pivoted to cloud-only. The bare-metal laptop is retired as
the fuzzing target. The system under test is now an AWS EC2 instance, which
also fits the threat model better: multi-tenant GPU cloud is the deployment
we care about, so fuzzing on EC2 is representative rather than a compromise.

## Instance recipe

- g4dn.2xlarge, spot: 8 vCPU, 32 GB RAM, one NVIDIA T4 (Turing). Turing is
  GSP-based, so open-gpu-kernel-modules is supported.
- Official Debian 12 AMI.
- 200 GB gp3 root volume with delete-on-termination set to false. Artifacts
  survive stop and accidental termination.
- Security group: SSH inbound only, from the operator's IP. Nothing else.
- IAM instance profile allowing `ec2:GetConsoleOutput` on the instance
  itself. That is how hard hangs get captured. The idle watchdog needs no
  IAM permission — it stops the machine with a local `shutdown -h`, and
  nothing in the repo calls the EC2 stop API.

## Golden image flow

Build once, then never again:

1. Launch from the Debian 12 AMI and run the pipeline's provision and build
   phases. Provision installs the baseline NVIDIA driver from Debian
   non-free (provides `nvidia-smi`, GSP firmware, and the CUDA userspace)
   plus the crash capture tooling; build swaps in the instrumented kernel
   and modules on top of that baseline.
2. Create an AMI from the instance once `build` is done — booted into the
   instrumented kernel with `nvidia-smi` working. The kernel build is the
   multi-hour part, so the image is taken after it, not after provision.
3. Launch every campaign and eval instance from that AMI.

Every later instance boots straight into the instrumented kernel, so the
per-instance setup cost after the first build is a `git clone` of this repo
and the config caps — re-running provision and build is not needed. If the
golden image rots (driver branch moves, Debian point release), rebuild it
the same way.

## Cost guardrails

Budget ceiling is $200/month, and the first weeks are learning time, so
guardrails come before campaigns:

- AWS Budgets alerts at $50 and $150. Set both up on day one.
- Idle watchdog: `sudo python3 tools/cost_ctl.py install-watchdog` installs
  a systemd timer that runs every 30 minutes and stops the instance when
  both fuzz units are inactive and no syz-manager process has run for
  `IDLE_MINUTES` (default 120, override via the environment). Stopping uses
  `shutdown -h`, which for an EBS-backed instance stops rather than
  terminates, so the volume and artifacts survive.
- `python3 tools/cost_ctl.py keepalive --hours 8` suppresses the watchdog
  during long interactive agent sessions (default 4 hours; `--clear` ends
  the hold immediately). The hold is an expiry timestamp in
  `state/KEEP_ALIVE`, so it lapses on its own — a forgotten keepalive
  cannot permanently disable the only automated stop.
- Stop the instance manually whenever leaving it idle without a campaign
  running. The watchdog is a backstop, not the primary control.
- Spot interruptions: a one-time spot request is **terminated** on
  interruption — there is no next boot of that instance, whatever
  delete-on-termination says about the volume. Recovery is: relaunch from
  the golden AMI, re-attach the surviving root volume if its artifacts
  matter, run `crashlog_ctl.py harvest`, then resume the pipeline from
  `state/pipeline.json`. Automatic resume after interruption exists only
  with a *persistent* spot request configured for stop/hibernate
  interruption behavior, which this runbook does not use.

## Costs

| Item | Cost |
|---|---|
| g4dn.2xlarge spot | ~$0.25/hr |
| 24h campaign | ~$6 |
| On-demand fallback | $0.75/hr (~$18/day) |
| 200 GB gp3 storage | ~$16/mo |
| AMI snapshot | ~$0.05/GB/mo |

A realistic monthly pattern: the learning week runs mostly stopped and
costs $20-30; campaign weeks stay within $150 even with daily 24h runs.

## Parallel eval

The eval phase needs at least 3 independent runs plus ablations. Launch 2-3
instances from the golden AMI and run them concurrently; each independent
campaign counts as a valid independent run for variance reporting. Two
instances running 12 campaigns of 24h each cost roughly $144 at spot
prices, which fits the budget if the rest of the month is quiet.

Mind the run-hour cap when sizing that matrix: 12 campaigns of 24h is 288
run-hours, and `campaign_ctl.py install-k`/`install-u` hard-refuse any
campaign whose projected hours would push the spend ledger past
`loop.max_total_run_hours` (default 216) — campaign #10 onward would be
refused. The ledger is per instance, so each eval box enforces its own cap.
Raise `max_total_run_hours` in `config/campaign.yaml` to cover the eval
matrix *before* the eval campaigns start: the orchestrator contract forbids
raising caps mid-loop, so sizing the cap for the eval is a deliberate
pre-launch decision, not a patch applied when a campaign is refused.

## Crash capture on EC2

There is no pstore on EC2. Crash capture is kdump plus the EC2 console
output: `crashlog_ctl.py harvest` auto-detects EC2 via the instance
metadata service (`--env auto` is the explicit default; `--env
ec2|baremetal` forces the mode), saves `aws ec2 get-console-output` to
`artifacts/crashes/pstore-<timestamp>/console-output.log` — harvest
directories are named `pstore-*` on both platforms — and still collects
`/var/crash` kdump dumps. A clean reboot with nothing new to collect exits
0, so harvesting after every boot is safe to script. Console output is also
the only record of a hard hang where kdump itself cannot run, which is why
the IAM profile is not optional.

## Learning-phase advice

For the first sessions, set `IDLE_MINUTES=60` so a forgotten instance
costs at most an hour. Expect to iterate on the workflow; that is what the
learning budget is for. The one hard rule: never leave an instance running
overnight without a campaign on it.
