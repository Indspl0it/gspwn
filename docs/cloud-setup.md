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
- Security group: SSH inbound only, from your IP. Nothing else.
- IAM instance profile allowing `ec2:GetConsoleOutput` and
  `ec2:StopInstances` on the instance itself. The first is how hard hangs
  get captured; the second lets the idle watchdog stop the machine.

## Golden image flow

Provision once, then never again:

1. Launch from the Debian 12 AMI and run the pipeline's provision phase.
   This installs the baseline NVIDIA driver from Debian non-free (gives you
   `nvidia-smi`, GSP firmware, and the CUDA userspace) plus the crash
   capture tooling. The pipeline's build phase swaps in the instrumented
   kernel and modules on top of this baseline.
2. Create an AMI from the provisioned instance.
3. Launch every campaign and eval instance from that AMI.

Re-provisioning cost after the first build is zero. If the golden image
rots (driver branch moves, Debian point release), rebuild it the same way.

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
- `touch state/KEEP_ALIVE` suppresses the watchdog during long interactive
  agent sessions. Delete the file when you are done.
- Stop the instance manually whenever you step away without a campaign
  running. The watchdog is a backstop, not the primary control.
- Spot interruptions: with delete-on-termination=false the root volume
  survives, and the campaign resumes via systemd on the next boot.

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

## Crash capture on EC2

There is no pstore on EC2. Crash capture is kdump plus the EC2 console
output: `crashlog_ctl.py harvest` auto-detects EC2 via the instance
metadata service (override with `--env ec2|baremetal`), saves
`aws ec2 get-console-output` to `artifacts/crashes/console-<timestamp>.log`,
and still collects `/var/crash` kdump dumps. Console output is also the
only record of a hard hang where kdump itself cannot run, which is why the
IAM profile is not optional.

## Learning-phase advice

For the first sessions, set `IDLE_MINUTES=60` so a forgotten instance
costs at most an hour. Expect to iterate on the workflow; that is what the
learning budget is for. The one hard rule: never leave an instance running
overnight without a campaign on it.
