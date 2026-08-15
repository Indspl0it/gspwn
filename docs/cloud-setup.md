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
  itself. That is how hard hangs get captured, and it is the only AWS
  permission the pipeline uses. Nothing in the repo calls any other EC2 API.

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

## Leaving the instance running

Nothing in the repo stops the instance. When the loop ends, the fuzz units
stop and the box keeps running until you stop it from the console. Stop it
whenever you leave it idle without a campaign: `stop` preserves the EBS
volume and everything in `artifacts/`, unlike `terminate`.

GPU instances are billed by the hour and the rate spans roughly two orders of
magnitude across the supported families. Check current pricing for your
instance and region in the AWS console, and set an AWS Budgets alert on day
one. The pipeline's own limits are counted in run-hours, not dollars: see
"Configuration and stopping rules" in the README.

Spot interruptions are the one failure that loses work. A one-time spot
request is **terminated** on interruption, not stopped, so there is no next
boot of that instance whatever delete-on-termination says about the volume.
Recovery is: relaunch from the golden AMI, re-attach the surviving root
volume if its artifacts matter, run `crashlog_ctl.py harvest`, then resume
the pipeline from `state/pipeline.json`. Automatic resume after interruption
exists only with a *persistent* spot request configured for stop/hibernate
interruption behavior, which this runbook does not use. For a campaign whose
artifacts matter, use on-demand.

## Sizing the run-hour cap

`campaign_ctl.py install-k`/`install-u` refuse any campaign whose projected
hours would push the spend ledger past `loop.max_total_run_hours` (default
216). The ledger is per instance, so each box enforces its own cap. If a
planned set of campaigns needs more, raise the value in
`config/campaign.yaml` *before* starting: the orchestrator contract forbids
raising a limit mid-loop, so this is a deliberate pre-launch decision rather
than a patch applied when a campaign is refused.

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
