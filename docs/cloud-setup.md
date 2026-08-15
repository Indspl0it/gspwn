# EC2 cloud setup

The project has pivoted to cloud-only. The bare-metal laptop is retired as
the fuzzing target. The system under test is now an AWS EC2 instance, which
also fits the threat model better: multi-tenant GPU cloud is the deployment
we care about, so fuzzing on EC2 is representative rather than a compromise.

## Instance recipe

Which GPU a family carries, and which families the open kernel modules
support at all, is in the README under "Supported GPUs and instances". Pick
from there before launching: the choice is made in the console and nothing in
this repo can validate it afterwards.

- g4dn.2xlarge: 8 vCPU, 32 GB RAM, one NVIDIA T4 (Turing). Turing is
  GSP-based, so open-gpu-kernel-modules is supported. This is the cheapest
  supported entry, not the only one.
- **On-demand, not spot, for any campaign whose artifacts matter.** A one-time
  spot request is terminated on interruption rather than stopped: the root
  volume goes with it, mid-campaign, and there is no next boot of that
  instance whatever delete-on-termination says. Spot is fine for a throwaway
  smoke run.
- Official Debian 12 AMI.
- Termination protection enabled (`disable-api-termination`).
- 200 GB gp3 root volume with delete-on-termination set to false.
- A **separate EBS volume mounted at `artifacts/`**. This is the single
  cheapest piece of insurance here. A GPU that will not come back costs you
  the instance; without a separate volume it also costs you the campaign,
  because a detachable volume can be reattached to a fresh box and a root
  volume in a dead instance is a recovery exercise.
- Security group: SSH inbound only, from the operator's IP. Nothing else.
- IAM instance profile allowing `ec2:GetConsoleOutput` on the instance
  itself. Attach it at launch. That is how hard hangs get captured: EC2 has
  no pstore, so a hang that never reaches kdump is only recoverable from the
  console log. It is the only AWS permission the pipeline uses, and nothing
  in the repo calls any other EC2 API.

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

## When the GPU stops answering

A GPU that falls off the bus (Xid 79) does not stop the fuzzer. syz-manager
keeps executing against nothing and the coverage curve flattens, which reads
exactly like a finished round. `coverage_ctl.py plateau` refuses to call that
a plateau, but recovering the card is a manual ladder:

| Step | Action | Autonomous? |
| --- | --- | --- |
| 1 | `nvidia-smi -r` (needs no process holding the GPU) | Yes |
| 2 | `rmmod nvidia_uvm nvidia_drm nvidia_modeset nvidia`, then `modprobe nvidia` | Yes |
| 3 | Guest `reboot` | Yes |
| 4 | **stop, then start, from the AWS console** | No |

Step 4 is the one that needs a human, and it is the one that usually works: a
guest reboot does not power-cycle a passthrough GPU, while a stop/start moves
the instance to different physical hardware. This is the reason `stop` and
`terminate` must not be confused. Stopping preserves the EBS volumes, which is
what makes stop/start a safe recovery rather than the end of the campaign.

Check the card at any time with `python3 tools/coverage_ctl.py gpu-health`.

## Learning-phase advice

Expect to iterate on the workflow for the first few sessions. Stop the
instance from the console whenever you leave it without a campaign running:
nothing in the repo will do it for you, and an idle GPU instance bills at the
same rate as a busy one.
