---
title: Troubleshooting
description: Symptom to cause to fix, for the failure modes the tools guard against.
---

## Coverage and measurement

A flat curve, an unreachable source and a missing edge count all leave the
round without a coverage claim.

| Symptom | Cause | Action |
|---|---|---|
| Coverage flat across the whole smoke window | The GPU has fallen off the bus, so the fuzzer runs against nothing | `python3 tools/coverage_ctl.py gpu-health`. Recover with `nvidia-smi -r`, a module reload, a guest reboot, then an instance stop and start |
| Coverage flat across the whole smoke window, GPU healthy | Descriptions bounce off the driver's argument validation | Check the smoke run's dmesg for uniform early-out per device node. Missing resource chaining is the usual cause |
| `sample` reports `source: unreachable` on Track K | syz-manager's stats endpoint is not answering at `track_k.http` | Confirm the unit is running with `systemctl is-active gspwn-k`, and confirm the address and the endpoint shape for the pinned syzkaller commit |
| `sample` reports `source: unreachable` on Track U | No harness output under `artifacts/runs/<id>/u/` | Confirm `run_all.sh` writes each harness's output there, and that `$RUN_ID` reached the container |
| `sample` reports `source: corpus-count-only` on Track U | The harnesses are libFuzzer, which writes no `fuzzer_stats` | Track U contributes a corpus count and no edge curve for those harnesses. Add an AFL++ harness for an edge signal |
| `sample` fails with a permission error | The CSV is owned by the root sampler | Re-run with `sudo`, or read the curve with `series` |
| `series` prints `edges: never recorded` | No sample carried an edge count | The run cannot support a coverage claim. Exclude it from the round's numbers and say so |

## Plateau verdicts

`plateau` exits 0 for `growing`, 3 for `plateaued` and 1 for `unknown`.

| Message | Cause | Action |
|---|---|---|
| `only N usable sample(s); need >= 3` | The run is too short, or the sampler started late | Install the sampler before the smoke window |
| `no edge data in any sample` | The source never reported an edge count | Fix the stats endpoint, then re-measure |
| `only N sample(s) usable for a discovery fit; need >= M` | Fewer points in the fitted tail than `coverage.min_fit_samples` | Lower `loop.coverage_sample_min`, or raise `coverage.fit_tail_fraction` |
| `the discovery curve does not fit the model well enough` | A stuck sampler, a source change mid-run, or a genuine regime change | Plot the series. The three look identical in the verdict and need different responses |
| `discovery exponent beta=... is outside (0, 1]` | The series is not behaving like an accumulation curve | Plot the series before concluding anything |
| `the fuzzer is still replaying its corpus after a restart` | The round ended before the fuzzer got back to its own high-water mark | Report the round as unmeasured. Nothing about saturation can be read from it |
| `the GPU was not healthy for N of M sample(s) in the window` | A dead GPU flattened the curve the same way a real plateau would | Recover the GPU and re-measure. Never record a plateau for a round whose GPU died |

An `unknown` verdict stops the loop by design, so a broken sampler cannot
authorise another campaign.

## Surface and completion verdicts

`completion` exits 0 for `complete`, 3 for `incomplete` and 1 for `unknown`.
`unknown` never satisfies the completion stop, so a corpus that cannot be read
cannot end a campaign.

| Message | Cause | Action |
|---|---|---|
| `N surface sample(s) recorded; need >= M before the curve's shape means anything` | Fewer surface samples than `coverage.surface_min_samples` | The surface column is written on `coverage.surface_sample_min`, which is coarser than the edge cadence. Run longer, or lower the cadence |
| `no surface value in any sample` | Every sample skipped the surface measurement | Confirm the sampler is not running with `--skip-surface` on Track K, and that the run has a `corpus.db` |
| `completion not measured: <error>` | The corpus, the inventories or the ledger could not be read | Read the named error. A missing `corpus.db` means the run has not written one yet |
| `N ledger row(s) name a target no inventory contains and are not counted` | The ledger outlived a driver bump | Expected after a bump. Rows are keyed on the driver release, so the stale ones are reported and ignored |
| `no new target reached across the last N sample(s), and the corpus names M target(s) throughout` | The surface curve is flat | Read it with the edge verdict. Both flat with the ledger open means the corpus is stuck on resource chains, and not that the surface is exhausted |

## Campaigns

`campaign_ctl.py install` refuses a live campaign, an exhausted run-hour
budget, a reused run id and a harness tree with nothing built in it.

| Symptom | Cause | Action |
|---|---|---|
| `refusing to install run X: another campaign is still live` | The single global units `gspwn-k` and `gspwn-u` belong to another run, or another run's deadline timer is enabled | Stop the old campaign, or pass `--replace` to retire it |
| `refusing to start: N h already spent + M h exceeds loop.max_total_run_hours` | The run-hour budget cannot cover this campaign | Raise `loop.max_total_run_hours` deliberately, or stop the loop |
| `corpus policy 'carry' requires --from-run` | `--corpus carry` with no source run | Name the previous run id |
| `run X already has a corpus.db but the corpus policy is 'fresh'` | The run id is being reused | Use a new run id |
| `run X is not registered` when sampling | The sampler was pointed at an id no campaign install or `round-add-run` names | Fix the id, or register the run. A typo would create a root-owned run directory that later confuses `series` and `status` |
| `run X: campaign window has elapsed, so this call is not sampling` | The sampler timer outlives the campaign | Expected. `--force` overrides it, at the cost of padding the run's sample count |
| The campaign never ends | The deadline file is gone and nothing enforces the window | `check-deadline` rebuilds it from the install record, and stops the units when it cannot |
| `run error: no harness sources under X, so this is not the harness tree` | The Track U container has no `/harnesses` mount, or it points at the wrong directory | The unit takes two mounts: `-v <repo>/artifacts:/artifacts` and `-v <repo>/harnesses:/harnesses`. Reinstall the campaign, or correct the unit |
| `run error: N harness source tree(s) under X and no built binary among them` | The mount is correct and `build_all.sh` has not run on this machine | Run `bash harnesses/build_all.sh`, then reinstall |
| `warning: N of M harnesses are built` | Some targets failed to build | The run proceeds on the built ones. Rebuild the rest, or record them as blocked in `harnesses/TARGETS.md` |

## The round

A round refuses to advance while a campaign is live, while a phase is
unfinished, and while a hard stop stands unoverridden.

| Symptom | Cause | Action |
|---|---|---|
| `next` prints `wait (run X has N h left ...)` | A campaign in this round is still inside its window | Block on `campaign_ctl.py wait --run-id X` |
| `refusing to measure a live campaign` | `round-end` was called while a run is still fuzzing | Wait it out. `--force` is for a campaign that really is finished with only a stale deadline file |
| `cannot advance to round N: round phase(s) not done` | A round phase is not `done` | Finish it, or stop the loop with `round-decide --decision stop --reason "..."` and run `report`. Marking a phase `blocked` does not satisfy the check |
| `cannot advance to round N: round M has no recorded round-end` | The round was never measured | Run `round-end --from-run <run-id>` |
| `A completion, budget or round-cap stop cannot be overridden` | `--decision continue` against a hard cap | Raise the cap in the configuration, deliberately |
| `Overriding it requires --reason` | `--decision continue` against a plateau or `unknown` stop | State the reason |

## Triage

`pipeline_ctl.py` refuses an unlinked duplicate and a duplicate chain, and a
single rejected id aborts the whole `crash-set` call.

| Symptom | Cause | Action |
|---|---|---|
| `WARN: no crashes dir under ...` | The run id is wrong, or the campaign wrote nowhere | Check the id. This means nothing was scanned, and says nothing about whether the run crashed |
| The flagged queue will not empty | A generic panic title with a varying stack flags every distinct stack | Read the reports, then group with one `crash-set a b c --duplicate-of X` call |
| `status 'duplicate' requires --duplicate-of <id>` | A crash was marked a duplicate with no link | Link it, or set `--status unique` |
| `X is itself a duplicate. Link directly to the surviving entry` | A duplicate chain | Point at the surviving entry. Chains and cycles are refused |
| `crash-set` changed nothing | A rejected id aborted the whole call | The error names the id. Fix it and re-run |
| The crash count looks enormous | Noise Xids dominate the registry | `show` and `brief` print how many are noise. They are excluded from every derived count |
| `X was replayed and its output carries no sanitizer signature — skipped, not registered` | The input did not crash this build of the harness | Confirm the binary under `harnesses/<name>/build/` is the sanitizer build that found the input |
| `X is a fuzzer crash input and no .sanlog report sits beside it — skipped, not registered` | The input was never replayed, so no sanitizer output exists to take a title from | Run `harnesses/replay_crashes.sh`, which `run_all.sh` runs at harvest |
| `N file(s) under X and not one carries a sanitizer signature` | Every input in the directory fell into one of the two rows above | The message names the split between the two and the fix for each |

## Reproduction

`repro_ctl.py verify` refuses a session whose runs cannot be scored, and exits
non-zero when a rate would rest on too few counted runs.

| Symptom | Cause | Action |
|---|---|---|
| `refusing to verify while gspwn-k is still fuzzing` | A Track K verification was started with the campaign live | Stop the campaign. `--allow-live-campaign` accepts an inflated rate |
| `dmesg returned no output — refusing to verify` | `kernel.dmesg_restrict=1` and a non-root read | Re-run under `sudo`, or `sudo sysctl -w kernel.dmesg_restrict=0`. Without this every run would score clean and manufacture a 0% rate |
| `another repro_ctl verify session holds state/repro.lock` | Two verifiers on one machine | Wait. They share one dmesg ring and would corrupt each other's delta windows |
| Every run comes back `VOID (dmesg ring wrapped)` | KASAN spam evicts the anchor between the before and after reads | Reduce concurrent noise, or verify on a quieter boot. The attempt cap ends the session once `poc.void_retry_factor` attempts are spent |
| `giving up after N attempts: too many void runs` | The attempt cap fired | Investigate the void reason. Raising `poc.void_retry_factor` only buys more attempts at the same failure |
| `0 counted runs (N void) — no rate recorded` | Every run was void | Exit 1. Investigate the void reason. No rate is available to report |
| `protocol shortfall — N of M requested runs counted` | Exit 2. The rate rests on a short denominator | Check `repro_runs_counted` against `repro_runs_requested` before citing the rate |
| `cannot derive a crash-specific signature` | The registry title yields no usable phrases and no stack frames are registered | Without a signature, runs would be scored against generic `BUG:` patterns any crash would trip |
| `no usable repro.c` | syz-prog2c failed and left an empty stub | Re-run `extract`, which detects the empty file and regenerates it |

## The state file

The state file's checks fire on unreadable JSON, a missing spend ledger, and a
record `rca` left incomplete.

| Symptom | Cause | Action |
|---|---|---|
| `... is not valid JSON` | A truncated or hand-edited state file | Restore from `state/pipeline.json.bak`, or re-init |
| `spend ledger ... is missing, but the state file records N billed run-hours` | The ledger was lost or predates this version | `pipeline_ctl.py spend-init` |
| `WARNING: spend ledger ... holds N run-hours while the state file records M` | A ledger write failed and the campaign-start guard would otherwise read headroom that was already spent | The guard takes the larger figure, so the cap holds. Find the failed write before the next install |
| `X was analysed by rca but has no finding` | The analysis happened and nothing survived it for the next round | Record one with `finding-set` |
| `X has a finding that steers nothing` | `adjacent` is empty with no `no_adjacent_reason`, or repeats `ioctls` | Read the source for the object's other callers, or state why there are none |
| `X was analysed by rca but has no impact record` | The report would carry a reproducer with no argued severity | Record one with `impact-set` |
| `X has an impact record that does not support its conclusion` | Undetermined with no reason, a primitive with no evidence, or a consequence outrunning its primitive | The message names which of the three |
| `triage.X is N now but the registry's hashes were built with M` | Dedup depth changed mid-campaign | Restore the value for the rest of this campaign, or start a fresh registry |
| Permission errors on every state write | A `sudo` run left the state file root-owned | The tools hand the files back to `$SUDO_USER` after a sudo write. Check `SUDO_USER` was set |

## The orchestrator

Exit 78 stops the unit deliberately. The remaining failures are configuration
the installer could not infer.

| Symptom | Cause | Action |
|---|---|---|
| The unit stops and is not restarted | `run` exited 78, listed in `RestartPreventExitStatus` | The journal names which of the six causes fired. [Conditions that stop the unit](/gspwn/guides/unattended-operation/#conditions-that-stop-the-unit) lists them |
| `circuit breaker tripped` | Too many same-boot starts, or too many reboots in the window | Read the journal, fix the cause, then `orchestrator_ctl.py reset` |
| `orchestrator.command is not set` | No agent invocation configured | Set it in `config/campaign.yaml` |
| `refusing to install: no non-root user to run the agent as` | `install` had no `--user` and no `$SUDO_USER` | Pass `--user`, or install with `sudo` from that user's shell |
| The harvest captures nothing after a panic | The agent user has no passwordless sudo | `orchestrator_ctl.py preflight` names the remediation |
| `WARN: could not measure the previous transcript` | `orchestrator.session_transcript_glob` is unset or matches nothing | Rotation falls back to the resume count, which does not track transcript growth |
| The agent's usage is billed to the API account | `ANTHROPIC_API_KEY` is set in the unit environment | The variable takes precedence over a subscription login. Unset it for the unit. The generated unit does not set it |

## The tenant surface gate

`verify_tenant_surface.py measure` exits 1 when the record and the instance
disagree, and 2 when nothing was measured. The `provision` phase blocks on
both.

### No container runtime on PATH

`'docker' is not on PATH`. Install `docker.io`, or pass `--runtime` with the
runtime this host uses.

### The nvidia runtime is unknown

`the container did not run`, and the error names an unknown runtime `nvidia`.
The NVIDIA container toolkit is absent, or `nvidia-ctk runtime configure` was
never run. Follow
[Installation](/gspwn/getting-started/installation/) step 5. The
distribution's `docker.io` package carries no `nvidia` runtime.

### No registry access

`could not pull ubuntu:22.04`. Pre-load the image and pass `--no-pull`, or set
`GSPWN_VERIFY_IMAGE` to one already present.

### Reachable and not modelled

`REACHABLE AND NOT MODELLED` means the container received a node the record
places outside the tenant surface. Stop. The threat model understates the
attacker, and every coverage figure would be measured against the wrong
denominator. Widen the model before spending.

### Modelled and not reachable, on the modeset and DRM nodes

`MODELLED AND NOT REACHABLE` naming the modeset and DRM nodes means the
measurement reached the legacy injection path. Check `runtime-mode`. A
`legacy` verdict means this host withholds those nodes. A measurement taken
with `--via gpus` on Docker 29.1.x or older reports legacy whatever the host is
configured for.

### Modelled and not reachable, on the NVSwitch nodes

`MODELLED AND NOT REACHABLE` naming `/dev/nvidia-nvswitch*` is expected on a
host without NVSwitch, because those nodes are conditional on
`NVIDIA_NVSWITCH`. Record the condition and continue.

### The host states no runtime mode

`runtime-mode` reports `not stated on this host` when no `config.toml` was
found. The toolkit default applies, and `measure` settles what the host
actually does.

### The entry-point artefact is missing

`surface/entry-points.json does not exist` because it was never generated.

```
python3 tools/ioctl_inventory.py --src artifacts/src/open-gpu-kernel-modules --emit-entry-points surface/entry-points.json
```

## The build

The build gate stops on a dropped instrumentation option, a module that will
not load, a kernel that will not boot, and a missing Go toolchain.

### Instrumentation options dropped by olddefconfig

`ERROR: these are not set in .config (after olddefconfig):` naming the symbols,
followed by `Fuzzing without them measures and symbolizes nothing.`
`olddefconfig` drops anything the tree does not offer, so the check runs after
it. The seven symbols it requires are `CONFIG_KCOV`,
`CONFIG_KCOV_INSTRUMENT_ALL`, `CONFIG_KCOV_ENABLE_COMPARISONS`,
`CONFIG_KASAN`, `CONFIG_KASAN_GENERIC`, `CONFIG_KALLSYMS_ALL`, and any one of
the `CONFIG_DEBUG_INFO` variants. Fix the base config.

### Fallback to make defconfig

`WARNING: <path> not found, falling back to 'make defconfig'.` means
`BASE_CONFIG` names no file. It defaults to `/boot/config-$(uname -r)`. A
defconfig kernel usually lacks the storage and network drivers the machine
boots with. Set `BASE_CONFIG` to a config known good for this hardware.

### Secure Boot is enabled

`ERROR: Secure Boot is enabled`. Unsigned out-of-tree modules will not load.
Disable it in firmware, or enrol a MOK and sign each `nvidia*.ko`.

### Secure Boot state is unknown

`WARNING: mokutil is not installed`. Install `mokutil`, or confirm Secure Boot
is off in firmware.

### No GRUB entry for the new kernel

`ERROR: no GRUB menu entry for <kver>`. The kernel installed and nothing would
boot it. The next reboot would come back on the old kernel and fail the build
gate for a reason that looks like the build.

### The NVIDIA module build drops the instrumentation flags

`conftest.sh` strips unknown CFLAGS from the environment. Patch
`kernel-open/conftest.sh` minimally to append them, log the patch, and retry
once per rung.

### No Go toolchain

`make: go: No such file or directory` in the syzkaller tree. `build-essential`
carries no Go toolchain, and syzkaller builds on the host. Follow
[Installation](/gspwn/getting-started/installation/) step 7.

### The Go toolchain is below the floor

`go.mod requires go >= 1.26.0` from `make` or from `syzlang_gen.py compile`.
The toolchain is below the floor and did not switch. Go 1.21 and later download
it under `GOTOOLCHAIN=auto`, so this means a toolchain below 1.21,
`GOTOOLCHAIN=local`, or no route to `proxy.golang.org`. Install the upstream
tarball, [Installation](/gspwn/getting-started/installation/) step 7.

### go is installed and the compile phase cannot find it

`syzlang_gen.py compile` exits 3 with `go` installed. The phase's shell has no
`/usr/local/go/bin` on `PATH`, and the install step's `export` covers one
shell. Add the `PATH` line to the campaign user's shell profile.

## Disk

Two symptoms cover the disk.

- `WARN: 12.4 GB free, under loop.min_free_disk_gb (20 GB).` means kdump dumps
  and the corpus have grown. Run
  `sudo python3 tools/crashlog_ctl.py prune --keep 10`, or grow the volume.
- Everything failing at once means the disk is full. The fuzzer, the sampler
  and every state write stop together.
