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

   Pass `SKIP_KERNEL=1` for rungs 2 and 3. Only the NVIDIA module CFLAGS
   differ between rungs, and the kernel is identical. Rebuilding it per rung
   spends hours of billed machine time producing the same image, and those
   hours come out of the same budget as the fuzzing.

   That path runs the full config check against the reused kernel's `.config`,
   so a rung 2 run can fail at the config check on a kernel rung 1 built. That
   is the intended outcome. Rung 2 compiles the NVIDIA modules with
   `-fsanitize-coverage=trace-cmp`, and against a kernel whose tree lost
   `CONFIG_KCOV_ENABLE_COMPARISONS` the `insmod` fails hours later with
   `Unknown symbol __sanitizer_cov_trace_cmp1`. The check also fails when
   `CONFIG_RANDOMIZE_BASE`, `CONFIG_MODULE_SIG_FORCE`,
   `CONFIG_SECURITY_LOCKDOWN_LSM_EARLY` or `CONFIG_DEBUG_INFO_NONE` survived
   as `y`: KASLR degrades the secondary dedup key, and either of the other two
   stops an unsigned out-of-tree module loading. The recovery is to re-run
   rung 1 so the kernel is rebuilt with a config that holds. Do not override
   the check.

   The script bases the config on `/boot/config-$(uname -r)` so the new
   kernel keeps the storage and network drivers this machine boots with.
   Override with `BASE_CONFIG=` only when the running config is known to be
   wrong for the target hardware. If it warns that it fell back to
   `defconfig`, stop. That kernel will very likely not find its own root
   filesystem, and the failure surfaces only after a full build and a reboot.
2. If the NVIDIA module build fails because conftest.sh strips
   KBUILD_EXTRA_CFLAGS, patch kernel-open/conftest.sh minimally to append
   the flags, log the patch into artifacts/builds/, retry ONCE per rung.
3. Reboot into the new kernel. The script sets the GRUB default to the entry
   it just installed and verifies it stuck, so this needs no manual step. If
   it reported an error there, do not reboot until it is resolved, because
   the machine would come back on the old kernel and fail the gate below for
   a reason that looks like the build.
4. Gate check. All four must hold:
   - `uname -r` matches the kernel just built.
   - `dmesg | grep -i kasan` shows the state the rung specifies.
   - `lsmod | grep nvidia` is non-empty.
   - `nvidia-smi` works.
5. On gate success, set instrumentation_rung in config/machine.yaml and
   artifacts/builds/manifest.json, and stop walking the ladder.

## State
Record progress with the state tool, never by editing pipeline.json:
`python3 tools/pipeline_ctl.py set-phase build in_progress|done|blocked
 --notes "rung N"`

## Gate evidence
Chosen rung, uname -r, dmesg KASAN line, nvidia-smi output.

## Errors

| Condition | Action |
|---|---|
| A rung fails its build or its boot | Harvest crash logs with `sudo python3 tools/crashlog_ctl.py harvest`, record the findings in artifacts/builds/rung-N-failed.md, proceed to the next rung |
| All rungs fail | Write artifacts/builds/FAILED.md and mark the phase blocked |

## Knowledge (cross-campaign)

Read what earlier campaigns established before you start:

```
python3 tools/knowledge_ctl.py show --phase build
```

Record what you learn **as you learn it**, not at the end from memory:

```
python3 tools/knowledge_ctl.py note --kind learning --phase build "..."
python3 tools/knowledge_ctl.py note --kind mistake  --phase build "..."
```

A **learning** is about the target. For this phase, typically build and
kernel facts: config options that matter, instrumentation that silently does
nothing. A **mistake** is about us: something that cost time, produced a
wrong number, or would repeat. Both are read by whoever runs this phase
next, on another box months from now, so write for someone without your
context. Recording nothing across a whole phase is itself worth questioning.

`knowledge/` is committed to a **public repository**. It carries ABI and
process facts and never findings: `note` refuses text naming a crash id or a
path under `artifacts/crashes|pocs|rca`, and the specifics belong in the
crash registry. Record the general form. It is also the more useful one,
because the next agent is looking at a different crash.
