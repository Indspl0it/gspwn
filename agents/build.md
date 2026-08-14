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

## State
Record progress with the state tool, never by editing pipeline.json:
`python3 tools/pipeline_ctl.py set-phase build in_progress|done|blocked
 --notes "rung N"`

## Gate evidence to return
chosen rung, uname -r, dmesg KASAN line, nvidia-smi output.

## Errors
Rung fails build or boot: harvest crash logs (`crashlog_ctl.py harvest`),
record findings in artifacts/builds/rung-N-failed.md, proceed to next rung.
All rungs fail: write artifacts/builds/FAILED.md, mark phase blocked.
