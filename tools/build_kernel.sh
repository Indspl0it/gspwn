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
LINUX_SRC="$(cd "$LINUX_SRC" && pwd)"
NVIDIA_SRC="$(cd "$NVIDIA_SRC" && pwd)"

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
