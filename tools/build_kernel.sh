#!/usr/bin/env bash
# Build instrumented kernel + NVIDIA open-gpu-kernel-modules.
# Degradation ladder (spec Phase 1):
#   RUNG=1  KASAN+KCOV kernel, KASAN+KCOV nvidia modules
#   RUNG=2  KASAN+KCOV kernel, KCOV-only nvidia modules
#   RUNG=3  KASAN+KCOV kernel, uninstrumented nvidia modules
# Required env: LINUX_SRC, NVIDIA_SRC, RUNG.
# Optional: JOBS (default nproc)
#           BASE_CONFIG (default /boot/config-$(uname -r))
#           SKIP_KERNEL=1 reuse the kernel already built and installed
set -euo pipefail

: "${LINUX_SRC:?set to kernel source dir}"
: "${NVIDIA_SRC:?set to open-gpu-kernel-modules dir}"
: "${RUNG:?1|2|3}"
JOBS="${JOBS:-$(nproc)}"
BASE_CONFIG="${BASE_CONFIG:-/boot/config-$(uname -r)}"
SKIP_KERNEL="${SKIP_KERNEL:-0}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOGDIR="$REPO_ROOT/artifacts/logs"
mkdir -p "$LOGDIR"
LINUX_SRC="$(cd "$LINUX_SRC" && pwd)"
NVIDIA_SRC="$(cd "$NVIDIA_SRC" && pwd)"

[[ "$RUNG" =~ ^[123]$ ]] || { echo "RUNG must be 1, 2 or 3"; exit 2; }

cd "$LINUX_SRC"
KVER=""

if [[ "$SKIP_KERNEL" == "1" ]]; then
  # Only the NVIDIA module CFLAGS differ between rungs, so walking the ladder
  # rebuilding the whole kernel each time spends hours of billed machine time
  # producing an identical image. agents/build.md passes this for rungs 2
  # and 3.
  echo "== kernel: SKIP_KERNEL=1, reusing the installed build =="
  [[ -f .config ]] || { echo "SKIP_KERNEL=1 but $LINUX_SRC/.config does not \
exist; run rung 1 first"; exit 2; }
else
  echo "== kernel config (KASAN+KCOV) =="
  # Start from the config this machine actually boots with, not defconfig. A
  # generic x86 defconfig has no NVMe or ENA driver, so on a cloud instance
  # the resulting kernel cannot find its own root filesystem, and the failure
  # arrives after a full build and a reboot. Falling back to defconfig is
  # loud, because it is very unlikely to boot.
  if [[ -f "$BASE_CONFIG" ]]; then
    echo "base config: $BASE_CONFIG"
    cp "$BASE_CONFIG" .config
    make olddefconfig 2>&1 | tee "$LOGDIR/build-kernel-config.log"
  else
    echo "WARNING: $BASE_CONFIG not found, falling back to 'make defconfig'."
    echo "         A defconfig kernel usually lacks the storage and network"
    echo "         drivers this machine boots with and will not come back up."
    echo "         Set BASE_CONFIG to a config known good for this hardware."
    make defconfig 2>&1 | tee "$LOGDIR/build-kernel-config.log"
  fi
  scripts/config --enable CONFIG_KCOV \
                 --enable CONFIG_KCOV_INSTRUMENT_ALL \
                 --enable CONFIG_KASAN \
                 --enable CONFIG_KASAN_GENERIC \
                 --enable CONFIG_UBSAN \
                 --enable CONFIG_DEBUG_KERNEL \
                 --enable CONFIG_DEBUG_INFO \
                 --disable CONFIG_DEBUG_INFO_NONE \
                 --enable CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT \
                 --enable CONFIG_KALLSYMS_ALL \
                 --enable CONFIG_PSTORE --enable CONFIG_PSTORE_RAM \
                 --enable CONFIG_PSTORE_CONSOLE \
                 --enable CONFIG_KEXEC_CORE --enable CONFIG_CRASH_DUMP \
                 --disable CONFIG_RANDOMIZE_BASE   # stable stacks for dedup
  # Distro configs sign and lock down modules; an out-of-tree NVIDIA build
  # cannot load under either.
  scripts/config --disable CONFIG_MODULE_SIG_FORCE \
                 --disable CONFIG_SECURITY_LOCKDOWN_LSM_EARLY \
                 --set-str CONFIG_SYSTEM_TRUSTED_KEYS "" \
                 --set-str CONFIG_MODULE_SIG_KEY ""
  make olddefconfig 2>&1 | tee -a "$LOGDIR/build-kernel-config.log"

  # olddefconfig silently drops anything the tree does not offer, and
  # CONFIG_DEBUG_INFO stopped being user-selectable in 5.18 — exactly the
  # class of setting that goes missing without a word and is only noticed
  # when symbolization is useless months later. Check what actually took.
  echo "== config check =="
  missing=""
  for sym in CONFIG_KCOV CONFIG_KCOV_INSTRUMENT_ALL CONFIG_KASAN \
             CONFIG_KASAN_GENERIC CONFIG_KALLSYMS_ALL; do
    grep -q "^${sym}=y" .config || missing="$missing $sym"
  done
  # Debug info is a choice in newer trees; any of these three satisfies it.
  grep -qE "^CONFIG_DEBUG_INFO(_DWARF[A-Z0-9_]*)?=y" .config \
    || missing="$missing CONFIG_DEBUG_INFO"
  if [[ -n "$missing" ]]; then
    echo "ERROR: these did not survive olddefconfig:$missing" >&2
    echo "       Fuzzing without them measures and symbolizes nothing." >&2
    exit 1
  fi
  echo "instrumentation present: KCOV, KASAN, kallsyms, debug info"

  echo "== kernel build (-j$JOBS) =="
  make -j"$JOBS" 2>&1 | tee "$LOGDIR/build-kernel.log"

  echo "== kernel install =="
  sudo make modules_install 2>&1 | tee -a "$LOGDIR/build-kernel.log"
  sudo make install        2>&1 | tee -a "$LOGDIR/build-kernel.log"
fi

echo "== NVIDIA modules (rung $RUNG) =="
cd "$NVIDIA_SRC"
KVER="$(make -sC "$LINUX_SRC" kernelrelease)"
# NVIDIA's conftest.sh strips unknown CFLAGS from env; pass via
# KBUILD_EXTRA_CFLAGS and patch kernel-open/conftest.sh if rung 1 fails
# (build agent handles the patch; see agents/build.md).
case "$RUNG" in
  1) KBUILD_EXTRA_CFLAGS="-fsanitize=kernel-address -fsanitize-coverage=trace-pc,trace-cmp" ;;
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

echo "== secure boot =="
# Not silently skipped when mokutil is absent: an unsigned out-of-tree module
# on a Secure Boot machine simply refuses to load, and the build phase would
# then fail its gate with nvidia-smi errors that say nothing about signing.
if ! command -v mokutil >/dev/null 2>&1; then
  echo "WARNING: mokutil is not installed, so Secure Boot state is unknown."
  echo "         If it is enabled, the modules just built will not load."
  echo "         apt install mokutil, or confirm SB is off in firmware."
elif mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled"; then
  echo "ERROR: Secure Boot is enabled. The out-of-tree NVIDIA modules are" >&2
  echo "       unsigned and will not load, so the build gate cannot pass." >&2
  echo "       Disable it in firmware, or enrol a MOK and sign each" >&2
  echo "       nvidia*.ko with sbsign/kmodsign, then re-run." >&2
  exit 1
else
  echo "Secure Boot: disabled"
fi

echo "== grub default =="
# Boot the kernel we just built, and verify that it will. The previous
# attempt guessed at a menu entry title ("Advanced options>Linux $KVER")
# that does not match what Debian generates, then swallowed the failure into
# an `|| echo` telling a human to fix it — so an unattended build rebooted
# into the old kernel and failed its own gate.
#
# Submenus are disabled so every kernel is a top-level entry with a stable,
# greppable id; otherwise the default has to be addressed as "submenu>entry"
# and the outer title differs per distro.
if ! grep -q "^GRUB_DISABLE_SUBMENU=" /etc/default/grub; then
  echo "GRUB_DISABLE_SUBMENU=y" | sudo tee -a /etc/default/grub >/dev/null
else
  sudo sed -i 's/^#*GRUB_DISABLE_SUBMENU=.*/GRUB_DISABLE_SUBMENU=y/' \
    /etc/default/grub
fi
if grep -q "^GRUB_DEFAULT=" /etc/default/grub; then
  sudo sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub
else
  echo "GRUB_DEFAULT=saved" | sudo tee -a /etc/default/grub >/dev/null
fi
sudo update-grub 2>&1 | tee -a "$LOGDIR/build-kernel.log"

ENTRY="$(grep -oP "menuentry_id_option '\K[^']+" /boot/grub/grub.cfg \
         | grep -F -- "$KVER" | grep -v recovery | head -1 || true)"
if [[ -z "$ENTRY" ]]; then
  echo "ERROR: no GRUB menu entry for $KVER in /boot/grub/grub.cfg." >&2
  echo "       The kernel installed but nothing would boot it, so the next" >&2
  echo "       reboot comes back on the old one and the build gate fails" >&2
  echo "       for a reason that looks like the build." >&2
  exit 1
fi
sudo grub-set-default "$ENTRY"
if ! sudo grub-editenv list | grep -qF "saved_entry=$ENTRY"; then
  echo "ERROR: grub-set-default did not stick (saved_entry is not $ENTRY)." >&2
  exit 1
fi
echo "next boot: $ENTRY"

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
