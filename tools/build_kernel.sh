#!/usr/bin/env bash
# Build instrumented kernel + NVIDIA open-gpu-kernel-modules.
# Degradation ladder:
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

# Symbols disabled deliberately below, and until now checked nowhere after
# olddefconfig had its say. Each fails differently and none of the failures
# names itself.
REQUIRED_DISABLED=(
  # KASLR shifts every address in every report. stack_hash strips offsets and
  # module names and keeps function names, so the primary dedup key survives,
  # and the RIP symbol crash_parse.py reads and every unsymbolized frame do
  # not. The secondary key degrades silently, which is the failure mode the
  # frameless-signature work exists to prevent.
  CONFIG_RANDOMIZE_BASE
  # An out-of-tree NVIDIA module is unsigned. Either of these surviving stops
  # it loading, and the build gate then fails with nvidia-smi errors that say
  # nothing about signing or lockdown.
  CONFIG_MODULE_SIG_FORCE
  CONFIG_SECURITY_LOCKDOWN_LSM_EARLY
  # Selecting this compiles the debug info out from under DEBUG_INFO.
  CONFIG_DEBUG_INFO_NONE
)

# check_config <config file> <context>
# olddefconfig silently drops anything the tree does not offer, and
# CONFIG_DEBUG_INFO stopped being user-selectable in 5.18 — exactly the class
# of setting that goes missing without a word and is only noticed when
# symbolization is useless months later. Check what actually took.
check_config() {
  local cfg="$1" context="$2" sym missing="" surviving=""
  [[ -f "$cfg" ]] || { echo "ERROR: no config at $cfg ($context)" >&2; exit 1; }
  # KCOV is coverage at all, INSTRUMENT_ALL is coverage outside the syscall
  # entry paths, ENABLE_COMPARISONS is the __sanitizer_cov_trace_cmp* symbols
  # the rung 1 and rung 2 module builds reference, KALLSYMS_ALL is
  # symbolization of module frames.
  for sym in CONFIG_KCOV CONFIG_KCOV_INSTRUMENT_ALL \
             CONFIG_KCOV_ENABLE_COMPARISONS CONFIG_KASAN \
             CONFIG_KASAN_GENERIC CONFIG_KALLSYMS_ALL; do
    grep -q "^${sym}=y" "$cfg" || missing="$missing $sym"
  done
  # Debug info is a choice in newer trees; any of these three satisfies it.
  grep -qE "^CONFIG_DEBUG_INFO(_DWARF[A-Z0-9_]*)?=y" "$cfg" \
    || missing="$missing CONFIG_DEBUG_INFO"
  for sym in "${REQUIRED_DISABLED[@]}"; do
    ! grep -q "^${sym}=y" "$cfg" || surviving="$surviving $sym"
  done
  if [[ -n "$missing" ]]; then
    echo "ERROR: these are not set in $cfg ($context):$missing" >&2
    echo "       Fuzzing without them measures and symbolizes nothing." >&2
    exit 1
  fi
  if [[ -n "$surviving" ]]; then
    echo "ERROR: these are still enabled in $cfg ($context):$surviving" >&2
    echo "       Each one was disabled on purpose; see REQUIRED_DISABLED in" >&2
    echo "       this script for what each one costs." >&2
    exit 1
  fi
  echo "config check ($context): KCOV, KCOV comparisons, KASAN, kallsyms," \
       "debug info present; KASLR, module signing and lockdown off"
}

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
  # The same check the build branch runs, against the config the reused
  # kernel came from. Rung 2 compiles the NVIDIA modules with
  # -fsanitize-coverage=trace-cmp against whatever kernel is installed: if
  # that kernel's tree lost CONFIG_KCOV_ENABLE_COMPARISONS, insmod fails with
  # 'Unknown symbol __sanitizer_cov_trace_cmp1' hours later, and skipping the
  # check here is what lets rung 2 walk into the failure rung 1 checks for.
  echo "== config check =="
  check_config .config "reused kernel, SKIP_KERNEL=1"
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
  # CONFIG_KCOV_ENABLE_COMPARISONS is not implied by CONFIG_KCOV and
  # carries no 'default y'. Without it kernel/kcov.c compiles out every
  # __sanitizer_cov_trace_cmp* definition, and the NVIDIA modules built
  # at rung 1 and rung 2 with -fsanitize-coverage=trace-cmp reference
  # symbols the kernel does not export: insmod fails with 'Unknown
  # symbol __sanitizer_cov_trace_cmp1'. syzkaller's comparison-hint
  # mutation reads the same data.
  scripts/config --enable CONFIG_KCOV \
                 --enable CONFIG_KCOV_INSTRUMENT_ALL \
                 --enable CONFIG_KCOV_ENABLE_COMPARISONS \
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

  echo "== config check =="
  check_config .config "after olddefconfig"

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
import json, os, subprocess, sys, tempfile
root, rung, kver = sys.argv[1], int(sys.argv[2]), sys.argv[3]
mdir = os.path.join(root, "artifacts", "builds")
mpath = os.path.join(mdir, "manifest.json")
# This runs at the end of a multi-hour build and it is the only record of what
# was built. A missing parent directory or an interrupt part-way through the
# write costs that record and the build with it, so the directory is created
# and the file is written through a temp file and renamed.
os.makedirs(mdir, exist_ok=True)
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
fd, tmp = tempfile.mkstemp(dir=mdir, suffix=".tmp")
try:
    with os.fdopen(fd, "w") as f:
        json.dump(m, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, mpath)
except BaseException:
    if os.path.exists(tmp):
        os.unlink(tmp)
    raise
print("manifest updated:", mpath)
EOF

echo "BUILD COMPLETE (rung $RUNG). Reboot into kernel $KVER."
