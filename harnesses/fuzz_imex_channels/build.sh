#!/usr/bin/env bash
# Build the NVIDIA_IMEX_CHANNELS harness.
#
# Leak policy: detect_leaks=0, and the reason is specific. parse_imex_info
# allocates imex->chans before its parse loop and does not free it on the
# failure branch, so every rejected input leaks that allocation. The library's
# only caller is nvidia-container-cli, which exits immediately afterwards, so
# the leak is bounded by one process lifetime and is not a Track U finding.
# Leaving detection on would fill the crash queue with one known non-finding.
# The leak is recorded in TARGETS.md so it is not rediscovered as new.
#
# src/cli/libnvc.c is linked because src/cli/common.c references the libnvc
# function-pointer table. The table is populated by dlopen at runtime and
# parse_imex_info never reads it, so nothing loads the shared library.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "${here}/../common/build_common.sh"

harness_build fuzz_imex_channels "${here}/fuzz_imex_channels.c" \
    src/cli/common.c \
    src/cli/libnvc.c \
    src/error_generic.c \
    src/utils.c

cat > "${here}/build/env.sh" <<'EOF'
# symbolize follows the consumer: afl-fuzz parses sanitizer output itself and
# aborts at startup on anything but symbolize=0, and a .sanlog carrying no
# symbols gives crash_parse.py no frames to hash. run_all.sh exports
# HARNESS_SYMBOLIZE=0 before sourcing this; replay_crashes.sh leaves it.
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=${HARNESS_SYMBOLIZE:-1}"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
EOF
echo "wrote ${here}/build/env.sh"
