#!/usr/bin/env bash
# Build the path_resolve harness.
#
# Leak policy: detect_leaks=1. do_path_resolve allocates nothing on the heap.
# It does leak a directory file descriptor whenever open_next fails, which
# surfaces as EMFILE and not as a leak report. TARGETS.md records that so the
# triage phase does not read it as a harness defect.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "${here}/../common/build_common.sh"

harness_build fuzz_path_resolve "${here}/fuzz_path_resolve.c" \
    src/error_generic.c \
    src/utils.c

cat > "${here}/build/env.sh" <<'EOF'
# symbolize follows the consumer: afl-fuzz parses sanitizer output itself and
# aborts at startup on anything but symbolize=0, and a .sanlog carrying no
# symbols gives crash_parse.py no frames to hash. run_all.sh exports
# HARNESS_SYMBOLIZE=0 before sourcing this; replay_crashes.sh leaves it.
export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1:symbolize=${HARNESS_SYMBOLIZE:-1}"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
EOF
echo "wrote ${here}/build/env.sh"
