#!/usr/bin/env bash
# Build the ld.so.cache parser harness.
#
# Leak policy: detect_leaks=1. The harness frees every path ldcache_resolve
# allocates and closes the mapping, so a leak report names a defect in the
# parser and not in the harness.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "${here}/../common/build_common.sh"

harness_build fuzz_ldcache "${here}/fuzz_ldcache.c" \
    src/ldcache.c \
    src/error_generic.c \
    src/utils.c

cat > "${here}/build/env.sh" <<'EOF'
export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1:symbolize=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
EOF
echo "wrote ${here}/build/env.sh"
