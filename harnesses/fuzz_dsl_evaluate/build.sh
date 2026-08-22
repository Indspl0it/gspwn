#!/usr/bin/env bash
# Build the --require predicate harness.
#
# Leak policy: detect_leaks=1. dsl_evaluate frees both of its allocations on
# every exit path, so a leak report here names a real defect.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "${here}/../common/build_common.sh"

harness_build fuzz_dsl_evaluate "${here}/fuzz_dsl_evaluate.c" \
    src/cli/dsl.c \
    src/error_generic.c \
    src/utils.c

cat > "${here}/build/env.sh" <<'EOF'
export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1:symbolize=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
EOF
echo "wrote ${here}/build/env.sh"
