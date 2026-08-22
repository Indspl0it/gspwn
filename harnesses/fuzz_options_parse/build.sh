#!/usr/bin/env bash
# Build the options_parse harness.
#
# Leak policy: detect_leaks=1. options_parse allocates nothing that outlives
# the call, so any leak this reports is a real one.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "${here}/../common/build_common.sh"

harness_build fuzz_options_parse "${here}/fuzz_options_parse.c" \
    src/options.c \
    src/error_generic.c \
    src/utils.c

cat > "${here}/build/env.sh" <<'EOF'
export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1:symbolize=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
EOF
echo "wrote ${here}/build/env.sh"
