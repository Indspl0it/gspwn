#!/usr/bin/env bash
# Build every Track U harness. This is the first thing the harness phase runs.
#
# None of these harnesses has ever been compiled. They were written by reading
# the source of libnvidia-container and nvidia-container-toolkit on a machine
# with no clang and no AFL++ image, so the first run of this script is also
# their first compile. Treat a build failure as expected work, not as a
# surprise: fix the harness, re-run, and record what was wrong through
# tools/knowledge_ctl.py.
#
# Environment:
#   SRC           libnvidia-container checkout   (default ../src/libnvidia-container)
#   TOOLKIT_SRC   toolkit checkout               (default ../src/nvidia-container-toolkit)
#   HARNESS_MODE  auto | afl | libfuzzer         (default auto)
#   AFL_DRIVER    AFL++ libFuzzer driver archive (default /usr/local/lib/afl/libAFLDriver.a)
#
# Exit status is the number of harnesses that failed to build, so a caller can
# branch on partial success. agents/harness.md permits Track U proceeding with
# fewer working harnesses as long as the shortfall is stated.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

C_TARGETS=(
    fuzz_ldcache
    fuzz_path_resolve
    fuzz_dsl_evaluate
    fuzz_options_parse
    fuzz_imex_channels
    fuzz_path_join
)
GO_TARGETS=(
    go_cudacompat_elf
)

failed=0
built=()
broken=()

for t in "${C_TARGETS[@]}" "${GO_TARGETS[@]}"; do
    echo "=============================================================="
    echo "building ${t}"
    echo "=============================================================="
    if bash "${here}/${t}/build.sh"; then
        built+=("${t}")
    else
        broken+=("${t}")
        failed=$((failed + 1))
    fi
done

echo
echo "built ${#built[@]}: ${built[*]:-none}"
echo "failed ${#broken[@]}: ${broken[*]:-none}"
if [ "${failed}" -gt 0 ]; then
    echo "record every failing target as blocked in TARGETS.md before running" \
         "the campaign, and say so in the gate evidence."
fi
exit "${failed}"
