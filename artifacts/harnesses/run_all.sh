#!/usr/bin/env bash
# Run every built Track U harness against its seeds for FUZZ_HOURS.
#
# Output layout, which agents/harness.md fixes:
#   /artifacts/runs/$RUN_ID/u/<harness-name>/    fuzzer output, one dir per harness
#   /artifacts/harnesses/crashes/<harness-name>/ crashes copied out at the end
#
# The coverage sampler reads AFL++'s fuzzer_stats from the first path. Only the
# afl build mode writes that file. In libfuzzer mode the directory holds the
# evolving corpus and the crash artifacts and no edge curve, and Track U then
# contributes nothing to the round's coverage verdict. Check which mode the
# binaries were built in before trusting a plateau decision.
#
# Environment:
#   RUN_ID       campaign run id, already set in the container environment
#   FUZZ_HOURS   wall-clock hours per harness (default 24)
#   HARNESS_MODE auto | afl | libfuzzer (default auto, matched to what exists)
#   JOBS         harnesses to run at once (default: all of them)
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

: "${FUZZ_HOURS:=24}"
: "${RUN_ID:=}"
: "${HARNESS_MODE:=auto}"
: "${ARTIFACT_ROOT:=/artifacts}"

if [ -z "${RUN_ID}" ]; then
    echo "run error: RUN_ID is unset. Every campaign gets its own run id and" \
         "its own workdir; runs that share one share an evolved corpus, and" \
         "neither run's coverage numbers then describe what it did." >&2
    exit 1
fi
case "${FUZZ_HOURS}" in
    ''|*[!0-9.]*) echo "run error: FUZZ_HOURS must be a number, and was ${FUZZ_HOURS}" >&2; exit 1;;
esac

SECONDS_TOTAL=$(awk -v h="${FUZZ_HOURS}" 'BEGIN{printf "%d", h*3600}')
if [ "${SECONDS_TOTAL}" -lt 60 ]; then
    echo "run error: FUZZ_HOURS=${FUZZ_HOURS} is under one minute of fuzzing." \
         "The smoke check in agents/harness.md uses 60 seconds; anything" \
         "shorter measures startup." >&2
    exit 1
fi

C_TARGETS=(
    fuzz_ldcache
    fuzz_path_resolve
    fuzz_dsl_evaluate
    fuzz_options_parse
    fuzz_imex_channels
    fuzz_path_join
)

RUN_ROOT="${ARTIFACT_ROOT}/runs/${RUN_ID}/u"
CRASH_ROOT="${ARTIFACT_ROOT}/harnesses/crashes"
mkdir -p "${RUN_ROOT}" "${CRASH_ROOT}"

detect_mode() {
    if [ "${HARNESS_MODE}" != "auto" ]; then
        echo "${HARNESS_MODE}"
        return
    fi
    if command -v afl-fuzz >/dev/null 2>&1; then
        echo afl
    else
        echo libfuzzer
    fi
}
MODE="$(detect_mode)"
echo "run ${RUN_ID}: ${FUZZ_HOURS}h per harness, mode ${MODE}, output ${RUN_ROOT}"

pids=()
names=()

for t in "${C_TARGETS[@]}"; do
    bin="${here}/${t}/build/${t}"
    seeds="${here}/${t}/seeds"
    dict="${here}/${t}/${t}.dict"
    out="${RUN_ROOT}/${t}"

    if [ ! -x "${bin}" ]; then
        echo "skipping ${t}: ${bin} was not built. Run build_all.sh first and" \
             "record the target as blocked in TARGETS.md if it stays broken."
        continue
    fi
    if [ ! -d "${seeds}" ] || [ -z "$(ls -A "${seeds}" 2>/dev/null)" ]; then
        echo "skipping ${t}: no seeds in ${seeds}. Regenerate them with" \
             "python3 ${here}/seedgen.py"
        continue
    fi
    mkdir -p "${out}"

    # Sanitizer options were written next to the binary by its build.sh. Each
    # harness states its own leak policy there; see TARGETS.md for why.
    [ -f "${here}/${t}/build/env.sh" ] && . "${here}/${t}/build/env.sh"

    if [ "${MODE}" = "afl" ]; then
        # AFL++ writes fuzzer_stats under ${out}/default/, which is what the
        # coverage sampler reads.
        AFL_AUTORESUME=1 AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 \
        timeout --signal=INT "${SECONDS_TOTAL}" \
            afl-fuzz -i "${seeds}" -o "${out}" -x "${dict}" \
                     -m none -- "${bin}" >"${out}/afl.log" 2>&1 &
    else
        mkdir -p "${out}/corpus" "${out}/crashes"
        timeout --signal=INT "${SECONDS_TOTAL}" \
            "${bin}" "${out}/corpus" "${seeds}" \
                     -dict="${dict}" \
                     -max_total_time="${SECONDS_TOTAL}" \
                     -print_final_stats=1 \
                     -artifact_prefix="${out}/crashes/" \
                     >"${out}/libfuzzer.log" 2>&1 &
    fi
    pids+=("$!")
    names+=("${t}")
    echo "started ${t} -> ${out}"
done

if [ "${#pids[@]}" -eq 0 ]; then
    echo "run error: no harness started. Nothing was built, or no seeds exist." >&2
    exit 1
fi

status=0
for i in "${!pids[@]}"; do
    wait "${pids[$i]}"
    rc=$?
    # 124 is timeout's own status and is the expected end of a timed campaign.
    if [ "${rc}" -ne 0 ] && [ "${rc}" -ne 124 ]; then
        echo "${names[$i]} exited with status ${rc}; see its log under ${RUN_ROOT}"
        status=1
    fi
done

# Copy crashes out. Reproduce every one against its harness before it goes to
# triage: anything the harness itself does wrong is a harness bug, not a
# finding. TARGETS.md carries the replay command for each target.
copied=0
for t in "${C_TARGETS[@]}"; do
    src=""
    [ -d "${RUN_ROOT}/${t}/default/crashes" ] && src="${RUN_ROOT}/${t}/default/crashes"
    [ -d "${RUN_ROOT}/${t}/crashes" ] && src="${RUN_ROOT}/${t}/crashes"
    [ -n "${src}" ] || continue
    n=$(find "${src}" -type f ! -name "README.txt" | wc -l)
    [ "${n}" -gt 0 ] || continue
    mkdir -p "${CRASH_ROOT}/${t}"
    cp -f "${src}"/* "${CRASH_ROOT}/${t}/" 2>/dev/null || true
    copied=$((copied + n))
    echo "${t}: ${n} crash inputs copied to ${CRASH_ROOT}/${t}"
done
echo "total crash inputs: ${copied}"
exit "${status}"
