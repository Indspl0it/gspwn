#!/usr/bin/env bash
# Replay every harvested Track U crash input under its own harness and write
# the sanitizer output beside it.
#
# Why this step exists. AFL++ and libFuzzer save the *bytes* that reproduced a
# crash, not the report the sanitizer printed: AFL++ names them
# id:NNNNNN,sig:NN,... and libFuzzer names them crash-<sha1>. run_all.sh
# copies those bytes to /artifacts/u-crashes/<harness-name>/.
# tools/crash_parse.py registers a Track U crash from a sanitizer signature —
# an ERROR: ...Sanitizer, SUMMARY:, runtime error: or SEGV line — and a raw
# input carries none, so without this step every finding is skipped with a
# warning and the registry stays empty. This script produces the missing half.
#
# Output layout:
#   crashes/<harness>/<input>          the bytes, as the fuzzer saved them
#   crashes/<harness>/<input>.sanlog   this input's sanitizer output
#
# The pairing is by name so crash_parse.py can tell an input from its report
# without a manifest, and so the report is readable next to the bytes that
# produced it. crash_parse.py registers the *input* path and reads the title
# and the stack frames out of the .sanlog, because the input path is what
# `repro_ctl.py extract` copies and `verify --track u --cmd` replays.
#
# Both build modes replay from a file argument: a libFuzzer binary runs one
# input as `./fuzz_x <file>`, and the AFL++ build links AFL++'s libAFLDriver.a,
# whose main() takes the same form. Both are compiled -fsanitize=address,
# undefined (see common/build_common.sh), so the report comes out on stderr.
#
# Environment:
#   ARTIFACT_ROOT       artifact tree root (default /artifacts)
#   CRASH_ROOT          crash root to replay (default $ARTIFACT_ROOT/u-crashes)
#   HARNESS_ROOT        where <harness>/build/<harness> lives (default: this dir)
#   REPLAY_TIMEOUT      seconds per input (default 60)
#   REPLAY_MAX_INPUTS   inputs replayed per harness (default 200)
#   REPLAY_FORCE=1      re-replay inputs that already have a .sanlog
#
# Exit status is 0 whenever the replay itself ran, whatever the harnesses did:
# a crashing input is the expected outcome here, and this script is called
# from run_all.sh's harvest, which must not fail a campaign over it. A harness
# binary that is absent is reported and skipped, because agents/harness.md
# permits Track U proceeding with fewer working harnesses. Exit 2 is reserved
# for a crash root that does not exist.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

: "${ARTIFACT_ROOT:=/artifacts}"
: "${CRASH_ROOT:=${ARTIFACT_ROOT}/u-crashes}"
# Where <harness>/build/<harness> is looked for. Defaults to this script's own
# directory, which is where run_all.sh calls it from. Overridable because the
# crash root can be carried to a triage box on its own, and the binaries that
# produced it then live somewhere else on that box.
: "${HARNESS_ROOT:=${here}}"
: "${REPLAY_TIMEOUT:=60}"
: "${REPLAY_MAX_INPUTS:=200}"
: "${REPLAY_FORCE:=0}"

REPORT_SUFFIX=".sanlog"

case "${REPLAY_TIMEOUT}" in
    ''|*[!0-9]*) echo "replay error: REPLAY_TIMEOUT must be a whole number of" \
                      "seconds, and was ${REPLAY_TIMEOUT}" >&2; exit 2;;
esac
case "${REPLAY_MAX_INPUTS}" in
    ''|*[!0-9]*) echo "replay error: REPLAY_MAX_INPUTS must be a whole" \
                      "number, and was ${REPLAY_MAX_INPUTS}" >&2; exit 2;;
esac

if [ ! -d "${CRASH_ROOT}" ]; then
    echo "replay error: no crash root at ${CRASH_ROOT}. run_all.sh creates it" \
         "and copies each harness's inputs into it." >&2
    exit 2
fi

# The harnesses to replay are read off the crash root rather than from a list
# held here: a directory under it is named for the harness that produced it,
# so the binary is derivable and a target this file has never heard of is
# still replayed. build_all.sh and run_all.sh each carry their own copy of the
# target list and a third copy would be a third thing to keep in step.
replayed=0
crashed=0
clean=0
skipped=0
missing_binaries=""

for hdir in "${CRASH_ROOT}"/*/; do
    [ -d "${hdir}" ] || continue
    t="$(basename "${hdir}")"
    bin="${HARNESS_ROOT}/${t}/build/${t}"

    if [ ! -x "${bin}" ]; then
        n=$(find "${hdir}" -maxdepth 3 -type f ! -name "README*" \
                 ! -name "*${REPORT_SUFFIX}" 2>/dev/null | wc -l)
        echo "skipping ${t}: ${bin} is not an executable harness, so its" \
             "${n} input(s) cannot be replayed and will not register. Build" \
             "it with build_all.sh on this machine, or replay them where the" \
             "binary lives and copy the ${REPORT_SUFFIX} files back."
        missing_binaries="${missing_binaries} ${t}"
        skipped=$((skipped + n))
        continue
    fi

    # Sanitizer options were written next to the binary by its build.sh. Each
    # harness states its own leak policy there; see TARGETS.md for why.
    # abort_on_error=1 is set there, so a report ends the process — which is
    # what makes one input one report.
    # shellcheck disable=SC1091
    [ -f "${HARNESS_ROOT}/${t}/build/env.sh" ] && . "${HARNESS_ROOT}/${t}/build/env.sh"

    count=0
    capped=0
    # -maxdepth 3 below the harness directory reaches the layouts a wholesale
    # copy of the fuzzer output tree produces (<harness>/default/crashes/ under
    # AFL++, <harness>/crashes/ under libFuzzer) and matches the bound
    # crash_parse.track_u_inputs walks. Read through a process substitution
    # rather than a pipe, so the counters below survive the loop.
    while IFS= read -r -d '' input; do
        case "$(basename "${input}")" in
            README|README.txt) continue;;
            *"${REPORT_SUFFIX}") continue;;
        esac
        report="${input}${REPORT_SUFFIX}"
        if [ -s "${report}" ] && [ "${REPLAY_FORCE}" != "1" ]; then
            continue
        fi
        if [ "${count}" -ge "${REPLAY_MAX_INPUTS}" ]; then
            capped=1
            break
        fi
        count=$((count + 1))
        replayed=$((replayed + 1))

        # Write through a temp file in the same directory and rename, so an
        # interrupted replay never leaves a half report that crash_parse.py
        # would read as the whole of what the sanitizer said. The harness's
        # stderr is merged into the report because that is where a sanitizer
        # prints; anything the replay machinery itself has to say stays on
        # this script's stderr.
        tmp="${report}.part"
        {
            echo "# replay of ${input}"
            echo "# harness ${bin}"
            timeout --signal=KILL "${REPLAY_TIMEOUT}" "${bin}" "${input}" 2>&1
            rc=$?
            echo "# exit ${rc}"
            # GNU timeout reports 124 when it fires and 137 when the process
            # died of the KILL it sent. Either way the input hung.
            if [ "${rc}" -eq 124 ] || [ "${rc}" -eq 137 ]; then
                echo "# killed at REPLAY_TIMEOUT=${REPLAY_TIMEOUT}s"
            fi
        } > "${tmp}"
        if [ -f "${tmp}" ]; then
            mv -f "${tmp}" "${report}"
        fi

        if grep -qE "ERROR: (Address|Memory|Leak|Thread|UndefinedBehavior)?Sanitizer|ERROR: libFuzzer:|^SUMMARY: |runtime error:|SEGV on unknown address" \
                "${report}"; then
            crashed=$((crashed + 1))
        else
            clean=$((clean + 1))
        fi
    done < <(find "${hdir}" -maxdepth 3 -type f -print0 | sort -z)

    if [ "${capped}" -eq 1 ]; then
        echo "${t}: stopped at REPLAY_MAX_INPUTS=${REPLAY_MAX_INPUTS}. Its" \
             "remaining inputs keep no report and will not register. Raise" \
             "the cap to take them all."
    fi
done

# An input sitting in the crash root itself names no harness, so nothing here
# can decide which binary to run it under. crash_parse.py reads it and will
# warn about it once per scan; say so here, where the operator who put it
# there is looking.
loose=$(find "${CRASH_ROOT}" -maxdepth 1 -type f ! -name "README*" \
             ! -name "*${REPORT_SUFFIX}" 2>/dev/null | wc -l)
if [ "${loose}" -gt 0 ]; then
    echo "${loose} input(s) sit in ${CRASH_ROOT} itself, naming no harness," \
         "so no binary can be chosen for them. Move each one into the" \
         "<harness-name>/ directory of the harness that found it."
fi

echo "replayed ${replayed} input(s): ${crashed} carry a sanitizer report," \
     "${clean} did not crash this build, ${skipped} could not be replayed"
if [ -n "${missing_binaries}" ]; then
    echo "no harness binary for:${missing_binaries}"
fi
if [ "${clean}" -gt 0 ]; then
    echo "an input that does not crash on replay is not registered. Either" \
         "the harness has been rebuilt since the run that saved it, or the" \
         "crash depends on state the replay does not reproduce; TARGETS.md" \
         "carries the per-target replay command to check by hand."
fi
exit 0
