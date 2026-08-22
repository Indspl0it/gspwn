#!/usr/bin/env bash
# Shared build machinery for the Track U C harnesses.
#
# Threat model (every harness in this tree assumes it): the attacker supplies
# the container image and its OCI configuration. libnvidia-container runs as
# root during container init, before the container is confined. Any byte the
# image or its configuration reaches is attacker-controlled.
#
# Sourced by each <target>/build.sh. Provides:
#   harness_prepare_src   generate src/nvc.h from the template, as the Makefile does
#   harness_build         compile one harness translation unit plus its library
#                         sources into build/<name>
#
# Two build modes:
#   libfuzzer   clang -fsanitize=address,undefined,fuzzer. Produces a libFuzzer
#               binary. Replays one input with: ./build/<name> <file>
#   afl         afl-clang-fast plus AFL++'s libAFLDriver.a. Produces an
#               afl-fuzz target, which is the only mode that writes the
#               fuzzer_stats file the coverage sampler reads.
# HARNESS_MODE selects one. The default, auto, picks afl when afl-clang-fast
# and the driver archive are both present and libfuzzer otherwise.
set -euo pipefail

HARNESS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${SRC:=$(cd "${HARNESS_ROOT}/../src/libnvidia-container" 2>/dev/null && pwd || true)}"
: "${HARNESS_MODE:=auto}"
: "${AFL_DRIVER:=/usr/local/lib/afl/libAFLDriver.a}"
: "${SANITIZERS:=address,undefined}"

harness_die() {
    echo "build error: $*" >&2
    exit 1
}

harness_prepare_src() {
    [ -n "${SRC}" ] || harness_die \
        "libnvidia-container checkout not found. Set SRC to a checkout, for \
example SRC=/artifacts/src/libnvidia-container"
    [ -d "${SRC}/src" ] || harness_die "no src/ directory under SRC=${SRC}"

    # The Makefile generates src/nvc.h from src/nvc.h.template by substituting
    # the version fields. Nothing in these harnesses reads the version, so the
    # substituted values only have to parse.
    if [ ! -f "${SRC}/src/nvc.h" ]; then
        [ -f "${SRC}/src/nvc.h.template" ] || harness_die \
            "neither src/nvc.h nor src/nvc.h.template exists under ${SRC}"
        local ver
        ver="$(cd "${SRC}" && git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0)"
        ver="${ver#v}"
        sed -e "s/{{NVC_MAJOR}}/${ver%%.*}/g" \
            -e "s/{{NVC_MINOR}}/0/g" \
            -e "s/{{NVC_PATCH}}/0/g" \
            -e "s/{{NVC_TAG}}//g" \
            -e "s/{{NVC_VERSION}}/\"${ver}\"/g" \
            "${SRC}/src/nvc.h.template" > "${SRC}/src/nvc.h"
        echo "generated ${SRC}/src/nvc.h from the template"
    fi
}

harness_select_mode() {
    if [ "${HARNESS_MODE}" = "auto" ]; then
        if command -v afl-clang-fast >/dev/null 2>&1 && [ -f "${AFL_DRIVER}" ]; then
            HARNESS_MODE=afl
        else
            HARNESS_MODE=libfuzzer
        fi
    fi
    case "${HARNESS_MODE}" in
        afl)
            HARNESS_CC="${CC:-afl-clang-fast}"
            HARNESS_FUZZ_FLAGS=""
            HARNESS_FUZZ_LIBS="${AFL_DRIVER}"
            [ -f "${AFL_DRIVER}" ] || harness_die \
                "HARNESS_MODE=afl needs the AFL++ driver archive. Not found at \
${AFL_DRIVER}. Set AFL_DRIVER to its path inside the AFL++ image."
            ;;
        libfuzzer)
            HARNESS_CC="${CC:-clang}"
            HARNESS_FUZZ_FLAGS="-fsanitize=fuzzer"
            HARNESS_FUZZ_LIBS=""
            ;;
        *)
            harness_die "HARNESS_MODE must be auto, afl or libfuzzer, and was ${HARNESS_MODE}"
            ;;
    esac
    command -v "${HARNESS_CC}" >/dev/null 2>&1 || harness_die \
        "compiler not on PATH: ${HARNESS_CC}. These harnesses build inside the \
AFL++/clang image named in config/campaign.yaml."
}

# harness_build <name> <harness.c> <library .c files...>
harness_build() {
    local name="$1"; shift
    local harness="$1"; shift
    local dir
    dir="$(cd "$(dirname "${harness}")" && pwd)"

    harness_prepare_src
    harness_select_mode
    mkdir -p "${dir}/build"

    local srcs=()
    local f
    for f in "$@"; do
        [ -f "${SRC}/${f}" ] || harness_die "library source missing: ${SRC}/${f}"
        srcs+=("${SRC}/${f}")
    done

    echo "building ${name} in ${HARNESS_MODE} mode with ${HARNESS_CC}"
    # -Wno-* : the library's own sources are compiled with the project's
    # warning set under gcc. Under clang a few of them are errors by default
    # and none of them is the defect being hunted.
    "${HARNESS_CC}" \
        -g -O1 -std=gnu11 \
        -D_GNU_SOURCE -DNDEBUG=0 \
        -I"${SRC}/src" -I"${SRC}" \
        -fsanitize="${SANITIZERS}" -fno-omit-frame-pointer \
        ${HARNESS_FUZZ_FLAGS} \
        -Wno-unused-parameter -Wno-unused-const-variable -Wno-sign-conversion \
        -Wno-conversion -Wno-unused-function \
        -o "${dir}/build/${name}" \
        "${harness}" "${srcs[@]}" \
        ${HARNESS_FUZZ_LIBS} \
        -lcap
    echo "built ${dir}/build/${name}"
}
