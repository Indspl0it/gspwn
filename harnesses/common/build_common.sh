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
: "${HARNESS_MODE:=auto}"
: "${AFL_DRIVER:=/usr/local/lib/afl/libAFLDriver.a}"
: "${SANITIZERS:=address,undefined}"

harness_die() {
    echo "build error: $*" >&2
    exit 1
}

# The checkout sits at a different absolute path in each of the two contexts
# this file builds in, so one relative default satisfies neither:
#
#   host build       HARNESS_ROOT=<repo>/harnesses, checkout at
#                    <repo>/artifacts/src/<name>
#   container run    HARNESS_ROOT=/harnesses on its own bind mount, checkout
#                    at /artifacts/src/<name> on the artifact mount
#
# harness_find_src <name> echoes the first candidate carrying a src/ directory
# and echoes nothing when none does. The caller reports the paths it tried.
HARNESS_SRC_CANDIDATES=(
    "${HARNESS_ROOT}/../artifacts/src"
    "/artifacts/src"
    "${HARNESS_ROOT}/../src"
)

harness_find_src() {
    local name="$1"
    local base
    for base in "${HARNESS_SRC_CANDIDATES[@]}"; do
        if [ -d "${base}/${name}/src" ]; then
            (cd "${base}/${name}" && pwd)
            return 0
        fi
    done
    return 1
}

harness_src_candidates() {
    local name="$1"
    local base
    for base in "${HARNESS_SRC_CANDIDATES[@]}"; do
        echo "  ${base}/${name}"
    done
}

# An explicit SRC is the operator's answer and is never searched over.
: "${SRC:=$(harness_find_src libnvidia-container || true)}"

harness_prepare_src() {
    if [ -z "${SRC}" ]; then
        harness_die "libnvidia-container checkout not found. Tried, in order:
$(harness_src_candidates libnvidia-container)
Each is accepted only when it carries a src/ directory. Clone the library \
under artifacts/src/, or set SRC to a checkout, for example \
SRC=/artifacts/src/libnvidia-container"
    fi
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

# The library's src/utils.h includes <sys/capability.h> and every target links
# -lcap, and the AFL++ image config/campaign.yaml names carries neither the
# header nor the archive. The build is the first thing a fresh instance runs
# and it runs as root inside that image, so the dependency is resolved here:
# this file is sourced by every C target's build.sh, which is the one path
# build_all.sh, a single target's build.sh and the container all take.
: "${HARNESS_CAP_PACKAGE:=libcap-dev}"

harness_have_header() {
    printf '#include <%s>\nint main(void) { return 0; }\n' "$1" \
        | "${HARNESS_CC}" -fsyntax-only -x c - >/dev/null 2>&1
}

harness_prepare_deps() {
    if harness_have_header sys/capability.h; then
        return 0
    fi
    if [ "$(id -u)" != 0 ] || ! command -v apt-get >/dev/null 2>&1; then
        harness_die "<sys/capability.h> is absent and this build cannot \
install it: apt-get needs root and was run as uid $(id -u). Install \
${HARNESS_CAP_PACKAGE} (libcap-devel on rpm distributions) and build again."
    fi
    echo "installing ${HARNESS_CAP_PACKAGE}: <sys/capability.h> is absent \
and every target includes it"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || harness_die "apt-get update failed. The build \
needs ${HARNESS_CAP_PACKAGE} and the container reaches no package index; \
check the instance's egress."
    apt-get install -y -qq "${HARNESS_CAP_PACKAGE}" || harness_die \
        "apt-get install ${HARNESS_CAP_PACKAGE} failed."
    harness_have_header sys/capability.h || harness_die \
        "${HARNESS_CAP_PACKAGE} installed and <sys/capability.h> is still \
absent. The package name differs on this image; set HARNESS_CAP_PACKAGE."
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
    harness_prepare_deps
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
