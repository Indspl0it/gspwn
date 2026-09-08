#!/usr/bin/env bash
# Install the cudacompat ELF-note fuzz target into the toolkit checkout and
# collect its seed corpus.
#
# Go is memory-safe. This target is a panic and denial-of-service target only.
# No sanitizer applies and no memory-corruption claim follows from it.
#
# A Go fuzz target has to live in the package it tests, so this script copies
# the harness file into the checkout. Pass --uninstall to remove it again.
#
# Coverage note: `go test -fuzz` writes no AFL++ fuzzer_stats file, so this
# target contributes no edge curve to the round's coverage verdict. run_all.sh
# records its execution count instead, and TARGETS.md states the limitation.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
HARNESS_ROOT="$(cd "${here}/.." && pwd)"

PKG_REL="cmd/nvidia-cdi-hook/cudacompat"
HARNESS="fuzz_cuda_elf_header_test.go"
TOOLKIT_NAME="nvidia-container-toolkit"

die() { echo "build error: $*" >&2; exit 1; }

# The checkout sits at <repo>/artifacts/src/ on a host build and at
# /artifacts/src/ inside the container, where the harness tree arrives on its
# own bind mount. build_common.sh searches the same three candidates for the C
# targets, and this target carries its own copy because it sources nothing.
TOOLKIT_CANDIDATES=(
    "${HARNESS_ROOT}/../artifacts/src"
    "/artifacts/src"
    "${HARNESS_ROOT}/../src"
)

find_toolkit_src() {
    local base
    for base in "${TOOLKIT_CANDIDATES[@]}"; do
        if [ -d "${base}/${TOOLKIT_NAME}/src" ] \
           || [ -d "${base}/${TOOLKIT_NAME}/${PKG_REL}" ]; then
            (cd "${base}/${TOOLKIT_NAME}" && pwd)
            return 0
        fi
    done
    return 1
}

# An explicit TOOLKIT_SRC is the operator's answer and is never searched over.
: "${TOOLKIT_SRC:=$(find_toolkit_src || true)}"

if [ -z "${TOOLKIT_SRC}" ]; then
    die "nvidia-container-toolkit checkout not found. Tried, in order:
$(for base in "${TOOLKIT_CANDIDATES[@]}"; do echo "  ${base}/${TOOLKIT_NAME}"; done)
Each is accepted only when it carries a src/ directory or the ${PKG_REL} \
package. Clone the toolkit under artifacts/src/, or set TOOLKIT_SRC to a \
checkout."
fi
[ -d "${TOOLKIT_SRC}/${PKG_REL}" ] || die \
    "package ${PKG_REL} not present under ${TOOLKIT_SRC}. The cudacompat hook \
moved between releases; find its directory and set PKG_REL."

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "${TOOLKIT_SRC}/${PKG_REL}/${HARNESS}"
    echo "removed ${TOOLKIT_SRC}/${PKG_REL}/${HARNESS}"
    exit 0
fi

command -v go >/dev/null 2>&1 || die \
    "go is not on PATH. This target needs the Go toolchain, which the AFL++ \
image does not carry; run it in a golang image instead."

mkdir -p "${here}/seeds"
found=0
for f in "${TOOLKIT_SRC}"/testdata/compat/*.so.* "${TOOLKIT_SRC}"/testdata/compat/*/*.so.*; do
    [ -f "${f}" ] || continue
    cp -f "${f}" "${here}/seeds/$(basename "${f}")"
    found=$((found + 1))
done
[ "${found}" -gt 0 ] || die \
    "no seed libraries found under ${TOOLKIT_SRC}/testdata/compat. The parser \
would start from random bytes, which wastes the campaign's first hours."
echo "collected ${found} seed libraries into ${here}/seeds"

cp -f "${here}/${HARNESS}" "${TOOLKIT_SRC}/${PKG_REL}/${HARNESS}"
echo "installed ${TOOLKIT_SRC}/${PKG_REL}/${HARNESS}"

# Compile the package and its tests without running the fuzz loop, so a build
# failure is reported here and not at campaign start.
( cd "${TOOLKIT_SRC}" && go vet "./${PKG_REL}/..." )
echo "go vet passed for ${PKG_REL}"
