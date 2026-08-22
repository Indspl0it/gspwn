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
: "${TOOLKIT_SRC:=$(cd "${here}/../../src/nvidia-container-toolkit" 2>/dev/null && pwd || true)}"

PKG_REL="cmd/nvidia-cdi-hook/cudacompat"
HARNESS="fuzz_cuda_elf_header_test.go"

die() { echo "build error: $*" >&2; exit 1; }

[ -n "${TOOLKIT_SRC}" ] || die \
    "nvidia-container-toolkit checkout not found. Set TOOLKIT_SRC to one."
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
