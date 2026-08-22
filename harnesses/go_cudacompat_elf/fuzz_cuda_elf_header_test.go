/*
Track U secondary target: GetCUDACompatElfHeaderFromReader in
cmd/nvidia-cdi-hook/cudacompat/cuda-elf-header.go of nvidia-container-toolkit.

Threat model: the attacker supplies the container image and its OCI
configuration. The hook runs as root during container init, before isolation is
enforced.

Go is memory-safe. A finding here supports a panic and denial-of-service claim
and no memory-corruption claim. agents/harness.md forbids the second.

Reachability. The cudacompat CDI hook inspects the libcuda.so shipped in the
container's CUDA forward-compatibility directory and reads its
.note.cuda.fwd_compatibility ELF note to decide whether the container's compat
libraries should take precedence. The library is a file inside the image, so
every byte the note parser sees is attacker-supplied.

The fix history says this parser has already produced one out-of-bounds panic.
Commit 232dda7 of 2026-05-07, "fix(cudacompat): Fix handling of CUDA compat on
Orin", rewrote trim() to clamp both slice bounds after an Orin library's note
padding drove a slice expression past the end of the section data. The
regression input is testdata/compat/libcuda.orin.13.2.1.so.1.1 and is one of
this target's seeds.

Installation. This file is copied into the cudacompat package by build.sh,
because a Go fuzz target has to live in the package under test. build.sh
removes it again on request; see that script.
*/
package cudacompat

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// seedDir is the directory this file's harness reads its seed libraries from.
// build.sh sets NVIDIA_FUZZ_SEEDS to the harness's own seeds/ directory. When
// it is unset the target still runs, with the package's own testdata as the
// only seed source.
const seedEnv = "NVIDIA_FUZZ_SEEDS"

func addSeeds(f *testing.F) {
	dir := os.Getenv(seedEnv)
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		f.Fatalf("cannot read seed directory %q: %v", dir, err)
	}
	added := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			f.Fatalf("cannot read seed %q: %v", entry.Name(), err)
		}
		f.Add(data)
		added++
	}
	if added == 0 {
		f.Fatalf("seed directory %q holds no files; an empty corpus spends the "+
			"first hours of the campaign rediscovering the ELF magic", dir)
	}
}

// FuzzGetCUDACompatElfHeaderFromReader drives the compat note parser over
// arbitrary bytes. The parser is expected to return an error on malformed
// input. A panic is the finding.
func FuzzGetCUDACompatElfHeaderFromReader(f *testing.F) {
	addSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		// The parser takes an io.ReaderAt, so no temporary file is needed and
		// the target leaves nothing on disk.
		header, err := GetCUDACompatElfHeaderFromReader(bytes.NewReader(data))
		if err != nil {
			return
		}
		if header == nil {
			return
		}
		// Exercise the fields the hook reads afterwards, so a defect in the
		// parsed values reaches the code that consumes them.
		_ = header.Format
		_ = header.CUDAVersion
		for _, v := range header.Driver {
			_ = v
		}
		for _, v := range header.Device {
			_ = v
		}
	})
}
