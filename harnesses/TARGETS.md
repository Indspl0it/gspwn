# Track U harness targets

Threat model for every entry point below: the attacker supplies the container
image and its OCI configuration. `libnvidia-container` runs as root during
container init, before the container is confined.

Entry points were ranked by mining the fix history of both NVIDIA container
repositories with `tools/patch_mine.py`, then filtering by whether image-supplied
bytes reach the function and whether the function can run without root, a GPU or
a live container. The mined record is
`docs/src/content/docs/knowledgebase/container-stack-fixes.mdx` and the
operational read is `tmp/surface/FINDINGS-patches-u.md`.

## Build status

**No harness in this tree has been compiled.** They were written on a machine
with no clang, no Go toolchain and no AFL++ image, from a reading of the
libnvidia-container and nvidia-container-toolkit sources at the commits checked
out under `artifacts/src/`. `build_all.sh` is the first thing the harness phase
runs, and its first run is also the first compile of every file here. A build
failure is expected work.

| Item | Value |
| --- | --- |
| Source read | `artifacts/src/libnvidia-container` at `08cb279`, `artifacts/src/nvidia-container-toolkit` at `1780ac6` |
| Build entry point | `harnesses/build_all.sh` |
| Campaign entry point | `harnesses/run_all.sh` |
| Seed generator | `harnesses/seedgen.py`, re-runnable |
| Compiled and coverage-checked | None. Gate evidence is absent until `build_all.sh` and the 60-second smoke run in `agents/harness.md` have both been done |

## Ranked entry points

Rank orders by expected yield: how directly image bytes reach the function,
how much parsing it does, and what the fix history says about the file it lives
in. The fix-commit counts come from `patch_mine.py --since 2019-01-01`.

| Rank | Entry point | File | Fix commits on the file | Reachability from a container image | Harness |
| --- | --- | --- | --- | --- | --- |
| 1 | `ldcache_open`, `ldcache_resolve` | `src/ldcache.c` | 0 | Conditional. `nvc.c:339` takes the cache path from `--ldcache` and defaults to the host `/etc/ld.so.cache`, which the attacker does not write. See the caveat below | `fuzz_ldcache` |
| 2 | `do_path_resolve`, through `path_resolve` and `path_resolve_full` | `src/utils.c` | 2 | Direct. Every path inside the container rootfs passes through it, and the rootfs is the attacker's filesystem | `fuzz_path_resolve` |
| 3 | `dsl_evaluate`, `dsl_compare_version`, `dsl_compare_string` | `src/cli/dsl.c` | 0 | Direct. Any `NVIDIA_REQUIRE_*` image environment variable becomes one `--require=EXPR` argument. A CUDA base image sets at least `NVIDIA_REQUIRE_CUDA` | `fuzz_dsl_evaluate` |
| 4 | `options_parse` | `src/options.c` | 1 on `src/options.h` | Direct. `NVIDIA_DRIVER_CAPABILITIES` becomes the container option string | `fuzz_options_parse` |
| 5 | `parse_imex_info`, `str_count_tokens` | `src/cli/common.c`, `src/utils.c` | 0 | Direct. `NVIDIA_IMEX_CHANNELS` drives host-side `mknod`. The architecture threat model names this surface | `fuzz_imex_channels` |
| 6 | `path_new`, `path_append`, `path_join` | `src/utils.c` | 2 | Direct. Every constructed path, including the SONAMEs discovered inside the image | `fuzz_path_join` |
| 7 | `GetCUDACompatElfHeaderFromReader` | toolkit `cmd/nvidia-cdi-hook/cudacompat/cuda-elf-header.go` | 6 | Direct. The `libcuda.so` in the image's CUDA compat directory. Already produced one out-of-bounds panic, fixed in `232dda7` | `go_cudacompat_elf` |

### Entry points inside the model with no harness

These rank high on reachability and on fix history and are excluded for the
reason given, so a later phase does not rediscover them and assume they were
missed.

| Entry point | File | Fix commits | Exclusion reason |
| --- | --- | --- | --- |
| `nvc_ldcache_update` | `src/nvc_ldcache.c` | 10 | The most-fixed function in the library. It clones with `CLONE_NEWPID` and `CLONE_NEWNS`, remounts `/proc`, changes root into the container, drops capabilities, installs a seccomp filter and calls `fexecve`. Running it needs root and a live container. Its input surface is the container's `ldconfig` binary and rootfs, which is a fixture no unit harness can supply |
| `limit_syscalls` | `src/nvc_ldcache.c` | 9 | Builds the seccomp allowlist. Nine of its fixes add one syscall each after a real image failed. It parses nothing |
| `mount_files`, `mount_in_root`, `mount_directory` | `src/nvc_mount.c` | 9 on the file | Carries the `ad1f8c8` fix. Every path it takes is already covered by `fuzz_path_resolve`; the remainder is `mount(2)` against a live rootfs, which needs root and a mount namespace |
| `find_compat_library_paths` | `src/nvc_container.c` | 2, including the `f23e5e5` security-fork merge | `glob(3)` over the image's CUDA compat directory. Harnessable with a rootfs fixture and a populated `struct nvc_container`, which is a larger fixture than the yield justifies while ranks 1 to 6 are unexplored. Recorded as the first candidate to add |
| `elftool_has_dependency`, `elftool_has_abi` | `src/elftool.c` | 0 | Reads the image's compat `libcuda.so` through libelf. A defect found here lands in elfutils and not in this project. Worth a harness only if the campaign has spare capacity |

## Reachability caveat on `fuzz_ldcache`

`ldcache_resolve` reads `h->nlibs` out of the mapped file and iterates that many
entries, deriving `key` and `value` as unchecked byte offsets from the start of
the mapping, then passes both to `str_has_prefix` and `path_resolve` as
NUL-terminated strings. Nothing checks the count or either offset against
`ctx->size`. That is the strongest memory-safety shape in the library.

Under the default configuration the file is the host's `/etc/ld.so.cache`
(`src/common.h:23`), which the Track U attacker does not write. A crash from
this harness therefore proves a parser defect and does not by itself prove Track
U reachability. Two things establish reachability, and the `poc` phase has to do
one of them before a severity is argued:

1. Find a deployment or an operator configuration that points `--ldcache` at a
   file inside the container rootfs.
2. Establish that the container-side `ld.so.cache` written by
   `nvc_ldcache_update` is read back by a later `lookup_paths` call in the same
   process.

Until one holds, a finding here is reported as a library defect with its
reachability marked `profile-check-blocked`.

## Known non-findings

Reproduce every crash against its harness before it goes to triage. These are
already understood and must not be filed as discoveries.

| Behaviour | Location | Reason excluded |
| --- | --- | --- |
| `imex->chans` leaks on every rejected channel list | `src/cli/common.c` `parse_imex_info` | The allocation happens before the parse loop and the failure branch returns without freeing it. The only caller is `nvidia-container-cli`, which exits immediately afterwards, so the leak is bounded by one short process lifetime. `fuzz_imex_channels` runs with `detect_leaks=0` for this reason |
| A directory file descriptor leaks whenever a path component cannot be opened | `src/utils.c` `open_next` | `openat` failure returns before the `xclose(dir)` on the following line, so the caller's previous descriptor is never closed. `do_path_resolve` then calls `xclose(fd)` on the `-1` it was handed. Under a long `fuzz_path_resolve` run this surfaces as `EMFILE` and not as a sanitizer report. It is a real defect of low severity in a short-lived process, and it is recorded here so the campaign does not treat descriptor exhaustion as a harness defect |
| `str_count_tokens` skips index 0 | `src/utils.c` | The skip looks like an off-by-one and is not one. For a leading separator it yields exactly the number of non-empty tokens, and for any other input it yields at least that many, so `parse_imex_info` never writes past its allocation. Checked by hand against every separator arrangement |

## Sanitizer policy

`agents/harness.md` requires the leak decision to be explicit per harness. Each
`build.sh` writes a `build/env.sh` next to its binary carrying the choice, and
`run_all.sh` sources it.

| Harness | `detect_leaks` | Reason |
| --- | --- | --- |
| `fuzz_ldcache` | 1 | The harness frees every path `ldcache_resolve` allocates and closes the mapping |
| `fuzz_path_resolve` | 1 | `do_path_resolve` allocates nothing on the heap |
| `fuzz_dsl_evaluate` | 1 | `dsl_evaluate` frees both allocations on every exit path |
| `fuzz_options_parse` | 1 | `options_parse` allocates nothing |
| `fuzz_imex_channels` | 0 | The known leak above would otherwise fill the queue with one non-finding |
| `fuzz_path_join` | 1 | These functions allocate nothing |

UBSan runs with `halt_on_error=1` everywhere, so the crashing input still
matches the report.

No harness runs as root. Every fixture is a temporary directory owned by the
fuzzing user, and no entry point in the list above needs privilege.

## Replay commands

The `poc` phase passes these to `repro_ctl.py verify --track u --cmd`, with
`{input}` replaced by the crashing file. All paths are relative to the
repository root.

| Harness | Replay command |
| --- | --- |
| `fuzz_ldcache` | `harnesses/fuzz_ldcache/build/fuzz_ldcache {input}` |
| `fuzz_path_resolve` | `harnesses/fuzz_path_resolve/build/fuzz_path_resolve {input}` |
| `fuzz_dsl_evaluate` | `harnesses/fuzz_dsl_evaluate/build/fuzz_dsl_evaluate {input}` |
| `fuzz_options_parse` | `harnesses/fuzz_options_parse/build/fuzz_options_parse {input}` |
| `fuzz_imex_channels` | `harnesses/fuzz_imex_channels/build/fuzz_imex_channels {input}` |
| `fuzz_path_join` | `harnesses/fuzz_path_join/build/fuzz_path_join {input}` |
| `go_cudacompat_elf` | `cd artifacts/src/nvidia-container-toolkit && go test ./cmd/nvidia-cdi-hook/cudacompat/ -run=FuzzGetCUDACompatElfHeaderFromReader/{input}` |

The six C binaries are libFuzzer or AFL++ driver targets and both accept a file
path as a single positional argument, which runs the input once and exits. The
Go target replays through Go's own crash corpus under
`cmd/nvidia-cdi-hook/cudacompat/testdata/fuzz/`, where `{input}` is the corpus
file name and not a path.

## Coverage output

`run_all.sh` writes each harness's fuzzer output to
`/artifacts/runs/$RUN_ID/u/<harness-name>/`, which is where the coverage sampler
looks. The harness names for `track_u.targets` in `config/campaign.yaml` are the
six C target names in the replay table above.

The sampler reads AFL++'s `fuzzer_stats`. Only the `afl` build mode writes that
file, so a `libfuzzer` build gives Track U no edge curve and the round's
coverage verdict is then decided on Track K alone. `build_all.sh` selects `afl`
automatically when `afl-clang-fast` and the AFL++ libFuzzer driver archive are
both present, which they are in the image named in `config/campaign.yaml`. Check
the mode before trusting a plateau decision.

`go test -fuzz` writes no `fuzzer_stats` at all. `go_cudacompat_elf` contributes
no coverage number under any configuration, and Go is memory-safe, so its
findings support a denial-of-service claim and no memory-corruption claim.

## Seeds

`seedgen.py` writes 80 seeds and 6 dictionaries. Every text seed is a value a
real container image supplies: the `NVIDIA_DRIVER_CAPABILITIES` option strings
declared in `src/options.h`, the `NVIDIA_REQUIRE_CUDA` predicates CUDA base
images ship, the `NVIDIA_IMEX_CHANNELS` separator arrangements, and the rootfs
paths `src/nvc_mount.c` and `src/nvc_container.c` construct.

The seven `ld.so.cache` seeds are constructed here, because neither
repository carries a sample. Their layout follows glibc's `dl-cache.h`
as `src/ldcache.c` reads it, including one libc5-prefixed variant that drives
the skip-and-realign branch in `ldcache_open`.

`go_cudacompat_elf` seeds from the four ELF libraries in the toolkit's
`testdata/compat/`, collected by its `build.sh`. One of them,
`libcuda.orin.13.2.1.so.1.1`, is the regression input for the out-of-bounds
panic that commit `232dda7` fixed, so the corpus starts at a known boundary.

## Out of scope

`agents/harness.md` and the architecture threat model both exclude symlink
time-of-check-to-time-of-use races and mount-escape logic bugs on Track U:
fuzzing finds them poorly. Seven of the ten disclosed Container Toolkit CVEs are
in exactly that class. The harnesses above target the parsing and path
construction underneath those races, which is a different and smaller claim.
