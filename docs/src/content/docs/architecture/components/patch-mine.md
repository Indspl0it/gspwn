---
title: patch_mine.py
description: "The security fix history of the two NVIDIA container repositories, mined into a ranked list of Track U entry points, and the two signals that carry different weights of evidence."
---

Mines the fix history of `libnvidia-container` and `nvidia-container-toolkit`
and ranks the files and functions those fixes touched. The `harness` phase names
`libnvidia-container` as the Track U primary target and states that defects of
the CVE-2024-0132 class are adjacent to it, without naming a function.

The module runs entirely off a git checkout. It reaches no device and needs no
GPU.

The mined record is
[Container stack fixes](/gspwn/knowledgebase/container-stack-fixes/). The
entry-point list derived from it is `harnesses/TARGETS.md`.

## Responsibility

The module owns the identification of fix commits, the extraction of the files
and functions each one touched, and the frequency ranking over both, and writes
only the JSON file it is given.

| Invariant | Enforced by |
|---|---|
| A shallow checkout cannot report an empty history as a clean one | `validate_repo` refuses a checkout where `git rev-parse --is-shallow-repository` prints true, and names `git fetch --unshallow --tags` |
| A checkout with no tags cannot report every fix as unreleased | `validate_repo` refuses a zero tag count and names `git fetch --tags` |
| A loose date cannot silently move the window | `validate_since` accepts `YYYY-MM-DD` and refuses everything else, because git resolves date words differently across versions |
| A forge-placed marker stays separable from a keyword guess | Each record carries a `signal` field holding `fork merge` or `keyword`, and a `matched` field holding the text that matched |
| A merge reports the fix it brought in | Every commit is diffed against its first parent, so a security-fork merge yields the fork's change and not the whole branch |
| A vendored or packaging change cannot inflate a hot-spot count | `IGNORED_PREFIXES` drops `vendor/`, `third_party/`, `deployments/`, `docs/`, `pkg/`, `mk/`, `tests/`, `tools/` and `.github/` |
| A CVE mapping is never asserted | The tool reports the earliest release tag containing a commit and states nothing about disclosure |
| A function count is never overstated | Names come from git's own hunk-header heuristic, and the module docstring states the count is a floor |
| An interrupted run leaves no half-written JSON | `write_json` writes to a temp file in the output directory, calls `fsync`, and moves it into place with `os.replace` |

## Output

One run mines a checkout over an optional date window and reports three
blocks: every fix candidate with its short hash, date, earliest release tag,
signal and subject; the top 20 files by fix-commit count; and the top 25
functions by fix-commit count. The full record, every commit and both
rankings, is also written as JSON.

Five conditions stop a run before it reports anything, four of them in
`validate_repo` and one in `validate_since`. Each refusal names the command that
repairs it.

| Condition | Message carries |
|---|---|
| `--repo` is not a directory | The instruction to pass a checkout of `libnvidia-container` or `nvidia-container-toolkit` |
| `--repo` is not a git checkout | The `git rev-parse --show-toplevel` error |
| The checkout is shallow | `git -C <repo> fetch --unshallow --tags` |
| The checkout has no tags | `git -C <repo> fetch --tags` |
| `--since` is not `YYYY-MM-DD` | The rejected value, and that git resolves loose date words differently across versions |

A shallow checkout holds one commit and no tags, and the empty result it
produces would read as a clean fix history. A loose date word silently shifts
the window, which changes every count.

## Concurrency and durability

Every git command the module issues is a read. The checkout is never modified,
and a run against a checkout another process is using is safe.

One JSON file is written per invocation, through a temp file in the output
directory and an atomic `os.replace`, so a crash mid-write leaves the previous
file intact and never a truncated one. A failed write removes the temp file and
logs the removal. No lock is taken, and two concurrent invocations writing the
same `--out` path race for it.

The module holds no state between runs and is safe to re-run after new fixes
are published.

## Prohibited behaviour

- Never assert a CVE mapping from a diff alone. A matching release version and
  a plausible diff are different weights of evidence. The tool supplies the
  version, and a human states the mapping with the evidence beside it.
- Never treat a keyword hit as a confirmed security fix. The keyword list
  catches ordinary maintenance. Every `nvidia-container-toolkit` commit
  touching `ldconfig` matches, and that is a large maintenance stream in that
  repository.
- Never match `capabilit` as a security keyword. In this codebase the word
  almost always means `NVIDIA_DRIVER_CAPABILITIES`, the image-supplied
  capability string, and matching it returned the entire MIG capability-mount
  history. POSIX capability handling is caught by `privilege` and `seccomp`.
- Never rank a file by lines changed. A vendored dependency bump changes
  thousands of lines and says nothing about where this project's defects are.
  The ranking counts distinct fix commits.
- Never report the function counts as complete. Git's funcname heuristic misses
  a definition whose opening brace is on its own line, so every count is a
  lower bound.
- Never mine a shallow checkout. A shallow clone holds one commit and no tags,
  and the empty result it produces reads as a clean fix history.

## The ranking method

Two axes produce the Track U entry-point list, and only the first is mechanical.

### Fix density

The tool counts distinct fix commits per file and per function across the
window. A commit becomes a candidate through one of two signals, and they carry
different weights.

- A fork merge is a merge whose subject is exactly `Merge commit from fork`.
  GitHub writes that subject when a private security-advisory fork is merged
  back. The forge places it, so it identifies a coordinated security fix
  without depending on any author's commit message discipline.
- A keyword hit is a subject or body matching one of the patterns in
  `KEYWORDS`, with word boundaries. This signal is a heuristic. It catches
  fixes that never went through an advisory, and it catches unrelated commits.
  Each record carries the text that matched, and a human reviews it.

### Reachability and harnessability

The second axis is applied by hand over the tool's output and recorded in
`harnesses/TARGETS.md`. Two conditions decide it. Bytes supplied by the
container image reach the function, and the function runs without root, without
a GPU and without a live container. A function failing the first falls outside
the Track U attacker definition. A function failing the second needs a fixture,
and the size of that fixture is stated per entry.

The two axes disagree. Over the whole history of the `libnvidia-container`
checkout under `artifacts/src/`, fix density puts `limit_syscalls` first with 12
fix commits and `nvc_ldcache_update` second with 11, both in
`src/nvc_ldcache.c`. Neither can be harnessed: `limit_syscalls` builds the
seccomp allowlist and parses nothing, and `nvc_ldcache_update` clones with
`CLONE_NEWPID` and `CLONE_NEWNS`, remounts `/proc`, changes root into the
container, drops capabilities, installs a seccomp filter and calls `fexecve`.
Nine of the ten highest-ranked functions belong to `src/nvc_ldcache.c`,
`src/nvc_mount.c` or `src/nvc_container.c`. `harnesses/TARGETS.md` carries an
exclusion row for four of them, `nvc_ldcache_update`, `limit_syscalls`,
`mount_files` and `mount_directory`, each naming the fixture a unit harness
cannot supply. The tenth is `file_create`, at `src/utils.c:537`, in the file the
`fuzz_path_resolve` and `fuzz_path_join` harnesses already drive.

The harnesses reach the layer beneath those functions. Commit `ad1f8c8`
fixed `mount_files` by replacing `file_mode` with `file_mode_nofollow` and
routing every mount destination through `path_resolve_full`. The defect was in
the caller. `file_mode_nofollow` is defined at `src/utils.c:688` and
`path_resolve_full` at `src/utils.c:934`, and a unit harness calls both
directly. Any Track U coverage claim states the gap, because a green harness
gate says nothing about the most-fixed function in the target.

## Harnesses

The harness set the ranking produced is committed under `harnesses/`, 106 files:
one directory per target, `common/build_common.sh`, `TARGETS.md`, and the three
scripts `build_all.sh`, `run_all.sh` and `replay_crashes.sh` alongside
`seedgen.py`.

| Harness | Entry point | Source file |
|---|---|---|
| `fuzz_ldcache` | `ldcache_open`, `ldcache_resolve` | `src/ldcache.c` |
| `fuzz_path_resolve` | `do_path_resolve`, through `path_resolve` and `path_resolve_full` | `src/utils.c` |
| `fuzz_dsl_evaluate` | `dsl_evaluate`, `dsl_compare_version`, `dsl_compare_string` | `src/cli/dsl.c` |
| `fuzz_options_parse` | `options_parse` | `src/options.c` |
| `fuzz_imex_channels` | `parse_imex_info`, `str_count_tokens` | `src/cli/common.c`, `src/utils.c` |
| `fuzz_path_join` | `path_new`, `path_append`, `path_join` | `src/utils.c` |
| `go_cudacompat_elf` | `GetCUDACompatElfHeaderFromReader` | toolkit `cmd/nvidia-cdi-hook/cudacompat/cuda-elf-header.go` |

The first six are the C targets listed in `track_u.targets` in
`config/campaign.yaml`. `go_cudacompat_elf` is absent from that list because
`go test -fuzz` writes no AFL++ `fuzzer_stats` file, so it produces no coverage
output for the sampler to read. Go is memory-safe, and a finding against the
toolkit supports a denial-of-service claim and no memory-corruption claim.

Each target directory holds a `build.sh`, the entry-point source, and a `seeds/`
directory; the six C targets each add a `.dict`. The seven entry points are
hand-written C and Go that no phase regenerates, authored offline from the
container sources at the commits checked out under `artifacts/src/`. Campaign
output goes to `artifacts/runs/` and stays ignored.

| Target | Files | Entry-point source |
|---|---|---|
| `fuzz_ldcache` | 10 | `fuzz_ldcache.c` |
| `fuzz_path_resolve` | 22 | `fuzz_path_resolve.c` |
| `fuzz_dsl_evaluate` | 13 | `fuzz_dsl_evaluate.c` |
| `fuzz_options_parse` | 14 | `fuzz_options_parse.c` |
| `fuzz_imex_channels` | 13 | `fuzz_imex_channels.c` |
| `fuzz_path_join` | 26 | `fuzz_path_join.c` |
| `go_cudacompat_elf` | 2 | `fuzz_cuda_elf_header_test.go` |

## Build status

No harness in the tree has been compiled. They were written on a machine with no
clang, no Go toolchain and no AFL++ image, from a reading of the
`libnvidia-container` and `nvidia-container-toolkit` sources at the commits
checked out under `artifacts/src/`. `harnesses/build_all.sh` is the
first thing the `harness` phase runs, and a build failure there is expected work
and not a defect. The script exit status is the count of targets that failed to
build, and `agents/harness.md` permits Track U proceeding with fewer working
harnesses as long as the shortfall is stated.

`harnesses/TARGETS.md` carries the same statement, the per-harness
leak policy, the replay command each target takes, and the reachability caveat
on `fuzz_ldcache`.

## Design notes

Release mapping uses `git tag --contains`, and the earliest release tag
containing a commit is the first version that shipped the fix. An NVIDIA
bulletin's Updated Version column can be checked against it directly. That
comparison carried seven of the ten disclosed Container Toolkit CVEs to a fix
commit. The remaining three fall in one release whose commit range holds no fork
merge, and they are recorded as not located.

The two repositories are joined by the git submodule
`third_party/libnvidia-container`, which the Go repository pins by commit. A
toolkit release therefore names exactly one library commit, and a bulletin
naming a toolkit version identifies a range in both histories at once.

The keyword list is set to over-report. A candidate a human discards costs one
line of review, and a fix commit the list misses never reaches the ranking.
Matching is on word boundaries, because substring matching made every commit
whose body contained `valid` inside `valid targets` a candidate. Over the whole
history of `libnvidia-container` the tool returns 46 candidates, and the 2017 build-out
supplies most of the difference. With `--since 2019-01-01` it returns 35.

Function names come from the trailing context of a zero-context diff hunk
header. Git derives that context with a language heuristic that finds C and Go
definitions well. A Debian changelog stanza header also parses as a call, which
is why `pkg/` is in the ignored prefixes.

## See also

- [Container stack fixes](/gspwn/knowledgebase/container-stack-fixes/)
- [Prior vulnerabilities](/gspwn/knowledgebase/prior-vulnerabilities/)
- [Threat model](/gspwn/architecture/threat-model/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
- [gitmine.py](/gspwn/architecture/components/gitmine/)
