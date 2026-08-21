---
title: patch_mine.py
description: "The security fix history of the two NVIDIA container repositories, mined into a ranked list of Track U entry points, and the two signals that carry different weights of evidence."
---

Mines the fix history of `libnvidia-container` and `nvidia-container-toolkit`
and ranks the files and functions those fixes touched. The `harness` phase names
`libnvidia-container` as the Track U primary target and states that the
CVE-2024-0132 class of defects lives adjacent to it, without naming a function.
Choosing entry points by judgement on a live system produces a list derived from
where defects might be. The fix history records where they were.

The module runs entirely off a git checkout. It reaches no device, opens no
socket, needs no GPU, and never writes into the checkout it reads.

The mined record is
[Container stack fixes](/gspwn/knowledgebase/container-stack-fixes/). The
entry-point list derived from it is `artifacts/harnesses/TARGETS.md`.

## Responsibility

The module owns the identification of fix commits, the extraction of the files
and functions each one touched, and the frequency ranking over both. It writes
only the JSON file it is given.

| Invariant | Enforced by |
|---|---|
| A shallow checkout cannot report an empty history as a clean one | `validate_repo` refuses a checkout where `git rev-parse --is-shallow-repository` prints true, and names the fetch command that fixes it |
| A checkout with no tags cannot report every fix as unreleased | `validate_repo` refuses a zero tag count and names `git fetch --tags` |
| A loose date cannot silently move the window | `validate_since` accepts `YYYY-MM-DD` and refuses everything else, because git resolves date words differently across versions |
| A forge-placed marker stays separable from a keyword guess | Each record carries a `signal` field holding `fork merge` or `keyword`, and a `matched` field holding the text that matched |
| A merge reports the fix it brought in | Every commit is diffed against its first parent, so a security-fork merge yields the fork's change and not the whole branch |
| A vendored or packaging change cannot inflate a hot-spot count | `IGNORED_PREFIXES` drops `vendor/`, `third_party/`, `deployments/`, `docs/`, `pkg/`, `mk/`, `tests/`, `tools/` and `.github/` |
| A CVE mapping is never asserted | The tool reports the earliest release tag containing a commit and states nothing about disclosure |
| A function count is never overstated | Names come from git's own hunk-header heuristic, and the module docstring states the count is a floor |
| An interrupted run leaves no half-written JSON | `write_json` writes to a temp file in the output directory, calls `fsync`, and moves it into place with `os.replace` |

## Interface

The module has one mode. Four arguments configure it, and the summary goes to
stdout whether or not `--out` is given.

| Argument | Effect |
|---|---|
| `--repo DIR` | The checkout to mine. Defaults to `artifacts/src/libnvidia-container` |
| `--since DATE` | An ISO date bounding the window. Defaults to the whole history |
| `--out PATH` | Writes the full record as JSON, holding every commit and both rankings |
| `--verbose` | Logs every git invocation at DEBUG |

The stdout summary carries three blocks: one line per fix candidate with its
short hash, date, earliest release tag, signal and subject; the top 20 files by
fix-commit count; and the top 25 functions by fix-commit count.

| Function | Returns |
|---|---|
| `list_commits(repo, since)` | One dict per commit in the window, holding hash, date, author, subject and body |
| `classify(commit)` | The signal, the text that matched, and a bug-class hint, or `None` when the commit is no candidate |
| `changed_functions(repo, sha)` | The files touched, and the enclosing function names per file |
| `first_release_tag(repo, sha)` | The earliest release tag containing the commit, or `None` when it is unreleased |
| `mine(repo, since)` | Every fix candidate with its files, functions and release tag, newest first |
| `hotspots(records)` | Files and functions ranked by the count of distinct fix commits touching each |
| `interesting(path)` | Whether a change to this path says anything about the project's own defects |

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing at run time. The `harness` phase invokes it as a command |
| This module imports | Nothing in `tools/`. It shells out to `git` |

## Failure modes

| Condition | Behaviour | Exit |
|---|---|---|
| `--repo` names no directory | Message naming the flag and the two checkouts it expects | 1 |
| `--repo` names a directory that is no git checkout | Message carrying git's own stderr | 1 |
| The checkout is shallow | Message naming `git fetch --unshallow --tags` for that path | 1 |
| The checkout carries no tags | Message naming `git fetch --tags`, because release mapping needs them | 1 |
| `--since` is not an ISO date | Message stating that git resolves loose date words differently across versions | 1 |
| The `--out` directory does not exist | Message naming the directory | 1 |
| A git invocation fails during mining | `GitError` carrying the command and git's stderr | 2 |
| A `git log` record does not split into five fields | `GitError` naming the field count and the first 200 characters of the record | 2 |
| A commit's diff carries no recognisable function name | The file is still counted, and its function list stays empty | 0 |
| A commit sits in no release tag | The release column prints a dash | 0 |

## Concurrency and durability

Every git command the module issues is a read. The checkout is never modified,
and a run against a checkout another process is using is safe.

One JSON file is written per invocation, through a temp file in the output
directory and an atomic `os.replace`, so a crash mid-write leaves the previous
file intact and never a truncated one. A failed write removes the temp file and
logs the removal. No lock is taken, and two concurrent invocations writing the
same `--out` path race for it.

The module holds no state between runs and is safe to re-run. Re-running after
new fixes land is the intended use, which is why the analysis is a tool and not
a one-off script.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never assert a CVE mapping from a diff alone | A matching release version and a plausible diff are different weights of evidence. The tool supplies the version, and a human states the mapping with the evidence beside it |
| Never treat a keyword hit as a confirmed security fix | The keyword list catches ordinary maintenance. Every `nvidia-container-toolkit` commit touching `ldconfig` matches, and that is a large maintenance stream in that repository |
| Never match `capabilit` as a security keyword | In this codebase the word almost always means `NVIDIA_DRIVER_CAPABILITIES`, the image-supplied capability string. Matching it returned the entire MIG capability-mount history. POSIX capability handling is caught by `privilege` and `seccomp` |
| Never rank a file by lines changed | A vendored dependency bump changes thousands of lines and says nothing about where this project's defects are. The ranking counts distinct fix commits |
| Never report the function counts as complete | Git's funcname heuristic misses a definition whose opening brace sits on its own line, so every count is a lower bound |
| Never mine a shallow checkout | A shallow clone holds one commit and no tags. The empty result it produces reads as a clean fix history |

## The ranking method

Two axes produce the Track U entry-point list, and only the first is mechanical.

**Fix density.** The tool counts distinct fix commits per file and per function
across the window. A commit becomes a candidate through one of two signals, and
they carry different weights.

| Signal | Marker | Weight |
|---|---|---|
| Fork merge | A merge whose subject is exactly `Merge commit from fork` | GitHub writes this subject when a private security-advisory fork is merged back. The forge places it, so it identifies a coordinated security fix without depending on any author's commit message discipline |
| Keyword | A subject or body matching one of the patterns in `KEYWORDS`, with word boundaries | A heuristic. It catches fixes that never went through an advisory, and it catches unrelated commits. Each record carries the text that matched, and a human reviews it |

**Reachability and harnessability.** The second axis is applied by hand over the
tool's output and recorded in `artifacts/harnesses/TARGETS.md`. Two questions
decide it. Do bytes supplied by the container image reach the function, and does
the function run without root, without a GPU and without a live container. A
function failing the first question falls outside the Track U attacker
definition. A function failing the second needs a fixture, and the size of that
fixture is stated per entry.

The two axes disagree, and the disagreement is the result that justifies the
harness set. Fix density puts `nvc_ldcache_update` first with 10 fix commits and
`limit_syscalls` second with 9, both in `src/nvc_ldcache.c`. Neither can be
harnessed: the first clones with `CLONE_NEWPID` and `CLONE_NEWNS`, remounts
`/proc`, changes root into the container, drops capabilities, installs a seccomp
filter and calls `fexecve`, and the second parses nothing. Six of the top ten
functions by fix density need root, a namespace or a live container.

What the harnesses reach is the layer beneath those functions. Commit `ad1f8c8`
fixed `mount_files` by replacing `file_mode` with `file_mode_nofollow` and
routing every mount destination through `path_resolve_full`. The defect lived in
the caller. The mechanism lives in `src/utils.c`, and `src/utils.c` is
harnessable. Any Track U coverage claim states the gap, because a green harness
gate says nothing about the most-fixed function in the target.

## Harnesses

The harness set the ranking produced is committed under `artifacts/harnesses/`,
105 files across seven targets.

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

These 105 files are committed source. They are hand-written C and Go that no
phase regenerates, authored offline from the container sources at a pinned
commit, and a clone that lacked them would lose the work outright. Their seed
corpora and dictionaries are inputs to the campaign and belong beside them.
Campaign output goes to `artifacts/runs/` and stays ignored.

## Build status

No harness in the tree has been compiled. They were written on a machine with no
clang, no Go toolchain and no AFL++ image, from a reading of the
`libnvidia-container` and `nvidia-container-toolkit` sources at the commits
checked out under `artifacts/src/`. `artifacts/harnesses/build_all.sh` is the
first thing the `harness` phase runs, and its first run is also the first
compile of every file in the tree. A build failure there is expected work and
not a defect. The script exit status is the count of targets that failed to
build, and `agents/harness.md` permits Track U proceeding with fewer working
harnesses as long as the shortfall is stated.

`artifacts/harnesses/TARGETS.md` carries the same statement, the per-harness
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
Substring matching was replaced by word-boundary matching after every commit
whose body contained `valid` inside `valid targets` became a candidate. The
window bounds the noise the pattern set leaves. Over the whole history of
`libnvidia-container` the tool returns 46 candidates, and the 2017 build-out
supplies most of the difference. With `--since 2019-01-01` it returns 35.

Function names come from the trailing context of a zero-context diff hunk
header. Git derives that context with a language heuristic that finds C and Go
definitions well. A Debian changelog stanza header also parses as a call, which
is why `pkg/` sits in the ignored prefixes.

## See also

- [Container stack fixes](/gspwn/knowledgebase/container-stack-fixes/)
- [Prior vulnerabilities](/gspwn/knowledgebase/prior-vulnerabilities/)
- [Threat model](/gspwn/architecture/threat-model/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
