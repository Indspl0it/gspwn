---
title: build_kernel.sh
description: The instrumented kernel and NVIDIA module build, its configuration checks, and the manifest it writes.
---

Builds and installs an instrumented kernel and the NVIDIA open kernel modules.
Bash, `set -euo pipefail`. It takes no arguments and reads six environment
variables. The install, `depmod` and GRUB steps call `sudo`.

## Inputs

| Variable | Default | Effect |
|---|---|---|
| `LINUX_SRC` | required | Kernel source tree. The script `cd`s into it and resolves it to an absolute path |
| `NVIDIA_SRC` | required | `open-gpu-kernel-modules` tree, resolved the same way |
| `RUNG` | required | `1`, `2` or `3`, the instrumentation rung |
| `JOBS` | `$(nproc)` | The `-j` argument to both `make` invocations |
| `BASE_CONFIG` | `/boot/config-$(uname -r)` | The kernel configuration the build starts from |
| `SKIP_KERNEL` | `0` | `1` reuses the installed kernel and rebuilds only the NVIDIA modules |

## The rung ladder

The kernel is the same at all three rungs. Only `KBUILD_EXTRA_CFLAGS` for the
NVIDIA module build differs, so walking the ladder with `SKIP_KERNEL=1` rebuilds
the modules alone.

| Rung | Kernel | NVIDIA module `KBUILD_EXTRA_CFLAGS` |
|---|---|---|
| 1 | KASAN and KCOV | `-fsanitize=kernel-address -fsanitize-coverage=trace-pc,trace-cmp` |
| 2 | KASAN and KCOV | `-fsanitize-coverage=trace-pc,trace-cmp` |
| 3 | KASAN and KCOV | empty |

## Stages

The script runs eight stages in order, each announced on stdout with a `==`
banner. Three logs are written under `artifacts/logs/`, so a configuration
failure and a build failure are never interleaved in one file.

| Stage | Work | Log |
|---|---|---|
| kernel config | Copies `BASE_CONFIG` to `.config` and runs `make olddefconfig`, applies `scripts/config`, runs `make olddefconfig` again | `build-kernel-config.log` |
| config check | Reads `.config` back and fails on a missing or a surviving symbol | none |
| kernel build | `make -j$JOBS` | `build-kernel.log` |
| kernel install | `sudo make modules_install` then `sudo make install` | `build-kernel.log` |
| NVIDIA modules | `make -C kernel-open -j$JOBS SYSSRC=$LINUX_SRC`, then `modules_install` and `depmod $KVER` | `build-nvidia.log` |
| secure boot | `mokutil --sb-state` | none |
| grub default | `update-grub`, then `grub-set-default` on the matched entry | `build-kernel.log` |
| manifest | Merges five keys into `artifacts/builds/manifest.json` | none |

`SKIP_KERNEL=1` replaces the first four stages with the config check alone, run
against the `.config` the installed kernel came from.

## Configuration

The build enables fifteen options in four groups, disables four, and clears two
signing key strings.

| Group | Options enabled |
|---|---|
| Coverage | `CONFIG_KCOV`, `CONFIG_KCOV_INSTRUMENT_ALL`, `CONFIG_KCOV_ENABLE_COMPARISONS` |
| Sanitizers | `CONFIG_KASAN`, `CONFIG_KASAN_GENERIC`, `CONFIG_UBSAN` |
| Symbolization | `CONFIG_DEBUG_KERNEL`, `CONFIG_DEBUG_INFO`, `CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT`, `CONFIG_KALLSYMS_ALL` |
| Crash capture | `CONFIG_PSTORE`, `CONFIG_PSTORE_RAM`, `CONFIG_PSTORE_CONSOLE`, `CONFIG_KEXEC_CORE`, `CONFIG_CRASH_DUMP` |

`CONFIG_SYSTEM_TRUSTED_KEYS` and `CONFIG_MODULE_SIG_KEY` are set to the empty
string, so a distribution configuration that names a signing key stops demanding
one.

`CONFIG_KCOV_ENABLE_COMPARISONS` is implied by nothing and carries no
`default y`. Without it `kernel/kcov.c` compiles out every
`__sanitizer_cov_trace_cmp*` definition, and the NVIDIA modules built at rungs 1
and 2 with `-fsanitize-coverage=trace-cmp` reference symbols the kernel does not
export, so `insmod` fails with `Unknown symbol __sanitizer_cov_trace_cmp1`.
syzkaller's comparison-hint mutation reads the same data.

## Configuration check

`make olddefconfig` drops anything the tree does not offer without a word, and
`CONFIG_DEBUG_INFO` stopped being user-selectable in 5.18. The check reads
`.config` back after `olddefconfig` and covers seven of the fifteen enabled
options and all four disabled ones. The other eight enabled options go
unchecked.

| Requirement | Symbols |
|---|---|
| Must be `=y` | `CONFIG_KCOV`, `CONFIG_KCOV_INSTRUMENT_ALL`, `CONFIG_KCOV_ENABLE_COMPARISONS`, `CONFIG_KASAN`, `CONFIG_KASAN_GENERIC`, `CONFIG_KALLSYMS_ALL` |
| One spelling must be `=y` | `CONFIG_DEBUG_INFO=y`, or any `CONFIG_DEBUG_INFO_DWARF*=y` |
| Must not be `=y` | The four symbols in `REQUIRED_DISABLED`, below |

The check runs on both branches. `SKIP_KERNEL=1` runs the identical function
against `$LINUX_SRC/.config` under the context string
`reused kernel, SKIP_KERNEL=1`, which is the branch that would otherwise let a
tree missing `CONFIG_KCOV_ENABLE_COMPARISONS` reach an `insmod` failure hours
into rung 2.

A symbol disabled on purpose can return through `olddefconfig` or a hand-edited
`.config`. `REQUIRED_DISABLED` holds four of them. Each fails differently and
none of the failures names itself.

| Symbol | Cost of it surviving |
|---|---|
| `CONFIG_RANDOMIZE_BASE` | Every address in every report shifts. `stack_hash` strips offsets and module names and keeps function names, so the primary dedup key survives, and the RIP symbol `crash_parse.py` reads and every unsymbolized frame do not. The secondary key degrades in silence |
| `CONFIG_MODULE_SIG_FORCE` | The unsigned out-of-tree NVIDIA module stops loading, and the build gate fails with `nvidia-smi` errors naming neither signing nor lockdown |
| `CONFIG_SECURITY_LOCKDOWN_LSM_EARLY` | The same |
| `CONFIG_DEBUG_INFO_NONE` | Selecting it compiles the debug info out from under `CONFIG_DEBUG_INFO` |

## Boot default

The GRUB steps make the machine come back on the kernel just built.
`GRUB_DISABLE_SUBMENU=y` makes every kernel a top-level entry with a stable,
greppable id, and `GRUB_DEFAULT=saved` makes `grub-set-default` select it. Both
lines are written to `/etc/default/grub`, appended when absent and rewritten by
`sed` when present.

The entry id is read out of `/boot/grub/grub.cfg` by matching
`menuentry_id_option '...'` against the kernel release and discarding recovery
entries, so no title is guessed. After `grub-set-default`, `grub-editenv list`
is grepped for `saved_entry=$ENTRY` and a mismatch stops the script, so an
unattended reboot never rests on an unchecked write.

## Manifest

The final stage runs an inline Python program that merges five keys into
`artifacts/builds/manifest.json`.

| Key | Value |
|---|---|
| `instrumentation_rung` | `RUNG`, as an integer |
| `kernel_release` | `make -sC $LINUX_SRC kernelrelease` |
| `gcc` | The first line of `gcc --version` |
| `linux_commit` | `git -C $LINUX_SRC rev-parse HEAD` |
| `nvidia_commit` | `git -C $NVIDIA_SRC rev-parse HEAD` |

The file is read back and updated, so keys the `provision` phase wrote and this
script does not write survive, among them the syzkaller and container source
commits. `artifacts/builds/` is created if absent, and the write goes through
`mkstemp` and `os.replace`, because this runs at the end of a multi-hour build
and is the only record of what was built.

The `provision` phase records the source commits and the gcc version in the same
file, and the `build` sub-agent writes `instrumentation_rung` to it at step 5 of
`agents/build.md`. The file has three writers.

## Exit codes

| Code | Conditions |
|---|---|
| 0 | Every stage completed |
| 1 | An unset required variable, a missing config file, a missing or surviving configuration symbol, Secure Boot enabled, no GRUB entry for the kernel release, or `grub-set-default` failing to stick |
| 2 | `RUNG` outside `1` to `3`, or `SKIP_KERNEL=1` with no `.config` in the source tree |

## Failure modes

Eleven conditions are handled. A missing base configuration and an absent
`mokutil` warn and continue, and the other nine stop the script.

| Condition | Behaviour |
|---|---|
| `LINUX_SRC`, `NVIDIA_SRC` or `RUNG` unset | Parameter expansion error naming the variable and what to set it to |
| `RUNG` outside 1 to 3 | `RUNG must be 1, 2 or 3` |
| `SKIP_KERNEL=1` with no `.config` in the source tree | Message instructing that rung 1 runs first |
| Base configuration absent | Falls back to `make defconfig` with a warning naming the consequence and `BASE_CONFIG` as the fix |
| No configuration file at the path checked | Message naming the path and the context |
| A required symbol missing from `.config` after `olddefconfig` | Names every missing symbol, and states that fuzzing without them measures and symbolizes nothing |
| A `REQUIRED_DISABLED` symbol still `=y` | Names every surviving symbol and points at `REQUIRED_DISABLED` for what each costs |
| `mokutil` absent | Warning that Secure Boot state is unknown, with the package to install |
| Secure Boot enabled | Refused, with both remedies named: disable it in firmware, or enrol a MOK and sign each `nvidia*.ko` |
| No GRUB menu entry matching the kernel release | Message naming the release and the file searched |
| `grub-set-default` does not stick | Message naming the expected `saved_entry` |

A defconfig fallback is loud because a generic x86 defconfig carries no NVMe or
ENA driver, so on a cloud instance the resulting kernel cannot find its own root
filesystem, and the failure arrives only after a full build and a reboot.

## Concurrency and durability

The script is sequential and takes no lock. One build runs at a time on the
machine under test. `SKIP_KERNEL=1` makes rungs 2 and 3 idempotent with respect
to the kernel: they reuse the installed image and rebuild the NVIDIA modules
alone, after running the full configuration check against the `.config` the
installed kernel came from.

## Callers

- The `build` sub-agent invokes the script through `exec.py`, once per rung,
  stopping at the first rung that passes its gate.
- The script calls `make`, `scripts/config`, `sudo`, `update-grub`,
  `grub-editenv`, `mokutil`, `depmod` and `python3`.

## Design notes

`KBUILD_EXTRA_CFLAGS` carries the instrumentation flags because NVIDIA's
`conftest.sh` strips unknown CFLAGS from the environment. When a rung fails for
that reason, the `build` sub-agent patches `kernel-open/conftest.sh` minimally,
logs the patch into `artifacts/builds/`, and retries once per rung.

CI validates the script with `bash -n tools/build_kernel.sh` in
`.github/workflows/selftest.yml`. Stubbing `make`, `scripts/config`, `sudo`,
`update-grub`, `grub-editenv`, `mokutil` and `depmod` would test the stubs, so a
real provision run is the only validation of the rest.

## See also

- [Scope and oracle](/gspwn/architecture/scope-and-oracle/)
