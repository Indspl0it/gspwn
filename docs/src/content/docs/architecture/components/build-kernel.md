---
title: build_kernel.sh
description: The instrumented kernel build, and the four checks that make its gate meaningful.
---

Builds and installs an instrumented kernel and the NVIDIA open kernel modules.
Bash, `set -euo pipefail`, root required for the install steps.

The degradation ladder has three rungs. Only the NVIDIA module CFLAGS differ
between them: rung 1 builds the modules with KASAN and KCOV, rung 2 with KCOV
only, rung 3 uninstrumented.

## Responsibility

The script owns the kernel configuration, the module build, the boot default and
the build manifest. It is the sole writer of `artifacts/builds/manifest.json`.

| Invariant | Enforced by |
|---|---|
| The kernel can find its own root filesystem | The configuration is based on `/boot/config-$(uname -r)`, and the fallback to `defconfig` is loud |
| Instrumentation is present in the built kernel | `.config` is grepped for every instrumentation symbol after `olddefconfig`, and a missing one exits 1 |
| Stacks are comparable across boots | `CONFIG_RANDOMIZE_BASE` is disabled, which is what makes the dedup hashes stable |
| Out-of-tree modules can load | `CONFIG_MODULE_SIG_FORCE` and `CONFIG_SECURITY_LOCKDOWN_LSM_EARLY` are disabled and the trusted-key strings cleared |
| The machine reboots into the kernel just built | The GRUB entry is found by matching the kernel release, and `grub-editenv list` confirms the saved entry changed |
| Earlier build facts survive | The manifest is extended in place |

## Interface

| Variable | Required | Meaning |
|---|---|---|
| `LINUX_SRC` | Yes | Kernel source directory |
| `NVIDIA_SRC` | Yes | `open-gpu-kernel-modules` directory |
| `RUNG` | Yes | `1`, `2` or `3` |
| `JOBS` | No | Parallel make jobs, default `nproc` |
| `BASE_CONFIG` | No | Base configuration, default `/boot/config-$(uname -r)` |
| `SKIP_KERNEL` | No | `1` reuses the kernel already built and installed |

Instrumentation enabled: `CONFIG_KCOV`, `CONFIG_KCOV_INSTRUMENT_ALL`,
`CONFIG_KASAN`, `CONFIG_KASAN_GENERIC`, `CONFIG_UBSAN`, `CONFIG_DEBUG_KERNEL`,
`CONFIG_DEBUG_INFO`, `CONFIG_KALLSYMS_ALL`, plus pstore and crash-dump support.

Three logs are written under `artifacts/logs/`, one per stage, so a
configuration failure and a build failure are not interleaved.

## Callers

| Direction | Modules |
|---|---|
| Invokes this script | The `build` sub-agent, through `exec.py` |
| This script calls | `make`, `scripts/config`, `sudo`, `update-grub`, `grub-editenv`, `mokutil`, `depmod` |

## Failure modes

| Condition | Behaviour | Exit code |
|---|---|---|
| `LINUX_SRC`, `NVIDIA_SRC` or `RUNG` unset | Parameter expansion error naming the variable | 1 |
| `RUNG` outside 1 to 3 | Message naming the valid values | 2 |
| `SKIP_KERNEL=1` with no `.config` in the source tree | Message instructing that rung 1 runs first | 2 |
| Base configuration absent | Falls back to `defconfig` with a loud warning naming the consequence | |
| An instrumentation symbol missing from `.config` after `olddefconfig` | Names every missing symbol | 1 |
| `mokutil` absent | Warning that Secure Boot state is unknown, with the command to install it | |
| Secure Boot enabled | Refused, since an unsigned out-of-tree module will not load | 1 |
| No GRUB menu entry matching the kernel release | Message naming the release and the file searched | 1 |
| `grub-set-default` does not stick | Message naming the expected `saved_entry` | 1 |

## Concurrency and durability

The script is sequential and takes no lock; one build runs at a time on the
machine under test. `SKIP_KERNEL=1` makes rungs 2 and 3 idempotent with respect
to the kernel: they reuse the installed image and rebuild only the NVIDIA
modules, after checking that a `.config` exists to reuse. The manifest is
appended to, so a rung that runs after `provision` keeps the
GSP firmware version that phase recorded. The boot default is verified after it
is set, so an unattended reboot does not depend on an unchecked write.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never start from a defconfig silently | A generic x86 defconfig has no NVMe or ENA driver, and on a cloud instance the resulting kernel cannot find its root filesystem. The failure appears only after a full build and a reboot |
| Never trust that a configuration option took | `olddefconfig` silently drops anything the tree does not offer, and `CONFIG_DEBUG_INFO` stopped being user-selectable in 5.18. Any of the three `DEBUG_INFO` variants satisfies the check |
| Never skip the Secure Boot check quietly | An unsigned out-of-tree module refuses to load, and the build phase then fails its gate with `nvidia-smi` errors that do not mention signing |
| Never guess a GRUB menu entry title | A guessed title such as `Advanced options>Linux $KVER` does not match what Debian generates, and an unattended build then reboots into the old kernel and fails its own gate |
| Never rebuild an identical kernel per rung | Only the NVIDIA module CFLAGS differ between rungs |
| Never leave the modules unsignable and unloadable | Distribution configurations sign and lock down modules |
| Never randomise the kernel base | Stable stacks across boots are what make the dedup hashes comparable |

## Design notes

`KBUILD_EXTRA_CFLAGS` carries the instrumentation flags because NVIDIA's
`conftest.sh` strips unknown CFLAGS from the environment. When rung 1 fails for
that reason, the `build` sub-agent patches `conftest.sh` minimally, logs the
patch, and retries once per rung.

Submenus are disabled so every kernel is a top-level entry with a stable,
greppable id, and `GRUB_DEFAULT` is set to `saved` so `grub-set-default` is what
selects the kernel.

The script is validated in CI by `bash -n`. Stubbing `make`, `scripts/config`,
`sudo`, `update-grub`, `grub-editenv`, `mokutil` and `depmod` would test the
stubs; a real provision run validates it.

## See also

- [build_kernel.sh reference](/gspwn/reference/cli/build-kernel/)
- [Scope and oracle](/gspwn/architecture/scope-and-oracle/)
