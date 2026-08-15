---
title: build_kernel.sh
description: The environment contract, the degradation ladder, and every check the build performs.
---

Builds and installs an instrumented kernel and the NVIDIA open kernel modules.

## Synopsis

```
sudo LINUX_SRC=... NVIDIA_SRC=... RUNG=1 bash tools/build_kernel.sh
```

No subcommands and no flags. Requires root: it installs a kernel and modules
and edits GRUB.

## Environment contract

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `LINUX_SRC` | Yes | None | The kernel source directory |
| `NVIDIA_SRC` | Yes | None | The `open-gpu-kernel-modules` directory |
| `RUNG` | Yes | None | `1`, `2` or `3` |
| `JOBS` | No | `$(nproc)` | Parallel make jobs |
| `BASE_CONFIG` | No | `/boot/config-$(uname -r)` | The kernel configuration to start from |
| `SKIP_KERNEL` | No | `0` | `1` reuses the kernel already built and installed |

| Condition | Result |
|---|---|
| `RUNG` is outside 1 to 3 | Exit 2 |
| `SKIP_KERNEL=1` and the source tree has no `.config` | Exit 2 |

## The degradation ladder

| Rung | Kernel | NVIDIA module CFLAGS |
|---|---|---|
| 1 | KASAN and KCOV | `-fsanitize=kernel-address -fsanitize-coverage=trace-pc,trace-cmp` |
| 2 | KASAN and KCOV | `-fsanitize-coverage=trace-pc,trace-cmp` |
| 3 | KASAN and KCOV | None |

Only the module flags differ between rungs. The kernel image is identical.
Pass `SKIP_KERNEL=1` for rungs 2 and 3, or each rung spends hours of billed
machine time producing the same image.

NVIDIA's `conftest.sh` strips unknown CFLAGS from the environment, so the flags
are passed as `KBUILD_EXTRA_CFLAGS`. When rung 1 fails for that reason, the
`build` sub-agent patches `kernel-open/conftest.sh` minimally, logs the patch,
and retries once per rung.

## The base configuration

The build starts from the configuration the machine boots with. A generic x86
defconfig has no NVMe or ENA driver, so on a cloud instance the resulting
kernel cannot find its own root filesystem, and the failure arrives after a
full build and a reboot.

```
WARNING: /boot/config-6.1.0-21-amd64 not found, falling back to 'make defconfig'.
         A defconfig kernel usually lacks the storage and network drivers this
         machine boots with and will not come back up.
         Set BASE_CONFIG to a config known good for this hardware.
```

## Configuration options set

| Group | Options |
|---|---|
| Coverage | `CONFIG_KCOV`, `CONFIG_KCOV_INSTRUMENT_ALL` |
| Sanitizers | `CONFIG_KASAN`, `CONFIG_KASAN_GENERIC`, `CONFIG_UBSAN` |
| Symbolization | `CONFIG_DEBUG_KERNEL`, `CONFIG_DEBUG_INFO`, `CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT`, `CONFIG_KALLSYMS_ALL` |
| Crash capture | `CONFIG_PSTORE`, `CONFIG_PSTORE_RAM`, `CONFIG_PSTORE_CONSOLE`, `CONFIG_KEXEC_CORE`, `CONFIG_CRASH_DUMP` |
| Stable stacks | `CONFIG_RANDOMIZE_BASE` disabled, so dedup hashes are comparable |
| Module loading | `CONFIG_MODULE_SIG_FORCE` and `CONFIG_SECURITY_LOCKDOWN_LSM_EARLY` disabled, trusted-key strings cleared |

Distribution configurations sign and lock down modules, and an out-of-tree
NVIDIA build cannot load under either.

## The configuration check

`make olddefconfig` silently drops anything the tree does not offer, and
`CONFIG_DEBUG_INFO` stopped being user-selectable in 5.18. The build verifies
what actually took:

```
== config check ==
instrumentation present: KCOV, KASAN, kallsyms, debug info
```

```
ERROR: these did not survive olddefconfig: CONFIG_KCOV_INSTRUMENT_ALL
       Fuzzing without them measures and symbolizes nothing.
```

Exit 1. `olddefconfig` drops these settings without a message, and the loss
otherwise surfaces only when symbolization fails months later.

## Secure Boot

```
== secure boot ==
Secure Boot: disabled
```

```
ERROR: Secure Boot is enabled. The out-of-tree NVIDIA modules are
       unsigned and will not load, so the build gate cannot pass.
       Disable it in firmware, or enrol a MOK and sign each
       nvidia*.ko with sbsign/kmodsign, then re-run.
```

A missing `mokutil` is reported as a warning. An unsigned out-of-tree module on
a Secure Boot machine refuses to load, and the build phase then fails its gate
with `nvidia-smi` errors that say nothing about signing.

## The GRUB default

The script disables GRUB submenus so every kernel is a top-level entry with a
stable, greppable id, sets `GRUB_DEFAULT=saved`, runs `update-grub`, finds the
non-recovery menu entry id for the kernel it just built, sets it as the saved
default, and verifies the setting stuck.

```
next boot: gnulinux-6.9.0-gspwn-advanced-2a4f...
```

```
ERROR: no GRUB menu entry for 6.9.0-gspwn in /boot/grub/grub.cfg.
       The kernel installed but nothing would boot it, so the next
       reboot comes back on the old one and the build gate fails
       for a reason that looks like the build.
```

Exit 1. Both a missing entry and a `grub-set-default` that did not stick are
errors, because an unattended build would otherwise reboot into the old kernel
and fail its own gate.

## The manifest

The build appends to `artifacts/builds/manifest.json`:

| Field | Source |
|---|---|
| `instrumentation_rung` | `RUNG` |
| `kernel_release` | `make -sC $LINUX_SRC kernelrelease` |
| `gcc` | `gcc --version`, first line |
| `linux_commit` | `git rev-parse HEAD` in `LINUX_SRC` |
| `nvidia_commit` | `git rev-parse HEAD` in `NVIDIA_SRC` |

The `provision` phase adds the GSP firmware version to the same file, and the
`report` phase reads affected versions from it.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Complete. Reboot into the reported kernel |
| 1 | A gate check failed: instrumentation, Secure Boot, or the GRUB entry |
| 2 | Bad input: an invalid `RUNG`, or `SKIP_KERNEL=1` with no existing `.config` |

## Files

| Path | Contents |
|---|---|
| `artifacts/builds/manifest.json` | Rung, kernel release, compiler and source commits |
| `artifacts/logs/build-kernel-config.log` | Configuration generation |
| `artifacts/logs/build-kernel.log` | The kernel build, install and `update-grub` |
| `artifacts/logs/build-nvidia.log` | The module build and install |

## See also

- [Requirements](/gspwn/getting-started/requirements/)
- [Your first campaign](/gspwn/getting-started/first-campaign/)
</content>
</invoke>
