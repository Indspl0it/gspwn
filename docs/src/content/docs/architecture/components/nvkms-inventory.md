---
title: nvkms_inventory.py
description: The /dev/nvidia-modeset command space, enumerated from the declaring enum and the dispatch table and reconciled between them.
---

Enumerates the NVKMS command space from the driver source and writes
`surface/nvkms-command-inventory.json`.

One ioctl request number carries every NVKMS call. The sub-command sits in the
`cmd` field of the `NvKmsIoctlParams` envelope, so the command space has to be
enumerated before the `describe` phase can attach a parameter struct per
sub-command.

## Two sources, reconciled

Neither file holds the whole answer.

| Source | Location | Holds |
|---|---|---|
| `enum NvKmsIoctlCommand` | `src/nvidia-modeset/interface/nvkms-api.h` | The declared command space and each ordinal |
| The `dispatch[]` array in `nvKmsIoctl()` | `src/nvidia-modeset/src/nvkms.c` | The populated space, as designated initialisers |

A declared command with no dispatch entry leaves its array slot
zero-initialised, `dispatch[cmd].proc` reads NULL, and `nvKmsIoctl()` rejects
the call. The record carries `dispatched: false` for it. Reading the enum alone
overstates the reachable surface; reading the dispatch table alone loses the
ordinals the enum assigns.

Two macros populate the array. `ENTRY` takes the plain form. `ENTRY_CUSTOM_USER`
adds a prepare and a done callback plus an extra user-state struct, and the
record notes which of the two declared each entry.

## Interface

| Flag | Effect | Default |
|---|---|---|
| `--src` | `open-gpu-kernel-modules` checkout to read | `artifacts/src/open-gpu-kernel-modules` |
| `--out` | JSON inventory to write | `surface/nvkms-command-inventory.json` |
| `--expect-declared` | Declared count to assert | 66 |
| `--expect-dispatched` | Dispatched count to assert | 64 |
| `-v` | Log every entry read | off |

The two expectation flags turn a silent drift in the driver source into a
failure. A driver release that adds a command fails the assertion, and the new
count becomes a deliberate edit with the release named beside it.

## Artefact

`surface/nvkms-command-inventory.json`, schema
`gspwn.nvkms-command-inventory/1`. The summary carries the declared count, the
dispatched count, and the split between the two entry macros. Each record
carries the command name, its ordinal, whether it is dispatched, and the
handler it dispatches to.

The undispatched commands are named with their ordinals, and none is dropped. A
command declared and unreachable is a fact about the driver, and an artefact
omitting it would read as though the enum and the table agreed.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing |
| Reads the artefact | [`refgen.py`](/gspwn/architecture/components/refgen/) renders `reference/surface/modeset-commands.md`; [`syzlang_gen.py`](/gspwn/architecture/components/syzlang-gen/) emits the `modeset` family; [`surface_cov.py`](/gspwn/architecture/components/surface-cov/) counts it in the denominator |
| Invokes it | The `describe` sub-agent |

## Limits

The inventory names the command space. It does not model the parameter struct
behind each command, which `syzlang_gen.py` derives separately.

`ARRAY_LEN(dispatch)` bounds the index space before the lookup, so a declared
ordinal outside that bound is rejected by the driver ahead of the NULL check.
The tool asserts every declared ordinal falls inside the bound.

## See also

- [Modeset commands](/gspwn/reference/surface/modeset-commands/)
- [Attack surface](/gspwn/architecture/attack-surface/)
