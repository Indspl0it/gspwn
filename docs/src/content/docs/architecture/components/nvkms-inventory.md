---
title: nvkms_inventory.py
description: The /dev/nvidia-modeset command space, enumerated from the declaring enum and the dispatch table and reconciled between them.
---

`nvkms_inventory.py` enumerates the NVKMS command space from the driver source
and writes `surface/nvkms-command-inventory.json`.

One ioctl request number carries every NVKMS call. The sub-command travels in
the `cmd` field of the `NvKmsIoctlParams` envelope, so the command space has to
be enumerated before the `describe` phase can attach a parameter struct per
sub-command.

## Invocation

```
python3 tools/nvkms_inventory.py --out surface/nvkms-command-inventory.json
```

| Option | Default | Effect |
|---|---|---|
| `--src` | `artifacts/src/open-gpu-kernel-modules` | The driver checkout both sources are read from |
| `--out` | `surface/nvkms-command-inventory.json` | Where the inventory JSON is written |
| `--expect-declared` | 66 | The declared command count asserted on every run |
| `--expect-dispatched` | 64 | The dispatched command count asserted on every run |
| `-v`, `--verbose` | off | Logs every entry read |

| Exit code | Condition |
|---|---|
| 0 | The inventory reconciled and was written |
| 2 | `--src` is not a directory, or any source condition below, printed to standard error as `error: <message>` |

The run prints the dispatched and declared counts with the driver version, the
plain and custom-user entry counts, the array length, the undispatched count,
and each undispatched command with its ordinal.

## Two sources, reconciled

| Source | Location | Holds |
|---|---|---|
| `enum NvKmsIoctlCommand` | `src/nvidia-modeset/interface/nvkms-api.h` | The declared command space and each ordinal |
| The `dispatch[]` array in `nvKmsIoctl()` | `src/nvidia-modeset/src/nvkms.c` | The populated space, as designated initialisers |

A declared command with no dispatch entry leaves its array slot
zero-initialised, `dispatch[cmd].proc` reads NULL, and `nvKmsIoctl()` rejects
the call. The record carries `dispatched: false` for it. Reading the enum alone
overstates the reachable surface, and reading the dispatch table alone loses
the ordinals the enum assigns.

Two macros populate the array. `ENTRY` takes the plain form.
`ENTRY_CUSTOM_USER` adds a prepare and a done callback plus an extra user-state
struct, and the record notes which of the two declared each entry.

Both macro names are also `#define` lines inside the initialiser, so a scrape
that counts a definition as a use reads 58 plain and 6 custom-user, which sums
to 64 and passes a total-only check. The macro split is asserted beside the
total for that reason, and the definitions are excluded structurally: by their
column-zero `#`, by the preprocessor continuation run they start, and by the
`_cmd` parameter name in the command-argument pattern. No exclusion is by line
number.

Six uses in the table wrap after the command argument, because the command name
and the proc symbol together run past the column limit, so the separators
inside the parentheses match a newline as well as a blank.

## Reconciled figures

These figures come from driver 610.57.04, which `version.mk` in the checkout
names.

| Figure | Value |
|---|---|
| Declared commands | 66 |
| Dispatched commands | 64 |
| Undispatched commands | 2 |
| Entries built by `ENTRY` | 59 |
| Entries built by `ENTRY_CUSTOM_USER` | 5 |
| Dispatch array length | 66 |

The two undispatched commands are `NVKMS_IOCTL_GET_3DVISION_DONGLE_PARAM_BYTES`
at ordinal 35 and `NVKMS_IOCTL_SET_3DVISION_AEGIS_PARAMS` at ordinal 36. Both
are named in the artefact with their ordinals, so a reader confirms 64 against
66 without re-running the scrape.

A driver release that adds or removes a command fails the run against
`--expect-declared` and `--expect-dispatched`, so the new count becomes a
deliberate edit with the release named beside it.

## Artefact

The tool writes `surface/nvkms-command-inventory.json`, schema
`gspwn.nvkms-command-inventory/1`. It carries `source` (the checkout path, the
driver version and the two source files), `scan` (the line each source was
found on, the array length and the bound expression), `summary`, and one record
per declared command in ordinal order.

| Record field | Content |
|---|---|
| `command` | The `NVKMS_IOCTL_*` name |
| `ordinal` | Its position in the enum, which is the index into the dispatch array |
| `dispatched` | Whether the table carries an entry for it |
| `macro` | `ENTRY` or `ENTRY_CUSTOM_USER`, or null when undispatched |
| `custom_user` | Whether the entry adds the prepare and done callbacks |
| `proc` | The handler symbol the macro pastes, or null |
| `param_struct`, `request_struct`, `reply_struct` | `NvKms<Proc>Params`, `NvKms<Proc>Request` and `NvKms<Proc>Reply`, from the macro expansion |
| `param_size` | The `sizeof(struct NvKms<Proc>Params)` expression. The tool records the expression and measures no size |
| `extra_user_state_struct` | `NvKms<Proc>ExtraUserState` for a custom-user entry, null otherwise |
| `undispatched_reason` | `no handler in the dispatch table`, or null |
| `source` | The `file:line` the record was read from |

## Failure modes

Every one of these raises `SourceError` and exits 2 before anything is written.

| Condition | Behaviour |
|---|---|
| `--src` is not a directory | Message naming the path |
| Either source file is absent or unreadable | Message naming the file and stating `--src` must point at an open-gpu-kernel-modules checkout |
| No `enum NvKmsIoctlCommand` declaration | Message naming the header the tool reads |
| The enum names anything but a bare `NVKMS_IOCTL_` identifier | Message naming the entry and the line, because ordinals are read off the declaration order and an explicit initialiser breaks that |
| No `dispatch[] = {` initialiser, or one that never closes | Message naming the source file and the line brace matching started from |
| The initialiser holds no recognised macro use | Message stating the table is built by macros the tool no longer recognises |
| `ARRAY_LEN(dispatch)` absent from the source | Message stating the kernel then applies some other limit than the array length the tool reports |
| One command dispatched twice | Message naming the command and both lines, because the second use overwrites the first slot |
| A dispatched command the enum does not declare | Message naming every such command |
| The declared or dispatched total differs from what is expected | Message naming both counts, and for the dispatched total the declared commands with no entry |
| A declared ordinal past the end of the array | Message naming the commands and the array length |
| The macro split does not sum to the entry total | Message naming the plain count, the custom-user count and the entry total |

`version.mk` absent, or carrying no `NVIDIA_VERSION`, is a warning. The
inventory is written with a null driver version.

## Concurrency and durability

The module reads two source files and writes one JSON file per invocation, and
takes no lock. The write goes through a temporary file beside the target and
`os.replace`, so an interrupted run leaves the previous inventory intact. The
temporary file is unlinked when the write fails.

## Consumers

Three components read the artefact.
[`refgen.py`](/gspwn/architecture/components/refgen/) renders
[Modeset commands](/gspwn/reference/surface/modeset-commands/) from it,
[`syzlang_gen.py`](/gspwn/architecture/components/syzlang-gen/) emits the
`modeset` description family, and
[`surface_cov.py`](/gspwn/architecture/components/surface-cov/) counts its 64
dispatched commands in the 852-target denominator.

## Limits

The inventory names each parameter struct and records the `sizeof` expression
for it. The measured size comes from `syzlang_gen.py`, which compiles the
headers separately.

`ARRAY_LEN(dispatch)` bounds the index space before the lookup, so a declared
ordinal outside that bound is rejected by the driver ahead of the NULL check.
The tool asserts every declared ordinal falls inside the bound.

## See also

- [Modeset commands](/gspwn/reference/surface/modeset-commands/)
- [Attack surface](/gspwn/architecture/attack-surface/)
