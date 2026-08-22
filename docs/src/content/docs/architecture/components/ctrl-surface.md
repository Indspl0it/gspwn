---
title: ctrl_surface.py
description: The RM control command space extracted from the NVOC export tables, the four privilege classes it derives, and the three readings of the flag word that produce a wrong answer.
---

Enumerates the commands behind `NV_ESC_RM_CONTROL` from the NVOC-generated
export tables in an open-gpu-kernel-modules checkout. One ioctl carries the
whole Resource Manager control interface and its `cmd` field selects the
operation, so the `describe` phase needs the command numbers, their privilege
class, and the parameter struct each one reads. The driver generates that
table into `src/nvidia/generated/g_*_nvoc.c`, and this module reads it.

The module runs entirely off the source tree. It reaches no device, opens no
socket, and needs no GPU.

## Responsibility

The module owns the parse of `NVOC_EXPORTED_METHOD_DEF` entries and the
privilege classification derived from their flags. It writes only the JSON
file it is given.

| Invariant | Enforced by |
|---|---|
| Flag names come from the driver branch being read | `RMCTRL_FLAGS_*` are parsed from `control.h` at run time, and access rights from `rs_access.h` |
| A flag definition with a trailing comment is still read | The definition pattern allows an optional `//` comment before end of line |
| A composite flag name never becomes a bit | Only single hex literals are accepted, and a value with more than one bit set exits with a message |
| A branch that renames a privilege flag fails loudly | Absence of any of the seven flags the classifier reads exits with a message naming them |
| An entry's fields belong to one entry | The `#if` gate constant must equal the entry's parsed `flags`, and `pClassInfo` must name the enclosing table's class |
| A method with no parameter struct is distinguished from a parse failure | `paramSize` matches either `sizeof(NAME)` or a literal `0`, and anything else rejects the entry |
| An unparsed entry is visible | Rejections are counted, listed under `scan.rejected`, and logged as a warning |
| A table format change fails loudly | Zero parsed methods exits with a message naming the directory |
| A flag bit the header does not name is preserved | Undecoded bits are recorded per record as `unknown_flag_bits` |

## Interface

One invocation walks the generated directory and writes the inventory.

| Flag | Effect | Default |
|---|---|---|
| `--src` | The open-gpu-kernel-modules checkout to read | `artifacts/src/open-gpu-kernel-modules` |
| `--out` | The JSON inventory to write | `surface/rm-control-inventory.json` |
| `-v`, `--verbose` | Logs every table found at DEBUG level | Off |

Standard output carries the totals: methods, owning classes, driver version,
the count in each privilege class, the test-only count, the count with no
kernel-side handler, and the rejected count.

The written JSON carries `schema`, `source`, `flag_definitions`,
`access_right_definitions`, `scan`, `summary` and `methods`. One `methods`
record holds the command number in hex and as an integer, the SDK interface
prefix, the owning class, the handler and export symbol, the parameter struct,
the raw flags with their decoded names, the access rights, the privilege
class, the test-only and routing booleans, and the source file and line.

| Function | Returns | Raises |
|---|---|---|
| `load_flag_defs(src_root)` | `{bit value: flag name}` from `control.h` | `SourceError` on a missing header, a multi-bit value, a duplicate bit, or a missing privilege flag |
| `load_access_right_defs(src_root)` | `{bit value: right name}` from `rs_access.h` | `SourceError` on a missing header or an empty result |
| `read_driver_version(src_root)` | The `NVIDIA_VERSION` string, or `None` | |
| `decode_bits(value, defs)` | The names for the set bits, and a mask of the bits with no name | |
| `classify_reachability(flag_names)` | One of `internal`, `privileged`, `non_privileged`, `kernel_only` | |
| `parse_entry(lines, first_line_no, rel_path, table_class)` | `(fields, None)`, or `(None, reason)` when the entry is rejected | |
| `scan_file(path, rel_path)` | `(entries, tables, rejected)` for one source file | |
| `build_record(fields, flag_defs, access_defs)` | One inventory record | |
| `summarise(records)` | The counts printed and written under `summary` | |
| `collect(src_root)` | The whole inventory | `SourceError` on a missing generated directory, an unpopulated tree, or zero methods |
| `write_json(inventory, out_path)` | `None` | `SourceError` when the directory or the file cannot be written |

Exported constants: `SCHEMA`, `DEFAULT_SRC`, `DEFAULT_OUT`, `GENERATED_DIR`,
`CONTROL_H`, `RS_ACCESS_H`, the `F_*` flag names, and the four `REACH_*`
values.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing at run time. The `describe` phase reads the JSON it writes |
| This module imports | Nothing in `tools/`. Standard library only |

## Failure modes

| Condition | Behaviour | Exit |
|---|---|---|
| `--src` is not a directory | Message naming the path | 2 |
| `src/nvidia/generated/` absent under `--src` | Message naming the expected path and what `--src` should point at | 2 |
| `control.h` or `rs_access.h` absent | Message naming the file and what it was being read for | 2 |
| A `RMCTRL_FLAGS_*` value has more than one bit set | Message naming the flag, the file and the value | 2 |
| `control.h` names none of the seven privilege flags the classifier reads | Message listing the missing names and stating the classification would be wrong | 2 |
| The generated directory holds no `.c` files | Message stating the tree looks unpopulated | 2 |
| Zero exported methods parsed | Message naming the directory and the expected table name | 2 |
| The output directory cannot be created, or the file cannot be written | Message naming the path and the operating-system error | 2 |
| An entry's gate constant disagrees with its flags | The entry is rejected, counted, and logged as a warning | 0 |
| An entry's `pClassInfo` names another class | The entry is rejected, counted, and logged as a warning | 0 |
| An entry lacks a field | The entry is rejected with the field named, counted, and logged as a warning | 0 |
| An entry is not closed before end of file | The entry is rejected and counted | 0 |
| `version.mk` absent or without `NVIDIA_VERSION` | `driver_version` reads null, and a warning is logged | 0 |
| A source file holds bytes that are not valid text | Read with `errors="replace"` | 0 |
| The output directory does not exist | Created, and the creation is logged | 0 |

## Concurrency and durability

The module writes one file per invocation and takes no lock. The write goes to
a sibling temporary file and is renamed onto the target, so an interrupted run
leaves the previous inventory intact. A failed write removes the temporary
file. Two concurrent invocations against the same `--out` produce one of the
two inventories and never a mixture of both.

The parse itself is pure. `scan_file` reads a file and returns records,
`build_record` maps one record with no state, and `summarise` reads records
and returns counts, which makes each directly testable. Log lines go to
standard error and the totals go to standard output, so the totals can be
piped without the log.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never read an empty flag word as an unrestricted command | `RMCTRL_FLAGS_NONE` and `RMCTRL_FLAGS_KERNEL_PRIVILEGED` are both `0x0`. `rmControlValidateClientPrivilegeAccess` rejects a command carrying none of `NON_PRIVILEGED`, `PRIVILEGED` or `INTERNAL` for any caller below `RS_PRIV_LEVEL_KERNEL`, so an empty mask means kernel-only. Reading it as a grant inverts 114 commands |
| Never classify by `NON_PRIVILEGED` alone | `serverControl_ValidateCookie` tests `INTERNAL` before the privilege check and returns `NV_ERR_NOT_SUPPORTED` for every caller whose `RmApi` left `bApiLockInternal` and `bGpuLockInternal` clear, which is every ioctl caller. 23 commands carry both flags, and counting them as reachable overstates the surface by that margin |
| Never count a GSP-routed command as kernel-side surface | `NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG` compiles `pFunc` to `NULL` when a command carries `ROUTE_TO_PHYSICAL` without `PHYSICAL_IMPLEMENTED_ON_VGPU_GUEST`. 679 of 1372 methods are in that set. Their implementation is in signed GSP firmware, so a description reaching one exercises the RPC serialisation path and no code in `nvidia.ko` |
| Never test `PRIVILEGED` after the kernel-only default | The driver tests `PRIVILEGED` first, so the one command carrying both `PRIVILEGED` and `INTERNAL` and any command carrying both `PRIVILEGED` and `NON_PRIVILEGED` resolve to the stricter outcome |
| Never hardcode the flag values | Flag values and command numbers both move between driver branches. A hardcoded table produces an inventory that parses cleanly and describes another driver |
| Never anchor a `#define` pattern at end of line | `RMCTRL_FLAGS_PRIVILEGED_IF_RS_ACCESS_DISABLED` carries a trailing comment, and an anchored pattern drops exactly the flag that promotes three commands to privileged |
| Never search for the `#if` gate without multiline mode | The gate is matched against a joined entry body. Without `re.M` the anchor binds to the start of the body and every entry is rejected as gateless |
| Never emit a record from an entry missing a field | A missing field means the line collector spanned two entries, and the record would carry one entry's command number with another's flags |
| Never report a truncated inventory as complete | A silently dropped entry is a command the `describe` phase never models. Rejections are counted in `scan.rejected_count`, listed with their reason, and printed |
| Never treat `RS_ACCESS_COUNT` as a right | It is the size of the enumeration. Including it would invent a fifth access right and shift the bit positions of the real four |

## Design notes

The `#if` gate is a free correctness check. NVOC writes each entry's own
`flags` value into the `NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG` condition above
it, so an entry whose parsed `flags` disagrees with its gate proves the line
collector crossed an entry boundary. The `pClassInfo` check is the same idea
against the enclosing table. Both fire zero times on `610.57.04`, which makes
the 1372-of-1372 parse credible.

Privilege classification is ordered to match the driver, `INTERNAL` first,
then `PRIVILEGED`, then `NON_PRIVILEGED`, with kernel-only as the default. The
flags overlap on 24 commands, and any other order changes their class.

Two gates sit outside the four classes because they resolve at run time.
`RM_TEST_ONLY_CODE` depends on `PDB_PROP_SYS_ENABLE_RM_TEST_ONLY_CODE`, and
`PRIVILEGED_IF_RS_ACCESS_DISABLED` depends on `g_resServ.bRsAccessEnabled`.
Both are recorded per record as booleans and left out of the class, so a
consumer can apply either without re-deriving the classification.

The `accessRight` field holds `NVBIT(RS_ACCESS_x)`, so the header's index
becomes a bit position. Five commands carry a non-zero value, all of them
`RS_ACCESS_NICE`.

The SDK interface prefix is derived from the top 16 bits of the command
number, so `0x20800102` yields `NV2080`. That derivation needs no header
lookup, which matters because 32 exported command numbers have no name in the
SDK headers at all.

## See also

- [RM control command surface](/gspwn/knowledgebase/rm-control-surface/)
- [Resource Manager object model](/gspwn/knowledgebase/rm-object-model/)
- [GSP offload](/gspwn/knowledgebase/gsp-offload/)
