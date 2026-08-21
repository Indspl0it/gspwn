---
title: surface_cov.py
description: The share of the driver's enumerated command surface a description set models and a corpus reaches, decomposed into three stages.
---

Measures how much of the driver's own enumerated command surface a description
set declares and a corpus names. `coverage_ctl.py` counts KCOV edges, and the
driver's edge space has no known size, so an edge count cannot support a
"covered X% of the driver" claim. `config/campaign.yaml` disclaims that reading
of it.

The inventories supply a denominator that has been measured.
`ioctl_inventory.py`, `ctrl_surface.py` and `object_graph.py` enumerate the 764
targets a default tenant may call, across escapes, UVM commands, RM control
commands and class allocations. Counting how many of those a corpus names
is a ratio over that denominator, and the ratio is a claim about the command
surface and never about lines of driver code.

The module reads committed artefacts. It reaches no device and needs no KCOV,
no syz-manager and no GPU.

## The denominator

`targets` prints the count per family. The figures below are for driver
610.57.04.

| Family | Targets | Contents |
|---|---|---|
| escape | 32 | Dispatched `NV_ESC_*` escapes on `/dev/nvidiactl` and `/dev/nvidiaX` |
| uvm | 39 | Commands on `/dev/nvidia-uvm` |
| uvm_tools | 7 | Commands on `/dev/nvidia-uvm-tools` |
| control | 531 | Non-privileged RM control commands carrying a kernel-side handler |
| alloc | 155 | Unprivileged allocatable classes, plus the three root classes the file descriptor itself gates |
| total | 764 | |

Four groups are counted and reported outside the denominator. Folding any of
them in would move the ratio with no campaign changing.

| Group | Count | Exclusion reason |
|---|---|---|
| control_gsp | 236 | The handler is compiled out and the parameter buffer crosses the RPC queue to GSP, where KCOV cannot follow |
| uvm_test | 104 | Reachable only under `uvm_enable_builtin_tests=1`, which the target does not set |
| escape_dead | 3 | Declared in `nv_escape.h` with no dispatch case |
| escape_mux | 2 | `NV_ESC_RM_CONTROL` and `NV_ESC_RM_ALLOC`, multiplexers whose leaves are counted in the control and alloc families |

The 236 GSP-routed commands are worth fuzzing. A tenant can call them and the
marshalling runs kernel-side, and the handler itself runs on firmware KCOV
cannot instrument. Effort spent there raises executions and moves no edge
count.

## The three stages

| Stage | Measured from | Fix when it loses a target |
|---|---|---|
| targetable | The three inventories | None. This stage is the denominator |
| modelled | `artifacts/descriptions/` | The describe phase writes the missing syzlang variant |
| exercised | The corpus under `artifacts/seeds/` | The programs do not build the state the call needs, which is a resource-chain problem before it is a seed problem |

modelled over targetable measures the describe phase's own completeness.
exercised over modelled measures whether the fuzzer builds programs valid
enough to emit the call at all. A headline ratio on its own hides which stage
lost the surface.

The generated baseline models 764 of 764 targets, 100.0% in every family. The
exercised column reads 0 because no campaign has run, and `report` states that
an empty corpus says nothing about the descriptions.

The measurement works because `syzlang_gen.py` names every control command as
its own syzlang variant, `ioctl$NV_ESC_RM_CONTROL_<handler>`, and never one
opaque `NV_ESC_RM_CONTROL` carrying a command field. The variant name is the
join key for all three stages, because a description declares it and a corpus
program names it in the same spelling. Corpus text is therefore
self-describing.

## Responsibility

The module owns the denominator and the three-stage decomposition over it. It
writes only the JSON file `targets --out` is given.

| Invariant | Enforced by |
|---|---|
| A missing inventory cannot shrink the denominator silently | `_load` raises `SurfaceError` naming the file and the regeneration step |
| A denominator cannot mix driver releases | `load_targets` compares the `driver_version` each inventory records and refuses more than one distinct value |
| A multiplexer and its leaves are never both counted | `NV_ESC_RM_CONTROL` and `NV_ESC_RM_ALLOC` are classified `escape_mux` and excluded, and the control and alloc families carry their leaves |
| One call never lands in two families | A class allocation whose variant name collides with a dispatched escape yields to the escape, so `NV_ESC_RM_ALLOC_MEMORY` is counted once |
| A UVM test command is separated by its gate | The discriminator is the `reachable` field the extractor recorded, and never the command name, because test and production commands share a node path and a module |
| The three root classes stay inside the denominator | `NV01_ROOT`, `NV01_ROOT_NON_PRIV` and `NV01_ROOT_CLIENT` carry no `RS_FLAGS_ALLOC_*` marker because the file descriptor gates them, and a default tenant allocates one as the first call of every program |
| An empty corpus is never read as a modelling failure | `report` names the corpus directory, states that the exercised column is empty by construction, and skips the resource-chain diagnosis |
| A directory that yielded no file is visible | `scan_variants` logs a warning when it reads nothing, so every stage below it reading zero is attributable |
| A description declaring a variant no inventory names is reported | `modelled` lists the surplus variants, because a stale inventory and a description outside the tenant surface both land there |

## Interface

| Subcommand | Output |
|---|---|
| `targets [--json] [--out PATH]` | The denominator per family, then the four excluded groups with the reason for each |
| `modelled [--top N]` | Modelled against targetable per family, then the variants the descriptions declare that no inventory names |
| `report [--json]` | The three-stage decomposition per family, the loss at each stage, and the excluded counts |
| `gaps [--stage model\|corpus] [--family F] [--top N]` | The uncovered targets, one worklist-ready line each |

`--desc` defaults to `artifacts/descriptions` and `--corpus` to
`artifacts/seeds`. `--family` accepts `escape`, `uvm`, `uvm_tools`, `control`
or `alloc`. `-v` logs at DEBUG.

| Function | Returns |
|---|---|
| `load_targets()` | The target map keyed by syzlang variant, the excluded map, and the version metadata |
| `scan_variants(paths, what)` | Variant name to the files naming it, over syzlang or program text |
| `stages(desc_dir, corpus_dir)` | The targets, the exclusions, the metadata, and the modelled and exercised variant sets |

## Callers

| Direction | Modules |
|---|---|
| Imports this module | `selftest.py`, for the denominator and scanner tests. The `describe` phase invokes `modelled` as a command and gates on it |
| This module imports | Nothing in `tools/`. `pipeline_state.py` is deliberately absent, because that module needs `fcntl` and this one stays POSIX-free so the describe agent can check its own denominator on the workstation before the target exists |

## Failure modes

| Condition | Behaviour | Exit |
|---|---|---|
| An inventory is absent | Message naming the file, the path, and the effect a missing inventory would have on the ratio | 1 |
| An inventory does not parse | Message naming the file and the underlying error | 1 |
| The inventories record different driver releases | Message listing the version each file carries, then the regeneration and `surface_verify.py check` steps | 1 |
| The description directory holds no file | Warning, and every stage below it reports zero | 0 |
| The corpus directory holds no program | Warning, and `report` states the exercised column is empty by construction | 0 |
| A file under either directory cannot be read | Warning naming the path, and the file is skipped | 0 |
| `gaps` finds nothing uncovered | The heading and a count of zero | 0 |
| No subcommand given | argparse usage message | 2 |

## Concurrency and durability

Every subcommand is read-only except `targets --out`, which writes the JSON
whole to `PATH.tmp` in the destination directory, flushes, `fsync`s and moves
it into place with `os.replace`. A crash mid-write leaves the previous file
intact and never a truncated one. No lock is taken. The module holds no state
between runs and is safe to re-run.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never present a surface number as a fraction of the driver's code | The denominator is the enumerated command surface. The driver's line and edge counts are not in it, and a reader who conflates the two gets a coverage claim the data does not support |
| Never fold the excluded groups into the denominator | The 236 GSP-routed commands alone would move the ratio by more than a quarter with no campaign changing, and the movement would read as progress |
| Never report the headline share without the per-stage split | Losing a target at the modelling stage and losing it at the corpus stage need different work, and one number cannot distinguish them |
| Never read an empty corpus as a description failure | The pre-fuzz state produces the same zero, and reporting it as a modelling gap sends the describe agent to fix a description set nothing has run against |
| Never count a multiplexer as a target alongside its leaves | `NV_ESC_RM_CONTROL` selects its real target from a field in its own parameter struct, so counting both puts the same calls in the denominator twice |
| Never continue past an inventory that names a different driver release | A denominator mixed across releases counts commands that do not coexist |

## Design notes

`coverage_ctl.py` and this module answer different questions about the same
campaign. An edge count answers whether the fuzzer is still finding new code.
A surface number answers which commands it never tried. A plateau at low
surface coverage and a plateau at high surface coverage call for opposite
actions, and the edge count alone cannot separate them. See
[Coverage and plateau](/gspwn/architecture/coverage-and-plateau/).

The join key is the syzlang variant name and not an ioctl request number,
because a request number identifies `NV_ESC_RM_CONTROL` and stops there. All
531 control commands share that one request number, and the command a program
actually issues appears in the variant name `syzlang_gen.py` assigns. A
measurement keyed on request numbers would collapse the control family to a
single target.

`modelled` reports the variants a description declares that no inventory names
because two different causes land in the same list. One class taking two
parameter structs produces an alternate calling form of a counted target, which
is expected. A description outside the tenant surface and a stale inventory are
both defects. The generated baseline produces exactly one such variant,
`NV_ESC_RM_ALLOC_NVOS21`, the alternate allocation form.

## See also

- [Coverage and plateau](/gspwn/architecture/coverage-and-plateau/)
- [Attack surface](/gspwn/architecture/attack-surface/)
- [ctrl_surface.py](/gspwn/architecture/components/ctrl-surface/)
- [object_graph.py](/gspwn/architecture/components/object-graph/)
- [surface_verify.py](/gspwn/architecture/components/surface-verify/)
</content>
