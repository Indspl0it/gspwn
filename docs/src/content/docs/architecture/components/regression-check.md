---
title: regression_check.py
description: Eight CI checks that compare committed artefacts which have to agree, and the defect class each one closes.
---

Compares the committed surface artefacts against each other, and the generated
reference pages against the artefacts they render. Each check covers a pair
that has to agree and that no other tool compares, so a disagreement between
them reaches the repository while every tool reports success.

The module reads committed files only. It needs no GPU, no kernel, no network
and no driver source checkout, so it runs in CI on the same runner as the
offline self-test.

## Responsibility

The module owns the eight comparisons and their exit codes. It writes nothing.

| Invariant | Enforced by |
|---|---|
| Every syzlang call name the ioctl map carries is declared | `names` joins the map values against the calls parsed out of `descriptions/*.txt` |
| A map value that is not a call name is refused | `read_ioctl_map` requires a string beginning `ioctl$`, and skips every key beginning `comment` |
| Every leaf selector renders as a constant | `pins` reads `cmd` and `hClass` out of each call's parameter struct and requires `const[` |
| A selector free on purpose stays visible | The allowlist is keyed on the whole `(variant, struct, field)` triple, so renaming any part of it retires the entry |
| An allowlist entry that has been fixed does not linger | An entry whose call now renders `const` is reported stale and fails the check |
| A check cannot report a clean run over nothing | A reporting group holding no call at all fails, and an absent artefact exits 2 |
| The denominator is still fully declared | `coverage` compares `surface_cov.load_targets()` against `surface_cov.scan_variants()` per family and names every target that lost its declaration |
| A derived artefact still matches the inventory it was derived from | `derived` requires `rm-chains.json` and `rm-control-rank.json` to account for the targetable control set command for command, and every call name they imply to be declared |
| A derived artefact carries the schema the reader expects | `_load_derived` requires the recorded schema stamp and the named array, and reports the producing command when either is wrong |
| A derived artefact still agrees with its own record structure | `rank_consistency` reads the ranking's order against its scores and its scores against its components and weighting; `chains_consistency` reads each chain's length against its step count and its last step against the class it targets |
| A pinned control selector carries the right value | `check_pins` compares each control variant's `cmd` against the method id `rm-control-inventory.json` holds for the handler the variant is named for, through `VALUE_CHECKED` and `control_method_ids` |
| A family's denominator cannot shrink unnoticed | `TARGET_FLOOR` records the per-family target count of driver 610.57.04, and `coverage` exits 1 on a family below its floor |
| A generated reference page still follows from the artefacts | `pages` regenerates the six pages under `docs/src/content/docs/reference/surface/`, the five content pages and the index over them, into a temporary directory through `refgen.py` and diffs byte for byte |
| Every artefact the description set was generated from still holds the recorded bytes | `stale` hashes each `path` under `generated_from` in `descriptions/generation.json` and compares it against the recorded `sha256` |
| A measured-size file added to the record is covered from its first commit | `recorded_inputs` reads a list member the same way as a mapping, so the list under `ctrl_sizes` needs no second reader |
| The checkout the description set came from is visible without opening the JSON | `stale` prints `driver_version` and `driver_commit` in its header |
| The four Track U target lists still name the same harnesses | `harnesses` compares `track_u.targets`, the `C_TARGETS` array, the `Harness` column of `harnesses/TARGETS.md`, and the directories holding a `build.sh` |
| A source that reads as empty cannot pass as a disagreement | `check_harnesses` exits 2 on a source carrying no name, because the reader for it is then the thing to fix |
| A directory under `harnesses/` that builds nothing is visible | A directory with no `build.sh` and no `HARNESS_EXCLUSIONS` entry is reported |
| Every command line in a phase brief resolves against the tool it names | `agents` reads each command out of `agents/*.md` and measures it against the tool's own argparse parser: the file, the subcommand, every flag, whether the flag takes a value, the declared choices and the declared type |
| An exit code a brief explains is one the tool can return | `agents` reads every `return` and every `sys.exit` in the tool through `ast`, resolving module-level integer constants, and reports a stated code the tool nowhere produces |
| A command shape the extractor cannot read is visible | A line naming a tool that does not read as an invocation of it is reported, so no command line is dropped in silence |

## Interface

| Subcommand | Output |
|---|---|
| `names` | Map entry count, distinct name count, declared call count, then each entry naming a call no description declares |
| `pins` | Selector fields examined, the per-group counts, then each field that renders free, each stale allowlist entry and each empty group |
| `coverage` | The per-family targetable, modelled and gap table, then each missing target by name |
| `derived` | The per-artefact records, implies, accounts, undeclared, mismatch and internal table, then each offending name and the command that regenerates the artefact |
| `pages` | The per-page records, generated size, committed size and state table, then the first differing line of each page that moved |
| `stale` | The recorded checkout, then one row per recorded input with its path, record count and state, then each input whose file is absent or hashes to another digest, with both digests |
| `harnesses` | The per-target table across the four sources, the declared exclusions and their reasons, then each target a source does not carry, naming that source and the ones that do |
| `agents` | The per-brief command and exit-code counts, the declared exclusions and their reasons, then each command line that does not resolve, with the file, the line and what the tool declares instead |
| `all` | The eight in `CHECK_ORDER`, each under its own header, reporting the worst verdict |

`CHECK_ORDER` is `names`, `pins`, `coverage`, `derived`, `pages`, `stale`,
`harnesses`, `agents`, which is the order the module docstring lists and the
order the CI steps carry. A check
registered in `CHECKS` and absent from `CHECK_ORDER` runs last.

`-v` logs what each artefact read contributed, and is accepted on either side
of the subcommand: `regression_check.py -v derived` and
`regression_check.py derived -v` both set it.

| Function | Returns |
|---|---|
| `read_ioctl_map()` | `(request key, call name)` pairs, comment keys dropped |
| `read_descriptions()` | Call name to parameter struct name, and struct name to field renderings |
| `parse_structs(text)` | Field renderings per struct block |
| `parse_calls(text)` | The parameter struct each `ioctl$` line points at |
| `control_method_ids()` | Handler symbol to the method id `rm-control-inventory.json` carries for it, over the targetable and the GSP-routed commands |
| `check_names()`, `check_pins()`, `check_coverage()`, `check_derived()`, `check_pages()`, `check_stale()`, `check_harnesses()`, `check_agents()` | The exit code for that check |
| `chains_implies(doc, path)`, `rank_implies(doc, path)` | The call names an artefact implies and the control commands it accounts for |
| `rank_consistency(doc, path)`, `chains_consistency(doc, path)` | The places an artefact contradicts its own record structure |
| `read_generation()` | The `generated_from` record and the repository root its paths resolve against, which is the parent of the directory holding `GENERATION` |
| `recorded_inputs(record)` | `(key, path, sha256, count)` per recorded input, list members included |
| `harness_config_targets()`, `harness_run_targets()`, `harness_doc_targets()`, `harness_directories()` | The Track U names each source carries |
| `agent_briefs()` | `(file name, path)` per brief under `AGENTS_DIR`, raising `CheckInput` when the directory holds none |
| `agent_commands(text)` | `(line number, command)` per simple command in one brief, over fenced blocks, inline code spans and bare command lines |
| `simple_commands(line)` | Every tool-bearing simple command inside one shell line, heredoc and comment removed |
| `command_words(command)` | `(tool path, [argument])`, interpreter, `sudo` and leading environment assignment dropped, or `None` |
| `tool_parser(tool)` | The argparse parser the tool declares, through `build_parser()` or by capturing the one `main()` builds |
| `parser_surface(parser)` | `({option string: action}, {subcommand: subparser})` |
| `tool_exit_codes(tool)` | Every integer a `return` or a `sys.exit` in the tool can yield |
| `agent_exit_claims(text)` | `(line number, tool path, exit code)` per exit code a brief states, bound to the tool named most recently at or before that line |
| `_load_derived(label, path, schema, array, remedy)` | The parsed artefact, raising `CheckInput` when it is absent, unparseable, wrongly stamped or missing its array |

## Callers

| Direction | Modules |
|---|---|
| Imports this module | `tools/selftest.py`. `.github/workflows/selftest.yml` invokes it as eight steps, at `:50`, `:58`, `:65`, `:74`, `:84`, `:93`, `:101` and `:110` |
| This module imports | `tools/surface_cov.py`, for `load_targets`, `scan_variants`, `CONTROL_PREFIX` and the artefact paths. `tools/refgen.py`, for `render` and `write`, which `pages` regenerates through. `tools/gspwn_config.py`, for `load`, which `harnesses` reads `track_u.targets` through. Every tool a phase brief names, which `agents` imports one at a time inside the check |

`surface_cov.py`, `refgen.py` and `gspwn_config.py` are the whole set of
top-level imports. `pipeline_state.py` is deliberately absent: it needs
`fcntl`, which would stop all four modules running on a Windows workstation.

`agents` is the one check that imports another tool, because a command line is
verified against that tool's own parser. Those imports sit inside the check, so
the other seven still run on a Windows workstation and `agents` reports the
absent `fcntl` there as exit 2.

## Failure modes

| Condition | Behaviour | Exit |
|---|---|---|
| The check passes | The counts and `OK` | 0 |
| `names` finds an undeclared call | Each offending request number and its variant, a multiplexer note where one applies, and the consequence for `trace2seed.py` | 1 |
| `pins` finds a free selector | The variant, the struct, the field and what it rendered as | 1 |
| `pins` finds a stale allowlist entry | The entry named, with the instruction to remove it | 1 |
| `pins` finds a reporting group with no call | The group named, stating that the check has gone silent | 1 |
| `pins` finds a control `cmd` pinned to a value the inventory does not carry for that handler | The variant, the pinned value and the inventory's method id | 1 |
| `pins` finds a call whose `arg` resolves to no declared struct inside a reported group | The call named, with its rendering | 1 |
| `coverage` finds a family short of its denominator | The per-family table with the gap, then the missing variant names | 1 |
| `coverage` finds a family below its `TARGET_FLOOR` | The family, its floor and its current count, with the two causes worth checking | 1 |
| `derived` finds an implied call name no description declares | The names, then the command that regenerates the artefact | 1 |
| `derived` finds a command the inventory no longer carries, or one the artefact never reaches | The names under either heading, then the regenerating command | 1 |
| `derived` finds an artefact contradicting its own record structure | The record position, the two disagreeing values, then the regenerating command | 1 |
| `pages` finds a page that differs, is absent, or is no longer produced | The per-page table, the first differing line, and the regenerating command | 1 |
| `stale` finds a recorded input absent or hashing to another digest | The per-input table, then the path with the recorded and the measured digest, and the command that regenerates the set | 1 |
| `stale` finds a `generated_from` entry that is neither the driver checkout nor an input record | `cannot run:` on stderr, naming the key and how it rendered | 2 |
| `harnesses` finds a target a source does not carry | The per-source table, then the target, the source that does not carry it and the ones that do | 1 |
| `harnesses` finds a directory with no `build.sh` and no declared exclusion | The directory named, with the instruction to declare it | 1 |
| `harnesses` finds a source carrying no name at all | `cannot run:` on stderr, naming the source | 2 |
| `agents` finds a command naming a tool, a subcommand, a flag or a value the tool does not declare | The per-brief table, then the brief, the line, the command and what the tool declares instead | 1 |
| `agents` finds a stated exit code the tool cannot return | The brief, the line and the code, stating that no `return` and no `sys.exit` in the tool yields it | 1 |
| `agents` finds a line naming a tool that does not read as a command | The brief, the line and the text, so a shape the extractor cannot read is visible | 1 |
| `agents` finds no brief, or a brief set carrying no command line | `cannot run:` on stderr, naming the directory | 2 |
| A derived artefact carries the wrong schema stamp or no records array | `cannot run:` on stderr, naming the file and the producing command | 2 |
| An artefact the check needs is absent, unparseable, or shaped in a way the check did not anticipate | `cannot run:` on stderr, naming the file | 2 |
| A check raises an unexpected exception | `cannot run: unexpected <class>` and the traceback on stderr. Under `all` the remaining checks still run | 2 |

CI fails on both non-zero codes, so an unreadable artefact never reads as a
pass. An exception out of a check is exit 2 and never exit 1, because exit 1
reads as "an offending entry was found", and a traceback leaving the process
would hide every verdict after it.

## Concurrency and durability

Every subcommand is read-only. No lock is taken, no file is written, and two
concurrent invocations do not interact.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never let a missing artefact exit 1 | Exit 1 means the check found an offending entry, and a checkout without the committed artefacts would then read as a real regression in the description set |
| Never key the allowlist on the variant name alone | The same field under a renamed struct is a different field, and a triple-keyed entry retires itself when any part moves |
| Never report a family count without failing on an empty group | An emitter that stopped producing a family and a parser that stopped matching the emitted form both produce a clean run over zero calls |
| Never treat `flags[...]` as a pin | A `flags` rendering enumerates several values, so the call still reaches more than one leaf |
| Never fail on a declared variant outside the denominator | Alternate calling forms and wrapper routes to counted targets are legitimate additions, and the count moves with every one of them |
| Never let `derived` read an artefact whose schema stamp it does not recognise | A producer that changed its record shape then reads as a total mismatch, which points at the driver bump and not at the format change |
| Never let an unexpected exception exit 1 or abandon the remaining checks | A traceback out of the process exits 1, which CI reads as an offending entry, and it hides every verdict after it |
| Never compare the allocation `hClass` against a value | No committed artefact carries the allocation class number. The class id `surface_cov.load_targets` joins onto an alloc target is the owning class's SDK class id, which differs from the allocation class number on 17 of the 62 alloc targets that carry one, so the comparison would report those 17 as defects |
| Never store a digest beside a generated page in place of regenerating it | Whoever edits the page is positioned to update the digest, and the digest of a stale page still matches itself |
| Never let `harnesses` report only that two lists differ | The reader would then have to open all four files to find which one moved, and the check exists to point at the line to edit |
| Never treat a directory under `harnesses/` as a known absence without a reason | An undeclared absence and a target dropped by mistake are indistinguishable, and `HARNESS_EXCLUSIONS` carries the reason for both entries |
| Never let `agents` skip a command line it cannot parse | A silent skip is a command nothing checks, which is the blind spot the check exists to close, so an unreadable line is reported as an offender |
| Never shell out to `--help` to read a tool's command surface | The help text is a rendering of the parser, and a flag hidden with `SUPPRESS` or a value type declared on an action never reaches it. The parser object carries both |
| Never measure a placeholder against a declared choice or a declared type | The operator substitutes it, so the brief carries no value to measure, and reporting one would make every documented `<id>` an offender |
| Never resolve a recorded input path against `REPO_ROOT` | The paths belong to the record, so they resolve against the parent of the directory holding it, which leaves the check pointable at a scratch tree through `GENERATION` alone |

## Design notes

`names` fails when the ioctl map names a call the description set does not
declare. `tools/trace2seed.py convert` reads the map to name the call a traced
request becomes, so an unresolvable name produces a program syz-db rejects, or
one that runs and attributes to no target. The check reports request numbers
and not names, because two request numbers can carry one name and a trace
carries the number.

`pins` reads the emitted artefacts. `tools/syzlang_gen.py` carries
`require_pinned()` and asserts the same rule at emission over 768 variants,
which covers generation. This check covers a description set edited by hand
afterwards, and for that the rule sweeps every call. The three name prefixes
serve only the reported counts.

The form alone is a weak assertion, so the control `cmd` is compared against a
value as well. `control_method_ids()` reads `rm-control-inventory.json` for the
method id it carries against each handler symbol, including the GSP-routed
commands, and `check_pins` joins on that symbol, which is the string both the
inventory row and the variant name are built from. A variant pinned to another
leaf's method id reaches one wrong leaf and reports as one right one, and the
form check alone passes it.

Four fields are free on purpose, and all four belong to escape-family targets.
`surface_cov.py` counts each escape as one target and never decomposes it per
leaf, so pinning the field would add no target to the denominator.

| Variant | Struct | Field | Free because |
|---|---|---|---|
| `NV_ESC_CHECK_VERSION_STR` | `nv_ioctl_rm_api_version_t` | `cmd` | Selects the version comparison mode inside one handler |
| `NV_ESC_RM_LOCKLESS_DIAGNOSTIC` | `NV_LOCKLESS_DIAGNOSTIC_PARAMS` | `cmd` | Selects a diagnostic sub-operation inside one root-only handler |
| `NV_ESC_RM_ALLOC_OBJECT` | `NVOS05_PARAMETERS` | `hClass` | A class multiplexer. The classes behind it are decomposed in the alloc family under `NV_ESC_RM_ALLOC`, and both routes meet the same `RS_ENTRY` privilege gate |
| `NV_ESC_RM_ALLOC_CONTEXT_DMA2` | `NVOS39_PARAMETERS` | `hClass` | A class multiplexer, on the same grounds |

The first two entries carry the whole of the module's own justification, that a
free field is a fuzzable input to a single handler. The other two are class
multiplexers and that sentence is false for them, so their reason is the
denominator one above.

`coverage` calls `load_targets` and `scan_variants` directly. Shelling out to
`surface_cov.py modelled` gives no failing exit code and no JSON output, and
calling the two functions leaves that module untouched while giving a message
that names the variants which went missing.

`TARGET_FLOOR` makes the denominator itself an assertion. `coverage` compares
the description set against whatever `load_targets()` returns, so a driver bump
that drops targets, or a defect in an inventory parser, shrinks both sides
together and the comparison still reads clean. A bump that legitimately retires
a target moves the floor, and moving it is the change to review.

| Family | Floor |
|---|---|
| escape | 32 |
| uvm | 39 |
| uvm_tools | 7 |
| control | 531 |
| alloc | 155 |

`derived` exists because nothing in CI runs `object_graph.py chains` or
`ctrl_rank.py rank`. Both artefacts are produced from
`rm-control-inventory.json`, so both go stale against the same driver bump.
`trace2seed.py chains` and `syzlang_gen.py emit` read them and neither reports
the drift, so without this check the drift first appears in the seeds phase, at
run time on the system under test.

`derived` also reads each artefact against its own restatement of its
structure, through `rank_consistency` and `chains_consistency`. Neither pass
needs the tool that produced the file. The ranking's `rank` is 1..N in array
order, its `rank_score` is the weighted sum of its `rank_components` to within
`SCORE_TOLERANCE`, and the score does not increase along the array within each
of the two runs the file is built from. A chain's `chain_length` matches its
step count, its last step's `external_class` is its `target_external_class`,
and its `command_count` matches its command list. Each restatement is read only
where the artefact carries it on every record; one carried on part of an array
is reported, and one carried nowhere leaves the command-set comparison as the
whole of the check. The counts land in the summary table's `internal` column.

`pages` regenerates through `refgen.render` and `refgen.write` into a
temporary directory and diffs the bytes, so it catches a page edited by hand
and an artefact regenerated without regenerating the pages. Writing through
`refgen.write` covers the writer as well as the renderer: a page written with
the platform's native line endings differs from the committed LF copy.

`stale` reads `descriptions/generation.json`, which `syzlang_gen.py emit`
writes. The record carries a `path`, a `sha256` and a record count for each of
the five artefacts the description set was generated from, plus the
`driver_version` and `driver_commit` of the checkout the emitter read. Nothing
read those digests before this check existed. A surface artefact regenerated
without regenerating the description set leaves the record naming bytes that no
longer exist, and both files still parse, so `coverage`, `derived` and `pages`
all pass over a set whose provenance has gone.

The recorded paths are repository-relative, and the root they resolve against
is the parent of the directory holding the record. Deriving it that way leaves
the whole check pointable at a scratch tree through `GENERATION` alone. The
failing case in `tools/selftest.py` reaches the check that way, without
touching a committed artefact.

`ctrl_sizes` is a list holding one member. Reading a list member the same way
as a mapping covers a second measured-size file from the run it is added in,
with no second reader.

| Recorded input | Path | Records |
|---|---|---|
| `control_inventory` | `surface/rm-control-inventory.json` | 1372 |
| `ctrl_rank` | `surface/rm-control-rank.json` | 531 |
| `ctrl_sizes` | `surface/ctrl-param-sizes.json` | 739 |
| `escape_inventory` | `surface/ioctl-inventory.json` | 4 |
| `object_graph` | `surface/rm-object-graph.json` | 222 |

`harnesses` compares the four files that carry the Track U target list. Each
drives a different step, so a target named by fewer than all four is built and
never run, or run and never built, and the campaign reports the skip as a
per-target note hours in.

| Source | Construct read | Drives |
|---|---|---|
| `config/campaign.yaml` | `track_u.targets`, through `gspwn_config.load` | The fuzz phase, and the output directory the coverage sampler reads |
| `harnesses/run_all.sh` | The `C_TARGETS` bash array | Which binaries the campaign runs |
| `harnesses/TARGETS.md` | Every `Harness` column in the file | The entry point, the reachability argument and the replay command |
| `harnesses/` | Directories holding a `build.sh` | What `build_all.sh` compiles |

An offender line names the source that does not carry the target and the
sources that do. A check reporting only that two lists differ leaves the reader
to open all four files to find which one moved.

Two directories under `harnesses/` carry no Track U target and are declared in
`HARNESS_EXCLUSIONS`. A name there is dropped from all four sources before they
are compared, and a directory holding no `build.sh` and named nowhere there is
reported, so the exclusion list is the whole of what the check accepts as a
known absence.

| Directory | Reason |
|---|---|
| `common` | A shared helper tree. It holds `build_common.sh`, which every harness `build.sh` sources, and builds no target of its own |
| `go_cudacompat_elf` | `go test -fuzz` writes no `fuzzer_stats`, so it produces no coverage output for the sampler to read. `config/campaign.yaml` records the same reason against `track_u.targets` |


The eight checks read committed artefacts. `coverage` cannot compute a
denominator without the four inventories under `surface/`, and it cannot
compute a numerator without the description set, so a checkout missing
either measures 0 of 852 and fails on every run. See
[Artifacts](/gspwn/reference/artifacts/) for the committed set.

## Current readings

Against the committed artefacts at driver 610.57.04.

| Check | Reading |
|---|---|
| `names` | 78 map entries over 78 distinct names, 909 declared calls, OK |
| `pins` | 836 selector fields across 909 calls, control 531, alloc 207, xfer 31, modeset 64, outside every group 3. 531 control `cmd` values checked against the inventory over 521 distinct values and 64 modeset `cmd` values over 64, 0 the inventory does not carry. 2 calls whose `arg` resolves to no declared struct, 0 of them inside a reported group. OK, 4 unpinned by design |
| `coverage` | 852 targetable, 852 modelled, 81 declared variants outside the denominator, denominator floor 852 across 7 families, OK |
| `derived` | 531 targetable control commands. `rm-chains.json` 98 records implying 598 names and accounting for 531, `rm-control-rank.json` 531 records implying 531 and accounting for 531, 0 undeclared, 0 mismatched and 0 internal, OK |
| `pages` | 6 generated pages. `allocation-classes.md` 253 records at 38706 bytes, `control-commands.md` 531 at 105433, `driver-cves.md` 61 at 59176, `escapes.md` 37 at 9350, `index.md` 5 at 8131, `modeset-commands.md` 66 at 14198, each equal to the committed copy, OK |
| `stale` | 6 recorded inputs, 6 matching, driver 610.57.04 at commit `e4a5faa`, OK |
| `harnesses` | 6 targets across 4 sources, 2 declared exclusions, OK |
| `agents` | 12 briefs, 179 command lines and 25 stated exit codes over 22 tools, 2 declared exclusions, OK |

The two calls whose `arg` resolves to no declared struct are
`UVM_DEINITIALIZE`, which declares no pointer, and `NV_ESC_ATTACH_GPUS_TO_FD`,
whose `arg` renders as `int32`. The 531-against-521 reading is five NV0090
commands each exported by three owning classes, so 15 handler symbols carry 5
distinct method ids. [surface_cov.py](/gspwn/architecture/components/surface-cov/)
records the same 521 against 531.

## Stated limits

None of the eight checks says whether a pinned selector reaches the handler it
names. That is settled by a call on the target.

`derived` compares the two artefacts against the inventory and not against the
driver source, so a bump that moves the source without moving
`rm-control-inventory.json` passes.

`pins` compares a value for the control family alone. The allocation `hClass`
and the XFER inner `cmd` have no committed authority to compare against, and
`VALUE_CHECKED` records the scope.

`pages` proves that a page follows from the artefacts. `coverage` and
`derived` cover whether the artefact is right about the driver, and neither
reads the driver source.

`stale` compares the recorded digest against the file on disk. Whether the
artefact is right about the driver is settled by `coverage` and `derived`, and
neither of those reads the driver source either.

`harnesses` reads the union of every `Harness` column in
`harnesses/TARGETS.md`. A harness carried by the replay table and absent from
the sanitizer table is outside what the check compares. It also says nothing
about whether a harness compiles or runs, and `build_all.sh` settles that on
the target machine.

`agents` reads the argument surface a command claims. It does not run the
command, so it says nothing about whether the tool succeeds, whether a required
argument the brief omits is supplied at run time, or whether the value behind a
placeholder is valid. Positional arguments are counted by neither the check nor
the parser it reads, because a brief writes them as placeholders.

Two tools a brief names declare no argparse parser and are resolved no further
than their file existing. `tools/build_kernel.sh` takes its inputs from the
environment. `tools/crashlog_ctl.py` reads `sys.argv` by hand, so its four
subcommands and its two flags are literals inside `main()` and no import
reaches them. `AGENT_TOOL_EXCLUSIONS` carries both with the reason, and the
check prints the pair on every run.

An exit code binds to the tool named most recently at or before the line that
states it. The briefs are written in that order, with the command block first
and the sentence after it saying what each code means. A brief that states a
code far from the command it belongs to binds it to the wrong tool.

The exit set covers every `return` and every `sys.exit` in the module. Reading
`main()` alone would miss the value a helper produces, so the set
over-approximates, and the check reports a code only when nothing anywhere in
the tool produces it.

## See also

- [syzlang_gen.py](/gspwn/architecture/components/syzlang-gen/)
- [surface_cov.py](/gspwn/architecture/components/surface-cov/)
- [refgen.py](/gspwn/architecture/components/refgen/)
- [trace2seed.py](/gspwn/architecture/components/trace2seed/)
- [Artifacts](/gspwn/reference/artifacts/)
