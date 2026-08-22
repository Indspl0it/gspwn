---
title: refgen.py
description: Renders the committed surface artefacts as the five reference pages under reference/surface/, deterministically, so CI can regenerate and diff them.
---

Turns the committed surface artefacts into the five pages under
`docs/src/content/docs/reference/surface/`. The site describes the tools that
enumerate the attack surface; without these pages a reader asking which escapes
exist, or where a given control command ranks, opens a 1.2 MB JSON file.

The module reads committed files only. It needs no GPU, no kernel, no network
and no driver source checkout, so it runs in CI on the same runner as the
offline self-test.

## Responsibility

The module owns the five generated pages and the determinism the CI `pages`
check depends on. It writes nothing outside `--out`.

| Invariant | Enforced by |
|---|---|
| Two runs over one artefact set produce byte-identical files | Every table is sorted on a key the page states, no value is read from the clock or the environment, and `write` opens each file with `newline="\n"` |
| A page names what it was generated from | `provenance()` writes the producing command, the artefact list from `PAGE_SOURCES`, and the check that guards the page, into every page |
| A page generated from an empty artefact is refused | `_need` requires the named array to exist and to hold at least one record, because such a page reads as a complete page and states nothing |
| The two CVE artefacts describe one population | `load_all` compares the disclosures `prior-cves.json` classifies `K` against the disclosures `cve-hotspots.json` mines, and names the difference in both directions |
| A patch-mining artefact of an unrecognised shape is refused | `load_all` requires `cve-hotspots.json` to carry schema `gspwn.cve-hotspots/1` |
| A multiplexer is never rendered without the field it dispatches on | `load_all` requires `comment_multiplexers.requests` in `tools/ioctl_map.json` |
| A half-written page never reaches the content directory | `write` writes a temp file in `--out` and calls `os.replace`, and unlinks the temp file on any exception, because a stray temp file inside the content directory is a page Starlight would try to build |

## Interface

| Command | Output |
|---|---|
| `refgen.py` | The five pages into `docs/src/content/docs/reference/surface`, then a page, records and bytes table |
| `refgen.py --out DIR` | The same five pages into `DIR` |
| `refgen.py -v` | Adds one log line per page with its byte count |

| Function | Returns |
|---|---|
| `load_all()` | Every artefact the five pages read, keyed by short name, with `targets`, `excluded` and `meta` from `surface_cov.load_targets()` |
| `render(docs=None)` | `({filename: text}, {filename: record count})`, fully deterministic |
| `write(pages, out_dir)` | The paths written, each written atomically with LF endings |
| `build_parser()` | The argument parser, split out of `main` so the defaults are readable without a run |
| `table(headers, rows)`, `code(value)`, `num(value)`, `cell(value)` | Markdown rendering helpers. Every driver identifier goes in a code span, which keeps `<any parent>` out of the markdown HTML parser and stops `register_check.py` reading an identifier as prose |

## Generated pages

| Page | Records | Sources |
|---|---|---|
| `escapes.md` | 37 | `surface/ioctl-inventory.json`, `tools/ioctl_map.json` |
| `control-commands.md` | 531 | `surface/rm-control-rank.json`, `rm-control-inventory.json`, `rm-object-graph.json` |
| `allocation-classes.md` | 253 | `surface/rm-object-graph.json`, `rm-chains.json` |
| `driver-cves.md` | 61 | `surface/prior-cves.json`, `cve-hotspots.json` |
| `index.md` | 4 | The four pages above, their record counts and their sources |

`PAGE_SOURCES` declares the per-page list and `provenance()` renders it, so the
sources a page names are the sources the check reads.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | `tools/regression_check.py`, for `render` and `write` in `check_pages`. `tools/selftest.py` |
| This module imports | `tools/surface_cov.py`, for `load_targets`, the artefact paths and `SURFACE_DIR` |

`surface_cov.py` is the only import. `pipeline_state.py` is deliberately
absent: it needs `fcntl`, which would stop both modules running on a Windows
workstation.

Nothing in CI runs `refgen.py` itself. `regression_check.py pages` regenerates
through `render` and `write` into a temporary directory and diffs against the
committed pages. CI checks the committed copies, and an editor runs the tool.

## Failure modes

| Condition | Behaviour | Exit |
|---|---|---|
| Every page written | The per-page records and bytes table | 0 |
| An artefact is absent or unparseable | `refgen: cannot run:` on stderr, naming the path and the label | 2 |
| An artefact is not a JSON object | The same, naming the path | 2 |
| A named array is absent or empty | The same, naming the artefact and the key, and stating that a page generated from it would state nothing | 2 |
| `cve-hotspots.json` carries an unrecognised schema stamp | The same, naming both stamps and the producing command | 2 |
| The classified and mined CVE sets differ | The same, naming the disclosures on each side | 2 |
| `tools/ioctl_map.json` carries no `comment_multiplexers.requests` block | The same, naming the file and the block | 2 |
| `surface_cov.load_targets()` raises `SurfaceError` | The same, carrying that module's message | 2 |

Exit 1 is not used. Every failure is an input this tool cannot read, and CI
fails on any non-zero code.

## Concurrency and durability

Reading is read-only and takes no lock. Each page is written to a temp file in
`--out` and renamed, so a reader opening a page during a run sees either the
old file or the new one. An interrupted run leaves no temp file: `write`
unlinks it on any exception, including `KeyboardInterrupt`.

Two concurrent runs into one directory can interleave their renames. Each
rename is atomic, and both runs produce the same bytes, so the result is the
same either way.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never edit a generated page by hand | `regression_check.py pages` regenerates and diffs, so a hand edit fails CI. A correction belongs in this tool or in the artefact |
| Never derive a value from the clock, the environment or an unordered iteration | The `pages` check compares bytes, so any of the three turns a clean tree into a CI failure |
| Never store a digest beside a page in place of regenerating it | Whoever edits a page is positioned to update the digest, and the digest of a stale page still matches itself |
| Never import `pipeline_state.py` | It needs `fcntl`, and this tool runs on a Windows workstation |
| Never render a page from an empty artefact | An empty table reads as a complete answer and states nothing |
| Never render a driver identifier outside a code span | Angle brackets reach the markdown HTML parser, and the register check reads the identifier as prose |

## Design notes

The five pages exist because the surface artefacts are the project's primary
reference and were readable only as JSON. The generator is the alternative to
hand-maintained tables, which drift against the artefacts with no check able to
say so.

Determinism makes the CI check possible. A digest committed beside a page
cannot distinguish a stale page from an edited one, so the check regenerates,
and regenerating is only a check if the output cannot move on its own.

Regenerating through `refgen.write` covers the writer as well as the renderer,
which comparing rendered strings would miss. A page written with the platform's
native line endings differs from the committed LF copy, which is a real defect
the repository's `.gitattributes` exists to prevent.

`driver-cves.md` joins two artefacts. `prior-cves.json` classifies each
disclosure and carries NVIDIA's bulletin sentence; `cve-hotspots.json` carries
what reading the fixing diff established, per disclosure. A CVE row without the
join states a weakness class and no location in the driver. The per-disclosure
function list is rendered for the 8 disclosures the mining narrowed; for the
other 53 the artefact's own verdict says the diff attributes no hunk to any one
disclosure, so the page states the verdict, the shared patch set, and how many
entry points that patch set touched.

`load_all` compares the two CVE populations before rendering because
`cve_patch_map.py` reads `prior-cves.json` to choose what to mine. A divergence
means one artefact was regenerated and the other was not, and the joined table
would drop or invent rows without saying so.

## Regenerating after a driver bump

The pages sit at the end of the extraction chain, so they are regenerated last.

1. Regenerate the artefacts, in dependency order.

   ```
   python3 tools/ioctl_inventory.py --src artifacts/src/open-gpu-kernel-modules
   python3 tools/ctrl_surface.py --src artifacts/src/open-gpu-kernel-modules
   python3 tools/object_graph.py extract --src artifacts/src/open-gpu-kernel-modules
   python3 tools/object_graph.py chains
   python3 tools/ctrl_rank.py rank
   ```

2. Regenerate the pages.

   ```
   python3 tools/refgen.py
   ```

3. Confirm the committed copies match.

   ```
   python3 tools/regression_check.py pages
   ```

Step 3 exits 1 whenever step 2 was skipped, so a bump that moves an artefact
and leaves the pages behind fails CI in the step whose title names the pages.

## Stated limits

| Limit | Consequence |
|---|---|
| Nothing in CI runs this tool | `pages` regenerates through the module and diffs, which catches a stale page. Producing the page is still an editor's step |
| The tool reads artefacts and never the driver source | A page follows from the artefacts it names. `coverage` and `derived` cover whether the artefacts follow from the driver |
| The record counts on `index.md` come from `render` | A builder that returned the wrong count would report the wrong count consistently, and the `pages` check compares bytes and not counts |

## See also

- [regression_check.py](/gspwn/architecture/components/regression-check/)
- [surface_cov.py](/gspwn/architecture/components/surface-cov/)
- [Enumerated surface](/gspwn/reference/surface/)
- [Artifacts](/gspwn/reference/artifacts/)
