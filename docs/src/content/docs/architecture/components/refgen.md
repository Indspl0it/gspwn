---
title: refgen.py
description: Renders the committed surface artefacts as the seven reference pages under reference/surface/, deterministically, so CI can regenerate and diff them.
---

Turns the committed surface artefacts into the six content pages and the
index over them, under
`docs/src/content/docs/reference/surface/`. Without these pages a reader asking
which escapes exist, or where a given control command ranks, opens a 1.2 MB
JSON file.

The module reads committed files only. It needs no GPU, no kernel, no network
and no driver source checkout, so it runs in CI on the same runner as the
offline self-test.

## Responsibility

The module owns the seven generated pages and the determinism the CI `pages`
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

## Generated pages

Six content pages and the index over them are rendered from a declared set of
artefacts.

| Page | Records | Sources |
|---|---|---|
| `escapes.md` | 37 | `surface/ioctl-inventory.json`, `tools/ioctl_map.json` |
| `control-commands.md` | 531 | `surface/rm-control-rank.json`, `rm-control-inventory.json`, `rm-object-graph.json` |
| `allocation-classes.md` | 253 | `surface/rm-object-graph.json`, `rm-chains.json` |
| `driver-cves.md` | 61 | `surface/prior-cves.json`, `cve-hotspots.json` |
| `modeset-commands.md` | 66 | `surface/nvkms-command-inventory.json` |
| `drm-commands.md` | 28 | `surface/drm-command-inventory.json` |
| `index.md` | 6 | Every source above, plus `surface/entry-points.json` for the entry-point census |

Every page carries its own provenance: the command that produced it, the
artefacts it was rendered from, and the check that guards it. The per-page
source list is declared once and rendered into the page, so the sources a page
names are the sources the check reads.

Nothing in CI runs the generator itself. A CI check regenerates the pages
into a temporary directory and diffs them against the committed set.

## Refusal conditions

A page that reads as complete and states nothing is worse than no page, so the
generator refuses to write one. An artefact that is absent, unparseable, or
carrying an unrecognised schema stamp stops the run with the path and the
producing command named. So does an array that is present and empty, and so
does a disagreement between the two CVE artefacts, which describe one
population and would otherwise silently drop or invent rows.

Every failure is an input the tool cannot read, so there is one failure code
and no partial output.

## Concurrency and durability

Reading is read-only and takes no lock. Each page is written to a temp file in
`--out` and renamed, so a reader opening a page during a run sees either the
old file or the new one. An interrupted run leaves no temp file: `write`
unlinks it on any exception, including `KeyboardInterrupt`.

Two concurrent runs into one directory can interleave their renames. Each
rename is atomic, and both runs produce the same bytes, so the result is the
same either way.

## Prohibited behaviour

Six rules hold. The first three follow from the `pages` check regenerating the
output and comparing bytes.

| Rule | Rationale |
|---|---|
| Never edit a generated page by hand | `regression_check.py pages` regenerates and diffs, so a hand edit fails CI. A correction belongs in this tool or in the artefact |
| Never derive a value from the clock, the environment or an unordered iteration | The `pages` check compares bytes, so any of the three turns a clean tree into a CI failure |
| Never store a digest beside a page in place of regenerating it | Whoever edits a page is positioned to update the digest, and the digest of a stale page still matches itself |
| Never import `pipeline_state.py` | It needs `fcntl`, and this tool runs on a Windows workstation |
| Never render a page from an empty artefact | An empty table reads as a complete answer and states nothing |
| Never render a driver identifier outside a code span | Angle brackets in a name like `<any parent>` otherwise reach the markdown HTML parser |

## Design notes

The generator is the alternative to hand-maintained tables, which drift against
the artefacts with no check able to say so.

Regenerating through `refgen.write` covers the writer as well as the renderer,
which comparing rendered strings would miss. A page written with the platform's
native line endings differs from the committed LF copy, which is a real defect
the repository's `.gitattributes` exists to prevent.

`driver-cves.md` joins two artefacts. `prior-cves.json` classifies each
disclosure and carries NVIDIA's bulletin sentence. `cve-hotspots.json` carries
what reading the fixing diff established, per disclosure. A CVE row without the
join states a weakness class and no location in the driver. The per-disclosure
function list is rendered for the 8 disclosures the mining narrowed. For the
other 53 the artefact's own verdict says the diff attributes no hunk to any one
disclosure, so the page states the verdict, the shared patch set, and how many
entry points that patch set touched.

`load_all` compares the two CVE populations before rendering because
`cve_patch_map.py` reads `prior-cves.json` to choose what to mine. A divergence
means one artefact was regenerated and the other was not, and the joined table
would drop or invent rows without saying so.

## Position in the extraction chain

The pages are last in the chain, so they are regenerated last. The five
inventories come first, then `rm-chains.json`, then the ranking that reads it,
then the pages.

| Order | Artefact | Produced by |
|---|---|---|
| 1 | `surface/ioctl-inventory.json` | `tools/ioctl_inventory.py` |
| 1 | `surface/rm-control-inventory.json` | `tools/ctrl_surface.py` |
| 1 | `surface/rm-object-graph.json` | `tools/object_graph.py extract` |
| 1 | `surface/nvkms-command-inventory.json` | `tools/nvkms_inventory.py` |
| 1 | `surface/drm-command-inventory.json` | `tools/drm_inventory.py` |
| 2 | `surface/rm-chains.json` | `tools/object_graph.py chains`, over the control inventory |
| 3 | `surface/rm-control-rank.json` | `tools/ctrl_rank.py`, over the control inventory, `rm-chains.json`, `cve-hotspots.json` and `ctrl-param-sizes.json` |
| 4 | The six pages and their index | `tools/refgen.py` |

A bump that moves an artefact and leaves the pages behind fails CI in the step
whose title names the pages.

## Stated limits

Three limits apply to what a generated page settles.

- Nothing in CI runs this tool. `pages` regenerates through the module and
  diffs, which catches a stale page. Producing the page is still an editor's
  step.
- The tool reads artefacts and never the driver source. A page follows from
  the artefacts it names, and `coverage` and `derived` cover whether the
  artefacts follow from the driver.
- The record counts on `index.md` come from `render`. A builder that returned
  the wrong count would report the wrong count consistently, and the `pages`
  check compares bytes and not counts.

## See also

- [surface_cov.py](/gspwn/architecture/components/surface-cov/)
- [Enumerated surface](/gspwn/reference/surface/)
