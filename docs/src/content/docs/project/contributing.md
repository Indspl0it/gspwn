---
title: Contributing
description: Branch and commit conventions, the pull request procedure, and the CI checks.
---

## Before starting

| Page | Covers |
|---|---|
| [Extending gspwn](/gspwn/architecture/extending/) | The five extension points |
| [Development](/gspwn/project/development/) | The local checks and the WSL path |

## Branch and commit

| Convention | Requirement |
|---|---|
| Base branch | `main`, which the documentation site deploys from |
| Mood | Imperative |
| Prefix taxonomy | None |
| Defect fixes | State what the defect produced, so a later reader can identify a recurrence |

The existing history is the reference:

```
Stop a dead GPU from reading as a plateau
Keep two different faults from merging into one bug
Run the orchestrator unit as the operator, not as root
```

## Pull request procedure

1. Run the offline suite.

   ```
   python3 tools/selftest.py
   ```

   Ends with `OK`, exit status 0.

2. Lint the package.

   ```
   python3 -m pyflakes tools/*.py
   ```

   No output, exit status 0.

3. Check the build script's syntax.

   ```
   bash -n tools/build_kernel.sh
   ```

   No output, exit status 0.

4. Validate the shipped configuration.

   ```
   python3 tools/gspwn_config.py
   ```

   Prints the effective configuration and the stopping rules, exit status 0. A
   rejected value exits 1 with `error:` and the failing key.

5. Build the site when the change touches `docs/`.

   ```
   cd docs && npm ci && npm run build
   ```

   Exit status 0. A broken internal link or a missing heading anchor fails the
   build.

## CI checks

`.github/workflows/selftest.yml` runs on every push to `main` and on every pull
request.

| Check | Fails on |
|---|---|
| Offline self-test | A behaviour regression in any tool |
| Lint | An undefined name, a bad import, or an unused import left by a deletion |
| Shell syntax | A syntax error in `build_kernel.sh` |
| Configuration | A shipped configuration that no longer validates |
| Prompt consistency | A command example naming a subcommand or flag the tool does not accept |

The prompt-consistency check scans `agents/*.md`, `AGENTS.md` and every page
under `docs/src/content/docs/`, so every command example on the site is
verified against the tools' real `--help` output.

`.github/workflows/docs.yml` builds the site on every pull request that touches
`docs/`, and deploys it to GitHub Pages on a push to `main`.

## Tests

Tests go in `tools/selftest.py`, alongside the class they belong with. The
suite is standard library `unittest`, offline, with every persistent path
redirected to a temporary directory.

| Rule | Reason |
|---|---|
| Exercise the real entry point | A test that reproduces the tool's logic by hand chooses the schema itself and passes whatever the tool does |
| Confirm the test can fail | Break the implementation on purpose and confirm the test catches it. A test never seen to fail is unverified |
| Build fixtures from the module's own constants | Coverage rows come from `coverage_ctl.FIELDS`. A hand-written comma string shifts every value one column left when a field is added |

## Adding a configuration key

All four steps are in `tools/gspwn_config.py`:

1. Add the default to `DEFAULTS`, under the section it belongs to.
2. Add a validator to `_RULES`.
3. Add a cross-field rule to `validate()` when the key constrains another.
4. Document it in [Configuration keys](/gspwn/reference/configuration/).

Then confirm the key resolves:

```
python3 tools/gspwn_config.py
```

The new key appears in the effective configuration, exit status 0.

The validator's message is the whole error a researcher sees, so it states what
the value must be and what goes wrong otherwise.

## Documentation changes

Pages live in `docs/src/content/docs/`. The navigation is an explicit array in
`docs/astro.config.mjs`, and adding a page means adding it there.

| Rule | Requirement |
|---|---|
| Tense and voice | Present tense, active voice, imperative for procedures |
| Headings | Sentence case |
| Terms | Every project-specific term defined at first use and in the glossary |
| Internal links | Absolute, with a trailing slash: `/gspwn/section/page/` |
| Configuration keys | Section-qualified: `loop.campaign_hours` |
| Command examples | Runnable and copy-pasteable |
| Scope | No documentation of behaviour absent from the code |
| Form | Tables for reference, prose for concepts, numbered steps for tasks |

## Changes requiring discussion

| Area | Consequence of changing it |
|---|---|
| The dedup depth defaults | They decide what reaches `rca`, and changing them mid-campaign corrupts a registry |
| The plateau threshold defaults | They decide whether another campaign runs |
| `poc.reliable_threshold` | A disclosure package is built on that label |
| The threat model | Scope decisions follow from it |
| The state schema | Every tool reads it, and existing registries must keep working |

## Security issues

Do not open a public issue for a vulnerability in a target, and do not record
one in `knowledge/`. See [Security and disclosure](/gspwn/project/security/).

## Licence

MIT. Contributions are made under the same terms. See
[Licence](/gspwn/project/license/).
