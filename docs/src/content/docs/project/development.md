---
title: Development
description: The local checks, the Windows path through WSL, and the CI steps.
---

Every check runs offline: no GPU, no kernel build, no root, no network.

## The five checks

```
python3 tools/selftest.py
python3 -m pyflakes tools/*.py
bash -n tools/build_kernel.sh
python3 tools/gspwn_config.py
python3 tools/register_check.py
```

| Check | Catches | Expected result |
|---|---|---|
| `selftest.py` | Behaviour regressions across every tool | Ends with `OK`, exit status 0 |
| `pyflakes` | Undefined names, bad imports, unused imports left by a deletion | No output, exit status 0 |
| `bash -n` | Syntax errors in the build script, which has no offline test | No output, exit status 0 |
| `gspwn_config.py` | A shipped configuration that no longer validates | The effective configuration and the stopping rules, exit status 0 |
| `register_check.py` | Documentation prose that breaks the writing register | A file and hit count, exit status 0 |

`AGENTS.md` requires the first of these after any change to the tools, before
their output is trusted.

## Dependencies

| Component | Requires |
|---|---|
| The tools | Python 3 and PyYAML. Everything else is standard library |
| The checks | `pyflakes` in addition |
| The documentation site | Node, confined to `docs/` |

```
python3 -m pip install pyyaml pyflakes
```

## The prompt-consistency check

CI parses `tools/<x>.py <subcommand> --flag` out of the prose files and
verifies each against the tool's real `--help` output.

| Scanned | Contents |
|---|---|
| `agents/*.md` | The twelve sub-agent definitions |
| `AGENTS.md` | The orchestrator contract |
| `docs/src/content/docs/` | Every documentation page |

The sub-agent definitions are the interface between the orchestrator and the
tools. A renamed subcommand that a definition still references fails at run
time on the machine under test, part-way through a campaign. A command example
in the documentation that names a flag no longer accepted fails the build.

```
checked 42 subcommands, 84 flag uses
```

## The writing-register check

`tools/register_check.py` reads every page under `docs/src/content/docs/` and
every component under `docs/src/components/`, and fails the build on the
constructions the writing register bans.

| Category | Examples |
|---|---|
| Question-shaped headings | `## What the build phase pins`, `## Where to go next` |
| Question-shaped table columns | `| Key | What it controls |`, `| Change | Why it is refused |` |
| Contrastive constructions | `rather than`, `instead of`, `not only X`, `X, not the Y,` |
| Typographic tells | Em dashes, en dashes, curly quotes, emoji |
| Register tells | Second person, filler openers, copula avoidance, marketing adjectives |

The heading and column categories are the reason the check exists. Both scan as
labels during a read-through, and one reference table carried the same
question-shaped column header ten times before the check was written.

Code is skipped: fenced blocks, inline code spans, and the style and script
blocks in a component. Everything in a code span is a reproduction, so a
message the tool prints keeps whatever wording the tool uses. Skipped regions
are blanked in place so the reported line numbers still match the file.

A banned construction inside quoted tool output is a defect in the tool. Editing
the page there would make the documentation disagree with what the program
prints.

Exemptions are listed in `EXEMPT` at the top of the tool, each with its reason.
An exemption names a file and one category, so the rest of the categories still
apply to that file.

| Exempt | Category | Reason |
|---|---|---|
| `project/faq.md` | All | A question-and-answer page. Questions are its structure. |
| `project/changelog.md` | Contrastive | Entries quote commit subjects as running text |
| `components/ThemeProvider.astro` | Contrastive | A source comment, not prose for a reader |
| `knowledgebase/gsp-offload.mdx` | Marketing adjective | `robust channel` is NVIDIA's name for the mechanism |
| `knowledgebase/scheduling.mdx` | Marketing adjective | The same term |

```
register_check: 116 file(s), 0 hit(s)
```

## Working on Windows

The tools are Linux-only: `pipeline_state.py` locks with `fcntl.flock`, and
several tools generate systemd units. Development on Windows goes through WSL.

```
wsl -d Ubuntu-24.04
cd /mnt/c/path/to/gspwn
python3 tools/selftest.py
```

| Condition | Effect | Handling |
|---|---|---|
| Line endings | A CRLF checkout breaks the shell scripts. A carriage return in a shebang fails as `bad interpreter: /bin/bash^M` | `.gitattributes` normalises everything to LF on checkout |
| Shell quoting | Git Bash on Windows expands `$var` before it reaches WSL | Escape it as `\$var` inside a `wsl -- bash -lc '...'` invocation |

## Running against a scratch state file

```
GSPWN_STATE=/tmp/scratch/pipeline.json python3 tools/pipeline_ctl.py init
```

| Component | Follows `GSPWN_STATE` |
|---|---|
| The state file | Yes |
| The spend ledger | No |
| The orchestrator breaker | No |
| The reproduction lock | No |

See [Environment variables](/gspwn/reference/environment/).

## Working on the documentation

The site is Astro Starlight, confined to `docs/` with its own `package.json`.
It is never in the Python tool path, and `selftest.yml` is untouched by it.

1. Install the dependencies and start the dev server.

   ```
   cd docs
   npm ci
   npm run dev
   ```

2. Build before opening a pull request.

   ```
   npm run build
   ```

   Exit status 0. The build fails on a broken internal link or a missing
   heading anchor.

## Verifying the generated units

1. Install the unit.

   ```
   sudo python3 tools/campaign_ctl.py install-k --run-id test-1
   ```

2. Verify it.

   ```
   systemd-analyze verify /etc/systemd/system/gspwn-k.service
   ```

`systemd-analyze verify` catches an unknown key in a section, which is silently
ignored at run time. `StartLimit*` under `[Service]` is an instance of that
failure mode.

## Seam verification after a batch of changes

A change that touches three or more files or moves a module boundary needs a
wider pass than the per-file checks. Defects appear where one file assumes
another's API has not changed.

1. Lint the whole package, because the breakage is in the callers.
2. Check that nothing still imports a deleted symbol.
3. Run the whole suite.
4. Run the configuration check, because a removed key is only visible there.

## CI workflow steps

`.github/workflows/selftest.yml` runs on every push to `main` and on every pull
request:

| Step | Command |
|---|---|
| Dependencies | `pip install pyyaml pyflakes` |
| Offline self-test | `python3 tools/selftest.py` |
| Lint | `python3 -m pyflakes tools/*.py` |
| Shell syntax | `bash -n tools/build_kernel.sh` |
| Documentation writing register | `python3 tools/register_check.py` |
| Configuration | `python3 tools/gspwn_config.py` |
| Prompt consistency | The `--help` cross-check above |

`.github/workflows/docs.yml` builds the site on every pull request that touches
`docs/`, and deploys it to GitHub Pages on a push to `main`.

Everything in CI is offline. Anything that touches the machine under test is
covered by the phase gates on that machine.

## See also

- [Contributing](/gspwn/project/contributing/)
- [Extending gspwn](/gspwn/architecture/extending/)
