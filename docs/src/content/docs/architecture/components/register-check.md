---
title: register_check.py
description: The writing-register linter over the documentation tree, and the exemption record for verbatim reproductions.
---

Checks documentation prose against the project's writing register and exits 1
on any non-exempt hit. It runs as the last step of the `selftest` CI job.

The register bans a family of constructions a read-through does not reliably
catch, because they scan as labels. Question-shaped section headings and
question-shaped table column headers are the clearest case: one reference table
carried the latter ten times before this check existed.

## Scope

| Root | Suffixes |
|---|---|
| `docs/src/content/docs` | `.md`, `.mdx`, `.astro` |
| `docs/src/components` | `.md`, `.mdx`, `.astro` |

Passing paths on the command line checks those files alone. With no arguments
it walks both roots.

## Checked constructions

| Family | Examples |
|---|---|
| Typography | em dash, en dash, curly quotes |
| Contrastive constructions | `rather`, `instead of`, `as opposed to`, `not just`, `not only`, and the appositive form `, not the segment,` |
| Addressing the reader | `you`, `your`, `we`, `our`, `let's` |
| Filler openers | `In order to`, `Additionally`, `Furthermore`, `It is worth noting` |
| Copula avoidance | `serves as`, `stands as`, `acts as`, `represents a`, `functions as` |
| Marketing adjectives | `crucial`, `robust`, `seamless`, `comprehensive`, `leverage`, `delve` |
| Meta-commentary | `as noted above`, `in other words`, `that said`, `this section covers` |
| Named Claude-family tells | `load-bearing`, `worth stating`, `carry the argument`, `full stop`, `the trap is`, `quietly`, `matters more` |
| Cleft constructions | `is what`, `are what`, `is how` |
| Question shapes | Section headings and markdown table column headers phrased as questions |
| Emoji | The pictographic ranges |

Patterns match across one line break, because prose in the documentation tree
wraps at 80 columns and a construction split by the wrap is the same
construction. The reported line number is the line the construction starts on.

## Reproductions are not prose

`strip_exempt_regions` removes `<style>` and `<script>` elements, fenced code
blocks and inline code spans before any pattern runs. Everything inside a code
span is a reproduction: a path, a command, or a string literal the program
prints. Documentation has to match what the program actually prints, so a
banned construction inside quoted tool output is a fact about the tool.

An inline code span is replaced by a marker character of the same width, never
deleted, so the cleft pattern can tell `the one \`identifier\`` from `the
one command`. The marker is `\x01`: it cannot occur in a documentation file, it
is not a word character, and it is not whitespace.

Where the register of real output is wrong, the fix belongs in the source as a
separate change. The check reports it, and never edits the quote.

## Exemptions

`EXEMPT` maps a path suffix to a rule name, a tuple of rule names, or `*`, each
with the reason it is exempt. `project/faq.md` is exempt from the two question
rules, because a genuine question-and-answer page has questions as its
structure, and the register rule exempts that shape explicitly.

An exemption carries its reason in the same entry, so a later reader can judge
whether it still holds.

## Exit codes

| Code | Condition |
|---|---|
| 0 | No non-exempt hit |
| 1 | At least one hit, each reported with its file, line, rule and surrounding text |

The summary line reports the file count and the hit count.

## Callers

| Direction | Modules |
|---|---|
| Imports this module | Nothing |
| Invokes it | `.github/workflows/selftest.yml`, as the last step after the seven `regression_check.py` subcommands |

## Limits

The check covers the greppable subset of the register. Three defects need
reading, because no pattern catches them: sentence fragments used for drama, a
semicolon standing in for a conjunction, and an opening paragraph that
announces its section without stating a fact.

`is where` is deliberately absent from the cleft family, because it has a
literal locative use. `is the one` carries both a determiner sense meaning "the
only" and a cleft sense, and the pattern separates them by what follows.

## See also

- [Contributing](/gspwn/project/contributing/)
- [`regression_check.py`](/gspwn/architecture/components/regression-check/)
