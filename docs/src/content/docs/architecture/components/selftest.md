---
title: selftest.py
description: The offline suite, its isolation model, and its coverage limits.
---

The offline self-test for the deterministic tools. Standard library `unittest`,
no GPU, no kernel build, no root. Fifty-six test classes.

`.github/workflows/selftest.yml` runs it on every push and pull request,
alongside pyflakes, `bash -n`, the configuration check and the
prompt-consistency check.

## Responsibility

The suite owns the offline verification of the deterministic tools and the
isolation that keeps a test run from touching a real campaign.

| Invariant | Enforced by |
|---|---|
| A test run cannot write real state | `StateTempMixin` redirects `STATE_PATH`, `DEFAULT_STATE_PATH` and `SPEND_PATH` at module level into a temporary directory |
| The spend ledger is redirected explicitly | The ledger does not follow `GSPWN_STATE`, so redirecting the state file alone would leave the suite writing the real `state/spend.json` |
| The fail-closed fallback is redirected too | `DEFAULT_STATE_PATH` is what `spend_for_budget` reads when the ledger is absent |
| A CSV fixture matches the current schema | Fixtures are built from `coverage_ctl.FIELDS` |
| A test exercises the tool itself | Assertions call the tool and capture its output |
| Corpus paths are testable without syzkaller | A `syz-db` stand-in packs and unpacks a directory of programs through a JSON blob |

## Coverage

The state schema and its durability contract, the round and phase machines, the
spend ledger, crash dedup and flagging, configuration validation including every
cross-field rule, the coverage model and each `unknown` case, campaign
management, the reproduction verdict rules and recovery path, the orchestrator
breaker and session resolution, the strace conversion, the `pipeline_ctl.py`
command line end to end, and the generated systemd units.

## Coverage limits

Anything touching the machine under test: kernel builds, live systemd units,
pstore and kdump harvesting, and real reproduction. Those are exercised by the
phase gates on the target machine.

`build_kernel.sh` has no offline test by design. Stubbing `make`,
`scripts/config`, `sudo`, `update-grub`, `grub-editenv`, `mokutil` and `depmod`
would test the stubs.

## Interface

Run the suite with `python3 tools/selftest.py`. It reports through the standard
`unittest` runner and exits non-zero on any failure.

| Helper | Purpose |
|---|---|
| `StateTempMixin` | Redirects every persistent path `pipeline_state` can write |
| `csv_line(ts, edges=None, source='test', gpu='ok', **extra)` | Builds a coverage row from `coverage_ctl.FIELDS` |
| `FAKE_SYZ_DB` | The `syz-db` stand-in used by the corpus and seed tests |

## Callers

| Direction | Modules |
|---|---|
| Invokes this module | `.github/workflows/selftest.yml`, and `AGENTS.md` requires it after any change to the tools |
| This module imports | Every deterministic module in `tools/`, with `pipeline_ctl` deferred into a wrapper function |

## Failure modes

| Condition | Behaviour |
|---|---|
| Any test fails | The runner reports the failure and the process exits non-zero |
| A tool's printed message changes | The tests that capture standard output fail |
| A field is added to `coverage_ctl.FIELDS` | Fixtures pick it up, since they are generated from the constant |
| A test leaves temporary state behind | `addCleanup` restores every redirected module attribute and removes the temporary directory |

## Concurrency and durability

Each test creates its own `TemporaryDirectory` and registers cleanup through
`addCleanup`, so tests do not leak state into each other within a run. The
`pipeline_state` paths are redirected by module attribute, which makes the
redirection effective for modules that already imported the constant. The suite writes nothing outside its temporary
directories, so it is safe to run on a campaign box.

## Prohibited behaviour

| Rule | Rationale |
|---|---|
| Never write to a real state file, ledger, breaker or knowledge directory | Running the tests on a campaign box would inject phantom hours into the ledger that gates live campaigns |
| Never hand-write a CSV row | Hand-written comma strings silently shifted every value one column left when a field was added |
| Never reimplement a tool's logic in a test | A test that chooses the schema itself passes regardless of what the tool does, and mutating the tool produces zero failures. That failure is recorded in `knowledge/mistakes.md` as a process error |
| Never import `pipeline_ctl` at module scope | Its argument parser reads configuration at build time, so the import is deferred into a wrapper function |

## Design notes

The `syz-db` stand-in packs and unpacks a directory of programs through a JSON
blob. That is what lets the seed-injection path, the corpus carry and the
promotion ledger be tested without building syzkaller.

Where a test asserts on printed output, it captures standard output, so a change
to the message is caught.

## See also

- [selftest.py reference](/gspwn/reference/cli/selftest/)
- [Development](/gspwn/project/development/)
