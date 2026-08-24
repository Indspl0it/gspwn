---
title: selftest.py
description: The offline suite, its isolation model, and its coverage limits.
---

The offline self-test for the deterministic tools. Standard library `unittest`,
no GPU, no kernel build, no root. 204 test classes carrying 1594 tests.

CI runs it on every push and pull request, alongside the lint, the shell syntax
check, the shipped-configuration check, the ten
[`regression_check.py`](/gspwn/architecture/components/regression-check/)
checks and a prompt-consistency check.

## Verified areas

| Area | Verified |
|---|---|
| State machine | The schema and its normalisation, the round and phase machines, and the refusal to advance a round with an unfinished phase |
| Durability | Atomic write, the backup file, and the transaction lock |
| Spend | Idempotent billing per run id, the machine-global fallback, and the refusal when the ledger is absent while hours are recorded |
| Completion ledger | Accounting and un-accounting a target, the deferred reason that does not close one, the denominator version stamped on a round, and the refusal to close on a repeated row |
| Crash identity | Title canonicalisation, stack hashing, the frameless signature, flagging, and re-scan idempotency |
| Configuration | Every cross-field validation rule, and agreement between the shipped defaults and the code defaults |
| Coverage model | Accumulation, the tail fit, the Heaps fit, the surface curve, and each `unknown` case |
| Campaign management | Deadline reconstruction, the overlap guard, corpus policy and seed packing |
| Reproduction | The verdict rules, the recovery path after a panic, and the attempt cap |
| Orchestrator | The circuit breaker, session resolution and rotation, the stall timeout, and the generated systemd units |
| Description generation | Struct size verification, selector pinning, the parent-set split, the value-family emission, and the `drm` and `modeset` families |
| Surface measurement | The 852-target denominator, the per-family floor, and the variant scan over corpus text |
| Seed conversion | The `strace` to syz-program conversion, and the chain-shaped programs |
| Command line | `pipeline_ctl.py` end to end |

## Isolation

A test run must not touch a real campaign, because the machine running the
tests may be a campaign box. Every persistent path `pipeline_state` can write
is redirected into a temporary directory at module level, and the spend ledger
is redirected explicitly because it does not follow `GSPWN_STATE`. Redirecting
the state file alone would leave the suite billing hours against the real
`state/spend.json`, which gates live campaigns.

Each test creates its own temporary directory and registers cleanup, so tests
do not leak state into each other within a run, and the suite writes nothing
outside those directories.

## Design decisions

| Rule | Rationale |
|---|---|
| Never write to a real state file, ledger, breaker or knowledge directory | Running the tests on a campaign box would inject phantom hours into the ledger that gates live campaigns |
| Never hand-write a CSV row | Fixtures are built from the schema constant. Hand-written comma strings silently shifted every value one column left when a field was added |
| Never reimplement a tool's logic in a test | A test that chooses the schema itself passes regardless of what the tool does, and mutating the tool produces zero failures |
| A test exercises the tool, never a stand-in for it | Assertions call the tool and capture its printed output, so a changed message is caught |

A `syz-db` stand-in packs and unpacks a directory of programs through a JSON
blob, which makes the seed-injection path, the corpus carry and the promotion
ledger testable without a syzkaller build.

## Coverage limits

Anything touching the machine under test: kernel builds, live systemd units,
pstore and kdump harvesting, and real reproduction. Those are exercised by the
phase gates on the target machine.

`build_kernel.sh` has no offline test by design. Stubbing `make`,
`scripts/config`, `sudo`, `update-grub`, `grub-editenv`, `mokutil` and `depmod`
would test the stubs.

## See also

- [regression_check.py](/gspwn/architecture/components/regression-check/)
- [Durability](/gspwn/architecture/durability/)
