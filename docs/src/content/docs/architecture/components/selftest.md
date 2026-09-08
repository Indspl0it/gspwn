---
title: selftest.py
description: The offline suite, its isolation model, and its coverage limits.
---

The offline self-test for the deterministic tools. Standard library
`unittest`, no GPU, no kernel build, no root, no network. Run it as
`python3 tools/selftest.py`, which takes `-v` and nothing else. 250 test
classes carry 1595 tests.

## Continuous integration

`.github/workflows/selftest.yml` runs on every pull request and on a push to
`main`, in one Ubuntu job with Python 3.11, `pyyaml` and `pyflakes`.

| Step | Command |
|---|---|
| Offline self-test | `python3 tools/selftest.py` |
| Lint | `python3 -m pyflakes tools/*.py` |
| Shell syntax | `bash -n tools/build_kernel.sh` |
| Shipped config is valid | `python3 tools/gspwn_config.py` |
| Thirteen checks over the committed artefacts | `python3 tools/regression_check.py <check>` for `names`, `pins`, `coverage`, `derived`, `reach`, `families`, `pages`, `stale`, `harnesses`, `agents`, `figures`, `citations` and `commands` |
| Documentation writing register | `python3 tools/register_check.py` |
| Prompts reference commands that exist | An inline script that parses every `tools/*.py` invocation in `agents/*.md`, `AGENTS.md`, the documentation tree and `README.md`, and checks each subcommand and flag against the tool's own `--help` |

## Verified areas

| Area | Verified |
|---|---|
| State machine | The schema and its normalisation, the round and phase machines, the worklist handoff, and the refusal to advance a round with an unfinished phase or a live campaign |
| Durability | Atomic write, the backup file, the transaction lock, the build manifest surviving an interrupt, and the leftovers an interrupted run reports |
| Spend and budget | Idempotent billing per run id, the machine-global fallback, the budget guard, and disk headroom |
| Completion ledger | Accounting and un-accounting a target, the deferred reason that does not close one, the denominator version stamped on a round, and the refusal to close on a repeated row |
| Crash identity | Title canonicalisation, stack hashing, the frameless signature, Xid classification, bulk triage decisions, flagging, and re-scan idempotency |
| Configuration | Every cross-field validation rule, and agreement between the shipped defaults and the code defaults |
| Coverage model | Accumulation, the tail fit, the Heaps fit, the surface curve, the two-curve stop rule, the GPU-health gate, and each `unknown` case |
| Campaign management | Deadline reconstruction, the overlap guard, corpus policy, corpus promotion and seed packing |
| Reproduction | The verdict rules, the recovery path after a panic, the attempt cap, the refusal during a live campaign, and the stale-binary rebuild |
| Orchestrator | The circuit breaker, session resolution and rotation, the stall timeout, and the generated systemd units |
| Findings and impact | The finding class, the requirement that a finding steers somewhere, the impact record, CWE derivation, and the analysis stamp outliving the `poc` phase |
| Description generation | Struct size verification, selector pinning, the parent-set split, the bitfield and enum member parse, the function-pointer typedef, the value-family rules and their audit round trip, and the `drm` and `modeset` families |
| Header inventories | The ioctl inventory parse, the NVKMS enum and dispatch scrapes and their cross-check, the DRM node scrape, the modeset request numbering, the entry-point artefact, and the UVM ordering measurement |
| Object graph and ranking | The parent map, narrow parent expansion, the chain walk terminating, cumulative reach, and control-rank scoring |
| Surface measurement | The 852-target denominator, the per-family floor, the shrinking-denominator alarm, and the variant scan over corpus text |
| Seed conversion | The `strace` to syz-program conversion, the ioctl map key format and name resolution, the traced multiplexer, and the chain-shaped programs |
| Track U | Coverage and corpus counting, the replay report reader, input layouts, the harness target lists, and the assertion that Track U does not use the GPU |
| Tenant surface | The tenant comparison, the injection path, the `--gpus` flag boundary, and the artefact error cases |
| Generated pages and CI checks | Refgen determinism and its rendered counts, the `pages` drift check, the register check across a line wrap, the prompt check, the documented check order, and the absence of an absolute path in any committed artefact |
| Command line | `pipeline_ctl.py` end to end, plus the surface un-account, completion, compile and verbose-placement paths |

## Isolation

A test run must not touch a real campaign, because the machine running the
tests may be a campaign box. `StateTempMixin.setUp` gives each test its own
temporary directory and redirects three `pipeline_state` module attributes
into it: `STATE_PATH`, `DEFAULT_STATE_PATH` and `SPEND_PATH`. Cleanup is
registered at the same time, so the previous values are restored when the test
ends.

All three redirects are needed. The spend ledger does not follow
`GSPWN_STATE`, so redirecting the state file alone would leave the suite
billing hours against the real `state/spend.json`, which gates live campaigns.
`DEFAULT_STATE_PATH` is the fail-closed fallback `spend_for_budget` reads when
the ledger is absent. Classes that exercise `knowledge_ctl` redirect
`KNOWLEDGE_DIR` into their own temporary directory the same way.

## Design decisions

| Rule | Rationale |
|---|---|
| Never write to a real state file, ledger, breaker or knowledge directory | Running the tests on a campaign box would inject phantom hours into the ledger that gates live campaigns |
| Never hand-write a CSV row | `csv_line` builds fixtures from `coverage_ctl.FIELDS`. Hand-written comma strings silently shifted every value one column left when a field was added |
| Never reimplement a tool's logic in a test | A test that chooses the schema itself passes regardless of what the tool does, and mutating the tool produces zero failures |
| A test exercises the tool, never a stand-in for it | Assertions call the tool and capture its printed output, so a changed message is caught |

`PipelineCtlRunner` runs `pipeline_ctl.py` as a subprocess against an
environment the subclass supplies in its own `setUp`, because some classes
redirect `GSPWN_STATE` alone and others add `GSPWN_SURFACE_LEDGER` beside it.

`FAKE_SYZ_DB` stands in for `syz-db` by packing and unpacking a directory of
programs through a JSON blob, which makes the seed-injection path, the corpus
carry and the promotion ledger testable without a syzkaller build.

## Coverage limits

| Limit | Settled by |
|---|---|
| Kernel builds, live systemd units, pstore and kdump harvesting, and real reproduction | The phase gates on the target machine |
| Whether the kernel tree compiles and boots | The `build` phase gate. `tools/build_kernel.sh` is read as text here, and three classes assert its config symbols, the order of its checks and its shell syntax |
| The running half of a Track U replay | `harnesses/replay_crashes.sh` on the target machine, which needs a built harness binary and a sanitizer runtime. The reading half is covered here, from a `.sanlog` written beside a raw fuzzer input |
| Committed artefacts under `artifacts/` | Classes reading them fail on a checkout missing them, which is the correct signal, because the CI checks reading the same files cannot run either |
| The git-mining classes | They skip themselves when `git` is absent from `PATH` |

## See also

- [Durability](/gspwn/architecture/durability/)
- [Components](/gspwn/architecture/components/)
