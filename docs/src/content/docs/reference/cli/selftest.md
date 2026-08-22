---
title: selftest.py
description: "The offline test suite: its scope and its limits."
---

The offline self-test for the deterministic tools. Standard library only, no
hardware.

## Synopsis

```
python3 tools/selftest.py [-v]
```

No subcommands. Root is never required. `AGENTS.md` requires this after any
change to the tools, and `.github/workflows/selftest.yml` runs it on every push
and pull request.

## Options

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `-v` | None | Off | Verbose output, one line per test |

## Test scope

- The state schema, its normalisation, and the round and phase machines.
- The durability contract: atomic write, the backup file, and the transaction
  lock.
- The spend ledger: idempotent billing, the machine-global fallback, and the
  refusal when the ledger is missing while hours are recorded.
- Crash dedup: title canonicalisation, stack hashing, the frameless signature,
  flagging, and re-scan idempotency.
- Configuration validation, including every cross-field rule.
- The coverage model: accumulation, the tail fit, the Heaps fit, and each of
  the `unknown` cases.
- Campaign management: deadline reconstruction, the overlap guard, corpus
  policy and seed packing.
- Reproduction: the verdict rules, the recovery path, and the attempt cap.
- The orchestrator breaker and session resolution.
- The `strace` to syz-program conversion.
- The `pipeline_ctl.py` command line end to end.
- The generated systemd units.

## Limits

Anything touching the machine under test: kernel builds, live systemd units,
pstore and kdump harvesting, and real reproduction. Those are exercised by the
phase gates on the target machine.

`tools/build_kernel.sh` has no offline test by design. Stubbing `make`,
`scripts/config`, `sudo`, `update-grub`, `grub-editenv`, `mokutil` and `depmod`
would test the stubs. `bash -n` and a real provision run validate it.

## Path isolation

The suite redirects every persistent path to a temporary directory through the
environment variables the tools read:

| Variable | Redirects |
|---|---|
| `GSPWN_STATE` | `state/pipeline.json` |
| `GSPWN_SPEND` | `state/spend.json` |
| `GSPWN_ORCH` | `state/orchestrator.json` |
| `GSPWN_KNOWLEDGE` | The `knowledge/` directory |
| `GSPWN_CONFIG` | `config/campaign.yaml` |

It also substitutes a stand-in for `syz-db` that packs and unpacks a directory
of programs through a JSON blob, so the seed-injection path is exercised
without a syzkaller build.

Coverage fixtures are built from `coverage_ctl.FIELDS`, so adding a column
keeps every value in its own field.

## Additional CI checks

The CI workflow runs four more checks alongside it:

```
python3 -m pyflakes tools/*.py
bash -n tools/build_kernel.sh
python3 tools/gspwn_config.py
```

The fourth parses `tools/<x>.py <subcommand> --flag` out of the prose files and
verifies each against the tool's real `--help` output. See
[Development](/gspwn/project/development/).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every test passed |
| 1 | At least one failed |

## See also

- [Development](/gspwn/project/development/)
- [Contributing](/gspwn/project/contributing/)
