---
title: Security and disclosure
description: The disclosure sequence, where finding data is held, and the limits on a PoC.
---

## Disclosure sequence

| Step | Performed by | Action |
|---|---|---|
| 1 | The `report` sub-agent | Assembles `artifacts/report/disclosure/<crash-id>/` from the reproducer, the root-cause analysis, the affected versions and a short impact statement |
| 2 | The operator | Reads the package |
| 3 | The operator | Marks the crash `reported` |
| 4 | The operator | Sends the package to NVIDIA PSIRT |
| 5 | The operator | Marks the disclosure `submitted` |
| 6 | The operator | Marks the disclosure `resolved` once the vendor closes it |

The `report` sub-agent stops at step 1. It does not contact NVIDIA PSIRT and
does not publish anything. Nothing leaves the machine without an operator
action.

The crash is marked before any disclosure transition:

```
python3 tools/pipeline_ctl.py crash-set crash-0001 --status reported
python3 tools/pipeline_ctl.py crash-set crash-0001 --disclosure submitted
```

| Disclosure status | Meaning |
|---|---|
| `pending` | The default. Nothing has been sent |
| `submitted` | The operator has sent it |
| `resolved` | The vendor has closed it |
| `not_applicable` | It is not a vendor-facing finding |

## Vulnerability detail locations

| Location | Committed | May carry findings |
|---|---|---|
| `state/pipeline.json` | No | Yes. The registry, research records and impact records |
| `artifacts/rca/`, `artifacts/pocs/`, `artifacts/report/` | No | Yes |
| `knowledge/learnings.md`, `knowledge/mistakes.md` | **Yes, to a public repository** | No |
| `config/*.yaml`, `tools/ioctl_map.json` | Yes | No |

`state/` and `artifacts/` are gitignored. Only the `.gitkeep` files are
committed, so the tree shape is version-controlled and its contents are not.

## Public knowledge files

`knowledge/` is committed. It carries ABI and process facts and never findings.
Two patterns are refused in a note: a crash id, and a path under
`artifacts/crashes`, `artifacts/pocs` or `artifacts/rca`.

```
python3 tools/knowledge_ctl.py note --kind mistake --phase triage \
  "crash-0001 was marked a duplicate too early"
```

```
error: refusing to record a note naming 'crash-0001': knowledge/ is committed to a public repo, and anything tied to a specific crash is finding data. Record the general form instead — the lesson that applies to the next crash of that shape — and keep the specifics in the crash registry (`pipeline_ctl.py crash-set <id> --notes`) or its research record (`pipeline_ctl.py finding-set`).
```

It refuses because the generalised form of the same note is publishable and
applies to the next agent, which is looking at a different crash.

The general form of that note:

```
python3 tools/knowledge_ctl.py note --kind mistake --phase triage \
  "A flagged crash was grouped as a duplicate without reading both reports. The flag exists precisely because a machine could not tell them apart."
```

## PoC scope

| Permitted | Prohibited |
|---|---|
| A reproducer that reliably triggers the vulnerability | Weaponization of that reproducer |
| An impact record naming the primitive the memory-safety violation hands an attacker | An escalation built from that primitive |

Describing that a use-after-free gives a controlled write into an allocation
the attacker can reclaim is analysis. Building the escalation from it is out of
scope for this campaign.

## Reporting a vulnerability in gspwn itself

| Finding | Channel |
|---|---|
| A defect in the tools | A public issue |
| Anything that would expose a target's unpatched vulnerability | The maintainer, privately |

## Before publishing anything from a campaign

| Check | Why |
|---|---|
| The finding is fixed, or the vendor has agreed to disclosure | Published detail on an unpatched flaw is usable against deployed systems |
| The reproducer does not embed host-specific paths or credentials | It travels with the package |
| `knowledge/` carries no crash ids or finding paths | It is committed |
| Coverage claims say "kernel-side reachable code only" | GSP firmware is not instrumented |
| Reachability claims rest on a `tenant-reachable` profile check | syzkaller holds more capability than the threat model's attacker |
| No claim extends to the cloud provider | Fuzzing a rented instance crosses no boundary the provider maintains |

## Credentials on the machine under test

The machine is deliberately unstable and is fed hostile input by design. It
should hold as little as possible.

| Credential | Guidance |
|---|---|
| AWS access keys | Never place long-lived keys on it. Use an instance profile |
| The IAM instance profile | Exactly one permission, `ec2:GetConsoleOutput` |
| The agent's login | Under the agent user's home directory, which is why the unit sets `HOME` |
| `ANTHROPIC_API_KEY` | Not set by the generated unit. In the unit environment it takes precedence over a subscription login and bills the API |

## The sudoers rule

The agent needs passwordless sudo for the pipeline tools, because crash
harvesting after a panic runs `sudo -n` from a headless session.

```
<agent-user> ALL=(root) NOPASSWD: /usr/bin/python3 /path/to/repo/tools/*.py
```

:::danger[Equivalent to unrestricted root unless the repository is protected]
If the agent user can write those scripts, it can write anything root would
run. Keep the repository root-owned on the machine under test and grant the
agent user read and execute only.

No tool writes this rule. It is a deliberate human step, validated with
`visudo -f /etc/sudoers.d/gspwn`.
:::

## See also

- [Rules of engagement](/gspwn/project/rules-of-engagement/)
- [Threat model](/gspwn/architecture/threat-model/)
- [Impact and severity](/gspwn/architecture/impact-and-severity/)
