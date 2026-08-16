---
title: Xid classification
description: The Xid table, the four classes, and the default class for an unlisted Xid.
---

An Xid is NVIDIA's error identifier, printed by the driver as an `NVRM:` line
in the kernel log. `crash_parse.py` classifies each one at registration and
stores the class on the registry entry.

## Classes

| Class | Meaning | Triage action |
|---|---|---|
| `noise` | The fuzzer caused it on purpose | Not queued for RCA. Kept in the registry as an audit trail, excluded from every derived crash count |
| `signal` | Security-relevant or memory-integrity relevant | Queue it |
| `health` | The GPU or the box is degraded | Not a finding. The measurement path is broken |
| `review` | Everything else, including every Xid not in the table | Read it before deciding |

A fuzzer generates bad pointers and illegal instructions by design, so the Xids
reporting those conditions are fuzzer exhaust. Classifying them as findings
inflates the crash count and obscures the entries that require triage.

```
python3 tools/pipeline_ctl.py crash-list --signal signal
```

## Xid table

| Xid | Class | Meaning |
|---|---|---|
| 8 | `noise` | GPU stopped processing (video engine), app-caused |
| 12 | `review` | Driver error handling exception |
| 13 | `noise` | Graphics engine exception: illegal instruction or address |
| 31 | `noise` | GPU memory page fault: illegal address by the app |
| 32 | `signal` | Invalid or corrupted push buffer stream (DMA) |
| 38 | `signal` | Driver firmware error |
| 43 | `noise` | GPU stopped processing, channel error caused by the app |
| 45 | `noise` | Preemptive channel cleanup, usually a killed process |
| 48 | `signal` | Double-bit ECC error |
| 61 | `signal` | Internal micro-controller breakpoint or warning |
| 62 | `signal` | Internal micro-controller halt |
| 63 | `health` | ECC page retirement or row remapping |
| 64 | `health` | ECC page retirement or row remapping failure |
| 69 | `noise` | Graphics engine class error |
| 74 | `health` | NVLink error |
| 79 | `health` | GPU has fallen off the bus |
| 92 | `signal` | High single-bit ECC error rate |
| 94 | `signal` | Contained ECC error |
| 95 | `signal` | Uncontained ECC error |
| 119 | `signal` | GSP RPC timeout |
| 120 | `signal` | GSP error |
| 140 | `signal` | Unrecovered ECC error |

The meanings are the widely published ones. Confirm the numbers against
NVIDIA's Xid documentation for the driver branch under test.

## Classification rules

| Input | Class assigned |
|---|---|
| An `NVRM:` line carrying an Xid number listed above | The class in the table |
| An `NVRM:` line carrying an Xid number the table does not list | `review` |
| An `NVRM:` line carrying no Xid number, such as a `GPU at ... error` line | Left unclassified |

A new driver branch can introduce an Xid this table does not list. Defaulting
it to `noise` would discard a potential finding.

```
Xid 151 is not in the classification table — treated as review, not exhaust, so a new signal is never silently discarded
```

## Title normalisation

Two fields are removed before the title becomes a dedup key.

| Field removed | Why |
|---|---|
| `pid=` and the channel number | The same recurring Xid must deduplicate across processes and channels |
| The PCI bus id | Which card faulted is provenance. On a multi-GPU box the same driver bug on two cards is one bug |

The bus id is kept in the entry's notes, so the classification note reads
`Xid 79: GPU has fallen off the bus; on 0000:00:1e`.

Classification runs **before** the bus id is stripped, because the Xid number
parser has to consume the parenthesised bus id as a group. Skipping it with a
loose pattern reads the first field of the bus id as the Xid number and
classifies every crash as an unknown Xid 0.

## Xid 79 and plateau verdicts

Xid 79 means the card has fallen off the bus. The fuzzer continues running,
syz-manager continues executing, the sampler continues appending rows, and the
edge count stops moving. The resulting curve is indistinguishable from a
plateau.

| Mechanism | Effect |
|---|---|
| Every Track K coverage sample records the GPU's state alongside the counters | `plateau` refuses to call a flat window a plateau when the GPU was not healthy across it |
| The Xid is classed `health` | It is excluded from the crash count |

## Reclassifying

Reclassifying is recorded as a judgement in the crash entry. An Xid classed
`noise` that looks like a finding gets a note saying why before it is
promoted:

```
python3 tools/pipeline_ctl.py crash-set crash-0042 --status unique \
  --notes "Xid 13 here follows a KASAN report in the same window, so it is not the usual app-caused exception"
```

## See also

- [Results and triage](/gspwn/guides/results-and-triage/)
- [Crash identity](/gspwn/architecture/crash-identity/)
