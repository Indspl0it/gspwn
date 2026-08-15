---
title: Rules of engagement
description: Authorized targets, permitted and prohibited actions, and the claims the campaign refuses to make.
---

## Authorization

gspwn is for security research on a machine the operator owns or is explicitly
authorised to test. It builds an instrumented kernel, panics the machine
repeatedly, and drives hostile input into a device driver.

Nothing else of value may share that machine.

## Permitted and prohibited actions

| The pipeline may | The pipeline does not |
|---|---|
| Install a kernel and reboot into it | Contact NVIDIA PSIRT or publish anything |
| Panic the machine, repeatedly and on purpose | Weaponize a reproducer past reliable triggering |
| Write systemd units and grant itself passwordless sudo for its own tools | Build an escalation from a memory-safety primitive |
| Leave the machine in a state where the GPU has stopped responding | Record a finding in the committed `knowledge/` tree |

Every action in the left column is normal operation. A machine under this
pipeline is expected to be unhealthy.

## Expected panics

Kernel fuzzing panics the box by design. Every mechanism that has to survive is
either a file on disk or a systemd unit with `OnBootSec`, and the circuit
breaker counts reboots separately from same-boot restarts, because reboots are
the normal case.

## Claims

| Claim | Status | Basis |
|---|---|---|
| An unprivileged container tenant reaching host kernel compromise on a GPU container platform | Supported | The claim this campaign is built to support |
| A finding is reachable by an unprivileged container tenant | Conditional | Only when the `poc` phase's profile check returned `tenant-reachable` |
| Anything about the cloud provider's boundary | Refused | Fuzzing a rented instance crosses no boundary the provider maintains |
| Anything about other tenants or provider infrastructure | Refused | Nothing observed here is evidence about either |
| Coverage of GSP firmware | Refused | GSP firmware is not instrumented |
| A fraction of the driver covered | Refused | Needs per-edge frequency counts that syz-manager does not report |
| A severity the evidence chain does not carry | Refused | `undetermined` is a valid outcome |
| A crash count including Xid 13 and 31 | Refused | Those are the fuzzer's own noise floor |

## Provider boundary

The campaign runs on an instance the operator rents:

- A guest kernel panic reboots that guest.
- The hypervisor is unaffected.
- The IOMMU fences GPU DMA to the same guest.

## Container reachability

syzkaller runs under `sandbox: namespace`, which holds a full capability set
inside a fresh user namespace. A container tenant has dropped capabilities, a
seccomp filter and a device cgroup allowlist. syzkaller therefore reaches paths
the attacker cannot, and every difference runs in the direction that produces
over-claims.

A `profile-check-blocked` finding is reported as unverified for reachability.

## Coverage statements

Coverage is kernel-side reachable code only. An aggregate edge counter supports
no statement about what fraction of the driver has been covered.

Both statements are printed by `series` and `plateau` on every invocation, and
every artifact reporting coverage repeats them.

## Severity

A severity is argued as an explicit chain: weakness, primitive, what it lands
on, what the attacker controls, reachability, consequence. A reader who
disagrees can identify which link they disagree with.

`undetermined` costs nothing, as long as the record says what blocked the
analysis. A finding whose impact record cannot carry a severity is reported
with its mechanism and no severity claim. A severity claim the record does not
support is the first one a vendor disproves, and it weakens every other finding
in the document.

## Findings in the public repository

`knowledge/` is committed to a public repository. It carries ABI and process
facts and never findings. The tool refuses a note naming a crash id or a path
under the finding directories.

## Crash counts

A fuzzer generates bad pointers and illegal instructions by design, and the
driver reports exactly that as Xid 13 and 31. Every derived count excludes
them, and the reported figures state how much of the registry they are.

## See also

- [Threat model](/gspwn/architecture/threat-model/)
- [Security and disclosure](/gspwn/project/security/)
- [Scope and oracle](/gspwn/architecture/scope-and-oracle/)
