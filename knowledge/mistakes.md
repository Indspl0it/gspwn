# Mistakes

Process errors and what avoids them next time. About us, not about the driver.

Audience: the next agent running that phase. A mistake worth recording is one
that cost a round, produced a wrong number, or would repeat.

Generalise. "Marked the phase done on the subagent's assertion without reading
the smoke log" is reusable; the same sentence naming one crash is not.

PUBLIC REPO: process notes only, never findings.

Appended by `tools/knowledge_ctl.py note --kind mistake`. Do not hand-edit:
the tool timestamps and locks, and hand-edits are how the format rots.

## 2026-08-15T07:36:42+00:00 — refine
Tags: measurement
A flat coverage curve was reported as a plateau on a card that had stopped
answering. syz-manager keeps executing and the sampler keeps appending rows
after the GPU falls off the bus, so the measurement path produced a
well-formed wrong number and the round was written up as having reached its
ceiling. Before believing any flat number, confirm the thing being measured
was alive for the whole window.

## 2026-08-15T07:36:42+00:00 — poc
Tags: threat-model
Reachability was claimed from the fuzzer's own environment rather than
verified. Syzkaller's namespace sandbox holds a full capability set inside a
fresh user namespace, which is more privileged than a default container
tenant with dropped caps, a seccomp filter and a device cgroup allowlist. The
gap runs in the direction that over-claims, so re-run the reproducer under a
matching profile before stating impact.

## 2026-08-15T07:36:42+00:00 — eval
Tags: testing
A regression test reproduced the tool's own logic by hand instead of calling
it, so it chose the schema itself and passed no matter what the tool did.
Mutating the tool produced zero failures. A test that has never been seen to
fail is unverified: exercise the real entry point, then break the
implementation on purpose and watch the test catch it.

## 2026-08-15T07:36:42+00:00 — report
Tags: scope
Descriptions were authored for an ioctl surface the stated threat model could
not reach, and the round spent on them could not have produced a claimable
finding. Confirm the attacker in the README threat model actually holds the
device node before modelling anything behind it; widening scope is a decision
recorded there first.
