---
title: FAQ
description: Non-obvious behaviour of the tools, and the reason for each.
---

## Phase order and timing

### Why does the fuzz phase wait out the whole campaign window?

Everything after it measures the run. `triage` scans the workdir, `refine` fits
the coverage curve, and `round-end` derives the verdict, the edge counts and
the billed hours from it.

Run at half an hour into a twenty-four hour campaign, all of them describe the
first half hour, every later gate passes by having nothing to do, and the round
bills a full campaign for thirty minutes of measurement.

The smoke window only says the campaign started correctly.

### Why does `next` return `wait` during a campaign window?

Same reason. `next` refuses to run ahead of a campaign still inside its window,
and names the run and the hours left. `round-end` refuses to measure one.

## Coverage measurement

### Why does an unknown coverage verdict stop the loop?

The next campaign would otherwise run without a coverage measurement.
`unknown` means no verdict could be produced: too few samples, no edge data, a
curve the model does not describe, a fuzzer still replaying its corpus, or a
GPU that was not healthy across the window.

A broken sampler must not silently authorise more machine time.

### Why is a plateau not reported when the GPU was unhealthy?

A card that has fallen off the bus does not stop the fuzzer. syz-manager keeps
executing, the sampler keeps appending rows, and the edge count stops moving.
That curve is indistinguishable from a real plateau, and only the plateau
reading gets written into a report as a finding about the target.

`growing` needs no such guard, because coverage cannot climb on a GPU that is
not answering.

### Why does the plateau test extrapolate the next campaign's new edges?

The loop asks how many new edges another campaign is expected to find, and the
extrapolation answers in those units. The same growth percentage covers ten
edges early in a run and a thousand late in one.

### Why is the coverage curve's y axis a running maximum?

syzkaller re-executes its corpus after every restart, and the reported edge
count climbs steeply back towards its previous high-water mark. That climb is
replay of coverage already found.

Measured against the raw count, a saturated run reports tens of percent of
growth after each panic. On a machine that panics by design, that growth keeps
a saturated campaign running indefinitely.

### Why does the fit cover only part of the run?

A power law fitted over a whole run is dominated by the early steep phase,
where syzkaller is still working through its seeds. A run that climbed hard and
then went completely flat would still report a healthy discovery exponent.

The cut is by executions, so a stretch where the box was panicking and doing
little work does not count as recent history.

## Crash registry

### Why are noise Xids registered at all if they are not findings?

As an audit trail. They stay in the registry so the record of what the campaign
saw is complete, and they are excluded from every count the tools derive:
`round-end`, `round-show`, `brief` and `show`.

`show` and `brief` say how many there are, so a headline count of 412 crashes
is not read as 412 findings.

### Why does a crash with the same title get flagged?

A collision in one key but not the other may be a second bug or the same bug
reported twice, and distinguishing them requires reading both reports.

A `flagged` entry persists in the registry, so the queue survives across
invocations of the tool.

## Reproduction verification

### Why does verification refuse while the fuzzer is running?

A run counts as a reproduction partly because the box went down during it, and
that inference holds only when the reproducer is the only thing capable of
panicking the machine.

With a campaign still running, the fuzzer panics the box by design and every
one of its panics would land as a hit, inflating the rate that decides whether
a finding is reliable enough to disclose.

### Why does verification refuse when dmesg returns nothing?

With `kernel.dmesg_restrict=1` a non-root `dmesg` yields empty output. An empty
before-and-after pair reads as a clean run, so every run would score clean and
a real bug would be classified `unreproducible` at a manufactured 0% rate.

### What is a void run?

A run that produced no usable verdict: the dmesg ring wrapped, the reproducer
would not execute, a timeout on a crash whose title is not hang-class, or a
verification process that died on the same boot.

Void runs are excluded from both the numerator and the denominator, and re-run.
An attempt cap bounds that, so a persistently wrapping ring cannot loop
forever.

## Budget and stopping

### Why is the spend ledger separate from the state file?

It is machine-global. `GSPWN_STATE` redirects the state file so a side run can
keep its own registry, and that run must still count against the one run-hour
cap. The ledger deliberately does not follow the redirect.

### Why does a missing spend ledger refuse?

Falling back to zero would grant the loop a fresh budget, which is the
expensive direction to be wrong in. A genuinely fresh machine, with no ledger
and no recorded hours, reads 0.0 and starts normally.

### Why can a budget stop not be overridden?

It is the spend ceiling. Raising it is a deliberate edit to
`config/campaign.yaml`, and no tool performs that edit. A plateau stop or an
`unknown` stop can be overridden with an explicit reason.

### Why is the deadline stored in a file?

A one-shot timer dies with the machine, and this machine dies routinely. After
a reboot the check reads the same deadline and still stops on time.

A missing deadline file previously removed the spend ceiling silently. The
deadline is now reconstructed from the install event when the file is gone.

### Why does stopping a campaign also disable its units?

An enabled `Restart=always` unit comes back on the next boot, and this pipeline
reboots by design. Stopping without disabling means the campaign restarts
itself the next time the kernel panics.

## Orchestrator and units

### Why does the orchestrator count reboots separately from restarts?

Kernel fuzzing panics the box by design, so reboots are expected. An agent
restarting on one boot means nothing is progressing and every restart costs
tokens.

A single shared limit would either stop a healthy campaign that panics often or
let a same-boot loop run unbounded.

### Why does session rotation use transcript size?

Size is what drives auto-compaction. A campaign that panics twenty times in an
hour writes almost nothing, while one that panics twice in three days writes a
great deal, so restart count tracks compaction poorly.

The restart count remains as a backstop for when the transcript cannot be
measured, and the tool reports each fall back to it.

### Why does the orchestrator unit run as a non-root user?

A system unit runs as root unless told otherwise, and a coding agent keeps its
login under the invoking user's home directory. Left as root it would look in
`/root`, find no credentials, fail, and be restarted until the breaker tripped.

### Why is `StartLimit*` under `[Unit]`?

`systemd.unit(5)` documents them there, and `systemd.service(5)` only
cross-references them. Written under `[Service]` they are an unknown key,
silently ignored, and the manager default of five starts per ten seconds
applies, which `RestartSec=60` can never reach.

## Analysis records

### Why can a research record be rejected for steering nothing?

`adjacent` is the only field carrying information the crash does not already
contain. `ioctls` is transcribed from the reproducer and `preconditions` mostly
from the same place, and a round can act on neither to look anywhere it has not
already looked.

A record whose `adjacent` is empty, or whose `adjacent` only repeats `ioctls`,
adds nothing to the next round's work list even though every other field is
filled in.

### Why is an empty `adjacent` sometimes acceptable?

A bug with no siblings on its lock or teardown path is a valid answer, and so
is a path that disappears into GSP where the other callers are not visible.
Recording which of the two applies is sufficient.

An invented neighbouring call sends the next round at a target that gets
modelled and measured before the error surfaces, which costs more than an empty
field.

### Why is `rca_done` not enough to tell whether a crash was analysed?

It is transient. The `poc` phase writes the reproduction class straight over
the status, and `poc` is the one phase guaranteed to run after `rca`. A check
keyed on the current status would stop seeing an unanalysed crash at the point
the pipeline reaches the phase that should notice it.

`rca_done_at` is the durable stamp, set once and never cleared.

### Why is the CWE derived from `bug_class`?

The mapping from bug class to weakness class is mechanical, and a free-text CWE
field invites a plausible wrong number that nobody re-checks. `bug_class` is
already a closed vocabulary, so the two cannot disagree by drift.

### Why is under-claiming a consequence not flagged?

It costs nothing, and flagging it would push the analysis towards escalating,
which is the direction that does cost something. A privilege-escalation
conclusion drawn from an undetermined primitive is the first finding a vendor
engineer disproves.

### Why does `knowledge_ctl.py` refuse a note naming a crash?

Those files are committed to a public repository. Anything tied to a specific
crash is finding data.

It refuses because the generalised form of the same note is publishable and
applies to the next agent, which is looking at a different crash.

## Absent features

### Why is there no default agent command?

The repository works with any `AGENTS.md`-aware coding agent and does not guess
which one is installed on the machine. `orchestrator_ctl.py install` refuses
until the invocation is set.

### Why is there no mutator plugin API?

syzkaller owns mutation on Track K, and AFL++ or libFuzzer owns it on Track U.
The outer loop's job is what the fuzzer cannot do for itself: modelling ioctls
it has no description for, and supplying valid object-chain seeds it cannot
invent.

## Crash capture

### Why does `crashlog_ctl.py harvest` delete pstore records?

pstore is a small fixed-size backend that frees a record only when the file is
deleted. Leaving records in place means the next panic has nowhere to write,
which on a machine that panics by design is lost findings, and every later
harvest re-copies the same records.

### Why does `harvest` refuse to run as a non-root user?

`/sys/fs/pstore` and `/var/crash` are root-only. Run as anyone else the globs
come back empty, and the previous behaviour reported "no new crash logs found"
and exited 0 while the evidence stayed on the machine.

"Nothing to harvest" and "could not look" must not be the same answer, because
the orchestrator runs this unattended after every panic.

## Kernel build

### Why does the build start from the running kernel's configuration?

A generic x86 defconfig has no NVMe or ENA driver, so on a cloud instance the
resulting kernel cannot find its own root filesystem, and the failure arrives
after a full build and a reboot.

### Why does the build check the configuration after generating it?

`make olddefconfig` silently drops anything the tree does not offer, and
`CONFIG_DEBUG_INFO` stopped being user-selectable in 5.18. That class of
setting goes missing silently and is noticed only when symbolization fails on a
crash log.

## See also

- [Troubleshooting](/gspwn/guides/troubleshooting/)
- [Architecture overview](/gspwn/architecture/overview/)
