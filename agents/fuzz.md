You are the fuzz-phase agent. Start and babysit both campaign tracks.

## Run identity (do this first)
Every campaign runs in its own directory and corpus. Pick ONE run id of the
form `r<round>-<n>` (e.g. `r2-1`) covering BOTH tracks, and use it for every
command below. Track U data lives under artifacts/runs/<id>/u/ and the
coverage sampler and deadline timer key on the single id. Per-track ids
(`r2-k1`/`r2-u1`) leave Track U unsampled and break the round accounting.
Never reuse a run id or point two campaigns at one workdir, because the eval
reports variance across *independent* runs and runs sharing a corpus are not
independent.

Corpus policy for the round comes from `loop.corpus_policy` in
config/campaign.yaml:

| Policy | Effect | Flags |
|---|---|---|
| `carry` | Builds on the previous round | `--corpus carry --from-run <prev>` |
| `fresh` | Starts empty and ignores what earlier rounds built | `--corpus fresh` |

A seeded run also passes `--seeds artifacts/seeds`, which packs the bank into
the run's corpus.db (merging anything carried). A run meant to start
clean must omit `--seeds` *and* use `--corpus fresh`, because either one alone
still inherits a corpus.

Every campaign carries a deadline of `loop.campaign_hours`, written to disk at
install time and enforced by `gspwn-deadline@<run-id>.timer`, so the run ends
on schedule even if this session is gone. Do not stop a campaign early by hand
unless a gate failed, because the round accounting reads the actual elapsed
time. Both install commands refuse while another run's campaign is still live.
Retire the old campaign first or pass `--replace`, which stops and disables
its units and its deadline timer.

## Do
1. Generate the run config (do not hand-write it):
   `python3 tools/campaign_ctl.py gen-config --run-id <id>`
2. Install and start, with the corpus policy for this round:
   sudo python3 tools/campaign_ctl.py install-k --run-id <id> \
     [--corpus carry --from-run <prev>] [--seeds artifacts/seeds]
   sudo python3 tools/campaign_ctl.py install-u --run-id <id>
   sudo python3 tools/campaign_ctl.py start k
   sudo python3 tools/campaign_ctl.py start u
   Both installs check the run-hour budget first and refuse a campaign the
   cap cannot cover, and both take `--hours` to override
   `loop.campaign_hours`.
   Installing over a still-live campaign needs `--replace`, which stops and
   disables the old units and its deadline timer. Without it the older run
   keeps fuzzing unbudgeted.
3. Start coverage sampling before the smoke window, so the curve covers the
   whole campaign and survives panics:
   `sudo python3 tools/coverage_ctl.py install-timer --run-id <id>`
   The timer samples both tracks. Each campaign carries its own deadline
   timer (`gspwn-deadline@<run-id>.timer`), installed by install-k/install-u,
   so the window holds even if sampling is not.
   Confirm the first sample of each is real. Use `sudo`, since the sampler
   runs as root and owns the CSV:
   `sudo python3 tools/coverage_ctl.py sample --run-id <id>` and
   `sudo python3 tools/coverage_ctl.py sample --run-id <id> --track u`
   must not report `source: unreachable`.
   For Track K, fix the http address in campaign.yaml or the stats endpoint
   for this syzkaller version. For Track U, read the harness list from
   `track_u.targets` in config/campaign.yaml, written by the harness phase,
   and do not guess harness names. Confirm run_all.sh writes each harness's
   output under `artifacts/runs/<id>/u/<harness>/`. A campaign with
   no coverage data cannot close its round, and the loop treats a missing
   verdict as a stop.
4. Register the run: `python3 tools/pipeline_ctl.py round-add-run --run-id <id>`
5. Smoke window (config: smoke_window_minutes). Poll
   `python3 tools/campaign_ctl.py status --run-id <id>` and
   `python3 tools/coverage_ctl.py series --run-id <id>`, and coverage must
   increase. If Track K unit is failed, read `journalctl -u gspwn-k` and fix
   once. The smoke window is an early abort and says only that the campaign
   started correctly. This phase continues past it.
5b. Wait out the campaign. This phase is not done until the window closes:
   ```
   python3 tools/campaign_ctl.py wait --run-id <id>
   ```
   It blocks until `loop.campaign_hours` have elapsed, printing a heartbeat,
   and returns when the deadline timer has stopped the units. The deadline
   lives on disk, so a panic during the wait is recovered by re-running the
   same command after the reboot, which resumes against the same deadline.

   Do not advance to triage on the strength of the smoke window. Everything
   after this phase measures the run: triage scans the workdir, refine fits
   the coverage curve, and round-end derives the verdict, the edge counts and
   the billed hours from it. Run at half an hour into a twenty-four hour
   campaign, all of them describe the first half hour and the round bills a
   full campaign for it. `pipeline_ctl.py next` reports `wait` while a
   campaign is live, and `round-end` refuses to measure one.
6. After any reboot, run `sudo python3 tools/crashlog_ctl.py harvest` BEFORE
   restarting the campaign, and hand the harvested paths to the triage phase.
   The coverage sampler is a systemd timer and resumes on its own. Confirm
   that it did with `systemctl is-active gspwn-coverage.timer`.
7. Record the campaign in state:
   `python3 tools/pipeline_ctl.py campaign-add --track k --note "<procs,
   sandbox, enabled_syscalls, seed corpus, rung>"` (and again for track u).
   campaign_ctl.py already logs start/stop events, and this adds the config
   summary the eval and report phases cite.

The orchestrator does long-running monitoring in a background subagent. This
phase does not block on it.

## State
`python3 tools/pipeline_ctl.py set-phase fuzz in_progress|done|blocked
 --notes "<one line>"`. Never edit pipeline.json by hand.

## Gate evidence
The campaign window has elapsed (`campaign_ctl.py wait --run-id <id>` has
returned, or `wait --check` exits 0), both units have been stopped by the
deadline timer, and the coverage series spans the whole campaign window.

During the smoke window: `systemctl is-active gspwn-k gspwn-u` both active,
and coverage stats showing an increase. Flat coverage across the whole smoke
window is a failed gate. It is not a slow start. Report it, and do not extend
the window until it looks green.

Before calling flat coverage a failed gate, run
`python3 tools/coverage_ctl.py gpu-health`. A GPU that has fallen off the bus
leaves the fuzzer running against nothing, and the curve looks identical to a
descriptions problem. Recover the GPU first (`nvidia-smi -r`, then a module
reload, then a guest reboot) and re-run the smoke window before drawing any
conclusion about the descriptions. A card that survives all three needs an
instance stop/start from the AWS console.

## Knowledge (cross-campaign)

Read what earlier campaigns established before you start:

```
python3 tools/knowledge_ctl.py show --phase fuzz
```

Record what you learn **as you learn it**, not at the end from memory:

```
python3 tools/knowledge_ctl.py note --kind learning --phase fuzz "..."
python3 tools/knowledge_ctl.py note --kind mistake  --phase fuzz "..."
```

A **learning** is about the target. For this phase, typically runtime facts:
what the driver does under sustained load, which Xids mean the card and not
the code. A **mistake** is about us: something that cost time, produced a
wrong number, or would repeat. Both are read by whoever runs this phase
next, on another box months from now, so write for someone without your
context. Recording nothing across a whole phase is itself worth questioning.

`knowledge/` is committed to a **public repository**. It carries ABI and
process facts and never findings: `note` refuses text naming a crash id or a
path under `artifacts/crashes|pocs|rca`, and the specifics belong in the
crash registry. Record the general form. It is also the more useful one,
because the next agent is looking at a different crash.
