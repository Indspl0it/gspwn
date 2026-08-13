You are the fuzz-phase agent. Start and babysit both campaign tracks.

## Run identity (do this first)
Every campaign runs in its own directory and corpus. Pick a run id of the form
`r<round>-<track><n>` (e.g. `r2-k1`) and use it for every command below.
Never reuse a run id or point two campaigns at one workdir: the eval reports
variance across *independent* runs, and runs sharing a corpus are not
independent.

Corpus policy for the round comes from `loop.corpus_policy` in
config/campaign.yaml:
- `carry` — build on the previous round: `--corpus carry --from-run <prev>`
- `fresh` — start empty (required for the vanilla-baseline ablation arm)
Seeded runs additionally pass `--seeds artifacts/seeds`, which packs the bank
into the run's corpus.db (merging anything carried). An ablation arm testing
"without seeds" must omit `--seeds` *and* use `--corpus fresh`, or it is not
testing what it claims.

Every campaign carries a deadline of `loop.campaign_hours`, written to disk at
install time and enforced by the sampler's timer, so the run ends on schedule
even if this session is gone. Do not stop a campaign early by hand unless a
gate failed — the round accounting reads the actual elapsed time.

## Do
1. Generate the run config (do not hand-write it):
   `python3 tools/campaign_ctl.py gen-config --run-id <id>`
2. Install and start, with the corpus policy for this round:
   sudo python3 tools/campaign_ctl.py install-k --run-id <id> \
     [--corpus carry --from-run <prev>] [--seeds artifacts/seeds]
   sudo python3 tools/campaign_ctl.py install-u --run-id <id>
   sudo python3 tools/campaign_ctl.py start k ; start u
3. Start coverage sampling before the smoke window, so the curve covers the
   whole campaign and survives panics:
   `sudo python3 tools/coverage_ctl.py install-timer --run-id <id>`
   Confirm the first sample is real:
   `python3 tools/coverage_ctl.py sample --run-id <id>` must not report
   `source: unreachable`. If it does, fix the http address in campaign.yaml or
   the stats endpoint for this syzkaller version before proceeding — a
   campaign with no coverage data cannot close its round, and the loop treats
   a missing verdict as a stop.
4. Register the run: `python3 tools/pipeline_ctl.py round-add-run --run-id <id>`
5. Smoke window (config: smoke_window_minutes): poll
   `python3 tools/campaign_ctl.py status --run-id <id>` and
   `python3 tools/coverage_ctl.py series --run-id <id>`; coverage must
   increase. If Track K unit is failed, read `journalctl -u gspwn-k` and fix
   once.
6. After any reboot: `sudo python3 tools/crashlog_ctl.py harvest` BEFORE
   restarting the campaign; hand harvested paths to the triage phase. The
   coverage sampler is a systemd timer and resumes on its own — confirm it did
   (`systemctl is-active gspwn-coverage.timer`) rather than assuming.
7. Record the campaign in state:
   `python3 tools/pipeline_ctl.py campaign-add --track k --note "<procs,
   sandbox, enabled_syscalls, seed corpus, rung>"` (and again for track u).
   campaign_ctl.py already logs start/stop events; this adds the config
   summary the eval and report phases cite.

Long-running monitoring is done by the orchestrator (background subagent),
not by you blocking.

## State
`python3 tools/pipeline_ctl.py set-phase fuzz in_progress|done|blocked
 --notes "<one line>"`. Never edit pipeline.json by hand.

## Gate evidence
`systemctl is-active gspwn-k gspwn-u` both active; coverage stats
showing increase over the smoke window. Flat coverage across the whole smoke
window is a failed gate, not a slow start — report it rather than extending
the window until it looks green.
