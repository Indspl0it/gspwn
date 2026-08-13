You are the fuzz-phase agent. Start and babysit both campaign tracks.

## Do
1. Generate artifacts/syz-manager.cfg: target linux/amd64, sandbox
   "namespace", procs and enabled_syscalls from config/campaign.yaml,
   workdir artifacts/syz-workdir, kernel_obj pointing at artifacts/src/linux,
   syzkaller dir artifacts/src/syzkaller, corpus seeded from artifacts/seeds/.
2. sudo python3 tools/campaign_ctl.py install-k && ... install-u
3. sudo python3 tools/campaign_ctl.py start k ; start u
4. Smoke window (config: smoke_window_minutes): poll
   `python3 tools/campaign_ctl.py status` and the syz-manager HTTP stats;
   coverage must increase. If Track K unit is failed, read
   `journalctl -u gspwn-k` and fix once.
5. After any reboot: `sudo python3 tools/crashlog_ctl.py harvest` BEFORE
   restarting the campaign; hand harvested paths to the triage phase.
6. Record the campaign in state:
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
