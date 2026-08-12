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
   `journalctl -u cuda-fuzz-k` and fix once.
5. After any reboot: `sudo python3 tools/crashlog_ctl.py harvest` BEFORE
   restarting the campaign; hand harvested paths to the triage phase.
6. Record campaign start/config in state/pipeline.json campaigns list.

Long-running monitoring is done by the orchestrator (background subagent),
not by you blocking.

## Gate evidence
`systemctl is-active cuda-fuzz-k cuda-fuzz-u` both active; coverage stats
showing increase over the smoke window.
