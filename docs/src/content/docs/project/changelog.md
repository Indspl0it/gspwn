---
title: Changelog
description: One line per change, newest first, each linking its commit.
---

## 2026-08-15

- Covered the review fixes with regression tests. [`22b7e91`](https://github.com/Indspl0it/gspwn/commit/22b7e91)
- Stopped the loop advancing past a campaign that was still running, and fixed twenty other defects found in a whole-repository review. [`0cbc23e`](https://github.com/Indspl0it/gspwn/commit/0cbc23e)
- Parked the README and the documentation tree pending a rebuild. [`800f523`](https://github.com/Indspl0it/gspwn/commit/800f523)
- Kept two different faults from merging into one registry entry. [`6e595b4`](https://github.com/Indspl0it/gspwn/commit/6e595b4)
- Gave a stackless report an identity that survives being seen twice. [`c11a675`](https://github.com/Indspl0it/gspwn/commit/c11a675)
- Added the impact record, replaced the growth threshold with a fitted discovery curve, and moved the research knobs into configuration. [`1ed421d`](https://github.com/Indspl0it/gspwn/commit/1ed421d)
- Reported a research record that steers nothing, and measured the session rotation point. [`c093230`](https://github.com/Indspl0it/gspwn/commit/c093230)
- Told the sub-agents about knowledge, findings and session resume. [`34b7e46`](https://github.com/Indspl0it/gspwn/commit/34b7e46)
- Let a restart resume the previous agent session. [`7982c34`](https://github.com/Indspl0it/gspwn/commit/7982c34)
- Carried knowledge across campaigns, and made the handoff derived rather than stored. [`2eba376`](https://github.com/Indspl0it/gspwn/commit/2eba376)
- Fed findings back into targeting through the research record. [`df95cf7`](https://github.com/Indspl0it/gspwn/commit/df95cf7)
- Ran the orchestrator unit as the operator rather than as root. [`b8fa904`](https://github.com/Indspl0it/gspwn/commit/b8fa904)
- Covered the redesign's three new behaviours with regression tests. [`7d4eada`](https://github.com/Indspl0it/gspwn/commit/7d4eada)
- Documented the GPU scope, and hardened the launch checklist. [`9c25572`](https://github.com/Indspl0it/gspwn/commit/9c25572)
- Supervised the orchestrating agent so a panic does not end the campaign. [`70be6c8`](https://github.com/Indspl0it/gspwn/commit/70be6c8)
- Narrowed the threat model to a default container tenant, and classified Xids. [`caefb34`](https://github.com/Indspl0it/gspwn/commit/caefb34)
- Stopped a dead GPU from reading as a coverage plateau. [`bd0c361`](https://github.com/Indspl0it/gspwn/commit/bd0c361)
- Removed the paper framing and the cost machinery. [`1ecec06`](https://github.com/Indspl0it/gspwn/commit/1ecec06)

## 2026-08-14

- Covered the two spend-ledger fixes with regression tests. [`f2a92b2`](https://github.com/Indspl0it/gspwn/commit/f2a92b2)
- Fixed four defects found reviewing the audit remediation. [`b2830ed`](https://github.com/Indspl0it/gspwn/commit/b2830ed)
- Fixed the audit findings: measurement integrity, budget guardrails and the cloud path. [`c799a1b`](https://github.com/Indspl0it/gspwn/commit/c799a1b)
- Removed the remaining editorial patterns from the documentation, and two stale claims. [`4d0205d`](https://github.com/Indspl0it/gspwn/commit/4d0205d)
- Removed editorial voice from the documentation. [`6a36e30`](https://github.com/Indspl0it/gspwn/commit/6a36e30)
- Ran the offline suite in CI. [`1ceca83`](https://github.com/Indspl0it/gspwn/commit/1ceca83)
- Fixed crash-capture losses, flagged-crash drops and two configuration gaps. [`2c670b1`](https://github.com/Indspl0it/gspwn/commit/2c670b1)
- Fixed five defects found in review. [`889679e`](https://github.com/Indspl0it/gspwn/commit/889679e)
- Rewrote the README so a newcomer could follow it. [`ac78062`](https://github.com/Indspl0it/gspwn/commit/ac78062)

## 2026-08-13

- Put Track U in the loop, and carried the work list through state rather than through a filename convention. [`5db270c`](https://github.com/Indspl0it/gspwn/commit/5db270c)
- Made every cap configurable and the loop unattended. [`55a8ce8`](https://github.com/Indspl0it/gspwn/commit/55a8ce8)
- Fixed reproduction-rate accounting and the crash status transitions. [`1584297`](https://github.com/Indspl0it/gspwn/commit/1584297)
- Closed the improvement loop: rounds, coverage tracking and corpus feedback. [`be45bf8`](https://github.com/Indspl0it/gspwn/commit/be45bf8)
- Closed the pipeline-state gap and hardened the tools. [`5dba2e1`](https://github.com/Indspl0it/gspwn/commit/5dba2e1)
- Updated the README. [`ce1d98a`](https://github.com/Indspl0it/gspwn/commit/ce1d98a)
- Renamed the project to gspwn. [`8455c41`](https://github.com/Indspl0it/gspwn/commit/8455c41)
- Started the repository. [`6f34802`](https://github.com/Indspl0it/gspwn/commit/6f34802)
- Aligned the design framing with the EC2 pivot. [`48fa9cb`](https://github.com/Indspl0it/gspwn/commit/48fa9cb)
- Added the MIT licence. [`63080aa`](https://github.com/Indspl0it/gspwn/commit/63080aa)
- Added a GitHub-facing README and a documentation index. [`1400258`](https://github.com/Indspl0it/gspwn/commit/1400258)
- Fixed the cloud review findings: the timer environment, the console-log triage path, and the harvest guards. [`95a5e39`](https://github.com/Indspl0it/gspwn/commit/95a5e39)
- Added a cloud deployment section to the environment constraints. [`61bf6f8`](https://github.com/Indspl0it/gspwn/commit/61bf6f8)
- Added the EC2 path to the provision sub-agent. [`c00e9a9`](https://github.com/Indspl0it/gspwn/commit/c00e9a9)
- Added an EC2 cloud setup guide. [`6330a08`](https://github.com/Indspl0it/gspwn/commit/6330a08)
- Added an idle auto-stop watchdog for EC2, since removed. [`86de9a5`](https://github.com/Indspl0it/gspwn/commit/86de9a5)
- Added an EC2 mode to the crash-log tool: kdump plus console output. [`775adbb`](https://github.com/Indspl0it/gspwn/commit/775adbb)
- Fixed the Track U memory cap, kernel-splat dmesg parsing, the kdump triage path, and the GSP firmware pin in the manifest. [`1ae0a5b`](https://github.com/Indspl0it/gspwn/commit/1ae0a5b)
- Added the rca, poc, eval and report sub-agents. [`03f0c66`](https://github.com/Indspl0it/gspwn/commit/03f0c66)
- Fixed the per-file dmesg loop in the triage sub-agent. [`d9a9a59`](https://github.com/Indspl0it/gspwn/commit/d9a9a59)

## 2026-08-12

- Added the fuzz and triage sub-agents. [`7f2281e`](https://github.com/Indspl0it/gspwn/commit/7f2281e)
- Added the describe, seeds and harness sub-agents. [`42f78b7`](https://github.com/Indspl0it/gspwn/commit/42f78b7)
- Made the kernel build absolutise its source paths, which the manifest's `git -C` calls needed. [`589779b`](https://github.com/Indspl0it/gspwn/commit/589779b)
- Added the provision and build sub-agents. [`671e6b4`](https://github.com/Indspl0it/gspwn/commit/671e6b4)
- Added the orchestrator contract. [`29edcc6`](https://github.com/Indspl0it/gspwn/commit/29edcc6)
- Corrected the expected error output for a reproduction verification with an unknown crash id. [`9398145`](https://github.com/Indspl0it/gspwn/commit/9398145)
- Added reproducer extraction and reproduction-rate classification. [`dc9a7fe`](https://github.com/Indspl0it/gspwn/commit/dc9a7fe)
- Added the strace-to-syz-program converter. [`305a0e2`](https://github.com/Indspl0it/gspwn/commit/305a0e2)
- Fixed the crash-parse invocation in the triage sub-agent. [`23a6851`](https://github.com/Indspl0it/gspwn/commit/23a6851)
- Added crash harvesting with title and stack-hash dedup, and collision flags. [`cddecc9`](https://github.com/Indspl0it/gspwn/commit/cddecc9)
- Added the systemd campaign manager with cgroup memory caps. [`9c24905`](https://github.com/Indspl0it/gspwn/commit/9c24905)
- Added the instrumented kernel and module build with its degradation ladder. [`eb7d9e7`](https://github.com/Indspl0it/gspwn/commit/eb7d9e7)
- Added the pstore and kdump crash-capture tool. [`9cebe3f`](https://github.com/Indspl0it/gspwn/commit/9cebe3f)
- Added the logged command runner. [`cea955f`](https://github.com/Indspl0it/gspwn/commit/cea955f)
- Fixed the gitignore rules for artifacts, and tracked the agents directory. [`0ae80bc`](https://github.com/Indspl0it/gspwn/commit/0ae80bc)
- Added the repository scaffolding, the configuration templates and the pipeline state helper. [`c629e11`](https://github.com/Indspl0it/gspwn/commit/c629e11)
- Added an implementation plan for the fuzzing workflow, since removed. [`fe80fe6`](https://github.com/Indspl0it/gspwn/commit/fe80fe6)
- Added a design specification for the fuzzing workflow, since removed. [`efe2293`](https://github.com/Indspl0it/gspwn/commit/efe2293)
