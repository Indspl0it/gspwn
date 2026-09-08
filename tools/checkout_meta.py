#!/usr/bin/env python3
"""One resolver for the commit of a driver source checkout.

Three tools record which tree an artefact was parsed from.
`ioctl_inventory.py` stamps it into `tools/ioctl_map.json` and
`surface/entry-points.json`, `surface_verify.py` prints it and compares it,
and `syzlang_gen.py` writes it into the six description banners and into
`descriptions/generation.json`.

`ioctl_inventory.py` and `surface_verify.py` each carried a copy of the same
three lines. `syzlang_gen.py` carried no resolution at all and recorded the
literal `--commit` string, so a run following the `agents/describe.md` step 4
invocation, which passes no `--commit`, wrote a placeholder into every banner
while the other artefacts recorded the short hash of the same tree. This
module holds the one implementation the three of them call.

The module imports the standard library only and runs no code at import time,
so a generator gains the resolver without gaining the version guard's
environment handling, and the guard that reads the generators' artefacts stays
downstream of them.
"""
import logging
import os
import subprocess

logger = logging.getLogger(__name__)

# Seconds git may take to answer. `rev-parse --short HEAD` reads local
# repository state and answers in well under a second; the bound exists
# because every caller runs unattended inside a pipeline phase, and a git
# process wedged on a network filesystem would hang the phase with no output.
DEFAULT_TIMEOUT_SEC = 30


def checkout_commit(src, timeout=DEFAULT_TIMEOUT_SEC):
    """Short HEAD of the checkout at `src`, or None.

    Both forms of `.git` resolve: the directory a clone carries, and the file
    holding a `gitdir:` pointer that a worktree and a submodule carry. A
    directory test answers None on a worktree, and `.claude/worktrees/` holds
    worktrees of this repository, so an operator pointing a tool at one would
    take the fallback with nothing reporting why.

    Returns None where `src` holds no `.git` entry, where git is absent, where
    it exits non-zero, where it exceeds `timeout`, and where it answers with
    an empty string. A caller records the result beside NVIDIA_VERSION,
    because a driver release is cut from many commits and the version alone
    does not identify the tree an artefact was parsed from.

    A failure is a warning and never an exception: the commit is provenance
    that a later reader uses to reproduce a run, and a generator that has
    parsed the tree successfully still has an artefact worth writing.
    """
    marker = os.path.join(src, ".git")
    if not os.path.exists(marker):
        logger.debug("no .git entry at %s, no commit to record", marker)
        return None
    try:
        out = subprocess.run(["git", "-C", src, "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("git rev-parse failed for %s: %s", src, exc)
        return None
    if out.returncode != 0:
        # A `.git` file pointing at a deleted gitdir exists and answers
        # nothing, so the marker test alone is not enough and stdout on a
        # failed query is not read.
        logger.warning("git rev-parse exited %d for %s: %s", out.returncode,
                       src, (out.stderr or "").strip())
        return None
    return out.stdout.strip() or None
