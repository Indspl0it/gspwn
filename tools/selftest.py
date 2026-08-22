#!/usr/bin/env python3
"""Offline self-test for the deterministic tools. Stdlib only, no hardware.

Covers the logic that does not need a GPU, a kernel build, or root: state
handling and its durability/locking contract, crash dedup and flagging, the
strace->syz-program conversion, and the pipeline_ctl CLI end to end. The
change wave that follows added the object graph parent map, the syzlang
emitter's typed XFER variants and its narrow allocation parent expansion, the
regression_check CI comparisons, the control ranking and the chain grouping,
the ioctl map repair and the chain-shaped seed programs, the two-curve stop
rule and the completion ledger, the version guard, the shared git-mining
module, and the config defaults. The second review wave added the deferral
rule in the completion ledger, the Track U replay reader, the version guard's
independent-source count, the impl definition scan behind the control ranking,
the combined-diff parse in the git-mining module, and the two register_check
gaps.

What it cannot cover, by construction: anything touching the SUT (kernel
builds, systemd units, pstore/kdump harvest, real reproduction). Those are
exercised by the phase gates on the target machine. The two clearest cases:

  kernel build    tools/build_kernel.sh is read as text. The classes over it
                  assert the config symbols, the order of the checks and the
                  shell syntax. Whether the tree compiles and boots is settled
                  by the build phase gate on the target machine.
  Track U replay  the reading half is covered here, from a .sanlog written
                  beside a raw fuzzer input. The running half needs a built
                  harness binary and a sanitizer runtime, and is exercised by
                  harnesses/replay_crashes.sh on the target machine.

Two further limits apply to parts of the suite. The classes that read the
committed artefacts under artifacts/ fail on a checkout missing them, which is
the correct signal: the CI checks that read the same files cannot run either.
The git-mining classes skip themselves when git is absent from PATH.

Usage: python3 tools/selftest.py [-v]      exit 0 = all passed
"""
import csv
import fcntl
import hashlib
import inspect
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import campaign_ctl
import corpus_ctl
import coverage_ctl
import crash_parse
import ctrl_rank
import ctrl_surface
import cve_patch_map
import gitmine
import gspwn_config
import ioctl_inventory
import knowledge_ctl
import object_graph
import orchestrator_ctl
import patch_mine
import refgen
import register_check
import regression_check
import repro_ctl
import pipeline_state as ps
import surface_cov
import surface_verify
import syzlang_gen
import trace2seed


def csv_line(ts, edges=None, source="test", gpu="ok", **extra):
    """One coverage.csv row, positioned by coverage_ctl.FIELDS.

    Fixtures used to hand-write comma strings, which silently shifted every
    value one column left when a field was added. Building from the field list
    keeps them correct across schema changes. gpu defaults to "ok" because
    these curves stand in for runs on a working GPU; a fixture that wants the
    dead-card case passes it explicitly.
    """
    row = {"ts": ts, "source": source, "gpu": gpu}
    if edges is not None:
        row["edges"] = edges
    row.update(extra)
    return ",".join(str(row.get(k, "")) for k in coverage_ctl.FIELDS)


# A stand-in for syz-db: pack/unpack a directory of programs through a JSON
# blob. Lets the seed-injection path be tested without a syzkaller build.
FAKE_SYZ_DB = r'''#!/usr/bin/env python3
import json, os, sys
mode, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
if mode == "pack":                     # pack <dir> <db>
    out = {}
    for n in sorted(os.listdir(a)):
        with open(os.path.join(a, n)) as f:
            out[n] = f.read()
    with open(b, "w") as f:
        json.dump(out, f)
elif mode == "unpack":                 # unpack <db> <dir>
    os.makedirs(b, exist_ok=True)
    with open(a) as f:
        for n, text in json.load(f).items():
            with open(os.path.join(b, n), "w") as g:
                g.write(text)
else:
    sys.exit("bad mode " + mode)
'''


class PipelineCtlRunner:
    """Run pipeline_ctl.py as a subprocess against self.env.

    Three classes across the file drive the CLI this way and had a byte
    identical copy of the runner each. The subclass supplies self.env in its
    own setUp, because the classes redirect different things: some set
    GSPWN_STATE alone and some add GSPWN_SURFACE_LEDGER beside it.
    """

    def ctl(self, *args, expect=0):
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, "pipeline_ctl.py")] +
            list(args), env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, expect,
                         "args=%s\nstdout=%s\nstderr=%s"
                         % (list(args), r.stdout, r.stderr))
        return r.stdout + r.stderr


class StateTempMixin:
    """Point pipeline_state at throwaway state for each test.

    Every module-level path pipeline_state can write must be redirected, not
    just STATE_PATH. The spend ledger deliberately does not follow
    GSPWN_STATE (that is what closes the redirect bypass), so redirecting the
    state file alone left the suite writing the real state/spend.json —
    running the tests on a campaign box would inject phantom hours into the
    ledger that gates live campaigns, and leak state between tests in the
    same run. DEFAULT_STATE_PATH is redirected too: it is the fail-closed
    fallback spend_for_budget() reads when the ledger is absent.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        state_dir = os.path.join(self.tmp.name, "state")
        self.state_path = os.path.join(state_dir, "pipeline.json")
        self.spend_path = os.path.join(state_dir, "spend.json")
        for attr, value in (("STATE_PATH", self.state_path),
                            ("DEFAULT_STATE_PATH", self.state_path),
                            ("SPEND_PATH", self.spend_path)):
            self.addCleanup(setattr, ps, attr, getattr(ps, attr))
            setattr(ps, attr, value)


class TestState(StateTempMixin, unittest.TestCase):
    def test_load_missing_returns_default(self):
        st = ps.load()
        self.assertEqual(st["version"], ps.SCHEMA_VERSION)
        self.assertEqual(set(st["phases"]), set(ps.PHASES))
        self.assertEqual(st["crashes"], {})

    def test_save_load_roundtrip(self):
        st = ps.default_state()
        ps.update_phase(st, "provision", "done", "manifest written")
        ps.save(st)
        back = ps.load()
        self.assertEqual(back["phases"]["provision"]["status"], "done")
        self.assertEqual(back["phases"]["provision"]["notes"],
                         "manifest written")
        self.assertIsNotNone(back["phases"]["provision"]["updated"])

    def test_save_is_atomic_no_tempfiles_left(self):
        ps.save(ps.default_state())
        leftovers = [f for f in os.listdir(os.path.dirname(self.state_path))
                     if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_normalize_fills_missing_keys(self):
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        with open(self.state_path, "w") as f:
            json.dump({"phases": {"provision": {"status": "done"}},
                       "crashes": {"crash-0001": {"title": "t",
                                                  "track": "K"}}}, f)
        st = ps.load()
        self.assertEqual(st["phases"]["provision"]["status"], "done")
        self.assertEqual(st["phases"]["build"]["status"], "pending")
        self.assertEqual(st["crashes"]["crash-0001"]["disclosure"], "pending")
        self.assertIsNone(st["crashes"]["crash-0001"]["repro_rate"])

    def test_corrupt_state_raises_clear_error(self):
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        with open(self.state_path, "w") as f:
            f.write("{not json")
        with self.assertRaises(ValueError) as cm:
            ps.load()
        self.assertIn("not valid JSON", str(cm.exception))

    def test_transaction_commits(self):
        with ps.transaction() as st:
            ps.update_phase(st, "build", "in_progress")
        self.assertEqual(ps.load()["phases"]["build"]["status"], "in_progress")

    def test_transaction_aborts_on_exception(self):
        ps.save(ps.default_state())
        with self.assertRaises(RuntimeError):
            with ps.transaction() as st:
                ps.update_phase(st, "build", "done")
                raise RuntimeError("boom")
        self.assertEqual(ps.load()["phases"]["build"]["status"], "pending")

    def test_concurrent_writers_do_not_lose_updates(self):
        """Two processes appending under the lock must both survive."""
        ps.save(ps.default_state())
        script = (
            "import sys; sys.path.insert(0, %r)\n"
            "import pipeline_state as ps\n"
            "for i in range(20):\n"
            "    with ps.transaction() as st:\n"
            "        st['campaigns'].append({'track': sys.argv[1]})\n"
        ) % HERE
        env = dict(os.environ, GSPWN_STATE=self.state_path)
        procs = [subprocess.Popen([sys.executable, "-c", script, t], env=env)
                 for t in ("k", "u")]
        for p in procs:
            self.assertEqual(p.wait(timeout=60), 0)
        self.assertEqual(len(ps.load()["campaigns"]), 40)

    def test_update_phase_rejects_bad_input(self):
        st = ps.default_state()
        with self.assertRaises(ValueError):
            ps.update_phase(st, "nonexistent", "done")
        with self.assertRaises(ValueError):
            ps.update_phase(st, "build", "finished")

    def test_next_phase_walks_and_stops_at_blocked(self):
        st = ps.default_state()
        self.assertEqual(ps.next_phase(st), "provision")
        ps.update_phase(st, "provision", "done")
        self.assertEqual(ps.next_phase(st), "build")
        ps.update_phase(st, "build", "blocked")
        self.assertEqual(ps.next_phase(st), "build")
        for p in ps.PHASES:
            ps.update_phase(st, p, "done")
        self.assertIsNone(ps.next_phase(st))

    def test_register_crash_ids_and_validation(self):
        st = ps.default_state()
        cid = ps.register_crash(st, {"track": "K", "title": "x",
                                     "stack_hash": "h", "status": "unique",
                                     "dir": "/tmp"})
        self.assertEqual(cid, "crash-0001")
        self.assertEqual(ps.register_crash(st, {"track": "U", "title": "y",
                                                "stack_hash": "h2",
                                                "status": "unique",
                                                "dir": "/tmp"}), "crash-0002")
        with self.assertRaises(ValueError):
            ps.register_crash(st, {"track": "K", "title": "z",
                                   "stack_hash": "h3", "status": "bogus"})
        with self.assertRaises(ValueError):
            ps.register_crash(st, {"track": "Z", "title": "z",
                                   "stack_hash": "h3", "status": "unique"})


class TestValidate(StateTempMixin, unittest.TestCase):
    def test_clean_state_has_no_problems(self):
        self.assertEqual(ps.validate(ps.default_state()), [])

    def test_detects_out_of_order_phases(self):
        st = ps.default_state()
        ps.update_phase(st, "report", "done")
        self.assertTrue(any("earlier phase" in p for p in ps.validate(st)))

    def test_parallel_trio_is_order_independent(self):
        st = ps.default_state()
        for p in ("provision", "build", "harness"):
            ps.update_phase(st, p, "done")
        # harness done before describe/seeds is legal per AGENTS.md
        self.assertEqual(ps.validate(st), [])

    def test_detects_bad_duplicate_links(self):
        st = ps.default_state()
        cid = ps.register_crash(st, {"track": "K", "title": "x",
                                     "stack_hash": "h", "status": "duplicate",
                                     "dir": "/tmp"})
        st["crashes"][cid]["duplicate_of"] = cid
        self.assertTrue(any("duplicate of itself" in p for p in ps.validate(st)))
        st["crashes"][cid]["duplicate_of"] = "crash-9999"
        self.assertTrue(any("unknown crash" in p for p in ps.validate(st)))

    def test_detects_out_of_range_repro_rate(self):
        st = ps.default_state()
        cid = ps.register_crash(st, {"track": "K", "title": "x",
                                     "stack_hash": "h", "status": "unique",
                                     "dir": "/tmp"})
        st["crashes"][cid]["repro_rate"] = 1.5
        self.assertTrue(any("repro_rate" in p for p in ps.validate(st)))


class TestCrashParse(StateTempMixin, unittest.TestCase):
    def reg(self, state, track, title, shash):
        with redirect_stdout(io.StringIO()) as out:
            crash_parse.register(state, track, title, shash, "/tmp/d")
        return out.getvalue()

    def test_norm_title_collapses_whitespace(self):
        self.assertEqual(crash_parse.norm_title("  KASAN:   slab-out\n"),
                         "KASAN: slab-out")

    def test_stack_hash_is_stable_and_frame_sensitive(self):
        a = "#0 0x1 in nvidia_ioctl\n#1 0x2 in rm_ioctl\n#2 0x3 in os_call\n"
        b = a.replace("os_call", "other_call")
        self.assertEqual(crash_parse.stack_hash(a), crash_parse.stack_hash(a))
        self.assertNotEqual(crash_parse.stack_hash(a), crash_parse.stack_hash(b))

    def test_new_then_duplicate(self):
        st = ps.default_state()
        self.assertIn("NEW", self.reg(st, "K", "KASAN: UAF in nv_free", "h1"))
        self.assertIn("DUP", self.reg(st, "K", "KASAN: UAF in nv_free", "h1"))
        self.assertEqual(len(st["crashes"]), 1)

    def test_flags_same_stack_different_title(self):
        st = ps.default_state()
        self.reg(st, "K", "title A", "same-hash")
        out = self.reg(st, "K", "title B", "same-hash")
        self.assertIn("FLAG", out)
        self.assertIn("same stack", out)
        self.assertEqual(len(st["crashes"]), 2)
        # The flag lives in the registry, not only in this output.
        self.assertEqual(st["crashes"]["crash-0002"]["status"], "flagged")

    def test_flags_same_title_different_stack(self):
        st = ps.default_state()
        self.reg(st, "K", "same title", "hash-1")
        out = self.reg(st, "K", "same title", "hash-2")
        self.assertIn("FLAG", out)
        self.assertIn("same title", out)
        self.assertEqual(st["crashes"]["crash-0002"]["status"], "flagged")

    def test_scan_dmesg_picks_up_kernel_and_nvrm_signals(self):
        st = ps.default_state()
        path = os.path.join(self.tmp.name, "dmesg.txt")
        with open(path, "w") as f:
            f.write("[  1.0] NVRM: Xid (PCI:0000:00:1e): 13, pid=1\n"
                    "[  2.0] BUG: KASAN: use-after-free in nv_uvm_free\n")
        with redirect_stdout(io.StringIO()):
            crash_parse.scan_dmesg(st, path)
        titles = [c["title"] for c in st["crashes"].values()]
        self.assertTrue(any("Xid" in t for t in titles), titles)
        self.assertTrue(any("KASAN" in t or "BUG" in t for t in titles), titles)


class TestFramelessSignature(unittest.TestCase):
    """A report with no stack at all still has to get a bug identity, and it
    is the only thing standing between one trace-less panic and a queue full
    of what look like distinct bugs."""

    def block(self, ts="1.0", addr="0xffff888012345678", cpu=3, pid=412,
              comm="syz-executor.0", oops=1, taint="G           O",
              tail="RIP: 0010:nv_open+0x40/0x120"):
        """A standard x86 oops prologue, which is all a frameless report is."""
        return ("[%s] BUG: unable to handle page fault for address: %s\n"
                "[%s] #PF: supervisor read access in kernel mode\n"
                "[%s] PGD 0 P4D 0\n"
                "[%s] Oops: 0000 [#%s] SMP NOPTI\n"
                "[%s] CPU: %s PID: %s Comm: %s Tainted: %s 6.6.0 #1\n"
                "[%s] %s\n"
                % (ts, addr, ts, ts, ts, oops, ts, cpu, pid, comm, taint,
                   ts, tail))

    def sig(self, block, **kw):
        return crash_parse.block_signature(block, **kw)

    def test_the_same_panic_twice_is_one_bug(self):
        """Every field that varies here varies on every occurrence of the same
        bug: the timestamp, the faulting address, the core, the task, the
        executor index, the oops counter, and the taint flags once the first
        die has tainted the kernel. Any one of them reaching the hash means a
        recurring trace-less panic registers as a new bug each time it fires,
        floods the queue, and buries the findings that matter — and triage and
        rca both run per registered crash, so the flood is not free."""
        self.assertEqual(
            self.sig(self.block()),
            self.sig(self.block(ts="9982.7", addr="0xffff88803abcdef0",
                                cpu=7, pid=9137, comm="syz-executor.4",
                                oops=2, taint="G      D    O")))

    def test_an_eight_digit_pid_is_still_recognised_as_a_pid(self):
        """Volatile fields are blanked before the hex blanking, not after: a
        long pid matches the address pattern, and if it were eaten as an
        address first the same panic would split on task id alone."""
        self.assertEqual(self.sig(self.block(pid=412)),
                         self.sig(self.block(pid=31337420)))

    def test_a_different_panic_is_a_different_bug(self):
        a = self.block()
        b = a.replace("page fault for address", "invalid opcode at")
        self.assertNotEqual(self.sig(a), self.sig(b))

    def test_a_different_process_is_a_different_bug(self):
        """Only the executor index is per-occurrence. The name is not, and a
        panic in modprobe is not the same bug as one in syz-executor."""
        self.assertNotEqual(self.sig(self.block(comm="syz-executor.0")),
                            self.sig(self.block(comm="modprobe")))

    def test_a_varying_register_dump_does_not_split_one_bug(self):
        """Register values are hex, so the address blanking neutralises them
        whether or not the line count reaches them."""
        a = self.block(tail="RAX: 0000000000000001 RBX: ffff888012345678")
        b = self.block(ts="2.0", pid=413,
                       tail="RAX: 00000000000000ff RBX: ffff88807654cba0")
        self.assertEqual(self.sig(a), self.sig(b))
        self.assertEqual(self.sig(a, lines=6), self.sig(b, lines=6))

    def test_two_faulting_functions_are_two_bugs(self):
        """The whole reason RIP is in the signature. Without it these two
        produce the same canonical title AND the same signature, so the second
        registers as a duplicate and never reaches rca — a lost finding, not
        queue noise."""
        a = self.block(tail="RIP: 0010:nv_open+0x40/0x120")
        b = self.block(tail="RIP: 0010:uvm_va_range_destroy+0x88/0x300")
        self.assertNotEqual(self.sig(a), self.sig(b))

    def test_the_faulting_function_is_found_wherever_it_sits(self):
        """How much prologue precedes RIP varies with the fault type, so a
        line count cannot reach it reliably. It is matched by pattern, and
        stays in the identity no matter how far down the report it is."""
        near = self.block(tail="RIP: 0010:nv_open+0x40/0x120")
        far = near.replace("RIP: 0010:nv_open",
                           "Call Trace:\n<TASK>\nRIP: 0010:nv_open")
        self.assertEqual(self.sig(near), self.sig(far))
        self.assertEqual(self.sig(near, lines=1), self.sig(far, lines=1))

    def test_the_faulting_function_survives_the_character_cut(self):
        """It is appended after the cut, never inside it: a long prologue must
        not be able to push the strongest evidence out of the identity."""
        a = self.block(tail="RIP: 0010:nv_open+0x40/0x120")
        b = self.block(tail="RIP: 0010:uvm_va_range_destroy+0x88/0x300")
        self.assertNotEqual(self.sig(a, chars=32), self.sig(b, chars=32))

    def test_the_same_function_at_a_different_offset_is_one_bug(self):
        """Offsets move with the build. stack_frames strips them for the same
        reason, and the same bug in two builds is one bug."""
        self.assertEqual(self.sig(self.block(tail="RIP: 0010:nv_open+0x40/0x120")),
                         self.sig(self.block(tail="RIP: 0010:nv_open+0x9c/0x120")))

    def test_the_older_bracketed_rip_format_is_read_the_same_way(self):
        a = self.block(tail="RIP: 0010:nv_open+0x40/0x120")
        b = self.block(tail="RIP: 0010:[<ffffffff81234567>] nv_open+0x40/0x120")
        self.assertEqual(self.sig(a), self.sig(b))

    def test_an_unresolved_rip_falls_back_to_the_prologue(self):
        """A bare address names nothing (module not loaded, no symbols), so
        there is nothing to add and the signature is what it was."""
        a = self.block(tail="RIP: 0010:0xffffffffc0a12345")
        b = self.block(tail="RIP: 0010:0xffffffffc0b98765")
        self.assertEqual(self.sig(a), self.sig(b))
        self.assertEqual(self.sig(a), self.sig(self.block(tail="Code: 48 8b")))

    def test_too_few_hashed_characters_merges_distinct_bugs(self):
        """Why the config floor exists. Cut short enough and the hash covers
        only the shared prologue, so the second bug never reaches rca."""
        a = self.block()
        b = a.replace("supervisor read access", "supervisor write access")
        self.assertNotEqual(self.sig(a), self.sig(b))
        self.assertEqual(self.sig(a, chars=24), self.sig(b, chars=24))

    def configured(self, **over):
        """Run with a patched triage config, as an operator edit would."""
        cfg = dict(gspwn_config.DEFAULTS["triage"], **over)
        orig = gspwn_config.triage
        gspwn_config.triage = lambda path=None: cfg
        self.addCleanup(setattr, gspwn_config, "triage", orig)

    def test_the_configured_depth_is_what_runs(self):
        """Comparing the default against itself would pass even if the value
        were hardcoded again, so this changes the config and checks the
        signature moves with it. An operator editing campaign.yaml has to
        actually change how bugs are counted."""
        block = self.block()
        default = self.sig(block)
        self.configured(frameless_signature_lines=1)
        self.assertNotEqual(self.sig(block), default)
        self.assertEqual(self.sig(block), self.sig(block, lines=1))

    def test_the_configured_char_cut_is_what_runs(self):
        block = self.block()
        default = self.sig(block)
        self.configured(frameless_signature_chars=32)
        self.assertNotEqual(self.sig(block), default)
        self.assertEqual(self.sig(block), self.sig(block, chars=32))

    def test_a_report_with_frames_never_reaches_the_fallback(self):
        """block_signature is the answer only when there is no stack. Where a
        frame hash exists it is the stronger key and has to win."""
        framed = ("BUG: KASAN: use-after-free in nv_free\n"
                  " #0 0x1 in nv_free\n #1 0x2 in rm_ioctl\n"
                  " #2 0x3 in os_call\n")
        self.assertTrue(crash_parse.stack_hash(framed))
        self.assertNotEqual(crash_parse.stack_hash(framed),
                            self.sig(framed))


class TestTriageSettingsDrift(StateTempMixin, unittest.TestCase):
    """Changing a dedup depth mid-campaign does not recompute the hashes
    already stored, so across the change one bug can register twice and two
    bugs can merge into one that never reaches rca. A comment saying so is not
    a check."""

    def reg(self, state, title="KASAN: UAF in nv_free", shash="h1"):
        with redirect_stdout(io.StringIO()):
            crash_parse.register(state, "K", title, shash, "/tmp/d")

    def test_the_settings_are_stamped_at_the_first_registration(self):
        st = ps.default_state()
        self.assertFalse(st["triage_settings"])
        self.reg(st)
        self.assertEqual(st["triage_settings"],
                         dict(gspwn_config.triage()))

    def test_the_stamp_is_not_rewritten_by_later_registrations(self):
        """Rewriting it would erase the evidence that the stored hashes were
        built under something else, which is the only thing it is for."""
        st = ps.default_state()
        self.reg(st)
        st["triage_settings"]["stack_hash_frames"] = 99
        self.reg(st, title="KASAN: UAF in nv_other", shash="h2")
        self.assertEqual(st["triage_settings"]["stack_hash_frames"], 99)

    def test_a_changed_depth_is_reported_by_validate(self):
        st = ps.default_state()
        self.reg(st)
        current = dict(gspwn_config.triage(), stack_hash_frames=7)
        drift = ps.triage_drift(st, current)
        self.assertEqual(drift, [("stack_hash_frames", 3, 7)])
        problems = ps.validate(st, current)
        self.assertTrue(any("stack_hash_frames" in p for p in problems),
                        problems)

    def test_unchanged_settings_are_not_reported(self):
        st = ps.default_state()
        self.reg(st)
        self.assertEqual(ps.triage_drift(st, dict(gspwn_config.triage())), [])
        self.assertEqual(ps.validate(st, dict(gspwn_config.triage())), [])

    def test_an_unstamped_registry_reports_nothing(self):
        """A state file from before this existed has no recorded settings, and
        inventing a comparison against the current ones would report drift
        that nobody caused."""
        st = ps.default_state()
        self.assertEqual(ps.triage_drift(st, dict(gspwn_config.triage())), [])

    def test_validate_still_works_without_the_settings(self):
        """The caller that cannot read config still gets every other check."""
        st = ps.default_state()
        self.reg(st)
        self.assertEqual(ps.validate(st), [])

    def test_the_validate_command_reports_the_drift(self):
        """Testing ps.validate directly proves the check works; it does not
        prove the command the agents actually run passes the config into it.
        That wiring is the whole feature from the outside."""
        st = ps.default_state()
        self.reg(st)
        ps.save(st)
        cfg = os.path.join(self.tmp.name, "drift.yaml")
        with open(cfg, "w") as f:
            f.write("triage:\n  stack_hash_frames: 7\n")
        env = dict(os.environ, GSPWN_STATE=ps.STATE_PATH, GSPWN_CONFIG=cfg)
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, "pipeline_ctl.py"),
             "validate"], env=env, capture_output=True, text=True)
        self.assertIn("stack_hash_frames", r.stdout + r.stderr)
        self.assertNotEqual(r.returncode, 0, r.stdout)


class TestTrace2Seed(unittest.TestCase):
    TRACE = (
        'openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3\n'
        'openat(AT_FDCWD, "/dev/nvidia0", O_RDWR) = 4\n'
        'ioctl(3, 0xc020462a, 0x7ffd) = 0\n'
        'ioctl(4, 0xdeadbeef, 0x7ffd) = 0\n'
        'openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 5\n'
        'ioctl(5, 0xc020462a, 0x0) = 0\n'
        'close(3) = 0\n'
    )
    MAP = {"0xc020462a": "ioctl$NV_ESC_RM_ALLOC"}

    def test_maps_devices_and_ioctls(self):
        prog = trace2seed.convert(self.TRACE, self.MAP)
        self.assertIn("r0 = openat$nvidiactl(", prog)
        self.assertIn("r1 = openat$nvidia(", prog)
        self.assertIn("ioctl$NV_ESC_RM_ALLOC(r0, 0xc020462a", prog)

    def test_unmapped_ioctl_is_recorded_not_dropped(self):
        prog = trace2seed.convert(self.TRACE, self.MAP)
        self.assertIn("# unmapped ioctl 0xdeadbeef", prog)

    def test_non_nvidia_fds_are_ignored(self):
        prog = trace2seed.convert(self.TRACE, self.MAP)
        self.assertNotIn("passwd", prog)
        # the ioctl on fd 5 (/etc/passwd) must not become a seed op
        self.assertEqual(prog.count("ioctl$NV_ESC_RM_ALLOC"), 1)

    def test_close_releases_the_resource(self):
        prog = trace2seed.convert(self.TRACE, self.MAP)
        self.assertIn("close(r0)", prog)


class TestIoctlInventoryParsing(unittest.TestCase):
    """The C-parsing invariants ioctl_inventory depends on.

    Each of these produced a wrong inventory before it was fixed, and each
    fails silently: the tool still emits a well-formed JSON file, just one
    that is short by a device node or attributes a privilege check to the
    wrong command.
    """

    # escape.c opens with a `//****` banner whose second and third characters
    # are a valid `/*`. A block-comment regex run before the line-comment one
    # treats that as the start of a comment and blanks the file to the next
    # `*/`, which lost all 21 escape dispatch sites in that file.
    BANNER = (
        "//***************************** Module Header ****************\n"
        "// the resource manager's customer\n"
        "//************************************************************\n"
        "int f(void)\n"
        "{\n"
        "    switch (cmd)\n"
        "    {\n"
        "        case NV_ESC_RM_FREE:\n"
        "        {\n"
        "            NV_CTL_DEVICE_ONLY(nv);\n"
        "            break;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )

    def test_banner_comment_does_not_blank_the_rest_of_the_file(self):
        clean = ioctl_inventory.strip_c_noise(self.BANNER)
        self.assertIn("case NV_ESC_RM_FREE:", clean)
        self.assertIn("switch (cmd)", clean)

    def test_stripping_preserves_line_numbering(self):
        clean = ioctl_inventory.strip_c_noise(self.BANNER)
        self.assertEqual(len(clean.splitlines()), len(self.BANNER.splitlines()))

    def test_a_brace_inside_a_string_is_not_counted(self):
        text = 'int f(void)\n{\n    p("{{{");\n    case NV_ESC_RM_FREE:\n}\n'
        clean = ioctl_inventory.strip_c_noise(text)
        self.assertEqual(clean.count("{"), 1)

    # NV_ESC_RM_ALLOC's device check sits inside a switch on hClass, so it
    # applies to some allocations and not others. A line-only scan either
    # truncates the case at the inner label or reports the check as
    # unconditional; both mislead the describe phase about which node to
    # attach the description to.
    NESTED = (
        "        case NV_ESC_RM_ALLOC:\n"
        "        {\n"
        "            switch (hClass)\n"
        "            {\n"
        "                case NV01_ROOT:\n"
        "                {\n"
        "                    NV_CTL_DEVICE_ONLY(nv);\n"
        "                    break;\n"
        "                }\n"
        "            }\n"
        "            break;\n"
        "        }\n"
        "        case NV_ESC_RM_FREE:\n"
        "        {\n"
        "            NV_CTL_DEVICE_ONLY(nv);\n"
        "            break;\n"
        "        }\n"
    )

    def blocks(self):
        return {lbl: (uncond, full)
                for lbl, _, uncond, full in ioctl_inventory.case_blocks(self.NESTED)}

    def test_nested_case_does_not_end_the_outer_case(self):
        blocks = self.blocks()
        self.assertIn("NV_ESC_RM_ALLOC", blocks)
        self.assertIn("NV01_ROOT", blocks["NV_ESC_RM_ALLOC"][1])

    def test_nested_assertion_is_not_reported_as_unconditional(self):
        uncond, full = self.blocks()["NV_ESC_RM_ALLOC"]
        self.assertNotIn("NV_CTL_DEVICE_ONLY", uncond)
        self.assertIn("NV_CTL_DEVICE_ONLY", full)

    def test_flat_assertion_is_reported_as_unconditional(self):
        uncond, _ = self.blocks()["NV_ESC_RM_FREE"]
        self.assertIn("NV_CTL_DEVICE_ONLY", uncond)

    def test_request_encoding_matches_an_observed_trace_value(self):
        # NV_ESC_RM_CONTROL is nr 0x2a and NVOS54_PARAMETERS measures 32
        # bytes on x86-64. 0xc020462a is the value this pipeline has seen in a
        # real strace, so it pins magic, direction and field order at once.
        self.assertEqual(
            hex(ioctl_inventory.rm_request(ord("F"), 0x2A, 32)), "0xc020462a")

    def test_map_refuses_two_commands_on_one_request_number(self):
        inventory = {"nodes": [{"commands": [
            {"name": "A", "requests": ["0x1"], "is_argument_array": False,
             "syzlang": "ioctl$A"},
            {"name": "B", "requests": ["0x1"], "is_argument_array": False,
             "syzlang": "ioctl$B"},
        ]}]}
        with self.assertRaises(ioctl_inventory.InventoryError) as cm:
            ioctl_inventory.build_map(inventory)
        self.assertIn("0x1", str(cm.exception))

    # The multiplexer fixture below is what the P0-6 map repair invalidated in
    # the two tests that follow. Both used NV_ESC_RM_CONTROL incidentally and
    # asserted that its request number reaches the name map, which the repair
    # stopped. TestIoctlMapKeyFormatting restates the original key-formatting
    # invariants on NV_ESC_RM_FREE, which still carries a call name; these two
    # assert the repair itself.
    MULTIPLEXER = {
        "name": "NV_ESC_RM_CONTROL", "nr": 42,
        "param_struct": "NVOS54_PARAMETERS", "param_size": 32,
        "requests": ["0xc020462a"], "is_argument_array": False,
        "syzlang": "ioctl$NV_ESC_RM_CONTROL",
    }

    def build_multiplexer_map(self, stamp=None):
        args = (stamp,) if stamp is not None else ()
        mapping, _skipped = ioctl_inventory.build_map(
            {"nodes": [{"commands": [dict(self.MULTIPLEXER)]}]}, *args)
        return mapping

    def test_the_version_stamp_survives_an_empty_name_map(self):
        # The stamp shares tools/ioctl_map.json with the request numbers, so a
        # key that trace2seed did not drop would be looked up as an ioctl. An
        # inventory carrying nothing but a multiplexer leaves the name map with
        # no request number at all, so the stamp has to be filtered by name and
        # not by whatever else the file happens to hold.
        mapping = self.build_multiplexer_map("610.57.04 (commit deadbee)")
        self.assertEqual(mapping[ioctl_inventory.MAP_VERSION_KEY],
                         "610.57.04 (commit deadbee)")
        self.assertTrue(
            ioctl_inventory.MAP_VERSION_KEY.startswith("comment"))
        self.assertTrue(
            ioctl_inventory.MAP_MULTIPLEXER_KEY.startswith("comment"))
        loaded = {k.lower(): v for k, v in mapping.items()
                  if not k.startswith("comment")}
        self.assertEqual(list(loaded), [])

    def test_a_multiplexer_request_number_is_not_looked_up_as_a_call(self):
        # The pre-repair map gave 0xc020462a the name ioctl$NV_ESC_RM_CONTROL,
        # which no description declares, so every trace-derived seed holding a
        # control call named a syscall syzkaller does not know and the whole
        # bank failed at parse. The request number now reaches the multiplexer
        # section instead, and convert() writes a comment naming the escape,
        # the parameter struct and the selector field.
        mapping = self.build_multiplexer_map()
        loaded = {k.lower(): v for k, v in mapping.items()
                  if not k.startswith("comment")}
        self.assertNotIn("0xc020462a", loaded)
        multiplexers = mapping[
            ioctl_inventory.MAP_MULTIPLEXER_KEY]["requests"]
        self.assertIn("0xc020462a", multiplexers)
        prog = trace2seed.convert(
            'openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3\n'
            'ioctl(3, 0xc020462a, 0x7ffd) = 0\n', loaded, multiplexers)
        self.assertNotIn("ioctl$NV_ESC_RM_CONTROL(r0, 0xc020462a", prog)
        self.assertNotIn("# unmapped ioctl", prog)
        self.assertIn("NV_ESC_RM_CONTROL on r0, request 0xc020462a", prog)
        self.assertIn("NVOS54_PARAMETERS.cmd", prog)


class TestReproHelpers(unittest.TestCase):
    def test_dmesg_delta_simple_append(self):
        self.assertEqual(repro_ctl.dmesg_delta("aaa", "aaabbb"), ("bbb", False))

    def test_dmesg_delta_survives_evicted_head(self):
        """Ring buffer dropped its head: anchor on the tail of `before`.

        A plain length-slice returns the wrong window here and would miss the
        reproduction entirely.
        """
        before = "head-noise " * 40 + "T" * 800   # tail exceeds the anchor
        after = before[200:] + "NEW CRASH TEXT"   # first 200 chars evicted
        self.assertEqual(repro_ctl.dmesg_delta(before, after),
                         ("NEW CRASH TEXT", False))
        self.assertNotEqual(after[len(before):], "NEW CRASH TEXT")

    def test_dmesg_delta_full_wrap_is_reported_not_guessed(self):
        # Nothing of `before` survives, so no delta can be computed. The
        # remaining buffer holds *earlier* runs' crash reports: scanning it
        # would score a hit on every later run.
        delta, wrapped = repro_ctl.dmesg_delta("old" * 400, "totally new")
        self.assertTrue(wrapped)

    def test_matched_signature_agrees_with_hit_counting(self):
        # The hit count and the logged verdict come from one predicate, so
        # they cannot disagree about whether a run reproduced.
        sig = {"funcs": ["nv_free"], "phrases": ["use-after-free in nv_free"]}
        self.assertEqual(repro_ctl.matched_signature("oops nv_free here", sig),
                         "nv_free")
        self.assertIsNone(repro_ctl.matched_signature("all quiet", sig))

    def test_a_different_bug_does_not_count_as_a_reproduction(self):
        # The rate that gates disclosure must measure *this* crash: a generic
        # kernel oops in the window is not evidence that this one reproduced.
        sig = {"funcs": ["nv_free"], "phrases": ["use-after-free in nv_free"]}
        self.assertIsNone(repro_ctl.matched_signature(
            "BUG: soft lockup - CPU#2 stuck", sig))
        self.assertIsNone(repro_ctl.matched_signature("KASAN: bad", sig))

    def test_a_title_phrase_counts_when_no_frame_is_available(self):
        # Report-less crashes still have to be scorable, so the title's
        # stable phrases are the fallback evidence.
        sig = {"funcs": [], "phrases": ["soft lockup in nv_uvm"]}
        self.assertEqual(repro_ctl.matched_signature(
            "x soft lockup in nv_uvm y", sig), "soft lockup in nv_uvm")


class TestReproVerifyBookkeeping(StateTempMixin, unittest.TestCase):
    """cmd_verify's durable progress accounting (no kernel involved)."""

    BOOT = "boot-current"

    def setUp(self):
        super().setUp()
        self._orig_root = repro_ctl.REPO_ROOT
        repro_ctl.REPO_ROOT = self.tmp.name
        self.addCleanup(lambda: setattr(repro_ctl, "REPO_ROOT",
                                        self._orig_root))
        # Stub the kernel-facing helpers: this suite must not depend on a real
        # dmesg (absent in containers, and a host emitting BUG:/KASAN: lines
        # would flip these assertions).
        self._orig_dmesg = repro_ctl.dmesg_text
        self._orig_boot = repro_ctl.boot_id
        self.addCleanup(lambda: setattr(repro_ctl, "dmesg_text",
                                        self._orig_dmesg))
        self.addCleanup(lambda: setattr(repro_ctl, "boot_id", self._orig_boot))
        self.log = "quiet boot\n"
        self.crashing = False      # every run reproduces
        self.wrapping = False      # ring buffer wraps past the anchor
        self.calls = 0
        repro_ctl.dmesg_text = self._fake_dmesg
        repro_ctl.boot_id = lambda: self.BOOT
        self.cid = "crash-0001"
        pocs = os.path.join(self.tmp.name, "artifacts", "pocs", self.cid)
        os.makedirs(pocs)
        exe = os.path.join(pocs, "repro")
        with open(exe, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")   # a repro that never reproduces
        os.chmod(exe, 0o755)
        st = ps.default_state()
        ps.register_crash(st, {"track": "K", "title": "KASAN: UAF in nv_zzz",
                               "stack_hash": "h", "status": "unique",
                               "dir": "/tmp"})
        ps.save(st)

    def _fake_dmesg(self):
        """Called twice per run: once before the repro, once after."""
        self.calls += 1
        is_after = self.calls % 2 == 0
        if is_after and self.wrapping:
            return "a totally different buffer %d\n" % self.calls
        if is_after and self.crashing:
            self.log += "KASAN: use-after-free in nv_zzz\n"
        return self.log

    def run_verify(self, runs, restart=False):
        with redirect_stdout(io.StringIO()) as out:
            self.rc = repro_ctl.cmd_verify(self.cid, runs, restart)
        return out.getvalue()

    def test_clean_runs_classify_unreproducible(self):
        out = self.run_verify(3)
        c = ps.load()["crashes"][self.cid]
        self.assertEqual(c["status"], "unreproducible")
        self.assertEqual(c["repro_rate"], 0.0)
        self.assertEqual(c["repro_progress"]["runs_done"], 3)
        self.assertIn("0/3", out)

    def test_progress_is_persisted_after_each_run(self):
        self.run_verify(2)
        self.assertFalse(ps.load()["crashes"][self.cid]["repro_progress"]
                         ["in_flight"])

    def test_interrupted_run_after_reboot_is_a_reproduction(self):
        """A run that panicked the box must not be silently lost."""
        with ps.transaction() as st:
            st["crashes"][self.cid]["repro_progress"] = {
                "runs_done": 1, "hits": 0, "in_flight": True,
                "boot_id": "boot-before-the-panic"}
        out = self.run_verify(2)
        self.assertIn("rebooted mid-run", out)
        c = ps.load()["crashes"][self.cid]
        self.assertEqual(c["repro_progress"]["hits"], 1)  # recovered run counts
        self.assertEqual(c["status"], "flaky")            # 1/2, not 0/2

    def test_interrupted_run_on_the_same_boot_is_void(self):
        """Ctrl-C, an OOM kill, or a repro that will not exec leaves the same
        in_flight marker as a panic — but the machine never went down, so it
        is not evidence of a bug and must not inflate the rate."""
        with ps.transaction() as st:
            st["crashes"][self.cid]["repro_progress"] = {
                "runs_done": 1, "hits": 0, "in_flight": True,
                "boot_id": self.BOOT}          # same boot: no panic happened
        out = self.run_verify(2)
        self.assertIn("VOID", out)
        c = ps.load()["crashes"][self.cid]
        self.assertEqual(c["repro_progress"]["hits"], 0)
        self.assertEqual(c["repro_progress"]["inconclusive"], 1)
        self.assertEqual(c["status"], "unreproducible")
        self.assertEqual(c["repro_rate"], 0.0)

    def test_rerun_with_fewer_runs_cannot_exceed_100_percent(self):
        """A 10-run pass re-verified with --runs 3 must not report 300%.

        The rate is the disclosure gate; dividing accumulated hits by a
        smaller requested run count wrote a rate the tool's own validate()
        rejects.
        """
        with ps.transaction() as st:
            st["crashes"][self.cid]["repro_progress"] = {
                "runs_done": 10, "hits": 9, "inconclusive": 0,
                "in_flight": False, "boot_id": self.BOOT}
        self.run_verify(3)
        st = ps.load()
        c = st["crashes"][self.cid]
        self.assertEqual(c["repro_rate"], 0.9)            # 9/10, not 9/3
        self.assertEqual(c["repro_progress"]["runs_done"], 10)  # never shrinks
        self.assertEqual(ps.validate(st), [])

    def test_ring_wrap_voids_the_run_instead_of_scoring_a_hit(self):
        self.wrapping = True
        out = self.run_verify(2)
        c = ps.load()["crashes"][self.cid]
        self.assertIn("VOID", out)
        self.assertEqual(c["repro_progress"]["hits"], 0)
        self.assertGreater(c["repro_progress"]["inconclusive"], 0)

    def test_all_void_records_no_rate(self):
        self.wrapping = True
        out = self.run_verify(1)
        self.assertIn("no rate recorded", out)
        self.assertEqual(self.rc, 1)
        self.assertIsNone(ps.load()["crashes"][self.cid]["repro_rate"])

    def test_repro_that_cannot_exec_is_void_not_a_crash(self):
        os.chmod(os.path.join(self.tmp.name, "artifacts", "pocs", self.cid,
                              "repro"), 0o644)
        out = self.run_verify(2)
        self.assertIn("would not run", out)
        self.assertEqual(self.rc, 1)          # no rate from zero counted runs
        c = ps.load()["crashes"][self.cid]
        self.assertEqual(c["repro_progress"]["hits"], 0)
        self.assertIsNone(c["repro_rate"])

    def test_reproducing_repro_is_reliable(self):
        self.crashing = True
        self.run_verify(3)
        c = ps.load()["crashes"][self.cid]
        self.assertEqual(c["repro_rate"], 1.0)
        self.assertEqual(c["status"], "reliable")

    def test_restart_discards_partial_progress(self):
        with ps.transaction() as st:
            st["crashes"][self.cid]["repro_progress"] = {
                "runs_done": 1, "hits": 1, "in_flight": True,
                "boot_id": "boot-before-the-panic"}
        self.run_verify(2, restart=True)
        c = ps.load()["crashes"][self.cid]
        self.assertEqual(c["repro_progress"]["hits"], 0)
        self.assertEqual(c["status"], "unreproducible")


class TestRoundModel(StateTempMixin, unittest.TestCase):
    def finish_round_phases(self, st):
        for p in ps.SETUP_PHASES + ps.ROUND_PHASES:
            ps.update_phase(st, p, "done")

    def test_new_state_starts_in_round_one(self):
        st = ps.default_state()
        self.assertEqual(ps.round_number(st), 1)
        self.assertEqual(ps.next_action(st), ("phase", "provision"))

    def test_v1_state_migrates_to_round_one(self):
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        with open(self.state_path, "w") as f:
            json.dump({"version": 1, "phases": {}, "crashes": {}}, f)
        st = ps.load()
        self.assertEqual(st["version"], ps.SCHEMA_VERSION)
        self.assertEqual(ps.round_number(st), 1)
        self.assertEqual(ps.validate(st), [])

    def test_round_phases_precede_the_decision(self):
        st = ps.default_state()
        self.finish_round_phases(st)
        self.assertEqual(ps.next_action(st), ("decide", None))

    def test_continue_then_advance_resets_round_phases(self):
        st = ps.default_state()
        self.finish_round_phases(st)
        ps.end_round(st, verdict="growing", run_hours=24)
        ps.record_decision(st, "continue", "still growing")
        self.assertEqual(ps.next_action(st), ("advance-round", None))
        ps.advance_round(st)
        self.assertEqual(ps.round_number(st), 2)
        # setup stays done, round phases reset, crash registry untouched
        self.assertEqual(st["phases"]["provision"]["status"], "done")
        self.assertEqual(st["phases"]["describe"]["status"], "pending")
        self.assertEqual(ps.next_action(st), ("phase", "describe"))

    def test_stop_routes_to_report(self):
        st = ps.default_state()
        self.finish_round_phases(st)
        ps.end_round(st, verdict="plateaued")
        ps.record_decision(st, "stop", "plateaued")
        self.assertEqual(ps.next_action(st), ("phase", "report"))
        ps.update_phase(st, "report", "done")
        self.assertEqual(ps.next_action(st), ("done", None))

    def test_cannot_advance_without_a_continue_decision(self):
        st = ps.default_state()
        self.finish_round_phases(st)
        with self.assertRaises(ValueError):
            ps.advance_round(st)
        ps.record_decision(st, "stop", "done here")
        with self.assertRaises(ValueError):
            ps.advance_round(st)

    def test_end_round_rejects_bad_verdict(self):
        st = ps.default_state()
        with self.assertRaises(ValueError):
            ps.end_round(st, verdict="probably-fine")

    def test_run_hours_accumulate_across_rounds(self):
        st = ps.default_state()
        self.finish_round_phases(st)
        ps.end_round(st, verdict="growing", run_hours=72)
        ps.record_decision(st, "continue", "growing")
        ps.advance_round(st)
        self.finish_round_phases(st)
        ps.end_round(st, verdict="growing", run_hours=72)
        self.assertEqual(ps.total_run_hours(st), 144)


class TestLoopDecision(StateTempMixin, unittest.TestCase):
    def state_at(self, rnd, verdict="growing", hours=0.0):
        st = ps.default_state()
        for _ in range(rnd - 1):
            ps.current_round(st)["decision"] = "continue"
            st["rounds"].append(dict(ps.DEFAULT_ROUND,
                                     round=len(st["rounds"]) + 1))
        r = ps.current_round(st)
        r["coverage_verdict"] = verdict
        r["run_hours"] = hours
        return st

    def test_continues_while_growing_under_caps(self):
        d, why = ps.loop_decision(self.state_at(1), max_rounds=3)
        self.assertEqual(d, "continue", why)

    def test_round_cap_stops(self):
        d, why = ps.loop_decision(self.state_at(3), max_rounds=3)
        self.assertEqual(d, "stop")
        self.assertIn("round cap", why)

    def test_plateau_stops(self):
        d, why = ps.loop_decision(self.state_at(1, verdict="plateaued"),
                                  max_rounds=5)
        self.assertEqual(d, "stop")
        self.assertIn("plateau", why)

    def test_unknown_verdict_stops_rather_than_spending_blind(self):
        d, why = ps.loop_decision(self.state_at(1, verdict="unknown"),
                                  max_rounds=5)
        self.assertEqual(d, "stop")
        self.assertIn("no coverage verdict", why)

    def test_budget_beats_growing_coverage(self):
        st = self.state_at(1, verdict="growing", hours=300)
        ps.record_run_hours("r1-k1", 300.0)   # the ledger is the authority
        d, why = ps.loop_decision(st, max_rounds=9, max_total_run_hours=216)
        self.assertEqual(d, "stop")
        self.assertIn("budget", why)

    def test_a_lost_ledger_stops_the_loop_rather_than_guessing(self):
        # Hours on record with no ledger: the loop must not spend another
        # campaign on the assumption that the budget is untouched.
        st = self.state_at(1, verdict="growing", hours=300)
        with self.assertRaises(ps.SpendLedgerMissing):
            ps.loop_decision(st, max_rounds=9, max_total_run_hours=216)

    def test_plateau_can_be_disabled(self):
        d, _ = ps.loop_decision(self.state_at(1, verdict="plateaued"),
                                max_rounds=5, stop_on_plateau=False)
        self.assertEqual(d, "continue")


class TestCoverage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._orig = coverage_ctl.RUNS_DIR
        coverage_ctl.RUNS_DIR = self.tmp.name
        self.addCleanup(lambda: setattr(coverage_ctl, "RUNS_DIR", self._orig))

    def write_csv(self, run_id, points):
        """points: [(ts_offset_min, edges)]"""
        d = os.path.join(self.tmp.name, run_id)
        os.makedirs(d, exist_ok=True)
        base = 1_700_000_000
        with open(os.path.join(d, "coverage.csv"), "w") as f:
            f.write(",".join(coverage_ctl.FIELDS) + "\n")
            for off, edges in points:
                f.write(csv_line(base + off * 60, edges) + "\n")

    def verdict(self, points, window=240, growth=0.02):
        self.write_csv("r1", points)
        return coverage_ctl.plateau_verdict(
            coverage_ctl.metric_rows("r1"), window, growth)[0]

    def test_growing_curve(self):
        pts = [(i * 60, 1000 + i * 200) for i in range(8)]
        self.assertEqual(self.verdict(pts), "growing")

    def test_flat_curve_is_plateaued(self):
        pts = [(i * 60, 5000 + i) for i in range(8)]
        self.assertEqual(self.verdict(pts), "plateaued")

    def test_too_few_samples_is_unknown(self):
        self.assertEqual(self.verdict([(0, 100), (60, 200)]), "unknown")

    def test_short_span_is_unknown_not_plateaued(self):
        """A run that just started must never read as plateaued."""
        pts = [(0, 100), (10, 101), (20, 102)]
        self.assertEqual(self.verdict(pts, window=240), "unknown")

    def test_early_growth_then_flat_tail_is_plateaued(self):
        # Big early gains must not mask a flat trailing window.
        pts = [(0, 100), (60, 5000), (120, 9000)] + \
              [(180 + i * 60, 9000 + i) for i in range(5)]
        self.assertEqual(self.verdict(pts, window=240), "plateaued")

    def test_missing_edges_column_is_unknown(self):
        d = os.path.join(self.tmp.name, "r2")
        os.makedirs(d)
        with open(os.path.join(d, "coverage.csv"), "w") as f:
            f.write(",".join(coverage_ctl.FIELDS) + "\n")
            for i in range(6):
                f.write(csv_line(1_700_000_000 + i * 3600,
                                 source="unreachable") + "\n")
        rows = coverage_ctl.metric_rows("r2")
        self.assertEqual(coverage_ctl.plateau_verdict(rows, 240, 0.02)[0],
                         "unknown")

    def test_parses_nested_json_stats(self):
        data = {"stats": [{"name": "corpus", "value": 421},
                          {"name": "coverage", "value": "12,345"}]}
        self.assertEqual(coverage_ctl._dig(data, {"corpus"}), 421)
        self.assertEqual(coverage_ctl._dig(data, {"coverage"}), 12345)

    def test_scrapes_dashboard_html(self):
        html = "<tr><td>corpus</td><td>1,234</td></tr><b>coverage</b>: 5678"
        got = coverage_ctl.parse_html(html)
        self.assertEqual(got["corpus"], 1234)
        self.assertEqual(got["edges"], 5678)


class TestCorpusPromotion(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.seeds = os.path.join(self.tmp.name, "seeds")
        os.makedirs(self.seeds)

    def test_hash_ignores_comments_and_whitespace(self):
        a = "openat$nvidiactl(0x0)\nioctl$NV(r0)\n"
        b = "  openat$nvidiactl(0x0)  \n# a comment\nioctl$NV(r0)\n\n"
        self.assertEqual(corpus_ctl.prog_hash(a), corpus_ctl.prog_hash(b))

    def test_hash_distinguishes_real_differences(self):
        self.assertNotEqual(corpus_ctl.prog_hash("ioctl$A(r0)"),
                            corpus_ctl.prog_hash("ioctl$B(r0)"))

    def test_existing_hashes_picks_up_untracked_files(self):
        with open(os.path.join(self.seeds, "seed-0001.syz"), "w") as f:
            f.write("ioctl$NV_ESC_RM_ALLOC(r0)\n")
        known = corpus_ctl.existing_hashes(self.seeds, {"hashes": {}})
        self.assertEqual(len(known), 1)
        self.assertEqual(list(known.values())[0]["source"], "pre-existing")

    def test_ledger_roundtrip_and_corruption_recovery(self):
        corpus_ctl.save_ledger(self.seeds, {"hashes": {"h1": {"file": "a"}}})
        self.assertEqual(corpus_ctl.load_ledger(self.seeds)["hashes"]["h1"]
                         ["file"], "a")
        with open(os.path.join(self.seeds, corpus_ctl.LEDGER), "w") as f:
            f.write("{corrupt")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(corpus_ctl.load_ledger(self.seeds),
                             {"hashes": {}})


class TestPipelineCtlCLI(PipelineCtlRunner, unittest.TestCase):
    """End-to-end CLI coverage via GSPWN_STATE redirection."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.join(self.tmp.name, "state", "pipeline.json")
        self.env = dict(os.environ, GSPWN_STATE=self.state)

    def test_init_show_next_setphase_flow(self):
        self.assertIn("initialized", self.ctl("init"))
        self.assertIn("already exists", self.ctl("init"))
        self.assertEqual(self.ctl("next").strip(), "provision")
        self.ctl("set-phase", "provision", "done", "--notes", "gate ok")
        self.assertEqual(self.ctl("next").strip(), "build")
        show = self.ctl("show")
        self.assertIn("provision", show)
        self.assertIn("gate ok", show)

    def test_set_phase_rejects_unknown_values(self):
        self.ctl("init")
        self.ctl("set-phase", "nope", "done", expect=2)
        self.ctl("set-phase", "build", "finished", expect=2)

    def test_crash_set_and_validate(self):
        self.ctl("init")
        st = ps.load(self.state)
        ps.register_crash(st, {"track": "K", "title": "KASAN: UAF in nv",
                               "stack_hash": "h1", "status": "unique",
                               "dir": "/tmp/a"})
        ps.register_crash(st, {"track": "K", "title": "KASAN: UAF in nv2",
                               "stack_hash": "h2", "status": "unique",
                               "dir": "/tmp/b"})
        ps.save(st, self.state)

        self.assertIn("crash-0001", self.ctl("crash-list"))
        self.assertIn("status=duplicate",
                      self.ctl("crash-set", "crash-0002",
                               "--duplicate-of", "crash-0001"))
        rows = self.ctl("crash-list", "--status", "duplicate").strip().split("\n")
        self.assertEqual(len(rows), 1, rows)          # filter excludes 0001
        self.assertTrue(rows[0].startswith("crash-0002"), rows)
        self.assertIn("dup_of=crash-0001", rows[0])
        self.assertIn("state is consistent", self.ctl("validate"))

        self.ctl("crash-set", "crash-0001", "--status", "reliable",
                 "--repro-rate", "0.9", "--disclosure", "submitted")
        out = self.ctl("crash-list", "--track", "K")
        self.assertIn("90%", out)
        self.assertIn("state is consistent", self.ctl("validate"))

    def test_crash_set_rejects_bad_references(self):
        self.ctl("init")
        st = ps.load(self.state)
        ps.register_crash(st, {"track": "K", "title": "t", "stack_hash": "h",
                               "status": "unique", "dir": "/tmp"})
        ps.save(st, self.state)
        self.ctl("crash-set", "crash-0404", "--status", "unique", expect=1)
        self.ctl("crash-set", "crash-0001", "--duplicate-of", "crash-0001",
                 expect=1)
        self.ctl("crash-set", "crash-0001", "--status", "banana", expect=1)
        self.ctl("crash-set", "crash-0001", "--repro-rate", "3", expect=1)

    def test_validate_reports_inconsistency(self):
        self.ctl("init")
        st = ps.load(self.state)
        ps.update_phase(st, "report", "done")
        ps.save(st, self.state)
        self.assertIn("PROBLEM", self.ctl("validate", expect=1))

    def test_clearing_a_duplicate_link_returns_the_crash_to_the_queue(self):
        """Undoing a triage mistake has to be one command.

        Clearing only the link left status=duplicate with nothing to duplicate
        — validate called that consistent and the crash stayed out of the
        unique/RCA queue permanently.
        """
        self.ctl("init")
        st = ps.load(self.state)
        for h in ("h1", "h2"):
            ps.register_crash(st, {"track": "K", "title": "KASAN: UAF in nv",
                                   "stack_hash": h, "status": "unique",
                                   "dir": "/tmp"})
        ps.save(st, self.state)
        self.ctl("crash-set", "crash-0002", "--duplicate-of", "crash-0001")
        self.ctl("crash-set", "crash-0002", "--duplicate-of", "none")
        c = ps.load(self.state)["crashes"]["crash-0002"]
        self.assertIsNone(c["duplicate_of"])
        self.assertEqual(c["status"], "unique")
        self.assertIn("crash-0002", self.ctl("crash-list", "--status",
                                             "unique"))
        # An explicit --status in the same command still wins.
        self.ctl("crash-set", "crash-0002", "--duplicate-of", "crash-0001")
        self.ctl("crash-set", "crash-0002", "--duplicate-of", "none",
                 "--status", "flagged")
        self.assertEqual(ps.load(self.state)["crashes"]["crash-0002"]["status"],
                         "flagged")

    def test_crash_list_rejects_an_unknown_status(self):
        # An unknown status must be a usage error, not an empty result:
        # "no crashes match" with exit 0 is indistinguishable from success.
        self.ctl("init")
        self.ctl("crash-list", "--status", "uniqe", expect=2)

    def test_phase_notes_do_not_survive_the_next_status(self):
        self.ctl("init")
        self.ctl("set-phase", "provision", "done", "--notes", "gate ok")
        self.ctl("set-phase", "provision", "failed")
        show = self.ctl("show")
        self.assertIn("failed", show)
        self.assertNotIn("gate ok", show)


class TestConfig(unittest.TestCase):
    """config/campaign.yaml is the only place a cap lives."""

    def write(self, text):
        p = os.path.join(self.tmp.name, "campaign.yaml")
        with open(p, "w") as f:
            f.write(text)
        return p

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_shipped_config_is_valid(self):
        cfg = gspwn_config.load(os.path.join(os.path.dirname(HERE), "config",
                                             "campaign.yaml"))
        self.assertEqual(cfg["loop"]["corpus_policy"], "carry")
        self.assertGreater(cfg["loop"]["campaign_hours"], 0)

    def test_defaults_fill_omitted_keys(self):
        cfg = gspwn_config.load(self.write("loop:\n  max_rounds: 7\n"))
        self.assertEqual(cfg["loop"]["max_rounds"], 7)
        self.assertEqual(cfg["loop"]["campaign_hours"],
                         gspwn_config.DEFAULTS["loop"]["campaign_hours"])
        self.assertEqual(cfg["track_k"]["procs"],
                         gspwn_config.DEFAULTS["track_k"]["procs"])

    def test_a_typo_in_a_cap_is_rejected_not_defaulted(self):
        # An unrecognized key must not fall back to the default value while
        # appearing to have been applied.
        with self.assertRaises(gspwn_config.ConfigError) as cm:
            gspwn_config.load(self.write("loop:\n  max_rouds: 10\n"))
        self.assertIn("max_rouds", str(cm.exception))

    def test_nonsense_caps_are_rejected(self):
        for bad in ("loop:\n  max_rounds: 0\n",
                    "loop:\n  max_total_run_hours: -5\n",
                    "loop:\n  plateau_min_growth: 40\n",
                    "loop:\n  corpus_policy: sometimes\n",
                    "track_k:\n  procs: 0\n",
                    "triage:\n  stack_hash_frames: 0\n",
                    "triage:\n  frameless_signature_lines: 0\n",
                    # Below the floor the hash covers little more than the
                    # report's opening words, so unrelated trace-less panics
                    # sharing a prologue merge and the second never reaches
                    # rca.
                    "triage:\n  frameless_signature_chars: 8\n",
                    "coverage:\n  min_fit_samples: 2\n",
                    "coverage:\n  model_min_r2: 0\n",
                    "coverage:\n  fit_tail_fraction: 0\n"):
            with self.assertRaises(gspwn_config.ConfigError, msg=bad):
                gspwn_config.load(self.write(bad))

    def test_campaign_longer_than_the_budget_is_rejected(self):
        with self.assertRaises(gspwn_config.ConfigError) as cm:
            gspwn_config.load(self.write(
                "loop:\n  campaign_hours: 400\n  max_total_run_hours: 100\n"))
        self.assertIn("campaign_hours", str(cm.exception))

    def test_plateau_window_must_hold_enough_samples(self):
        # < 3 samples in the window always yields 'unknown', which stops the
        # loop — a config that guarantees that is a misconfiguration.
        with self.assertRaises(gspwn_config.ConfigError):
            gspwn_config.load(self.write(
                "loop:\n  plateau_window_min: 10\n  coverage_sample_min: 10\n"))

    def test_a_resume_anchor_carrying_a_quote_is_rejected(self):
        """It is substituted into a shell line the operator already quoted, so
        a quote would end that quoting and hand the rest to the shell. The
        config is the wrong place to discover that, since the launch it breaks
        is the one recovering from a panic."""
        for bad in ('orchestrator:\n  resume_anchor: "the agent\'s brief"\n',
                    'orchestrator:\n  resume_anchor: \'say "brief" first\'\n',
                    'orchestrator:\n  resume_anchor: "   "\n'):
            with self.assertRaises(gspwn_config.ConfigError, msg=bad) as cm:
                gspwn_config.load(self.write(bad))
            self.assertIn("resume_anchor", str(cm.exception))

    def test_a_plain_resume_anchor_is_accepted(self):
        cfg = gspwn_config.load(self.write(
            "orchestrator:\n  resume_anchor: run brief, it is truth\n"))
        self.assertEqual(cfg["orchestrator"]["resume_anchor"],
                         "run brief, it is truth")

    def test_manager_url_follows_the_configured_port(self):
        p = self.write('track_k:\n  http: "127.0.0.1:9999"\n')
        self.assertEqual(gspwn_config.manager_url(p), "http://127.0.0.1:9999")


class TestSeedInjection(unittest.TestCase):
    """Seeds must land in corpus.db — syz-manager reads nothing else."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        fake = os.path.join(self.tmp.name, "syz-db")
        with open(fake, "w") as f:
            f.write(FAKE_SYZ_DB)
        os.chmod(fake, 0o755)
        self._orig_db = corpus_ctl.SYZ_DB
        corpus_ctl.SYZ_DB = fake
        self.addCleanup(lambda: setattr(corpus_ctl, "SYZ_DB", self._orig_db))
        self.seeds = os.path.join(self.tmp.name, "seeds")
        os.makedirs(self.seeds)
        for n in ("a", "b"):
            with open(os.path.join(self.seeds, "%s.syz" % n), "w") as f:
                f.write("ioctl$NV_%s(r0)\n" % n)
        self.db = os.path.join(self.tmp.name, "corpus.db")

    def packed(self):
        with open(self.db) as f:
            return json.load(f)

    def test_seeds_are_packed_into_the_corpus_db(self):
        with redirect_stdout(io.StringIO()):
            n = campaign_ctl.install_seeds(self.db, self.seeds)
        self.assertEqual(n, 2)
        self.assertTrue(os.path.exists(self.db))
        self.assertEqual(len(self.packed()), 2)
        self.assertIn("ioctl$NV_a(r0)", "".join(self.packed().values()))

    def test_packing_seeds_preserves_a_carried_corpus(self):
        """Round N+1 carries the corpus AND adds the seed bank; neither wins."""
        with open(self.db, "w") as f:
            json.dump({"carried-0001": "ioctl$NV_carried(r0)\n"}, f)
        with redirect_stdout(io.StringIO()):
            campaign_ctl.install_seeds(self.db, self.seeds)
        blob = self.packed()
        self.assertEqual(len(blob), 3)
        self.assertIn("ioctl$NV_carried(r0)", "".join(blob.values()))

    def test_empty_seed_bank_warns_and_packs_nothing(self):
        empty = os.path.join(self.tmp.name, "empty")
        os.makedirs(empty)
        with redirect_stdout(io.StringIO()) as out:
            n = campaign_ctl.install_seeds(self.db, empty)
        self.assertEqual(n, 0)
        self.assertIn("NOT seeded", out.getvalue())
        self.assertFalse(os.path.exists(self.db))


class TestCampaignDeadline(StateTempMixin, unittest.TestCase):
    """A campaign has to end on its own for the loop to be unattended."""

    def setUp(self):
        super().setUp()
        self._orig_runs = campaign_ctl.RUNS_DIR
        campaign_ctl.RUNS_DIR = os.path.join(self.tmp.name, "runs")
        self.addCleanup(lambda: setattr(campaign_ctl, "RUNS_DIR",
                                        self._orig_runs))
        self.calls = []

    class Args:
        def __init__(self, run_id):
            self.run_id = run_id

    def fake_systemctl(self, active):
        """Swap the module reference, never mutate the real subprocess module:
        patching subprocess.run in place would leak into every other test."""
        calls = self.calls

        def run(cmd, **kw):
            calls.append(cmd)
            return types.SimpleNamespace(
                stdout="active\n" if active else "inactive\n",
                stderr="", returncode=0)
        real = campaign_ctl.subprocess
        campaign_ctl.subprocess = types.SimpleNamespace(run=run)
        self.addCleanup(lambda: setattr(campaign_ctl, "subprocess", real))

    def test_deadline_roundtrips_as_an_absolute_time(self):
        at = campaign_ctl.write_deadline("r1-k1", 24)
        self.assertAlmostEqual(campaign_ctl.read_deadline("r1-k1"), at, delta=1)

    def test_before_the_deadline_nothing_is_stopped(self):
        campaign_ctl.write_deadline("r1-k1", 5)
        self.fake_systemctl(True)
        with redirect_stdout(io.StringIO()) as out:
            campaign_ctl.cmd_check_deadline(self.Args("r1-k1"))
        self.assertIn("left of its campaign window", out.getvalue())
        self.assertEqual(self.calls, [])

    def test_past_the_deadline_the_campaign_is_stopped_and_recorded(self):
        campaign_ctl.write_deadline("r1-k1", -1)     # already elapsed
        self.fake_systemctl(True)
        with redirect_stdout(io.StringIO()) as out:
            campaign_ctl.cmd_check_deadline(self.Args("r1-k1"))
        self.assertIn("window elapsed", out.getvalue())
        self.assertIn(["systemctl", "stop", "gspwn-k"], self.calls)
        events = ps.load()["campaigns"]
        self.assertTrue(any(e.get("note") == "campaign window elapsed"
                            for e in events), events)

    def test_a_run_with_no_deadline_is_left_alone(self):
        with redirect_stdout(io.StringIO()) as out:
            campaign_ctl.cmd_check_deadline(self.Args("r9-k9"))
        self.assertIn("no deadline recorded", out.getvalue())


class TestDerivedRoundEnd(StateTempMixin, unittest.TestCase):
    """round-end measures the loop's numbers instead of being told them."""

    def setUp(self):
        super().setUp()
        self._orig_runs = coverage_ctl.RUNS_DIR
        coverage_ctl.RUNS_DIR = os.path.join(self.tmp.name, "runs")
        self.addCleanup(lambda: setattr(coverage_ctl, "RUNS_DIR",
                                        self._orig_runs))
        ps.save(ps.default_state())

    def write_curve(self, run_id, points):
        d = os.path.join(coverage_ctl.RUNS_DIR, run_id)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "coverage.csv"), "w") as f:
            f.write(",".join(coverage_ctl.FIELDS) + "\n")
            for ts, edges in points:
                f.write(csv_line(ts, edges, source="json:/stats") + "\n")

    class Args:
        def __init__(self, **kw):
            for k in ("from_run", "coverage_verdict", "new_crashes",
                      "edges_start", "edges_end", "run_hours", "notes",
                      "worklist"):
                setattr(self, k, kw.get(k))

    def test_growing_curve_is_measured_from_the_csv(self):
        base = 1_700_000_000
        # 10 h of samples, edges climbing steadily -> still growing.
        self.write_curve("r1-k1", [(base + i * 3600, 1000 + i * 300)
                                   for i in range(11)])
        with ps.transaction() as st:
            ps.register_crash(st, {"track": "K", "title": "t", "stack_hash": "h",
                                   "status": "unique", "dir": "/tmp"})
        with redirect_stdout(io.StringIO()) as out:
            pipeline_ctl_cmd_round_end(self.Args(from_run="r1-k1"))
        r = ps.load()["rounds"][-1]
        self.assertEqual(r["coverage_verdict"], "growing")
        self.assertEqual(r["edges_start"], 1000)
        self.assertEqual(r["edges_end"], 4000)
        self.assertEqual(r["run_hours"], 10.0)     # measured, not the config
        self.assertEqual(r["new_crashes"], 1)
        self.assertIn("measured from run", out.getvalue())

    def test_flat_curve_is_measured_as_plateaued(self):
        base = 1_700_000_000
        self.write_curve("r1-k1", [(base + i * 3600, 5000 + i)
                                   for i in range(11)])
        with redirect_stdout(io.StringIO()):
            pipeline_ctl_cmd_round_end(self.Args(from_run="r1-k1"))
        self.assertEqual(ps.load()["rounds"][-1]["coverage_verdict"],
                         "plateaued")

    def test_a_run_that_died_early_bills_only_what_it_used(self):
        """The budget cap is only real if run_hours reflects the actual run."""
        base = 1_700_000_000
        self.write_curve("r1-k1", [(base, 100), (base + 3600, 120),
                                   (base + 7200, 130)])
        with redirect_stdout(io.StringIO()):
            pipeline_ctl_cmd_round_end(self.Args(from_run="r1-k1"))
        self.assertEqual(ps.load()["rounds"][-1]["run_hours"], 2.0)

    def test_missing_curve_yields_unknown_which_stops_the_loop(self):
        with redirect_stdout(io.StringIO()):
            pipeline_ctl_cmd_round_end(self.Args(from_run="never-ran"))
        st = ps.load()
        self.assertEqual(st["rounds"][-1]["coverage_verdict"], "unknown")
        decision, reason = ps.loop_decision(st, max_rounds=5,
                                            max_total_run_hours=100)
        self.assertEqual(decision, "stop")

    def two_hour_curve(self, run_id="r1-k1"):
        base = 1_700_000_000
        self.write_curve(run_id, [(base, 100), (base + 3600, 120),
                                  (base + 7200, 130)])

    def test_hours_entered_by_hand_reach_the_ledger_the_budget_reads(self):
        """A round total the budget cannot see is not a spend ceiling.

        --run-hours belongs to no single run, so it bills under the round's
        own key. A measured run alongside it is the case that used to fail
        silently: the ledger existed and looked healthy, holding the derived
        2 h while the round recorded 7, so no guard ever fired and the
        difference simply went unspent on paper.
        """
        self.two_hour_curve()
        with redirect_stdout(io.StringIO()):
            pipeline_ctl_cmd_round_end(self.Args(from_run="r1-k1",
                                                 run_hours=5.0))
        self.assertEqual(ps.load()["rounds"][-1]["run_hours"], 7.0)
        self.assertEqual(ps.spend_for_budget(), 7.0)

    def test_re_running_round_end_does_not_double_bill_manual_hours(self):
        """The ledger takes the round's unattributed total, not the
        increment, so the round history and the budget cannot drift apart
        when round-end is retried. Re-measuring the same run bills it once;
        the hand-entered hours accumulate."""
        self.two_hour_curve()
        for hours in (5.0, 3.0):
            with redirect_stdout(io.StringIO()):
                pipeline_ctl_cmd_round_end(self.Args(from_run="r1-k1",
                                                     run_hours=hours))
        self.assertEqual(ps.load()["rounds"][-1]["run_hours"], 10.0)
        self.assertEqual(ps.spend_for_budget(), 10.0)

    def test_an_explicit_flag_still_overrides_the_measurement(self):
        base = 1_700_000_000
        self.write_curve("r1-k1", [(base + i * 3600, 1000 + i * 300)
                                   for i in range(11)])
        with redirect_stdout(io.StringIO()):
            pipeline_ctl_cmd_round_end(
                self.Args(from_run="r1-k1", coverage_verdict="plateaued"))
        self.assertEqual(ps.load()["rounds"][-1]["coverage_verdict"],
                         "plateaued")


class TestTrackUCoverage(StateTempMixin, unittest.TestCase):
    """Track U has to be in the loop's view, or a round stops while the
    container-toolkit harnesses are still finding coverage."""

    def setUp(self):
        # StateTempMixin, not just a temp RUNS_DIR: cmd_sample reads the
        # registry, and without the redirect these tests answer from the
        # real state/pipeline.json.
        super().setUp()
        self.addCleanup(setattr, coverage_ctl, "RUNS_DIR",
                        coverage_ctl.RUNS_DIR)
        coverage_ctl.RUNS_DIR = os.path.join(self.tmp.name, "runs")

    def register_run(self, run_id):
        """Put a run in the registry — cmd_sample refuses unknown ids."""
        st = ps.default_state()
        ps.current_round(st)["run_ids"] = [run_id]
        ps.save(st)

    def harness(self, run_id, name, stats=None, queue=0):
        d = os.path.join(coverage_ctl.track_u_dir(run_id), name)
        os.makedirs(d, exist_ok=True)
        if stats:
            with open(os.path.join(d, "fuzzer_stats"), "w") as f:
                f.write(stats)
        if queue:
            q = os.path.join(d, "queue")
            os.makedirs(q, exist_ok=True)
            for i in range(queue):
                open(os.path.join(q, "id%03d" % i), "w").close()
        return d

    def test_afl_stats_are_summed_across_harnesses(self):
        self.harness("r1-u1", "parse_cfg",
                     "edges_found : 300\nexecs_done : 1000\n"
                     "unique_crashes : 1\ncorpus_count : 40\n")
        self.harness("r1-u1", "ldcache",
                     "edges_found : 200\nexecs_done : 500\n"
                     "unique_crashes : 0\ncorpus_count : 10\n")
        row, source = coverage_ctl.collect_u("r1-u1")
        self.assertEqual(row["edges"], 500)
        self.assertEqual(row["execs"], 1500)
        self.assertEqual(row["crashes"], 1)
        self.assertEqual(row["corpus"], 50)
        self.assertIn("fuzzer_stats", source)

    def test_libfuzzer_harness_reports_corpus_but_no_edges(self):
        # Corpus size must never stand in for coverage.
        self.harness("r1-u1", "oci_parse", queue=7)
        row, source = coverage_ctl.collect_u("r1-u1")
        self.assertEqual(row["corpus"], 7)
        self.assertIsNone(row.get("edges"))
        self.assertEqual(source, "corpus-count-only")

    def test_missing_track_u_output_is_unreachable(self):
        row, source = coverage_ctl.collect_u("never-ran")
        self.assertEqual(source, "unreachable")
        self.assertEqual(row, {})

    def write_curve(self, run_id, track, points):
        d = os.path.join(coverage_ctl.RUNS_DIR, run_id)
        os.makedirs(d, exist_ok=True)
        with open(coverage_ctl.csv_path(run_id, track), "w") as f:
            f.write(",".join(coverage_ctl.FIELDS) + "\n")
            for ts, edges in points:
                f.write(csv_line(ts, edges, source="src") + "\n")

    def test_a_growing_track_u_keeps_the_round_alive(self):
        base = 1_700_000_000
        self.write_curve("r1", "k", [(base + i * 3600, 5000 + i)
                                     for i in range(11)])      # flat
        self.write_curve("r1", "u", [(base + i * 3600, 100 + i * 50)
                                     for i in range(11)])      # growing
        verdict, detail, per = coverage_ctl.run_verdict("r1", 240, 0.02)
        self.assertEqual(per["k"][0], "plateaued")
        self.assertEqual(per["u"][0], "growing")
        self.assertEqual(verdict, "growing")
        self.assertIn("u: growing", detail)

    def test_both_flat_is_plateaued(self):
        base = 1_700_000_000
        for t in ("k", "u"):
            self.write_curve("r1", t, [(base + i * 3600, 5000 + i)
                                       for i in range(11)])
        self.assertEqual(coverage_ctl.run_verdict("r1", 240, 0.02)[0],
                         "plateaued")

    def test_an_unsampled_track_does_not_force_unknown(self):
        """Track U absent entirely must not veto a healthy Track K verdict."""
        base = 1_700_000_000
        self.write_curve("r1", "k", [(base + i * 3600, 1000 + i * 300)
                                     for i in range(11)])
        verdict, _, per = coverage_ctl.run_verdict("r1", 240, 0.02)
        self.assertEqual(verdict, "growing")
        self.assertNotIn("u", per)

    def test_no_samples_at_all_is_unknown(self):
        self.assertEqual(coverage_ctl.run_verdict("r1", 240, 0.02)[0],
                         "unknown")

    def test_sampling_stops_once_the_campaign_window_is_up(self):
        self.register_run("r1-k1")
        d = os.path.join(coverage_ctl.RUNS_DIR, "r1-k1")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "deadline"), "w") as f:
            f.write("%d\n" % (int(__import__("time").time()) - 10))
        args = types.SimpleNamespace(run_id="r1-k1", url="http://127.0.0.1:1",
                                     track="k", force=False)
        with redirect_stdout(io.StringIO()) as out:
            rc = coverage_ctl.cmd_sample(args)
        self.assertEqual(rc, 0)
        self.assertIn("not sampling", out.getvalue())
        self.assertFalse(os.path.exists(coverage_ctl.csv_path("r1-k1")))


class TestFlaggedCrashesReachTheRegistry(StateTempMixin, unittest.TestCase):
    """A collision in one dedup key but not the other must survive as a
    registry entry, not just a line of stdout."""

    def setUp(self):
        super().setUp()
        self.st = ps.default_state()
        with redirect_stdout(io.StringIO()):
            crash_parse.register(self.st, "K", "KASAN: UAF in nv_a", "hash-a",
                                 "/tmp/a")

    def test_same_title_different_stack_is_registered_flagged(self):
        # A collision must produce a registry entry, not only log output:
        # a second bug behind a generic title has to remain addressable.
        with redirect_stdout(io.StringIO()) as out:
            cid = crash_parse.register(self.st, "K", "KASAN: UAF in nv_a",
                                       "hash-DIFFERENT", "/tmp/b")
        self.assertIsNotNone(cid)
        c = self.st["crashes"][cid]
        self.assertEqual(c["status"], "flagged")
        self.assertIn("same title", c["notes"])
        self.assertIn("FLAG", out.getvalue())

    def test_same_stack_different_title_is_registered_flagged(self):
        with redirect_stdout(io.StringIO()):
            cid = crash_parse.register(self.st, "K", "KASAN: UAF in nv_b",
                                       "hash-a", "/tmp/c")
        self.assertEqual(self.st["crashes"][cid]["status"], "flagged")
        self.assertIn("same stack", self.st["crashes"][cid]["notes"])

    def test_identical_crash_is_not_re_registered(self):
        """Harvest runs after every reboot, so re-scans must be idempotent."""
        before = len(self.st["crashes"])
        with redirect_stdout(io.StringIO()) as out:
            cid = crash_parse.register(self.st, "K", "KASAN: UAF in nv_a",
                                       "hash-a", "/tmp/a")
        self.assertIsNone(cid)
        self.assertEqual(len(self.st["crashes"]), before)
        self.assertIn("DUP", out.getvalue())

    def test_flagged_entries_are_findable_and_valid(self):
        with redirect_stdout(io.StringIO()):
            crash_parse.register(self.st, "K", "KASAN: UAF in nv_a", "hash-x",
                                 "/tmp/b")
        self.assertEqual(ps.validate(self.st), [])
        flagged = [c for c in self.st["crashes"].values()
                   if c["status"] == "flagged"]
        self.assertEqual(len(flagged), 1)


class TestBudgetGuard(StateTempMixin, unittest.TestCase):
    """A campaign outside a round never passes through round-decide, so the
    run-hour cap has to be checked where a campaign starts.

    Hours come from the ledger, not the state file: the ledger is what a run
    redirecting GSPWN_STATE cannot escape.
    """

    def test_campaign_within_budget_is_allowed(self):
        ps.record_run_hours("r1-k1", 100.0)
        self.assertEqual(campaign_ctl.check_budget(24, 216), 100.0)

    def test_campaign_over_budget_is_refused(self):
        ps.record_run_hours("r1-k1", 200.0)
        with self.assertRaises(SystemExit) as cm:
            campaign_ctl.check_budget(24, 216)
        self.assertIn("max_total_run_hours", str(cm.exception))

    def test_a_fresh_state_file_does_not_buy_a_fresh_budget(self):
        # The redirect bypass: pipeline.json says nothing was spent, the
        # ledger says 200 h. The ledger wins.
        ps.record_run_hours("r1-k1", 200.0)
        ps.save(ps.default_state())
        with self.assertRaises(SystemExit) as cm:
            campaign_ctl.check_budget(24, 216)
        self.assertIn("max_total_run_hours", str(cm.exception))

    def test_a_state_redirect_cannot_seed_the_ledger_from_its_own_state(
            self):
        """Seeding must read the same file spend_for_budget does.

        The shape that broke: 100 h on the machine's record, no ledger yet,
        and a run with its own registry billing first. Seeding from
        STATE_PATH built the ledger out of that run's empty registry and all
        100 h dropped off the cap — the bypass the ledger exists to close,
        reopened one function below the guard.
        """
        st = ps.default_state()
        st["rounds"][-1]["run_ids"] = ["r1-k1"]
        st["rounds"][-1]["run_hours"] = 100.0
        st["rounds"][-1]["run_hours_by_run"] = {"r1-k1": 100.0}
        ps.save(st, ps.DEFAULT_STATE_PATH)
        # The side run redirects its registry; the ledger must not follow.
        # StateTempMixin's cleanup restores STATE_PATH afterwards.
        ps.STATE_PATH = os.path.join(self.tmp.name, "state", "side.json")
        ps.save(ps.default_state(), ps.STATE_PATH)

        ps.record_run_hours("side-1", 2.0)

        self.assertEqual(ps.spend_for_budget(), 102.0)
        self.assertEqual(ps._read_ledger(self.spend_path)["r1-k1"], 100.0)

    def test_a_lost_ledger_refuses_rather_than_reading_as_unspent(self):
        # Fail closed: hours on record with no ledger means the ledger was
        # lost, not that the budget is fresh.
        st = ps.default_state()
        st["rounds"][-1]["run_hours"] = 200.0
        ps.save(st)
        with self.assertRaises(SystemExit) as cm:
            campaign_ctl.check_budget(24, 216)
        self.assertIn("spend-init", str(cm.exception))

    def test_a_genuinely_fresh_machine_starts_at_zero(self):
        # No ledger AND no recorded hours is a new machine, not a lost
        # ledger — it must still be able to start its first campaign.
        self.assertEqual(campaign_ctl.check_budget(24, 216), 0.0)


class TestPlateauAcrossRestarts(unittest.TestCase):
    """The fuzzer restarts by design: units are Restart=always and the box
    panics. Edge counts reset to zero when it does."""

    def rows(self, edges, step=3600, gpu="ok"):
        base = 1_700_000_000
        return [{"ts": base + i * step, "edges": e, "gpu": gpu}
                for i, e in enumerate(edges)]

    def test_the_accumulation_curve_never_goes_backwards(self):
        """The original bug: comparing across the reset gave -75% growth,
        which read as a plateau and stopped a campaign that was in fact
        finding new edges fast."""
        rows = self.rows([6000, 10000, 14000, 18000, 22000, 24000, 25000,
                          26000, 500, 2500, 4500, 6500])
        curve = [s for _n, s in coverage_ctl.accumulate(rows)]
        self.assertEqual(curve, sorted(curve))
        self.assertEqual(max(curve), 26000)

    def test_a_run_mid_replay_is_unknown_not_plateaued(self):
        """It has rediscovered nothing new, but it has not had the chance:
        a flat curve during recovery is not evidence of saturation."""
        rows = self.rows([6000, 14000, 22000, 26000, 500, 2500, 4500, 6500])
        verdict, detail = coverage_ctl.plateau_verdict(rows, 240, 0.02)
        self.assertEqual(verdict, "unknown", detail)
        self.assertIn("replaying", detail)

    def test_replay_after_a_restart_is_not_reported_as_growth(self):
        """The expensive version of the same error. A saturated run panics,
        replays its corpus, and the climb back reads as tens of percent of
        growth — so on a box that panics by design, a dead campaign can keep
        itself alive indefinitely through its own crashes."""
        saturated = [int(20000 * (1 - 2.718 ** (-i / 8.0))) for i in range(40)]
        replay = [int(19997 * (1 - 2.718 ** (-i / 40.0))) for i in range(60)]
        verdict, detail = coverage_ctl.plateau_verdict(
            self.rows(saturated + replay), 240, 0.02)
        self.assertNotEqual(verdict, "growing", detail)

    def test_discovery_past_the_high_water_mark_is_growth(self):
        """Recovery finished and the run went beyond where it had been. That
        is the only thing after a restart that counts as discovery."""
        rows = self.rows([20000, 24000, 26000, 500, 12000, 26000,
                          30000, 34000, 38000, 42000])
        verdict, detail = coverage_ctl.plateau_verdict(rows, 240, 0.02)
        self.assertEqual(verdict, "growing", detail)

    def test_a_flat_run_after_full_recovery_plateaus(self):
        rows = self.rows([20000, 24000, 26000, 9000, 20000, 26000,
                          26010, 26020, 26030, 26040])
        verdict, detail = coverage_ctl.plateau_verdict(rows, 240, 0.02)
        self.assertEqual(verdict, "plateaued", detail)

    def test_a_run_with_no_restart_is_unaffected(self):
        rows = self.rows([1000, 2000, 3000, 4000, 5000])
        self.assertEqual(coverage_ctl.plateau_verdict(rows, 240, 0.02)[0],
                         "growing")

    def test_round_history_never_records_lost_coverage(self):
        """edges_end below edges_start would read as the round going backwards."""
        rows = self.rows([1000, 26000, 500, 6500])
        seg, restarted = coverage_ctl.since_last_reset(rows)
        self.assertTrue(restarted)
        self.assertEqual(max(r["edges"] for r in rows), 26000)


class TestDiscoveryModel(unittest.TestCase):
    """The plateau decision is an extrapolation from a fitted species
    accumulation curve, so it has to recover a known curve, refuse a curve it
    does not describe, and measure against work rather than the clock."""

    BASE = 1_700_000_000

    def rows(self, pairs, gpu="ok", step=600):
        """pairs: [(cumulative execs, reported edges)]"""
        return [{"ts": self.BASE + i * step, "edges": e, "execs": x,
                 "gpu": gpu} for i, (x, e) in enumerate(pairs)]

    def power(self, beta, n=60, per=200_000, scale=2000):
        return [(i * per, int(scale * i ** beta)) for i in range(1, n)]

    def verdict(self, rows, horizon=24):
        return coverage_ctl.plateau_verdict(rows, 240, 0.02,
                                            horizon_hours=horizon)

    def test_the_fit_recovers_a_known_discovery_exponent(self):
        for beta in (0.2, 0.5, 0.9):
            fit = coverage_ctl.heaps_fit(
                coverage_ctl.accumulate(self.rows(self.power(beta))))
            self.assertAlmostEqual(fit["beta"], beta, places=3)
            self.assertGreater(fit["r2"], 0.999)

    def test_executions_accumulate_across_a_counter_reset(self):
        """A restart zeroes the exec counter. Work already done did happen,
        and a negative delta would erase it."""
        acc = coverage_ctl.accumulate(
            self.rows([(1000, 10), (2000, 20), (3000, 30),
                       (500, 5), (1500, 15)]))
        self.assertEqual([n for n, _s in acc], [1000, 2000, 3000, 3500, 4500])

    def test_edges_accumulate_as_a_running_maximum(self):
        """Replay after a restart re-covers edges already counted, so the
        curve must not move for them."""
        acc = coverage_ctl.accumulate(
            self.rows([(1000, 900), (2000, 26000), (3000, 500),
                       (4000, 9000), (5000, 26050)]))
        self.assertEqual([s for _n, s in acc],
                         [900, 26000, 26000, 26000, 26050])

    def test_a_near_linear_discovery_curve_is_growing(self):
        self.assertEqual(self.verdict(self.rows(self.power(0.95)))[0],
                         "growing")

    def test_a_dead_flat_tail_is_a_plateau(self):
        """The clearest plateau there is: not one input in the recent stretch
        of work reached code the run had not already reached."""
        climb = self.power(0.8, n=40)
        flat = [((39 + i) * 200_000, climb[-1][1]) for i in range(1, 40)]
        verdict, detail = self.verdict(self.rows(climb + flat))
        self.assertEqual(verdict, "plateaued", detail)
        self.assertIn("no new edge", detail)

    def test_the_fit_follows_the_current_regime_not_the_whole_run(self):
        """A run that climbed hard and then went flat would report a healthy
        exponent if the early steep phase were allowed to dominate."""
        climb = self.power(0.8, n=40)
        flat = [((39 + i) * 200_000, climb[-1][1] + 1) for i in range(1, 40)]
        rows = self.rows(climb + flat)
        whole = coverage_ctl.heaps_fit(coverage_ctl.accumulate(rows))
        tail = coverage_ctl.heaps_fit(
            coverage_ctl.fit_tail(coverage_ctl.accumulate(rows), 0.5))
        self.assertGreater(whole["beta"], tail["beta"])
        self.assertLess(tail["beta"], 0.01)

    def test_a_curve_the_model_does_not_describe_is_unknown(self):
        """Extrapolating from a curve that is not a discovery curve is how a
        confident wrong number reaches a report."""
        noise = [500, 9000, 1200, 15000, 800, 20000, 3000, 40000, 1500, 60000]
        rows = self.rows([(i * 100_000, noise[i % 10] + i)
                          for i in range(1, 40)])
        verdict, detail = self.verdict(rows)
        self.assertEqual(verdict, "unknown", detail)
        self.assertIn("does not fit the model", detail)

    def test_a_superlinear_series_is_unknown(self):
        """beta above 1 means edges are arriving faster than inputs, which an
        accumulation curve cannot do — the series is something else."""
        rows = self.rows([(i * 100_000, int(100 * i ** 2)) for i in range(1, 40)])
        verdict, detail = self.verdict(rows)
        self.assertEqual(verdict, "unknown", detail)
        self.assertIn("beta", detail)

    def test_too_few_points_is_unknown_not_plateaued(self):
        rows = self.rows([(i * 100_000, 500 * i) for i in range(1, 6)])
        verdict, detail = self.verdict(rows)
        self.assertEqual(verdict, "unknown", detail)

    def test_a_longer_horizon_expects_more_new_edges(self):
        """The verdict answers 'is another campaign of THIS length worth
        running', so the horizon has to move the number."""
        fit = coverage_ctl.heaps_fit(
            coverage_ctl.accumulate(self.rows(self.power(0.5))))
        short = coverage_ctl.expected_new_edges(fit, 1_000_000)
        long_ = coverage_ctl.expected_new_edges(fit, 10_000_000)
        self.assertGreater(long_, short)

    def test_discovery_slows_as_the_run_goes_on(self):
        """Concavity: the same extra work buys fewer edges later. If this
        fails the model is not a saturating one and the verdict is
        meaningless."""
        early = coverage_ctl.heaps_fit(
            coverage_ctl.accumulate(self.rows(self.power(0.5, n=20))))
        late = coverage_ctl.heaps_fit(
            coverage_ctl.accumulate(self.rows(self.power(0.5, n=60))))
        self.assertGreater(
            coverage_ctl.expected_new_edges(early, 1_000_000),
            coverage_ctl.expected_new_edges(late, 1_000_000))

    def test_a_slow_stretch_is_not_mistaken_for_saturation(self):
        """The reason the x axis is executions. Same wall-clock, same curve
        shape, but one box did a hundredth of the work — measured against the
        clock it looks saturated, measured against work it has barely
        started."""
        busy = self.rows(self.power(0.5))
        idle = self.rows([(x // 100, e) for x, e in self.power(0.5)])
        self.assertEqual(self.verdict(busy)[0], self.verdict(idle)[0])
        self.assertLess(coverage_ctl.exec_rate_per_hour(idle),
                        coverage_ctl.exec_rate_per_hour(busy))

    def test_an_unhealthy_gpu_still_blocks_a_plateau_claim(self):
        """A GPU off the bus flattens the curve exactly like saturation, and
        only the plateau reading becomes a claim about the target."""
        climb = self.power(0.8, n=40)
        flat = [((39 + i) * 200_000, climb[-1][1]) for i in range(1, 40)]
        rows = self.rows(climb + flat)
        self.assertEqual(self.verdict(rows)[0], "plateaued")
        for r in rows[-6:]:
            r["gpu"] = "unreachable"
        verdict, detail = self.verdict(rows)
        self.assertEqual(verdict, "unknown", detail)
        self.assertIn("GPU was not healthy", detail)

    def test_a_flat_prefix_is_not_a_plateau_when_execs_stop_being_reported(self):
        """accumulate() drops the execution axis at the first sample missing an
        exec count and never picks it up again, so the tail can end long before
        the run does. A flat prefix must not then be reported as a plateau: this
        run quadrupled its coverage after the counts stopped."""
        flat = [(i * 100_000, 1000) for i in range(1, 31)]
        rows = self.rows(flat)
        for i in range(20):
            rows.append({"ts": rows[-1]["ts"] + 600, "edges": 1000 + 200 * i,
                         "execs": None, "gpu": "ok"})
        self.assertIsNone(coverage_ctl.exec_rate_per_hour(rows))
        verdict, detail = self.verdict(rows)
        self.assertNotEqual(verdict, "plateaued", detail)
        self.assertNotIn("no new edge", detail)

    def test_ols_refuses_a_degenerate_fit(self):
        """A slope of zero from a flat series would read as a perfectly
        trusted flat curve rather than as no information."""
        self.assertIsNone(coverage_ctl._ols([1, 2, 3], [5, 5, 5]))
        self.assertIsNone(coverage_ctl._ols([1, 1, 1], [1, 2, 3]))
        self.assertIsNone(coverage_ctl._ols([1, 2], [1, 2]))


class TestTrackUCorpusCounting(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._orig = coverage_ctl.RUNS_DIR
        coverage_ctl.RUNS_DIR = os.path.join(self.tmp.name, "runs")
        self.addCleanup(lambda: setattr(coverage_ctl, "RUNS_DIR", self._orig))

    def test_afl_queue_is_not_counted_twice(self):
        """AFL++ writes fuzzer_stats and queue/ into the same directory, so
        adding both double-counted every AFL++ harness's corpus."""
        d = os.path.join(coverage_ctl.track_u_dir("r1"), "h1")
        os.makedirs(os.path.join(d, "queue"))
        with open(os.path.join(d, "fuzzer_stats"), "w") as f:
            f.write("edges_found : 100\ncorpus_count : 40\n")
        for i in range(40):
            open(os.path.join(d, "queue", "id%03d" % i), "w").close()
        row, _ = coverage_ctl.collect_u("r1")
        self.assertEqual(row["corpus"], 40)

    def test_libfuzzer_dir_is_still_counted(self):
        d = os.path.join(coverage_ctl.track_u_dir("r1"), "h2")
        os.makedirs(os.path.join(d, "corpus"))
        for i in range(5):
            open(os.path.join(d, "corpus", "c%d" % i), "w").close()
        row, _ = coverage_ctl.collect_u("r1")
        self.assertEqual(row["corpus"], 5)


class TestConfigRobustness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, text):
        p = os.path.join(self.tmp.name, "c.yaml")
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_wrong_typed_values_raise_config_error_not_typeerror(self):
        """Callers catch ConfigError. A TypeError escaping validate() takes
        down every tool, including the root sampler, with a raw traceback."""
        for bad in ('loop:\n  plateau_window_min: "240"\n',
                    "loop:\n  plateau_window_min: null\n",
                    'loop:\n  coverage_sample_min: "10"\n',
                    'loop:\n  campaign_hours: "24"\n',
                    'track_k:\n  smoke_window_minutes: "30"\n'):
            with self.assertRaises(gspwn_config.ConfigError, msg=bad):
                gspwn_config.load(self.write(bad))


class TestWorklistHandoff(StateTempMixin, unittest.TestCase):
    """The learning handoff is state, not a filename two prompts agree on."""

    @staticmethod
    def close_round(st, **kw):
        """Bring a round to the point where it may legally advance.

        advance_round refuses a round whose phases are unfinished or whose
        hours were never measured — that guardrail is what stops a round
        slipping past without billing its spend. These tests are about the
        worklist, so they satisfy it rather than work around it.
        """
        for p in ps.ROUND_PHASES:
            ps.update_phase(st, p, "done")
        ps.end_round(st, verdict="growing", run_hours=1.0, **kw)

    def test_worklist_carries_into_the_next_round(self):
        st = ps.default_state()
        self.close_round(st, worklist="artifacts/eval/r1-k1/worklist.md")
        ps.record_decision(st, "continue", "still growing")
        new = ps.advance_round(st)
        self.assertEqual(new["round"], 2)
        self.assertEqual(new["worklist_in"],
                         "artifacts/eval/r1-k1/worklist.md")
        self.assertIsNone(new["worklist"])   # round 2 has not produced one yet

    def test_first_round_has_no_inherited_worklist(self):
        self.assertIsNone(ps.current_round(ps.default_state())["worklist_in"])

    def test_cli_prints_the_path_and_flags_a_missing_file(self):
        import pipeline_ctl
        st = ps.default_state()
        self.close_round(st, worklist="artifacts/eval/gone.md")
        ps.record_decision(st, "continue", "x")
        ps.advance_round(st)
        ps.save(st)
        args = types.SimpleNamespace()
        with redirect_stdout(io.StringIO()) as out:
            rc = pipeline_ctl.cmd_worklist(args)
        self.assertEqual(rc, 1)              # recorded but not on disk
        self.assertIn("MISSING", out.getvalue())


class TestGpuHealthGatesThePlateau(unittest.TestCase):
    """A dead GPU flattens the curve exactly like a finished round.

    The fuzzer keeps executing against a card that has fallen off the bus, the
    sampler keeps appending rows, and edge growth stops. Without the GPU
    column that reads as "plateaued", the loop stops, and the round is written
    up as having reached a coverage ceiling it never reached.
    """

    B = 1_700_000_000

    def rows(self, edges, gpu="ok", step=3600):
        """gpu: one status for every row, or a per-row list, or None to model
        a curve written before the column existed."""
        out = []
        for i, e in enumerate(edges):
            r = {"ts": self.B + i * step, "edges": e}
            g = gpu[i] if isinstance(gpu, list) else gpu
            if g is not None:
                r["gpu"] = g
            out.append(r)
        return out

    FLAT = [9000, 9010, 9020, 9030, 9040, 9050]
    GROWING = [1000, 3000, 6000, 10000, 15000, 21000]

    def verdict(self, rows):
        return coverage_ctl.plateau_verdict(rows, 240, 0.02)

    def test_a_flat_curve_on_a_healthy_gpu_is_still_a_plateau(self):
        # The gate must not fire on the case it is not meant to catch.
        self.assertEqual(self.verdict(self.rows(self.FLAT))[0], "plateaued")

    def test_a_flat_curve_over_a_dead_gpu_is_unknown_not_plateaued(self):
        verdict, detail = self.verdict(self.rows(self.FLAT, "dead"))
        self.assertEqual(verdict, "unknown")
        self.assertIn("dead", detail)

    def test_one_unhealthy_sample_in_the_window_blocks_the_claim(self):
        """A window is contaminated by any sample taken while the GPU was out.

        Growth measured across a period the card was not answering is not a
        measurement of the target, however few samples are affected.
        """
        gpu = ["ok", "ok", "ok", "ok", "hung", "ok"]
        verdict, detail = self.verdict(self.rows(self.FLAT, gpu))
        self.assertEqual(verdict, "unknown")
        self.assertIn("hung x1", detail)

    def test_a_curve_with_no_gpu_column_cannot_report_a_plateau(self):
        """Absence of evidence that the GPU was alive is not evidence it was.

        Curves written before the column existed fail closed, so a run in
        flight across the upgrade stops the loop instead of asserting a
        plateau nothing checked.
        """
        verdict, detail = self.verdict(self.rows(self.FLAT, None))
        self.assertEqual(verdict, "unknown")
        self.assertIn("unrecorded", detail)

    def test_growth_is_still_growth_when_the_gpu_probe_failed(self):
        """The carve-out: only the plateau reading is gated.

        Coverage cannot climb on a card that is not answering, so growth is
        its own evidence the probe was having a bad moment. Gating this too
        would let one transient nvidia-smi failure end a campaign that was
        still finding edges.
        """
        self.assertEqual(self.verdict(self.rows(self.GROWING, "dead"))[0],
                         "growing")


class TestCoverageCsvSchema(StateTempMixin, unittest.TestCase):
    """The gpu column was added to a file format already in use.

    These go through cmd_sample rather than reproducing its append by hand.
    The behaviour being guarded is how the sampler chooses its fieldnames, so
    a test that picks the fieldnames itself would pass no matter what the
    sampler does.
    """

    OLD_FIELDS = ["ts", "uptime_s", "edges", "corpus", "corpus_bytes",
                  "crashes", "execs", "source"]

    def setUp(self):
        super().setUp()
        self.runs = tempfile.TemporaryDirectory()
        self.addCleanup(self.runs.cleanup)
        self._orig = coverage_ctl.RUNS_DIR
        coverage_ctl.RUNS_DIR = self.runs.name
        self.addCleanup(lambda: setattr(coverage_ctl, "RUNS_DIR", self._orig))
        # No syz-manager and no GPU in this suite: stub both collectors so
        # these exercise the CSV write path and nothing else.
        self._orig_collect = coverage_ctl.collect
        self._orig_gpu = coverage_ctl.gpu_health
        self.edges = 100
        coverage_ctl.collect = lambda rid, url, track: (
            {"edges": self.edges}, "json:/stats")
        coverage_ctl.gpu_health = lambda: ("ok", "stub")
        self.addCleanup(lambda: setattr(coverage_ctl, "collect",
                                        self._orig_collect))
        self.addCleanup(lambda: setattr(coverage_ctl, "gpu_health",
                                        self._orig_gpu))
        st = ps.default_state()
        st["campaigns"].append({"track": "k", "action": "install",
                                "run_id": "r1", "at": ps._now(), "hours": 1,
                                "note": ""})
        ps.save(st)

    def sample(self):
        args = types.SimpleNamespace(run_id="r1", track="k", url="http://x",
                                     force=False)
        with redirect_stdout(io.StringIO()) as out:
            rc = coverage_ctl.cmd_sample(args)
        return rc, out.getvalue()

    def write_old_csv(self):
        import csv as _csv
        os.makedirs(os.path.join(self.runs.name, "r1"), exist_ok=True)
        path = coverage_ctl.csv_path("r1")
        with open(path, "w", newline="") as f:
            w = _csv.DictWriter(f, fieldnames=self.OLD_FIELDS)
            w.writeheader()
            w.writerow({"ts": 1, "edges": 50, "source": "json:/stats"})
        return path

    def test_a_sample_records_the_gpu_status_alongside_the_counters(self):
        """gpu is text, not a count: putting it through _to_int would turn
        "ok" into None and silently un-record every healthy sample."""
        self.sample()
        row = coverage_ctl.read_rows("r1")[0]
        self.assertEqual(row["gpu"], "ok")
        self.assertEqual(row["source"], "json:/stats")
        self.assertEqual(row["edges"], 100)

    def test_sampling_a_pre_gpu_csv_keeps_its_column_count(self):
        """Writing 9 values under an 8-column header shifts every later read
        by one, which would corrupt the edge counts the loop decides on."""
        path = self.write_old_csv()
        self.edges = 110
        rc, out = self.sample()
        self.assertEqual(rc, 0)
        with open(path) as f:
            widths = {len(l.split(",")) for l in f.read().strip().splitlines()}
        self.assertEqual(widths, {len(self.OLD_FIELDS)})
        rows = coverage_ctl.read_rows("r1")
        self.assertEqual(rows[1]["edges"], 110)   # not shifted a column
        self.assertIsNone(rows[1]["gpu"])         # and not invented either
        self.assertIn("predates the gpu column", out)

    def test_an_unhealthy_gpu_is_reported_at_sample_time(self):
        """The operator should not have to wait for a plateau verdict to
        learn the card stopped answering four hours ago."""
        coverage_ctl.gpu_health = lambda: ("dead", "nvidia-smi exit 9")
        rc, out = self.sample()
        self.assertIn("GPU is dead", out)
        self.assertEqual(coverage_ctl.read_rows("r1")[0]["gpu"], "dead")


class TestXidClassification(StateTempMixin, unittest.TestCase):
    """A fuzzer makes Xid 13 and 31 by design; those are not findings.

    Harvesting every NVRM line as a crash buries the interesting entries and
    makes any "crashes found" number meaningless.
    """

    def cls(self, title):
        return crash_parse.xid_class(title)[0]

    def test_the_xid_number_is_read_past_the_bus_id_colons(self):
        """Regression: skipping to the number with [^:]* stops at the first
        colon inside (PCI:0000:00:1e), reads the bus id's first field as the
        Xid, and classifies every crash as an unknown Xid 0."""
        cls, why = crash_parse.xid_class(
            "Xid (PCI:0000:00:1e): 13, pid=1234, Graphics Exception")
        self.assertEqual(cls, "noise")
        self.assertIn("Xid 13", why)

    def test_fuzzer_generated_xids_are_classed_as_noise(self):
        for t in ("Xid (PCI:0000:00:1e): 13, Graphics Exception",
                  "Xid (PCI:0000:00:1e): 31, Ch 00000008, MMU Fault",
                  "Xid (PCI:0000:00:1e): 43, Channel Error"):
            self.assertEqual(self.cls(t), "noise", t)

    def test_memory_integrity_xids_are_classed_as_signal(self):
        for t in ("Xid (PCI:0000:00:1e): 48, Double Bit ECC",
                  "Xid (PCI:0000:00:1e): 119, GSP RPC Timeout",
                  "Xid (PCI:0000:00:1e): 120, GSP Error"):
            self.assertEqual(self.cls(t), "signal", t)

    def test_a_gpu_off_the_bus_is_a_health_problem_not_a_finding(self):
        self.assertEqual(
            self.cls("Xid (PCI:0000:00:1e): 79, GPU has fallen off the bus"),
            "health")

    def test_an_unlisted_xid_is_never_classed_as_noise(self):
        """The property the whole table exists to guarantee.

        A driver branch can introduce an Xid this table predates. Defaulting
        it to exhaust would silently discard the one class of finding the
        campaign exists to produce.
        """
        for n in (222, 999, 7, 150):
            cls = self.cls("Xid (PCI:0000:00:1e): %d, something new" % n)
            self.assertEqual(cls, "review", n)

    def test_an_nvrm_line_without_an_xid_number_is_not_classified(self):
        self.assertIsNone(
            self.cls("GPU at PCI:0000:00:1e has an internal error"))

    def test_registering_an_nvrm_crash_records_its_signal(self):
        st = ps.default_state()
        path = os.path.join(self.tmp.name, "dmesg.txt")
        with open(path, "w") as f:
            f.write("[ 1.0] NVRM: Xid (PCI:0000:00:1e): 31, pid=1, MMU Fault\n"
                    "[ 2.0] NVRM: Xid (PCI:0000:00:1e): 119, RPC Timeout\n")
        with redirect_stdout(io.StringIO()):
            crash_parse.scan_dmesg(st, path)
        got = sorted((c["signal"], c["title"]) for c in st["crashes"].values())
        self.assertEqual([s for s, _ in got], ["noise", "signal"])
        # The reason travels with the crash, so triage does not have to
        # re-derive why an entry was set aside.
        notes = " ".join(c["notes"] for c in st["crashes"].values())
        self.assertIn("Xid 31", notes)


class TestOrchestratorBreaker(unittest.TestCase):
    """The supervisor restarts the agent forever unless something stops it.

    Two counters, not one: this pipeline panics the box on purpose, so a
    shared limit would either stop a healthy campaign or let a same-boot loop
    run all night.
    """

    NOW = 1_700_000_000.0
    CONF = {"orchestrator": {"window_min": 60, "max_same_boot_starts": 5,
                             "max_reboots": 10, "command": "true"}}

    def state(self, spec):
        """spec: [(minutes_ago, boot_id)]"""
        return {"starts": [{"ts": int(self.NOW - m * 60), "boot_id": b}
                           for m, b in spec], "blocked": None}

    def tripped(self, spec, this_boot):
        reason, _ = orchestrator_ctl.check(self.state(spec), self.CONF,
                                           self.NOW, this_boot)
        return reason

    def test_a_rebooting_campaign_is_not_a_restart_loop(self):
        """Eight panics an hour is a working kernel fuzzer, not a fault."""
        spec = [(i * 7, "boot%d" % i) for i in range(8)]
        self.assertIsNone(self.tripped(spec, "boot0"))

    def test_repeated_starts_on_one_boot_trip_the_breaker(self):
        spec = [(i * 5, "same") for i in range(6)]
        reason = self.tripped(spec, "same")
        self.assertIsNotNone(reason)
        self.assertIn("on this boot", reason)

    def test_reboots_faster_than_the_limit_trip_the_breaker(self):
        spec = [(i * 4, "boot%d" % i) for i in range(12)]
        reason = self.tripped(spec, "boot0")
        self.assertIsNotNone(reason)
        self.assertIn("booted", reason)

    def test_starts_older_than_the_window_do_not_count(self):
        spec = [(90 + i * 5, "same") for i in range(6)]
        self.assertIsNone(self.tripped(spec, "same"))

    def test_exactly_at_the_limit_is_allowed(self):
        """Off-by-one here either blocks a campaign a start early or lets one
        extra through; the limit is the number of starts allowed."""
        spec = [(i * 5, "same") for i in range(5)]
        self.assertIsNone(self.tripped(spec, "same"))

    def test_an_unreadable_boot_id_counts_against_the_same_boot_limit(self):
        """Treating an unknown boot as a fresh one is what would let a
        same-boot loop run forever on a box where boot_id cannot be read."""
        spec = [(i * 5, None) for i in range(6)]
        reason = self.tripped(spec, None)
        self.assertIsNotNone(reason)
        self.assertIn("on this boot", reason)


class TestOrchestratorRun(StateTempMixin, unittest.TestCase):
    """`run` is what the systemd unit calls: what it returns decides whether
    the unit restarts or stops."""

    def setUp(self):
        super().setUp()
        self._orig_path = orchestrator_ctl.ORCH_PATH
        orchestrator_ctl.ORCH_PATH = os.path.join(self.tmp.name, "orch.json")
        self.addCleanup(lambda: setattr(orchestrator_ctl, "ORCH_PATH",
                                        self._orig_path))
        self._orig_cfg = orchestrator_ctl.cfg
        # Built from DEFAULTS rather than hand-written, so a new orchestrator
        # key cannot make cmd_run raise KeyError here while working in
        # production, where load() always fills every key.
        orchestrator_ctl.cfg = lambda: {
            "orchestrator": dict(gspwn_config.DEFAULTS["orchestrator"],
                                 window_min=60, max_same_boot_starts=2,
                                 max_reboots=10, command="true")}
        self.addCleanup(lambda: setattr(orchestrator_ctl, "cfg",
                                        self._orig_cfg))
        # Harvest shells out to crashlog_ctl as root; this suite runs offline.
        self._orig_harvest = orchestrator_ctl.harvest
        orchestrator_ctl.harvest = lambda: None
        self.addCleanup(lambda: setattr(orchestrator_ctl, "harvest",
                                        self._orig_harvest))
        ps.save(ps.default_state())

    def run_once(self, command="true"):
        args = types.SimpleNamespace(command=command)
        with redirect_stdout(io.StringIO()) as out:
            rc = orchestrator_ctl.cmd_run(args)
        return rc, out.getvalue()

    def test_a_healthy_start_launches_the_agent(self):
        rc, out = self.run_once()
        self.assertEqual(rc, 0)
        self.assertIn("launching", out)

    def test_a_tripped_breaker_stops_the_unit_instead_of_restarting(self):
        """BLOCKED_EXIT is named in RestartPreventExitStatus. Returning
        anything else here restarts into the same wall every RestartSec."""
        for _ in range(2):
            self.run_once()
        rc, out = self.run_once()
        self.assertEqual(rc, orchestrator_ctl.BLOCKED_EXIT)
        self.assertIn("circuit breaker tripped", out)
        # And it stays blocked without re-deciding.
        rc, out = self.run_once()
        self.assertEqual(rc, orchestrator_ctl.BLOCKED_EXIT)
        self.assertIn("is blocked", out)

    def test_reset_clears_the_start_history_as_well_as_the_trip(self):
        """Clearing only the flag re-trips on the very next start, because
        the counted window has not moved."""
        for _ in range(3):
            self.run_once()
        with redirect_stdout(io.StringIO()):
            orchestrator_ctl.cmd_reset(types.SimpleNamespace())
        rc, out = self.run_once()
        self.assertEqual(rc, 0)
        self.assertIn("launching", out)

    def test_a_complete_pipeline_stops_the_unit(self):
        """Relaunching an agent to read 'complete' costs tokens to reach an
        answer that will not change."""
        st = ps.load()
        for p in ps.PHASES:
            st["phases"][p]["status"] = "done"
        st["rounds"][-1]["decision"] = "stop"
        ps.save(st)
        rc, out = self.run_once()
        self.assertEqual(rc, orchestrator_ctl.BLOCKED_EXIT)
        self.assertIn("complete", out)

    def test_a_blocked_phase_stops_the_unit(self):
        st = ps.load()
        st["phases"]["fuzz"]["status"] = "blocked"
        ps.save(st)
        rc, out = self.run_once()
        self.assertEqual(rc, orchestrator_ctl.BLOCKED_EXIT)
        self.assertIn("blocked", out)

    def test_no_configured_command_stops_rather_than_looping(self):
        """Only a human can supply this, so retrying every 60s is pure burn."""
        orchestrator_ctl.cfg = lambda: {
            "orchestrator": {"window_min": 60, "max_same_boot_starts": 2,
                             "max_reboots": 10, "command": ""}}
        rc, out = self.run_once(command=None)
        self.assertEqual(rc, orchestrator_ctl.BLOCKED_EXIT)
        self.assertIn("orchestrator.command", out)


GOOD_FINDING = {"subsystem": "nvidia_uvm", "bug_class": "uaf",
                "trigger": "ioctl-sequence",
                "ioctls": ["UVM_CREATE_RANGE_GROUP", "UVM_FREE"],
                "preconditions": ["channel bound", "async work in flight"],
                "adjacent": ["UVM_DESTROY_RANGE_GROUP"],
                "source_refs": ["uvm_range_group.c:412"],
                "hypothesis": "teardown skips the in-flight refcount check",
                "confidence": "medium"}


class TestFindingClass(StateTempMixin, unittest.TestCase):
    """The research record is the only path from a finding back into
    targeting. Every rule here exists because the failure it prevents is
    silent: the edge stays wired and carries nothing."""

    def setUp(self):
        super().setUp()
        with ps.transaction() as st:
            self.cid = ps.register_crash(
                st, {"track": "K", "title": "t", "stack_hash": "h",
                     "status": "unique", "dir": "d"})

    def store(self, **over):
        f = dict(GOOD_FINDING, **over)
        with ps.transaction() as st:
            return ps.set_finding(st, self.cid, f)

    def refused(self, **over):
        with self.assertRaises(ValueError) as e:
            self.store(**over)
        return str(e.exception)

    def test_a_complete_record_is_stored_with_call_order_preserved(self):
        f = self.store()
        self.assertEqual(f["ioctls"],
                         ["UVM_CREATE_RANGE_GROUP", "UVM_FREE"])

    def test_a_misspelled_field_is_refused_rather_than_dropped(self):
        """Dropping it would leave ioctls empty while the command reported
        success, which is the whole failure mode this schema guards."""
        with self.assertRaises(ValueError) as e:
            with ps.transaction() as st:
                ps.set_finding(st, self.cid,
                               dict(GOOD_FINDING, ioctl=["UVM_FREE"]))
        self.assertIn("unknown finding field", str(e.exception))

    def test_a_record_without_a_subsystem_is_refused(self):
        self.assertIn("subsystem", self.refused(subsystem=""))

    def test_a_taxonomy_with_nothing_to_target_is_refused(self):
        msg = self.refused(ioctls=[], preconditions=[], adjacent=[])
        self.assertIn("at least one of", msg)

    def test_a_track_u_record_may_carry_preconditions_alone(self):
        """Userspace findings have no ioctls; requiring them would make the
        whole Track U half of the pipeline unable to record anything."""
        f = self.store(ioctls=[], adjacent=[],
                       preconditions=["4096-byte path component"],
                       no_adjacent_reason="userspace, no sibling ioctls")
        self.assertEqual(f["preconditions"], ["4096-byte path component"])

    def test_an_unknown_bug_class_is_refused(self):
        self.assertIn("unknown bug_class", self.refused(bug_class="use-after-free"))

    def test_a_list_field_given_as_a_bare_string_is_refused(self):
        self.assertIn("must be a list", self.refused(ioctls="UVM_FREE"))

    def test_list_entries_are_deduped_and_blanks_dropped(self):
        f = self.store(ioctls=["C", "A", "C", "  B  ", ""])
        self.assertEqual(f["ioctls"], ["C", "A", "B"])

    def test_rca_done_without_a_record_is_an_integrity_problem(self):
        """The analysis happened and nothing survived it."""
        with ps.transaction() as st:
            st["crashes"][self.cid]["status"] = "rca_done"
        problems = ps.validate(ps.load())
        self.assertTrue(any("no finding" in p for p in problems), problems)

    def test_a_duplicate_does_not_inflate_its_subsystem(self):
        """Weighting a subsystem by how often the fuzzer rediscovered one bug
        would send every later round after the noisiest crash, not the most
        productive area."""
        self.store()
        with ps.transaction() as st:
            other = ps.register_crash(
                st, {"track": "K", "title": "t2", "stack_hash": "h2",
                     "status": "unique", "dir": "d"})
            ps.set_finding(st, other, GOOD_FINDING)
        self.assertEqual(len(ps.findings(ps.load())), 2)
        with ps.transaction() as st:
            st["crashes"][other]["status"] = "duplicate"
            st["crashes"][other]["duplicate_of"] = self.cid
        self.assertEqual(len(ps.findings(ps.load())), 1)


class TestFindingSteersSomewhere(StateTempMixin, unittest.TestCase):
    """`adjacent` is the only field carrying anything the crash does not
    already contain, so a record can pass every schema rule and still be
    inert. That is the likeliest way this whole path dies, and it is
    invisible unless something counts it."""

    def gap(self, **over):
        return ps.finding_target_gap(dict(GOOD_FINDING, **over))

    def test_a_record_with_real_adjacent_calls_steers(self):
        self.assertIsNone(self.gap())

    def test_empty_adjacent_with_no_reason_steers_nothing(self):
        msg = self.gap(adjacent=[])
        self.assertIsNotNone(msg)
        self.assertIn("no_adjacent_reason", msg)

    def test_empty_adjacent_with_a_reason_is_accepted(self):
        """A bug with no siblings on its teardown path is a real answer, and
        guessing a neighbour to fill the field would be worse than saying so."""
        self.assertIsNone(self.gap(adjacent=[],
                                   no_adjacent_reason="single-call bug, no "
                                                      "other callers of the "
                                                      "object"))

    def test_adjacent_that_only_repeats_ioctls_steers_nothing(self):
        """The perfunctory case: every field filled in, nothing new named."""
        msg = self.gap(adjacent=["UVM_FREE"])
        self.assertIsNotNone(msg)
        self.assertIn("already in ioctls", msg)

    def test_adjacent_adding_one_new_call_is_enough(self):
        self.assertIsNone(self.gap(adjacent=["UVM_FREE", "UVM_UNMAP_EXTERNAL"]))

    def test_an_inert_record_is_reported_by_validate(self):
        with ps.transaction() as st:
            cid = ps.register_crash(
                st, {"track": "K", "title": "t", "stack_hash": "h",
                     "status": "unique", "dir": "d"})
            ps.set_finding(st, cid, dict(GOOD_FINDING,
                                         adjacent=["UVM_FREE"]))
        problems = ps.validate(ps.load())
        self.assertTrue(any("steers nothing" in p for p in problems), problems)

    def test_an_inert_duplicate_is_not_reported(self):
        """Duplicates are already excluded from the worklist, so an inert one
        costs nothing and reporting it would be noise the operator learns to
        ignore."""
        with ps.transaction() as st:
            keep = ps.register_crash(
                st, {"track": "K", "title": "t", "stack_hash": "h",
                     "status": "unique", "dir": "d"})
            ps.set_finding(st, keep, GOOD_FINDING)
            dup = ps.register_crash(
                st, {"track": "K", "title": "t2", "stack_hash": "h2",
                     "status": "unique", "dir": "d"})
            ps.set_finding(st, dup, dict(GOOD_FINDING, adjacent=["UVM_FREE"]))
        with ps.transaction() as st:
            st["crashes"][dup]["status"] = "duplicate"
            st["crashes"][dup]["duplicate_of"] = keep
        problems = ps.validate(ps.load())
        self.assertEqual([p for p in problems if "steers nothing" in p], [])


GOOD_IMPACT = {"primitive": "controlled-write",
               "consequence": "privilege-escalation",
               "corrupted_object": "uvm_va_range_t",
               "cache": "kmalloc-512",
               "access_type": "write", "access_size": 8,
               "overwrite_target": "function-pointer",
               "reclaim_path": "UVM_CREATE_EXTERNAL_RANGE reallocates from "
                               "kmalloc-512 with caller-sized data",
               "allocation_site": "uvm_va_range.c:118",
               "free_site": "uvm_va_range.c:412",
               "access_site": "uvm_channel.c:906",
               "attacker_control": ["allocation-timing", "written-data"],
               "evidence": ["uvm_va_range.c:412", "uvm_channel.c:906"],
               "unverified": ["that the reclaim wins the race in practice"],
               "confidence": "medium"}


class TestImpactRecord(StateTempMixin, unittest.TestCase):
    """A reproducer proves a crash condition, which is a bug report. The
    impact record is what makes it a vulnerability report, so its schema has
    to refuse the shapes that would let an unargued severity through."""

    def setUp(self):
        super().setUp()
        with ps.transaction() as st:
            self.cid = ps.register_crash(
                st, {"track": "K", "title": "t", "stack_hash": "h",
                     "status": "unique", "dir": "d"})
            ps.set_finding(st, self.cid, GOOD_FINDING)

    def store(self, **over):
        with ps.transaction() as st:
            return ps.set_impact(st, self.cid, dict(GOOD_IMPACT, **over))

    def refused(self, **over):
        with self.assertRaises(ValueError) as e:
            self.store(**over)
        return str(e.exception)

    def test_a_complete_record_is_stored(self):
        im = self.store()
        self.assertEqual(im["primitive"], "controlled-write")
        self.assertEqual(im["access_size"], 8)

    def test_a_misspelled_field_is_refused_rather_than_dropped(self):
        """Dropping it would leave the real field at its default while the
        command reported success."""
        with self.assertRaises(ValueError) as e:
            with ps.transaction() as st:
                ps.set_impact(st, self.cid,
                              dict(GOOD_IMPACT, primative="controlled-write"))
        self.assertIn("unknown impact field", str(e.exception))

    def test_an_unknown_primitive_is_refused(self):
        """The vocabulary is closed so the report can group by it; 'rce' is
        also exactly the word an over-claiming record would reach for."""
        self.assertIn("unknown primitive", self.refused(primitive="rce"))

    def test_an_unknown_consequence_is_refused(self):
        self.assertIn("unknown consequence",
                      self.refused(consequence="critical"))

    def test_an_unknown_attacker_control_entry_is_refused(self):
        self.assertIn("unknown attacker_control",
                      self.refused(attacker_control=["everything"]))

    def test_a_malformed_cwe_is_refused(self):
        self.assertIn("CWE-416", self.refused(cwe="416"))

    def test_a_negative_access_size_is_refused(self):
        self.assertIn("access_size", self.refused(access_size=-4))

    def test_a_boolean_access_size_is_refused(self):
        """bool is an int subclass, so True would otherwise store as size 1."""
        self.assertIn("access_size", self.refused(access_size=True))

    def test_list_entries_are_deduped_and_blanks_dropped(self):
        im = self.store(evidence=["a.c:1", "", "a.c:1", "  b.c:2  "])
        self.assertEqual(im["evidence"], ["a.c:1", "b.c:2"])

    def test_a_duplicate_is_not_counted_as_a_second_vulnerability(self):
        self.store()
        with ps.transaction() as st:
            other = ps.register_crash(
                st, {"track": "K", "title": "t2", "stack_hash": "h2",
                     "status": "unique", "dir": "d"})
            ps.set_impact(st, other, GOOD_IMPACT)
        self.assertEqual(len(ps.impacts(ps.load())), 2)
        with ps.transaction() as st:
            st["crashes"][other]["status"] = "duplicate"
            st["crashes"][other]["duplicate_of"] = self.cid
        self.assertEqual(len(ps.impacts(ps.load())), 1)

    def test_rca_done_without_an_impact_is_an_integrity_problem(self):
        """Otherwise the report carries a reproducer with no argued severity,
        which is the gap this record exists to close."""
        with ps.transaction() as st:
            st["crashes"][self.cid]["status"] = "rca_done"
        problems = ps.validate(ps.load())
        self.assertTrue(any("no impact record" in p for p in problems),
                        problems)


class TestImpactSupportsItsConclusion(StateTempMixin, unittest.TestCase):
    """The expensive failure is not a malformed record, it is a well-formed
    one whose conclusion outruns its evidence. A severity a vendor engineer
    disproves discredits every other finding in the same report."""

    def gap(self, **over):
        return ps.impact_support_gap(dict(GOOD_IMPACT, **over))

    def test_an_evidenced_record_supports_itself(self):
        self.assertIsNone(self.gap())

    def test_undetermined_without_a_reason_is_flagged(self):
        """Unexplained undetermined is indistinguishable from analysis nobody
        did."""
        msg = self.gap(primitive="undetermined", consequence="undetermined")
        self.assertIn("undetermined_reason", msg)

    def test_undetermined_with_a_reason_is_accepted(self):
        """A path that vanishes into GSP firmware genuinely cannot be followed
        further, and that answer has to stay cheap — otherwise the agent
        invents an impact story, which is the worst outcome available."""
        self.assertIsNone(self.gap(
            primitive="undetermined", consequence="undetermined",
            undetermined_reason="the faulting path enters GSP firmware; the "
                                "callee is not visible from the open modules"))

    def test_a_primitive_with_no_evidence_is_flagged(self):
        msg = self.gap(evidence=[])
        self.assertIn("no evidence", msg)

    def test_primitive_none_needs_no_evidence(self):
        """A fault that only kills the machine is a complete answer, and most
        kernel faults are that."""
        self.assertIsNone(self.gap(primitive="none", consequence="dos-only",
                                   evidence=[], attacker_control=[]))

    def test_escalation_from_an_undetermined_primitive_is_flagged(self):
        msg = self.gap(primitive="undetermined",
                       consequence="container-escape",
                       undetermined_reason="could not follow the callee")
        self.assertIn("outruns the mechanism", msg)

    def test_escalation_with_no_attacker_control_is_flagged(self):
        msg = self.gap(attacker_control=["none"])
        self.assertIn("above denial of service", msg)

    def test_escalation_with_only_unknown_control_is_flagged(self):
        self.assertIn("above denial of service",
                      self.gap(attacker_control=["unknown"]))

    def test_info_disclosure_needs_no_attacker_control(self):
        """An out-of-bounds read can hand back adjacent memory without the
        attacker influencing anything, so requiring control here would push
        real findings down to dos-only."""
        self.assertIsNone(self.gap(primitive="info-leak",
                                   consequence="info-disclosure",
                                   attacker_control=[]))

    def test_a_consequence_weaker_than_the_primitive_is_not_flagged(self):
        """Under-claiming costs nothing. Flagging it would push the agent
        towards escalating, which is the direction that does cost something."""
        self.assertIsNone(self.gap(consequence="dos-only",
                                   attacker_control=[]))

    def test_an_unsupported_record_is_reported_by_validate(self):
        with ps.transaction() as st:
            cid = ps.register_crash(
                st, {"track": "K", "title": "t", "stack_hash": "h",
                     "status": "unique", "dir": "d"})
            ps.set_impact(st, cid, dict(GOOD_IMPACT, evidence=[]))
        problems = ps.validate(ps.load())
        self.assertTrue(any("does not support its conclusion" in p
                            for p in problems), problems)

    def test_an_unsupported_duplicate_is_not_reported(self):
        """Duplicates never reach the report as their own finding, so an
        unsupported one costs nothing and reporting it is noise."""
        with ps.transaction() as st:
            keep = ps.register_crash(
                st, {"track": "K", "title": "t", "stack_hash": "h",
                     "status": "unique", "dir": "d"})
            ps.set_impact(st, keep, GOOD_IMPACT)
            dup = ps.register_crash(
                st, {"track": "K", "title": "t2", "stack_hash": "h2",
                     "status": "unique", "dir": "d"})
            ps.set_impact(st, dup, dict(GOOD_IMPACT, evidence=[]))
        with ps.transaction() as st:
            st["crashes"][dup]["status"] = "duplicate"
            st["crashes"][dup]["duplicate_of"] = keep
        problems = ps.validate(ps.load())
        self.assertEqual([p for p in problems
                          if "does not support its conclusion" in p], [])


class TestCweDerivation(StateTempMixin, unittest.TestCase):
    """CWE is derived from bug_class rather than typed in: the mapping is
    mechanical, and a free-text field invites a plausible wrong number that
    nobody re-checks."""

    def crash_with(self, bug_class, **impact_over):
        with ps.transaction() as st:
            cid = ps.register_crash(
                st, {"track": "K", "title": "t" + bug_class,
                     "stack_hash": "h" + bug_class, "status": "unique",
                     "dir": "d"})
            ps.set_finding(st, cid, dict(GOOD_FINDING, bug_class=bug_class))
            if impact_over is not None:
                ps.set_impact(st, cid, dict(GOOD_IMPACT, **impact_over))
            return st["crashes"][cid]

    def test_uaf_derives_cwe_416(self):
        self.assertEqual(ps.cwe_of(self.crash_with("uaf")), "CWE-416")

    def test_oob_write_derives_cwe_787(self):
        self.assertEqual(ps.cwe_of(self.crash_with("oob-write")), "CWE-787")

    def test_bug_class_other_derives_nothing_rather_than_guessing(self):
        self.assertEqual(ps.cwe_of(self.crash_with("other")), "")

    def test_an_explicit_cwe_overrides_the_derived_one(self):
        """For bug_class 'other', and for the cases where a more specific
        child class is right."""
        c = self.crash_with("integer-overflow", cwe="CWE-680")
        self.assertEqual(ps.cwe_of(c), "CWE-680")

    def test_every_bug_class_has_a_mapping_entry(self):
        """A bug_class added later without a CWE entry would silently report
        an empty weakness class for every finding of that kind."""
        self.assertEqual(sorted(ps.CWE_OF_BUG_CLASS), sorted(ps.BUG_CLASS))

    def test_a_crash_with_no_finding_has_no_cwe(self):
        with ps.transaction() as st:
            cid = ps.register_crash(
                st, {"track": "K", "title": "t", "stack_hash": "h",
                     "status": "unique", "dir": "d"})
            self.assertEqual(ps.cwe_of(st["crashes"][cid]), "")


class TestKnowledgeNotes(unittest.TestCase):
    """knowledge/ is committed to a public repo and appended by parallel
    agents on a machine that panics on purpose."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(setattr, knowledge_ctl, "KNOWLEDGE_DIR",
                        knowledge_ctl.KNOWLEDGE_DIR)
        knowledge_ctl.KNOWLEDGE_DIR = self.tmp.name

    def note(self, text, kind="learning", phase="describe", tags=""):
        args = types.SimpleNamespace(text=text, kind=kind, phase=phase,
                                     tags=tags)
        with redirect_stdout(io.StringIO()):
            return knowledge_ctl.cmd_note(args)

    def test_a_note_round_trips_through_the_file(self):
        self.note("UVM numbering does not follow the RM convention",
                  tags="abi,uvm")
        entries = knowledge_ctl._entries("learning")
        self.assertEqual(len(entries), 1)
        _ts, phase, tags, body = entries[0]
        self.assertEqual(phase, "describe")
        self.assertEqual(tags, "abi, uvm")
        self.assertIn("RM convention", body)

    def test_a_note_naming_a_crash_id_is_refused(self):
        """These files are public. The generalised form is also the useful
        one, because the next agent is looking at a different crash."""
        with self.assertRaises(SystemExit) as e:
            self.note("marked crash-0003 a duplicate too early", kind="mistake")
        self.assertIn("crash-0003", str(e.exception))

    def test_a_note_naming_a_crash_artifact_path_is_refused(self):
        with self.assertRaises(SystemExit) as e:
            self.note("see artifacts/crashes/0012/report.txt for the layout")
        self.assertIn("artifacts/crashes/", str(e.exception))

    def test_the_generalised_form_of_a_refused_note_is_accepted(self):
        self.note("do not mark a crash a duplicate before its repro rate is "
                  "measured", kind="mistake")
        self.assertEqual(len(knowledge_ctl._entries("mistake")), 1)

    def test_a_refused_note_writes_nothing(self):
        with self.assertRaises(SystemExit):
            self.note("crash-0001 was mishandled")
        self.assertEqual(knowledge_ctl._entries("learning"), [])

    def test_learnings_and_mistakes_are_separate_files(self):
        self.note("a target fact", kind="learning")
        self.note("a process error", kind="mistake")
        self.assertEqual(len(knowledge_ctl._entries("learning")), 1)
        self.assertEqual(len(knowledge_ctl._entries("mistake")), 1)

    def test_appending_keeps_one_header_and_loses_nothing(self):
        """Each append rewrites the file; a header re-emitted per entry, or an
        entry dropped, would only show up after the file had grown."""
        for i in range(12):
            self.note("entry number %d" % i)
        with io.open(knowledge_ctl._path("learning"), encoding="utf-8") as f:
            text = f.read()
        self.assertEqual(text.count("# Learnings"), 1)
        self.assertEqual(len(knowledge_ctl._entries("learning")), 12)
        for i in range(12):
            self.assertIn("entry number %d" % i, text)

    def test_a_note_is_written_atomically(self):
        """Rewrite through a tempfile and rename, so a panic mid-append leaves
        the previous good file rather than a torn one."""
        self.note("first")
        leftovers = [n for n in os.listdir(self.tmp.name)
                     if n.endswith(".tmp")]
        self.assertEqual(leftovers, [])


class TestSessionRotation(unittest.TestCase):
    """Rotation is by transcript size because size is what drives
    auto-compaction. Restart count does not: twenty restarts may write less
    than one long uninterrupted stretch."""

    NOW = 1_700_000_000.0
    MB = 1048576

    def conf(self, **over):
        o = {"resume_command": "claude --resume {session}", "max_resumes": 40,
             "max_session_mb": 6, "session_transcript_glob": ""}
        o.update(over)
        return {"orchestrator": o}

    def resolve(self, prev, size=None, **over):
        state = {"session": prev}
        return orchestrator_ctl.resolve_session(state, self.conf(**over),
                                                self.NOW, "NEW", size)

    def prev(self, resumes=0, sid="OLD"):
        return {"id": sid, "resumes": resumes, "started": 1}

    def test_no_previous_session_starts_fresh(self):
        s, resuming, _ = self.resolve(None)
        self.assertEqual((s["id"], s["resumes"], resuming), ("NEW", 0, False))

    def test_a_small_transcript_resumes(self):
        s, resuming, why = self.resolve(self.prev(), size=2 * self.MB)
        self.assertEqual((s["id"], s["resumes"], resuming), ("OLD", 1, True))
        self.assertIn("2.0 MB", why)

    def test_a_transcript_past_the_size_limit_rotates(self):
        s, resuming, why = self.resolve(self.prev(), size=7 * self.MB)
        self.assertEqual((s["id"], resuming), ("NEW", False))
        self.assertIn("7.0 MB", why)

    def test_exactly_at_the_size_limit_rotates(self):
        s, resuming, _ = self.resolve(self.prev(), size=6 * self.MB)
        self.assertEqual((s["id"], resuming), ("NEW", False))

    def test_size_rotates_even_when_the_resume_count_is_low(self):
        """The point of the change: one restart with a huge transcript must
        rotate, where counting restarts would have carried it on."""
        s, resuming, _ = self.resolve(self.prev(resumes=1), size=20 * self.MB)
        self.assertEqual((s["id"], resuming), ("NEW", False))

    def test_the_resume_count_still_backstops_an_unmeasurable_transcript(self):
        s, resuming, _ = self.resolve(self.prev(resumes=40), size=None)
        self.assertEqual((s["id"], resuming), ("NEW", False))

    def test_an_unmeasurable_transcript_still_resumes_below_the_backstop(self):
        s, resuming, why = self.resolve(self.prev(resumes=3), size=None)
        self.assertEqual((s["id"], resuming), ("OLD", True))
        self.assertIn("unmeasured", why)

    def test_a_zero_size_limit_disables_the_size_check(self):
        s, resuming, _ = self.resolve(self.prev(), size=99 * self.MB,
                                      max_session_mb=0)
        self.assertEqual((s["id"], resuming), ("OLD", True))

    def test_resume_off_never_resumes(self):
        s, resuming, why = self.resolve(self.prev(), size=1,
                                        resume_command="")
        self.assertEqual((s["id"], resuming), ("NEW", False))
        self.assertIn("unset", why)

    def test_resolve_session_mutates_nothing(self):
        """It is called inside the breaker lock; a mutation here would be
        written whether or not the launch went ahead."""
        state = {"session": self.prev(resumes=2)}
        before = json.dumps(state, sort_keys=True)
        orchestrator_ctl.resolve_session(state, self.conf(), self.NOW, "NEW",
                                         self.MB)
        self.assertEqual(json.dumps(state, sort_keys=True), before)

    def test_transcript_size_is_summed_across_matching_files(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for n in ("a", "b"):
            with io.open(os.path.join(tmp.name, "%s-SID.jsonl" % n), "w") as f:
                f.write("x" * 100)
        pattern = os.path.join(tmp.name, "*-{session}.jsonl")
        self.assertEqual(
            orchestrator_ctl.transcript_bytes(pattern, "SID"), 200)

    def test_a_missing_transcript_measures_as_unknown_not_zero(self):
        """Zero would read as a small transcript and silently disable the only
        rotation rule that tracks what actually matters."""
        self.assertIsNone(
            orchestrator_ctl.transcript_bytes("/nonexistent/{session}.jsonl",
                                              "SID"))
        self.assertIsNone(orchestrator_ctl.transcript_bytes("", "SID"))


class TestResumeCommandRendering(unittest.TestCase):
    def test_the_session_id_is_substituted(self):
        self.assertEqual(
            orchestrator_ctl.render_command("claude --resume {session}", "U1"),
            "claude --resume U1")

    def test_a_prompt_containing_braces_survives(self):
        """str.format would raise on the first brace of an embedded JSON
        example, and these invocations carry prompts."""
        self.assertEqual(
            orchestrator_ctl.render_command('c -p \'emit {"a": 1} for '
                                            '{session}\'', "U1"),
            'c -p \'emit {"a": 1} for U1\'')

    def test_the_anchor_expands_and_points_at_brief(self):
        out = orchestrator_ctl.render_command("c -p '{anchor}'", "U1")
        self.assertIn("pipeline_ctl.py brief", out)

    def test_the_anchor_carries_no_shell_quote_characters(self):
        """It is substituted into a command line the operator already
        quoted, so an apostrophe in it would end that quoting."""
        self.assertNotIn("'", orchestrator_ctl.RESUME_ANCHOR)
        self.assertNotIn('"', orchestrator_ctl.RESUME_ANCHOR)

    def test_a_configured_anchor_replaces_the_default(self):
        """The anchor is the first thing a resumed agent reads, so it is a
        tuning knob and an operator must be able to change it."""
        out = orchestrator_ctl.render_command("c -p '{anchor}'", "U1",
                                              "read the brief first")
        self.assertEqual(out, "c -p 'read the brief first'")

    def test_the_shipped_config_anchor_matches_the_module_default(self):
        """Two copies of the same prompt: campaign.yaml is what actually runs
        and the module constant is only the unreadable-config fallback, so a
        drift between them would change behaviour on the recovery path only."""
        self.assertEqual(
            gspwn_config.load()["orchestrator"]["resume_anchor"],
            orchestrator_ctl.RESUME_ANCHOR)


class TestBrief(StateTempMixin, unittest.TestCase):
    """`brief` is what a fresh or compacted session reads to recover, so it
    has to work on a state file in any condition."""

    def setUp(self):
        super().setUp()
        self.addCleanup(setattr, knowledge_ctl, "KNOWLEDGE_DIR",
                        knowledge_ctl.KNOWLEDGE_DIR)
        knowledge_ctl.KNOWLEDGE_DIR = os.path.join(self.tmp.name, "knowledge")
        ps.save(ps.default_state())

    def brief(self, last=3):
        import pipeline_ctl
        with redirect_stdout(io.StringIO()) as out:
            pipeline_ctl.cmd_brief(types.SimpleNamespace(last=last))
        return out.getvalue()

    def test_it_works_on_a_fresh_pipeline(self):
        out = self.brief()
        self.assertIn("run phase provision", out)
        self.assertIn("none registered", out)

    def test_it_names_the_next_action_and_the_blocked_phase(self):
        with ps.transaction() as st:
            ps.update_phase(st, "provision", "done")
            ps.update_phase(st, "build", "blocked", "kernel would not boot")
        out = self.brief()
        self.assertIn("blocked", out)
        self.assertIn("kernel would not boot", out)

    def test_it_reports_the_findings_rollup(self):
        with ps.transaction() as st:
            cid = ps.register_crash(
                st, {"track": "K", "title": "t", "stack_hash": "h",
                     "status": "unique", "dir": "d"})
            ps.set_finding(st, cid, GOOD_FINDING)
        self.assertIn("nvidia_uvm", self.brief())

    def test_it_says_when_nothing_steers_the_next_round(self):
        self.assertIn("only steer on coverage", self.brief())

    def test_it_surfaces_integrity_problems(self):
        with ps.transaction() as st:
            cid = ps.register_crash(
                st, {"track": "K", "title": "t", "stack_hash": "h",
                     "status": "rca_done", "dir": "d"})
            st["crashes"][cid]["finding"] = None
        self.assertIn("Integrity", self.brief())

    def test_it_stamps_its_own_time_so_a_stale_copy_is_visible(self):
        out = self.brief()
        self.assertIn("generated", out)
        self.assertIn("Re-run it", out)

    def test_an_absent_knowledge_dir_is_simply_empty(self):
        """Nothing recorded yet is the normal first-campaign state, not a
        failure, so it must not read as one."""
        knowledge_ctl.KNOWLEDGE_DIR = "/nonexistent/nope"
        out = self.brief()
        self.assertIn("run phase provision", out)
        self.assertNotIn("knowledge unavailable", out)

    def test_an_unreadable_knowledge_file_does_not_cost_the_state_summary(self):
        """A corrupt or unreadable knowledge file must not take down the part
        of the brief the reader cannot get anywhere else. An absent directory
        does not exercise this: it returns empty without raising, which is why
        the failure has to be injected."""
        def boom(_kind):
            raise ValueError("simulated unreadable knowledge file")
        self.addCleanup(setattr, knowledge_ctl, "_entries",
                        knowledge_ctl._entries)
        knowledge_ctl._entries = boom
        out = self.brief()
        self.assertIn("run phase provision", out)
        self.assertIn("knowledge unavailable", out)


class TestCampaignWindowGatesTheRound(StateTempMixin, unittest.TestCase):
    """The loop must not measure a campaign that is still running.

    The fuzz gate used to be the 30-minute smoke window, so an unattended
    round advanced half an hour into a 24-hour run: triage scanned a nearly
    empty workdir, the later gates were satisfied by having nothing to do, and
    round-end fitted a three-sample curve while the campaign kept fuzzing
    behind it. Everything downstream inherited that.
    """

    def setUp(self):
        super().setUp()
        self._orig_runs = campaign_ctl.RUNS_DIR
        campaign_ctl.RUNS_DIR = os.path.join(self.tmp.name, "runs")
        self.addCleanup(lambda: setattr(campaign_ctl, "RUNS_DIR",
                                        self._orig_runs))
        import pipeline_ctl
        self.ctl = pipeline_ctl
        st = ps.default_state()
        ps.current_round(st)["run_ids"] = ["r1-1"]
        ps.save(st)

    def with_deadline(self, hours):
        campaign_ctl.write_deadline("r1-1", hours)

    def fuzz_done(self):
        with ps.transaction() as st:
            ps.update_phase(st, "fuzz", "done")

    def test_a_campaign_inside_its_window_is_visible_as_live(self):
        self.with_deadline(5)
        live = self.ctl._live_runs(ps.load())
        self.assertEqual([r for r, _ in live], ["r1-1"])

    def test_an_elapsed_campaign_is_not_live(self):
        self.with_deadline(-1)
        self.assertEqual(self.ctl._live_runs(ps.load()), [])

    def test_next_reports_wait_while_the_campaign_runs(self):
        self.with_deadline(5)
        self.fuzz_done()
        kind, val = self.ctl._next_action(ps.load())
        self.assertEqual(kind, "wait")
        self.assertEqual(val[0], "r1-1")

    def test_the_fuzz_phase_itself_is_never_told_to_wait(self):
        """fuzz is what starts the campaign. Telling it to wait for the
        campaign it has not installed yet would deadlock the round."""
        self.with_deadline(5)
        kind, val = self.ctl._next_action(ps.load())
        self.assertEqual((kind, val), ("phase", "provision"))

    def test_once_the_window_closes_the_pipeline_moves_on(self):
        self.with_deadline(-1)
        self.fuzz_done()
        kind, _ = self.ctl._next_action(ps.load())
        self.assertEqual(kind, "phase")

    def test_wait_check_reports_a_live_campaign_without_blocking(self):
        self.with_deadline(5)
        args = types.SimpleNamespace(run_id="r1-1", check=True, poll_min=1)
        with redirect_stdout(io.StringIO()) as out:
            rc = campaign_ctl.cmd_wait(args)
        self.assertEqual(rc, 1)
        self.assertIn("still fuzzing", out.getvalue())

    def test_wait_returns_once_the_window_has_elapsed(self):
        self.with_deadline(-1)
        args = types.SimpleNamespace(run_id="r1-1", check=False, poll_min=1)
        with redirect_stdout(io.StringIO()) as out:
            rc = campaign_ctl.cmd_wait(args)
        self.assertEqual(rc, 0)
        self.assertIn("has elapsed", out.getvalue())

    def test_wait_refuses_a_run_it_cannot_date(self):
        args = types.SimpleNamespace(run_id="r9-9", check=True, poll_min=1)
        with self.assertRaises(SystemExit):
            with redirect_stdout(io.StringIO()):
                campaign_ctl.cmd_wait(args)


class TestRoundEndRefusesALiveCampaign(StateTempMixin, unittest.TestCase):
    """round-end is where a live campaign becomes wrong numbers on record."""

    def setUp(self):
        super().setUp()
        self._orig_runs = campaign_ctl.RUNS_DIR
        campaign_ctl.RUNS_DIR = os.path.join(self.tmp.name, "runs")
        coverage_dir = os.path.join(self.tmp.name, "runs")
        self._orig_cov = coverage_ctl.RUNS_DIR
        coverage_ctl.RUNS_DIR = coverage_dir
        self.addCleanup(lambda: setattr(campaign_ctl, "RUNS_DIR",
                                        self._orig_runs))
        self.addCleanup(lambda: setattr(coverage_ctl, "RUNS_DIR",
                                        self._orig_cov))
        os.makedirs(os.path.join(coverage_dir, "r1-1"), exist_ok=True)
        with open(coverage_ctl.csv_path("r1-1"), "w") as f:
            f.write(",".join(coverage_ctl.FIELDS) + "\n")
            for i in range(4):
                f.write(csv_line(1000 + i * 600, edges=10 + i * 5,
                                 execs=1000 * (i + 1)) + "\n")
        st = ps.default_state()
        ps.current_round(st)["run_ids"] = ["r1-1"]
        ps.save(st)

    def args(self, force=False):
        return types.SimpleNamespace(
            from_run=["r1-1"], coverage_verdict=None, new_crashes=None,
            edges_start=None, edges_end=None, run_hours=None, notes=None,
            worklist=None, force=force)

    def test_measuring_a_live_campaign_is_refused(self):
        campaign_ctl.write_deadline("r1-1", 5)
        with self.assertRaises(SystemExit) as cm:
            with redirect_stdout(io.StringIO()):
                pipeline_ctl_cmd_round_end(self.args())
        self.assertIn("refusing to measure a live campaign", str(cm.exception))
        self.assertIsNone(ps.current_round(ps.load())["ended"])

    def test_force_measures_it_anyway(self):
        """The deadline file can outlive the campaign it described. --force is
        the way to say so, and it has to actually work or the escape hatch is
        theatre."""
        campaign_ctl.write_deadline("r1-1", 5)
        with redirect_stdout(io.StringIO()):
            pipeline_ctl_cmd_round_end(self.args(force=True))
        self.assertIsNotNone(ps.current_round(ps.load())["ended"])

    def test_an_elapsed_campaign_needs_no_force(self):
        campaign_ctl.write_deadline("r1-1", -1)
        with redirect_stdout(io.StringIO()):
            pipeline_ctl_cmd_round_end(self.args())
        self.assertIsNotNone(ps.current_round(ps.load())["ended"])


class TestNoiseXidsAreNotFindings(StateTempMixin, unittest.TestCase):
    """A campaign that counts its own exhaust has not found anything.

    The Xid classification existed and was tested; it was simply never
    consulted where the counts are derived, so every round's new_crashes
    carried the Xids the fuzzer produces on purpose.
    """

    DMESG = ("[1.0] NVRM: Xid (PCI:0000:00:1e): 13, pid=1, Graphics "
             "Exception\n"
             "[2.0] NVRM: Xid (PCI:0000:00:1e): 31, pid=2, Ch 8\n"
             "[3.0] NVRM: Xid (PCI:0000:00:1e): 119, pid=3, GSP RPC Timeout\n")

    def registry(self):
        st = ps.default_state()
        path = os.path.join(self.tmp.name, "dmesg.txt")
        with open(path, "w") as f:
            f.write(self.DMESG)
        with redirect_stdout(io.StringIO()):
            crash_parse.scan_dmesg(st, path)
        return st

    def test_only_the_signal_xid_counts_as_a_finding(self):
        import pipeline_ctl
        st = self.registry()
        self.assertEqual(len(st["crashes"]), 3)      # all three registered
        self.assertEqual(pipeline_ctl._derived_new_crashes(st), 1)

    def test_noise_entries_stay_in_the_registry_as_an_audit_trail(self):
        st = self.registry()
        signals = sorted(c["signal"] for c in st["crashes"].values())
        self.assertEqual(signals, ["noise", "noise", "signal"])

    def test_a_signal_xid_alone_still_counts(self):
        import pipeline_ctl
        st = ps.default_state()
        ps.register_crash(st, {"track": "K", "title": "NVRM Xid: 119",
                               "stack_hash": "h", "status": "unique",
                               "dir": "d", "signal": "signal"})
        self.assertEqual(pipeline_ctl._derived_new_crashes(st), 1)

    def test_the_bus_id_is_provenance_not_identity(self):
        """The same driver bug on two cards is one bug. Leaving the bus id in
        the title registered it once per card."""
        st = self.registry()
        titles = [c["title"] for c in st["crashes"].values()]
        self.assertFalse([t for t in titles if "PCI:" in t], titles)
        self.assertTrue(any("0000:00:1e" in (c["notes"] or "")
                            for c in st["crashes"].values()))


class TestRcaGuardOutlivesThePocPhase(StateTempMixin, unittest.TestCase):
    """`status` is not durable, so the integrity check cannot key on it.

    The poc phase writes reliable/flaky/unreproducible straight over
    `rca_done`, and poc always runs after rca, so a check keyed on the current
    status stopped seeing an unanalysed crash exactly when it mattered.
    """

    def setUp(self):
        super().setUp()
        self.st = ps.default_state()
        self.cid = ps.register_crash(self.st, {
            "track": "K", "title": "KASAN: uaf", "stack_hash": "h",
            "status": "unique", "dir": "d"})

    def problems(self):
        return [p for p in ps.validate(self.st) if self.cid in p]

    def test_an_analysed_crash_with_no_records_is_a_problem(self):
        ps.set_crash_status(self.st["crashes"][self.cid], "rca_done")
        self.assertEqual(len(self.problems()), 2)     # finding + impact

    def test_the_problem_survives_poc_overwriting_the_status(self):
        c = self.st["crashes"][self.cid]
        ps.set_crash_status(c, "rca_done")
        ps.set_crash_status(c, "reliable", "repro_ctl")
        self.assertEqual(len(self.problems()), 2)

    def test_a_crash_poc_verified_but_never_analysed_is_not_flagged(self):
        """Only crashes rca actually finished with owe a finding and an
        impact. A reliable crash still queued for analysis owes nothing yet."""
        ps.set_crash_status(self.st["crashes"][self.cid], "reliable",
                            "repro_ctl")
        self.assertEqual(self.problems(), [])

    def test_a_duplicate_is_exempt(self):
        c = self.st["crashes"][self.cid]
        ps.set_crash_status(c, "rca_done")
        other = ps.register_crash(self.st, {
            "track": "K", "title": "t2", "stack_hash": "h2",
            "status": "unique", "dir": "d2"})
        c["duplicate_of"] = other
        ps.set_crash_status(c, "duplicate")
        self.assertEqual(self.problems(), [])

    def test_the_stamp_is_written_once(self):
        c = self.st["crashes"][self.cid]
        ps.set_crash_status(c, "rca_done")
        first = c["rca_done_at"]
        ps.set_crash_status(c, "reliable", "repro_ctl")
        ps.set_crash_status(c, "rca_done")
        self.assertEqual(c["rca_done_at"], first)

    def test_a_registry_predating_the_stamp_still_reports(self):
        """was_analysed falls back to the current status, so a state file
        written before the stamp existed is not silently exempted."""
        c = self.st["crashes"][self.cid]
        c["status"] = "rca_done"
        c.pop("rca_done_at", None)
        self.assertEqual(len(self.problems()), 2)

    def test_the_status_change_is_recorded_in_the_trail(self):
        c = self.st["crashes"][self.cid]
        ps.set_crash_status(c, "rca_done")
        ps.set_crash_status(c, "reliable", "repro_ctl")
        self.assertEqual([h["to"] for h in c["history"]],
                         ["rca_done", "reliable"])

    def test_setting_the_same_status_twice_adds_no_trail_entry(self):
        c = self.st["crashes"][self.cid]
        ps.set_crash_status(c, "reliable")
        ps.set_crash_status(c, "reliable")
        self.assertEqual(len(c["history"]), 1)


class TestOrchestratorUnitSections(unittest.TestCase):
    """systemd ignores keys in the wrong section, silently.

    StartLimitIntervalSec and StartLimitBurst are [Unit] options;
    systemd.service(5) only cross-references them. Under [Service] they are an
    unknown key, so the intended limit never applied and the manager default
    of 5 starts per 10s governed instead, which RestartSec=60 can never reach.
    """

    def sections(self):
        text = orchestrator_ctl.UNIT_TMPL.format(
            root="/r", restart_sec=60, user="u", home="/h",
            limit_interval=3600, limit_burst=20,
            blocked_exit=orchestrator_ctl.BLOCKED_EXIT)
        out, name = {}, None
        for line in text.splitlines():
            if line.startswith("[") and line.endswith("]"):
                name = line.strip("[]")
                out[name] = []
            elif name and line and not line.startswith("#"):
                out[name].append(line)
        return out

    def test_the_start_rate_limit_is_in_the_unit_section(self):
        unit = "\n".join(self.sections()["Unit"])
        self.assertIn("StartLimitIntervalSec=3600", unit)
        self.assertIn("StartLimitBurst=20", unit)

    def test_it_is_not_in_the_service_section(self):
        service = "\n".join(self.sections()["Service"])
        self.assertNotIn("StartLimit", service)

    def test_the_restart_settings_stay_in_the_service_section(self):
        service = "\n".join(self.sections()["Service"])
        self.assertIn("Restart=always", service)
        self.assertIn("RestartPreventExitStatus=%d"
                      % orchestrator_ctl.BLOCKED_EXIT, service)


class TestAgentStallTimeout(unittest.TestCase):
    """The breaker counts starts, not stalls.

    An agent blocked on a prompt or a wedged tool held the pipeline open for
    as long as it liked while the instance billed, and nothing anywhere
    noticed.
    """

    def kill_after_a_second(self, cmd):
        """launch_agent prints why it killed the agent; that belongs in the
        journal on a real box, not in the middle of the test output."""
        with redirect_stdout(io.StringIO()):
            return orchestrator_ctl.launch_agent(cmd, max_hours=1.0 / 3600.0)

    def test_an_agent_past_the_limit_is_killed(self):
        started = time.time()
        r = self.kill_after_a_second("sleep 30")
        self.assertNotEqual(r.returncode, 0)
        self.assertLess(time.time() - started, 25)

    def test_a_normal_agent_is_untouched(self):
        self.assertEqual(orchestrator_ctl.launch_agent("true", 1).returncode, 0)

    def test_zero_means_no_limit(self):
        self.assertEqual(orchestrator_ctl.launch_agent("true", 0).returncode, 0)

    def test_the_whole_process_group_goes(self):
        """shell=True means the immediate child is a shell. Killing only that
        leaves the agent running, detached, still stuck on whatever it was
        stuck on."""
        marker = os.path.join(tempfile.mkdtemp(), "alive")
        self.kill_after_a_second("sh -c 'sleep 20; touch %s' & wait" % marker)
        time.sleep(3)
        self.assertFalse(os.path.exists(marker))


class TestDeadlineReconstruction(StateTempMixin, unittest.TestCase):
    """Losing one small file used to remove the spend ceiling in silence."""

    def setUp(self):
        super().setUp()
        self._orig_runs = campaign_ctl.RUNS_DIR
        campaign_ctl.RUNS_DIR = os.path.join(self.tmp.name, "runs")
        self.addCleanup(lambda: setattr(campaign_ctl, "RUNS_DIR",
                                        self._orig_runs))

    def install_event(self, hours=24):
        st = ps.default_state()
        st["campaigns"].append({"track": "k", "action": "install",
                                "run_id": "r1-1", "at": ps._now(),
                                "hours": hours, "note": "window"})
        ps.save(st)

    def test_a_lost_deadline_is_rebuilt_from_the_install_record(self):
        self.install_event(24)
        at = campaign_ctl.reconstruct_deadline("r1-1")
        self.assertIsNotNone(at)
        self.assertAlmostEqual((at - time.time()) / 3600.0, 24, delta=0.1)

    def test_the_rebuilt_deadline_is_written_back(self):
        self.install_event(24)
        campaign_ctl.reconstruct_deadline("r1-1")
        self.assertIsNotNone(campaign_ctl.read_deadline("r1-1"))

    def test_the_latest_install_wins(self):
        """install-k and install-u both write one, and install-u resets the
        clock, so the newest is the window actually in force."""
        self.install_event(2)
        st = ps.load()
        st["campaigns"].append({"track": "u", "action": "install",
                                "run_id": "r1-1", "at": ps._now(),
                                "hours": 24, "note": "window"})
        ps.save(st)
        at = campaign_ctl.reconstruct_deadline("r1-1")
        self.assertAlmostEqual((at - time.time()) / 3600.0, 24, delta=0.1)

    def test_nothing_to_reconstruct_from_returns_none(self):
        self.assertIsNone(campaign_ctl.reconstruct_deadline("r9-9"))

    def test_check_deadline_uses_the_reconstruction(self):
        self.install_event(24)
        args = types.SimpleNamespace(run_id="r1-1")
        with redirect_stdout(io.StringIO()) as out:
            campaign_ctl.cmd_check_deadline(args)
        self.assertIn("rebuilt it from the install record", out.getvalue())
        self.assertIn("left of its campaign window", out.getvalue())

    def test_wait_still_dates_a_run_whose_deadline_file_is_gone(self):
        """Testing reconstruct_deadline directly proves the reconstruction
        works; it does not prove the fuzz gate uses it. `wait` is what the
        phase blocks on, so if it reads only the file, losing that file turns
        the gate into an immediate error and the round advances anyway."""
        self.install_event(24)
        self.assertIsNone(campaign_ctl.read_deadline("r1-1"))
        args = types.SimpleNamespace(run_id="r1-1", check=True, poll_min=1)
        with redirect_stdout(io.StringIO()) as out:
            rc = campaign_ctl.cmd_wait(args)
        self.assertEqual(rc, 1)
        self.assertIn("still fuzzing", out.getvalue())

    def test_an_undatable_run_with_nothing_running_is_left_alone(self):
        args = types.SimpleNamespace(run_id="r9-9")
        with redirect_stdout(io.StringIO()) as out:
            rc = campaign_ctl.cmd_check_deadline(args)
        self.assertEqual(rc, 0)
        self.assertIn("nothing to enforce", out.getvalue())


class TestEveryCampaignBills(StateTempMixin, unittest.TestCase):
    """A round that never closes used to keep its hours off the cap entirely.

    bill_run skipped anything attached to a round, assuming round-end would
    bill it. A round abandoned to a blocked phase or a breaker trip never
    reaches round-end, so a whole campaign went unbilled.
    """

    def setUp(self):
        super().setUp()
        self._orig = coverage_ctl.RUNS_DIR
        coverage_ctl.RUNS_DIR = os.path.join(self.tmp.name, "runs")
        self.addCleanup(lambda: setattr(coverage_ctl, "RUNS_DIR", self._orig))
        os.makedirs(os.path.join(coverage_ctl.RUNS_DIR, "r1-1"))
        with open(coverage_ctl.csv_path("r1-1"), "w") as f:
            f.write(",".join(coverage_ctl.FIELDS) + "\n")
            # Not epoch 0: read_rows filters on `if r.get("ts")`, so a sample
            # at 0 is dropped and the measured span collapses to one stamp.
            f.write(csv_line(1700000000, edges=1) + "\n")
            f.write(csv_line(1700007200, edges=9) + "\n")   # two hours on

    def test_a_round_campaign_is_billed_at_its_stop(self):
        st = ps.default_state()
        ps.current_round(st)["run_ids"] = ["r1-1"]
        ps.save(st)
        with redirect_stdout(io.StringIO()):
            campaign_ctl.bill_run("r1-1", "test")
        self.assertAlmostEqual(ps.total_spend_hours(), 2.0, delta=0.01)

    def test_billing_twice_does_not_double_count(self):
        with redirect_stdout(io.StringIO()):
            campaign_ctl.bill_run("r1-1", "test")
            campaign_ctl.bill_run("r1-1", "test")
        self.assertAlmostEqual(ps.total_spend_hours(), 2.0, delta=0.01)

    def test_hours_come_from_the_samples_not_the_configured_window(self):
        """A run that died after two hours must not bill the configured 24."""
        hours, basis = campaign_ctl.measured_run_hours("r1-1")
        self.assertAlmostEqual(hours, 2.0, delta=0.01)
        self.assertIn("coverage samples", basis)


class TestDiskHeadroom(unittest.TestCase):
    """Everything this pipeline writes shares one filesystem."""

    def test_free_space_is_measurable(self):
        self.assertIsInstance(coverage_ctl.disk_free_mb(), int)

    def test_it_is_a_recorded_column(self):
        self.assertIn("disk_free_mb", coverage_ctl.FIELDS)

    def test_plenty_of_space_warns_about_nothing(self):
        self.assertEqual(coverage_ctl.disk_warning(500 * 1024), "")

    def test_running_short_warns(self):
        out = coverage_ctl.disk_warning(1024)      # 1 GB, floor is 20
        self.assertIn("min_free_disk_gb", out)

    def test_an_unmeasurable_filesystem_does_not_invent_a_warning(self):
        self.assertEqual(coverage_ctl.disk_warning(None), "")


class TestTrackUDoesNotUseTheGpu(unittest.TestCase):
    """Gating the container-toolkit verdict on the GPU reported a real
    plateau as unknown, for a reason unrelated to what was measured."""

    def test_the_not_applicable_marker_is_not_unhealthy(self):
        rows = [{"gpu": coverage_ctl.GPU_NOT_APPLICABLE}] * 3
        self.assertEqual(coverage_ctl.unhealthy_gpu_samples(rows), {})

    def test_a_dead_gpu_still_counts_on_track_k(self):
        self.assertEqual(coverage_ctl.unhealthy_gpu_samples([{"gpu": "dead"}]),
                         {"dead": 1})

    def test_an_unrecorded_gpu_still_counts(self):
        """Absence of evidence that the GPU was alive is not evidence that it
        was, and that stays true."""
        self.assertEqual(coverage_ctl.unhealthy_gpu_samples([{}]),
                         {"unrecorded": 1})

    def test_a_flat_track_u_curve_can_still_be_called_a_plateau(self):
        rows = [{"ts": 1_700_000_000 + i * 600, "edges": 100,
                 "execs": 1000 * (i + 1),
                 "gpu": coverage_ctl.GPU_NOT_APPLICABLE} for i in range(30)]
        verdict, detail = coverage_ctl.plateau_verdict(rows, 240, 0.02)
        self.assertEqual(verdict, "plateaued", detail)


class TestLiveCampaignBlocksVerification(unittest.TestCase):
    """A reproduction is scored partly on the box going down during the run.

    That inference only holds when the reproducer is the only thing that can
    panic the machine, and the fuzzer panics it by design.
    """

    def fake_is_active(self, state):
        self.queried = []

        def run(cmd, **kw):
            self.queried.append(cmd[1] if len(cmd) > 1 else cmd[0])
            return types.SimpleNamespace(stdout=state + "\n", stderr="",
                                         returncode=0)
        real = repro_ctl.subprocess
        repro_ctl.subprocess = types.SimpleNamespace(run=run)
        self.addCleanup(lambda: setattr(repro_ctl, "subprocess", real))

    def test_verification_is_refused_while_the_fuzzer_runs(self):
        self.fake_is_active("active")
        with self.assertRaises(SystemExit) as cm:
            repro_ctl._refuse_live_campaign(False)
        self.assertIn("still fuzzing", str(cm.exception))

    def test_a_restarting_unit_counts_as_running(self):
        self.fake_is_active("activating")
        with self.assertRaises(SystemExit):
            repro_ctl._refuse_live_campaign(False)

    def test_a_stopped_campaign_lets_verification_proceed(self):
        self.fake_is_active("inactive")
        self.assertIsNone(repro_ctl._refuse_live_campaign(False))
        # The refusal is keyed on what systemctl reported, so the test has to
        # show the function read it. A body of `pass` reaches neither.
        # _refuse_live_campaign runs ["systemctl", "is-active", "gspwn-k"].
        self.assertEqual(self.queried, ["is-active"])

    def test_the_override_is_honoured(self):
        self.fake_is_active("active")
        self.assertIsNone(repro_ctl._refuse_live_campaign(True))
        # The override returns before the query, so an active campaign is
        # never read. A body of `pass` would also skip the query, which is why
        # test_verification_is_refused_while_the_fuzzer_runs is the paired
        # test that fails against one.
        self.assertEqual(self.queried, [])


class TestStaleReproducerIsRebuilt(unittest.TestCase):
    """extract regenerates repro.c; a build-if-absent check then verified the
    previous binary against the new source, and neither file looked wrong."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.src = os.path.join(self.tmp.name, "repro.c")
        self.exe = os.path.join(self.tmp.name, "repro")

    def write(self, path, mtime):
        with open(path, "w") as f:
            f.write("x")
        os.utime(path, (mtime, mtime))

    def test_a_newer_source_forces_a_rebuild(self):
        self.write(self.exe, 1000)
        self.write(self.src, 2000)
        self.assertTrue(repro_ctl.needs_rebuild(self.src, self.exe))

    def test_an_up_to_date_binary_is_kept(self):
        self.write(self.src, 1000)
        self.write(self.exe, 2000)
        self.assertFalse(repro_ctl.needs_rebuild(self.src, self.exe))

    def test_a_missing_binary_is_not_a_stale_one(self):
        self.write(self.src, 1000)
        self.assertFalse(repro_ctl.needs_rebuild(self.src, self.exe))


class TestConfigValidatesWhatReachesTheSystem(unittest.TestCase):
    """The unvalidated keys were the ones that fail late, on the target."""

    def load(self, text):
        path = os.path.join(tempfile.mkdtemp(), "campaign.yaml")
        with open(path, "w") as f:
            f.write(text)
        return gspwn_config.load(path)

    def rejects(self, text, needle):
        with self.assertRaises(gspwn_config.ConfigError) as cm:
            self.load(text)
        self.assertIn(needle, str(cm.exception))

    def test_a_systemd_byte_spec_typo_is_caught(self):
        self.rejects("track_k:\n  memory_max: 12GB\n", "memory_max")

    def test_a_valid_byte_spec_passes(self):
        self.assertEqual(self.load("track_k:\n  memory_max: 12G\n")
                         ["track_k"]["memory_max"], "12G")

    def test_an_unknown_sandbox_is_caught(self):
        self.rejects("track_k:\n  sandbox: sandboxed\n", "sandbox")

    def test_a_malformed_stats_address_is_caught(self):
        self.rejects("track_k:\n  http: localhost\n", "http")

    def test_a_scalar_syscall_list_is_caught(self):
        self.rejects("track_k:\n  enabled_syscalls: ioctl$NV_*\n",
                     "enabled_syscalls")

    def test_an_empty_docker_image_is_caught(self):
        self.rejects("track_u:\n  docker_image: ''\n", "docker_image")

    def test_an_agent_timeout_under_the_campaign_window_is_caught(self):
        """The fuzz phase waits out the whole window in one launch, so a
        shorter timeout kills every healthy agent at the same point."""
        self.rejects("loop:\n  campaign_hours: 24\norchestrator:\n"
                     "  max_agent_hours: 12\n", "max_agent_hours")

    def test_a_longer_agent_timeout_passes(self):
        cfg = self.load("loop:\n  campaign_hours: 24\norchestrator:\n"
                        "  max_agent_hours: 30\n")
        self.assertEqual(cfg["orchestrator"]["max_agent_hours"], 30)

    def test_zero_disables_the_agent_timeout(self):
        cfg = self.load("orchestrator:\n  max_agent_hours: 0\n")
        self.assertEqual(cfg["orchestrator"]["max_agent_hours"], 0)

    def test_the_reliable_threshold_must_be_a_fraction(self):
        self.rejects("poc:\n  reliable_threshold: 80\n", "reliable_threshold")

    def test_the_poc_section_reaches_the_tool(self):
        self.assertEqual(sorted(gspwn_config.DEFAULTS["poc"]),
                         ["default_runs", "reliable_threshold",
                          "repro_timeout_sec", "void_retry_factor"])


class TestBulkTriageDecisions(unittest.TestCase):
    """The triage gate is an empty flagged queue, and one generic panic title
    with a varying stack flags every distinct stack."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.join(self.tmp.name, "state", "pipeline.json")
        self.env = dict(os.environ, GSPWN_STATE=self.state)
        st = ps.default_state()
        self.ids = [ps.register_crash(st, {
            "track": "K", "title": "t%d" % i, "stack_hash": "h%d" % i,
            "status": "flagged", "dir": "d%d" % i}) for i in range(4)]
        ps.save(st, self.state)

    def ctl(self, *args, expect=0):
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, "pipeline_ctl.py")]
            + list(args), env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, expect,
                         "args=%s\n%s%s" % (list(args), r.stdout, r.stderr))
        return r.stdout + r.stderr

    def crashes(self):
        return ps.load(self.state)["crashes"]

    def test_one_call_resolves_several_flags(self):
        self.ctl("crash-set", *self.ids[1:], "--duplicate-of", self.ids[0])
        self.assertEqual([self.crashes()[i]["status"] for i in self.ids[1:]],
                         ["duplicate"] * 3)

    def test_a_single_id_still_works(self):
        self.ctl("crash-set", self.ids[0], "--status", "unique")
        self.assertEqual(self.crashes()[self.ids[0]]["status"], "unique")

    def test_a_rejected_id_changes_nothing(self):
        """All-or-nothing, so the queue is never left half-decided and a retry
        of the same command is safe."""
        self.ctl("crash-set", self.ids[0], "crash-9999", "--status", "unique",
                 expect=1)
        self.assertEqual(self.crashes()[self.ids[0]]["status"], "flagged")


class TestAdvanceRoundRemediation(StateTempMixin, unittest.TestCase):
    """The error told the reader to do something that does not work."""

    def message(self):
        st = ps.default_state()
        for p in ps.PHASES:
            ps.update_phase(st, p, "done")
        ps.update_phase(st, "poc", "blocked")
        ps.record_decision(st, "continue")
        ps.end_round(st, run_hours=1.0)
        with self.assertRaises(ValueError) as cm:
            ps.advance_round(st)
        return str(cm.exception)

    def test_it_no_longer_suggests_marking_the_phase_blocked(self):
        self.assertNotIn("mark them blocked first", self.message())

    def test_it_says_marking_blocked_will_not_help(self):
        self.assertIn("does not satisfy", self.message())

    def test_it_offers_the_two_things_that_do_work(self):
        msg = self.message()
        self.assertIn("Finish them", msg)
        self.assertIn("round-decide", msg)


class TestSeedsParseAsSyzlang(unittest.TestCase):
    """openat takes four arguments. Emitting three produced a seed bank that
    could not parse at all, and the seeds gate would have blamed the model."""

    def prog(self):
        trace = ('openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3\n'
                 'ioctl(3, 0xc020462a, 0x7ffd) = 0\n'
                 'close(3) = 0\n')
        return trace2seed.convert(trace, {"0xc020462a": "ioctl$NV_ALLOC"})

    def test_openat_carries_the_directory_fd(self):
        line = [l for l in self.prog().splitlines() if "openat" in l][0]
        self.assertIn(trace2seed.AT_FDCWD, line)

    def test_openat_has_four_arguments(self):
        line = [l for l in self.prog().splitlines() if "openat" in l][0]
        args = line.split("(", 1)[1].rsplit(")", 1)[0]
        self.assertEqual(len(args.split(", ")), 4, line)

    def test_the_mapped_count_does_not_depend_on_the_description_prefix(self):
        """The map's values are whatever describe named its descriptions.
        Counting lines starting with "ioctl$" reported zero mapped while
        emitting them, and the seeds gate reads that ratio."""
        import re as _re
        prog = trace2seed.convert(
            'openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3\n'
            'ioctl(3, 0xc020462a, 0x0) = 0\n',
            {"0xc020462a": "nv_esc_rm_alloc"})
        mapped = sum(1 for ln in prog.splitlines()
                     if _re.match(r"^[A-Za-z_][\w$]*\(r\d+,", ln))
        self.assertEqual(mapped, 1, prog)


class TestHarvestDoesNotFakeSuccess(unittest.TestCase):
    """Reporting "no new crash logs found" when it could not read anything
    lost the panic evidence silently, on the automated recovery path."""

    def test_a_non_root_harvest_is_refused(self):
        import crashlog_ctl
        real = crashlog_ctl.os.geteuid
        crashlog_ctl.os.geteuid = lambda: 1000
        self.addCleanup(lambda: setattr(crashlog_ctl.os, "geteuid", real))
        with self.assertRaises(SystemExit) as cm:
            crashlog_ctl.cmd_harvest("baremetal")
        self.assertIn("must run as root", str(cm.exception))


class TestSyzlangSizeVerification(unittest.TestCase):
    """A parameter struct whose parsed layout does not total its measured
    sizeof is wrong. Emitting it anyway produces a description that compiles,
    runs, and never reaches the driver, because the ioctl request number
    encodes the size the driver expects."""

    HEADER = """
typedef struct
{
    NvU32 a;
    NvU64 b;
    NvU8  c;
} FIX_PARAMS;
"""
    # a at 0, four bytes of padding, b at 8, c at 16, seven bytes of tail
    # padding for the eight-byte alignment b forces.
    TRUE_SIZE = 24

    def emitter(self, sizes):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "fix.h")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.HEADER)
        index = syzlang_gen.TypeIndex()
        index.scan_file(path, "fix.h")
        return syzlang_gen.Emitter(index, sizes)

    def test_a_layout_matching_the_measured_size_is_emitted_as_fields(self):
        emitter = self.emitter({"FIX_PARAMS": self.TRUE_SIZE})
        self.assertEqual(emitter.ensure("FIX_PARAMS"), "FIX_PARAMS")
        self.assertEqual(emitter.size_mismatch, [])
        self.assertEqual(emitter.opaque, [])
        block = emitter.rendered["FIX_PARAMS"]
        for field in ("a", "b", "c"):
            self.assertIn("\t%s\t" % field, block.replace("       ", "\t"))

    def test_the_emitted_struct_totals_the_measured_size(self):
        """Padding is explicit and the struct is packed, so the emitted size
        cannot depend on syzkaller's alignment rules agreeing with the
        compiler's."""
        emitter = self.emitter({"FIX_PARAMS": self.TRUE_SIZE})
        emitter.ensure("FIX_PARAMS")
        block = emitter.rendered["FIX_PARAMS"]
        self.assertIn("[packed]", block)
        total = 0
        for line in block.splitlines():
            if not line.startswith("\t"):
                continue
            syz = [p for p in line.split("\t") if p.strip()][-1]
            if syz.startswith("array[const[0, int8],"):
                total += int(syz.rsplit(",", 1)[1].strip(" ]"))
            elif syz == "const[0, int8]":
                total += 1
            else:
                total += {"int8": 1, "int16": 2, "int32": 4,
                          "int64": 8}[syz]
        self.assertEqual(total, self.TRUE_SIZE, block)

    def test_a_layout_disagreeing_with_the_measured_size_is_reported(self):
        emitter = self.emitter({"FIX_PARAMS": self.TRUE_SIZE + 8})
        emitter.ensure("FIX_PARAMS")
        self.assertEqual(emitter.size_mismatch,
                         [("FIX_PARAMS", self.TRUE_SIZE, self.TRUE_SIZE + 8)])

    def test_a_mismatched_struct_falls_back_to_the_measured_size(self):
        measured = self.TRUE_SIZE + 8
        emitter = self.emitter({"FIX_PARAMS": measured})
        emitter.ensure("FIX_PARAMS")
        self.assertIn("array[int8, %d]" % measured,
                      emitter.rendered["FIX_PARAMS"])
        self.assertEqual([name for name, _size, _why in emitter.opaque],
                         ["FIX_PARAMS"])

    def test_a_struct_with_neither_a_layout_nor_a_size_is_not_emitted(self):
        """Nothing is guessed to fill a description. A command whose parameter
        type cannot be sized is left out and counted."""
        emitter = self.emitter({})
        self.assertIsNone(emitter.ensure("ABSENT_PARAMS"))
        self.assertEqual([name for name, _why in emitter.unresolved],
                         ["ABSENT_PARAMS"])
        self.assertNotIn("ABSENT_PARAMS", emitter.rendered)


class CvePatchBracketing(unittest.TestCase):
    """The three invariants that decide whether a release diff is evidence.

    A wrong bracket produces a diff of a whole branch divergence and every
    function in it reads as a security fix. A wrong path filter drops the RM
    control handlers, which is most of the surface. A wrong line attribution
    files a hunk under the previous function.
    """

    ROWS = [
        # (product, platform, affected, updated)
        ("GeForce", "Linux(R580)", "All prior to 580.95.05", "580.95.05"),
        ("Tesla", "Linux(R535)", "All prior to 535.274.02", "535.274.02"),
        ("GeForce", "Windows(R580)", "All prior to 581.42", "581.42"),
        ("Virtual GPU Manager", "Red Hat Enterprise Linux KVM(R580)",
         "580.82.02", "580.95.02(September 2025 Release)"),
        ("Cloud Gaming", "Linux(R550)", "All prior to 550.00.00",
         "550.00.00"),
    ]

    def test_only_linux_rows_for_the_open_modules_are_read(self):
        self.assertEqual(cve_patch_map.linux_fix_versions(self.ROWS),
                         {"580.95.05", "535.274.02"})

    def resolve(self, tags, brackets):
        """Run resolve_cves with git replaced by a fixed bracket table."""
        record = {"cve": "CVE-2025-23280", "bulletin_id": "5703",
                  "bulletin_date": "2025-10-09", "cwe": "CWE-416",
                  "subsystem": None, "component_as_nvidia_words_it": ""}
        original = cve_patch_map.bracket
        cve_patch_map.bracket = lambda _src, tag: brackets.get(tag)
        try:
            return cve_patch_map.resolve_cves(
                "unused", tags, [record],
                {"CVE-2025-23280": self.ROWS})[0]
        finally:
            cve_patch_map.bracket = original

    def test_a_version_absent_from_the_tags_is_reported_and_not_guessed(self):
        out = self.resolve({"580.95.05"}, {"580.95.05": ("580.82.09",
                                                         "580.95.05")})
        self.assertEqual(out["fix_versions_stated"],
                         ["535.274.02", "580.95.05"])
        self.assertEqual(out["fix_versions_present_as_tag"], ["580.95.05"])
        self.assertEqual([(p["from"], p["to"]) for p in out["tag_pairs"]],
                         [("580.82.09", "580.95.05")])

    def test_a_predecessor_on_another_branch_is_flagged(self):
        """565.77..570.86.15 is a branch opening, not a release. Left
        unflagged it contributes 528 changed files to the ranking."""
        out = self.resolve({"580.95.05"}, {"580.95.05": ("565.77",
                                                         "580.95.05")})
        self.assertTrue(out["tag_pairs"][0]["cross_branch"])
        out = self.resolve({"580.95.05"}, {"580.95.05": ("580.82.09",
                                                         "580.95.05")})
        self.assertFalse(out["tag_pairs"][0]["cross_branch"])

    def test_the_path_filter_keeps_the_control_handlers(self):
        keep = ["src/nvidia/src/kernel/rmapi/client_resource.c",
                "src/nvidia/src/kernel/gpu/mem_mgr/mem_desc.c",
                "kernel-open/nvidia-uvm/uvm_va_range.c",
                "src/nvidia/arch/nvalloc/unix/src/escape.c"]
        drop = ["kernel-open/nvidia-drm/nvidia-drm-drv.c",
                "kernel-open/nvidia-modeset/nvidia-modeset-linux.c",
                "src/nvidia/generated/g_client_resource_nvoc.c",
                "version.mk"]
        for path in keep:
            self.assertTrue(cve_patch_map.path_in_scope(path, False), path)
        for path in drop:
            self.assertFalse(cve_patch_map.path_in_scope(path, False), path)
        self.assertTrue(cve_patch_map.path_in_scope(
            "src/nvidia/generated/g_client_resource_nvoc.c", True))

    SOURCE = "\n".join([
        "#include <nv.h>",                        # 1
        "",                                       # 2
        "static NV_STATUS _helper(NvU32 a)",      # 3
        "{",                                      # 4
        "    return a;",                          # 5
        "}",                                      # 6
        "",                                       # 7
        "NV_STATUS",                              # 8
        "memdescCreate",                          # 9
        "(",                                      # 10
        "    NvU64 Size",                         # 11
        ")",                                      # 12
        "{",                                      # 13
        "    return NV_OK;",                      # 14
        "}",                                      # 15
    ])

    def test_both_declarator_styles_are_recognised(self):
        ranges = cve_patch_map.function_ranges(self.SOURCE)
        self.assertEqual([name for name, _first, _last in ranges],
                         ["_helper", "memdescCreate"])

    def test_a_line_between_two_functions_is_attributed_to_neither(self):
        ranges = cve_patch_map.function_ranges(self.SOURCE)
        self.assertEqual(cve_patch_map.enclosing(ranges, 5), "_helper")
        self.assertEqual(cve_patch_map.enclosing(ranges, 14), "memdescCreate")
        self.assertIsNone(cve_patch_map.enclosing(ranges, 7))

    def test_a_verdict_without_its_evidence_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "verdicts.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"verdicts": {"CVE-2024-0090": {
                    "verdict": "located"}}}, handle)
            with self.assertRaises(cve_patch_map.SourceError) as caught:
                cve_patch_map.load_verdicts(path)
            self.assertIn("basis", str(caught.exception))


class SurfaceDenominator(unittest.TestCase):
    """The denominator decides every ratio surface coverage reports. Counting
    one call twice, or dropping the allocation the whole DAG hangs from, moves
    the number without any campaign changing."""

    def inventories(self, tmp, ctrl_methods=None, graph_records=None,
                    version="610.57.04"):
        source = {"path": tmp, "driver_version": version}
        ioctl = {
            "source": source,
            "nodes": [
                {"paths": ["/dev/nvidiactl"], "module": "nvidia", "commands": [
                    {"name": "NV_ESC_CARD_INFO"},
                    {"name": "NV_ESC_RM_CONTROL"},
                    {"name": "NV_ESC_RM_ALLOC"},
                ]},
                {"paths": ["/dev/nvidia-uvm"], "module": "nvidia-uvm",
                 "commands": [
                     {"name": "UVM_REGISTER_CHANNEL", "reachable": True},
                     {"name": "UVM_TEST_THING", "reachable": False,
                      "reachability_gate": "uvm_enable_builtin_tests"},
                 ]},
                {"paths": ["/dev/nvidia-uvm-tools"], "module": "nvidia-uvm",
                 "commands": [{"name": "UVM_TOOLS_INIT", "reachable": True}]},
            ],
            "dead_escapes": ["NV_ESC_RM_ADD_VBLANK_CALLBACK"],
        }
        ctrl = {"source": source, "methods": ctrl_methods if ctrl_methods
                is not None else []}
        graph = {"source": source, "records": graph_records
                 if graph_records is not None else []}
        for name, doc in (("ioctl-inventory.json", ioctl),
                          ("rm-control-inventory.json", ctrl),
                          ("rm-object-graph.json", graph)):
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
        return tmp

    def load(self, tmp):
        original = (surface_cov.IOCTL_INV, surface_cov.CTRL_INV,
                    surface_cov.OBJ_GRAPH)
        surface_cov.IOCTL_INV = os.path.join(tmp, "ioctl-inventory.json")
        surface_cov.CTRL_INV = os.path.join(tmp, "rm-control-inventory.json")
        surface_cov.OBJ_GRAPH = os.path.join(tmp, "rm-object-graph.json")
        try:
            return surface_cov.load_targets()
        finally:
            (surface_cov.IOCTL_INV, surface_cov.CTRL_INV,
             surface_cov.OBJ_GRAPH) = original

    def test_the_two_multiplexer_escapes_are_not_counted_as_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            targets, excluded, _ = self.load(self.inventories(tmp))
        self.assertNotIn("NV_ESC_RM_CONTROL", targets)
        self.assertNotIn("NV_ESC_RM_ALLOC", targets)
        self.assertEqual(excluded["NV_ESC_RM_CONTROL"]["family"],
                         "escape_mux")
        self.assertIn("NV_ESC_CARD_INFO", targets)

    def test_a_gsp_routed_command_is_excluded_and_still_counted(self):
        methods = [{"reachability": "non_privileged", "handler": "fooCtrlCmd",
                    "handler_compiled_out": True, "method_id": "0x1",
                    "sdk_prefix": "NV0000"}]
        with tempfile.TemporaryDirectory() as tmp:
            targets, excluded, _ = self.load(
                self.inventories(tmp, ctrl_methods=methods))
        variant = "NV_ESC_RM_CONTROL_fooCtrlCmd"
        self.assertNotIn(variant, targets)
        self.assertEqual(excluded[variant]["family"], "control_gsp")

    def test_a_privileged_command_is_absent_from_both_sides(self):
        methods = [{"reachability": "privileged", "handler": "barCtrlCmd",
                    "handler_compiled_out": False}]
        with tempfile.TemporaryDirectory() as tmp:
            targets, excluded, _ = self.load(
                self.inventories(tmp, ctrl_methods=methods))
        variant = "NV_ESC_RM_CONTROL_barCtrlCmd"
        self.assertNotIn(variant, targets)
        self.assertNotIn(variant, excluded)

    def test_the_fd_level_root_class_is_a_target(self):
        """NV01_ROOT_CLIENT spells no RS_FLAGS_ALLOC_* flag because the fd is
        the gate. Reading that as an unknown privilege drops the first call of
        every program from the denominator."""
        # The sentinel is spelled literally here and not read from
        # surface_cov: object_graph.py writes it and surface_cov reads it, so
        # it is a contract between two tools. A fixture built from the
        # constant under test would pass whatever the constant said.
        records = [{"alloc_privilege": "unclassified", "depth": 1,
                    "parents": ["<root fd>"],
                    "external_class": "NV01_ROOT_CLIENT"}]
        with tempfile.TemporaryDirectory() as tmp:
            targets, _, _ = self.load(
                self.inventories(tmp, graph_records=records))
        self.assertIn("NV_ESC_RM_ALLOC_NV01_ROOT_CLIENT", targets)

    def test_an_unclassified_class_below_the_root_is_not_a_target(self):
        records = [{"alloc_privilege": "unclassified", "depth": 3,
                    "parents": ["NV01_DEVICE_0"], "external_class": "MYSTERY"}]
        with tempfile.TemporaryDirectory() as tmp:
            targets, _, _ = self.load(
                self.inventories(tmp, graph_records=records))
        self.assertNotIn("NV_ESC_RM_ALLOC_MYSTERY", targets)

    def test_a_uvm_test_command_is_separated_by_its_gate_not_its_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            targets, excluded, _ = self.load(self.inventories(tmp))
        self.assertIn("UVM_REGISTER_CHANNEL", targets)
        self.assertEqual(excluded["UVM_TEST_THING"]["family"], "uvm_test")
        self.assertEqual(targets["UVM_TOOLS_INIT"]["family"], "uvm_tools")

    def test_a_dead_escape_is_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            targets, excluded, _ = self.load(self.inventories(tmp))
        self.assertNotIn("NV_ESC_RM_ADD_VBLANK_CALLBACK", targets)
        self.assertEqual(
            excluded["NV_ESC_RM_ADD_VBLANK_CALLBACK"]["family"],
            "escape_dead")

    def test_inventories_from_different_releases_are_refused(self):
        """Mixing releases counts commands that do not coexist, and the ratio
        that comes out looks ordinary."""
        with tempfile.TemporaryDirectory() as tmp:
            self.inventories(tmp)
            path = os.path.join(tmp, "rm-control-inventory.json")
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            doc["source"]["driver_version"] = "580.65.06"
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
            with self.assertRaises(surface_cov.SurfaceError) as caught:
                self.load(tmp)
        self.assertIn("580.65.06", str(caught.exception))

    def test_a_missing_inventory_is_refused_and_not_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(surface_cov.SurfaceError) as caught:
                self.load(tmp)
        self.assertIn("denominator", str(caught.exception))


class SurfaceVariantScan(unittest.TestCase):
    """One pattern reads a description file and a corpus program, because both
    spell the variant the same way. A pattern that matched only the
    declaration would report every corpus as exercising nothing."""

    def scan(self, text, suffix):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "prog" + suffix)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            return surface_cov.scan_variants([path], "test")

    def test_a_syzlang_declaration_is_matched(self):
        line = ("ioctl$NV_ESC_RM_CONTROL_fooCtrlCmd(fd fd_nvidiactl, "
                "cmd const[0xc020462a], arg ptr[inout, params])")
        self.assertIn("NV_ESC_RM_CONTROL_fooCtrlCmd", self.scan(line, ".txt"))

    def test_a_corpus_call_site_is_matched(self):
        prog = "r0 = openat(0xffffffffffffff9c, &(0x7f0)='/dev/nvidiactl')\n" \
               "ioctl$UVM_REGISTER_CHANNEL(r0, 0x1b, &(0x7f00))\n"
        self.assertIn("UVM_REGISTER_CHANNEL", self.scan(prog, ".syz"))

    def test_a_plain_ioctl_without_a_variant_is_not_counted(self):
        self.assertEqual(self.scan("ioctl(r0, 0x1b, 0x0)\n", ".syz"), {})


class HistoryWorklistItems(unittest.TestCase):
    """The round-1 worklist is the only steering signal that exists before a
    campaign runs. An item naming a handler the method table does not spell is
    an item no agent can act on."""

    def test_the_nvoc_impl_suffix_is_stripped_from_the_variant(self):
        """The source spells fooCtrlCmdBar_IMPL and the exported method table
        spells fooCtrlCmdBar. syzlang_gen names the variant after the table."""
        self.assertEqual(cve_patch_map._variant("fooCtrlCmdBar_IMPL"),
                         "NV_ESC_RM_CONTROL_fooCtrlCmdBar")

    def test_a_handler_without_the_suffix_is_left_alone(self):
        self.assertEqual(cve_patch_map._variant("fooCtrlCmdBar"),
                         "NV_ESC_RM_CONTROL_fooCtrlCmdBar")

    def test_only_a_command_the_tenant_can_call_with_a_kernel_handler_passes(
            self):
        self.assertTrue(cve_patch_map._reachable(
            {"reachability": "non_privileged", "kernel_side_handler": True}))
        self.assertFalse(cve_patch_map._reachable(
            {"reachability": "non_privileged", "kernel_side_handler": False}))
        self.assertFalse(cve_patch_map._reachable(
            {"reachability": "privileged", "kernel_side_handler": True}))

    def test_the_header_path_is_repository_relative(self):
        """The worklist is committed and read on another machine, so an
        absolute path from whoever ran the tool is a broken pointer."""
        absolute = os.path.join(cve_patch_map.REPO_ROOT, "surface",
                                "cve-hotspots.json")
        self.assertEqual(cve_patch_map._relative(absolute),
                         "surface/cve-hotspots.json")


# ---------------------------------------------------------------------------
# Phase 1 (P0-1): the object graph parent map. From tmp/tests/phase1-objgraph.py.
#
# The internal-to-external class map is one-to-many, and every external class
# of a named internal parent is a legal parent.
#
# Failability, per tmp/impl/phase1.md: test_depths_are_unchanged_by_the_widening
# and the two sentinel tests pass against both mutations run there. They are
# regression cover for the widening, and they fail against an implementation
# that seeds the sentinels differently or lets a sentinel record fall through
# to classId parsing.
# ---------------------------------------------------------------------------


class TestObjectGraphParentMap(unittest.TestCase):
    """The RS_ENTRY internal-to-external relation is one-to-many.

    18 internal classes in resource_list.h export more than one external
    class. DispChannelDma exports 23, KernelGraphicsObject 17, KernelChannel
    11. A map that keeps only the first declaration drops 970 of the 1216
    parent edges and leaves 122 of 222 records with an under-reported parent
    list, which the emitter then reads as a single legal parent and pins.

    Nothing in the pipeline reports the loss: the description set compiles,
    generation.json counts 155 alloc variants, and surface_cov reports 155 of
    155 modelled.
    """

    @staticmethod
    def entry(external, internal, parents):
        """One parsed RS_ENTRY record, carrying the fields build_graph reads."""
        return {"external_class": external, "internal_class": internal,
                "parents": parents, "multi_instance": "NV_FALSE",
                "alloc_param": "RS_NONE", "free_priority": None,
                "flags": "RS_FLAGS_ALLOC_NON_PRIVILEGED",
                "access_rights": "RS_ACCESS_NONE"}

    # KernelChannel in miniature: one internal class, three external classes,
    # and one child naming it as its parent.
    CHANNELS = [
        ("GF100_CHANNEL_GPFIFO", "KernelChannel"),
        ("TURING_CHANNEL_GPFIFO_A", "KernelChannel"),
        ("BLACKWELL_CHANNEL_GPFIFO_A", "KernelChannel"),
    ]

    def channel_entries(self):
        entries = [self.entry("NV01_ROOT", "RmClientResource", "RS_ROOT_OBJECT")]
        for external, internal in self.CHANNELS:
            entries.append(self.entry(external, internal,
                                      "RS_LIST(classId(RmClientResource))"))
        entries.append(self.entry("AMPERE_A", "KernelGraphicsObject",
                                  "RS_LIST(classId(KernelChannel))"))
        return entries

    def test_every_external_class_of_a_named_internal_parent_is_a_parent(self):
        graph, _ = object_graph.build_graph(self.channel_entries())
        self.assertEqual(graph["AMPERE_A"],
                         ["GF100_CHANNEL_GPFIFO", "TURING_CHANNEL_GPFIFO_A",
                          "BLACKWELL_CHANNEL_GPFIFO_A"])

    def test_the_map_holds_a_list_per_internal_class(self):
        _, int2ext = object_graph.build_graph(self.channel_entries())
        self.assertEqual(int2ext["KernelChannel"],
                         ["GF100_CHANNEL_GPFIFO", "TURING_CHANNEL_GPFIFO_A",
                          "BLACKWELL_CHANNEL_GPFIFO_A"])
        self.assertEqual(int2ext["RmClientResource"], ["NV01_ROOT"])

    def test_two_internal_parents_sharing_an_external_class_list_it_once(self):
        # RmClientResource exports NV01_ROOT and NV01_ROOT_CLIENT; a second
        # internal class also exports NV01_ROOT_CLIENT. A child naming both
        # must list NV01_ROOT_CLIENT once, in the order the table declares it.
        entries = [
            self.entry("NV01_ROOT", "RmClientResource", "RS_ROOT_OBJECT"),
            self.entry("NV01_ROOT_CLIENT", "RmClientResource", "RS_ROOT_OBJECT"),
            self.entry("NV01_ROOT_CLIENT", "ClientProxy", "RS_ROOT_OBJECT"),
            self.entry("NV01_DEVICE_0", "OtherProxy", "RS_ROOT_OBJECT"),
            self.entry("NV01_MEMORY", "Memory",
                       "RS_LIST(classId(RmClientResource), classId(ClientProxy))"),
        ]
        graph, _ = object_graph.build_graph(entries)
        self.assertEqual(graph["NV01_MEMORY"],
                         ["NV01_ROOT", "NV01_ROOT_CLIENT"])

    def test_children_of_reaches_every_widened_parent(self):
        graph, _ = object_graph.build_graph(self.channel_entries())
        kids = object_graph.children_of(graph)
        for external, _internal in self.CHANNELS:
            self.assertIn("AMPERE_A", kids[external])

    def test_a_parent_naming_no_known_internal_class_is_counted(self):
        entries = [
            self.entry("NV01_ROOT", "RmClientResource", "RS_ROOT_OBJECT"),
            self.entry("NV01_MEMORY", "Memory",
                       "RS_LIST(classId(RmClientResource), classId(NotInTable))"),
        ]
        with self.assertLogs(object_graph.logger, level="WARNING") as caught:
            graph, _ = object_graph.build_graph(entries)
        self.assertEqual(graph["NV01_MEMORY"], ["NV01_ROOT"])
        self.assertIn("NotInTable", "\n".join(caught.output))

    def test_a_resolvable_table_logs_no_unresolved_warning(self):
        # assertLogs fails when nothing is logged, so a counter firing on a
        # clean table is caught here rather than passing unnoticed.
        with self.assertRaises(AssertionError):
            with self.assertLogs(object_graph.logger, level="WARNING"):
                object_graph.build_graph(self.channel_entries())

    def test_root_object_short_circuits_before_any_classid_lookup(self):
        entries = [
            self.entry("NV01_ROOT", "RmClientResource",
                       "RS_ROOT_OBJECT RS_LIST(classId(KernelChannel))"),
            self.entry("GF100_CHANNEL_GPFIFO", "KernelChannel",
                       "RS_LIST(classId(RmClientResource))"),
        ]
        graph, _ = object_graph.build_graph(entries)
        self.assertEqual(graph["NV01_ROOT"], [object_graph.ROOT])

    def test_any_parent_short_circuits_before_any_classid_lookup(self):
        entries = [
            self.entry("NV01_ROOT", "RmClientResource", "RS_ROOT_OBJECT"),
            self.entry("NV01_EVENT", "Event",
                       "RS_ANY_PARENT RS_LIST(classId(RmClientResource))"),
        ]
        graph, _ = object_graph.build_graph(entries)
        self.assertEqual(graph["NV01_EVENT"], [object_graph.ANY_PARENT])

    def test_depths_are_unchanged_by_the_widening(self):
        # The recovered edges run to siblings at the same depth, so the
        # breadth-first depth of every class is what it was. A widening that
        # moved a class up the tree would be a different defect.
        depth = object_graph.depths(
            object_graph.build_graph(self.channel_entries())[0])
        self.assertEqual(depth["NV01_ROOT"], 1)
        self.assertEqual(depth["GF100_CHANNEL_GPFIFO"], 2)
        self.assertEqual(depth["BLACKWELL_CHANNEL_GPFIFO_A"], 2)
        self.assertEqual(depth["AMPERE_A"], 3)


class TestWidenedParentReachesTheEmitter(unittest.TestCase):
    """syzlang_gen.parent_resource reads the widened list correctly.

    The pin at the emitter turned the parse loss into 63 dead alloc variants,
    and the fix leaves it unchanged: a class with one legal parent still gets
    that parent's own resource. The table now reports several for the affected
    classes, so the multi-parent branch is the one taken.
    """

    @staticmethod
    def by_class(names):
        return {name: {"external_class": name} for name in names}

    def test_several_legal_parents_take_the_generic_handle(self):
        record = {"parents": ["GF100_CHANNEL_GPFIFO", "TURING_CHANNEL_GPFIFO_A",
                              "BLACKWELL_CHANNEL_GPFIFO_A"]}
        by_class = self.by_class(record["parents"])
        self.assertEqual(
            syzlang_gen.parent_resource(record, by_class, {}),
            ("nv_handle", None))

    def test_one_legal_parent_still_pins_to_that_resource(self):
        record = {"parents": ["NV01_DEVICE_0"]}
        by_class = self.by_class(record["parents"])
        self.assertEqual(
            syzlang_gen.parent_resource(record, by_class, {}),
            (syzlang_gen.resource_name("NV01_DEVICE_0"), "NV01_DEVICE_0"))

    def test_the_root_sentinel_still_takes_the_file_descriptor(self):
        record = {"parents": [syzlang_gen.ROOT_SENTINEL]}
        self.assertEqual(syzlang_gen.parent_resource(record, {}, {}),
                         ("fd_root", None))


# ---------------------------------------------------------------------------
# Phase 2: kernel config, crash registration and reproducer extraction. From
# tmp/tests/phase2-crash.py.
#
# 19 of the 21 tests break when the phase 2 fixes are reverted to git HEAD. The
# two that do not, per tmp/impl/phase2.md, guard behaviour the fixes had to
# preserve:
#
#   test_the_cmp_instrumentation_flag_is_still_what_needs_it
#       The config entry is only worth having while the rungs still pass
#       trace-cmp. Removing that flag from build_kernel.sh fails this test.
#   test_a_file_in_the_root_is_still_read
#       The pre-fix scanner read files in the crash root and nothing else.
#       Descending into the harness subdirectories must not cost that, which is
#       the libFuzzer and manual-copy layout.
# ---------------------------------------------------------------------------


class TestKcovComparisonsAreConfigured(unittest.TestCase):
    """The instrumented build asks for trace-cmp instrumentation, so the
    kernel has to export the symbols it emits.

    This reads the script. Whether the config survives olddefconfig and
    whether nvidia.ko then loads are decided by the build machine, and only
    the check inside the script can observe that. What is testable offline is
    that the symbol is both requested and verified, because omitting either
    is what made the failure arrive hours later as an nvidia-smi error.
    """

    def script(self):
        with io.open(os.path.join(HERE, "build_kernel.sh"),
                     encoding="utf-8") as f:
            return f.read()

    def test_comparisons_are_enabled_alongside_kcov(self):
        s = self.script()
        self.assertIn("--enable CONFIG_KCOV_ENABLE_COMPARISONS", s)

    def test_comparisons_are_in_the_post_olddefconfig_check(self):
        # olddefconfig drops what the tree does not offer without a word.
        # A symbol that is enabled but never verified is the same silence.
        s = self.script()
        i = s.index("for sym in CONFIG_KCOV")
        j = s.index("; do", i)
        self.assertIn("CONFIG_KCOV_ENABLE_COMPARISONS", s[i:j])

    def test_the_cmp_instrumentation_flag_is_still_what_needs_it(self):
        # If the rungs stop passing trace-cmp, the config entry above is
        # dead weight and this test should be the thing that says so.
        self.assertIn("-fsanitize-coverage=trace-pc,trace-cmp", self.script())


class TestSyzReportIsIndexed(StateTempMixin, unittest.TestCase):
    """syzkaller writes report0, report1, ... and never a bare `report`.

    Reading the unsuffixed name yields '' from stack_hash for every Track K
    crash, which kills the secondary dedup key: two sightings of one panic
    cannot match on stack and land in the flagged review queue instead.
    """

    REPORT = ("BUG: KASAN: use-after-free in nv_uvm_free\n"
              "Call Trace:\n"
              " nv_uvm_free+0x12/0x34 [nvidia_uvm]\n"
              " uvm_release+0x8/0x20 [nvidia_uvm]\n"
              " __x64_sys_ioctl+0x40/0x80\n")

    def crash_dir(self, workdir, name, files):
        cdir = os.path.join(workdir, "crashes", name)
        os.makedirs(cdir, exist_ok=True)
        for fname, text in files.items():
            with open(os.path.join(cdir, fname), "w") as f:
                f.write(text)
        return cdir

    def test_report0_supplies_the_stack_hash(self):
        wd = os.path.join(self.tmp.name, "workdir")
        self.crash_dir(wd, "aaaa", {
            "description": "KASAN: use-after-free Read in nv_uvm_free",
            "report0": self.REPORT,
            "log0": "irrelevant"})
        st = ps.default_state()
        with redirect_stdout(io.StringIO()):
            crash_parse.scan_syz(st, wd)
        self.assertEqual(len(st["crashes"]), 1)
        shash = st["crashes"]["crash-0001"]["stack_hash"]
        self.assertTrue(shash, "report0 was not read: no stack hash")
        self.assertEqual(shash, crash_parse.stack_hash(self.REPORT))

    def test_lowest_index_wins(self):
        # Index 0 is the oldest sighting and the one `description` was
        # derived from, so its frames are the ones that belong with the
        # registered title.
        wd = os.path.join(self.tmp.name, "workdir")
        other = self.REPORT.replace("nv_uvm_free", "nv_other_free")
        cdir = self.crash_dir(wd, "aaaa", {
            "description": "KASAN: use-after-free Read in nv_uvm_free",
            "report1": other,
            "report0": self.REPORT})
        self.assertEqual(crash_parse.syz_report_path(cdir),
                         os.path.join(cdir, "report0"))

    def test_a_bare_report_still_resolves(self):
        wd = os.path.join(self.tmp.name, "workdir")
        cdir = self.crash_dir(wd, "aaaa", {
            "description": "KASAN: use-after-free Read in nv_uvm_free",
            "report": self.REPORT})
        self.assertEqual(crash_parse.syz_report_path(cdir),
                         os.path.join(cdir, "report"))

    def test_repro_report_is_not_mistaken_for_the_report(self):
        # repro.report is syz-repro's own output for the reproducer run, and
        # `report*` must not sweep it up as this crash's report.
        wd = os.path.join(self.tmp.name, "workdir")
        cdir = self.crash_dir(wd, "aaaa", {
            "description": "KASAN: use-after-free Read in nv_uvm_free",
            "repro.report": self.REPORT})
        self.assertIsNone(crash_parse.syz_report_path(cdir))

    def test_two_sightings_of_one_panic_dedup_instead_of_flagging(self):
        """The whole point of the secondary key. With the report unread both
        sightings carry '' and register as flagged for manual review."""
        wd = os.path.join(self.tmp.name, "workdir")
        for name in ("aaaa", "bbbb"):
            self.crash_dir(wd, name, {
                "description": "KASAN: use-after-free Read in nv_uvm_free",
                "report0": self.REPORT})
        st = ps.default_state()
        with redirect_stdout(io.StringIO()) as out:
            crash_parse.scan_syz(st, wd)
        text = out.getvalue()
        self.assertIn("DUP", text)
        self.assertNotIn("FLAG", text)
        self.assertEqual(st["crashes"]["crash-0002"]["status"], "duplicate")
        self.assertEqual(st["crashes"]["crash-0002"]["duplicate_of"],
                         "crash-0001")


class TestTrackUCrashesAreFound(StateTempMixin, unittest.TestCase):
    """run_all.sh copies crash inputs into
    artifacts/u-crashes/<harness-name>/, one level below the root
    the scanner is pointed at. Globbing one level saw only directories and
    skipped every one of them without a word.
    """

    ASAN = ("==1234==ERROR: AddressSanitizer: heap-buffer-overflow on "
            "address 0x60300000eff8\n"
            "    #0 0x4a1b2c in parse_config /src/nvc_config.c:88\n"
            "    #1 0x4a2f00 in main /src/harness.c:20\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow\n")

    def harness_crash(self, root, harness, name, text):
        d = os.path.join(root, harness)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, name), "w") as f:
            f.write(text)

    def test_a_crash_one_level_down_is_registered(self):
        root = os.path.join(self.tmp.name, "crashes")
        self.harness_crash(root, "nvc_config", "id:000000,sig:06", self.ASAN)
        st = ps.default_state()
        with redirect_stdout(io.StringIO()):
            crash_parse.scan_track_u(st, root)
        self.assertEqual(len(st["crashes"]), 1)
        c = st["crashes"]["crash-0001"]
        self.assertEqual(c["track"], "U")
        self.assertIn("AddressSanitizer", c["title"])

    def test_every_harness_subdirectory_is_scanned(self):
        root = os.path.join(self.tmp.name, "crashes")
        self.harness_crash(root, "nvc_config", "id:000000,sig:06", self.ASAN)
        self.harness_crash(root, "nvc_ldcache", "crash-deadbeef",
                           self.ASAN.replace("parse_config", "read_ldcache"))
        st = ps.default_state()
        with redirect_stdout(io.StringIO()):
            crash_parse.scan_track_u(st, root)
        self.assertEqual(len(st["crashes"]), 2)

    def test_a_file_in_the_root_is_still_read(self):
        # libFuzzer's artifact_prefix and a manual copy both land here.
        root = os.path.join(self.tmp.name, "crashes")
        os.makedirs(root, exist_ok=True)
        with open(os.path.join(root, "crash-0badcafe"), "w") as f:
            f.write(self.ASAN)
        st = ps.default_state()
        with redirect_stdout(io.StringIO()):
            crash_parse.scan_track_u(st, root)
        self.assertEqual(len(st["crashes"]), 1)

    def test_afl_readme_is_not_a_crash_and_is_not_warned_about(self):
        # AFL++ writes README.txt into its crashes dir and run_all.sh copies
        # it along with the inputs; run_all.sh excludes it from its own
        # count for the same reason.
        root = os.path.join(self.tmp.name, "crashes")
        self.harness_crash(root, "nvc_config", "README.txt",
                           "this is an AFL crashes directory\n")
        self.harness_crash(root, "nvc_config", "id:000000,sig:06", self.ASAN)
        st = ps.default_state()
        with redirect_stdout(io.StringIO()) as out:
            crash_parse.scan_track_u(st, root)
        self.assertEqual(len(st["crashes"]), 1)
        self.assertNotIn("README.txt", out.getvalue())

    def test_a_populated_directory_that_registers_nothing_says_so(self):
        root = os.path.join(self.tmp.name, "crashes")
        self.harness_crash(root, "nvc_config", "id:000000,sig:06",
                           "plain output, no sanitizer ever ran\n")
        st = ps.default_state()
        with redirect_stdout(io.StringIO()) as out:
            crash_parse.scan_track_u(st, root)
        self.assertEqual(st["crashes"], {})
        self.assertIn("not one carries a sanitizer signature",
                      out.getvalue())

    def test_an_empty_directory_says_so(self):
        root = os.path.join(self.tmp.name, "crashes")
        os.makedirs(root, exist_ok=True)
        st = ps.default_state()
        with redirect_stdout(io.StringIO()) as out:
            crash_parse.scan_track_u(st, root)
        self.assertIn("no crash input files under", out.getvalue())

    def test_a_rescan_does_not_claim_the_directory_is_empty(self):
        # register() returns None for an identical re-sighting, so counting
        # registrations would fire the warning on every harvest after the
        # first. Harvest runs after every reboot.
        root = os.path.join(self.tmp.name, "crashes")
        self.harness_crash(root, "nvc_config", "id:000000,sig:06", self.ASAN)
        st = ps.default_state()
        with redirect_stdout(io.StringIO()):
            crash_parse.scan_track_u(st, root)
        with redirect_stdout(io.StringIO()) as out:
            crash_parse.scan_track_u(st, root)
        self.assertNotIn("WARN", out.getvalue())
        self.assertEqual(len(st["crashes"]), 1)


class TestExtractProducesAReproC(unittest.TestCase):
    """`extract` has to leave a compilable repro.c behind, because
    `verify` compiles that exact path and refuses to run without it.

    The old copy list named repro.syz, repro0, report and log, none of which
    syzkaller writes, so extract copied repro.cprog and description and
    stopped: repro.c was never produced and every kernel reproducer failed
    its precondition with a message telling the operator to run extract,
    which they already had.
    """

    REPORT = ("BUG: KASAN: use-after-free in nv_uvm_free\n"
              " nv_uvm_free+0x12/0x34 [nvidia_uvm]\n")
    CPROG = "// autogenerated by syzkaller\nint main(void){return 0;}\n"
    PROG = "r0 = openat$nvidiactl(0xffffffffffffff9c, &AUTO, 0x2, 0x0)\n"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(setattr, repro_ctl, "REPO_ROOT", repro_ctl.REPO_ROOT)
        repro_ctl.REPO_ROOT = self.tmp.name
        self.src = os.path.join(self.tmp.name, "workdir", "crashes", "aaaa")
        os.makedirs(self.src)
        self.dest = os.path.join(self.tmp.name, "artifacts", "pocs",
                                 "crash-0001")

    def write(self, name, text):
        with open(os.path.join(self.src, name), "w") as f:
            f.write(text)

    def extract(self):
        with redirect_stdout(io.StringIO()) as out:
            repro_ctl._extract_k("crash-0001", {"dir": self.src})
        return out.getvalue()

    def stub_prog2c(self, marker="/* generated */\n"):
        """syz-prog2c is a built syzkaller binary and is absent offline."""
        calls = []

        def fake(syz, c_out):
            calls.append((syz, c_out))
            with open(c_out, "w") as f:
                f.write(marker)

        self.addCleanup(setattr, repro_ctl, "_generate_repro_c",
                        repro_ctl._generate_repro_c)
        repro_ctl._generate_repro_c = fake
        return calls

    def test_repro_cprog_becomes_repro_c(self):
        self.write("repro.prog", self.PROG)
        self.write("repro.cprog", self.CPROG)
        self.write("description", "KASAN: use-after-free Read in nv_uvm_free")
        self.extract()
        c_out = os.path.join(self.dest, "repro.c")
        self.assertTrue(os.path.exists(c_out), os.listdir(self.dest))
        with open(c_out) as f:
            self.assertEqual(f.read(), self.CPROG)

    def test_repro_prog_is_copied_and_translated_when_there_is_no_cprog(self):
        calls = self.stub_prog2c()
        self.write("repro.prog", self.PROG)
        self.write("description", "KASAN: use-after-free Read in nv_uvm_free")
        self.extract()
        prog_out = os.path.join(self.dest, "repro.prog")
        self.assertTrue(os.path.exists(prog_out), os.listdir(self.dest))
        self.assertEqual(calls, [(prog_out, os.path.join(self.dest,
                                                         "repro.c"))])

    def test_a_hand_placed_repro_syz_is_accepted(self):
        calls = self.stub_prog2c()
        self.write("repro.syz", self.PROG)
        self.extract()
        self.assertEqual(len(calls), 1)
        self.assertTrue(os.path.exists(os.path.join(self.dest, "repro.prog")))

    def test_the_indexed_report_lands_under_the_name_signatures_read(self):
        # crash_signature reads artifacts/pocs/<cid>/report. A file copied
        # in as report0 leaves it with no frames, and the signature silently
        # degrades to title tokens.
        self.write("repro.cprog", self.CPROG)
        self.write("report0", self.REPORT)
        self.write("log0", "console output\n")
        self.extract()
        with open(os.path.join(self.dest, "report")) as f:
            self.assertEqual(f.read(), self.REPORT)
        self.assertTrue(os.path.exists(os.path.join(self.dest, "log")))
        sig = repro_ctl.crash_signature(
            {"title": "KASAN: use-after-free Read in nv_uvm_free",
             "dir": self.src}, "crash-0001")
        self.assertIn("nv_uvm_free", sig["funcs"])

    def test_an_empty_repro_c_is_replaced_rather_than_trusted(self):
        self.write("repro.prog", self.PROG)
        self.write("repro.c", "")
        self.stub_prog2c("/* regenerated */\n")
        out = self.extract()
        self.assertIn("regenerating", out)
        with open(os.path.join(self.dest, "repro.c")) as f:
            self.assertEqual(f.read(), "/* regenerated */\n")

    def test_no_reproducer_at_all_is_reported(self):
        self.write("description", "KASAN: use-after-free Read in nv_uvm_free")
        self.write("report0", self.REPORT)
        out = self.extract()
        self.assertIn("WARN", out)
        self.assertFalse(os.path.exists(os.path.join(self.dest, "repro.c")))


# ---------------------------------------------------------------------------
# Phase 3: the version guard, tools/surface_verify.py. From
# tmp/tests/phase3-verify.py.
#
# Per tmp/impl/phase3-verify.md, three of the eleven pass under both reverts
# built there: test_two_agreeing_sources_pass,
# test_two_disagreeing_sources_fail_with_the_disagreement_code and
# test_no_running_still_counts_the_remaining_sources. They lock in behaviour
# that was already correct and had to stay correct through the inversion of the
# source-count default. test_allow_single_source_accepts_the_deliberate_case
# also passes under the source-count revert, because the old default returned 0
# on one source with or without a flag; it is the companion assertion to
# test_one_source_alone_is_not_a_verdict, and together they show that the flag,
# and only the flag, moves that path.
# ---------------------------------------------------------------------------


class TestVersionGuardSourceCount(unittest.TestCase):
    """A verdict needs two sources. One source agrees with itself.

    The guard used to return `DISAGREE if args.strict else 0` on both the
    zero-source and the one-source path, and no call site passed --strict. A
    machine where nvidia-smi was down and config/machine.yaml carried no
    driver_branch exited 0 having compared nothing, which is the silent
    mismatch the module exists to catch.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        self.surface = os.path.join(root, "surface")
        self.descriptions = os.path.join(root, "descriptions")
        self.src = os.path.join(root, "checkout")
        os.makedirs(self.surface)
        os.makedirs(self.descriptions)
        os.makedirs(self.src)
        # Point every module-level path at the temp tree, so the test never
        # reads the repository's own artefacts and never depends on whether
        # this machine has a driver loaded.
        for name, value in (
                ("MAP_PATH", os.path.join(root, "ioctl_map.json")),
                ("SURFACE_DIR", self.surface),
                ("DESCRIPTIONS_DIR", self.descriptions),
                ("MACHINE_YAML", os.path.join(root, "machine.yaml"))):
            original = getattr(surface_verify, name)
            setattr(surface_verify, name, value)
            self.addCleanup(setattr, surface_verify, name, original)
        self.set_running(None)

    def set_running(self, version):
        """Stand in for /proc/driver/nvidia/version and nvidia-smi."""
        original = surface_verify.running_version
        surface_verify.running_version = lambda: version
        self.addCleanup(setattr, surface_verify, "running_version", original)

    def write_map(self, version):
        with open(surface_verify.MAP_PATH, "w") as f:
            json.dump({surface_verify.VERSION_KEY: version,
                       "0xc020462a": "NV_ESC_RM_ALLOC"}, f)

    def write_checkout(self, version):
        with open(os.path.join(self.src, "version.mk"), "w") as f:
            f.write("NVIDIA_VERSION = %s\n" % version)

    def write_declared(self, version):
        with open(surface_verify.MACHINE_YAML, "w") as f:
            f.write("driver_branch: \"%s\"\n" % version)

    def write_generation(self, version):
        path = os.path.join(self.descriptions, "generation.json")
        with open(path, "w") as f:
            json.dump({"generated_from": {"driver_version": version}}, f)

    def check(self, *argv):
        """Run `check` against the temp tree and return (exit code, stdout)."""
        args = surface_verify.build_parser().parse_args(
            ["check", "--src", self.src] + list(argv))
        buf = io.StringIO()
        # cmd_check logs at ERROR on both failure paths. The message is part
        # of the contract, and printing it to stderr during a passing test run
        # reads as a failure, so it is suppressed here and asserted through
        # the exit code instead.
        logging.disable(logging.ERROR)
        self.addCleanup(logging.disable, logging.NOTSET)
        with redirect_stdout(buf):
            code = surface_verify.cmd_check(args)
        return code, buf.getvalue()

    # Three tests counted one source per versioned artefact file and are
    # superseded by TestVersionGuardCountsIndependentSources, which counts
    # independent source groups. The helpers above are reused by that class,
    # so this one keeps them:
    #   test_one_source_alone_is_not_a_verdict
    #       -> test_six_artefacts_agreeing_are_not_a_verdict
    #   test_allow_single_source_accepts_the_deliberate_case
    #       -> test_allow_single_source_still_accepts_the_artefact_group
    #   test_two_agreeing_sources_pass
    #       -> test_an_artefact_group_plus_a_checkout_is_two_sources

    def test_two_disagreeing_sources_fail_with_the_disagreement_code(self):
        self.write_map("610.57.04")
        self.set_running("610.62")
        code, out = self.check()
        self.assertEqual(code, surface_verify.DISAGREE)
        self.assertIn("DISAGREEMENT", out)
        self.assertIn("610.62", out)

    def test_disagreement_and_insufficiency_are_distinguishable(self):
        # An operator remedies these differently: one regenerates artefacts,
        # the other brings a second source up. One exit code cannot say which.
        self.assertNotEqual(surface_verify.DISAGREE,
                            surface_verify.INSUFFICIENT)
        self.assertNotEqual(surface_verify.INSUFFICIENT, 0)
        # argparse exits 2 on a usage error, so neither verdict may be 2.
        self.assertNotIn(2, (surface_verify.DISAGREE,
                             surface_verify.INSUFFICIENT))

    def test_no_source_at_all_fails_even_when_single_is_allowed(self):
        # --allow-single-source permits one known source. Zero sources means
        # the guard read nothing, which is a broken tree and never deliberate.
        code, out = self.check("--allow-single-source")
        self.assertEqual(code, surface_verify.INSUFFICIENT)
        self.assertIn("no version source available", out)

    def test_disagreement_outranks_the_source_count(self):
        # Two sources that disagree report the disagreement, and
        # --allow-single-source does not suppress it.
        self.write_map("610.57.04")
        self.write_declared("610.62")
        code, _ = self.check("--allow-single-source")
        self.assertEqual(code, surface_verify.DISAGREE)

    def test_no_running_still_counts_the_remaining_sources(self):
        self.write_map("610.57.04")
        self.write_checkout("610.57.04")
        self.set_running("610.62")
        code, out = self.check("--no-running")
        self.assertEqual(code, 0)
        self.assertNotIn("610.62", out)

    def test_the_strict_flag_is_gone(self):
        # No call site passed it, and a no-op flag named --strict would read
        # as protection while providing none.
        with self.assertRaises(SystemExit):
            surface_verify.build_parser().parse_args(["check", "--strict"])


class TestVersionGuardCoversDescriptions(unittest.TestCase):
    """descriptions/ is the artefact syzkaller consumes.

    The guard scanned tools/ioctl_map.json and surface/*.json only,
    so a fresh inventory paired with descriptions generated from an older
    checkout passed `check` cleanly.
    """

    def setUp(self):
        TestVersionGuardSourceCount.setUp(self)

    set_running = TestVersionGuardSourceCount.set_running
    write_map = TestVersionGuardSourceCount.write_map
    write_generation = TestVersionGuardSourceCount.write_generation
    check = TestVersionGuardSourceCount.check

    # test_the_generation_record_is_a_version_source counted the description
    # stamp as a source of its own. It is now read inside the artefact group,
    # because generation.json copies its version out of the control
    # inventory. TestVersionGuardCountsIndependentSources
    # .test_the_generation_record_is_still_scanned_as_an_artefact carries the
    # same intent against the new behaviour.

    def test_stale_descriptions_against_a_fresh_map_are_caught(self):
        self.write_map("610.62")
        self.write_generation("610.57.04")
        code, out = self.check()
        self.assertEqual(code, surface_verify.DISAGREE)
        self.assertIn("artefacts disagree with each other", out)


# ---------------------------------------------------------------------------
# Phase 3: the typed XFER variants. From tmp/tests/phase3-xfer.py.
#
# Every test here fails with the phase 3 change reverted; the 13 mutations are
# recorded in tmp/impl/phase3.md. One entry in that table is an artifact of the
# failability harness and not of this suite:
# test_the_xfer_emitter_runs_the_assertion_on_every_variant fails under M2
# because M2 replaces xfer_variant_struct, which is the function that test
# patches. It fails for the right reason under M1 and M4.
# ---------------------------------------------------------------------------


class XferFixture(unittest.TestCase):
    """A synthetic escape node in the shape ioctl_inventory.py emits.

    The real inventory is a committed artefact that a clean checkout may not
    carry, and these tests are about the emitter's rules and not about the
    driver release, so the node is built here.
    """

    HEADER = """
typedef struct
{
    NvU32 cmd;
    NvU32 size;
    NvU64 ptr;
} nv_ioctl_xfer_t;

typedef struct
{
    NvU32 hRoot;
    NvU32 hObjectParent;
} SMALL_PARAMS;

typedef struct
{
    NvU8 body[15412];
} BIG_PARAMS;

typedef struct
{
    NvU8 body[20000];
} OVERSIZE_PARAMS;
"""

    @staticmethod
    def command(name, nr, struct, size, **kwargs):
        record = {
            "name": name,
            "nr": nr,
            "param_struct": struct,
            "param_size": size,
            "is_argument_array": False,
            "node_restriction": None,
            "requires_admin": False,
            "requests": ["0x%x" % (0xc0000000 + nr)],
        }
        record.update(kwargs)
        return record

    def setUp(self):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "xfer.h")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.HEADER)
        index = syzlang_gen.TypeIndex()
        index.scan_file(path, "xfer.h")
        self.emitter = syzlang_gen.Emitter(index, {})
        self.commands = [
            self.command("NV_ESC_RM_CONTROL", 42, "SMALL_PARAMS", 8),
            self.command("NV_ESC_RM_ALLOC", 43, "SMALL_PARAMS", 8),
            self.command("NV_ESC_RM_FREE", 41, "SMALL_PARAMS", 8,
                         node_restriction="control_device_only"),
            self.command("NV_ESC_QUERY_DEVICE_INTR", 213, "SMALL_PARAMS", 8,
                         node_restriction="actual_device_only"),
            self.command("NV_ESC_WAIT_OPEN_COMPLETE", 218, "SMALL_PARAMS", 8),
            self.command("NV_ESC_CARD_INFO", 200, "SMALL_PARAMS", 8,
                         is_argument_array=True,
                         node_restriction="control_device_only"),
            self.command("NV_ESC_RM_LOCKLESS_DIAGNOSTIC", 95, "BIG_PARAMS",
                         15412, requires_admin=True,
                         node_restriction="control_device_only"),
            self.command("NV_ESC_IOCTL_XFER_CMD", 211, "nv_ioctl_xfer_t", 16),
        ]

    def inventory(self, commands=None):
        return {"nodes": [{"commands": commands or self.commands}]}

    def emit(self, commands=None):
        text, records = syzlang_gen.emit_xfer(self.emitter,
                                              self.inventory(commands))
        lines = [line for line in text.splitlines()
                 if line and not line.startswith("#")]
        return lines, records

    @staticmethod
    def field(block, name):
        for line in block.splitlines():
            parts = [p for p in line.split("\t") if p.strip()]
            if len(parts) == 2 and parts[0].strip() == name:
                return parts[1].strip()
        return None


class TestXferVariantsPinTheInnerCommand(XferFixture):
    """nv.c:2509 overwrites arg_cmd, arg_size and arg_ptr from the three
    fields of nv_ioctl_xfer_t and re-enters the same dispatch switch. A free
    cmd therefore reaches every escape and every command the two multiplexers
    dispatch, and an integer ptr resolves to an unmapped address, so the inner
    copy_from_user returns -EFAULT before any driver code runs."""

    def test_every_emitted_variant_pins_the_inner_command(self):
        _lines, records = self.emit()
        emitted = [r for r in records if r["emitted"]]
        self.assertTrue(emitted)
        for record in emitted:
            block = self.emitter.rendered[record["variant"]]
            self.assertEqual(self.field(block, "cmd"),
                             "const[%d, int32]" % record["inner_command"],
                             block)

    def test_the_pinned_command_is_the_bare_escape_number(self):
        """nv_validate_ioctl_data keys on (_cmd & 0xFF) at nv.c:2412, so the
        full _IOC request number in this field matches no table entry."""
        _lines, records = self.emit()
        by_name = {r["escape"]: r for r in records if r["emitted"]}
        block = self.emitter.rendered[by_name["NV_ESC_RM_FREE"]["variant"]]
        self.assertEqual(self.field(block, "cmd"), "const[41, int32]")

    def test_every_emitted_variant_sets_the_measured_argument_size(self):
        """nv.c:2439 compares arg_size against sizeof for a non-array escape
        and returns NV_ERR_INVALID_ARGUMENT before dispatch on any other
        value."""
        _lines, records = self.emit()
        for record in [r for r in records if r["emitted"]]:
            block = self.emitter.rendered[record["variant"]]
            self.assertEqual(self.field(block, "size"),
                             "const[%d, int32]" % record["inner_size"], block)

    def test_the_inner_pointer_is_a_pointer_and_not_an_integer(self):
        _lines, records = self.emit()
        for record in [r for r in records if r["emitted"]]:
            block = self.emitter.rendered[record["variant"]]
            self.assertTrue(self.field(block, "ptr").startswith("ptr64[inout,"),
                            block)

    def test_the_inner_pointer_names_the_escapes_own_parameter_struct(self):
        _lines, records = self.emit()
        by_name = {r["escape"]: r for r in records if r["emitted"]}
        block = self.emitter.rendered[by_name["NV_ESC_RM_FREE"]["variant"]]
        self.assertEqual(self.field(block, "ptr"),
                         "ptr64[inout, SMALL_PARAMS]")

    def test_neither_multiplexer_gets_a_wrapper(self):
        """A wrapper naming NV_ESC_RM_CONTROL or NV_ESC_RM_ALLOC would have to
        leave the inner command or class field of the parameter struct free,
        which is the hole the typed variants exist to close."""
        lines, records = self.emit()
        declined = {r["escape"]: r["reason"] for r in records
                    if not r["emitted"]}
        self.assertIn("NV_ESC_RM_CONTROL", declined)
        self.assertIn("NV_ESC_RM_ALLOC", declined)
        for line in lines:
            self.assertNotIn("_RM_CONTROL(", line)
            self.assertNotIn("_RM_ALLOC(", line)

    def test_the_wrapper_escape_itself_is_left_to_the_escape_family(self):
        """NV_ESC_IOCTL_XFER_CMD keeps its own variant name in the escape
        block, so the escape family still models all 32 of its targets."""
        _lines, records = self.emit()
        self.assertNotIn("NV_ESC_IOCTL_XFER_CMD",
                         [r["escape"] for r in records])

    def test_an_argument_over_the_absolute_maximum_is_declined(self):
        """nv.c:2513 rejects arg_size above NV_ABSOLUTE_MAX_IOCTL_SIZE before
        it validates the inner command, so a variant naming a larger struct
        would never dispatch."""
        commands = self.commands + [
            self.command("NV_ESC_TOO_BIG", 99, "OVERSIZE_PARAMS", 20000)]
        _lines, records = self.emit(commands)
        declined = {r["escape"]: r["reason"] for r in records
                    if not r["emitted"]}
        self.assertIn("NV_ESC_TOO_BIG", declined)
        self.assertIn("2513", declined["NV_ESC_TOO_BIG"])

    def test_a_large_argument_under_the_maximum_is_emitted(self):
        _lines, records = self.emit()
        emitted = [r["escape"] for r in records if r["emitted"]]
        self.assertIn("NV_ESC_RM_LOCKLESS_DIAGNOSTIC", emitted)

    def test_each_variant_takes_the_inner_escapes_own_device_node(self):
        """The node restriction is checked in the case body, after the
        unwrap, so it applies on this route exactly as it does on the direct
        one. A wrapper typed to the wrapper's own unrestricted fd would spend
        most executions on NV_CTL_DEVICE_ONLY and NV_ACTUAL_DEVICE_ONLY."""
        lines, _records = self.emit()
        by_variant = {}
        for line in lines:
            name = line.split("(")[0]
            by_variant[name] = line
        self.assertIn("fd fd_nvidiactl",
                      by_variant["ioctl$NV_ESC_IOCTL_XFER_CMD_RM_FREE"])
        self.assertIn(
            "fd fd_nvidia,",
            by_variant["ioctl$NV_ESC_IOCTL_XFER_CMD_QUERY_DEVICE_INTR"])
        self.assertIn(
            "fd fd_nv,",
            by_variant["ioctl$NV_ESC_IOCTL_XFER_CMD_WAIT_OPEN_COMPLETE"])

    def test_the_outer_request_number_is_the_wrappers_own(self):
        lines, _records = self.emit()
        for line in lines:
            self.assertIn("cmd const[0xc00000d3]", line)

    def test_one_variant_is_emitted_per_in_scope_inner_escape(self):
        lines, records = self.emit()
        self.assertEqual(len(lines), 5)
        self.assertEqual(sorted(r["escape"] for r in records if r["emitted"]),
                         ["NV_ESC_CARD_INFO", "NV_ESC_QUERY_DEVICE_INTR",
                          "NV_ESC_RM_FREE", "NV_ESC_RM_LOCKLESS_DIAGNOSTIC",
                          "NV_ESC_WAIT_OPEN_COMPLETE"])


class TestSelectorPinAssertion(XferFixture):
    """render_struct applies an override by field name, so a field renamed in
    the driver header silently drops its override and leaves the selector
    free. Nothing downstream notices: the variant name is unchanged, the size
    still matches and the description still compiles."""

    def test_a_pinned_field_passes(self):
        name = syzlang_gen.variant_struct(
            self.emitter, "SMALL_PARAMS", "pinned",
            {"hRoot": "const[0x5, int32]"})
        # variant_struct renders into the emitter and returns the variant
        # name, so the override is read back from the rendered block. Without
        # this the test asserted only that no SystemExit was raised, which a
        # body of `pass` satisfies too.
        self.assertIn("const[0x5, int32]", self.emitter.rendered[name])
        self.assertIsNone(
            syzlang_gen.require_pinned(self.emitter, "pinned", "hRoot",
                                       "a test"))

    def test_a_free_field_fails_the_build(self):
        syzlang_gen.variant_struct(self.emitter, "SMALL_PARAMS", "free", {})
        with self.assertRaises(SystemExit) as caught:
            syzlang_gen.require_pinned(self.emitter, "free", "hRoot",
                                       "a test")
        self.assertIn("hRoot", str(caught.exception))

    def test_an_override_naming_a_field_that_does_not_exist_fails(self):
        """The dropped-override case. The override dict is well formed and the
        rendered struct does not carry the pin."""
        syzlang_gen.variant_struct(
            self.emitter, "SMALL_PARAMS", "renamed",
            {"hRootRenamed": "const[0x5, int32]"})
        with self.assertRaises(SystemExit):
            syzlang_gen.require_pinned(self.emitter, "renamed", "hRoot",
                                       "a test")

    def test_a_variant_that_was_never_rendered_fails(self):
        with self.assertRaises(SystemExit):
            syzlang_gen.require_pinned(self.emitter, "absent", "hRoot",
                                       "a test")

    def test_a_field_pinned_to_something_other_than_a_constant_fails(self):
        syzlang_gen.variant_struct(
            self.emitter, "SMALL_PARAMS", "flagged",
            {"hRoot": "flags[some_set, int32]"})
        with self.assertRaises(SystemExit):
            syzlang_gen.require_pinned(self.emitter, "flagged", "hRoot",
                                       "a test")

    def test_the_xfer_emitter_runs_the_assertion_on_every_variant(self):
        """Reached by dropping the pin from the override the emitter builds,
        which is the mutation the assertion exists to catch."""
        original = syzlang_gen.xfer_variant_struct.__globals__["variant_struct"]

        def unpinned(emitter, base, name, overrides):
            stripped = dict(overrides)
            stripped.pop("cmd", None)
            return original(emitter, base, name, stripped)

        syzlang_gen.xfer_variant_struct.__globals__["variant_struct"] = unpinned
        try:
            with self.assertRaises(SystemExit) as caught:
                self.emit()
            self.assertIn("cmd", str(caught.exception))
        finally:
            syzlang_gen.xfer_variant_struct.__globals__["variant_struct"] = \
                original


class TestMeasuredSizesAreRecorded(unittest.TestCase):
    """The description set on disk was produced with a measured-size file that
    lived outside the repository, and no manifest recorded that it had been
    passed. Dropping it takes size_match from 595 to 74 and the run still
    exits 0."""

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.path = os.path.join(self.directory, "sizes.json")
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump({"A_PARAMS": 8, "B_PARAMS": 16}, fh)
        self.saved = syzlang_gen.DEFAULT_CTRL_SIZES
        syzlang_gen.DEFAULT_CTRL_SIZES = self.path

    def tearDown(self):
        syzlang_gen.DEFAULT_CTRL_SIZES = self.saved

    @staticmethod
    def args(**kwargs):
        namespace = {"ctrl_sizes": None, "no_ctrl_sizes": False}
        namespace.update(kwargs)
        return types.SimpleNamespace(**namespace)

    def test_the_committed_file_is_used_when_nothing_is_passed(self):
        self.assertEqual(syzlang_gen.resolve_ctrl_sizes(self.args()),
                         [self.path])

    def test_an_explicit_path_wins_over_the_default(self):
        self.assertEqual(
            syzlang_gen.resolve_ctrl_sizes(self.args(ctrl_sizes=["/other"])),
            ["/other"])

    def test_opting_out_is_explicit(self):
        self.assertEqual(
            syzlang_gen.resolve_ctrl_sizes(self.args(no_ctrl_sizes=True)), [])

    def test_opting_out_and_naming_a_file_contradict_each_other(self):
        with self.assertRaises(SystemExit):
            syzlang_gen.resolve_ctrl_sizes(
                self.args(ctrl_sizes=["/other"], no_ctrl_sizes=True))

    def test_a_missing_default_is_an_error_and_not_a_quieter_set(self):
        syzlang_gen.DEFAULT_CTRL_SIZES = os.path.join(self.directory, "gone")
        with self.assertRaises(SystemExit) as caught:
            syzlang_gen.resolve_ctrl_sizes(self.args())
        self.assertIn("--no-ctrl-sizes", str(caught.exception))

    def test_the_recorded_digest_is_the_digest_of_the_file_read(self):
        record = syzlang_gen.size_source_record(self.path)
        with open(self.path, "rb") as fh:
            expected = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(record["sha256"], expected)
        self.assertEqual(record["entries"], 2)

    def test_the_recorded_path_does_not_depend_on_the_host(self):
        """generation.json records the inputs a regeneration has to repeat, so
        a backslash spelling would make the record uncheckable from another
        machine."""
        record = syzlang_gen.size_source_record(self.path)
        self.assertNotIn("\\", record["path"])


# ---------------------------------------------------------------------------
# Phase 4: the three CI regression checks, tools/regression_check.py. From
# tmp/tests/phase4-ci.py.
#
# The coverage fixtures read the committed inventories under surface
# and the committed description set under descriptions, both
# un-ignored as of this phase. A checkout without them fails these tests, and
# that is the correct signal: the CI checks cannot run either.
#
# Per tmp/impl/phase4.md, no mutation makes
# test_the_denominator_reads_the_committed_inventories fail. It asserts that the
# three inventories exist and describe 610.57.04, which is a property of the
# committed artefacts and not of the tool, so no change to regression_check.py
# can move it. It names the cause when a checkout is missing the un-ignored
# files.
# ---------------------------------------------------------------------------


def _run_check(name):
    """-> (exit code, stdout) for one regression_check subcommand."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = regression_check.main([name])
    return code, buf.getvalue()


def _patched(**attrs):
    """Set regression_check module attributes, returning the old values."""
    old = {k: getattr(regression_check, k) for k in attrs}
    for k, v in attrs.items():
        setattr(regression_check, k, v)
    return old


def _restore(old):
    for k, v in old.items():
        setattr(regression_check, k, v)


# A description set with one call in each of the three groups the pin check
# reports, every selector pinned. The fixtures below edit one line of it.
PINNED_SET = """\
ioctl$NV_ESC_RM_CONTROL_fooCtrlCmdBar(fd fd_nvidiactl, cmd const[0xc020462a], arg ptr[inout, nvos54_ctrl_fooCtrlCmdBar])
ioctl$NV_ESC_RM_ALLOC_FOO_A(fd fd_nv, cmd const[0xc030462b], arg ptr[inout, nvos64_alloc_foo_a])
ioctl$NV_ESC_IOCTL_XFER_CMD_RM_FREE(fd fd_nvidiactl, cmd const[0xc01046d3], arg ptr[inout, nv_xfer_rm_free])

nvos54_ctrl_fooCtrlCmdBar {
\thClient\tnvh_nv01_root
\tcmd\tconst[0x00000102, int32]
\tstatus\tint32
} [packed]

nvos64_alloc_foo_a {
\thRoot\tnvh_nv01_root
\thClass\tconst[0xc997, int32]
\tstatus\tint32
} [packed]

nv_xfer_rm_free {
\tcmd\tconst[41, int32]
\tsize\tconst[16, int32]
} [packed]
"""


class Phase4Fixtures(unittest.TestCase):
    """Temp directories and files the three check fixtures share."""

    def tempdir(self):
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        return holder.name

    def map_file(self, mapping):
        path = os.path.join(self.tempdir(), "ioctl_map.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(mapping, f)
        return path

    def desc_dir(self, text, name="nvidia.txt"):
        directory = self.tempdir()
        with open(os.path.join(directory, name), "w", encoding="utf-8") as f:
            f.write(text)
        return directory


class TestNameClosureAgainstTheDescriptions(Phase4Fixtures):
    """regression_check names: every ioctl_map name is a declared call."""

    def _names(self, mapping):
        old = _patched(IOCTL_MAP=self.map_file(mapping))
        try:
            return _run_check("names")
        finally:
            _restore(old)

    def _a_declared_name(self):
        calls, _structs = regression_check.read_descriptions()
        self.assertTrue(calls, "the committed description set declares no call")
        return sorted(calls)[0]

    def test_a_map_naming_only_declared_calls_passes(self):
        code, out = self._names({
            "comment": "fixture",
            "0xc0000001": "ioctl$" + self._a_declared_name(),
        })
        self.assertEqual(code, 0, out)
        self.assertIn("names: OK", out)

    def test_a_map_naming_an_undeclared_call_fails_and_names_the_entry(self):
        code, out = self._names({
            "comment": "fixture",
            "0xdeadbeef": "ioctl$NV_ESC_NOT_A_REAL_CALL",
        })
        self.assertEqual(code, 1)
        self.assertIn("0xdeadbeef", out)
        self.assertIn("NV_ESC_NOT_A_REAL_CALL", out)

    def test_every_offending_request_number_is_reported_not_only_the_name(self):
        # NV_ESC_RM_ALLOC reaches the map under two request numbers, so a
        # report keyed on the name alone would hide one of them.
        code, out = self._names({
            "0xc020462b": "ioctl$NV_ESC_RM_ALLOC",
            "0xc030462b": "ioctl$NV_ESC_RM_ALLOC",
        })
        self.assertEqual(code, 1)
        self.assertIn("0xc020462b", out)
        self.assertIn("0xc030462b", out)
        self.assertIn("2 entry/entries name a call", out)

    def test_a_multiplexer_is_reported_with_the_family_its_leaves_sit_in(self):
        code, out = self._names({"0xc020462a": "ioctl$NV_ESC_RM_CONTROL"})
        self.assertEqual(code, 1)
        self.assertIn("multiplexer", out)
        self.assertIn("control", out)

    def test_comment_keys_are_not_read_as_entries(self):
        code, out = self._names({
            "comment": "ioctl$NV_ESC_NOT_A_REAL_CALL appears here in prose",
            "comment_arrays": "ioctl$NV_ESC_ALSO_NOT_REAL",
            "0xc0000001": "ioctl$" + self._a_declared_name(),
        })
        self.assertEqual(code, 0, out)

    def test_a_map_value_that_is_not_a_call_name_stops_the_check(self):
        code, _out = self._names({"0xc0000001": "NV_ESC_NO_PREFIX"})
        self.assertEqual(code, 2)

    def test_an_absent_map_stops_the_check_rather_than_passing_it(self):
        old = _patched(IOCTL_MAP=os.path.join(self.tempdir(), "absent.json"))
        try:
            code, _out = _run_check("names")
        finally:
            _restore(old)
        self.assertEqual(code, 2)


class TestSelectorPinsInTheEmittedSet(Phase4Fixtures):
    """regression_check pins: every emitted leaf selector renders const."""

    def _pins(self, text):
        old = _patched(DESC_DIR=self.desc_dir(text))
        try:
            return _run_check("pins")
        finally:
            _restore(old)

    def test_a_fully_pinned_set_passes(self):
        code, out = self._pins(PINNED_SET)
        self.assertEqual(code, 0, out)
        self.assertIn("pins: OK", out)

    def test_the_committed_set_passes(self):
        code, out = _run_check("pins")
        self.assertEqual(code, 0, out)

    def test_a_free_control_cmd_fails_and_names_the_variant(self):
        code, out = self._pins(PINNED_SET.replace(
            "\tcmd\tconst[0x00000102, int32]", "\tcmd\tint32"))
        self.assertEqual(code, 1)
        self.assertIn("NV_ESC_RM_CONTROL_fooCtrlCmdBar", out)
        self.assertIn("nvos54_ctrl_fooCtrlCmdBar", out)
        self.assertIn("cmd", out)

    def test_a_free_alloc_hclass_fails_and_names_the_variant(self):
        code, out = self._pins(PINNED_SET.replace(
            "\thClass\tconst[0xc997, int32]", "\thClass\tint32"))
        self.assertEqual(code, 1)
        self.assertIn("NV_ESC_RM_ALLOC_FOO_A", out)
        self.assertIn("hClass", out)

    def test_a_free_xfer_inner_cmd_fails(self):
        code, out = self._pins(PINNED_SET.replace(
            "\tcmd\tconst[41, int32]", "\tcmd\tint32"))
        self.assertEqual(code, 1)
        self.assertIn("NV_ESC_IOCTL_XFER_CMD_RM_FREE", out)

    def test_a_flags_selector_is_not_a_pin(self):
        # flags[...] leaves the field free over a named set, which still
        # reaches more than one leaf from one description.
        code, out = self._pins(PINNED_SET.replace(
            "\thClass\tconst[0xc997, int32]",
            "\thClass\tflags[nvos64_classes, int32]"))
        self.assertEqual(code, 1)
        self.assertIn("flags[nvos64_classes, int32]", out)

    def test_a_selector_free_by_design_passes_when_all_three_parts_match(self):
        variant, struct, field = ("NV_ESC_RM_ALLOC_OBJECT",
                                  "NVOS05_PARAMETERS", "hClass")
        self.assertIn((variant, struct, field),
                      regression_check.UNPINNED_BY_DESIGN)
        code, out = self._pins(PINNED_SET + (
            "\nioctl$%s(fd fd_nvidiactl, cmd const[0xc0144628], "
            "arg ptr[inout, %s])\n\n%s {\n\t%s\tint32\n} [packed]\n"
            % (variant, struct, struct, field)))
        self.assertEqual(code, 0, out)

    def test_the_same_free_field_under_another_struct_is_not_allowlisted(self):
        code, out = self._pins(PINNED_SET + (
            "\nioctl$NV_ESC_RM_ALLOC_OBJECT(fd fd_nvidiactl, "
            "cmd const[0xc0144628], arg ptr[inout, NVOS05_RENAMED])\n\n"
            "NVOS05_RENAMED {\n\thClass\tint32\n} [packed]\n"))
        self.assertEqual(code, 1)
        self.assertIn("NVOS05_RENAMED", out)

    def test_an_allowlisted_field_that_is_now_pinned_is_reported_as_stale(self):
        code, out = self._pins(PINNED_SET + (
            "\nioctl$NV_ESC_RM_ALLOC_OBJECT(fd fd_nvidiactl, "
            "cmd const[0xc0144628], arg ptr[inout, NVOS05_PARAMETERS])\n\n"
            "NVOS05_PARAMETERS {\n\thClass\tconst[0x5080, int32]\n} [packed]\n"))
        self.assertEqual(code, 1)
        self.assertIn("stale", out)

    def test_an_allowlist_entry_whose_call_is_absent_is_not_stale(self):
        code, out = self._pins(PINNED_SET)
        self.assertEqual(code, 0, out)
        self.assertNotIn("stale", out)

    def test_the_allowlisted_struct_under_another_variant_is_not_stale(self):
        # The entry names one call. A different call reaching the same struct
        # with the field pinned says nothing about that entry.
        code, out = self._pins(PINNED_SET + (
            "\nioctl$NV_ESC_RM_ALLOC_SOMETHING_ELSE(fd fd_nvidiactl, "
            "cmd const[0xc0144628], arg ptr[inout, NVOS05_PARAMETERS])\n\n"
            "NVOS05_PARAMETERS {\n\thClass\tconst[0x5080, int32]\n} [packed]\n"))
        self.assertEqual(code, 0, out)
        self.assertNotIn("stale", out)

    def test_a_group_that_lost_every_call_fails_rather_than_reading_clean(self):
        code, out = self._pins("\n".join(
            line for line in PINNED_SET.splitlines()
            if "NV_ESC_IOCTL_XFER_CMD_" not in line))
        self.assertEqual(code, 1)
        self.assertIn("xfer group holds no call", out)

    def test_an_empty_description_directory_stops_the_check(self):
        old = _patched(DESC_DIR=self.tempdir())
        try:
            code, _out = _run_check("pins")
        finally:
            _restore(old)
        self.assertEqual(code, 2)

    def test_the_struct_parser_reads_the_committed_set_completely(self):
        # generation.json records how many structs the emitter wrote. A parser
        # that silently dropped blocks would let a free selector through.
        with open(os.path.join(regression_check.DESC_DIR, "generation.json"),
                  encoding="utf-8") as f:
            manifest = json.load(f)
        _calls, structs = regression_check.read_descriptions()
        self.assertEqual(len(structs), manifest["counts"]["structs_emitted"])


class TestDenominatorCoverage(Phase4Fixtures):
    """regression_check coverage: a variant is declared for every target."""

    def desc_copy(self, transform=None):
        """The committed description set, optionally with one line changed."""
        directory = self.tempdir()
        for name in sorted(os.listdir(regression_check.DESC_DIR)):
            if not name.endswith(".txt"):
                continue
            with open(os.path.join(regression_check.DESC_DIR, name),
                      encoding="utf-8") as f:
                text = f.read()
            if transform:
                text = transform(text)
            with open(os.path.join(directory, name), "w",
                      encoding="utf-8") as f:
                f.write(text)
        return directory

    def _without(self, variant):
        needle = "ioctl$%s(" % variant

        def drop(text):
            return "\n".join(line for line in text.splitlines()
                             if needle not in line)

        old = _patched(DESC_DIR=self.desc_copy(drop))
        try:
            return _run_check("coverage")
        finally:
            _restore(old)

    def _first_target_in(self, family):
        targets, _excluded, _meta = surface_cov.load_targets()
        return sorted(n for n, r in targets.items()
                      if r["family"] == family)[0]

    def test_the_committed_set_covers_every_target(self):
        code, out = _run_check("coverage")
        self.assertEqual(code, 0, out)
        self.assertIn("coverage: OK", out)
        self.assertIn("764 targetable", out)

    def test_an_unmodified_copy_of_the_set_still_covers_every_target(self):
        old = _patched(DESC_DIR=self.desc_copy())
        try:
            code, out = _run_check("coverage")
        finally:
            _restore(old)
        self.assertEqual(code, 0, out)

    def test_a_target_losing_its_declaration_fails_and_is_named(self):
        victim = self._first_target_in("control")
        code, out = self._without(victim)
        self.assertEqual(code, 1)
        self.assertIn(victim, out)
        self.assertIn("763 modelled", out)

    def test_the_family_the_gap_falls_in_is_reported(self):
        victim = self._first_target_in("alloc")
        code, out = self._without(victim)
        self.assertEqual(code, 1)
        self.assertRegex(out, r"alloc\s+155\s+154\s+1")

    def test_an_empty_description_set_stops_the_check(self):
        old = _patched(DESC_DIR=self.tempdir())
        try:
            code, _out = _run_check("coverage")
        finally:
            _restore(old)
        self.assertEqual(code, 2)

    def test_the_denominator_reads_the_committed_inventories(self):
        for path in (surface_cov.IOCTL_INV, surface_cov.CTRL_INV,
                     surface_cov.OBJ_GRAPH):
            self.assertTrue(os.path.exists(path),
                            "%s is absent, so the coverage check cannot run"
                            % path)
        _targets, _excluded, meta = surface_cov.load_targets()
        self.assertEqual(meta["driver_version"], "610.57.04")


class TestTheRunnerContract(Phase4Fixtures):
    """regression_check all: the worst of the three verdicts is the verdict."""

    def test_all_runs_every_check_and_passes_when_each_one_passes(self):
        old = _patched(IOCTL_MAP=self.map_file({"comment": "fixture"}))
        try:
            code, out = _run_check("all")
        finally:
            _restore(old)
        self.assertIn("== names ==", out)
        self.assertIn("== pins ==", out)
        self.assertIn("== coverage ==", out)
        self.assertEqual(code, 0, out)

    def test_all_fails_when_one_check_fails(self):
        old = _patched(IOCTL_MAP=self.map_file(
            {"0xdeadbeef": "ioctl$NV_ESC_NOT_A_REAL_CALL"}))
        try:
            code, out = _run_check("all")
        finally:
            _restore(old)
        self.assertEqual(code, 1, out)

    def test_a_check_that_cannot_run_exits_two_and_not_one(self):
        old = _patched(DESC_DIR=self.tempdir())
        try:
            code, _out = _run_check("coverage")
        finally:
            _restore(old)
        self.assertEqual(code, 2)

    def test_every_subcommand_is_reachable_from_the_parser(self):
        parser = regression_check.build_parser()
        for name in list(regression_check.CHECKS) + ["all"]:
            self.assertEqual(parser.parse_args([name]).check, name)


# ---------------------------------------------------------------------------
# Phase 5: the control ranking and the chain grouping. From
# tmp/tests/phase5-chains.py.
#
# tmp/impl/phase5.md records one coverage gap in the failability run:
# ctrl_rank.build_records marks a named struct with no measured size as
# param_size_state "unmeasured" and scores it as zero bytes, and no test here
# asserts that. All 531 commands have a measured size on the committed inputs,
# so the branch is untaken today.
# ---------------------------------------------------------------------------


def _entry(external, internal, parents, privilege="unprivileged",
           alloc_param="RS_NONE"):
    """One RS_ENTRY row in the shape parse_entries produces."""
    return {
        "external_class": external,
        "internal_class": internal,
        "multi_instance": "NV_TRUE",
        "parents": parents,
        "alloc_param": alloc_param,
        "flags": {"unprivileged": "RS_FLAGS_ALLOC_NON_PRIVILEGED",
                  "privileged": "RS_FLAGS_ALLOC_PRIVILEGED",
                  "kernel": "RS_FLAGS_ALLOC_KERNEL_PRIVILEGED",
                  "unclassified": "RS_FLAGS_ACQUIRE_GPUS_LOCK"}[privilege],
        "access_rights": "RS_ACCESS_NONE",
    }


# Root -> Device -> Subdevice, with a privileged sibling of Subdevice and a
# class whose only external class is privileged.
FIXTURE_ENTRIES = [
    _entry("ROOT_A", "ClientRes", "RS_ROOT_OBJECT", "unclassified"),
    _entry("ROOT_B", "ClientRes", "RS_ROOT_OBJECT", "unclassified"),
    _entry("DEVICE", "DeviceRes", "RS_LIST(classId(ClientRes))"),
    _entry("SUBDEV", "SubdevRes", "RS_LIST(classId(DeviceRes))"),
    _entry("FAULTBUF", "FaultRes", "RS_LIST(classId(SubdevRes))", "privileged"),
    _entry("CHANNEL", "ChanRes", "RS_LIST(classId(DeviceRes))",
           alloc_param="RS_REQUIRED(NV_CHANNEL_ALLOC_PARAMS)"),
    # One internal class exporting a deep external class before a shallow one,
    # which is the shape 18 internal classes have in the real table.
    _entry("MULTI_DEEP", "MultiRes", "RS_LIST(classId(SubdevRes))"),
    _entry("MULTI_SHALLOW", "MultiRes", "RS_LIST(classId(ClientRes))"),
]


def _fixture_graph():
    graph, _ = object_graph.build_graph(FIXTURE_ENTRIES)
    by_ext = {e["external_class"]: e for e in FIXTURE_ENTRIES}
    return graph, by_ext


def _method(handler, owning_class, method_id, class_id="0x2080",
            param_struct="P", gsp=False):
    """One control inventory method in the shape ctrl_surface.py emits."""
    return {
        "method_id": method_id,
        "class_id": class_id,
        "sdk_prefix": "NV" + class_id[2:],
        "owning_class": owning_class,
        "handler": handler,
        "param_struct": param_struct,
        "param_size_zero": False,
        "reachability": "non_privileged",
        "routed_to_physical": gsp,
        "handler_compiled_out": False,
    }


class TestMeasuredDepthReplacesTheLadder(unittest.TestCase):
    """rank_commands orders on the object graph, not on the SDK class id.

    The ladder mapped class 0x0000 to 1, 0x0080 to 2, 0x2080 to 3 and every
    other class to 4, so 216 of the 531 commands shared one bucket and the
    order inside it was the method id.
    """

    def setUp(self):
        self.graph = {"records": [
            {"external_class": "ROOT_A", "internal_class": "ClientRes",
             "depth": 1},
            {"external_class": "DEVICE", "internal_class": "DeviceRes",
             "depth": 2},
            {"external_class": "SUBDEV", "internal_class": "SubdevRes",
             "depth": 3},
            {"external_class": "CHANNEL", "internal_class": "ChanRes",
             "depth": 3},
            {"external_class": "OBJ", "internal_class": "ObjRes",
             "depth": 4},
        ]}

    def test_a_shallow_class_the_ladder_flattened_sorts_ahead(self):
        """A 0xc637 command on a depth-2 class beat a 0x2080 command only after
        the ladder went. The ladder gave the first 4 and the second 3."""
        deep = _method("subdeviceCmd", "SubdevRes", "0x20800001", "0x2080")
        shallow = _method("deviceCmd", "DeviceRes", "0xc6370001", "0xc637")
        ranked = syzlang_gen.rank_commands([deep, shallow], self.graph, None,
                                           "reachability")
        self.assertEqual([m["handler"] for m in ranked],
                         ["deviceCmd", "subdeviceCmd"])

    def test_the_hardcoded_class_ids_carry_no_weight_of_their_own(self):
        """0x0000 was depth 1 in the ladder unconditionally. Sitting it on a
        depth-4 class must put it last."""
        planted = _method("plantedCmd", "ObjRes", "0x00000001", "0x0000")
        client = _method("clientCmd", "ClientRes", "0xffff0001", "0xffff")
        ranked = syzlang_gen.rank_commands([planted, client], self.graph, None,
                                           "reachability")
        self.assertEqual([m["handler"] for m in ranked],
                         ["clientCmd", "plantedCmd"])

    def test_depth_beats_gsp_routing_and_gsp_routing_beats_the_method_id(self):
        rows = [
            _method("deepDirect", "SubdevRes", "0x00000001"),
            _method("shallowGsp", "ClientRes", "0xffffffff", gsp=True),
            _method("shallowDirectHigh", "ClientRes", "0xfffffffe"),
            _method("shallowDirectLow", "ClientRes", "0x00000002"),
        ]
        ranked = syzlang_gen.rank_commands(rows, self.graph, None,
                                           "reachability")
        self.assertEqual([m["handler"] for m in ranked],
                         ["shallowDirectLow", "shallowDirectHigh",
                          "shallowGsp", "deepDirect"])

    def test_graph_depths_takes_the_shallowest_external_class(self):
        """DispChannelDma exports 23 external classes. The prologue cost is the
        cheapest of them and not whichever the table declares first."""
        graph = {"records": [
            {"external_class": "LATE", "internal_class": "Multi", "depth": 4},
            {"external_class": "EARLY", "internal_class": "Multi", "depth": 2},
        ]}
        self.assertEqual(syzlang_gen.graph_depths(graph), {"Multi": 2})

    def test_a_record_with_no_depth_is_not_a_zero(self):
        graph = {"records": [
            {"external_class": "X", "internal_class": "Orphan", "depth": None},
        ]}
        self.assertEqual(syzlang_gen.graph_depths(graph), {})

    def test_source_order_is_still_the_escape_hatch(self):
        rows = [_method("b", "SubdevRes", "0x2"), _method("a", "ClientRes", "0x1")]
        self.assertEqual(
            [m["handler"] for m in
             syzlang_gen.rank_commands(rows, self.graph, None, "source")],
            ["b", "a"])


class TestUnrankedCommandsStayDeterministic(unittest.TestCase):
    """15 of the 531 are owned by a class with no RS_ENTRY row.

    They cannot be dropped and they cannot be ordered on a depth that does not
    exist, so they sort last in a fixed order.
    """

    def setUp(self):
        self.graph = {"records": [
            {"external_class": "ROOT_A", "internal_class": "ClientRes",
             "depth": 1},
        ]}
        self.rows = [
            _method("memCtrlCmdGetTag", "Memory", "0x00730001"),
            _method("memCtrlCmdSetTag", "Memory", "0x00730002"),
            _method("profilerBaseCtrlCmdBindPmResources", "ProfilerBase",
                    "0x00b0c001"),
            _method("cliresCtrlCmdSystemGetCpuInfo", "ClientRes", "0xffff0000"),
        ]

    def test_a_class_with_no_graph_record_sorts_after_every_measured_depth(self):
        ranked = syzlang_gen.rank_commands(self.rows, self.graph, None,
                                           "reachability")
        self.assertEqual(ranked[0]["handler"], "cliresCtrlCmdSystemGetCpuInfo")
        self.assertEqual({m["handler"] for m in ranked[1:]},
                         {"memCtrlCmdGetTag", "memCtrlCmdSetTag",
                          "profilerBaseCtrlCmdBindPmResources"})

    def test_the_unresolved_tail_is_ordered_by_method_id(self):
        ranked = syzlang_gen.rank_commands(self.rows, self.graph, None,
                                           "reachability")
        self.assertEqual([m["handler"] for m in ranked[1:]],
                         ["memCtrlCmdGetTag", "memCtrlCmdSetTag",
                          "profilerBaseCtrlCmdBindPmResources"])

    def test_the_order_does_not_depend_on_the_input_order(self):
        forward = syzlang_gen.rank_commands(list(self.rows), self.graph, None,
                                            "reachability")
        backward = syzlang_gen.rank_commands(list(reversed(self.rows)),
                                             self.graph, None, "reachability")
        self.assertEqual([m["handler"] for m in forward],
                         [m["handler"] for m in backward])

    def test_a_ranking_file_wins_over_the_graph_depth(self):
        ranking = {"commands": [
            {"handler": "memCtrlCmdGetTag", "rank": 1},
            {"handler": "cliresCtrlCmdSystemGetCpuInfo", "rank": 2},
            {"handler": "memCtrlCmdSetTag", "rank": 3},
            {"handler": "profilerBaseCtrlCmdBindPmResources", "rank": 4},
        ]}
        ranked = syzlang_gen.rank_commands(self.rows, self.graph, ranking,
                                           "reachability")
        self.assertEqual([m["handler"] for m in ranked],
                         ["memCtrlCmdGetTag", "cliresCtrlCmdSystemGetCpuInfo",
                          "memCtrlCmdSetTag",
                          "profilerBaseCtrlCmdBindPmResources"])

    def test_a_handler_the_ranking_omits_sorts_last_and_is_reported(self):
        """A stale ranking is a warning and never a silent drop: every command
        the caller passed comes back."""
        ranking = {"commands": [{"handler": "memCtrlCmdSetTag", "rank": 1}]}
        with self.assertLogs("syzlang_gen", level="WARNING"):
            ranked = syzlang_gen.rank_commands(self.rows, self.graph, ranking,
                                               "reachability")
        self.assertEqual(len(ranked), len(self.rows))
        self.assertEqual(ranked[0]["handler"], "memCtrlCmdSetTag")


class TestChainWalkTerminates(unittest.TestCase):
    """A parent cycle must not hang the extractor.

    resource_list.h declares no cycle today. Nothing in the parser prevents
    one, and the walk runs over whatever the table says.
    """

    def test_a_two_class_cycle_reachable_from_the_root_terminates(self):
        graph = {"A": [object_graph.ROOT], "B": ["C"], "C": ["B"]}
        depth = {object_graph.ROOT: 0, "A": 1, "B": 2, "C": 3}
        self.assertIsNone(object_graph.allocatable_chain(graph, depth, "B"))

    def test_a_self_parent_terminates(self):
        graph = {"A": ["A"]}
        depth = {object_graph.ROOT: 0, "A": 1}
        self.assertIsNone(object_graph.allocatable_chain(graph, depth, "A"))

    def test_a_cycle_hanging_off_a_real_chain_still_reaches_the_root(self):
        graph = {"A": [object_graph.ROOT], "B": ["A", "C"], "C": ["B"]}
        depth = {object_graph.ROOT: 0, "A": 1, "B": 2, "C": 3}
        self.assertEqual(object_graph.allocatable_chain(graph, depth, "B"),
                         ["A", "B"])

    def test_a_class_outside_the_allocatable_depth_map_has_no_chain(self):
        graph = {"A": [object_graph.ROOT]}
        depth = {object_graph.ROOT: 0, "A": 1}
        self.assertIsNone(object_graph.allocatable_chain(graph, depth, "Z"))

    # test_the_any_parent_sentinel_ends_the_walk asserted that a class whose
    # only parent is RS_ANY_PARENT chains in one step. An RS_ANY_PARENT class
    # is allocated under a client, so the chain is the client plus the class.
    # TestAnyParentChainCostsAClient.test_the_sentinel_resolves_to_a_client
    # carries the replacement.

    def test_a_privileged_step_is_not_walked_through(self):
        """FAULTBUF is privileged, so it is absent from the allocatable depths
        and nothing chains through it."""
        graph, by_ext = _fixture_graph()
        alloc_depth = object_graph.allocatable_depths(graph, by_ext)
        self.assertNotIn("FAULTBUF", alloc_depth)
        self.assertIsNone(object_graph.allocatable_chain(graph, alloc_depth,
                                                         "FAULTBUF"))

    def test_the_cheapest_chain_is_the_shortest_over_every_external_class(self):
        graph, by_ext = _fixture_graph()
        alloc_depth = object_graph.allocatable_depths(graph, by_ext)
        target, steps = object_graph.cheapest_chain(
            FIXTURE_ENTRIES, graph, alloc_depth, "SubdevRes")
        self.assertEqual(target, "SUBDEV")
        self.assertEqual(steps, ["ROOT_A", "DEVICE", "SUBDEV"])

    def test_the_cheapest_chain_is_not_the_first_declared_chain(self):
        """MultiRes declares MULTI_DEEP first and MULTI_SHALLOW second. Taking
        the first costs 3 allocations where 2 reach the same handlers."""
        graph, by_ext = _fixture_graph()
        alloc_depth = object_graph.allocatable_depths(graph, by_ext)
        target, steps = object_graph.cheapest_chain(
            FIXTURE_ENTRIES, graph, alloc_depth, "MultiRes")
        self.assertEqual(target, "MULTI_SHALLOW")
        self.assertEqual(steps, ["ROOT_A", "MULTI_SHALLOW"])

    def test_two_root_classes_tie_break_on_the_class_name(self):
        """ClientRes exports ROOT_A and ROOT_B at the same cost, so the answer
        must not depend on dict iteration order."""
        graph, by_ext = _fixture_graph()
        alloc_depth = object_graph.allocatable_depths(graph, by_ext)
        target, steps = object_graph.cheapest_chain(
            FIXTURE_ENTRIES, graph, alloc_depth, "ClientRes")
        self.assertEqual((target, steps), ("ROOT_A", ["ROOT_A"]))

    def test_a_class_whose_every_external_class_is_privileged_has_no_chain(self):
        graph, by_ext = _fixture_graph()
        alloc_depth = object_graph.allocatable_depths(graph, by_ext)
        self.assertEqual(
            object_graph.cheapest_chain(FIXTURE_ENTRIES, graph, alloc_depth,
                                        "FaultRes"),
            (None, None))


class TestCumulativeReach(unittest.TestCase):
    """The greedy curve behind the chain-grouped program shapes.

    Each step buys the highest command count per new allocation, and a class
    whose chain is already built costs nothing.
    """

    def _records(self):
        graph, by_ext = _fixture_graph()
        alloc_depth = object_graph.allocatable_depths(graph, by_ext)
        depth = object_graph.depths(graph)
        commands = {
            "ClientRes": [{"method_id": "0x1", "handler": "clientOne"}],
            # Six commands over a three-allocation chain is a yield of 2.0,
            # against the client's 1.0, so the greedy step is unambiguous.
            "SubdevRes": [{"method_id": "0x%x" % i,
                           "handler": "subdev%d" % i} for i in range(6)],
            "DeviceRes": [{"method_id": "0x5", "handler": "deviceOne"}],
            "ChanRes": [{"method_id": "0x6", "handler": "chanOne"}],
            "FaultRes": [{"method_id": "0x7", "handler": "faultOne"}],
        }
        return object_graph.chain_records(FIXTURE_ENTRIES, graph, alloc_depth,
                                          depth, commands)

    def test_the_curve_credits_every_class_allocated_along_the_way(self):
        """Subdevice costs 3 allocations and unlocks 6 commands. The client and
        the device sit inside that chain, so their 2 commands arrive at no
        further cost and the curve reads 8 at 3 allocations."""
        curve = object_graph.cumulative_reach(self._records())
        at = {}
        for row in curve:
            at[row["allocations"]] = row["commands"]
        self.assertEqual(at[3], 8)

    def test_the_first_step_is_the_best_yield_per_allocation(self):
        curve = object_graph.cumulative_reach(self._records())
        self.assertEqual(curve[0]["class_added"], "SubdevRes")
        self.assertEqual(curve[0]["allocations"], 3)
        self.assertEqual(curve[0]["commands"], 6)

    def test_a_class_already_inside_a_built_chain_costs_nothing(self):
        curve = object_graph.cumulative_reach(self._records())
        free = [r for r in curve if r["new_allocations"] == 0]
        self.assertEqual({r["class_added"] for r in free},
                         {"ClientRes", "DeviceRes"})

    def test_the_curve_ends_at_every_reachable_command(self):
        """9 of the 10 commands. FaultRes owns the tenth and is privileged."""
        curve = object_graph.cumulative_reach(self._records())
        self.assertEqual(curve[-1]["commands"], 9)
        self.assertEqual(curve[-1]["allocations"], 4)

    def test_an_unallocatable_class_never_enters_the_curve(self):
        curve = object_graph.cumulative_reach(self._records())
        self.assertNotIn("FaultRes", {r["class_added"] for r in curve})

    def test_a_class_owning_no_command_never_enters_the_curve(self):
        recs = [r for r in self._records()]
        for rec in recs:
            if rec["internal_class"] == "ChanRes":
                rec["commands"], rec["command_count"] = [], 0
        curve = object_graph.cumulative_reach(recs)
        self.assertNotIn("ChanRes", {r["class_added"] for r in curve})

    def test_the_commands_a_chain_unlocks_are_named_on_the_record(self):
        recs = {r["internal_class"]: r for r in self._records()}
        self.assertEqual(recs["SubdevRes"]["command_count"], 6)
        self.assertEqual(recs["SubdevRes"]["chain_length"], 3)
        self.assertEqual(
            [s["external_class"] for s in recs["SubdevRes"]["chain"]],
            ["ROOT_A", "DEVICE", "SUBDEV"])

    def test_an_unallocatable_record_names_its_reason(self):
        recs = {r["internal_class"]: r for r in self._records()}
        self.assertIsNone(recs["FaultRes"]["chain"])
        self.assertIn("privilege", recs["FaultRes"]["unallocatable_reason"])

    def test_a_chain_step_naming_no_privilege_flag_is_recorded(self):
        """The three root classes carry no RS_FLAGS_ALLOC_* flag. They are
        admitted, because excluding them empties every chain, and the record
        says so rather than reading as verified-unprivileged."""
        recs = {r["internal_class"]: r for r in self._records()}
        self.assertEqual(recs["SubdevRes"]["unclassified_steps"], ["ROOT_A"])

    def test_the_alloc_param_of_each_step_travels_with_the_chain(self):
        """A program builder needs the parameter struct of every prologue step,
        not only of the class it is aiming at."""
        recs = {r["internal_class"]: r for r in self._records()}
        chan = recs["ChanRes"]["chain"][-1]
        self.assertEqual(chan["alloc_param_struct"], "NV_CHANNEL_ALLOC_PARAMS")
        self.assertEqual(chan["alloc_param_kind"], "required")


class TestControlRankScoring(unittest.TestCase):
    """ctrl_rank.py combines chain length, CVE history and parameter size."""

    def _rows(self, **over):
        base = {
            "method_id": "0x1", "handler": "h", "owning_class": "C",
            "sdk_prefix": "NV", "class_id": "0x0", "routed_to_physical": False,
            "impl_file": None, "impl_line": None, "param_struct": "P",
            "param_size": 0, "param_size_state": "measured",
            "chain_length": 1, "chain_target_class": "X",
            "no_chain_reason": None, "cve_file_releases": 0,
            "cve_function_releases": 0, "cve_function": None,
        }
        base.update(over)
        return base

    def test_a_shorter_chain_scores_higher_with_everything_else_equal(self):
        rows = [self._rows(handler="deep", method_id="0x1", chain_length=4),
                self._rows(handler="shallow", method_id="0x2", chain_length=1)]
        ordered = ctrl_rank.score_records(rows)
        self.assertEqual([r["handler"] for r in ordered], ["shallow", "deep"])

    def test_a_command_with_no_chain_ranks_last(self):
        rows = [self._rows(handler="nochain", method_id="0x1",
                           chain_length=None, cve_file_releases=18,
                           param_size=200000),
                self._rows(handler="plain", method_id="0x2", chain_length=4)]
        ordered = ctrl_rank.score_records(rows)
        self.assertEqual(ordered[-1]["handler"], "nochain")
        # Both score 0 on depth, because `plain` sits at the deepest chain in
        # the set. Reachability has to lead the key or the CVE and size
        # components carry the unreachable command past it.
        self.assertGreater(rows[0]["rank_score"], rows[1]["rank_score"])

    def test_the_size_component_is_logarithmic(self):
        """Ranking on the raw byte count puts a handful of enormous diagnostic
        structs at the top of every campaign. 229392 bytes must not be 14000
        times the weight of 16."""
        rows = [self._rows(handler="huge", method_id="0x1", param_size=229392),
                self._rows(handler="small", method_id="0x2", param_size=16)]
        ctrl_rank.score_records(rows)
        by = {r["handler"]: r["rank_components"]["size"] for r in rows}
        self.assertEqual(by["huge"], 1.0)
        self.assertGreater(by["small"], 0.2)

    def test_a_function_level_cve_match_outweighs_a_file_level_one(self):
        """The decoy sets the ceiling the two are normalised against. Without
        it both saturate at 1.0 and the comparison says nothing."""
        rows = [self._rows(handler="fileonly", method_id="0x1",
                           cve_file_releases=8),
                self._rows(handler="function", method_id="0x2",
                           cve_file_releases=8, cve_function_releases=8),
                self._rows(handler="decoy", method_id="0x3",
                           cve_file_releases=18)]
        ordered = ctrl_rank.score_records(rows)
        self.assertLess([r["handler"] for r in ordered].index("function"),
                        [r["handler"] for r in ordered].index("fileonly"))

    def test_the_components_are_kept_beside_the_score(self):
        """The weighting is a judgement, so a consumer that disagrees has to be
        able to re-sort without re-running the scan."""
        rows = [self._rows()]
        ctrl_rank.score_records(rows)
        self.assertEqual(set(rows[0]["rank_components"]),
                         {"depth", "cve", "size"})

    def test_the_rank_is_a_dense_ordinal_from_one(self):
        rows = [self._rows(handler=str(i), method_id="0x%d" % i,
                           chain_length=(i % 4) + 1) for i in range(10)]
        ordered = ctrl_rank.score_records(rows)
        self.assertEqual([r["rank"] for r in ordered], list(range(1, 11)))

    def test_two_identical_commands_keep_a_fixed_order(self):
        rows = [self._rows(handler="b", method_id="0x2"),
                self._rows(handler="a", method_id="0x1")]
        ordered = ctrl_rank.score_records(rows)
        self.assertEqual([r["handler"] for r in ordered], ["a", "b"])

    def test_the_hotspot_arrays_are_read_as_arrays(self):
        """by_file and by_function are JSON arrays. Indexing them as maps reads
        nothing and scores every command at zero CVE weight."""
        by_file, by_function = ctrl_rank.hotspot_index({"hotspots": {
            "by_file": [{"file": "a.c", "releases": 4}],
            "by_function": [{"file": "a.c", "function": "f_IMPL",
                             "releases": 3}],
        }})
        self.assertEqual(by_file, {"a.c": 4})
        self.assertEqual(by_function["f_IMPL"]["releases"], 3)

    # test_the_impl_suffix_is_what_joins_a_handler_to_a_hotspot passed
    # scan_impl_definitions a (file, line) pair. The scan now returns
    # (file, line, suffix), because 42 of the 69 CVE-cold commands carry _VF,
    # _KERNEL or _PHYSICAL where the join assumed _IMPL. The replacement is
    # TestImplScanFindsEveryDefinitionStyle
    # .test_a_resolved_handler_carries_file_line_and_suffix.

    def test_an_unlocated_handler_carries_null_provenance_and_no_cve_weight(self):
        rows = ctrl_rank.build_records(
            [_method("mysteryCmd", "SubdevRes", "0x1")],
            {}, {"src/a.c": 6}, {}, {"SubdevRes": (3, "SUBDEV", None)}, {"P": 8})
        self.assertIsNone(rows[0]["impl_file"])
        self.assertEqual(rows[0]["cve_file_releases"], 0)

    def test_an_owning_class_absent_from_the_chains_keeps_its_reason(self):
        rows = ctrl_rank.build_records(
            [_method("memCtrlCmdGetTag", "Memory", "0x1")],
            {}, {}, {}, {}, {"P": 8})
        self.assertIsNone(rows[0]["chain_length"])
        self.assertIn("RS_ENTRY", rows[0]["no_chain_reason"])


# ---------------------------------------------------------------------------
# Phase 6: the ioctl map repair and the chain-shaped seed programs. From
# tmp/tests/phase6-seeds.py.
#
# TestIoctlMapKeyFormatting below restates, on a fixture that is not a
# multiplexer, the two key-formatting invariants that TestIoctlInventoryParsing
# proved on NV_ESC_RM_CONTROL before the P0-6 repair took the multiplexer
# request numbers out of the name map. The two tests in
# TestIoctlInventoryParsing now assert the repair itself.
#
# Failability, per tmp/impl/phase6.md: all 38 tests are detected by at least one
# of 30 mutations. M26, the loader dropping its request-number normalisation, is
# detected by nothing here, because the build_map fixtures are hand-built and
# never pass through build_rm_commands and the loader's lowercasing is invisible
# to a fixture whose keys are already lowercase. M30 covers the same invariant,
# that the form convert() looks a request number up in is the form the generator
# writes, and 7 tests detect it.
# ---------------------------------------------------------------------------


class TestIoctlMapNamesResolve(unittest.TestCase):
    """Every call name tools/ioctl_map.json carries is declared somewhere.

    The map named ioctl$NV_ESC_RM_CONTROL and ioctl$NV_ESC_RM_ALLOC for two
    releases after the generator replaced both with per-command variants.
    Those two request numbers carry 686 of the 764 targets and dominate a real
    CUDA trace, so every trace-derived seed holding a control or allocation
    call named a syscall syzkaller does not know. The seeds gate could not see
    it: it reports an unmapped ratio, and those entries were mapped.
    """

    CONTROL = {
        "name": "NV_ESC_RM_CONTROL", "nr": 42, "param_struct":
        "NVOS54_PARAMETERS", "param_size": 32, "is_argument_array": False,
        "syzlang": "ioctl$NV_ESC_RM_CONTROL", "requests": ["0xc020462a"],
    }
    ALLOC = {
        "name": "NV_ESC_RM_ALLOC", "nr": 43, "param_struct":
        "NVOS64_PARAMETERS", "param_size": 48, "param_struct_alt":
        "NVOS21_PARAMETERS", "param_size_alt": 32, "is_argument_array": False,
        "syzlang": "ioctl$NV_ESC_RM_ALLOC",
        "requests": ["0xc030462b", "0xc020462b"],
    }
    FREE = {
        "name": "NV_ESC_RM_FREE", "nr": 41, "param_struct":
        "NVOS00_PARAMETERS", "param_size": 16, "is_argument_array": False,
        "syzlang": "ioctl$NV_ESC_RM_FREE", "requests": ["0xc0104629"],
    }

    def build(self, *commands):
        mapping, _skipped = ioctl_inventory.build_map(
            {"nodes": [{"commands": list(commands)}]})
        return mapping

    def test_every_committed_name_is_declared_by_a_description(self):
        names, _mux = trace2seed.load_map(trace2seed.DEFAULT_MAP)
        declared = trace2seed.declared_calls(trace2seed.DEFAULT_DESC)
        undeclared = sorted(set(names.values()) - set(declared))
        self.assertEqual(undeclared, [], undeclared)

    def test_the_committed_map_gives_no_multiplexer_a_call_name(self):
        names, mux = trace2seed.load_map(trace2seed.DEFAULT_MAP)
        self.assertEqual(sorted(mux),
                         ["0xc020462a", "0xc020462b", "0xc030462b"])
        for request in mux:
            self.assertNotIn(request, names)

    def test_a_multiplexer_is_not_written_into_the_name_map(self):
        mapping = self.build(self.CONTROL, self.FREE)
        self.assertEqual(mapping.get("0xc0104629"), "ioctl$NV_ESC_RM_FREE")
        self.assertNotIn("0xc020462a", mapping)

    def test_a_multiplexer_is_recorded_with_its_selector_field(self):
        mapping = self.build(self.CONTROL)
        record = mapping[ioctl_inventory.MAP_MULTIPLEXER_KEY]["requests"]
        self.assertEqual(record["0xc020462a"], {
            "escape": "NV_ESC_RM_CONTROL",
            "param_struct": "NVOS54_PARAMETERS",
            "selector_field": "cmd",
            "variant_prefix": "ioctl$NV_ESC_RM_CONTROL_",
        })

    def test_each_multiplexer_request_names_the_struct_its_size_came_from(self):
        record = self.build(self.ALLOC)[
            ioctl_inventory.MAP_MULTIPLEXER_KEY]["requests"]
        # 0xc030462b encodes 48 bytes and 0xc020462b encodes 32, so the pairing
        # holds whichever order build_rm_commands assembled `requests` in.
        self.assertEqual(record["0xc030462b"]["param_struct"],
                         "NVOS64_PARAMETERS")
        self.assertEqual(record["0xc020462b"]["param_struct"],
                         "NVOS21_PARAMETERS")

    def test_a_multiplexer_request_matching_no_struct_size_is_refused(self):
        bad = dict(self.CONTROL, requests=["0xc0404629"])
        with self.assertRaises(ioctl_inventory.InventoryError) as caught:
            self.build(bad)
        self.assertIn("0xc0404629", str(caught.exception))

    def test_a_multiplexer_carrying_no_param_struct_is_refused(self):
        bad = {k: v for k, v in self.CONTROL.items()
               if k not in ("param_struct", "param_size")}
        with self.assertRaises(ioctl_inventory.InventoryError) as caught:
            self.build(bad)
        self.assertIn("NV_ESC_RM_CONTROL", str(caught.exception))

    def test_the_multiplexer_section_key_is_skipped_by_both_readers(self):
        # Both tools/trace2seed.py and tools/regression_check.py iterate the
        # map's request-number entries by skipping keys prefixed "comment", so
        # a section under any other key would be read as a request number whose
        # value is not a call name.
        self.assertTrue(
            ioctl_inventory.MAP_MULTIPLEXER_KEY.startswith("comment"))
        self.assertEqual(trace2seed.MULTIPLEXER_KEY,
                         ioctl_inventory.MAP_MULTIPLEXER_KEY)
        mapping = self.build(self.CONTROL, self.FREE)
        loaded = {k.lower(): v for k, v in mapping.items()
                  if not k.startswith("comment")}
        self.assertEqual(list(loaded), ["0xc0104629"])

    def test_a_request_number_cannot_be_both_named_and_a_multiplexer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "map.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({
                    "0xc020462a": "ioctl$NV_ESC_RM_CONTROL",
                    trace2seed.MULTIPLEXER_KEY: {"requests": {
                        "0xc020462a": {"escape": "NV_ESC_RM_CONTROL",
                                       "param_struct": "NVOS54_PARAMETERS",
                                       "selector_field": "cmd",
                                       "variant_prefix": "ioctl$x_"}}},
                }, handle)
            with self.assertRaises(trace2seed.SeedError) as caught:
                trace2seed.load_map(path)
        self.assertIn("0xc020462a", str(caught.exception))


class TestTracedMultiplexerIsHonest(unittest.TestCase):
    """A traced control call becomes a comment naming what is missing.

    strace does not decode NVIDIA parameter structs, so NVOS54_PARAMETERS.cmd
    never reaches the trace text and the request number is the same for all 531
    control commands. No entry in the name map can recover the identity, and
    the previous entry asserted one that no description declares.
    """

    TRACE = (
        'openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3\n'
        'ioctl(3, 0xc0104629, 0x7ffd) = 0\n'
        'ioctl(3, 0xc020462a, 0x7ffd) = 0\n'
        'ioctl(3, 0xc030462b, 0x7ffd) = 0\n'
        'ioctl(3, 0xdeadbeef, 0x7ffd) = 0\n'
        'close(3) = 0\n'
    )
    NAMES = {"0xc0104629": "ioctl$NV_ESC_RM_FREE"}
    MUX = {
        "0xc020462a": {"escape": "NV_ESC_RM_CONTROL",
                       "param_struct": "NVOS54_PARAMETERS",
                       "selector_field": "cmd",
                       "variant_prefix": "ioctl$NV_ESC_RM_CONTROL_"},
        "0xc030462b": {"escape": "NV_ESC_RM_ALLOC",
                       "param_struct": "NVOS64_PARAMETERS",
                       "selector_field": "hClass",
                       "variant_prefix": "ioctl$NV_ESC_RM_ALLOC_"},
    }

    def prog(self):
        return trace2seed.convert(self.TRACE, self.NAMES, self.MUX)

    def call_lines(self):
        return [ln for ln in self.prog().splitlines()
                if ln and not ln.startswith("#")]

    def test_a_traced_multiplexer_emits_no_call(self):
        for line in self.call_lines():
            self.assertNotIn("ioctl$NV_ESC_RM_CONTROL(", line)
            self.assertNotIn("ioctl$NV_ESC_RM_ALLOC(", line)

    def test_the_comment_names_the_escape_the_struct_and_the_field(self):
        prog = self.prog()
        self.assertIn("# NV_ESC_RM_CONTROL on r0, request 0xc020462a: "
                      "NVOS54_PARAMETERS.cmd selects the command", prog)
        self.assertIn("# NV_ESC_RM_ALLOC on r0, request 0xc030462b: "
                      "NVOS64_PARAMETERS.hClass selects the command", prog)

    def test_a_multiplexer_is_not_reported_as_unmapped(self):
        # It is not a gap in the map. Counting it as unmapped sends the seeds
        # phase off to extend a map that cannot hold the answer.
        self.assertEqual(self.prog().count("# unmapped ioctl"), 1)
        self.assertIn("# unmapped ioctl 0xdeadbeef", self.prog())

    def test_a_multiplexer_is_not_counted_as_a_mapped_call(self):
        mapped = [ln for ln in self.call_lines() if "(r0," in ln]
        self.assertEqual(len(mapped), 1)
        self.assertTrue(mapped[0].startswith("ioctl$NV_ESC_RM_FREE(r0,"))

    def test_the_program_opens_with_one_header_naming_the_chains_route(self):
        lines = self.prog().splitlines()
        headers = [ln for ln in lines if "trace2seed.py chains" in ln]
        self.assertEqual(len(headers), 1)
        self.assertTrue(lines[0].startswith("# 2 call(s) here reached"))

    def test_a_trace_with_no_multiplexer_gets_no_header(self):
        prog = trace2seed.convert(
            'openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3\n'
            'ioctl(3, 0xc0104629, 0x0) = 0\n', self.NAMES, self.MUX)
        self.assertNotIn("dispatching escape", prog)

    def test_a_caller_passing_no_multiplexer_map_is_unaffected(self):
        # tools/selftest.py and any caller with a hand-built map calls
        # convert(text, map); the multiplexer section is an addition and not a
        # new requirement.
        prog = trace2seed.convert(self.TRACE, self.NAMES)
        self.assertEqual(prog.count("# unmapped ioctl"), 3)

    def test_the_summary_counts_multiplexer_calls_apart_from_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            trace = os.path.join(tmp, "t.txt")
            with open(trace, "w", encoding="utf-8") as handle:
                handle.write(self.TRACE)
            mapping = dict(self.NAMES)
            mapping[trace2seed.MULTIPLEXER_KEY] = {"requests": self.MUX}
            path = os.path.join(tmp, "map.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(mapping, handle)
            out = io.StringIO()
            with redirect_stdout(out):
                rc = trace2seed.main(["convert", "--trace", trace,
                                      "--out-dir", tmp, "--map", path])
        self.assertEqual(rc, 0)
        self.assertIn("1 mapped ioctls, 1 unmapped, 2 multiplexer calls",
                      out.getvalue())


class TestChainShapedProgramBuildsItsPrologueOnce(unittest.TestCase):
    """One prologue, many commands.

    A trace supplies a real object chain and a real fd lifecycle and cannot
    supply control commands; the ranked command list supplies those and knows
    no chain. A chain-shaped program joins the two. rm-chains.json records that
    three allocations reach 315 of the 531 control commands and four reach 337,
    which only pays off if the three allocations are written once.
    """

    STEPS = {
        "NV01_ROOT": {"external_class": "NV01_ROOT",
                      "alloc_param_struct": "NvHandle",
                      "alloc_param_kind": "optional",
                      "alloc_privilege": "unclassified"},
        "NV01_DEVICE_0": {"external_class": "NV01_DEVICE_0",
                          "alloc_param_struct": "NV0080_ALLOC_PARAMETERS",
                          "alloc_param_kind": "optional",
                          "alloc_privilege": "unprivileged"},
        "NV20_SUBDEVICE_0": {"external_class": "NV20_SUBDEVICE_0",
                             "alloc_param_struct": "NV2080_ALLOC_PARAMETERS",
                             "alloc_param_kind": "optional",
                             "alloc_privilege": "unprivileged"},
        "NV30_GSYNC": {"external_class": "NV30_GSYNC",
                       "alloc_param_struct": "NvHandle",
                       "alloc_param_kind": "optional",
                       "alloc_privilege": "unprivileged"},
        "NV01_TIMER": {"external_class": "NV01_TIMER",
                       "alloc_param_struct": "NvHandle",
                       "alloc_param_kind": "optional",
                       "alloc_privilege": "unprivileged"},
    }

    @classmethod
    def record(cls, internal, path, handlers, reason=None):
        return {
            "internal_class": internal,
            "target_external_class": path[-1] if path else None,
            "chain": [cls.STEPS[name] for name in path],
            "chain_length": len(path),
            "commands": [{"handler": h, "method_id": "0x0"} for h in handlers],
            "command_count": len(handlers),
            "unallocatable_reason": reason,
            "unclassified_steps": [],
        }

    def chains(self):
        return {
            "schema": "gspwn.rm-chains/1",
            "chains": [
                self.record("RmClientResource", ("NV01_ROOT",), ["cliresA"]),
                self.record("Device", ("NV01_ROOT", "NV01_DEVICE_0"),
                            ["devB"]),
                self.record("Subdevice",
                            ("NV01_ROOT", "NV01_DEVICE_0",
                             "NV20_SUBDEVICE_0"),
                            ["subC", "subD", "subE"]),
                self.record("GsyncApi", ("NV01_ROOT", "NV30_GSYNC"),
                            ["gsyncF"]),
                self.record("MmuFaultBuffer", (), ["faultG"],
                            reason="every external class requires allocation "
                                   "privilege"),
            ],
            "unresolved_owning_classes": [
                {"owning_class": "MmuFaultBuffer", "command_count": 1,
                 "reason": "every external class requires allocation privilege",
                 "commands": ["faultG"]},
            ],
        }

    RANKS = {"cliresA": 1, "devB": 2, "subC": 3, "subD": 4, "subE": 5,
             "gsyncF": 6}

    def declared(self):
        out = {}
        for name in self.STEPS:
            out[trace2seed.ALLOC_PREFIX + name] = ("fd_nv", "0xc030462b")
        for handler in self.RANKS:
            out[trace2seed.CONTROL_PREFIX + handler] = ("fd_nvidiactl",
                                                        "0xc020462a")
        return out

    def build(self, max_calls=40, declared=None, chains=None):
        return trace2seed.build_chain_programs(
            chains or self.chains(), self.RANKS,
            self.declared() if declared is None else declared, max_calls)

    def text_for(self, programs, needle):
        return [text for name, text in programs if needle in name][0]

    def test_the_deepest_chain_carries_every_shorter_one(self):
        # Subdevice's three allocations also build RmClientResource's and
        # Device's objects, so their commands need no second prologue.
        programs, report = self.build()
        text = self.text_for(programs, "nv20_subdevice_0")
        for handler in ("cliresA", "devB", "subC", "subD", "subE"):
            self.assertIn(trace2seed.CONTROL_PREFIX + handler + "(r0,", text)
        self.assertEqual(report["prologues"], 2)

    def test_the_prologue_is_written_once_per_program(self):
        text = self.text_for(self.build()[0], "nv20_subdevice_0")
        for step in ("NV01_ROOT", "NV01_DEVICE_0", "NV20_SUBDEVICE_0"):
            self.assertEqual(
                text.count(trace2seed.ALLOC_PREFIX + step + "(r0,"), 1, step)
        self.assertEqual(text.count("openat$nvidiactl("), 1)

    def test_a_shorter_prologue_is_not_emitted_again_for_its_own_commands(self):
        programs, _report = self.build()
        names = sorted(name for name, _t in programs)
        self.assertNotIn("chain-nv01_root-00.syz", names)
        self.assertNotIn("chain-nv01_device_0-00.syz", names)

    def test_a_chain_off_the_covered_path_gets_its_own_prologue(self):
        # NV30_GSYNC hangs off NV01_ROOT and is not on Subdevice's path, so it
        # cannot ride the same allocation set.
        text = self.text_for(self.build()[0], "nv30_gsync")
        self.assertIn(trace2seed.ALLOC_PREFIX + "NV01_ROOT(r0,", text)
        self.assertIn(trace2seed.ALLOC_PREFIX + "NV30_GSYNC(r0,", text)
        self.assertIn(trace2seed.CONTROL_PREFIX + "gsyncF(r0,", text)

    def test_every_chained_command_reaches_exactly_one_program(self):
        programs, report = self.build()
        emitted = []
        for _name, text in programs:
            emitted.extend(ln.split("(")[0][len(trace2seed.CONTROL_PREFIX):]
                           for ln in text.splitlines()
                           if ln.startswith(trace2seed.CONTROL_PREFIX))
        self.assertEqual(sorted(emitted),
                         ["cliresA", "devB", "gsyncF", "subC", "subD", "subE"])
        self.assertEqual(report["commands"], 6)

    def test_the_commands_are_ordered_by_rank(self):
        text = self.text_for(self.build()[0], "nv20_subdevice_0")
        order = [ln.split("(")[0][len(trace2seed.CONTROL_PREFIX):]
                 for ln in text.splitlines()
                 if ln.startswith(trace2seed.CONTROL_PREFIX)]
        self.assertEqual(order, ["cliresA", "devB", "subC", "subD", "subE"])

    def test_an_unranked_command_sorts_after_every_ranked_one(self):
        programs = trace2seed.build_chain_programs(
            self.chains(), {"subE": 1}, self.declared(), 40)[0]
        text = self.text_for(programs, "nv20_subdevice_0")
        order = [ln.split("(")[0][len(trace2seed.CONTROL_PREFIX):]
                 for ln in text.splitlines()
                 if ln.startswith(trace2seed.CONTROL_PREFIX)]
        self.assertEqual(order[0], "subE")

    def test_a_long_command_list_splits_and_repeats_the_prologue(self):
        # room = max_calls - 1 openat - 3 allocations = 2 commands per program.
        programs, report = self.build(max_calls=6)
        parts = [text for name, text in programs if "nv20_subdevice_0" in name]
        self.assertEqual(len(parts), 3)
        for text in parts:
            self.assertEqual(
                text.count(trace2seed.ALLOC_PREFIX + "NV01_ROOT(r0,"), 1)
        emitted = [ln for text in parts for ln in text.splitlines()
                   if ln.startswith(trace2seed.CONTROL_PREFIX)]
        self.assertEqual(len(emitted), len(set(emitted)))
        self.assertEqual(report["programs"], len(programs))

    def test_no_program_exceeds_the_call_limit(self):
        for _name, text in self.build(max_calls=6)[0]:
            calls = [ln for ln in text.splitlines()
                     if ln and not ln.startswith("#")]
            self.assertLessEqual(len(calls), 6, text)

    def test_a_prologue_that_cannot_fit_emits_nothing_and_is_reported(self):
        programs, report = self.build(max_calls=3)
        self.assertEqual([p for p in report["oversize"] if len(p[0]) == 3],
                         [(("NV01_ROOT", "NV01_DEVICE_0", "NV20_SUBDEVICE_0"),
                           3)])
        self.assertNotIn("nv20_subdevice_0",
                         " ".join(name for name, _t in programs))
        # The shorter chains still build: the deepest one is dropped before the
        # grouping, so it does not take their commands with it.
        self.assertIn("cliresA", " ".join(t for _n, t in programs))

    def test_an_undeclared_allocation_drops_only_its_own_chain(self):
        declared = {k: v for k, v in self.declared().items()
                    if k != trace2seed.ALLOC_PREFIX + "NV20_SUBDEVICE_0"}
        programs, report = self.build(declared=declared)
        joined = " ".join(text for _name, text in programs)
        self.assertNotIn("subC", joined)
        self.assertIn("cliresA", joined)
        self.assertIn("devB", joined)
        self.assertEqual(
            report["undeclared"][trace2seed.ALLOC_PREFIX + "NV20_SUBDEVICE_0"],
            3)

    def test_an_undeclared_control_variant_is_dropped_and_counted(self):
        declared = {k: v for k, v in self.declared().items()
                    if k != trace2seed.CONTROL_PREFIX + "subD"}
        programs, report = self.build(declared=declared)
        joined = " ".join(text for _name, text in programs)
        self.assertNotIn("subD", joined)
        self.assertIn("subC", joined)
        self.assertEqual(report["undeclared"],
                         {trace2seed.CONTROL_PREFIX + "subD": 1})

    def test_the_request_numbers_come_from_the_description_set(self):
        # Not hardcoded here: a driver bump moves every struct size and with it
        # every request number, and a seed carrying the old one dispatches to
        # nothing.
        declared = self.declared()
        declared[trace2seed.CONTROL_PREFIX + "subC"] = ("fd_nvidiactl",
                                                        "0xc0ff462a")
        text = self.text_for(self.build(declared=declared)[0],
                             "nv20_subdevice_0")
        self.assertIn(trace2seed.CONTROL_PREFIX + "subC(r0, 0xc0ff462a,", text)

    def test_a_class_with_no_chain_is_accounted_for_and_not_emitted(self):
        programs, report = self.build()
        self.assertNotIn("faultG", " ".join(t for _n, t in programs))
        self.assertEqual(report["unreached"],
                         [("MmuFaultBuffer",
                           "every external class requires allocation "
                           "privilege", 1)])

    def test_the_unreached_account_reads_the_artefact_not_the_records(self):
        # A class with no RS_ENTRY row owns commands that appear under no
        # internal-class record at all, so scanning the records alone loses
        # them silently.
        doc = self.chains()
        doc["unresolved_owning_classes"].append(
            {"owning_class": "Memory", "command_count": 6,
             "reason": "no RS_ENTRY row for this class", "commands": []})
        _programs, report = self.build(chains=doc)
        self.assertEqual(sum(c for _o, _r, c in report["unreached"]), 7)

    def test_the_greedy_pick_weighs_commands_against_allocations(self):
        # Device owns four commands behind two allocations and Subdevice owns
        # one behind three. Taking the largest command set first would put all
        # five behind the three-allocation prologue; the yield per allocation
        # buys the cheaper prologue first, so four of the five need two
        # allocations rather than three.
        doc = {
            "schema": "gspwn.rm-chains/1",
            "chains": [
                self.record("Device", ("NV01_ROOT", "NV01_DEVICE_0"),
                            ["devB", "devH", "devI", "devJ"]),
                self.record("Subdevice",
                            ("NV01_ROOT", "NV01_DEVICE_0",
                             "NV20_SUBDEVICE_0"), ["subC"]),
            ],
            "unresolved_owning_classes": [],
        }
        declared = self.declared()
        for handler in ("devH", "devI", "devJ"):
            declared[trace2seed.CONTROL_PREFIX + handler] = ("fd_nvidiactl",
                                                             "0xc020462a")
        programs, report = trace2seed.build_chain_programs(
            doc, {}, declared, 40)
        self.assertEqual(report["prologues"], 2)
        shallow = self.text_for(programs, "nv01_device_0")
        self.assertNotIn("NV20_SUBDEVICE_0", shallow)
        for handler in ("devB", "devH", "devI", "devJ"):
            self.assertIn(trace2seed.CONTROL_PREFIX + handler + "(r0,",
                          shallow)

    def test_the_grouping_does_not_depend_on_the_record_order(self):
        # Two siblings of the same length owning the same number of commands
        # score identically, so without an ordering the record order decides
        # which prologue is written first and the seed bank changes shape from
        # one regeneration to the next.
        doc = {
            "schema": "gspwn.rm-chains/1",
            "chains": [
                self.record("GsyncApi", ("NV01_ROOT", "NV30_GSYNC"),
                            ["gsyncF"]),
                self.record("TimerApi", ("NV01_ROOT", "NV01_TIMER"),
                            ["timerK"]),
            ],
            "unresolved_owning_classes": [],
        }
        declared = self.declared()
        declared[trace2seed.CONTROL_PREFIX + "timerK"] = ("fd_nvidiactl",
                                                          "0xc020462a")
        forward = trace2seed.build_chain_programs(doc, {}, declared, 40)[0]
        doc["chains"].reverse()
        reverse = trace2seed.build_chain_programs(doc, {}, declared, 40)[0]
        self.assertEqual(forward, reverse)
        self.assertEqual([name for name, _t in forward],
                         ["chain-nv01_timer-00.syz", "chain-nv30_gsync-00.syz"])

    def test_a_chain_artefact_of_the_wrong_shape_is_refused_by_name(self):
        with self.assertRaises(trace2seed.SeedError) as caught:
            self.build(chains={"records": []})
        self.assertIn("object_graph.py chains", str(caught.exception))

    def test_the_committed_artefacts_account_for_every_control_target(self):
        chains = trace2seed.load_json(trace2seed.DEFAULT_CHAINS, "chains")
        declared = trace2seed.declared_calls(trace2seed.DEFAULT_DESC)
        rank = trace2seed.load_json(trace2seed.DEFAULT_RANK, "rank")
        ranks = {c["handler"]: c["rank"] for c in rank["commands"]}
        _programs, report = trace2seed.build_chain_programs(
            chains, ranks, declared)
        accounted = report["commands"] + sum(c for _o, _r, c
                                             in report["unreached"])
        self.assertEqual(report["undeclared"], {})
        self.assertEqual(accounted, chains["counts"]["targetable_commands"])


class TestIoctlMapKeyFormatting(unittest.TestCase):
    """Replaces the two TestIoctlInventoryParsing tests that used
    NV_ESC_RM_CONTROL as an incidental fixture. Both are about how a map key is
    written and read back, and neither is about the multiplexer, so the fixture
    moves to an escape that still carries a call name."""

    FREE = {"name": "NV_ESC_RM_FREE", "nr": 41,
            "param_struct": "NVOS00_PARAMETERS", "param_size": 16,
            "is_argument_array": False, "syzlang": "ioctl$NV_ESC_RM_FREE",
            "requests": ["0xc0104629"]}

    def test_version_stamp_is_never_read_as_a_request_number(self):
        # The stamp shares tools/ioctl_map.json with the request numbers, so a
        # key that trace2seed did not drop would be looked up as an ioctl.
        mapping, _ = ioctl_inventory.build_map(
            {"nodes": [{"commands": [self.FREE]}]}, "610.57.04 (commit dead)")
        self.assertEqual(mapping[ioctl_inventory.MAP_VERSION_KEY],
                         "610.57.04 (commit dead)")
        self.assertTrue(
            ioctl_inventory.MAP_VERSION_KEY.startswith("comment"))
        loaded = {k.lower(): v for k, v in mapping.items()
                  if not k.startswith("comment")}
        self.assertEqual(list(loaded), ["0xc0104629"])

    def test_map_keys_are_what_trace2seed_looks_up(self):
        mapping, _ = ioctl_inventory.build_map(
            {"nodes": [{"commands": [self.FREE]}]})
        loaded = {k.lower(): v for k, v in mapping.items()
                  if not k.startswith("comment")}
        prog = trace2seed.convert(
            'openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3\n'
            'ioctl(3, 0xc0104629, 0x7ffd) = 0\n', loaded)
        self.assertIn("ioctl$NV_ESC_RM_FREE(r0, 0xc0104629", prog)


# ---------------------------------------------------------------------------
# Phase 7: the two-curve stop rule, the completion ledger and the round cap.
# From tmp/tests/phase7-stoprule.py.
#
# All 34 fail against HEAD copies of the four tools, per tmp/impl/phase7.md.
# Two initially passed both ways and were strengthened until they
# discriminated: test_an_incomplete_surface_is_not_a_stop calls
# surface_stop_reason directly, and
# test_the_budget_still_outranks_a_growing_curve also asserts that a complete
# surface reports completion and not the ceiling it also reached.
# ---------------------------------------------------------------------------


class TestSurfaceCurve(unittest.TestCase):
    """The second curve. A flat edge curve is not by itself a plateau."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._orig = coverage_ctl.RUNS_DIR
        coverage_ctl.RUNS_DIR = self.tmp.name
        self.addCleanup(lambda: setattr(coverage_ctl, "RUNS_DIR", self._orig))

    def write_csv(self, run_id, points):
        """points: [(ts_offset_min, edges, surface)]"""
        d = os.path.join(self.tmp.name, run_id)
        os.makedirs(d, exist_ok=True)
        base = 1_700_000_000
        with open(os.path.join(d, "coverage.csv"), "w") as f:
            f.write(",".join(coverage_ctl.FIELDS) + "\n")
            for off, edges, surface in points:
                f.write(csv_line(base + off * 60, edges,
                                 surface=surface) + "\n")

    def verdict(self, points, window=240, growth=0.02):
        """-> (verdict, detail) with the second curve supplied."""
        self.write_csv("r1", points)
        return coverage_ctl.plateau_verdict(
            coverage_ctl.metric_rows("r1"), window, growth,
            surface=coverage_ctl.surface_growth(coverage_ctl.read_rows("r1")))

    def test_flat_edges_with_a_climbing_surface_is_not_a_plateau(self):
        # The reading this whole column exists for: a command whose handler
        # rejects the call early adds a target and almost no edges, so the
        # edge curve can flatten while the round is still reaching commands
        # it had never reached.
        points = [(i * 60, 5000 + i, 100 + i * 20) for i in range(8)]
        self.write_csv("r1", points)
        verdict, detail = coverage_ctl.plateau_verdict(
            coverage_ctl.metric_rows("r1"), 240, 0.02,
            surface=coverage_ctl.surface_growth(coverage_ctl.read_rows("r1")))
        self.assertEqual(verdict, "growing")
        self.assertIn("surface curve is not", detail)
        # Without the second curve the same run reads as a plateau, which is
        # the verdict this change exists to correct.
        self.assertEqual(coverage_ctl.plateau_verdict(
            coverage_ctl.metric_rows("r1"), 240, 0.02)[0], "plateaued")

    def test_both_curves_flat_stays_a_plateau(self):
        points = [(i * 60, 5000 + i, 640) for i in range(8)]
        self.assertEqual(self.verdict(points)[0], "plateaued")

    def test_a_plateau_detail_names_the_surface_reading(self):
        points = [(i * 60, 5000 + i, 640) for i in range(8)]
        self.write_csv("r1", points)
        _v, detail = coverage_ctl.plateau_verdict(
            coverage_ctl.metric_rows("r1"), 240, 0.02,
            surface=coverage_ctl.surface_growth(coverage_ctl.read_rows("r1")))
        self.assertIn("Surface curve: flat", detail)

    def test_too_few_surface_samples_leave_the_edge_verdict_alone(self):
        # Absence of a second curve must not rescue a plateau: a run sampled
        # before the column existed would otherwise never stop.
        points = [(i * 60, 5000 + i, None) for i in range(8)]
        self.assertEqual(self.verdict(points)[0], "plateaued")
        state, why = coverage_ctl.surface_growth(coverage_ctl.read_rows("r1"))
        self.assertEqual(state, "unknown")
        self.assertIn("need >=", why)

    def test_a_corpus_minimisation_dip_does_not_read_as_a_falling_surface(self):
        # syzkaller minimises its corpus, so the unpacked count can genuinely
        # drop. The running maximum makes that contribute nothing rather than
        # reading as a shrinking surface.
        points = [(i * 60, 5000 + i, s)
                  for i, s in enumerate([300, 300, 300, 300, 300, 120])]
        self.write_csv("r1", points)
        state, _why = coverage_ctl.surface_growth(
            coverage_ctl.read_rows("r1"))
        self.assertEqual(state, "flat")

    def test_track_u_is_never_asked_for_a_surface_sample(self):
        # Track U produces no syzlang programs, so a 0 there would put an
        # absence of evidence into the curve as a measurement.
        due, why = coverage_ctl.surface_due(
            "r1", "u", coverage_ctl.csv_path("r1", "u"))
        self.assertFalse(due)
        self.assertIn("no syzlang programs", why)

    def test_the_surface_cadence_is_read_from_the_csv_itself(self):
        self.write_csv("r1", [(0, 10, 100)])
        path = coverage_ctl.csv_path("r1")
        # The recorded sample is from 1_700_000_000, decades ago, so any
        # interval is satisfied and the next sample is due.
        due, _why = coverage_ctl.surface_due("r1", "k", path, interval_min=60)
        self.assertTrue(due)
        # A sample taken now is inside the interval and the next one is not.
        with open(path, "a") as f:
            f.write(csv_line(int(time.time()), 11, surface=101) + "\n")
        due, why = coverage_ctl.surface_due("r1", "k", path, interval_min=60)
        self.assertFalse(due)
        self.assertIn("surface interval", why)


class TestSurfaceTargetKeys(unittest.TestCase):
    """The ledger's identity. The variant name cannot be it."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.targets, _excluded, cls.meta = surface_cov.load_targets()
        except surface_cov.SurfaceError as exc:
            raise unittest.SkipTest("inventories not generated: %s" % exc)

    def test_every_target_has_a_distinct_key(self):
        keys = [t["abi_key"] for t in self.targets.values()]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(len(keys), 764)

    def test_the_composite_holds_531_distinct_control_targets(self):
        control = [t for t in self.targets.values()
                   if t["family"] == "control"]
        composite = {(t["class_id"], t["method_id"], t["owning_class"])
                     for t in control}
        self.assertEqual(len(control), 531)
        self.assertEqual(len(composite), 531)

    def test_sdk_prefix_and_method_id_alone_would_merge_ten_commands(self):
        # The evidence for including owning_class: five NV0090 commands are
        # each exported by three owning classes, and those are three different
        # allocation chains reaching one ABI command.
        control = [t for t in self.targets.values()
                   if t["family"] == "control"]
        pairs = {(t["sdk_prefix"], t["method_id"]) for t in control}
        self.assertEqual(len(pairs), 521)
        self.assertLess(len(pairs), len(control))

    def test_alloc_targets_with_no_numeric_identity_still_key_uniquely(self):
        alloc = [t for t in self.targets.values() if t["family"] == "alloc"]
        without = [t for t in alloc if t["class_id"] is None]
        recovered = [t for t in alloc if t["class_id"]]
        self.assertEqual(len(alloc), 155)
        self.assertEqual(len(without), 93)
        self.assertEqual(len(recovered), 62)
        self.assertEqual(len({t["abi_key"] for t in without}), 93)

    def test_a_recovered_alloc_class_id_comes_from_the_control_inventory(self):
        root = self.targets["NV_ESC_RM_ALLOC_NV01_ROOT"]
        self.assertEqual(root["internal_class"], "RmClientResource")
        self.assertEqual(root["class_id"], "0x0000")

    def test_a_control_key_survives_a_handler_rename(self):
        # The failure the composite exists to prevent: a driver refactor
        # renames the C handler, the variant changes with it, and a ledger
        # keyed on the variant loses the row while the file still looks full.
        before = self.targets["NV_ESC_RM_CONTROL_cliresCtrlCmdSystemGetCpuInfo"]
        renamed = dict(before, variant="NV_ESC_RM_CONTROL_cliresCtrlCmdCpuInfo")
        self.assertNotEqual(renamed["variant"], before["variant"])
        self.assertEqual(surface_cov.abi_key(renamed), before["abi_key"])


class TestCompletionLedger(StateTempMixin, unittest.TestCase):
    """Every unreached target carries a written reason, recorded once."""

    def setUp(self):
        super().setUp()
        self.ledger = os.path.join(self.tmp.name, "completion-ledger.json")

    def account(self, **record):
        base = {"key": "control/0x0000/0x00000102/RmClientResource",
                "variant": "NV_ESC_RM_CONTROL_cliresCtrlCmdSystemGetCpuInfo",
                "family": "control", "reason": "deliberately-deferred",
                "detail": "left for a later campaign"}
        base.update(record)
        return ps.set_surface_account(base, path=self.ledger,
                                      driver_version="610.57.04",
                                      targets_total=764)

    def test_reaccounting_updates_the_row_and_keeps_the_first_timestamp(self):
        first = self.account()
        again = self.account(reason="needs-privilege",
                             detail="the handler checks a capability",
                             evidence=["src/nvidia/x.c:12"])
        ledger = ps.load_surface_ledger(self.ledger)
        self.assertEqual(len(ledger["accounted"]), 1)
        self.assertEqual(again["reason"], "needs-privilege")
        self.assertEqual(again["first_recorded"], first["first_recorded"])

    def test_a_free_text_reason_is_refused(self):
        with self.assertRaises(ValueError) as cm:
            self.account(reason="not reached yet")
        self.assertIn("closed vocabulary", str(cm.exception))
        self.assertEqual(ps.load_surface_ledger(self.ledger)["accounted"], {})

    def test_a_category_with_no_written_detail_is_refused(self):
        with self.assertRaises(ValueError) as cm:
            self.account(detail="")
        self.assertIn("needs a detail", str(cm.exception))

    def test_a_claim_about_driver_source_needs_a_file_line(self):
        for reason in ps.SURFACE_REASON_NEEDS_EVIDENCE:
            with self.assertRaises(ValueError) as cm:
                self.account(reason=reason, detail="stated without evidence")
            self.assertIn("file:line", str(cm.exception))
        self.account(reason="needs-privilege", detail="capability check",
                     evidence=["src/nvidia/src/kernel/rmapi/x.c:1204"])
        self.assertEqual(len(ps.load_surface_ledger(self.ledger)["accounted"]),
                         1)

    def test_an_unknown_field_is_refused_rather_than_dropped(self):
        with self.assertRaises(ValueError) as cm:
            self.account(reasons="deliberately-deferred")
        self.assertIn("unknown accounting field", str(cm.exception))

    def test_a_ledger_for_another_driver_release_is_refused(self):
        self.account()
        with self.assertRaises(ps.SurfaceLedgerMismatch) as cm:
            ps.load_surface_ledger(self.ledger, driver_version="615.00.00")
        self.assertIn("the accounted rows cannot be counted", str(cm.exception))

    def test_completion_is_a_union_and_not_a_sum(self):
        # A target exercised in a later round after an earlier one wrote a
        # reason for it. Adding the two counts closes a ledger with a target
        # still open, which is the one way this rule can stop a campaign that
        # is not finished.
        verdict, counts, closed = ps.surface_completion(
            {"a", "b"}, {"b", "c"}, 4)
        self.assertEqual(verdict, "incomplete")
        self.assertEqual(counts["closed"], 3)
        self.assertEqual(counts["exercised"] + counts["accounted"], 4)
        self.assertEqual(closed, {"a", "b", "c"})

    def test_completion_closes_when_the_union_reaches_the_denominator(self):
        verdict, counts, _closed = ps.surface_completion(
            {"a", "b"}, {"c", "d"}, 4)
        self.assertEqual(verdict, "complete")
        self.assertEqual(counts["closed"], 4)

    def test_an_unmeasured_corpus_is_unknown_and_never_complete(self):
        verdict, counts, closed = ps.surface_completion(None, {"a"}, 764)
        self.assertEqual(verdict, "unknown")
        self.assertIsNone(counts["exercised"])
        self.assertIsNone(closed)


class TestStopRule(StateTempMixin, unittest.TestCase):
    """Completion is primary and hard; the round cap is a distant backstop."""

    def state(self, **round_fields):
        st = ps.default_state()
        ps.current_round(st).update(round_fields)
        return st

    def test_completion_is_a_hard_non_overridable_stop(self):
        st = self.state(surface_verdict="complete", surface_exercised=700,
                        surface_accounted=64, surface_closed=764,
                        surface_total=764, surface_ledger="artifacts/x.json",
                        coverage_verdict="growing")
        hard = ps.hard_cap_reason(st, max_rounds=10)
        self.assertIsNotNone(hard)
        self.assertIn("command surface complete", hard)
        decision, reason = ps.loop_decision(st, max_rounds=10)
        self.assertEqual(decision, "stop")
        self.assertIn("Nothing is left to fuzz", reason)

    def test_completion_wins_even_while_coverage_is_still_growing(self):
        st = self.state(surface_verdict="complete", surface_closed=764,
                        surface_total=764, surface_ledger="artifacts/x.json",
                        coverage_verdict="growing")
        self.assertEqual(ps.loop_decision(st, max_rounds=10)[0], "stop")

    def test_an_incomplete_surface_is_not_a_stop(self):
        st = self.state(surface_verdict="incomplete", surface_closed=700,
                        surface_total=764, coverage_verdict="growing")
        self.assertIsNone(ps.surface_stop_reason(st))
        self.assertIsNone(ps.hard_cap_reason(st, max_rounds=10))
        self.assertEqual(ps.loop_decision(st, max_rounds=10)[0], "continue")

    def test_an_unknown_surface_reading_never_stops_on_completion(self):
        st = self.state(surface_verdict="unknown", coverage_verdict="growing")
        self.assertIsNone(ps.surface_stop_reason(st))

    def test_the_round_cap_reason_says_the_loop_failed_to_converge(self):
        st = self.state(coverage_verdict="growing")
        ps.current_round(st)["round"] = 10
        hard = ps.hard_cap_reason(st, max_rounds=10)
        self.assertIn("without converging", hard)
        self.assertIn("completion ledger", hard)

    def test_completion_is_reported_ahead_of_the_round_cap(self):
        # A campaign that finishes on its last permitted round has to record
        # why it finished, not which limit it happened to touch.
        st = self.state(surface_verdict="complete", surface_closed=764,
                        surface_total=764, surface_ledger="artifacts/x.json",
                        coverage_verdict="plateaued")
        ps.current_round(st)["round"] = 10
        hard = ps.hard_cap_reason(st, max_rounds=10)
        self.assertIn("command surface complete", hard)
        self.assertNotIn("round cap", hard)

    def test_both_curves_flat_with_an_open_ledger_reads_as_a_stuck_corpus(self):
        st = self.state(coverage_verdict="plateaued",
                        surface_verdict="incomplete", surface_closed=700,
                        surface_total=764)
        decision, reason = ps.loop_decision(st, max_rounds=10)
        self.assertEqual(decision, "stop")
        self.assertIn("corpus is stuck", reason)
        self.assertIn("64 target(s)", reason)
        # Overridable, unlike completion: hard_cap_reason declines to claim it.
        self.assertIsNone(ps.hard_cap_reason(st, max_rounds=10))

    def test_a_plateau_with_no_ledger_reading_says_so(self):
        st = self.state(coverage_verdict="plateaued")
        _decision, reason = ps.loop_decision(st, max_rounds=10)
        self.assertIn("no completion reading", reason)
        self.assertNotIn("corpus is stuck", reason)

    def test_the_budget_still_outranks_a_growing_curve(self):
        st = self.state(coverage_verdict="growing")
        ps.record_run_hours("r1", 300.0)
        hard = ps.hard_cap_reason(st, max_rounds=10, max_total_run_hours=216)
        self.assertIn("run-hour budget spent", hard)
        # And a finished campaign reports completion rather than the ceiling
        # it also happened to reach, because the two mean different things to
        # whoever reads the round afterwards.
        done = self.state(surface_verdict="complete", surface_closed=764,
                          surface_total=764,
                          surface_ledger="surface/x.json",
                          coverage_verdict="growing")
        hard = ps.hard_cap_reason(done, max_rounds=10,
                                  max_total_run_hours=216)
        self.assertIn("command surface complete", hard)
        self.assertNotIn("budget", hard)

    def test_end_round_records_the_surface_reading(self):
        st = ps.default_state()
        ps.end_round(st, verdict="plateaued",
                     surface={"verdict": "incomplete", "exercised": 600,
                              "accounted": 40, "closed": 630, "total": 764,
                              "ledger": "surface/x.json"})
        r = ps.current_round(st)
        self.assertEqual(r["surface_verdict"], "incomplete")
        self.assertEqual(r["surface_closed"], 630)
        self.assertEqual(r["surface_total"], 764)
        self.assertEqual(ps.validate(st), [])

    def test_end_round_refuses_an_unknown_surface_verdict(self):
        st = ps.default_state()
        with self.assertRaises(ValueError) as cm:
            ps.end_round(st, surface={"verdict": "mostly"})
        self.assertIn("unknown surface verdict", str(cm.exception))

    def test_a_complete_verdict_with_no_ledger_path_is_an_integrity_problem(self):
        # The primary stop is non-overridable, so the evidence behind it has
        # to be on record and auditable afterwards.
        st = ps.default_state()
        ps.end_round(st, surface={"verdict": "complete", "exercised": 764,
                                  "accounted": 0, "closed": 764,
                                  "total": 764, "ledger": None})
        problems = ps.validate(st)
        self.assertTrue(any("names no completion ledger" in p
                            for p in problems), problems)


# ---------------------------------------------------------------------------
# Phase 9: the shared git-mining module, tools/gitmine.py, and the two miners
# that import it. From tmp/tests/phase9-gitmine.py.
#
# GitmineRepoCase is the base class carrying the repository helpers and is
# merged before the classes that inherit from it. Every repository test skips
# when git is absent from PATH.
#
# Per tmp/impl/phase9.md, with gitmine.py present and both miners at HEAD three
# tests fail substantively: test_a_patch_fixture_does_not_inject_a_file,
# test_mining_survives_a_local_diff_noprefix and
# test_cve_patch_map_names_the_shared_implementation. The five deletion tests
# pass against the old code as well, because the old parser held the wrong file
# name at that point and derived no name from it. They are the regression guard
# for the binding, which the parser now asserts instead of inferring from git's
# choice of context string.
# ---------------------------------------------------------------------------


class GitmineRepoCase(unittest.TestCase):
    """Base class: builds throwaway git repositories for the miner tests.

    Setup runs git through subprocess directly and never through the module
    under test, so a fault in the wrapper cannot make its own fixture.
    """

    # Identity and signing are pinned so the tests do not read the user's
    # global git configuration, and gpg is never invoked.
    GIT_IDENTITY = ("-c", "user.name=gspwn selftest",
                    "-c", "user.email=selftest@gspwn.invalid",
                    "-c", "commit.gpgsign=false")

    @classmethod
    def have_git(cls):
        try:
            proc = subprocess.run(["git", "--version"], capture_output=True)
        except OSError:
            return False
        return proc.returncode == 0

    def setUp(self):
        if not self.have_git():
            self.skipTest("git is not on PATH")

    def new_repo(self):
        """An initialised empty repository in a directory removed at teardown."""
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        repo = holder.name
        self.run_git(repo, "init", "-q")
        return repo

    def run_git(self, repo, *args):
        """One git command in repo, asserting it succeeded."""
        proc = subprocess.run(
            ["git", "-C", repo] + list(self.GIT_IDENTITY) + list(args),
            capture_output=True, text=True, encoding="utf-8",
            errors="replace")
        self.assertEqual(proc.returncode, 0,
                         "git %s failed: %s" % (" ".join(args), proc.stderr))
        return proc.stdout

    def write(self, repo, name, text):
        """Create or overwrite one file in the repository working tree."""
        path = os.path.join(repo, name)
        parent = os.path.dirname(path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)

    def commit(self, repo, message):
        """Stage the whole tree and commit it, returning the new sha."""
        self.run_git(repo, "add", "-A")
        self.run_git(repo, "commit", "-q", "-m", message)
        return self.run_git(repo, "rev-parse", "HEAD").strip()


class GitmineHunkHeaderTest(unittest.TestCase):
    """parse_hunk_header against the shapes the unified format allows."""

    def test_absent_count_means_one_line(self):
        hunk = gitmine.parse_hunk_header("@@ -54 +53,0 @@ func NewLocator() {")
        self.assertEqual((hunk.old_start, hunk.old_count), (54, 1))
        self.assertEqual((hunk.new_start, hunk.new_count), (53, 0))

    def test_context_is_stripped_and_kept(self):
        hunk = gitmine.parse_hunk_header("@@ -1,2 +1,3 @@  static int foo(void) ")
        self.assertEqual(hunk.context, "static int foo(void)")

    def test_pure_deletion_anchors_at_zero(self):
        hunk = gitmine.parse_hunk_header("@@ -1,32 +0,0 @@")
        self.assertEqual((hunk.old_start, hunk.old_count), (1, 32))
        self.assertEqual((hunk.new_start, hunk.new_count), (0, 0))
        self.assertEqual(hunk.context, "")

    def test_added_and_removed_start_empty(self):
        hunk = gitmine.parse_hunk_header("@@ -0,0 +1,5 @@")
        self.assertEqual(hunk.added, [])
        self.assertEqual(hunk.removed, [])

    def test_a_line_that_is_not_a_hunk_header_returns_none(self):
        for line in ("@@@ -1,2 -1,2 +1,2 @@@", "+++ b/foo.c", "@@ -a +b @@",
                     "", "index ba7b9e6a..48b3ef8c 100644"):
            self.assertIsNone(gitmine.parse_hunk_header(line), line)

    def test_context_function_takes_the_last_identifier_before_a_paren(self):
        self.assertEqual(
            gitmine.context_function("static int nvc_ldcache_update(struct nvc"),
            "nvc_ldcache_update")
        self.assertEqual(
            gitmine.context_function("func (c *Client) Do(req *Request"), "Do")

    def test_context_function_returns_none_without_a_call_shape(self):
        for context in ("", "jobs:", "struct dsl_rule {"):
            self.assertIsNone(gitmine.context_function(context), context)


class GitmineDeletionFixtureTest(unittest.TestCase):
    """The deletion-hunk regression, on a real zero-context diff.

    FIXTURE is `git diff --no-color -U0 780ece98cf0d^ 780ece98cf0d` in
    nvidia-container-toolkit, reproduced verbatim and complete. It carries the
    shape that `patch_mine.changed_functions` used to read wrongly: a modified
    file, then a file the commit deletes, whose post-image git writes as the
    bare string `/dev/null` with no `b/` prefix. A parser testing for
    `+++ b//dev/null` never matches it, so every hunk of the deleted file was
    read while the current file was still `.github/workflows/e2e.yaml`.
    """

    FIXTURE = """diff --git a/.github/workflows/e2e.yaml b/.github/workflows/e2e.yaml
index ba7b9e6a..48b3ef8c 100644
--- a/.github/workflows/e2e.yaml
+++ b/.github/workflows/e2e.yaml
@@ -45,2 +44,0 @@ jobs:
-          # LTS branch. EOL June 2026
-          - 535
@@ -52,2 +49,0 @@ jobs:
-          - ispr: true
-            driver_branch: 580
diff --git a/tests/e2e/infra/driver-branch-535.yaml b/tests/e2e/infra/driver-branch-535.yaml
deleted file mode 100644
index 5f4cbe1d..00000000
--- a/tests/e2e/infra/driver-branch-535.yaml
+++ /dev/null
@@ -1,32 +0,0 @@
-apiVersion: holodeck.nvidia.com/v1alpha1
-kind: Environment
-metadata:
-  name: HOLODECK_NAME
-  description: "end-to-end test infrastructure"
-spec:
-  provider: aws
-  auth:
-    keyName: cnt-ci
-    privateKey: HOLODECK_PRIVATE_KEY
-  instance:
-    type: g4dn.xlarge
-    region: us-west-1
-    ingressIpRanges:
-    - 18.190.12.32/32
-    - 3.143.46.93/32
-    - 44.230.241.223/32
-    - 44.235.4.62/32
-    - 52.15.119.136/32
-    - 52.24.205.48/32
-    image:
-      architecture: amd64
-  containerRuntime:
-    install: true
-    name: docker
-  nvidiaContainerToolkit:
-    install: false
-  nvidiaDriver:
-    install: true
-    source: package
-    package:
-      branch: "535"
"""

    DELETED = "tests/e2e/infra/driver-branch-535.yaml"
    MODIFIED = ".github/workflows/e2e.yaml"

    def setUp(self):
        self.entries = gitmine.parse_unified_diff(self.FIXTURE)
        self.by_path = {e.old_path or e.new_path: e for e in self.entries}

    def test_both_entries_are_reported(self):
        self.assertEqual([e.old_path for e in self.entries],
                         [self.MODIFIED, self.DELETED])

    def test_the_deleted_file_reports_no_post_image(self):
        entry = self.by_path[self.DELETED]
        self.assertEqual(entry.status, "deleted")
        self.assertIsNone(entry.new_path)
        self.assertEqual(entry.old_path, self.DELETED)

    def test_the_deletion_hunk_belongs_to_the_deleted_file(self):
        entry = self.by_path[self.DELETED]
        self.assertEqual(len(entry.hunks), 1)
        hunk = entry.hunks[0]
        self.assertEqual((hunk.old_start, hunk.old_count), (1, 32))
        self.assertEqual((hunk.new_start, hunk.new_count), (0, 0))
        self.assertEqual(len(hunk.removed), 32)
        self.assertEqual(hunk.added, [])
        self.assertEqual(hunk.removed[0],
                         "apiVersion: holodeck.nvidia.com/v1alpha1")

    def test_the_deletion_hunk_is_not_credited_to_the_previous_file(self):
        entry = self.by_path[self.MODIFIED]
        self.assertEqual(len(entry.hunks), 2)
        self.assertEqual([(h.old_start, h.old_count) for h in entry.hunks],
                         [(45, 2), (52, 2)])
        self.assertEqual([h.context for h in entry.hunks], ["jobs:", "jobs:"])
        self.assertNotIn(32, [h.old_count for h in entry.hunks])

    def test_the_modified_file_keeps_its_own_removed_lines(self):
        entry = self.by_path[self.MODIFIED]
        self.assertEqual(entry.status, "modified")
        self.assertEqual(entry.hunks[0].removed,
                         ["          # LTS branch. EOL June 2026",
                          "          - 535"])


class GitmineDiffBudgetTest(unittest.TestCase):
    """The hunk body is read by the line budget its header declares."""

    def test_an_added_file_reports_no_pre_image(self):
        text = ("--- /dev/null\n"
                "+++ b/src/cli/main.c\n"
                "@@ -0,0 +1,2 @@\n"
                "+int main(void)\n"
                "+{ return 0; }\n")
        entry, = gitmine.parse_unified_diff(text)
        self.assertEqual(entry.status, "added")
        self.assertIsNone(entry.old_path)
        self.assertEqual(entry.new_path, "src/cli/main.c")
        self.assertEqual(entry.hunks[0].added, ["int main(void)",
                                                "{ return 0; }"])

    def test_a_body_line_shaped_like_a_file_header_stays_a_body_line(self):
        # The added line's own text begins with "++ b/", so the diff line
        # begins with "+++ b/". Reading it as a header injects a file that the
        # commit never touched.
        text = ("--- a/testdata/sample.patch\n"
                "+++ b/testdata/sample.patch\n"
                "@@ -1,0 +2,2 @@ context\n"
                "+++ b/injected.c\n"
                "+-- a/injected.c\n")
        entry, = gitmine.parse_unified_diff(text)
        self.assertEqual(entry.new_path, "testdata/sample.patch")
        self.assertEqual(entry.hunks[0].added,
                         ["++ b/injected.c", "-- a/injected.c"])

    def test_a_removed_line_shaped_like_a_pre_image_header_is_kept(self):
        text = ("--- a/src/count.c\n"
                "+++ b/src/count.c\n"
                "@@ -10,1 +10,1 @@ static void tick(void)\n"
                "---i;\n"
                "+++i;\n")
        entry, = gitmine.parse_unified_diff(text)
        self.assertEqual(entry.hunks[0].removed, ["--i;"])
        self.assertEqual(entry.hunks[0].added, ["++i;"])

    def test_a_no_newline_marker_counts_against_nothing(self):
        text = ("--- a/f\n"
                "+++ b/f\n"
                "@@ -1 +1 @@\n"
                "-old\n"
                "\\ No newline at end of file\n"
                "+new\n"
                "\\ No newline at end of file\n")
        entry, = gitmine.parse_unified_diff(text)
        self.assertEqual(entry.hunks[0].removed, ["old"])
        self.assertEqual(entry.hunks[0].added, ["new"])

    def test_an_entry_without_a_header_pair_produces_no_record(self):
        text = ("diff --git a/mk/build.sh b/mk/build.sh\n"
                "old mode 100644\n"
                "new mode 100755\n"
                "diff --git a/logo.png b/logo.png\n"
                "index 1111111..2222222 100644\n"
                "Binary files a/logo.png and b/logo.png differ\n")
        self.assertEqual(gitmine.parse_unified_diff(text), [])

    def test_a_path_without_a_prefix_is_taken_as_written(self):
        # What `diff.noprefix=true` produces. The configuration is pinned off
        # on every invocation, and the parser does not depend on that.
        text = ("--- src/foo.c\n"
                "+++ src/foo.c\n"
                "@@ -3,0 +4 @@ int foo(void)\n"
                "+    return 1;\n")
        entry, = gitmine.parse_unified_diff(text)
        self.assertEqual(entry.new_path, "src/foo.c")
        self.assertEqual(entry.status, "modified")


class GitmineGitWrapperTest(GitmineRepoCase):
    """run_git pins the diff format, sets a timeout, and raises what it is told."""

    def test_the_prefix_is_pinned_against_a_local_diff_noprefix(self):
        repo = self.new_repo()
        self.write(repo, "src/foo.c", "int foo(void)\n{\n    return 0;\n}\n")
        first = self.commit(repo, "add foo")
        self.run_git(repo, "config", "diff.noprefix", "true")
        self.write(repo, "src/foo.c", "int foo(void)\n{\n    return 1;\n}\n")
        second = self.commit(repo, "change foo")
        diff = gitmine.run_git(repo, ["diff", "--no-color", "-U0", first,
                                      second])
        self.assertIn("+++ b/src/foo.c", diff)
        entry, = gitmine.parse_unified_diff(diff)
        self.assertEqual(entry.new_path, "src/foo.c")

    def test_a_failing_command_raises_with_the_command_and_stderr(self):
        repo = self.new_repo()
        with self.assertRaises(gitmine.GitError) as caught:
            gitmine.run_git(repo, ["rev-parse", "does-not-exist"])
        message = str(caught.exception)
        self.assertIn("rev-parse does-not-exist", message)
        self.assertIn(repo, message)

    def test_the_error_class_is_the_caller_s_own(self):
        repo = self.new_repo()
        with self.assertRaises(cve_patch_map.SourceError):
            gitmine.run_git(repo, ["rev-parse", "does-not-exist"],
                            error=cve_patch_map.SourceError)

    def test_a_timeout_is_reported_and_not_read_as_an_empty_result(self):
        repo = self.new_repo()
        self.write(repo, "f", "one\n")
        self.commit(repo, "one")
        with self.assertRaises(gitmine.GitError) as caught:
            gitmine.run_git(repo, ["log"], timeout=0)
        self.assertIn("timed out", str(caught.exception))

    def test_list_tags_drops_blank_lines(self):
        repo = self.new_repo()
        self.write(repo, "f", "one\n")
        self.commit(repo, "one")
        self.run_git(repo, "tag", "v1.0.0")
        self.run_git(repo, "tag", "v1.0.0-rc.1")
        self.assertEqual(sorted(gitmine.list_tags(repo)),
                         ["v1.0.0", "v1.0.0-rc.1"])


class GitmineTagMappingTest(GitmineRepoCase):
    """The earliest release tag containing a commit, and the ancestor tag."""

    def test_version_key_orders_by_component_and_not_by_string(self):
        self.assertLess(gitmine.version_key("v1.9.0"),
                        gitmine.version_key("v1.17.0"))
        self.assertEqual(gitmine.version_key("535.129.03"), (535, 129, 3))

    def test_first_release_tag_is_the_earliest_and_ignores_a_candidate(self):
        repo = self.new_repo()
        self.write(repo, "f", "one\n")
        sha = self.commit(repo, "one")
        self.run_git(repo, "tag", "v1.17.0")
        self.run_git(repo, "tag", "v1.9.0")
        self.run_git(repo, "tag", "v1.8.0-rc.2")
        self.assertEqual(gitmine.first_release_tag(repo, sha), "v1.9.0")

    def test_first_release_tag_is_none_for_an_unreleased_commit(self):
        repo = self.new_repo()
        self.write(repo, "f", "one\n")
        first = self.commit(repo, "one")
        self.run_git(repo, "tag", "v1.0.0")
        self.write(repo, "f", "two\n")
        second = self.commit(repo, "two")
        self.assertEqual(gitmine.first_release_tag(repo, first), "v1.0.0")
        self.assertIsNone(gitmine.first_release_tag(repo, second))

    def test_previous_tag_walks_ancestry(self):
        repo = self.new_repo()
        self.write(repo, "f", "one\n")
        self.commit(repo, "one")
        self.run_git(repo, "tag", "525.53")
        self.write(repo, "f", "two\n")
        self.commit(repo, "two")
        self.run_git(repo, "tag", "525.60.11")
        self.assertEqual(gitmine.previous_tag(repo, "525.60.11^"), "525.53")

    def test_previous_tag_raises_when_nothing_is_tagged_below(self):
        repo = self.new_repo()
        self.write(repo, "f", "one\n")
        self.commit(repo, "one")
        self.write(repo, "f", "two\n")
        self.commit(repo, "two")
        self.run_git(repo, "tag", "525.60.11")
        with self.assertRaises(gitmine.GitError):
            gitmine.previous_tag(repo, "525.60.11^")


class PatchMineDiffAttributionTest(GitmineRepoCase):
    """changed_functions over the shapes the old whole-commit parser misread."""

    KEPT = ("#include <stdio.h>\n"
            "\n"
            "int nvc_ldcache_update(struct nvc_context *ctx)\n"
            "{\n"
            "    return 0;\n"
            "}\n")
    DOOMED = ("int nvc_cli_main(int argc, char **argv)\n"
              "{\n"
              "    return 1;\n"
              "}\n")

    def build(self, repo):
        """Two commits: one adding both files, one deleting the later path.

        `src/aaa_kept.c` sorts before `src/zzz_doomed.c`, so git writes the
        deletion after the surviving file and the deletion's hunks follow a
        `+++ b/src/aaa_kept.c` header. Under that ordering a parser keyed on
        `+++ b/` credits them to the wrong file.
        """
        self.write(repo, "src/aaa_kept.c", self.KEPT)
        self.write(repo, "src/zzz_doomed.c", self.DOOMED)
        self.commit(repo, "add both")
        self.write(repo, "src/aaa_kept.c",
                   self.KEPT.replace("return 0;", "return ctx ? 0 : -1;"))
        os.unlink(os.path.join(repo, "src", "zzz_doomed.c"))
        return self.commit(repo, "delete the cli and harden the update")

    def test_a_deleted_file_is_reported_nowhere(self):
        repo = self.new_repo()
        sha = self.build(repo)
        files, funcs = patch_mine.changed_functions(repo, sha)
        self.assertEqual(files, ["src/aaa_kept.c"])
        self.assertNotIn("src/zzz_doomed.c", funcs)

    def test_the_surviving_file_keeps_only_its_own_functions(self):
        repo = self.new_repo()
        sha = self.build(repo)
        _files, funcs = patch_mine.changed_functions(repo, sha)
        self.assertEqual(funcs, {"src/aaa_kept.c": ["nvc_ldcache_update"]})
        self.assertNotIn("nvc_cli_main",
                         funcs.get("src/aaa_kept.c", []))

    def test_the_deletion_entry_carries_its_own_hunk(self):
        repo = self.new_repo()
        sha = self.build(repo)
        parents = patch_mine.run_git(repo, ["log", "-1", "--format=%P",
                                            sha]).split()
        diff = patch_mine.run_git(repo, ["diff", "--no-color", "-U0",
                                         parents[0], sha])
        entries = {e.old_path: e for e in gitmine.parse_unified_diff(diff)}
        self.assertEqual(entries["src/zzz_doomed.c"].status, "deleted")
        self.assertEqual(len(entries["src/zzz_doomed.c"].hunks), 1)
        self.assertEqual(len(entries["src/aaa_kept.c"].hunks), 1)

    def test_mining_survives_a_local_diff_noprefix(self):
        # Under `diff.noprefix=true` git writes `+++ src/aaa_kept.c`. A parser
        # keyed on the `b/` prefix matched nothing and reported a clean summary
        # of zero hot spots for every commit in the window.
        repo = self.new_repo()
        sha = self.build(repo)
        self.run_git(repo, "config", "diff.noprefix", "true")
        files, funcs = patch_mine.changed_functions(repo, sha)
        self.assertEqual(files, ["src/aaa_kept.c"])
        self.assertEqual(funcs, {"src/aaa_kept.c": ["nvc_ldcache_update"]})

    def test_a_patch_fixture_does_not_inject_a_file(self):
        # A line whose own text begins with "++ b/" is a line of the file under
        # `testdata/`, and reading it as a header adds a path the commit never
        # touched to the hot-spot ranking.
        repo = self.new_repo()
        self.write(repo, "testdata/sample.patch", "@@ -1 +1 @@\n")
        self.commit(repo, "add the fixture")
        self.write(repo, "testdata/sample.patch",
                   "@@ -1 +1 @@\n++ b/injected.c\n")
        sha = self.commit(repo, "extend the fixture")
        files, _funcs = patch_mine.changed_functions(repo, sha)
        self.assertEqual(files, ["testdata/sample.patch"])


class CvePatchMapHunkBodyTest(GitmineRepoCase):
    """diff_file counts every changed line, including the header-shaped ones."""

    SOURCE = ("static void tick(NvU32 *pCount)\n"
              "{\n"
              "    if (pCount == NULL)\n"
              "        return;\n"
              "    --*pCount;\n"
              "}\n")
    PATCHED = ("static void tick(NvU32 *pCount)\n"
               "{\n"
               "    if (pCount == NULL)\n"
               "        return;\n"
               "    ++*pCount;\n"
               "}\n")

    def build(self, repo):
        """Two tagged commits whose diff decrements one line and increments it."""
        self.write(repo, "src/tick.c", self.SOURCE)
        self.commit(repo, "add tick")
        self.run_git(repo, "tag", "550.54.14")
        self.write(repo, "src/tick.c", self.PATCHED)
        self.commit(repo, "count up")
        self.run_git(repo, "tag", "550.90.07")

    def test_a_removed_line_beginning_with_two_dashes_is_counted(self):
        repo = self.new_repo()
        self.build(repo)
        rows = cve_patch_map.diff_file(repo, "550.54.14", "550.90.07",
                                       "src/tick.c")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["function"], "tick")
        self.assertEqual(rows[0]["lines_removed"], 1)
        self.assertEqual(rows[0]["lines_added"], 1)
        self.assertEqual(rows[0]["hunks"], 1)
        self.assertEqual(rows[0]["attributed_to"], "post")

    def test_a_deleted_file_is_attributed_to_its_pre_image(self):
        repo = self.new_repo()
        self.build(repo)
        self.write(repo, "src/gone.c",
                   "static void gone(NvU32 *pCount)\n{\n    return;\n}\n")
        self.commit(repo, "add gone")
        self.run_git(repo, "tag", "550.90.08")
        os.unlink(os.path.join(repo, "src", "gone.c"))
        self.commit(repo, "remove gone")
        self.run_git(repo, "tag", "550.90.09")
        rows = cve_patch_map.diff_file(repo, "550.90.08", "550.90.09",
                                       "src/gone.c")
        self.assertEqual([r["attributed_to"] for r in rows], ["pre"])
        self.assertEqual(rows[0]["file"], "src/gone.c")
        self.assertEqual(rows[0]["lines_removed"], 4)


class GitmineAttributionExportTest(unittest.TestCase):
    """The C attribution helpers cve_patch_map calls are gitmine's own."""

    SOURCE = ("NV_STATUS\n"
              "memdescCreate\n"
              "(\n"
              "    MEMORY_DESCRIPTOR **ppMemDesc\n"
              ")\n"
              "{\n"
              "    return NV_OK;\n"
              "}\n")

    def test_cve_patch_map_names_the_shared_implementation(self):
        self.assertIs(cve_patch_map.function_ranges, gitmine.function_ranges)
        self.assertIs(cve_patch_map.enclosing, gitmine.enclosing)
        self.assertIs(cve_patch_map.declarator_name, gitmine.declarator_name)

    def test_a_multi_line_declarator_supplies_the_name(self):
        ranges = gitmine.function_ranges(self.SOURCE)
        self.assertEqual([r[0] for r in ranges], ["memdescCreate"])
        self.assertEqual(gitmine.enclosing(ranges, 7), "memdescCreate")
        self.assertIsNone(gitmine.enclosing(ranges, 1))


class GitminePosixFreeTest(unittest.TestCase):
    """gitmine runs on the workstation, so it imports nothing POSIX-only."""

    def test_the_module_does_not_import_fcntl_or_pipeline_state(self):
        with open(gitmine.__file__, encoding="utf-8") as handle:
            source = handle.read()
        for banned in ("import fcntl", "import pipeline_state",
                       "import termios", "import pwd"):
            self.assertNotIn(banned, source, banned)
        self.assertNotIn("fcntl", sys.modules.get("gitmine").__dict__)


# ---------------------------------------------------------------------------
# The narrow alloc parent expansion. From tmp/tests/alloc-expand.py.
#
# A class whose legal parents all coexist on one chip emits one call per
# parent, each pinning that parent's own resource; a class whose parent set is
# chip-gated keeps one call on nv_handle; and the class-level name stays on
# exactly one call per class, which holds surface_cov's alloc denominator still.
# surface_cov.VARIANT_RE and surface_cov.ALLOC_PREFIX are used directly so the
# denominator tests join on the same expression the ledger joins on.
#
# All 22 fail under at least one of the 11 mutations in
# tmp/impl/alloc-expand.md.
# ---------------------------------------------------------------------------


class AllocExpansionFixture(unittest.TestCase):
    """A synthetic object graph in the shape object_graph.py emits.

    The committed graph is an artefact a clean checkout may not carry, and
    these tests are about the emitter's rules and not about the driver
    release, so the records are built here. The shape reproduces the three
    real parent-set forms: the root classes, a narrow set whose members
    coexist, and the chip-gated GPFIFO channel family.
    """

    HEADER = """
typedef struct
{
    NvU32 hRoot;
    NvU32 hObjectParent;
    NvU32 hObjectNew;
    NvU32 hClass;
    NvU64 pAllocParms;
    NvU64 pRightsRequested;
    NvU32 paramsSize;
    NvU32 flags;
    NvU32 status;
} NVOS64_PARAMETERS;

typedef struct
{
    NvU32 hRoot;
    NvU32 hObjectParent;
    NvU32 hObjectNew;
    NvU32 hClass;
    NvU64 pAllocParms;
    NvU32 paramsSize;
    NvU32 status;
} NVOS21_PARAMETERS;

typedef struct
{
    NvU32 field;
} ALLOC_PARAMS;
"""

    # The eleven-strong GPFIFO family in miniature. gpuGetClassByClassId
    # admits one of these per chip, so a variant per member is one live
    # description and the rest dead on any given GPU.
    GATED = ["GF100_CHANNEL_GPFIFO", "TURING_CHANNEL_GPFIFO_A",
             "BLACKWELL_CHANNEL_GPFIFO_A"]

    @staticmethod
    def record(external, parents, depth, internal="Thing",
               privilege="unprivileged", param="ALLOC_PARAMS"):
        return {"external_class": external, "internal_class": internal,
                "parents": parents, "depth": depth,
                "alloc_privilege": privilege,
                "alloc_param_struct": param, "alloc_param_kind": "required"}

    def graph(self, extra=()):
        records = [
            # The three root classes hang off the file descriptor.
            self.record("NV01_ROOT", [syzlang_gen.ROOT_SENTINEL], 1,
                        privilege="unclassified", param=None),
            self.record("NV01_ROOT_CLIENT", [syzlang_gen.ROOT_SENTINEL], 1,
                        privilege="unclassified", param=None),
            # Narrow: both parents are root classes and coexist on one chip.
            self.record("NV01_DEVICE_0", ["NV01_ROOT", "NV01_ROOT_CLIENT"], 2),
            # One legal parent: pinned before this change and after it.
            self.record("NV20_SUBDEVICE_0", ["NV01_DEVICE_0"], 3),
            # Narrow, and its two parents sit at different depths, so the
            # cheapest-first rule has something to decide.
            self.record("CHEAPEST_CHILD",
                        ["NV20_SUBDEVICE_0", "NV01_DEVICE_0"], 3),
        ]
        for name in self.GATED:
            records.append(self.record(name, ["NV01_DEVICE_0"], 3))
        # Wide: the parent set is the chip-gated family.
        records.append(self.record("WIDE_CHILD", list(self.GATED), 4))
        # The sentinel naming no class to take a resource from.
        records.append(
            self.record("ANY_CHILD", [syzlang_gen.ANY_PARENT_SENTINEL], 4))
        records.extend(extra)
        return {"records": records}

    def class_map(self, graph):
        return {r["external_class"]: 0x1000 + i
                for i, r in enumerate(graph["records"])}

    def inventory(self):
        return {"nodes": [{"commands": [{
            "name": syzlang_gen.ALLOC_ESCAPE,
            "requests": ["0xc0304600", "0xc0204601"],
        }]}]}

    def setUp(self):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "alloc.h")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.HEADER)
        index = syzlang_gen.TypeIndex()
        index.scan_file(path, "alloc.h")
        self.emitter = syzlang_gen.Emitter(index, {})

    def emit(self, graph=None, limit_privilege=True):
        graph = graph or self.graph()
        text, records, skipped = syzlang_gen.emit_alloc(
            self.emitter, self.inventory(), graph, self.class_map(graph),
            limit_privilege)
        return text, [r for r in records if r["emitted"]], skipped

    @staticmethod
    def names(records):
        """{class: [variant name, ...]} over the emitted records."""
        out = {}
        for record in records:
            out.setdefault(record["class"], []).append(record["variant_name"])
        return out

    def struct_of(self, variant_name, text):
        """The struct one emitted call points at, read from the call line."""
        for line in text.splitlines():
            if line.startswith("ioctl$%s(" % variant_name):
                return line.rsplit("ptr[inout, ", 1)[1].rstrip("])")
        self.fail("no call named %s in the emitted text" % variant_name)

    def field(self, struct, name):
        for block in self.emitter.blocks():
            if not block.startswith(struct + " {"):
                continue
            for line in block.splitlines():
                parts = [p for p in line.split("\t") if p.strip()]
                if len(parts) == 2 and parts[0].strip() == name:
                    return parts[1].strip()
        self.fail("no field %s in struct %s" % (name, struct))


class TestNarrowParentSetsExpand(AllocExpansionFixture):
    """A class whose legal parents all coexist on one chip emits one call per
    parent. Before this change such a class emitted one call whose
    hObjectParent took the generic nv_handle, because a syzlang field carries
    one type and the class had no single legal parent to pin. Every variant
    the expansion produces is allocatable on every chip, so the looser pin
    buys nothing the expansion does not."""

    def test_a_narrow_class_emits_one_variant_per_legal_parent(self):
        _text, records, _skipped = self.emit()
        self.assertEqual(
            sorted(self.names(records)["NV01_DEVICE_0"]),
            ["NV_ESC_RM_ALLOC_NV01_DEVICE_0",
             "NV_ESC_RM_ALLOC_NV01_DEVICE_0_UNDER_NV01_ROOT_CLIENT"])

    def test_every_narrow_variant_pins_its_own_parent_resource(self):
        text, records, _skipped = self.emit()
        pins = {r["variant_name"]:
                self.field(self.struct_of(r["variant_name"], text),
                           "hObjectParent")
                for r in records if r["class"] == "NV01_DEVICE_0"}
        self.assertEqual(pins, {
            "NV_ESC_RM_ALLOC_NV01_DEVICE_0": "nvh_nv01_root",
            "NV_ESC_RM_ALLOC_NV01_DEVICE_0_UNDER_NV01_ROOT_CLIENT":
                "nvh_nv01_root_client"})

    def test_no_narrow_variant_is_left_on_the_generic_handle(self):
        _text, records, _skipped = self.emit()
        narrow = [r for r in records
                  if r["class"] in ("NV01_DEVICE_0", "CHEAPEST_CHILD")]
        self.assertEqual([r["parent_resource"] for r in narrow
                          if r["parent_resource"] == "nv_handle"], [])
        self.assertEqual(len(narrow), 4)

    def test_the_class_level_variant_names_the_cheapest_parent(self):
        # NV01_DEVICE_0 sits at depth 2 and NV20_SUBDEVICE_0 at depth 3, so
        # the class-level name carries the shorter allocation chain and the
        # deeper parent takes the suffixed name.
        _text, records, _skipped = self.emit()
        by_name = {r["variant_name"]: r for r in records}
        self.assertEqual(
            by_name["NV_ESC_RM_ALLOC_CHEAPEST_CHILD"]["parent_resource"],
            "nvh_nv01_device_0")
        self.assertEqual(
            by_name["NV_ESC_RM_ALLOC_CHEAPEST_CHILD_UNDER_NV20_SUBDEVICE_0"]
            ["parent_resource"], "nvh_nv20_subdevice_0")

    def test_a_single_parent_class_still_emits_one_pinned_variant(self):
        _text, records, _skipped = self.emit()
        self.assertEqual(self.names(records)["NV20_SUBDEVICE_0"],
                         ["NV_ESC_RM_ALLOC_NV20_SUBDEVICE_0"])
        pin = [r["parent_resource"] for r in records
               if r["class"] == "NV20_SUBDEVICE_0"]
        self.assertEqual(pin, ["nvh_nv01_device_0"])

    def test_a_root_object_class_is_not_expanded(self):
        # RS_ROOT_OBJECT hangs off the file descriptor, so there is no parent
        # handle to enumerate and hObjectParent is a constant zero.
        text, records, _skipped = self.emit()
        self.assertEqual(self.names(records)["NV01_ROOT"],
                         ["NV_ESC_RM_ALLOC_NV01_ROOT"])
        self.assertEqual(
            self.field(self.struct_of("NV_ESC_RM_ALLOC_NV01_ROOT", text),
                       "hObjectParent"), "const[0, int32]")

    def test_a_root_object_naming_a_concrete_parent_is_not_expanded(self):
        # No class in 610.57.04 carries RS_ROOT_OBJECT beside a concrete
        # parent. The file descriptor is the gate when it is present, so a
        # record of that shape stays on the root form rather than enumerating
        # parents whose handles the call does not consume.
        graph = self.graph(extra=[self.record(
            "HYBRID_ROOT",
            [syzlang_gen.ROOT_SENTINEL, "NV01_DEVICE_0", "NV20_SUBDEVICE_0"],
            2)])
        text, records, _skipped = self.emit(graph)
        self.assertEqual(self.names(records)["HYBRID_ROOT"],
                         ["NV_ESC_RM_ALLOC_HYBRID_ROOT"])
        self.assertEqual(
            self.field(self.struct_of("NV_ESC_RM_ALLOC_HYBRID_ROOT", text),
                       "hObjectParent"), "const[0, int32]")

    def test_a_parent_outside_the_connected_component_sorts_last(self):
        # depth is null for a class the breadth-first walk never reached.
        # Read as a zero it would sort ahead of every real parent and take
        # the class-level name, which is the one name the ledger counts.
        graph = self.graph(extra=[
            self.record("ORPHAN_PARENT", [], None),
            self.record("ORPHAN_CHILD", ["ORPHAN_PARENT", "NV01_DEVICE_0"], 3),
        ])
        _text, records, _skipped = self.emit(graph)
        self.assertEqual(
            sorted(self.names(records)["ORPHAN_CHILD"]),
            ["NV_ESC_RM_ALLOC_ORPHAN_CHILD",
             "NV_ESC_RM_ALLOC_ORPHAN_CHILD_UNDER_ORPHAN_PARENT"])
        by_name = {r["variant_name"]: r for r in records}
        self.assertEqual(
            by_name["NV_ESC_RM_ALLOC_ORPHAN_CHILD"]["parent_resource"],
            "nvh_nv01_device_0")

    def test_the_any_parent_sentinel_is_not_expanded(self):
        _text, records, _skipped = self.emit()
        self.assertEqual(self.names(records)["ANY_CHILD"],
                         ["NV_ESC_RM_ALLOC_ANY_CHILD"])
        pin = [r["parent_resource"] for r in records
               if r["class"] == "ANY_CHILD"]
        self.assertEqual(pin, ["nv_handle"])

    def test_every_emitted_variant_pins_hclass(self):
        # Phase 3's require_pinned assertion runs per variant, so the
        # expansion has to satisfy it on the added ones as well.
        text, records, _skipped = self.emit()
        free = [r["variant_name"] for r in records
                if not self.field(self.struct_of(r["variant_name"], text),
                                  "hClass").startswith("const[")]
        self.assertEqual(free, [])

    def test_each_variant_gets_its_own_struct(self):
        text, records, _skipped = self.emit()
        structs = [self.struct_of(r["variant_name"], text) for r in records]
        self.assertEqual(len(structs), len(set(structs)))


class TestWideParentSetsAreNotExpanded(AllocExpansionFixture):
    """gpuGetClassByClassId admits one *_CHANNEL_GPFIFO class per chip, so at
    most one member of that family exists on any given GPU. A variant per
    member would put one live description and the rest dead into the choice
    table and the corpus for the whole campaign, where nv_handle draws from a
    pool holding the correct handle and corrects itself under coverage
    feedback. descriptions/nvidia.txt declares resource
    nv_handle[int32] and every nvh_* resource derives from it, so the loose
    pin is a lower per-execution hit rate and never an unreachable path."""

    def test_a_wide_class_still_emits_one_variant(self):
        _text, records, _skipped = self.emit()
        self.assertEqual(self.names(records)["WIDE_CHILD"],
                         ["NV_ESC_RM_ALLOC_WIDE_CHILD"])

    def test_the_wide_variant_takes_the_generic_handle(self):
        text, records, _skipped = self.emit()
        self.assertEqual(
            self.field(self.struct_of("NV_ESC_RM_ALLOC_WIDE_CHILD", text),
                       "hObjectParent"), "nv_handle")
        self.assertEqual([r["parent_class"] for r in records
                          if r["class"] == "WIDE_CHILD"], [None])

    def test_the_split_is_the_chip_gate_and_not_the_set_size(self):
        # Four parents, none of them chip-gated, is narrow. Two parents drawn
        # from the gated family is wide. A size threshold would get both the
        # wrong way round.
        self.assertTrue(syzlang_gen.parent_is_narrow(
            ["NV01_ROOT", "NV01_ROOT_CLIENT", "NV01_DEVICE_0",
             "NV20_SUBDEVICE_0"]))
        self.assertFalse(syzlang_gen.parent_is_narrow(self.GATED[:2]))

    def test_one_gated_parent_beside_ungated_ones_is_still_narrow(self):
        # A set naming a single channel class has no exclusion inside it, so
        # every one of its parents can be allocated on the same chip.
        self.assertTrue(syzlang_gen.parent_is_narrow(
            ["GF100_CHANNEL_GPFIFO", "NV01_DEVICE_0"]))
        self.assertEqual(
            syzlang_gen.chip_exclusive_parents(
                ["GF100_CHANNEL_GPFIFO", "NV01_DEVICE_0"]),
            ["GF100_CHANNEL_GPFIFO"])

    def test_a_single_parent_set_is_not_narrow(self):
        # One legal parent is already pinned by parent_resource, and calling
        # it narrow would make parent_options duplicate that decision.
        self.assertFalse(syzlang_gen.parent_is_narrow(["NV01_DEVICE_0"]))
        self.assertFalse(syzlang_gen.parent_is_narrow([]))

    def test_the_channel_group_is_not_read_as_a_gated_class(self):
        # KEPLER_CHANNEL_GROUP_A is a channel group and not a GPFIFO channel.
        # 11 real classes name it beside NV01_DEVICE_0, and reading it as
        # gated would leave all 11 on nv_handle.
        self.assertEqual(
            syzlang_gen.chip_exclusive_parents(
                ["KEPLER_CHANNEL_GROUP_A", "NV01_DEVICE_0"]), [])
        self.assertTrue(syzlang_gen.parent_is_narrow(
            ["KEPLER_CHANNEL_GROUP_A", "NV01_DEVICE_0"]))


class TestTheAllocDenominatorDoesNotMove(AllocExpansionFixture):
    """surface_cov.load_targets keys the alloc family on
    NV_ESC_RM_ALLOC_<CLASS>, one target per allocatable class, built from the
    object graph and not from the descriptions. scan_variants joins on the
    whole variant name, so a per-parent name that replaced the class-level
    one would drop that class out of the modelled count and a per-parent name
    that collided with another class's name would double-count it."""

    def scanned(self, text):
        return set(surface_cov.VARIANT_RE.findall(text))

    def test_every_class_keeps_exactly_one_class_level_name(self):
        graph = self.graph()
        _text, records, _skipped = self.emit(graph)
        classes = {r["external_class"] for r in graph["records"]}
        class_level = [r["variant_name"] for r in records
                       if r["class_level_name"]]
        self.assertEqual(len(class_level), len(set(class_level)))
        self.assertEqual(
            set(class_level),
            {surface_cov.ALLOC_PREFIX + name for name in classes})

    def test_the_modelled_count_is_the_class_count(self):
        graph = self.graph()
        text, _records, _skipped = self.emit(graph)
        targets = {surface_cov.ALLOC_PREFIX + r["external_class"]
                   for r in graph["records"]}
        self.assertEqual(targets & self.scanned(text), targets)

    def test_the_added_names_stay_outside_the_denominator(self):
        graph = self.graph()
        text, records, _skipped = self.emit(graph)
        targets = {surface_cov.ALLOC_PREFIX + r["external_class"]
                   for r in graph["records"]}
        extra = self.scanned(text) - targets
        # Three per-parent names and the 32-bit-parameter form of the escape.
        self.assertEqual(
            sorted(extra),
            ["NV_ESC_RM_ALLOC_CHEAPEST_CHILD_UNDER_NV20_SUBDEVICE_0",
             "NV_ESC_RM_ALLOC_NV01_DEVICE_0_UNDER_NV01_ROOT_CLIENT",
             "NV_ESC_RM_ALLOC_NVOS21"])
        self.assertTrue(all(syzlang_gen.PARENT_VARIANT_SEP in name
                            for name in extra
                            if name != "NV_ESC_RM_ALLOC_NVOS21"))
        self.assertEqual(len([r for r in records
                              if not r["class_level_name"]]), 2)

    def test_a_per_parent_name_that_collides_fails_emission(self):
        # A class literally named <class>_UNDER_<parent> would have the same
        # variant name as one of the expansion's, and the later of the two
        # would silently overwrite the earlier struct.
        graph = self.graph(extra=[self.record(
            "NV01_DEVICE_0" + syzlang_gen.PARENT_VARIANT_SEP
            + "NV01_ROOT_CLIENT", ["NV01_DEVICE_0"], 3)])
        with self.assertRaises(SystemExit) as caught:
            self.emit(graph)
        self.assertIn("collided", str(caught.exception))

    def test_the_manifest_counts_split_class_level_from_per_parent(self):
        _text, records, _skipped = self.emit()
        self.assertEqual(
            sum(1 for r in records if r["class_level_name"]), 10)
        self.assertEqual(
            sum(1 for r in records if not r["class_level_name"]), 2)
        self.assertEqual(len(records), 12)


# ---------------------------------------------------------------------------
# Config defaults: loop.max_rounds and the three promoted coverage keys. From
# tmp/tests/config-defaults.py.
#
# Per tmp/impl/config-defaults.md, one test passes against the reverted tree by
# design: test_an_unknown_key_in_any_section_is_still_rejected asserts an
# invariant the schema change had to preserve. Three others initially passed
# both ways and were strengthened until they discriminated.
# ---------------------------------------------------------------------------


class TestShippedConfigAndCodeDefaultsAgree(unittest.TestCase):
    """A deployment whose campaign.yaml is absent, or whose section is
    trimmed, must get the same value the shipped file sets. Where the two
    disagree the trimmed deployment silently reinstates the old behaviour."""

    def shipped_path(self):
        return os.path.join(os.path.dirname(HERE), "config", "campaign.yaml")

    def shipped_text(self):
        with open(self.shipped_path(), encoding="utf-8") as f:
            return f.read()

    def yaml_scalar(self, key):
        """The raw value of `key:` in the shipped file, read as text.

        Read from the text and not from load(), because a merged value equals
        the default whether or not the file sets it, and that is the exact
        disagreement under test.
        """
        lines = [ln for ln in self.shipped_text().splitlines()
                 if ln.strip().startswith(key + ":")]
        self.assertEqual(len(lines), 1,
                         "expected one %s: line in campaign.yaml, found %d"
                         % (key, len(lines)))
        return lines[0].split(":", 1)[1].split("#")[0].strip()

    def test_max_rounds_is_ten_in_both_the_code_and_the_shipped_config(self):
        self.assertEqual(gspwn_config.DEFAULTS["loop"]["max_rounds"], 10)
        self.assertEqual(int(self.yaml_scalar("max_rounds")), 10)

    def test_every_promoted_coverage_key_agrees_with_the_shipped_config(self):
        for key, expected in (("surface_sample_min", 60),
                              ("surface_min_samples", 5),
                              ("unpack_timeout_sec", 300)):
            self.assertEqual(gspwn_config.DEFAULTS["coverage"][key], expected,
                             "DEFAULTS disagrees on coverage.%s" % key)
            self.assertEqual(int(self.yaml_scalar(key)), expected,
                             "campaign.yaml disagrees on coverage.%s" % key)

    def test_the_shipped_config_still_loads(self):
        cfg = gspwn_config.load(self.shipped_path())
        self.assertEqual(cfg["loop"]["max_rounds"], 10)
        self.assertEqual(cfg["coverage"]["surface_sample_min"], 60)
        self.assertEqual(cfg["coverage"]["surface_min_samples"], 5)
        self.assertEqual(cfg["coverage"]["unpack_timeout_sec"], 300)


class TestPromotedCoverageKeys(unittest.TestCase):
    """The three keys were module constants until this change. Promoting one
    must not move its default, break its environment override, or make a
    config file that predates it unloadable."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, text):
        path = os.path.join(self.tmp.name, "campaign.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def use(self, text):
        """Point gspwn_config at a temporary config for one test.

        CONFIG_PATH is resolved at import, so the module global is what the
        cached readers consult; the cache is keyed on the file's identity and
        is cleared on both sides of the swap.
        """
        path = self.write(text)
        previous = gspwn_config.CONFIG_PATH
        gspwn_config.CONFIG_PATH = path
        gspwn_config._CACHE.clear()

        def restore():
            gspwn_config.CONFIG_PATH = previous
            gspwn_config._CACHE.clear()

        self.addCleanup(restore)
        return path

    def unset(self, *names):
        for name in names:
            previous = os.environ.pop(name, None)
            if previous is not None:
                self.addCleanup(os.environ.__setitem__, name, previous)

    # -- a config that predates the keys ---------------------------------

    def test_a_config_omitting_the_new_keys_loads_with_the_old_values(self):
        cfg = gspwn_config.load(self.write(
            "coverage:\n  min_fit_samples: 8\n  gpu_probe_timeout_sec: 20\n"))
        self.assertEqual(cfg["coverage"]["surface_sample_min"], 60)
        self.assertEqual(cfg["coverage"]["surface_min_samples"], 5)
        self.assertEqual(cfg["coverage"]["unpack_timeout_sec"], 300)

    def test_a_config_with_no_coverage_section_at_all_loads(self):
        cfg = gspwn_config.load(self.write("loop:\n  max_rounds: 4\n"))
        self.assertEqual(cfg["coverage"]["surface_sample_min"], 60)
        self.assertEqual(cfg["loop"]["max_rounds"], 4)

    def test_an_empty_config_loads_and_max_rounds_is_the_backstop(self):
        cfg = gspwn_config.load(self.write(""))
        self.assertEqual(cfg["loop"]["max_rounds"], 10)

    # -- a config carrying the keys --------------------------------------

    def test_a_config_carrying_the_new_keys_loads(self):
        cfg = gspwn_config.load(self.write(
            "coverage:\n"
            "  surface_sample_min: 30\n"
            "  surface_min_samples: 4\n"
            "  unpack_timeout_sec: 900\n"))
        self.assertEqual(cfg["coverage"]["surface_sample_min"], 30)
        self.assertEqual(cfg["coverage"]["surface_min_samples"], 4)
        self.assertEqual(cfg["coverage"]["unpack_timeout_sec"], 900)

    def test_zero_disables_the_surface_cadence_gate(self):
        cfg = gspwn_config.load(self.write("coverage:\n  surface_sample_min: 0\n"))
        self.assertEqual(cfg["coverage"]["surface_sample_min"], 0)

    # -- an unknown key is still refused ---------------------------------

    def test_a_misspelled_new_key_is_rejected_while_the_correct_one_loads(self):
        with self.assertRaises(gspwn_config.ConfigError) as cm:
            gspwn_config.load(self.write(
                "coverage:\n  surface_sample_mins: 30\n"))
        self.assertIn("surface_sample_mins", str(cm.exception))
        self.assertIn("unknown key", str(cm.exception))
        # The pair is what discriminates. A schema that declares neither
        # spelling rejects both, and the rejection above would say nothing
        # about the key having been promoted.
        cfg = gspwn_config.load(self.write(
            "coverage:\n  surface_sample_min: 30\n"))
        self.assertEqual(cfg["coverage"]["surface_sample_min"], 30)

    def test_an_unknown_key_in_any_section_is_still_rejected(self):
        for text, needle in (("coverage:\n  surface_smaple_min: 30\n",
                              "surface_smaple_min"),
                             ("loop:\n  max_round: 10\n", "max_round"),
                             ("nonesuch:\n  x: 1\n", "nonesuch")):
            with self.assertRaises(gspwn_config.ConfigError) as cm:
                gspwn_config.load(self.write(text))
            self.assertIn(needle, str(cm.exception))

    # -- validation ------------------------------------------------------

    def test_nonsense_values_for_the_new_keys_are_rejected(self):
        for bad in ("coverage:\n  surface_sample_min: -1\n",
                    "coverage:\n  surface_sample_min: 12.5\n",
                    # One sample has nothing to be compared against, so the
                    # curve would read flat from the first measurement and a
                    # still-climbing surface would stop the loop.
                    "coverage:\n  surface_min_samples: 1\n",
                    "coverage:\n  unpack_timeout_sec: 0\n",
                    "coverage:\n  unpack_timeout_sec: -30\n"):
            with self.assertRaises(gspwn_config.ConfigError) as cm:
                gspwn_config.load(self.write(bad))
            # The rejection has to come from the value rule. A schema that
            # never declared the key rejects the same text as an unknown key,
            # which proves nothing about the value being checked.
            self.assertNotIn("unknown key", str(cm.exception), bad)
            self.assertIn("invalid configuration", str(cm.exception), bad)

    # -- the values reach the tools --------------------------------------

    def test_the_configured_cadence_reaches_the_sampler(self):
        self.unset("GSPWN_SURFACE_SAMPLE_MIN")
        self.use("coverage:\n  surface_sample_min: 17\n")
        self.assertEqual(coverage_ctl.surface_sample_min(), 17)

    def test_the_environment_overrides_the_configured_cadence(self):
        self.use("coverage:\n  surface_sample_min: 17\n")
        os.environ["GSPWN_SURFACE_SAMPLE_MIN"] = "3"
        self.addCleanup(os.environ.pop, "GSPWN_SURFACE_SAMPLE_MIN", None)
        self.assertEqual(coverage_ctl.surface_sample_min(), 3)

    def test_a_non_numeric_cadence_override_is_refused_by_name(self):
        os.environ["GSPWN_SURFACE_SAMPLE_MIN"] = "hourly"
        self.addCleanup(os.environ.pop, "GSPWN_SURFACE_SAMPLE_MIN", None)
        with self.assertRaises(ValueError) as cm:
            coverage_ctl.surface_sample_min()
        self.assertIn("GSPWN_SURFACE_SAMPLE_MIN", str(cm.exception))

    def test_an_unreadable_config_leaves_the_sampler_on_its_default(self):
        # _coverage_cfg swallows the error on purpose: a config this tool
        # cannot read must not stop a running campaign's sampler.
        self.unset("GSPWN_SURFACE_SAMPLE_MIN")
        self.use("coverage:\n  surface_sample_min: not-a-number\n")
        self.assertEqual(coverage_ctl.surface_sample_min(), 60)

    def test_the_configured_floor_reaches_the_surface_curve(self):
        rows = [{"surface": 100 + i, "execs": 1000 * (i + 1), "ts": i * 60}
                for i in range(3)]
        self.unset("GSPWN_SURFACE_MIN_SAMPLES")
        strict = dict(gspwn_config.DEFAULTS["coverage"], surface_min_samples=5)
        self.assertEqual(coverage_ctl.surface_growth(rows, cov=strict)[0],
                         "unknown")
        loose = dict(gspwn_config.DEFAULTS["coverage"], surface_min_samples=2)
        self.assertEqual(coverage_ctl.surface_growth(rows, cov=loose)[0],
                         "growing")

    def test_the_environment_overrides_the_configured_floor(self):
        rows = [{"surface": 100 + i, "execs": 1000 * (i + 1), "ts": i * 60}
                for i in range(3)]
        loose = dict(gspwn_config.DEFAULTS["coverage"], surface_min_samples=2)
        strict = dict(gspwn_config.DEFAULTS["coverage"], surface_min_samples=5)
        self.addCleanup(os.environ.pop, "GSPWN_SURFACE_MIN_SAMPLES", None)
        os.environ["GSPWN_SURFACE_MIN_SAMPLES"] = "9"
        self.assertEqual(coverage_ctl.surface_growth(rows, cov=loose)[0],
                         "unknown")
        # Both directions, because a floor read from neither the environment
        # nor the configuration happens to sit between the two values and
        # would satisfy the first assertion on its own.
        os.environ["GSPWN_SURFACE_MIN_SAMPLES"] = "2"
        self.assertEqual(coverage_ctl.surface_growth(rows, cov=strict)[0],
                         "growing")

    def test_the_configured_unpack_timeout_reaches_surface_cov(self):
        self.unset("GSPWN_UNPACK_TIMEOUT_SEC")
        self.use("coverage:\n  unpack_timeout_sec: 45\n")
        self.assertEqual(surface_cov.unpack_timeout_sec(), 45)

    def test_the_environment_overrides_the_configured_unpack_timeout(self):
        self.use("coverage:\n  unpack_timeout_sec: 45\n")
        os.environ["GSPWN_UNPACK_TIMEOUT_SEC"] = "7"
        self.addCleanup(os.environ.pop, "GSPWN_UNPACK_TIMEOUT_SEC", None)
        self.assertEqual(surface_cov.unpack_timeout_sec(), 7)

    def test_an_unreadable_config_leaves_surface_cov_on_its_default(self):
        # surface_cov has to stay usable where the config cannot be read at
        # all, which is the workstation with no PyYAML installed.
        self.unset("GSPWN_UNPACK_TIMEOUT_SEC")
        self.use("coverage:\n  unpack_timeout_sec: also-not-a-number\n")
        self.assertEqual(surface_cov.unpack_timeout_sec(), 300)


# ---------------------------------------------------------------------------
# The cleanup wave: the regression_check derived staleness check and the
# atomic, line-ending-stable write in object_graph cmd_extract. From
# tmp/tests/cleanup-checks.py.
#
# Per tmp/impl/cleanup.md, 29 of the 32 fail under at least one mutation. The
# three that do not are
# test_the_committed_artefact_is_lf_with_a_forward_slash_path,
# test_every_reader_of_the_committed_artefact_still_loads_it and
# test_the_committed_digest_matches_the_committed_ranking. All three assert
# properties of the committed artefacts, which no change to either tool can
# move, so no mutation can reach them. They name the cause when a checkout is
# missing an un-ignored file or carries one in the wrong form.
# ---------------------------------------------------------------------------


class DerivedFixture(unittest.TestCase):
    """A description set, a denominator and the two derived artefacts on disk.

    Every test builds the four from scratch so a case can move exactly one of
    them and nothing else. The real committed artefacts are read by one test
    per class and never written.
    """

    # Two owning classes, three control commands, one allocation chain.
    HANDLERS = ["cliresCtrlCmdGpuGetIdInfo", "subdeviceCtrlCmdBiosGetSKUInfo",
                "subdeviceCtrlCmdGpuGetInfoV2"]
    CHAIN_CLASSES = ["NV01_ROOT", "NV01_DEVICE_0"]

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(self._cleanup)
        self.desc = os.path.join(self.dir, "descriptions")
        os.makedirs(self.desc)
        self.chains_path = os.path.join(self.dir, "rm-chains.json")
        self.rank_path = os.path.join(self.dir, "rm-control-rank.json")

        self._saved_desc = regression_check.DESC_DIR
        self._saved_derived = regression_check.DERIVED
        self._saved_load = surface_cov.load_targets
        regression_check.DESC_DIR = self.desc
        regression_check.DERIVED = [
            ("rm-chains.json", self.chains_path, "gspwn.rm-chains/1",
             "chains", "tools/object_graph.py chains"),
            ("rm-control-rank.json", self.rank_path,
             "gspwn.rm-control-rank/1", "commands", "tools/ctrl_rank.py rank"),
        ]
        surface_cov.load_targets = self.fake_load_targets

        self.control = list(self.HANDLERS)
        self.write_descriptions(self.control, self.CHAIN_CLASSES)
        self.write_chains()
        self.write_rank()

    def _cleanup(self):
        regression_check.DESC_DIR = self._saved_desc
        regression_check.DERIVED = self._saved_derived
        surface_cov.load_targets = self._saved_load
        for name in sorted(os.listdir(self.dir), reverse=True):
            path = os.path.join(self.dir, name)
            if os.path.isdir(path):
                for inner in os.listdir(path):
                    os.remove(os.path.join(path, inner))
                os.rmdir(path)
            else:
                os.remove(path)
        os.rmdir(self.dir)

    # -- the denominator -------------------------------------------------

    def fake_load_targets(self):
        targets = {}
        for handler in self.control:
            targets[surface_cov.CONTROL_PREFIX + handler] = {
                "family": "control", "variant": handler}
        for klass in self.CHAIN_CLASSES:
            targets[surface_cov.ALLOC_PREFIX + klass] = {
                "family": "alloc", "variant": klass}
        return targets, {}, {"driver_version": "610.57.04"}

    # -- the artefacts ---------------------------------------------------

    def write_descriptions(self, handlers, classes):
        lines = []
        for handler in handlers:
            lines.append("ioctl$%s%s(fd fd_nvidiactl, cmd const[0xc020462a], "
                         "arg ptr[in, NVOS54_PARAMETERS])"
                         % (surface_cov.CONTROL_PREFIX, handler))
        for klass in classes:
            lines.append("ioctl$%s%s(fd fd_nv, cmd const[0xc030462b], "
                         "arg ptr[in, NVOS64_PARAMETERS])"
                         % (surface_cov.ALLOC_PREFIX, klass))
        with open(os.path.join(self.desc, "nvidia_ctrl.txt"), "w",
                  encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(lines) + "\n")

    def write_chains(self, chained=None, unresolved=None, steps=None,
                     schema="gspwn.rm-chains/1", drop_unresolved=False):
        chained = self.HANDLERS[:2] if chained is None else chained
        unresolved = [self.HANDLERS[2]] if unresolved is None else unresolved
        steps = self.CHAIN_CLASSES if steps is None else steps
        doc = {
            "schema": schema,
            "chains": [{
                "internal_class": "Subdevice",
                "chain": [{"external_class": c} for c in steps],
                "commands": [{"handler": h, "method_id": "0x0"}
                             for h in chained],
            }],
            "unresolved_owning_classes": [{
                "owning_class": "Memory",
                "reason": "no RS_ENTRY row for this class",
                "commands": list(unresolved),
            }],
        }
        if drop_unresolved:
            del doc["unresolved_owning_classes"]
        self.write_json(self.chains_path, doc)

    def write_rank(self, handlers=None, schema="gspwn.rm-control-rank/1"):
        handlers = self.control if handlers is None else handlers
        self.write_json(self.rank_path, {
            "schema": schema,
            "commands": [{"handler": h, "rank": i + 1}
                         for i, h in enumerate(handlers)],
        })

    @staticmethod
    def write_json(path, doc):
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(doc, handle, indent=1, sort_keys=True)

    # -- the runner ------------------------------------------------------

    def run_derived(self):
        """-> (exit code, everything the check printed)."""
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = regression_check.check_derived()
        return code, buffer.getvalue()


class TestDerivedTracksTheControlInventory(DerivedFixture):
    """`derived` fails when a driver bump moves the control inventory and the
    two artefacts derived from it are left as they were.

    Nothing in CI runs tools/object_graph.py chains or tools/ctrl_rank.py
    rank. tools/trace2seed.py chains reads rm-chains.json to build every
    chain-shaped program and tools/syzlang_gen.py emit reads
    rm-control-rank.json for the order it emits the control family in, so both
    go stale silently and the first report is a run-time one, on the target.
    """

    def test_artefacts_that_match_the_inventory_pass(self):
        code, out = self.run_derived()
        self.assertEqual(code, 0)
        self.assertIn("derived: OK", out)

    def test_the_committed_artefacts_match_the_committed_inventory(self):
        regression_check.DESC_DIR = self._saved_desc
        regression_check.DERIVED = self._saved_derived
        surface_cov.load_targets = self._saved_load
        code, out = self.run_derived()
        self.assertEqual(code, 0, out)
        self.assertIn("rm-chains.json", out)
        self.assertIn("rm-control-rank.json", out)

    def test_a_chain_naming_a_command_the_inventory_dropped_fails(self):
        self.control = self.HANDLERS[:2]
        self.write_descriptions(self.control, self.CHAIN_CLASSES)
        self.write_rank(self.control)
        code, out = self.run_derived()
        self.assertEqual(code, 1)
        self.assertIn("rm-chains.json names 1 control command", out)
        self.assertIn(self.HANDLERS[2], out)

    def test_a_command_the_inventory_gained_is_missing_from_the_chains(self):
        self.control = self.HANDLERS + ["subdeviceCtrlCmdGpuGetEngines"]
        self.write_descriptions(self.control, self.CHAIN_CLASSES)
        self.write_rank(self.control)
        code, out = self.run_derived()
        self.assertEqual(code, 1)
        self.assertIn("appear nowhere in rm-chains.json", out)
        self.assertIn("NV_ESC_RM_CONTROL_subdeviceCtrlCmdGpuGetEngines", out)

    def test_a_ranking_that_lost_a_command_fails_naming_it(self):
        self.write_rank(self.control[:2])
        code, out = self.run_derived()
        self.assertEqual(code, 1)
        self.assertIn("appear nowhere in rm-control-rank.json", out)
        self.assertIn(self.HANDLERS[2], out)

    def test_a_ranking_naming_a_command_the_inventory_dropped_fails(self):
        self.write_rank(self.control + ["subdeviceCtrlCmdRetired"])
        code, out = self.run_derived()
        self.assertEqual(code, 1)
        self.assertIn("rm-control-rank.json names 1 control command", out)
        self.assertIn("subdeviceCtrlCmdRetired", out)

    def test_a_command_only_under_the_unresolved_block_still_counts(self):
        """The 15 commands of Memory and ProfilerBase appear under no chain
        record at all, so an account that scans the records alone loses them
        and reports the inventory as short by 15."""
        self.write_chains(chained=self.HANDLERS[:1],
                          unresolved=self.HANDLERS[1:])
        code, out = self.run_derived()
        self.assertEqual(code, 0, out)

    def test_dropping_the_unresolved_block_exits_2(self):
        self.write_chains(drop_unresolved=True)
        with self.assertRaises(regression_check.CheckInput) as caught:
            self.run_derived()
        self.assertIn("unresolved_owning_classes", str(caught.exception))

    def test_an_undeclared_chain_step_fails(self):
        """A chain step whose allocation variant no description declares emits
        a program syz-db rejects at the first line of its prologue."""
        self.write_chains(steps=self.CHAIN_CLASSES + ["NV20_SUBDEVICE_0"])
        code, out = self.run_derived()
        self.assertEqual(code, 1)
        self.assertIn("implies 1 call name(s) no description declares", out)
        self.assertIn("NV_ESC_RM_ALLOC_NV20_SUBDEVICE_0", out)

    def test_an_undeclared_command_is_reported_as_undeclared(self):
        self.control.append("subdeviceCtrlCmdUndeclared")
        self.write_chains(chained=self.HANDLERS[:2]
                          + ["subdeviceCtrlCmdUndeclared"])
        self.write_rank(self.control)
        code, out = self.run_derived()
        self.assertEqual(code, 1)
        self.assertIn("NV_ESC_RM_CONTROL_subdeviceCtrlCmdUndeclared", out)

    def test_the_report_names_the_command_that_regenerates_the_artefact(self):
        self.write_rank(self.control[:1])
        _code, out = self.run_derived()
        self.assertIn("Regenerate with `tools/ctrl_rank.py rank`.", out)

    def test_both_artefacts_are_reported_in_one_run(self):
        self.write_chains(chained=self.HANDLERS[:1], unresolved=[])
        self.write_rank(self.control[:1])
        code, out = self.run_derived()
        self.assertEqual(code, 1)
        self.assertIn("rm-chains.json", out)
        self.assertIn("rm-control-rank.json", out)
        self.assertEqual(out.count("Regenerate with"), 2)


class TestDerivedRefusesAnArtefactItCannotRead(DerivedFixture):
    """Exit 2 covers every input the check cannot parse as what it claims to
    be, so a checkout missing an artefact never reads as a passing run."""

    def test_an_absent_artefact_exits_2(self):
        os.remove(self.chains_path)
        with self.assertRaises(regression_check.CheckInput) as caught:
            self.run_derived()
        self.assertIn("tools/object_graph.py chains", str(caught.exception))

    def test_a_schema_stamp_the_check_does_not_read_exits_2(self):
        self.write_chains(schema="gspwn.rm-chains/2")
        with self.assertRaises(regression_check.CheckInput) as caught:
            self.run_derived()
        self.assertIn("gspwn.rm-chains/2", str(caught.exception))

    def test_an_empty_records_array_exits_2(self):
        self.write_json(self.rank_path, {"schema": "gspwn.rm-control-rank/1",
                                         "commands": []})
        with self.assertRaises(regression_check.CheckInput) as caught:
            self.run_derived()
        self.assertIn("reads as a clean run", str(caught.exception))

    def test_a_record_missing_the_field_the_check_joins_on_exits_2(self):
        self.write_json(self.rank_path, {
            "schema": "gspwn.rm-control-rank/1",
            "commands": [{"rank": 1}]})
        with self.assertRaises(regression_check.CheckInput) as caught:
            self.run_derived()
        self.assertIn("commands[0] carries no `handler`",
                      str(caught.exception))

    def test_malformed_json_exits_2(self):
        with open(self.chains_path, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        with self.assertRaises(regression_check.CheckInput):
            self.run_derived()

    def test_an_unreadable_denominator_exits_2(self):
        def refuse():
            raise surface_cov.SurfaceError("the RM control inventory is absent")
        surface_cov.load_targets = refuse
        with self.assertRaises(regression_check.CheckInput) as caught:
            self.run_derived()
        self.assertIn("control inventory", str(caught.exception))

    def test_the_subcommand_is_registered_and_runs_under_all(self):
        self.assertIn("derived", regression_check.CHECKS)
        self.assertIs(regression_check.CHECKS["derived"],
                      regression_check.check_derived)
        ran = []
        saved = dict(regression_check.CHECKS)
        try:
            for name in saved:
                regression_check.CHECKS[name] = (
                    lambda n=name: (ran.append(n), 0)[1])
            regression_check.CHECKS["derived"] = lambda: (ran.append(
                "derived"), 1)[1]
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = regression_check.main(["all"])
        finally:
            regression_check.CHECKS.clear()
            regression_check.CHECKS.update(saved)
        # Every registered check, read from the registry, so adding one to
        # CHECKS without adding it to the CI workflow is caught by
        # test_the_workflow_runs_the_check_on_every_push and not by an
        # unrelated list going out of date here.
        self.assertEqual(sorted(ran), sorted(saved))
        self.assertIn("derived", ran)
        self.assertEqual(code, 1)


class TestNameClosureBeatsTheDigestComparison(DerivedFixture):
    """Why `derived` compares names and not the digest generation.json records.

    descriptions/generation.json records the sha256 of the ranking
    that ordered the emitted set, under generated_from.ctrl_rank. Comparing it
    against the file on disk is the obvious alternative check, and it passes on
    the defect this check exists for: the ranking is left untouched across a
    driver bump, so the digest recorded at the last emission still matches it.
    """

    def digest(self, path):
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()

    def test_the_digest_still_matches_a_ranking_the_bump_left_behind(self):
        recorded = self.digest(self.rank_path)
        # The driver bump: the inventory gains a command and the description
        # set is regenerated. Nothing rewrites the ranking.
        self.control = self.HANDLERS + ["subdeviceCtrlCmdGpuGetEngines"]
        self.write_descriptions(self.control, self.CHAIN_CLASSES)
        self.assertEqual(self.digest(self.rank_path), recorded)
        code, out = self.run_derived()
        self.assertEqual(code, 1)
        self.assertIn("appear nowhere in rm-control-rank.json", out)

    def test_the_committed_digest_matches_the_committed_ranking(self):
        """The state the digest comparison would report, on the real files."""
        generation = os.path.join(self._saved_desc, "generation.json")
        with open(generation, encoding="utf-8") as handle:
            recorded = json.load(handle)["generated_from"]["ctrl_rank"]
        self.assertEqual(recorded["sha256"],
                         self.digest(regression_check.CTRL_RANK))

    def test_name_closure_does_not_see_a_reordered_ranking(self):
        """What the digest catches and this check does not: a ranking rebuilt
        after the emission, same commands, different order. Reported here so
        the gap is recorded rather than assumed absent."""
        before = self.digest(self.rank_path)
        self.write_rank(list(reversed(self.control)))
        self.assertNotEqual(self.digest(self.rank_path), before)
        code, _out = self.run_derived()
        self.assertEqual(code, 0)


class TestExtractWritesAtomicallyAndInOneLineEnding(unittest.TestCase):
    """tools/object_graph.py extract writes rm-object-graph.json, which
    surface_cov.load_targets, syzlang_gen and cve_patch_map all read as input.

    A plain open truncates the target before the first byte of the new content
    lands, so an interrupted run leaves those three reading a JSON prefix. The
    same write is the repository's only artefact producer that emitted CRLF on
    a Windows run and LF under WSL over identical source.
    """

    TABLE = """
static const RS_ENTRY g_resourceClassInfo[] =
{
    RS_ENTRY(
        /* External Class         */ NV01_ROOT,
        /* Internal Class         */ RmClientResource,
        /* Multi-Instance         */ NV_TRUE,
        /* Parents                */ RS_ROOT_OBJECT,
        /* Alloc Param Info       */ RS_REQUIRED(NvHandle),
        /* Resource Free Priority */ RS_FREE_PRIORITY_DEFAULT,
        /* Flags                  */ RS_FLAGS_ALLOC_NON_PRIVILEGED,
        /* Required Access Rights */ RS_ACCESS_NONE
    )
    RS_ENTRY(
        /* External Class         */ NV01_DEVICE_0,
        /* Internal Class         */ Device,
        /* Multi-Instance         */ NV_TRUE,
        /* Parents                */ RS_LIST(classId(RmClientResource)),
        /* Alloc Param Info       */ RS_REQUIRED(NV0080_ALLOC_PARAMETERS),
        /* Resource Free Priority */ RS_FREE_PRIORITY_DEFAULT,
        /* Flags                  */ RS_FLAGS_ALLOC_NON_PRIVILEGED,
        /* Required Access Rights */ RS_ACCESS_NONE
    )
};
"""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.src = os.path.join(self.dir, "src-tree")
        table = os.path.join(self.src, "src", "nvidia", "src", "kernel",
                             "rmapi")
        os.makedirs(table)
        with open(os.path.join(table, "resource_list.h"), "w",
                  encoding="utf-8", newline="\n") as handle:
            handle.write(self.TABLE)
        with open(os.path.join(self.src, "version.mk"), "w",
                  encoding="utf-8", newline="\n") as handle:
            handle.write("NVIDIA_VERSION = 610.57.04\n")
        self.out = os.path.join(self.dir, "surface", "rm-object-graph.json")
        self.addCleanup(self.wipe)

    def wipe(self):
        for root, dirs, names in os.walk(self.dir, topdown=False):
            for name in names:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.dir)

    def extract(self, out=None):
        args = types.SimpleNamespace(src=self.src, out=out or self.out)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = object_graph.cmd_extract(args)
        return code, buffer.getvalue()

    def test_the_records_are_written_and_readable(self):
        self.assertEqual(self.extract()[0], 0)
        with open(self.out, encoding="utf-8") as handle:
            doc = json.load(handle)
        self.assertEqual(doc["record_count"], 2)
        self.assertEqual(doc["source"]["driver_version"], "610.57.04")

    def test_a_failure_mid_write_leaves_the_previous_artefact_intact(self):
        self.extract()
        with open(self.out, "rb") as handle:
            good = handle.read()

        saved = object_graph.json.dump

        def die(*_args, **_kwargs):
            raise OSError(28, "No space left on device")

        object_graph.json.dump = die
        try:
            with self.assertRaises(OSError):
                self.extract()
        finally:
            object_graph.json.dump = saved
        with open(self.out, "rb") as handle:
            self.assertEqual(handle.read(), good)

    def test_a_failure_mid_write_leaves_no_temp_file_behind(self):
        saved = object_graph.json.dump

        def die(*_args, **_kwargs):
            raise OSError(28, "No space left on device")

        object_graph.json.dump = die
        try:
            with self.assertRaises(OSError):
                self.extract()
        finally:
            object_graph.json.dump = saved
        self.assertEqual([n for n in os.listdir(os.path.dirname(self.out))
                          if n.endswith(".tmp")], [])

    def test_the_target_is_replaced_and_never_truncated_in_place(self):
        seen = []
        saved = object_graph.os.replace

        def watch(src, dst):
            seen.append((os.path.basename(src), os.path.basename(dst)))
            return saved(src, dst)

        object_graph.os.replace = watch
        try:
            self.extract()
        finally:
            object_graph.os.replace = saved
        self.assertEqual(seen, [("rm-object-graph.json.tmp",
                                 "rm-object-graph.json")])

    def test_the_written_bytes_carry_no_carriage_return(self):
        self.extract()
        with open(self.out, "rb") as handle:
            self.assertNotIn(b"\r", handle.read())

    def test_the_recorded_table_path_uses_forward_slashes(self):
        self.extract()
        with open(self.out, encoding="utf-8") as handle:
            path = json.load(handle)["source"]["path"]
        self.assertNotIn("\\", path)
        self.assertTrue(path.endswith(
            "src/nvidia/src/kernel/rmapi/resource_list.h"), path)

    def test_two_runs_over_the_same_source_write_the_same_bytes(self):
        self.extract()
        with open(self.out, "rb") as handle:
            first = handle.read()
        second_path = os.path.join(self.dir, "surface", "again.json")
        self.extract(out=second_path)
        with open(second_path, "rb") as handle:
            self.assertEqual(handle.read(), first)

    def test_the_output_directory_is_created_when_it_is_absent(self):
        nested = os.path.join(self.dir, "new", "deeper", "graph.json")
        self.assertEqual(self.extract(out=nested)[0], 0)
        self.assertTrue(os.path.isfile(nested))

    def test_the_committed_artefact_is_lf_with_a_forward_slash_path(self):
        """The form the repository's .gitattributes declares for every file
        and every other committed artefact already carries."""
        with open(surface_cov.OBJ_GRAPH, "rb") as handle:
            raw = handle.read()
        self.assertNotIn(b"\r", raw)
        doc = json.loads(raw.decode("utf-8"))
        self.assertNotIn("\\", doc["source"]["path"])
        self.assertEqual(doc["source"]["driver_version"], "610.57.04")

    def test_every_reader_of_the_committed_artefact_still_loads_it(self):
        targets, _excluded, meta = surface_cov.load_targets()
        self.assertEqual(len(targets), 764)
        self.assertEqual(meta.get("driver_version"), "610.57.04")


# ---------------------------------------------------------------------------
# The generated surface reference pages, tools/refgen.py, and the fifth CI
# check that keeps them from drifting, tools/regression_check.py pages.
#
# Every class here reads the committed artefacts under surface and
# the committed pages under docs/src/content/docs/reference/surface. A
# checkout without them fails these tests, which is the correct signal: the CI
# step that compares the same files cannot run either.
#
# test_the_committed_pages_match_the_committed_artefacts is the one case no
# mutation of refgen.py can leave passing, because any change to the renderer
# moves the generated bytes away from the committed ones. That is the point of
# it: it is the same comparison CI makes.
# ---------------------------------------------------------------------------


# A regular-expression word boundary, named because the two-character
# escape is easy to lose in an edit and a lost one turns the CVE
# exclusion test into a test that matches nothing.
BOUNDARY = chr(92) + "b"


def _read_json(path):
    """-> one committed JSON artefact, with the handle closed."""
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


class RefgenFixture(unittest.TestCase):
    """The five pages rendered once, and a scratch directory to write into.

    Rendering reads roughly 2 MB of JSON, so it happens once per class and
    every case works from the result. Nothing here writes to the real
    documentation tree.
    """

    @classmethod
    def setUpClass(cls):
        cls.pages, cls.rows = refgen.render()

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="refgen-test-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.out = os.path.join(self.dir, "surface")

    def committed(self, name):
        """-> the bytes of one committed page."""
        with open(os.path.join(refgen.DEFAULT_OUT, name), "rb") as handle:
            return handle.read()

    def write_pages(self, pages=None):
        """Write a full set into the scratch directory and point the check at
        it."""
        refgen.write(pages or self.pages, self.out)
        old = _patched(PAGES_DIR=self.out)
        self.addCleanup(lambda: _patched(**old))
        return self.out

    def run_pages(self):
        """-> (exit code, everything the check printed)."""
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = regression_check.check_pages()
        return code, buffer.getvalue()


class TestRefgenOutputIsDeterministic(RefgenFixture):
    """Two runs over one set of artefacts produce byte-identical files.

    The staleness check regenerates and diffs on every push, so any value
    varying between runs, a timestamp, a set iteration order or an absolute
    path, fails CI on a checkout nobody touched.
    """

    def test_two_renders_produce_the_same_bytes(self):
        again, _rows = refgen.render()
        self.assertEqual(sorted(again), sorted(self.pages))
        for name in sorted(self.pages):
            self.assertEqual(again[name], self.pages[name], name)

    def test_two_writes_produce_the_same_files(self):
        first = os.path.join(self.dir, "first")
        second = os.path.join(self.dir, "second")
        refgen.write(self.pages, first)
        refgen.write(refgen.render()[0], second)
        for name in sorted(self.pages):
            with open(os.path.join(first, name), "rb") as handle:
                left = handle.read()
            with open(os.path.join(second, name), "rb") as handle:
                right = handle.read()
            self.assertEqual(left, right, name)

    def test_no_page_carries_a_carriage_return(self):
        """The form .gitattributes declares and every committed artefact
        already carries. A page written with CRLF differs from the committed
        LF copy on its first line."""
        refgen.write(self.pages, self.out)
        for name in sorted(self.pages):
            with open(os.path.join(self.out, name), "rb") as handle:
                self.assertNotIn(b"\r", handle.read(), name)

    def test_no_page_names_a_path_from_the_machine_that_ran_the_tool(self):
        """An absolute path or a backslash separator in the output makes the
        bytes depend on the checkout location, so the check would fail for
        everyone except whoever last regenerated."""
        for name, text in sorted(self.pages.items()):
            self.assertNotIn(regression_check.REPO_ROOT, text, name)
            self.assertNotIn("\\", text, name)

    def test_the_writer_leaves_no_temporary_file_behind(self):
        """A stray .tmp inside the content directory is a page Starlight
        tries to build."""
        refgen.write(self.pages, self.out)
        self.assertEqual(sorted(os.listdir(self.out)), sorted(self.pages))


class TestRefgenRendersTheMeasuredCounts(RefgenFixture):
    """The pages state what the artefacts measure.

    The three control counts are the ones a reader is most likely to confuse,
    because they are close together and every one of them is correct for a
    different question.
    """

    def test_the_control_page_states_all_three_command_counts(self):
        text = self.pages["control-commands.md"]
        rank = _read_json(regression_check.CTRL_RANK)
        graph = _read_json(surface_cov.OBJ_GRAPH)
        internal = {r["internal_class"] for r in graph["records"]}
        named = len(rank["commands"])
        with_entry = sum(1 for c in rank["commands"]
                         if c["owning_class"] in internal)
        with_chain = sum(1 for c in rank["commands"]
                         if c.get("chain_length") is not None)
        self.assertEqual((named, with_entry, with_chain), (531, 516, 514))
        self.assertIn("| Naming an owning class | %d |" % named, text)
        self.assertIn("| Whose owning class has an `RS_ENTRY` row | %d |"
                      % with_entry, text)
        self.assertIn("| With a chain an unprivileged process can build | %d |"
                      % with_chain, text)

    def test_the_control_page_states_the_no_chain_reason_split(self):
        text = self.pages["control-commands.md"]
        self.assertIn("| `null`, a chain exists | 514 |", text)
        self.assertIn("| `no RS_ENTRY row for this class` | 15 |", text)
        self.assertIn("| `every external class requires allocation "
                      "privilege` | 2 |", text)

    def test_the_control_page_carries_one_row_per_ranked_command(self):
        text = self.pages["control-commands.md"]
        rank = _read_json(regression_check.CTRL_RANK)
        self.assertEqual(self.rows["control-commands.md"],
                         len(rank["commands"]))
        for command in rank["commands"]:
            self.assertIn("| %d | `%s` |" % (command["rank"],
                                             command["handler"]), text)

    def test_the_control_page_states_the_excluded_populations(self):
        """Naming each population against its count is what keeps 1372 and
        531 from being read as the same measurement. The rows are checked
        whole, because a bare count appears again as a rank."""
        text = self.pages["control-commands.md"]
        summary = _read_json(surface_cov.CTRL_INV)["summary"]
        reach = summary["by_reachability"]
        rows = [
            ("Exported by the generated `_nvoc.c` tables",
             summary["methods"], "`methods`"),
            ("Callable only from an internal RM client",
             reach["internal"], "`reachability` = `internal`"),
            ("Callable only from kernel space",
             reach["kernel_only"], "`reachability` = `kernel_only`"),
            ("Gated on a privileged client",
             reach["privileged"], "`reachability` = `privileged`"),
            ("Routed to GSP, so the CPU-side handler is compiled out",
             reach["non_privileged"] - 531, "`handler_compiled_out`"),
            ("Targetable", 531, "(the set below)"),
        ]
        self.assertEqual(
            [row[1] for row in rows], [1372, 241, 114, 250, 236, 531])
        for label, count, field in rows:
            self.assertIn("| %s | %d | %s |" % (label, count, field),
                          text)

    def test_the_escapes_page_carries_every_dispatched_and_dead_escape(self):
        text = self.pages["escapes.md"]
        inv = _read_json(surface_cov.IOCTL_INV)
        rm = inv["nodes"][0]["commands"]
        self.assertEqual(len(rm), 34)
        self.assertEqual(len(inv["dead_escapes"]), 3)
        # Four tables on this page open a row with an escape name, so the
        # dispatched one is sliced out by its headings first.
        section = text.split("## Dispatched escapes")[1].split(
            "## Multiplexer selectors")[0]
        rows = {line.split("|")[1].strip(): line
                for line in section.splitlines()
                if line.startswith("| `NV_ESC")}
        for command in rm:
            row = rows["`%s`" % command["name"]]
            self.assertIn("%d (`0x%02x`)" % (command["nr"], command["nr"]),
                          row)
            self.assertIn("`%s`" % command["param_struct"], row)
            self.assertIn("| %d |" % command["param_size"], row)
        for name in inv["dead_escapes"]:
            self.assertIn("| `%s` | declared, no dispatch site |" % name, text)

    def test_the_escapes_page_names_each_multiplexer_selector_field(self):
        text = self.pages["escapes.md"]
        muxes = _read_json(regression_check.IOCTL_MAP)[
            refgen.MAP_MULTIPLEXER_KEY]["requests"]
        self.assertEqual(len(muxes), 3)
        for request, record in sorted(muxes.items()):
            self.assertIn("| `%s` | `%s` | `%s` | `%s` |"
                          % (request, record["escape"],
                             record["param_struct"],
                             record["selector_field"]), text)

    def test_the_allocation_page_carries_every_class_and_chain(self):
        text = self.pages["allocation-classes.md"]
        targets, _excluded, _meta = surface_cov.load_targets()
        classes = sorted(t["external_class"] for t in targets.values()
                         if t["family"] == "alloc")
        chains = _read_json(regression_check.CHAINS)
        self.assertEqual(len(classes), 155)
        self.assertEqual(len(chains["chains"]), 98)
        for name in classes:
            self.assertIn("| `%s` |" % name, text)
        for chain in chains["chains"]:
            self.assertIn("| `%s` |" % chain["internal_class"], text)

    def test_the_allocation_page_carries_the_reach_curve_and_the_unresolved(
            self):
        text = self.pages["allocation-classes.md"]
        chains = _read_json(regression_check.CHAINS)
        for index, row in enumerate(chains["cumulative_reach"]):
            self.assertIn("| %d | `%s` | %d | %d | %d |"
                          % (index + 1, row["class_added"], row["commands"],
                             row["allocations"], row["new_allocations"]),
                          text)
        for row in chains["unresolved_owning_classes"]:
            self.assertIn("| `%s` | %d | `%s` |"
                          % (row["owning_class"], row["command_count"],
                             row["reason"]), text)

    def test_the_cve_page_carries_the_61_classified_k_and_nothing_else(self):
        text = self.pages["driver-cves.md"]
        doc = _read_json(refgen.PRIOR_CVES)
        keep = [r for r in doc["records"] if r["classification"] == "K"]
        drop = [r for r in doc["records"] if r["classification"] != "K"]
        self.assertEqual((len(keep), len(drop)), (61, 180))
        for record in keep:
            self.assertIn(record["cve"], text)
        for record in drop:
            # Matched with a trailing word boundary, because
            # CVE-2022-3161 is a prefix of CVE-2022-31615 and a plain
            # containment test would read the second as the first.
            pattern = re.escape(record["cve"]) + BOUNDARY
            self.assertIsNone(re.search(pattern, text), record["cve"])

    def test_the_condensed_bulletin_text_is_a_substring_of_the_original(self):
        """The register exempts a verbatim reproduction and forbids editing
        one. Every cell has to be text NVIDIA published, cut at both ends and
        changed nowhere."""
        doc = _read_json(refgen.PRIOR_CVES)
        seen = 0
        for record in doc["records"]:
            if record["classification"] != "K":
                continue
            whole = record["component_as_nvidia_words_it"]
            condensed = refgen.condense(whole)
            self.assertTrue(condensed, record["cve"])
            self.assertIn(condensed, whole, record["cve"])
            self.assertIn(condensed, self.pages["driver-cves.md"],
                          record["cve"])
            seen += 1
        self.assertEqual(seen, 61)

    def test_every_page_names_its_producer_and_its_sources(self):
        for name, text in sorted(self.pages.items()):
            self.assertIn("Generated by `%s`" % refgen.TOOL, text, name)
            self.assertIn(refgen.CHECK, text, name)
            for source in refgen.PAGE_SOURCES.get(name, []):
                self.assertIn("`%s`" % source, text, name)

    def test_the_index_lists_every_page_with_its_record_count(self):
        text = self.pages["index.md"]
        for name in sorted(refgen.PAGE_SOURCES):
            title, slug, _summary = refgen.PAGE_TITLES[name]
            self.assertIn("[%s](/gspwn/reference/surface/%s/) | %d |"
                          % (title, slug, self.rows[name]), text)


class TestPagesCheckCatchesDrift(RefgenFixture):
    """`pages` fails when a page and the artefacts behind it disagree.

    A digest committed next to the pages would not catch the case this check
    exists for. Whoever edits a page is positioned to recompute the digest,
    and a digest of a stale page still matches that stale page. Regenerating
    and diffing compares the page against the artefacts every time.
    """

    def test_freshly_generated_pages_pass(self):
        self.write_pages()
        code, out = self.run_pages()
        self.assertEqual(code, 0, out)
        self.assertIn("pages: OK", out)

    def test_the_committed_pages_match_the_committed_artefacts(self):
        """The comparison CI makes, against the real documentation tree."""
        code, out = self.run_pages()
        self.assertEqual(code, 0, out)
        self.assertIn("pages: OK", out)

    def test_a_hand_edited_page_fails_and_names_the_page(self):
        self.write_pages()
        target = os.path.join(self.out, "control-commands.md")
        with open(target, "r", encoding="utf-8") as handle:
            text = handle.read()
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text.replace(
                "| Whose owning class has an `RS_ENTRY` row | 516 |",
                "| Whose owning class has an `RS_ENTRY` row | 531 |"))
        code, out = self.run_pages()
        self.assertEqual(code, 1)
        self.assertIn("control-commands.md: the committed page and the "
                      "regenerated one differ", out)
        self.assertIn("first difference at line", out)
        self.assertIn("committed   | Whose owning class has an `RS_ENTRY` "
                      "row | 531 |", out)
        self.assertIn("regenerated | Whose owning class has an `RS_ENTRY` "
                      "row | 516 |", out)
        self.assertIn(refgen.TOOL, out)

    def test_an_edit_of_the_same_length_still_fails(self):
        """A byte count comparison passes on this one. The check compares the
        bytes themselves."""
        self.write_pages()
        target = os.path.join(self.out, "escapes.md")
        with open(target, "rb") as handle:
            raw = handle.read()
        with open(target, "wb") as handle:
            handle.write(raw.replace(b"`NV_ESC_RM_FREE`", b"`NV_ESC_RM_XXXX`"))
        with open(target, "rb") as handle:
            self.assertEqual(len(handle.read()), len(raw))
        code, out = self.run_pages()
        self.assertEqual(code, 1)
        self.assertIn("escapes.md", out)

    def test_a_page_rewritten_with_crlf_endings_fails(self):
        self.write_pages()
        target = os.path.join(self.out, "index.md")
        with open(target, "rb") as handle:
            raw = handle.read()
        with open(target, "wb") as handle:
            handle.write(raw.replace(b"\n", b"\r\n"))
        code, out = self.run_pages()
        self.assertEqual(code, 1)
        self.assertIn("index.md", out)

    def test_a_missing_page_fails_and_names_the_path(self):
        self.write_pages()
        os.remove(os.path.join(self.out, "driver-cves.md"))
        code, out = self.run_pages()
        self.assertEqual(code, 1)
        self.assertIn("no committed page at docs/src/content/docs/reference/"
                      "surface/driver-cves.md", out)

    def test_a_page_the_tool_no_longer_produces_fails_as_an_orphan(self):
        """A renamed page leaves the old one behind, and Starlight goes on
        building it from artefacts nothing regenerates."""
        self.write_pages()
        with open(os.path.join(self.out, "uvm-commands.md"), "w",
                  encoding="utf-8", newline="\n") as handle:
            handle.write("---\ntitle: Leftover\n---\n")
        code, out = self.run_pages()
        self.assertEqual(code, 1)
        self.assertIn("uvm-commands.md: a committed page tools/refgen.py no "
                      "longer produces", out)

    def test_an_unreadable_artefact_exits_2_and_never_1(self):
        """The check has no opinion to report about a page it could not
        render, so a missing input is the input code and not the offence
        code."""
        saved = refgen.render

        def broken():
            raise refgen.RefgenError("surface/rm-chains.json: "
                                     "No such file or directory")
        refgen.render = broken
        try:
            with self.assertRaises(regression_check.CheckInput) as caught:
                regression_check.check_pages()
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = regression_check.main(["pages"])
        finally:
            refgen.render = saved
        self.assertIn("rm-chains.json", str(caught.exception))
        self.assertEqual(code, 2)

    def test_pages_is_registered_and_all_runs_it(self):
        self.assertIn("pages", regression_check.CHECKS)
        self.assertIs(regression_check.CHECKS["pages"],
                      regression_check.check_pages)
        parser = regression_check.build_parser()
        self.assertEqual(parser.parse_args(["pages"]).check, "pages")

        ran = []
        saved = dict(regression_check.CHECKS)
        try:
            for name in list(regression_check.CHECKS):
                regression_check.CHECKS[name] = (
                    lambda n=name: (ran.append(n), 0)[1])
            with redirect_stdout(io.StringIO()):
                code = regression_check.main(["all"])
        finally:
            regression_check.CHECKS.clear()
            regression_check.CHECKS.update(saved)
        self.assertEqual(code, 0)
        self.assertIn("pages", ran)

    def test_the_workflow_runs_the_check_on_every_push(self):
        """The other four checks are CI steps and this one has to be as well,
        or a page drifts until someone runs the tool by hand."""
        path = os.path.join(regression_check.REPO_ROOT, ".github", "workflows",
                            "selftest.yml")
        with open(path, encoding="utf-8") as handle:
            workflow = handle.read()
        for name in sorted(regression_check.CHECKS):
            self.assertIn("python3 tools/regression_check.py %s" % name,
                          workflow)


class TestCveJoinAgainstThePatchMining(RefgenFixture):
    """driver-cves.md joins the classified record to the patch-mining output.

    Without the join a row states a weakness class and no location in the
    driver. With it, a row states how far reading the fixing diff got, which
    for 45 of the 61 is "one patch set answers for several disclosures", and
    that limit is the fact a reader needs before trusting any function name.

    test_the_two_cve_artefacts_describe_one_population asserts a property of
    the two committed artefacts and no mutation of refgen.py can make it fail.
    It names the cause when a checkout carries a regenerated prior-cves.json
    and a stale cve-hotspots.json, which is the state the load-time guard
    refuses; that guard has its own case below.
    """

    @classmethod
    def setUpClass(cls):
        super(TestCveJoinAgainstThePatchMining, cls).setUpClass()
        cls.hotspots = _read_json(refgen.HOTSPOTS)
        cls.text = cls.pages["driver-cves.md"]

    def test_the_two_cve_artefacts_describe_one_population(self):
        classified = {r["cve"] for r in _read_json(refgen.PRIOR_CVES)["records"]
                      if r["classification"] == "K"}
        mined = {r["cve"] for r in self.hotspots["records"]}
        self.assertEqual(len(mined), 61)
        self.assertEqual(classified, mined)

    def test_the_page_names_the_patch_mining_output_as_a_source(self):
        self.assertIn("`surface/cve-hotspots.json`", self.text)
        self.assertIn("surface/cve-hotspots.json",
                      refgen.PAGE_SOURCES["driver-cves.md"])

    def test_the_verdict_counts_match_the_artefact(self):
        """Driven by the artefact's own verdict names, so a reading dropped
        from the tool leaves a verdict the page never explains."""
        counts = self.hotspots["summary"]["verdict_counts"]
        self.assertEqual(counts, {"located": 4, "plausible": 4,
                                  "not_located": 45, "unresolved": 8})
        self.assertEqual(sorted(n for n, _r in refgen.VERDICT_READINGS),
                         sorted(counts))
        for name in sorted(counts):
            self.assertIn("| `%s` | %d |" % (name, counts[name]), self.text)
        seen = {r["verdict"] for r in self.hotspots["records"]}
        self.assertEqual(seen, set(counts))

    def test_every_disclosure_carries_a_verdict_row(self):
        for record in self.hotspots["records"]:
            self.assertIn("| `%s` | `%s` |" % (record["cve"],
                                               record["verdict"]), self.text)

    def test_a_row_states_the_release_brackets_and_the_shared_patch_set(self):
        """45 of the 61 share a release with other disclosures, and the count
        of them is the reason no function can be attributed to one CVE."""
        checked = 0
        for record in self.hotspots["records"]:
            for pair in record["tag_pairs"]:
                self.assertIn("`%s..%s`" % (pair["from"], pair["to"]),
                              self.text)
                checked += 1
        self.assertEqual(checked, 124)
        shared = max(len(v) for r in self.hotspots["records"]
                     for v in r["shared_patch_set"].values())
        self.assertEqual(shared, 17)

    def test_the_located_fix_functions_are_rendered_with_their_file(self):
        rows = 0
        for record in self.hotspots["records"]:
            for qualified in record["fix_functions"]:
                path, _sep, name = qualified.rpartition("::")
                self.assertIn("| `%s` | `%s` | `%s` | `%s` |"
                              % (record["cve"], record["verdict"], path, name),
                              self.text)
                rows += 1
        self.assertEqual(rows, 13)

    def test_only_the_narrowed_disclosures_name_a_function(self):
        """The 53 the mining could not narrow appear in no row of the located
        table, because the artefact's own verdict says the diff attributes no
        hunk to any one of them."""
        named = [r for r in self.hotspots["records"] if r["fix_functions"]]
        self.assertEqual(len(named), 8)
        for record in named:
            self.assertIn(record["verdict"], ("located", "plausible"))
        section = self.text.split("## Located fix functions")[1].split(
            "## Reachability of the located paths")[0]
        absent = 0
        for record in self.hotspots["records"]:
            if record["verdict"] in ("not_located", "unresolved"):
                self.assertNotIn(record["cve"], section, record["cve"])
                absent += 1
        self.assertEqual(absent, 53)

    def test_the_reachability_notes_are_reproduced_whole(self):
        notes = [r for r in self.hotspots["records"]
                 if r["reachability_note"]]
        self.assertEqual(len(notes), 8)
        for record in notes:
            self.assertIn("| `%s` | %s |" % (record["cve"],
                                             record["reachability_note"]),
                          self.text)

    def test_the_unresolved_reasons_are_reproduced_whole(self):
        reasons = [r for r in self.hotspots["records"]
                   if r["unresolved_reason"]]
        self.assertEqual(len(reasons), 8)
        for record in reasons:
            self.assertEqual(record["verdict"], "unresolved")
            self.assertIn("| `%s` | %s |" % (record["cve"],
                                             record["unresolved_reason"]),
                          self.text)

    def test_each_verdict_basis_is_written_once_and_keyed(self):
        """Bulletin 5415's basis answers for 19 disclosures. Repeating a
        627-character text 19 times is what the key table replaces."""
        keys, rows = refgen._basis_keys(self.hotspots["records"])
        self.assertEqual(len(rows), 19)
        self.assertEqual(sum(row[1] for row in rows), 53)
        self.assertEqual(rows[0][1], 19)
        for text, key in sorted(keys.items()):
            self.assertEqual(self.text.count(text), 1, key)
            self.assertIn("| %s | %d |" % (key, sum(
                1 for r in self.hotspots["records"]
                if r["verdict_basis"] == text)), self.text)

    def test_the_entry_point_table_skips_the_file_level_join(self):
        """An escape_file target is a file-level join, and the artefact's own
        note on that kind says it places the function on no single escape's
        path."""
        by_function = self.hotspots["hotspots"]["by_function"]
        wanted, skipped = [], []
        for function in by_function:
            kinds = {t["kind"] for t in function.get("targets") or []}
            if kinds & set(refgen.ENTRY_POINT_KINDS):
                wanted.append(function)
            elif kinds:
                skipped.append(function)
        self.assertEqual((len(wanted), len(skipped)), (16, 11))
        for function in wanted:
            self.assertIn("| `%s` | `%s` | %d |"
                          % (function["function"], function["file"],
                             function["releases"]), self.text)
        for function in skipped:
            self.assertNotIn("| `%s` | `%s` |"
                             % (function["function"], function["file"]),
                             self.text)

    def test_an_entry_point_row_states_the_surface_family(self):
        """A hot function handling a test-only or privileged command is not on
        the surface being fuzzed, and the row has to say so."""
        self.assertIn("| `UVM_TEST_NUMA_CHECK_AFFINITY` | (none) | (none) | "
                      "(none) | `uvm_test` |", self.text)
        self.assertEqual(self.text.count("(outside the model) |"), 4)
        family = refgen._family_lookup(refgen.load_all())
        self.assertEqual(
            family({"kind": "uvm_command",
                    "command": "UVM_TEST_NUMA_CHECK_AFFINITY"}), "uvm_test")
        self.assertIsNone(
            family({"kind": "rm_control", "method_id": "0x00000605"}))

    def test_a_divergent_cve_population_is_refused(self):
        """cve_patch_map.py chooses what to mine by reading prior-cves.json,
        so a population mismatch means one of the two was regenerated and the
        other was not. Rendering it would drop or invent rows in silence."""
        doc = _read_json(refgen.PRIOR_CVES)
        dropped = None
        for record in doc["records"]:
            if record["classification"] == "K" and dropped is None:
                dropped = record["cve"]
                record["classification"] = "out"
        path = os.path.join(self.dir, "prior-cves.json")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(doc, handle)
        saved = refgen.PRIOR_CVES
        refgen.PRIOR_CVES = path
        try:
            with self.assertRaises(refgen.RefgenError) as caught:
                refgen.load_all()
        finally:
            refgen.PRIOR_CVES = saved
        self.assertIn(dropped, str(caught.exception))
        self.assertIn("cve_patch_map.py", str(caught.exception))

    def test_a_patch_mining_artefact_of_another_schema_is_refused(self):
        doc = {"schema": "gspwn.cve-hotspots/2", "records": [{"cve": "x"}]}
        path = os.path.join(self.dir, "cve-hotspots.json")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(doc, handle)
        saved = refgen.HOTSPOTS
        refgen.HOTSPOTS = path
        try:
            with self.assertRaises(refgen.RefgenError) as caught:
                refgen.load_all()
        finally:
            refgen.HOTSPOTS = saved
        self.assertIn(refgen.HOTSPOTS_SCHEMA, str(caught.exception))
        self.assertIn("gspwn.cve-hotspots/2", str(caught.exception))




# ---------------------------------------------------------------------------
# Review wave 2, pipeline core. From tmp/tests2/core.py and tmp/fix/core.md:
# the completion ledger, the two-curve stop rule, the surface cadence and the
# coverage.csv header migration. 14 classes, 44 tests.
#
# Four of the 44 pass with the fixes reverted, by design. Each is the negative
# control for a test in the same class that discriminates, and each is marked
# as one where it stands.
# ---------------------------------------------------------------------------


class TestADeferredReasonDoesNotCloseItsTarget(StateTempMixin,
                                               unittest.TestCase):
    """B1. Seven reasons say a target cannot be reached. One says it can."""

    def setUp(self):
        super().setUp()
        self.ledger = os.path.join(self.tmp.name, "ledger.json")

    def account(self, key, reason, **kw):
        record = {"key": key, "variant": "NV_ESC_RM_CONTROL_%s" % key,
                  "family": "control", "reason": reason,
                  "detail": "written by the test"}
        if reason in ps.SURFACE_REASON_NEEDS_EVIDENCE:
            record["evidence"] = ["src/nvidia/x.c:1"]
        record.update(kw)
        return ps.set_surface_account(record, path=self.ledger,
                                      driver_version="610.57.04",
                                      targets_total=764)

    def test_a_deferred_target_is_not_counted_into_the_closing_union(self):
        verdict, counts, closed = ps.surface_completion(
            {"a"}, {"b", "c"}, 3, deferred={"b"})
        self.assertEqual(verdict, "incomplete")
        self.assertEqual(closed, {"a", "c"})
        self.assertEqual(counts["accounted"], 1)
        self.assertEqual(counts["deferred"], 1)
        self.assertEqual(counts["closed"], 2)

    def test_every_other_reason_still_closes_its_target(self):
        closing = [r for r in sorted(ps.SURFACE_REASON)
                   if r not in ps.SURFACE_REASON_DEFERRED]
        self.assertEqual(len(closing), 7)
        for reason in closing:
            _verdict, counts, closed = ps.surface_completion(
                set(), {"k"}, 1, deferred=set())
            self.assertEqual(closed, {"k"}, reason)
            self.assertEqual(counts["accounted"], 1, reason)

    def test_only_the_deferring_reason_lands_in_the_deferred_set(self):
        for i, reason in enumerate(sorted(ps.SURFACE_REASON)):
            self.account("k%d" % i, reason)
        every, deferred = ps.surface_ledger_keys(self.ledger, "610.57.04")
        self.assertEqual(len(every), len(ps.SURFACE_REASON))
        self.assertEqual(len(deferred), 1)
        row = ps.load_surface_ledger(self.ledger)["accounted"][deferred.pop()]
        self.assertIn(row["reason"], ps.SURFACE_REASON_DEFERRED)

    def test_a_deferred_target_reached_later_is_closed_by_the_execution(self):
        # The union still holds: the target was exercised, whatever the row
        # written for it in an earlier round says.
        verdict, counts, closed = ps.surface_completion(
            {"a"}, {"a"}, 1, deferred={"a"})
        self.assertEqual(verdict, "complete")
        self.assertEqual(closed, {"a"})
        self.assertEqual(counts["deferred"], 1)

    def test_a_ledger_of_deferrals_cannot_end_the_campaign(self):
        # The failure the fix exists to prevent: 400 targets named by the
        # corpus, 364 written off as put aside, and a stop reading "Nothing is
        # left to fuzz" over 364 reachable commands nobody fuzzed.
        exercised = {"t%d" % i for i in range(400)}
        deferred = {"t%d" % i for i in range(400, 764)}
        verdict, counts, _closed = ps.surface_completion(
            exercised, deferred, 764, deferred=deferred)
        self.assertEqual(verdict, "incomplete")
        self.assertEqual(counts["closed"], 400)
        with ps.transaction() as st:
            ps.end_round(st, verdict="growing",
                         surface={"verdict": verdict, "ledger": self.ledger,
                                  "exercised": counts["exercised"],
                                  "accounted": counts["accounted"],
                                  "deferred": counts["deferred"],
                                  "closed": counts["closed"],
                                  "total": counts["total"]})
        st = ps.load()
        self.assertIsNone(ps.surface_stop_reason(st))
        self.assertIsNone(ps.hard_cap_reason(st, max_rounds=10))
        self.assertEqual(ps.loop_decision(st, max_rounds=10)[0], "continue")

    def test_the_round_records_how_many_targets_were_put_aside(self):
        with ps.transaction() as st:
            ps.end_round(st, verdict="plateaued",
                         surface={"verdict": "incomplete", "exercised": 400,
                                  "accounted": 100, "deferred": 264,
                                  "closed": 500, "total": 764,
                                  "ledger": self.ledger})
        r = ps.load()["rounds"][-1]
        self.assertEqual(r["surface_deferred"], 264)
        _decision, reason = ps.loop_decision(ps.load(), max_rounds=10)
        self.assertIn("264 of them deliberately deferred", reason)


class TestRemovingAnAccountedRow(StateTempMixin, unittest.TestCase):
    """B1. A campaign must be able to leave a completion verdict."""

    def setUp(self):
        super().setUp()
        self.ledger = os.path.join(self.tmp.name, "ledger.json")

    def account(self, key):
        return ps.set_surface_account(
            {"key": key, "variant": "NV_ESC_RM_CONTROL_%s" % key,
             "family": "control", "reason": "no-param-model",
             "detail": "the struct carries a union this harness cannot model",
             "evidence": ["src/nvidia/x.c:1"]},
            path=self.ledger, driver_version="610.57.04", targets_total=764)

    def test_a_removed_row_leaves_the_ledger(self):
        self.account("k1")
        self.account("k2")
        removed = ps.clear_surface_account("k1", path=self.ledger,
                                           driver_version="610.57.04")
        self.assertEqual(removed["key"], "k1")
        self.assertEqual(ps.accounted_keys(self.ledger, "610.57.04"), {"k2"})

    def test_removing_a_row_that_is_not_there_says_so_and_changes_nothing(self):
        self.account("k1")
        self.assertIsNone(ps.clear_surface_account("absent", path=self.ledger))
        self.assertEqual(ps.accounted_keys(self.ledger), {"k1"})

    def test_a_completion_verdict_built_on_a_wrong_row_can_be_left(self):
        # 400 exercised and 364 closed out fires the hard stop. Removing one
        # row and re-measuring reopens the campaign, with no override anywhere.
        exercised = {"t%d" % i for i in range(400)}
        for i in range(400, 764):
            self.account("t%d" % i)
        accounted, deferred = ps.surface_ledger_keys(self.ledger, "610.57.04")
        verdict, counts, _closed = ps.surface_completion(
            exercised, accounted, 764, deferred=deferred)
        self.assertEqual(verdict, "complete")
        with ps.transaction() as st:
            ps.end_round(st, verdict="growing",
                         surface=dict(counts, verdict=verdict,
                                      ledger=self.ledger))
        self.assertIsNotNone(ps.hard_cap_reason(ps.load(), max_rounds=10))

        ps.clear_surface_account("t500", path=self.ledger,
                                 driver_version="610.57.04")
        accounted, deferred = ps.surface_ledger_keys(self.ledger, "610.57.04")
        verdict, counts, _closed = ps.surface_completion(
            exercised, accounted, 764, deferred=deferred)
        self.assertEqual(verdict, "incomplete")
        with ps.transaction() as st:
            ps.end_round(st, verdict="growing",
                         surface=dict(counts, verdict=verdict,
                                      ledger=self.ledger))
        st = ps.load()
        self.assertIsNone(ps.hard_cap_reason(st, max_rounds=10))
        self.assertEqual(ps.loop_decision(st, max_rounds=10)[0], "continue")


class TestSurfaceUnaccountCLI(PipelineCtlRunner, unittest.TestCase):
    """The removal a recovery has to reach for, from the command line."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ledger = os.path.join(self.tmp.name, "ledger.json")
        self.env = dict(os.environ,
                        GSPWN_STATE=os.path.join(self.tmp.name, "state",
                                                 "pipeline.json"),
                        GSPWN_SURFACE_LEDGER=self.ledger)

    def write_row(self, key):
        with open(self.ledger, "w") as f:
            json.dump({"schema": ps.SURFACE_LEDGER_SCHEMA,
                       "driver_version": "610.57.04", "targets_total": 764,
                       "updated": None,
                       "accounted": {key: {"key": key, "variant": "V",
                                           "family": "control",
                                           "reason": "chain-unbuildable",
                                           "detail": "d", "evidence": [],
                                           "round": 1,
                                           "first_recorded": "t",
                                           "recorded": "t"}}}, f)

    def test_the_subcommand_exists(self):
        self.assertIn("surface-unaccount", self.ctl("--help"))

    def test_a_row_is_removed_by_its_stored_key(self):
        self.write_row("control/0x0/0x1/Foo")
        out = self.ctl("surface-unaccount", "--key", "control/0x0/0x1/Foo")
        self.assertIn("removed", out)
        with open(self.ledger) as f:
            self.assertEqual(json.load(f)["accounted"], {})

    def test_a_key_with_no_row_is_reported_and_not_invented(self):
        self.write_row("control/0x0/0x1/Foo")
        out = self.ctl("surface-unaccount", "--key", "other", expect=1)
        self.assertIn("nothing was removed", out)

    def test_naming_the_row_twice_or_not_at_all_is_refused(self):
        self.assertIn("not with both",
                      self.ctl("surface-unaccount", "--key", "k",
                               "--variant", "v", expect=1))
        self.assertIn("--variant", self.ctl("surface-unaccount", expect=1))


class TestALedgerRowThatIsNotAnObject(StateTempMixin, unittest.TestCase):
    """I5. Hand editing is a recovery path, so its failure mode matters."""

    def setUp(self):
        super().setUp()
        self.ledger = os.path.join(self.tmp.name, "ledger.json")
        with open(self.ledger, "w") as f:
            json.dump({"schema": ps.SURFACE_LEDGER_SCHEMA,
                       "driver_version": "610.57.04", "targets_total": 764,
                       "updated": None,
                       "accounted": {"control/0x0/0x1/Foo": "no-param-model",
                                     "control/0x0/0x2/Bar": {
                                         "key": "control/0x0/0x2/Bar",
                                         "variant": "V", "family": "control",
                                         "reason": "chain-unbuildable",
                                         "detail": "d", "evidence": [],
                                         "round": 1, "first_recorded": "t",
                                         "recorded": "t"}}}, f)

    def test_the_bad_row_is_named_instead_of_raising_an_attribute_error(self):
        with self.assertRaises(ValueError) as cm:
            ps.load_surface_ledger(self.ledger, "610.57.04")
        self.assertIn("control/0x0/0x1/Foo", str(cm.exception))
        self.assertIn("not JSON objects", str(cm.exception))

    def test_the_readers_that_used_to_traceback_now_raise_valueerror(self):
        for call in (lambda: ps.accounted_keys(self.ledger),
                     lambda: ps.surface_ledger_keys(self.ledger),
                     lambda: ps.set_surface_account(
                         {"key": "control/0x0/0x1/Foo", "variant": "V",
                          "family": "control", "reason": "uvm_test",
                          "detail": "d"}, path=self.ledger)):
            with self.assertRaises(ValueError):
                call()


class TestAFreshLedgerCarriesTheDenominator(StateTempMixin,
                                            unittest.TestCase):
    """I9. A ledger nobody has written to still knows what it counts against."""

    def test_an_absent_ledger_reports_the_total_it_was_asked_about(self):
        path = os.path.join(self.tmp.name, "nothing-here.json")
        ledger = ps.load_surface_ledger(path, "610.57.04", targets_total=764)
        self.assertEqual(ledger["targets_total"], 764)
        self.assertEqual(ledger["driver_version"], "610.57.04")
        self.assertEqual(ledger["accounted"], {})
        self.assertFalse(os.path.exists(path))


class TestTheLedgerPointerSurvivesARound(StateTempMixin, unittest.TestCase):
    """I6. A campaign accounting against its own ledger keeps it."""

    def test_advancing_a_round_carries_the_pointer_forward(self):
        st = ps.default_state()
        for p in ps.ROUND_PHASES:
            st["phases"][p] = {"status": "done", "updated": "t", "notes": ""}
        r = ps.current_round(st)
        r.update({"surface_ledger": "surface/other.json",
                  "decision": "continue", "ended": "t", "run_hours": 1.0})
        new = ps.advance_round(st)
        self.assertEqual(new["round"], 2)
        self.assertEqual(new["surface_ledger"],
                         "surface/other.json")


class TestSurfaceIsNotMeasuredWhenItCannotBeStored(unittest.TestCase):
    """B2. A run in flight paid an unpack per sample for a discarded value."""

    LEGACY = ["ts", "uptime_s", "edges", "corpus", "corpus_bytes", "crashes",
              "execs", "source", "gpu", "disk_free_mb"]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._orig = coverage_ctl.RUNS_DIR
        coverage_ctl.RUNS_DIR = os.path.join(self.tmp.name, "runs")
        self.addCleanup(lambda: setattr(coverage_ctl, "RUNS_DIR", self._orig))
        self.run_id = "r-legacy"
        os.makedirs(coverage_ctl.run_dir(self.run_id), exist_ok=True)
        self.path = coverage_ctl.csv_path(self.run_id, "k")
        now = int(time.time())
        with open(self.path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=self.LEGACY)
            w.writeheader()
            for i in range(6):
                w.writerow({"ts": now - (6 - i) * 600, "uptime_s": 1,
                            "edges": 100 + i, "corpus": 10, "corpus_bytes": 1,
                            "crashes": 0, "execs": 1000 * (i + 1),
                            "source": "http", "gpu": "ok",
                            "disk_free_mb": 90000})

    def test_a_csv_that_cannot_hold_the_column_is_not_due(self):
        due, why = coverage_ctl.surface_due(self.run_id, "k", self.path)
        self.assertFalse(due)
        self.assertIn("predates the surface column", why)
        self.assertIn("migrate-csv", why)

    def test_the_storability_check_comes_before_the_cadence_check(self):
        # interval 0 means "measure every sample" and used to reach past the
        # column check, which is where the repeated unpack came from.
        due, _why = coverage_ctl.surface_due(self.run_id, "k", self.path,
                                             interval_min=0)
        self.assertFalse(due)

    def test_no_corpus_is_unpacked_for_a_run_that_cannot_record_it(self):
        calls = []
        for name, fake in (
                ("collect_surface", lambda rid: (calls.append(rid), 500)[1]),
                ("collect", lambda rid, url, track: (
                    {"edges": 200, "execs": 9000, "corpus": 11,
                     "corpus_bytes": 2, "crashes": 0, "uptime_s": 2}, "http")),
                ("gpu_health", lambda timeout=None: ("ok", "fine")),
                ("disk_free_mb", lambda: 90000),
                ("campaign_finished", lambda rid: False),
                ("registered_runs", lambda st: {self.run_id})):
            self.addCleanup(setattr, coverage_ctl, name,
                            getattr(coverage_ctl, name))
            setattr(coverage_ctl, name, fake)
        # collect_surface returns (count, note); the fake above returns one
        # value, so give it the pair shape the caller unpacks.
        coverage_ctl.collect_surface = lambda rid: (calls.append(rid),
                                                    (500, "fake"))[1]

        class Args:
            pass

        for _ in range(3):
            a = Args()
            a.run_id, a.track, a.url = self.run_id, "k", "http://x"
            a.force, a.skip_surface = False, False
            with redirect_stdout(io.StringIO()):
                coverage_ctl.cmd_sample(a)
        self.assertEqual(calls, [])
        rows = coverage_ctl.read_rows(self.run_id, "k")
        self.assertEqual(len(rows), 9)
        self.assertTrue(all(r["surface"] is None for r in rows))

    def test_a_migrated_csv_is_measured_again(self):
        added, kept = coverage_ctl.migrate_csv(self.path)
        self.assertEqual(added, ["surface"])
        self.assertEqual(kept, 6)
        due, why = coverage_ctl.surface_due(self.run_id, "k", self.path,
                                            interval_min=0)
        self.assertTrue(due, why)


class TestCsvHeaderMigration(unittest.TestCase):
    """The one operation on a coverage.csv that is not an append."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "coverage.csv")

    def read(self):
        with open(self.path) as f:
            return f.read()

    def write(self, header, rows):
        with open(self.path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=header)
            w.writeheader()
            for row in rows:
                w.writerow(row)

    def test_the_missing_column_is_added_and_every_value_survives(self):
        self.write(["ts", "edges", "source"],
                   [{"ts": 1, "edges": 10, "source": "http"},
                    {"ts": 2, "edges": 20, "source": "http"}])
        added, kept = coverage_ctl.migrate_csv(self.path)
        self.assertIn("surface", added)
        self.assertEqual(kept, 2)
        with open(self.path, newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual([r["edges"] for r in rows], ["10", "20"])
        self.assertEqual([r["surface"] for r in rows], ["", ""])
        self.assertEqual(coverage_ctl.existing_fields(self.path)[:3],
                         ["ts", "edges", "source"])

    def test_a_file_that_already_has_every_column_is_left_alone(self):
        self.write(coverage_ctl.FIELDS, [{"ts": 1, "edges": 10}])
        before = self.read()
        added, kept = coverage_ctl.migrate_csv(self.path)
        self.assertEqual(added, [])
        self.assertEqual(kept, 0)
        self.assertEqual(self.read(), before)

    def test_a_column_this_version_does_not_know_keeps_its_position(self):
        self.write(["ts", "edges", "future_thing"],
                   [{"ts": 1, "edges": 10, "future_thing": "x"}])
        coverage_ctl.migrate_csv(self.path)
        fields = coverage_ctl.existing_fields(self.path)
        self.assertEqual(fields[:3], ["ts", "edges", "future_thing"])
        with open(self.path, newline="") as f:
            self.assertEqual(list(csv.DictReader(f))[0]["future_thing"], "x")

    def test_a_sample_landing_mid_rewrite_aborts_it_with_the_file_intact(self):
        self.write(["ts", "edges"], [{"ts": 1, "edges": 10}])
        before = self.read()
        real_getsize = os.path.getsize
        sizes = []

        def grew(path):
            sizes.append(path)
            # Second reading of the target file: the sampler appended.
            return real_getsize(path) + (1 if len(sizes) > 1 else 0)

        self.addCleanup(setattr, os.path, "getsize", real_getsize)
        os.path.getsize = grew
        with self.assertRaises(RuntimeError) as cm:
            coverage_ctl.migrate_csv(self.path)
        os.path.getsize = real_getsize
        self.assertIn("grew while it was being rewritten", str(cm.exception))
        self.assertEqual(self.read(), before)
        leftovers = [n for n in os.listdir(self.tmp.name)
                     if n.endswith(".tmp")]
        self.assertEqual(leftovers, [])


class TestSinceLastResetIsAboutEdges(unittest.TestCase):
    """Incomplete work: a parameter no caller ever passed."""

    def test_it_takes_the_rows_and_nothing_else(self):
        params = list(inspect.signature(
            coverage_ctl.since_last_reset).parameters)
        self.assertEqual(params, ["rows"])

    def test_a_falling_edge_count_still_segments_the_curve(self):
        # Negative control: passes with the fix reverted too. The
        # segmentation on a falling edge is the behaviour that already
        # worked. test_it_takes_the_rows_and_nothing_else is the paired
        # test that discriminates.
        rows = [{"edges": 10}, {"edges": 20}, {"edges": 5}, {"edges": 9}]
        seg, restarted = coverage_ctl.since_last_reset(rows)
        self.assertTrue(restarted)
        self.assertEqual(seg, [{"edges": 5}, {"edges": 9}])


class TestCompletionDenominatorFloor(unittest.TestCase):
    """I7. A truncated inventory is a smaller surface a corpus can close."""

    FAMILIES = ("escape", "uvm", "uvm_tools", "control", "alloc")

    def fake_measure(self, families):
        targets = {}
        for fam in families:
            for i in range(3):
                v = "%s_%d" % (fam, i)
                targets[v] = {"variant": v, "family": fam, "label": v,
                              "abi_key": "%s/%d" % (fam, i)}
        meta = {"driver_version": "610.57.04", "corpus": "/tmp/c",
                "corpus_programs": 1, "corpus_mtime": None}

        def measure(desc_dir, corpus=None, run_id=None):
            return targets, {}, meta, {}, set(targets)
        return measure

    def patch(self, families):
        self.addCleanup(setattr, surface_cov, "measure", surface_cov.measure)
        surface_cov.measure = self.fake_measure(families)

    def test_a_family_with_no_target_is_refused_as_a_denominator(self):
        self.patch([f for f in self.FAMILIES if f != "control"])
        st = coverage_ctl.completion_status(
            ledger_path=os.path.join(tempfile.gettempdir(), "no-ledger.json"))
        self.assertEqual(st["verdict"], "unknown")
        self.assertIn("control", st["detail"])
        self.assertIn("not the command surface", st["detail"])

    def test_a_complete_set_of_families_is_measured(self):
        # Negative control: passes with the fix reverted too. Paired
        # with test_a_family_with_no_target_is_refused_as_a_denominator,
        # which is the half that discriminates.
        self.patch(self.FAMILIES)
        st = coverage_ctl.completion_status(
            ledger_path=os.path.join(tempfile.gettempdir(), "no-ledger.json"))
        self.assertEqual(st["verdict"], "complete")
        self.assertEqual(st["total"], 15)

    def test_an_unmeasurable_union_does_not_raise_through_the_catch_all(self):
        # I8: `abi_key not in closed` against a closed of None raised
        # TypeError into the catch-all, which kept the verdict and replaced
        # the detail with a Python error string.
        self.patch(self.FAMILIES)
        self.addCleanup(setattr, ps, "surface_completion",
                        ps.surface_completion)
        ps.surface_completion = lambda *a, **kw: (
            "unknown", {"exercised": None, "accounted": 0, "deferred": 0,
                        "closed": None, "total": 15}, None)
        st = coverage_ctl.completion_status(
            ledger_path=os.path.join(tempfile.gettempdir(), "no-ledger.json"))
        self.assertEqual(st["verdict"], "unknown")
        self.assertNotIn("TypeError", st["detail"])
        self.assertIn("could not be measured", st["detail"])
        self.assertEqual(len(st["remaining"]), 15)


class TestCompletionStatusReadsDeferralsSeparately(unittest.TestCase):
    """B1 through the reading the stop rule actually consumes."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ledger = os.path.join(self.tmp.name, "ledger.json")
        targets = {}
        for fam in ("escape", "uvm", "uvm_tools", "control", "alloc"):
            for i in range(2):
                v = "%s_%d" % (fam, i)
                targets[v] = {"variant": v, "family": fam, "label": v,
                              "abi_key": "%s/%d" % (fam, i)}
        self.targets = targets
        meta = {"driver_version": "610.57.04", "corpus": "/tmp/c",
                "corpus_programs": 1, "corpus_mtime": None}
        reached = {v for v in targets if not v.startswith("control")}

        def measure(desc_dir, corpus=None, run_id=None):
            return targets, {}, meta, {}, reached
        self.addCleanup(setattr, surface_cov, "measure", surface_cov.measure)
        surface_cov.measure = measure

    def account(self, key, reason):
        record = {"key": key, "variant": "V", "family": "control",
                  "reason": reason, "detail": "d"}
        if reason in ps.SURFACE_REASON_NEEDS_EVIDENCE:
            record["evidence"] = ["src/x.c:1"]
        ps.set_surface_account(record, path=self.ledger,
                               driver_version="610.57.04", targets_total=10)

    def test_deferring_the_last_two_targets_does_not_complete_the_ledger(self):
        self.account("control/0", "deliberately-deferred")
        self.account("control/1", "deliberately-deferred")
        st = coverage_ctl.completion_status(ledger_path=self.ledger)
        self.assertEqual(st["verdict"], "incomplete")
        self.assertEqual(st["closed"], 8)
        self.assertEqual(st["accounted"], 0)
        self.assertEqual(st["deferred"], 2)
        self.assertIn("deliberately deferred", st["detail"])
        self.assertEqual(len(st["remaining"]), 2)

    def test_a_reason_that_says_unreachable_still_closes_the_ledger(self):
        self.account("control/0", "chain-unbuildable")
        self.account("control/1", "chain-unbuildable")
        st = coverage_ctl.completion_status(ledger_path=self.ledger)
        self.assertEqual(st["verdict"], "complete")
        self.assertEqual(st["accounted"], 2)
        self.assertEqual(st["deferred"], 0)


class TestCompletionCommandLine(unittest.TestCase):
    """I2, I3 and I10: what the command says about what it measured."""

    class Args:
        def __init__(self, **kw):
            self.run_id = kw.get("run_id")
            self.corpus = kw.get("corpus")
            self.ledger = kw.get("ledger")
            self.top = kw.get("top", 40)

    def stub(self, **over):
        st = {"verdict": "incomplete", "exercised": 700, "accounted": 0,
              "deferred": 0, "closed": 700, "total": 764, "detail": "d",
              "driver_version": "610.57.04", "ledger": "/tmp/l.json",
              "corpora": [],
              "remaining": [{"family": "control", "label": "L%d" % i,
                             "variant": "V%d" % i} for i in range(64)]}
        st.update(over)
        self.addCleanup(setattr, coverage_ctl, "completion_status",
                        coverage_ctl.completion_status)
        coverage_ctl.completion_status = lambda **kw: st

    def run_cmd(self, args):
        with redirect_stdout(io.StringIO()) as out:
            rc = coverage_ctl.cmd_completion(args)
        return rc, out.getvalue()

    def test_naming_two_corpora_is_refused_instead_of_dropping_one(self):
        with self.assertRaises(SystemExit) as cm:
            coverage_ctl.cmd_completion(
                self.Args(run_id=["r1"], corpus="/tmp/x"))
        self.assertIn("two different corpora", str(cm.exception))

    def test_measuring_the_seed_bank_says_so(self):
        self.stub()
        _rc, out = self.run_cmd(self.Args())
        self.assertIn("seed bank", out)
        self.assertIn("corpus_ctl.py promote", out)
        self.assertIn("--run-id", out)

    def test_measuring_a_run_carries_no_seed_bank_caveat(self):
        # Negative control: passes with the fix reverted too. Paired
        # with test_measuring_the_seed_bank_says_so.
        self.stub()
        _rc, out = self.run_cmd(self.Args(run_id=["r1"]))
        self.assertNotIn("seed bank", out)

    def test_top_zero_names_nothing_and_does_not_offer_to_raise_it(self):
        self.stub()
        _rc, out = self.run_cmd(self.Args(top=0))
        self.assertNotIn("V0", out)
        self.assertNotIn("raise --top", out)
        self.assertIn("64 target(s) not listed", out)

    def test_a_shortened_list_still_offers_the_rest(self):
        # Negative control: passes with the fix reverted too. Paired
        # with test_top_zero_names_nothing_and_does_not_offer_to_raise_it.
        self.stub()
        _rc, out = self.run_cmd(self.Args(top=10))
        self.assertIn("V0", out)
        self.assertIn("54 more (raise --top)", out)

    def test_a_negative_top_is_refused_by_the_parser(self):
        parser = coverage_ctl.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["completion", "--top", "-5"])


class TestRoundEndDoesNotHoldTheLockOverTheUnpack(StateTempMixin,
                                                  unittest.TestCase):
    """I1, and I6's second half: --ledger re-points a round already ended."""

    def setUp(self):
        super().setUp()
        self._orig_runs = coverage_ctl.RUNS_DIR
        coverage_ctl.RUNS_DIR = os.path.join(self.tmp.name, "runs")
        self.addCleanup(lambda: setattr(coverage_ctl, "RUNS_DIR",
                                        self._orig_runs))
        ps.save(ps.default_state())
        d = os.path.join(coverage_ctl.RUNS_DIR, "r1")
        os.makedirs(d, exist_ok=True)
        base = 1_700_000_000
        with open(os.path.join(d, "coverage.csv"), "w") as f:
            f.write(",".join(coverage_ctl.FIELDS) + "\n")
            for i in range(11):
                f.write(csv_line(base + i * 3600, 1000 + i * 300,
                                 source="json:/stats") + "\n")

    class Args:
        def __init__(self, **kw):
            for k in ("from_run", "coverage_verdict", "new_crashes",
                      "edges_start", "edges_end", "run_hours", "notes",
                      "worklist", "ledger", "force"):
                setattr(self, k, kw.get(k))

    def stub_completion(self, record=None, verdict="unknown"):
        self.addCleanup(setattr, coverage_ctl, "completion_status",
                        coverage_ctl.completion_status)

        def fake(run_ids=None, corpus=None, ledger_path=None):
            if record is not None:
                record.append(ledger_path)
            return {"verdict": verdict, "exercised": None, "accounted": None,
                    "deferred": None, "closed": None, "total": None,
                    "detail": "stubbed"}
        coverage_ctl.completion_status = fake

    def test_the_state_lock_is_free_while_the_completion_is_measured(self):
        seen = {}
        self.addCleanup(setattr, coverage_ctl, "completion_status",
                        coverage_ctl.completion_status)

        def probe(run_ids=None, corpus=None, ledger_path=None):
            lock = ps._lock_path(ps.STATE_PATH)
            os.makedirs(os.path.dirname(lock) or ".", exist_ok=True)
            fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o644)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                seen["free"] = True
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                seen["free"] = False
            finally:
                os.close(fd)
            return {"verdict": "unknown", "exercised": None,
                    "accounted": None, "deferred": None, "closed": None,
                    "total": None, "detail": "stubbed"}
        coverage_ctl.completion_status = probe
        with redirect_stdout(io.StringIO()):
            pipeline_ctl_cmd_round_end(self.Args(from_run=["r1"]))
        self.assertTrue(seen.get("free"),
                        "round-end held the state lock across the corpus "
                        "unpack, blocking every other pipeline command")

    def test_a_round_already_ended_can_be_pointed_at_another_ledger(self):
        seen = []
        self.stub_completion(record=seen)
        with redirect_stdout(io.StringIO()):
            pipeline_ctl_cmd_round_end(self.Args(from_run=["r1"]))
        first = ps.load()["rounds"][-1]["surface_ledger"]
        with redirect_stdout(io.StringIO()):
            pipeline_ctl_cmd_round_end(
                self.Args(from_run=["r1"], ledger="surface/b.json"))
        self.assertEqual(seen[-1], "surface/b.json")
        self.assertEqual(ps.load()["rounds"][-1]["surface_ledger"],
                         "surface/b.json")
        self.assertNotEqual(first, "surface/b.json")

    def test_the_round_carries_the_deferred_count_the_reading_produced(self):
        self.addCleanup(setattr, coverage_ctl, "completion_status",
                        coverage_ctl.completion_status)
        coverage_ctl.completion_status = lambda **kw: {
            "verdict": "incomplete", "exercised": 700, "accounted": 20,
            "deferred": 44, "closed": 720, "total": 764, "detail": "d"}
        with redirect_stdout(io.StringIO()):
            pipeline_ctl_cmd_round_end(self.Args(from_run=["r1"]))
        self.assertEqual(ps.load()["rounds"][-1]["surface_deferred"], 44)


class TestTheRefusalNamesEveryHardStop(PipelineCtlRunner,
                                       unittest.TestCase):
    """I4. An operator blocked by completion was told it was the budget."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.join(self.tmp.name, "state", "pipeline.json")
        self.env = dict(os.environ, GSPWN_STATE=self.state)

    def complete_round(self):
        self.ctl("init")
        st = ps.load(self.state)
        r = ps.current_round(st)
        r.update({"surface_verdict": "complete", "surface_total": 764,
                  "surface_exercised": 700, "surface_accounted": 64,
                  "surface_closed": 764, "coverage_verdict": "growing",
                  "surface_ledger": "state/completion-ledger.json"})
        ps.save(st, self.state)

    def test_a_completion_stop_is_named_as_one(self):
        self.complete_round()
        out = self.ctl("round-decide", "--decision", "continue",
                       "--reason", "one more", expect=1)
        self.assertIn("completion, budget or round-cap", out)

    def test_the_refusal_names_the_way_out_of_a_wrong_verdict(self):
        self.complete_round()
        out = self.ctl("round-decide", "--decision", "continue",
                       "--reason", "one more", expect=1)
        self.assertIn("surface-unaccount", out)
        self.assertIn("round-end", out)

    def test_the_help_no_longer_names_only_two_of_the_three(self):
        out = self.ctl("round-decide", "--help")
        self.assertIn("completion", out)


# ---------------------------------------------------------------------------
# Review wave 2, crash registration and reproducers. From tmp/tests2/crash.py
# and tmp/fix/crash.md: the Track U replay step, the syz report/log split, the
# seed call budget, the kernel config check. 17 classes, 88 tests, every one
# of which fails with its own fix reverted (tmp/fix/failability.py).
#
# The reading half of the Track U replay is covered here. The running half
# needs a built harness binary and is exercised by tmp/fix/replay_e2e.sh.
# ---------------------------------------------------------------------------


class TestTrackURegistersFromAReplayReport(StateTempMixin, unittest.TestCase):
    """HIGH-1. A Track U crash input is the bytes the fuzzer saved, not a
    report: AFL++ writes id:NNNNNN,sig:NN,... and libFuzzer writes
    crash-<sha1>, and neither carries an ERROR:/SUMMARY:/runtime error:/SEGV
    line. The scanner requires one, so before the replay step every finding
    was skipped and the registry stayed empty for the whole track.

    harnesses/replay_crashes.sh runs each input back through its
    harness and writes the sanitizer output to <input>.sanlog. These tests
    drive the reading half; the running half needs a built harness binary and
    is exercised end to end by tmp/fix/replay_e2e.sh.
    """

    ASAN = ("==4711==ERROR: AddressSanitizer: heap-buffer-overflow on "
            "address 0x60300000eff8\n"
            "READ of size 4 at 0x60300000eff8 thread T0\n"
            "    #0 0x4a1b2c in ldcache_parse /src/ldcache.c:88\n"
            "    #1 0x4a2f00 in LLVMFuzzerTestOneInput /h/fuzz.c:41\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow\n")

    def crash_root(self, files):
        """files: {relative path: bytes or str} -> the crash root path."""
        root = os.path.join(self.tmp.name, "crashes")
        for rel, body in files.items():
            p = os.path.join(root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            mode = "wb" if isinstance(body, bytes) else "w"
            with open(p, mode) as f:
                f.write(body)
        os.makedirs(root, exist_ok=True)
        return root

    def scan(self, root):
        st = ps.default_state()
        with redirect_stdout(io.StringIO()) as out:
            crash_parse.scan_track_u(st, root)
        return st, out.getvalue()

    def test_a_raw_input_alone_registers_nothing(self):
        # The state the replay step exists to end. Without it the campaign
        # loses every Track U finding to a warning.
        root = self.crash_root({
            "fuzz_ldcache/id:000000,sig:06,src:000000,op:havoc,rep:2":
                b"\x00\x01AAAA\xff\xfe"})
        st, _out = self.scan(root)
        self.assertEqual(st["crashes"], {})

    def test_the_replay_report_beside_it_registers_the_crash(self):
        name = "fuzz_ldcache/id:000000,sig:06,src:000000,op:havoc,rep:2"
        root = self.crash_root({name: b"\x00\x01AAAA\xff\xfe",
                                name + crash_parse.REPORT_SUFFIX: self.ASAN})
        st, _out = self.scan(root)
        self.assertEqual(len(st["crashes"]), 1)
        c = st["crashes"]["crash-0001"]
        self.assertEqual(c["track"], "U")
        self.assertIn("AddressSanitizer", c["title"])

    def test_the_registered_path_is_the_input_and_not_the_report(self):
        # repro_ctl extract copies c["dir"] to artifacts/pocs/<cid>/input and
        # verify --track u replays that file. Registering the report path
        # would hand verify a text log to replay.
        name = "fuzz_ldcache/crash-da39a3ee"
        root = self.crash_root({name: b"\xde\xad\xbe\xef",
                                name + crash_parse.REPORT_SUFFIX: self.ASAN})
        st, _out = self.scan(root)
        self.assertEqual(st["crashes"]["crash-0001"]["dir"],
                         os.path.join(root, name))

    def test_the_frames_come_from_the_report(self):
        # The stack hash is the secondary dedup key. Hashing the raw input
        # would yield '' for every Track U crash.
        name = "fuzz_ldcache/crash-da39a3ee"
        root = self.crash_root({name: b"\xde\xad\xbe\xef",
                                name + crash_parse.REPORT_SUFFIX: self.ASAN})
        st, _out = self.scan(root)
        self.assertEqual(st["crashes"]["crash-0001"]["stack_hash"],
                         crash_parse.stack_hash(self.ASAN))

    def test_a_report_is_not_registered_a_second_time_as_an_input(self):
        name = "fuzz_ldcache/crash-da39a3ee"
        root = self.crash_root({name: b"\xde\xad\xbe\xef",
                                name + crash_parse.REPORT_SUFFIX: self.ASAN})
        st, _out = self.scan(root)
        self.assertEqual(len(st["crashes"]), 1)

    def test_an_input_that_did_not_crash_on_replay_is_not_registered(self):
        name = "fuzz_ldcache/id:000000,sig:06"
        root = self.crash_root({
            name: b"harmless",
            name + crash_parse.REPORT_SUFFIX:
                "# replay of %s\nparsed ok\n# exit 0\n" % name})
        st, out = self.scan(root)
        self.assertEqual(st["crashes"], {})
        self.assertIn("was replayed", out)

    def test_the_unreplayed_warning_names_the_replay_step(self):
        # The warning used to say "check that the harnesses were built with a
        # sanitizer". They are: common/build_common.sh compiles every harness
        # -fsanitize=address,undefined in both modes. The file is an input.
        root = self.crash_root({"fuzz_ldcache/id:000000,sig:06": b"\x00"})
        _st, out = self.scan(root)
        self.assertIn("replay_crashes.sh", out)
        self.assertNotIn("built with a sanitizer", out)

    def test_the_summary_separates_unreplayed_from_replayed_clean(self):
        root = self.crash_root({
            "fuzz_a/id:000000,sig:06": b"\x00",
            "fuzz_b/id:000000,sig:06": b"\x00",
            "fuzz_b/id:000000,sig:06" + crash_parse.REPORT_SUFFIX:
                "parsed ok\n# exit 0\n"})
        _st, out = self.scan(root)
        self.assertIn("1 of them have no replay report", out)
        self.assertIn("1 were replayed and did not crash", out)

    def test_a_report_whose_input_was_deleted_still_registers(self):
        # Losing the finding is worse than registering it against a path
        # verify cannot replay.
        root = self.crash_root({
            "fuzz_ldcache/crash-da39a3ee" + crash_parse.REPORT_SUFFIX:
                self.ASAN})
        st, _out = self.scan(root)
        self.assertEqual(len(st["crashes"]), 1)

    def test_a_hand_copied_sanitizer_log_still_registers_directly(self):
        # The behaviour before the replay step: a file that already holds a
        # report is read as one, with no .sanlog beside it.
        root = self.crash_root({"fuzz_ldcache/asan.log": self.ASAN})
        st, _out = self.scan(root)
        self.assertEqual(len(st["crashes"]), 1)

    def test_a_libfuzzer_verdict_is_a_sanitizer_title(self):
        # An out-of-memory or a deadly signal caught by the libFuzzer driver
        # rather than by ASan is still the crash the input was saved for, and
        # a replay under a libFuzzer-built harness is what produces it.
        title = crash_parse.sanitizer_title(
            "==1==ERROR: libFuzzer: out-of-memory (malloc(4294967296))\n")
        self.assertIsNotNone(title)
        self.assertIn("libFuzzer", title)


class TestTrackUInputsAreFoundAtEveryLayout(StateTempMixin,
                                            unittest.TestCase):
    """MEDIUM-3 and L5. run_all.sh's copy step is
    `cp -f "${src}"/* ... || true`, and its documented recovery is a
    wholesale copy of the fuzzer output tree, which lands the inputs at
    <harness>/default/crashes/ under AFL++ and <harness>/crashes/ under
    libFuzzer. The descent was one level deep and saw none of them.
    """

    ASAN = TestTrackURegistersFromAReplayReport.ASAN

    def root_with(self, rel):
        root = os.path.join(self.tmp.name, "crashes")
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(self.ASAN)
        return root

    def found(self, root):
        return [os.path.relpath(p, root).replace(os.sep, "/")
                for p in crash_parse.track_u_inputs(root)]

    def test_the_afl_recovery_layout_is_read(self):
        root = self.root_with("fuzz_x/default/crashes/id:000000,sig:06")
        self.assertEqual(self.found(root),
                         ["fuzz_x/default/crashes/id:000000,sig:06"])

    def test_the_libfuzzer_recovery_layout_is_read(self):
        root = self.root_with("fuzz_x/crashes/crash-da39a3ee")
        self.assertEqual(self.found(root), ["fuzz_x/crashes/crash-da39a3ee"])

    def test_a_deeper_tree_is_not_walked(self):
        # A corpus directory copied here by accident holds thousands of
        # files, and an unbounded walk would read every one of them.
        root = self.root_with("a/b/c/d/e/input")
        self.assertEqual(self.found(root), [])

    def test_a_plain_readme_is_not_a_crash_input(self):
        # The exclusion matched README.txt exactly. The AFL++ tree has
        # carried both spellings.
        root = os.path.join(self.tmp.name, "crashes")
        d = os.path.join(root, "fuzz_x")
        os.makedirs(d)
        for name in ("README", "README.txt"):
            with open(os.path.join(d, name), "w") as f:
                f.write("afl readme\n")
        self.assertEqual(self.found(root), [])

    def test_the_deep_layout_registers_and_does_not_warn(self):
        root = self.root_with("fuzz_x/default/crashes/id:000000,sig:06")
        st = ps.default_state()
        with redirect_stdout(io.StringIO()) as out:
            crash_parse.scan_track_u(st, root)
        self.assertEqual(len(st["crashes"]), 1)
        self.assertNotIn("no crash input files", out.getvalue())


class TestSyzLogSuppliesTheStackWhenNoReportExists(StateTempMixin,
                                                   unittest.TestCase):
    """MEDIUM-1. syzkaller writes report<N> only when the symbolized report
    text came out non-empty, so a manager running without kernel_obj produces
    log<N> and no report at all. scan_syz read the report name alone and
    hashed the empty string, which is no evidence and kills the secondary
    dedup key for every crash in that workdir. stack_frames parses raw
    console traces as well as syzkaller frame lines, so the log carries the
    same function names.
    """

    LOG = ("[   12.345678] BUG: KASAN: use-after-free in nv_uvm_free\n"
           "[   12.345679] Call Trace:\n"
           "[   12.345680]  nv_uvm_free+0x12/0x34 [nvidia_uvm]\n"
           "[   12.345681]  uvm_release+0x8/0x20 [nvidia_uvm]\n"
           "[   12.345682]  __x64_sys_ioctl+0x40/0x80\n")

    def crash_dir(self, files):
        wd = os.path.join(self.tmp.name, "workdir")
        cdir = os.path.join(wd, "crashes", "aaaa")
        os.makedirs(cdir, exist_ok=True)
        for name, text in files.items():
            with open(os.path.join(cdir, name), "w") as f:
                f.write(text)
        return wd, cdir

    def test_the_log_is_selected_when_no_report_exists(self):
        _wd, cdir = self.crash_dir({"description": "KASAN: use-after-free",
                                    "log0": self.LOG, "log1": self.LOG})
        self.assertEqual(os.path.basename(crash_parse.syz_evidence_path(cdir)),
                         "log0")

    def test_the_report_still_wins_when_both_exist(self):
        _wd, cdir = self.crash_dir({"description": "KASAN: use-after-free",
                                    "report0": self.LOG, "log0": self.LOG})
        self.assertEqual(os.path.basename(crash_parse.syz_evidence_path(cdir)),
                         "report0")

    def test_a_log_only_directory_registers_with_a_stack_hash(self):
        wd, _cdir = self.crash_dir({"description": "KASAN: use-after-free "
                                                   "Read in nv_uvm_free",
                                    "log0": self.LOG})
        st = ps.default_state()
        with redirect_stdout(io.StringIO()):
            crash_parse.scan_syz(st, wd)
        self.assertEqual(st["crashes"]["crash-0001"]["stack_hash"],
                         crash_parse.stack_hash(self.LOG))

    def test_the_hash_is_not_empty(self):
        # '' is 'no evidence' and never drives a stack decision, so an empty
        # hash here silently retires the secondary key.
        wd, _cdir = self.crash_dir({"description": "KASAN: use-after-free",
                                    "log0": self.LOG})
        st = ps.default_state()
        with redirect_stdout(io.StringIO()):
            crash_parse.scan_syz(st, wd)
        self.assertNotEqual(st["crashes"]["crash-0001"]["stack_hash"], "")

    def test_a_directory_with_neither_still_resolves_to_none(self):
        _wd, cdir = self.crash_dir({"description": "KASAN: use-after-free"})
        self.assertIsNone(crash_parse.syz_evidence_path(cdir))

    def test_repro_report_and_report_html_are_still_not_reports(self):
        _wd, cdir = self.crash_dir({"description": "d",
                                    "repro.report": "x", "report.html": "y"})
        self.assertIsNone(crash_parse.syz_evidence_path(cdir))


class TestSignatureReadsTheIndexedReport(StateTempMixin, unittest.TestCase):
    """MEDIUM-2. _report_texts joined the bare names `report` and `log` onto
    the syzkaller crash directory, whose per-sighting files are report<N> and
    log<N>. Both open() calls raised OSError and were swallowed, leaving a
    signature built from title tokens alone.
    """

    REPORT = ("BUG: KASAN: use-after-free in nv_uvm_free\n"
              "Call Trace:\n"
              " nv_uvm_free+0x12/0x34 [nvidia_uvm]\n"
              " uvm_release+0x8/0x20 [nvidia_uvm]\n")

    def entry(self, files):
        cdir = os.path.join(self.tmp.name, "crashes", "aaaa")
        os.makedirs(cdir, exist_ok=True)
        for name, text in files.items():
            with open(os.path.join(cdir, name), "w") as f:
                f.write(text)
        return {"track": "K", "dir": cdir,
                "title": "KASAN: use-after-free in nv_uvm_free"}

    def test_the_indexed_report_is_read(self):
        c = self.entry({"report0": self.REPORT})
        texts = repro_ctl._report_texts(c, "crash-0001")
        self.assertTrue(any("uvm_release" in t for t in texts))

    def test_the_indexed_log_is_read(self):
        c = self.entry({"log0": self.REPORT})
        texts = repro_ctl._report_texts(c, "crash-0001")
        self.assertTrue(any("uvm_release" in t for t in texts))

    def test_the_signature_carries_frames_from_the_indexed_report(self):
        # Without the report the funcs list holds only identifier-like title
        # tokens, and uvm_release appears in no title.
        c = self.entry({"report0": self.REPORT})
        sig = repro_ctl.crash_signature(c, "crash-0001")
        self.assertIn("uvm_release", sig["funcs"])

    def test_an_unextracted_crash_is_no_longer_title_tokens_alone(self):
        c = self.entry({"report0": self.REPORT})
        with_report = repro_ctl.crash_signature(c, "crash-0001")["funcs"]
        c_bare = dict(c, dir=os.path.join(self.tmp.name, "nothing"))
        without = repro_ctl.crash_signature(c_bare, "crash-0001")["funcs"]
        self.assertNotEqual(with_report, without)

    def test_a_track_u_entry_reads_the_replay_report(self):
        # The registry path for a Track U crash is the input file, whose
        # bytes are not text. The sanitizer output sits beside it.
        d = os.path.join(self.tmp.name, "u")
        os.makedirs(d, exist_ok=True)
        inp = os.path.join(d, "crash-da39a3ee")
        with open(inp, "wb") as f:
            f.write(b"\xde\xad\xbe\xef")
        with open(inp + crash_parse.REPORT_SUFFIX, "w") as f:
            f.write(self.REPORT)
        texts = repro_ctl._report_texts({"track": "U", "dir": inp,
                                         "title": "t"}, "crash-0001")
        self.assertTrue(any("uvm_release" in t for t in texts))


class TestExtractIsCrashDurable(StateTempMixin, unittest.TestCase):
    """MEDIUM-9. _extract_k copied every artefact with shutil.copy while
    _extract_u used _atomic_copy, whose docstring calls it the state-file
    idiom for a pipeline that panics the machine by design. A panic during
    extract leaves a truncated repro.c, which is non-empty, so the stale
    check passes it, _prepare_k compiles it, gcc fails, and the message sends
    the operator back to extract to copy the same truncated file again.
    """

    def test_no_artefact_is_copied_with_shutil_copy(self):
        # Read the source: a durability property has no offline observable.
        # The seam is that one copy path in the module uses the durable idiom
        # and the other did not.
        with io.open(os.path.join(HERE, "repro_ctl.py"),
                     encoding="utf-8") as f:
            body = f.read()
        start = body.index("def _extract_k(")
        end = body.index("def _extract_u(")
        self.assertNotIn("shutil.copy(", body[start:end])
        self.assertIn("_atomic_copy(", body[start:end])

    def test_a_copied_artefact_lands_with_the_full_content(self):
        src = os.path.join(self.tmp.name, "src")
        os.makedirs(src, exist_ok=True)
        body = "int main(void) { return 0; }\n" * 400
        for name in ("repro.cprog", "description"):
            with open(os.path.join(src, name), "w") as f:
                f.write(body)
        cid = "crash-0001"
        dest = os.path.join(repro_ctl.REPO_ROOT, "artifacts", "pocs", cid)
        self.addCleanup(shutil.rmtree, dest, True)
        with redirect_stdout(io.StringIO()):
            repro_ctl._extract_k(cid, {"track": "K", "dir": src})
        with open(os.path.join(dest, "repro.c")) as f:
            self.assertEqual(f.read(), body)


class TestExtractRefusesALogHarvestedCrash(StateTempMixin,
                                           unittest.TestCase):
    """L3. scan_dmesg registers a harvested kernel report as track K with the
    log file it was read out of as `dir`. extract on one of those reached
    _extract_k, copied nothing, and printed "syz-manager found no reproducer
    for this crash" about a crash syz-manager was never shown.
    """

    def test_a_file_dir_is_refused_with_a_message_naming_the_log(self):
        log = os.path.join(self.tmp.name, "dmesg.txt")
        with open(log, "w") as f:
            f.write("BUG: KASAN: use-after-free in nv_uvm_free\n")
        with self.assertRaises(SystemExit) as cm:
            with redirect_stdout(io.StringIO()):
                repro_ctl._extract_k("crash-0001", {"track": "K", "dir": log})
        self.assertIn(log, str(cm.exception))
        self.assertNotIn("syz-manager found no reproducer", str(cm.exception))

    def test_the_message_says_what_to_do_instead(self):
        log = os.path.join(self.tmp.name, "dmesg.txt")
        with open(log, "w") as f:
            f.write("BUG:\n")
        with self.assertRaises(SystemExit) as cm:
            with redirect_stdout(io.StringIO()):
                repro_ctl._extract_k("crash-0001", {"track": "K", "dir": log})
        self.assertIn("by hand", str(cm.exception))


class TestForceIsNotSilentOnTrackK(StateTempMixin, unittest.TestCase):
    """L2. cmd_extract accepts --force for either track and _extract_k takes
    no such argument, so on a Track K crash the flag was accepted and did
    nothing with no message.
    """

    def test_force_on_a_track_k_crash_says_it_changed_nothing(self):
        src = os.path.join(self.tmp.name, "crashdir")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "repro.cprog"), "w") as f:
            f.write("int main(void){return 0;}\n")
        cid = "crash-0001"
        dest = os.path.join(repro_ctl.REPO_ROOT, "artifacts", "pocs", cid)
        self.addCleanup(shutil.rmtree, dest, True)
        st = ps.default_state()
        ps.register_crash(st, {"track": "K", "title": "t", "stack_hash": "",
                               "status": "unique", "dir": src,
                               "repro_rate": None, "duplicate_of": None,
                               "disclosure": "pending",
                               "signal": "unclassified", "notes": ""})
        ps.save(st)
        with redirect_stdout(io.StringIO()) as out:
            repro_ctl.cmd_extract(cid, force=True)
        self.assertIn("--force applies to track U", out.getvalue())

    def test_no_message_when_force_was_not_passed(self):
        src = os.path.join(self.tmp.name, "crashdir")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(src, "repro.cprog"), "w") as f:
            f.write("int main(void){return 0;}\n")
        cid = "crash-0001"
        dest = os.path.join(repro_ctl.REPO_ROOT, "artifacts", "pocs", cid)
        self.addCleanup(shutil.rmtree, dest, True)
        st = ps.default_state()
        ps.register_crash(st, {"track": "K", "title": "t", "stack_hash": "",
                               "status": "unique", "dir": src,
                               "repro_rate": None, "duplicate_of": None,
                               "disclosure": "pending",
                               "signal": "unclassified", "notes": ""})
        ps.save(st)
        with redirect_stdout(io.StringIO()) as out:
            repro_ctl.cmd_extract(cid, force=False)
        self.assertNotIn("--force", out.getvalue())


class TestTheChainAccountClosesAtEveryBudget(unittest.TestCase):
    """MEDIUM-4 and L1. `accounted` was built from the emitted commands plus
    the unreached block and never from the oversize or undeclared totals, so
    a budget that dropped commands produced a summary line that looked
    closed. At the default budget nothing is dropped, which is the only case
    the phase 6 report measured.
    """

    STEPS = ("NV01_ROOT", "NV01_DEVICE_0", "NV20_SUBDEVICE_0", "NV30_GSYNC")
    RANKS = {"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6}

    def record(self, internal, chain, handlers, reason=None):
        return {"internal_class": internal,
                "chain": [{"external_class": s} for s in chain],
                "commands": [{"handler": h} for h in handlers],
                "unallocatable_reason": reason}

    def chains(self):
        return {
            "schema": "gspwn.rm-chains/1",
            "chains": [
                self.record("RmClientResource", ("NV01_ROOT",), ["a"]),
                self.record("Device", ("NV01_ROOT", "NV01_DEVICE_0"), ["b"]),
                self.record("Subdevice",
                            ("NV01_ROOT", "NV01_DEVICE_0",
                             "NV20_SUBDEVICE_0"), ["c", "d", "e"]),
                self.record("GsyncApi", ("NV01_ROOT", "NV30_GSYNC"), ["f"]),
            ],
            "unresolved_owning_classes": [
                {"owning_class": "Memory", "command_count": 2,
                 "reason": "no RS_ENTRY row for this class", "commands": []},
            ],
        }

    def declared(self):
        out = {}
        for name in self.STEPS:
            out[trace2seed.ALLOC_PREFIX + name] = ("fd_nv", "0xc030462b")
        for handler in self.RANKS:
            out[trace2seed.CONTROL_PREFIX + handler] = ("fd_nvidiactl",
                                                        "0xc020462a")
        return out

    def account(self, max_calls=40, declared=None):
        _programs, report = trace2seed.build_chain_programs(
            self.chains(), self.RANKS,
            self.declared() if declared is None else declared, max_calls)
        return report

    def total(self, report):
        return (report["commands"] + len(report["dropped"])
                + sum(c for _o, _r, c in report["unreached"]))

    def test_the_account_closes_at_the_default_budget(self):
        self.assertEqual(self.total(self.account()), 8)

    def test_the_account_closes_when_a_budget_drops_a_prologue(self):
        # max_calls 4 leaves room for no command behind the three-allocation
        # prologue, so Subdevice's three commands are dropped.
        report = self.account(max_calls=4)
        self.assertTrue(report["oversize"])
        self.assertEqual(self.total(report), 8)

    def test_the_dropped_commands_are_named(self):
        report = self.account(max_calls=4)
        self.assertEqual(report["dropped"], ["c", "d", "e"])

    def test_the_account_closes_when_a_description_is_missing(self):
        declared = {k: v for k, v in self.declared().items()
                    if k != trace2seed.ALLOC_PREFIX + "NV30_GSYNC"}
        report = self.account(declared=declared)
        self.assertEqual(self.total(report), 8)
        self.assertEqual(report["dropped"], ["f"])

    def test_a_command_blocked_by_two_names_is_counted_once(self):
        # The per-name undeclared counts book the whole command list against
        # each missing name, so summing them double-counts. L1.
        declared = {k: v for k, v in self.declared().items()
                    if k not in (trace2seed.ALLOC_PREFIX + "NV01_DEVICE_0",
                                 trace2seed.ALLOC_PREFIX + "NV20_SUBDEVICE_0")}
        report = self.account(declared=declared)
        # NV01_DEVICE_0 blocks b plus c, d, e; NV20_SUBDEVICE_0 blocks c, d, e
        # again. The per-name sum is 7 and the commands lost are four.
        self.assertEqual(sum(report["undeclared"].values()), 7)
        self.assertEqual(report["undeclared_commands"], ["b", "c", "d", "e"])
        self.assertEqual(self.total(report), 8)

    def test_a_command_another_prologue_still_reaches_is_not_counted_lost(self):
        # "b" is blocked on the Subdevice path but Device's own prologue
        # carries it, so it is not a lost command.
        declared = {k: v for k, v in self.declared().items()
                    if k != trace2seed.ALLOC_PREFIX + "NV20_SUBDEVICE_0"}
        report = self.account(declared=declared)
        self.assertNotIn("b", report["undeclared_commands"])
        self.assertNotIn("b", report["dropped"])


class TestChainsRefusesABudgetThatWritesNothing(unittest.TestCase):
    """MEDIUM-5. --max-calls accepted zero and negative values and an empty
    run exited 0, so a seeds phase gate reading the exit status saw success
    against an empty bank.
    """

    def run_chains(self, args, env=None):
        cmd = [sys.executable, os.path.join(HERE, "trace2seed.py"),
               "chains"] + args
        e = dict(os.environ)
        e.pop("GSPWN_SEED_MAX_CALLS", None)
        e.update(env or {})
        return subprocess.run(cmd, capture_output=True, text=True, env=e)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = os.path.join(self.tmp.name, "seeds")
        os.makedirs(self.out, exist_ok=True)

    def test_max_calls_zero_is_refused(self):
        r = self.run_chains(["--out-dir", self.out, "--max-calls", "0"])
        self.assertEqual(r.returncode, 2)
        self.assertIn("cannot hold a program", r.stderr)

    def test_a_negative_max_calls_is_refused(self):
        r = self.run_chains(["--out-dir", self.out, "--max-calls", "-5"])
        self.assertEqual(r.returncode, 2)

    def test_max_calls_two_is_refused_and_names_the_floor(self):
        r = self.run_chains(["--out-dir", self.out, "--max-calls", "2"])
        self.assertEqual(r.returncode, 2)
        self.assertIn("openat", r.stderr)

    def test_the_floor_itself_is_accepted(self):
        r = self.run_chains(["--out-dir", self.out, "--max-calls",
                             str(trace2seed.MIN_MAX_CALLS)])
        self.assertEqual(r.returncode, 0)

    def test_an_empty_chain_artefact_exits_non_zero(self):
        empty = os.path.join(self.tmp.name, "empty.json")
        with open(empty, "w") as f:
            f.write('{"chains":[]}')
        r = self.run_chains(["--chains", empty, "--out-dir", self.out])
        self.assertEqual(r.returncode, 1)
        self.assertIn("seed bank is empty", r.stderr)


class TestABadSeedBudgetVariableFailsAsASeedError(unittest.TestCase):
    """MEDIUM-6. GSPWN_SEED_MAX_CALLS is documented in the environment
    reference and was read at module scope with no guard, so a non-integer
    value ended the process in a traceback before argparse had printed a
    usage line. Every other input to this tool fails as a SeedError naming
    what was wrong.
    """

    def run_tool(self, args, value):
        e = dict(os.environ)
        e["GSPWN_SEED_MAX_CALLS"] = value
        return subprocess.run(
            [sys.executable, os.path.join(HERE, "trace2seed.py")] + args,
            capture_output=True, text=True, env=e)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_chains_exits_two_and_names_the_variable(self):
        r = self.run_tool(["chains", "--out-dir", self.tmp.name], "abc")
        self.assertEqual(r.returncode, 2)
        self.assertIn("GSPWN_SEED_MAX_CALLS", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_the_message_names_the_value_that_was_rejected(self):
        r = self.run_tool(["chains", "--out-dir", self.tmp.name], "abc")
        self.assertIn("'abc'", r.stderr)

    def test_importing_the_module_does_not_raise(self):
        r = self.run_tool(["--help"], "abc")
        self.assertEqual(r.returncode, 0)

    def test_convert_is_not_failed_by_a_variable_it_does_not_read(self):
        trace = os.path.join(self.tmp.name, "t.txt")
        with open(trace, "w") as f:
            f.write('openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3\n')
        r = self.run_tool(["convert", "--trace", trace,
                           "--out-dir", self.tmp.name], "abc")
        self.assertEqual(r.returncode, 0)

    def test_a_valid_value_is_still_honoured(self):
        r = self.run_tool(["chains", "--out-dir", self.tmp.name,
                           "--descriptions",
                           os.path.join(os.path.dirname(HERE), "descriptions"
                                        )], "2")
        self.assertEqual(r.returncode, 2)
        self.assertIn("cannot hold a program", r.stderr)


class TestVerboseWorksOnEitherSideOfTheSubcommand(unittest.TestCase):
    """L6. -v/--verbose was declared on the top-level parser only, so
    `trace2seed.py chains -v` failed and the pre-subcommand routing broke on
    `--trace X --out-dir Y -v`, because -v landed after the inserted
    `convert`.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.trace = os.path.join(self.tmp.name, "t.txt")
        with open(self.trace, "w") as f:
            f.write('openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3\n')

    def run_tool(self, args):
        return subprocess.run(
            [sys.executable, os.path.join(HERE, "trace2seed.py")] + args,
            capture_output=True, text=True)

    def test_verbose_after_the_subcommand_is_accepted(self):
        r = self.run_tool(["convert", "-v", "--trace", self.trace,
                           "--out-dir", self.tmp.name])
        self.assertEqual(r.returncode, 0)
        self.assertIn("INFO", r.stderr)

    def test_verbose_before_the_subcommand_still_logs(self):
        # argparse pitfall: a store_true on the subparser with a default of
        # False overwrites the value the top-level flag already set.
        r = self.run_tool(["-v", "convert", "--trace", self.trace,
                           "--out-dir", self.tmp.name])
        self.assertEqual(r.returncode, 0)
        self.assertIn("INFO", r.stderr)

    def test_the_legacy_invocation_accepts_a_trailing_verbose(self):
        r = self.run_tool(["--trace", self.trace, "--out-dir", self.tmp.name,
                           "-v"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("INFO", r.stderr)

    def test_neither_placement_logs_without_the_flag(self):
        r = self.run_tool(["convert", "--trace", self.trace,
                           "--out-dir", self.tmp.name])
        self.assertNotIn("INFO", r.stderr)


class TestInterruptedRunLeftoversAreReported(unittest.TestCase):
    """L7. write_atomic leaves a .trace2seed-*.tmp in the output directory
    when a run is killed between NamedTemporaryFile and os.replace. The stale
    scan matches chain-*.syz only, so the leftovers accumulate unnamed.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_chains(self):
        return subprocess.run(
            [sys.executable, os.path.join(HERE, "trace2seed.py"), "chains",
             "--out-dir", self.tmp.name],
            capture_output=True, text=True)

    def test_a_leftover_temp_file_is_named(self):
        leftover = (trace2seed.TEMP_PREFIX + "abc123"
                    + trace2seed.TEMP_SUFFIX)
        with open(os.path.join(self.tmp.name, leftover), "w") as f:
            f.write("half a program")
        r = self.run_chains()
        self.assertIn(leftover, r.stdout)

    def test_a_clean_directory_reports_no_leftovers(self):
        r = self.run_chains()
        self.assertNotIn("interrupted run", r.stdout)

    def test_the_prefix_write_atomic_uses_is_the_one_scanned_for(self):
        # The scan and the writer must not drift apart: a renamed prefix on
        # one side leaves the other looking for a name nothing writes.
        with io.open(os.path.join(HERE, "trace2seed.py"),
                     encoding="utf-8") as f:
            body = f.read()
        start = body.index("def write_atomic(")
        end = body.index("def cmd_convert(")
        self.assertIn("prefix=TEMP_PREFIX", body[start:end])
        self.assertIn("suffix=TEMP_SUFFIX", body[start:end])


class TestTracedAllocationFormsAreNamed(unittest.TestCase):
    """Incomplete work: the 32-byte NVOS21_PARAMETERS allocation form. Two
    request numbers reach NV_ESC_RM_ALLOC and differ only in the parameter
    size the ioctl encoding carries: 0xc020462b is 32 bytes over
    NVOS21_PARAMETERS and 0xc030462b is 48 over NVOS64_PARAMETERS. The
    description set declares 204 variants over the wider struct and one over
    the narrower, so a workload issuing the narrower form for any other class
    reaches an allocation route the surface model does not carry. Nothing
    reported which form a trace used.
    """

    MUX = {
        "0xc020462b": {"escape": "NV_ESC_RM_ALLOC",
                       "param_struct": "NVOS21_PARAMETERS",
                       "selector_field": "hClass",
                       "variant_prefix": "ioctl$NV_ESC_RM_ALLOC_"},
        "0xc030462b": {"escape": "NV_ESC_RM_ALLOC",
                       "param_struct": "NVOS64_PARAMETERS",
                       "selector_field": "hClass",
                       "variant_prefix": "ioctl$NV_ESC_RM_ALLOC_"},
        "0xc020462a": {"escape": "NV_ESC_RM_CONTROL",
                       "param_struct": "NVOS54_PARAMETERS",
                       "selector_field": "cmd",
                       "variant_prefix": "ioctl$NV_ESC_RM_CONTROL_"},
    }

    TRACE = ('openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3\n'
             'ioctl(3, 0xc030462b, 0x7ffd0) = 0\n'
             'ioctl(3, 0xc020462b, 0x7ffd0) = 0\n')

    def test_the_request_size_is_read_off_the_request_number(self):
        self.assertEqual(trace2seed.request_size("0xc020462b"), 32)
        self.assertEqual(trace2seed.request_size("0xc030462b"), 48)

    def test_an_unparseable_request_yields_zero_rather_than_raising(self):
        self.assertEqual(trace2seed.request_size("TCGETS"), 0)

    def test_both_calling_forms_are_named_in_the_header(self):
        prog = trace2seed.convert(self.TRACE, {}, self.MUX)
        self.assertIn("traced under 2 calling forms", prog)
        self.assertIn("NVOS21_PARAMETERS", prog)
        self.assertIn("NVOS64_PARAMETERS", prog)

    def test_one_form_alone_does_not_produce_the_line(self):
        one = ('openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3\n'
               'ioctl(3, 0xc030462b, 0x7ffd0) = 0\n')
        self.assertNotIn("calling forms", trace2seed.convert(one, {}, self.MUX))

    def test_each_note_carries_its_parameter_size(self):
        prog = trace2seed.convert(self.TRACE, {}, self.MUX)
        self.assertIn("(32-byte parameter form)", prog)
        self.assertIn("(48-byte parameter form)", prog)

    def test_the_multiplexer_count_is_unchanged(self):
        # The three counts convert reports must still separate: a multiplexer
        # is neither mapped nor unmapped.
        prog = trace2seed.convert(self.TRACE, {}, self.MUX)
        notes = [ln for ln in prog.splitlines()
                 if re.match(r"^# \w+ on r\d+, request ", ln)]
        self.assertEqual(len(notes), 2)


class TestChainProgramsDoNotClaimHandleWiring(unittest.TestCase):
    """Incomplete work: handle wiring. Every parameter struct is written
    &AUTO. The head comment asserted that syzkaller wires hObjectNew to
    hObjectParent from the resource types the descriptions declare, and that
    is unverified: no syzkaller tree exists in this repository and no emitted
    program has been through prog.Deserialize. Stating it as fact is the
    thing this test prevents.
    """

    def program(self):
        return trace2seed.chain_program(
            ("NV01_ROOT", "NV01_DEVICE_0"), ["a"],
            {trace2seed.ALLOC_PREFIX + "NV01_ROOT": ("fd_nv", "0xc030462b"),
             trace2seed.ALLOC_PREFIX + "NV01_DEVICE_0": ("fd_nv",
                                                         "0xc030462b"),
             trace2seed.CONTROL_PREFIX + "a": ("fd_nvidiactl", "0xc020462a")},
            1, 1)

    def test_the_header_says_the_wiring_is_unverified(self):
        text = self.program()
        self.assertIn("has not been checked", text)

    def test_the_header_names_the_consequence_if_it_does_not_hold(self):
        self.assertIn("zero parent handle", self.program())

    def test_the_header_still_names_where_the_resources_are_declared(self):
        self.assertIn("nvidia_structs.txt", self.program())


class TestReusedKernelConfigIsChecked(unittest.TestCase):
    """MEDIUM-7 and MEDIUM-8. The SKIP_KERNEL branch verified only that
    .config exists, and the symbol loop sat in the else branch. Rung 2 builds
    the NVIDIA modules with -fsanitize-coverage=trace-cmp against whatever
    kernel is installed, so a tree whose config lost
    CONFIG_KCOV_ENABLE_COMPARISONS returns the insmod failure the check
    exists to prevent, at rung 2, with nothing between. Separately no
    --disable setting was verified, including CONFIG_RANDOMIZE_BASE, which
    the comment at its disable site calls the precondition for stable stacks
    in dedup.

    Read from the script. Whether a symbol survives olddefconfig and whether
    the modules then load are decided on the build machine, and only the
    check inside the script can observe that.
    """

    def script(self):
        with io.open(os.path.join(HERE, "build_kernel.sh"),
                     encoding="utf-8") as f:
            return f.read()

    def skip_branch(self):
        s = self.script()
        start = s.index('if [[ "$SKIP_KERNEL" == "1" ]]; then')
        return s[start:s.index("\nelse", start)]

    def test_the_reused_kernel_branch_runs_the_config_check(self):
        self.assertIn("check_config", self.skip_branch())

    def test_the_check_is_one_function_used_by_both_branches(self):
        # Two copies drift. The rung that reuses a kernel has to assert the
        # same symbols as the rung that built it.
        self.assertEqual(self.script().count("check_config .config"), 2)

    def test_the_disabled_symbols_are_verified(self):
        s = self.script()
        for sym in ("CONFIG_RANDOMIZE_BASE", "CONFIG_MODULE_SIG_FORCE",
                    "CONFIG_SECURITY_LOCKDOWN_LSM_EARLY",
                    "CONFIG_DEBUG_INFO_NONE"):
            self.assertIn(sym, s.split("REQUIRED_DISABLED=(")[1]
                          .split(")")[0], sym)

    def test_a_surviving_disabled_symbol_is_an_error_and_not_a_warning(self):
        s = self.script()
        i = s.index("if [[ -n \"$surviving\" ]]; then")
        self.assertIn("exit 1", s[i:i + 400])

    def test_every_symbol_the_disable_list_names_is_actually_disabled(self):
        # A symbol asserted off that the script never turns off would fail
        # every build on a distro config that ships it on.
        s = self.script()
        block = s.split("REQUIRED_DISABLED=(")[1].split("\n)")[0]
        for line in block.splitlines():
            sym = line.strip()
            if not sym.startswith("CONFIG_"):
                continue
            self.assertIn("--disable %s" % sym, s, sym)

    def test_the_comparisons_symbol_is_still_in_the_enabled_loop(self):
        s = self.script()
        i = s.index("for sym in CONFIG_KCOV")
        self.assertIn("CONFIG_KCOV_ENABLE_COMPARISONS", s[i:s.index("; do", i)])


class TestTheBuildManifestSurvivesAnInterrupt(unittest.TestCase):
    """L9. The manifest heredoc wrote artifacts/builds/manifest.json with
    json.dump(m, open(mpath,"w")): no mkdir -p on the parent and no
    temp-and-rename. It runs at the end of a multi-hour build, and a missing
    directory or an interrupt there costs the build record.

    The heredoc is extracted and run against a throwaway tree. What it does
    on a real build machine (the gcc and git subprocesses) is not exercised.
    """

    def heredoc(self):
        with io.open(os.path.join(HERE, "build_kernel.sh"),
                     encoding="utf-8") as f:
            s = f.read()
        i = s.index('python3 - "$REPO_ROOT" "$RUNG" "$KVER"')
        start = s.index("<<'EOF'", i) + len("<<'EOF'")
        return s[start:s.index("\nEOF", i)]

    def test_the_heredoc_creates_the_parent_directory(self):
        self.assertIn("makedirs", self.heredoc())

    def test_the_heredoc_writes_through_a_temp_file_and_renames(self):
        body = self.heredoc()
        self.assertIn("mkstemp", body)
        self.assertIn("os.replace", body)

    def test_it_writes_a_manifest_into_a_tree_that_has_no_builds_dir(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = dict(os.environ)
        env["LINUX_SRC"] = tmp.name
        env["NVIDIA_SRC"] = tmp.name
        r = subprocess.run(
            [sys.executable, "-", tmp.name, "1", "6.1.0-test"],
            input=self.heredoc(), capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(tmp.name, "artifacts", "builds",
                               "manifest.json")) as f:
            m = json.load(f)
        self.assertEqual(m["kernel_release"], "6.1.0-test")
        self.assertEqual(m["instrumentation_rung"], 1)

    def test_no_temp_file_is_left_behind(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = dict(os.environ)
        env["LINUX_SRC"] = tmp.name
        env["NVIDIA_SRC"] = tmp.name
        subprocess.run([sys.executable, "-", tmp.name, "2", "6.1.0-test"],
                       input=self.heredoc(), capture_output=True, text=True,
                       env=env)
        d = os.path.join(tmp.name, "artifacts", "builds")
        self.assertEqual([n for n in os.listdir(d) if n.endswith(".tmp")], [])

    def test_a_second_run_merges_rather_than_replaces(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = dict(os.environ)
        env["LINUX_SRC"] = tmp.name
        env["NVIDIA_SRC"] = tmp.name
        d = os.path.join(tmp.name, "artifacts", "builds")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "manifest.json"), "w") as f:
            json.dump({"kept_by_an_earlier_phase": True}, f)
        subprocess.run([sys.executable, "-", tmp.name, "3", "6.1.0-test"],
                       input=self.heredoc(), capture_output=True, text=True,
                       env=env)
        with open(os.path.join(d, "manifest.json")) as f:
            m = json.load(f)
        self.assertTrue(m["kept_by_an_earlier_phase"])
        self.assertEqual(m["instrumentation_rung"], 3)


class TestTheReplayScriptIsBounded(unittest.TestCase):
    """HIGH-1, the running half. Replaying is running a fuzzer target on a
    crashing input, so it is bounded: a timeout per input, a cap on inputs
    per harness, and a path that survives a harness binary that is absent.

    Read from the script plus a run against a stub harness. The real harness
    binaries do not exist in this checkout; whether a libFuzzer or AFL++
    driver binary replays a file argument the way this assumes is decided on
    the SUT.
    """

    def script_path(self):
        return os.path.join(os.path.dirname(HERE), "harnesses", "replay_crashes.sh")

    def script(self):
        with io.open(self.script_path(), encoding="utf-8") as f:
            return f.read()

    def setUp(self):
        if not shutil.which("bash"):
            self.skipTest("bash is not on PATH")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def tree(self, inputs, with_binary=True, harness="fuzz_x"):
        """-> (harness root, crash root) holding a stub that crashes on 'B'."""
        hroot = os.path.join(self.tmp.name, "harnesses")
        croot = os.path.join(self.tmp.name, "crashes")
        build = os.path.join(hroot, harness, "build")
        os.makedirs(build, exist_ok=True)
        os.makedirs(os.path.join(croot, harness), exist_ok=True)
        if with_binary:
            stub = os.path.join(build, harness)
            with open(stub, "w") as f:
                f.write('#!/usr/bin/env bash\n'
                        'b="$(head -c1 "$1")"\n'
                        '[ "$b" = "B" ] || { echo ok; exit 0; }\n'
                        'echo "==1==ERROR: AddressSanitizer: '
                        'heap-buffer-overflow" >&2\n'
                        'exit 1\n')
            os.chmod(stub, 0o755)
        for name, body in inputs.items():
            with open(os.path.join(croot, harness, name), "wb") as f:
                f.write(body)
        return hroot, croot

    def run_replay(self, hroot, croot, env=None):
        e = dict(os.environ)
        e.update({"HARNESS_ROOT": hroot, "CRASH_ROOT": croot,
                  "REPLAY_TIMEOUT": "10"})
        e.update(env or {})
        return subprocess.run(["bash", self.script_path()],
                              capture_output=True, text=True, env=e)

    def test_it_parses(self):
        r = subprocess.run(["bash", "-n", self.script_path()],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_crashing_input_gets_a_report_beside_it(self):
        hroot, croot = self.tree({"id:000000,sig:06": b"Bbad"})
        r = self.run_replay(hroot, croot)
        self.assertEqual(r.returncode, 0, r.stderr)
        report = os.path.join(croot, "fuzz_x",
                              "id:000000,sig:06" + crash_parse.REPORT_SUFFIX)
        self.assertTrue(os.path.isfile(report))
        with open(report) as f:
            self.assertIn("AddressSanitizer", f.read())

    def test_the_report_registers_the_input_end_to_end(self):
        hroot, croot = self.tree({"id:000000,sig:06": b"Bbad"})
        self.run_replay(hroot, croot)
        st = ps.default_state()
        with redirect_stdout(io.StringIO()):
            crash_parse.scan_track_u(st, croot)
        self.assertEqual(len(st["crashes"]), 1)
        self.assertEqual(st["crashes"]["crash-0001"]["dir"],
                         os.path.join(croot, "fuzz_x", "id:000000,sig:06"))

    def test_a_second_run_replays_nothing(self):
        hroot, croot = self.tree({"id:000000,sig:06": b"Bbad"})
        self.run_replay(hroot, croot)
        r = self.run_replay(hroot, croot)
        self.assertIn("replayed 0 input(s)", r.stdout)

    def test_replay_force_redoes_them(self):
        hroot, croot = self.tree({"id:000000,sig:06": b"Bbad"})
        self.run_replay(hroot, croot)
        r = self.run_replay(hroot, croot, {"REPLAY_FORCE": "1"})
        self.assertIn("replayed 1 input(s)", r.stdout)

    def test_the_input_cap_stops_and_says_so(self):
        hroot, croot = self.tree({"id:00000%d,sig:06" % i: b"Bbad"
                                  for i in range(4)})
        r = self.run_replay(hroot, croot, {"REPLAY_MAX_INPUTS": "2"})
        self.assertIn("REPLAY_MAX_INPUTS=2", r.stdout)
        self.assertIn("replayed 2 input(s)", r.stdout)

    def test_a_missing_harness_binary_is_reported_and_not_fatal(self):
        hroot, croot = self.tree({"id:000000,sig:06": b"Bbad"},
                                 with_binary=False)
        r = self.run_replay(hroot, croot)
        self.assertEqual(r.returncode, 0)
        self.assertIn("no harness binary for", r.stdout)

    def test_a_missing_crash_root_exits_two(self):
        r = self.run_replay(self.tmp.name,
                            os.path.join(self.tmp.name, "absent"))
        self.assertEqual(r.returncode, 2)

    def test_a_non_numeric_timeout_is_refused(self):
        hroot, croot = self.tree({"id:000000,sig:06": b"Bbad"})
        r = self.run_replay(hroot, croot, {"REPLAY_TIMEOUT": "abc"})
        self.assertEqual(r.returncode, 2)

    def test_the_readme_afl_writes_is_not_replayed(self):
        hroot, croot = self.tree({"id:000000,sig:06": b"Bbad",
                                  "README.txt": b"afl readme"})
        r = self.run_replay(hroot, croot)
        self.assertIn("replayed 1 input(s)", r.stdout)

    def test_run_all_invokes_it_after_the_copy(self):
        # The replay has to run where the binaries and the inputs are both
        # present, which is the harvest step of run_all.sh.
        with io.open(os.path.join(os.path.dirname(HERE), "harnesses",
                                  "run_all.sh"),
                     encoding="utf-8") as f:
            s = f.read()
        self.assertLess(s.index("total crash inputs:"),
                        s.index('bash "${here}/replay_crashes.sh"'))

    def test_the_report_suffix_matches_what_crash_parse_reads(self):
        # Two names for one pairing convention: a drift on either side
        # silently returns Track U to registering nothing.
        self.assertIn('REPORT_SUFFIX="%s"' % crash_parse.REPORT_SUFFIX,
                      self.script())


# ---------------------------------------------------------------------------
# Review wave 2, surface extraction and description generation. From
# tmp/tests2/surface.py and tmp/fix/surface.md: the version guard's
# independent-source rule, the impl definition scan, the chip-gated parent
# expansion, the pin gates and the provenance digest. 14 classes, 82 tests.
#
# Six tests above were superseded by these and are gone; each site carries a
# comment naming its replacement.
# ---------------------------------------------------------------------------


class TestVersionGuardCountsIndependentSources(unittest.TestCase):
    """Six artefacts built from one checkout are one source, not six.

    `compared = len(rows)` counted one entry per versioned artefact file, and
    `compared < 2` was the only gate that could return INSUFFICIENT. All six
    committed artefacts take their driver_version from the same version.mk:
    ioctl_inventory.py, ctrl_surface.py and object_graph.py read one checkout
    and generation.json copies the value out of the control inventory. A tree
    with no source checkout, no loaded driver and no declared branch therefore
    exited 0 reporting "agreement across 6 sources", having compared the
    artefacts only to each other. This is P1-2 in a new shape: the old defect
    returned 0 when nothing answered, this one when only self-referential
    sources answered.
    """

    setUp = TestVersionGuardSourceCount.setUp
    set_running = TestVersionGuardSourceCount.set_running
    write_map = TestVersionGuardSourceCount.write_map
    write_checkout = TestVersionGuardSourceCount.write_checkout
    write_declared = TestVersionGuardSourceCount.write_declared
    write_generation = TestVersionGuardSourceCount.write_generation
    check = TestVersionGuardSourceCount.check

    def write_surface(self, name, version):
        """One surface/*.json carrying a driver_version."""
        with open(os.path.join(self.surface, name), "w") as f:
            json.dump({"source": {"driver_version": version}}, f)

    def write_six_artefacts(self, version):
        """The committed shape: six files, one stamp, one checkout behind it."""
        self.write_map(version)
        for name in ("ioctl-inventory.json", "rm-chains.json",
                     "rm-control-inventory.json", "rm-object-graph.json"):
            self.write_surface(name, version)
        self.write_generation(version)

    def test_six_artefacts_agreeing_are_not_a_verdict(self):
        # The exact reproduction from the review. Before the fix this printed
        # "agreement across 6 sources" and returned 0.
        self.write_six_artefacts("610.57.04")
        code, out = self.check("--no-running")
        self.assertEqual(code, surface_verify.INSUFFICIENT)
        self.assertNotIn("agreement", out)
        # The operator is told why six files did not count as six sources.
        self.assertIn("one source", out)
        self.assertIn("--allow-single-source", out)

    def test_all_six_are_still_read_and_printed(self):
        # Counting them once must not stop the guard reading them. Each still
        # appears in the table, and a partial regeneration is still caught.
        self.write_six_artefacts("610.57.04")
        _code, out = self.check("--no-running")
        for name in ("tools/ioctl_map.json",
                     "surface/ioctl-inventory.json",
                     "surface/rm-object-graph.json",
                     "descriptions/generation.json"):
            self.assertIn(name, out)

    def test_the_generation_record_is_still_scanned_as_an_artefact(self):
        # Replaces TestVersionGuardCoversDescriptions
        # .test_the_generation_record_is_a_version_source. The description set
        # is what syzkaller consumes, so its stamp must still be read; it is
        # now read as part of the artefact group rather than as a source of
        # its own.
        self.write_map("610.57.04")
        self.write_generation("610.57.04")
        self.write_checkout("610.57.04")
        code, out = self.check()
        self.assertEqual(code, 0)
        self.assertIn("descriptions/generation.json", out)

    def test_an_artefact_group_plus_a_checkout_is_two_sources(self):
        self.write_six_artefacts("610.57.04")
        self.write_checkout("610.57.04")
        code, out = self.check("--no-running")
        self.assertEqual(code, 0)
        self.assertIn("agreement across 2 independent sources", out)
        self.assertIn("artefacts (6 files)", out)

    def test_an_artefact_group_plus_a_running_driver_is_two_sources(self):
        self.write_six_artefacts("610.57.04")
        self.set_running("610.57.04")
        code, out = self.check()
        self.assertEqual(code, 0)
        self.assertIn("agreement across 2 independent sources", out)

    def test_an_artefact_group_plus_a_declared_branch_is_two_sources(self):
        self.write_six_artefacts("610.57.04")
        self.write_declared("610.57.04")
        code, out = self.check("--no-running")
        self.assertEqual(code, 0)
        self.assertIn("agreement across 2 independent sources", out)

    def test_the_three_observing_groups_are_counted_separately(self):
        # No artefact at all: a checkout, a running driver and a declared
        # branch are three independent sources between them.
        self.write_checkout("610.57.04")
        self.set_running("610.57.04")
        self.write_declared("610.57.04")
        code, out = self.check()
        self.assertEqual(code, 0)
        self.assertIn("agreement across 3 independent sources", out)

    def test_allow_single_source_still_accepts_the_artefact_group(self):
        # Replaces
        # TestVersionGuardSourceCount.test_allow_single_source_accepts_the_deliberate_case.
        # The flag covers one deliberate source, and the artefact group is one.
        self.write_six_artefacts("610.57.04")
        code, _out = self.check("--no-running", "--allow-single-source")
        self.assertEqual(code, 0)

    def test_a_partial_regeneration_is_still_a_disagreement(self):
        # Grouping the artefacts must not hide a disagreement inside the
        # group: that is the signal that one extractor was re-run and the
        # others were not.
        self.write_six_artefacts("610.57.04")
        self.write_surface("rm-object-graph.json", "610.62")
        code, out = self.check("--no-running")
        self.assertEqual(code, surface_verify.DISAGREE)
        self.assertIn("artefacts disagree with each other", out)

    def test_source_groups_partitions_rather_than_dropping(self):
        # Every available source reaches exactly one group, so the printed
        # table and the counted groups cannot drift apart.
        groups = surface_verify.source_groups(
            {"a.json": "610.57.04", "b.json": "610.57.04"},
            "610.57.04", "610.57.04", "610.57.04")
        self.assertEqual(len(groups), 4)
        members = [row for _name, rows in groups for row in rows]
        self.assertEqual(len(members), 5)
        self.assertEqual(groups[0][0], surface_verify.ARTEFACT_GROUP)
        self.assertEqual(len(groups[0][1]), 2)

    def test_an_absent_group_is_not_counted(self):
        groups = surface_verify.source_groups({}, None, None, None)
        self.assertEqual(groups, [])


class TestStampWritesTheSameBytesOnEveryPlatform(unittest.TestCase):
    """cmd_stamp opened the map with no newline=, so a run on Windows rewrote
    every line of tools/ioctl_map.json with CRLF. object_graph.write_json and
    syzlang_gen.write_file both pin LF for the stated reason that a run on
    Windows and a run under WSL must produce the same bytes."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.src = os.path.join(self.tmp.name, "checkout")
        os.makedirs(self.src)
        with open(os.path.join(self.src, "version.mk"), "w") as f:
            f.write("NVIDIA_VERSION = 610.57.04\n")
        self.map_path = os.path.join(self.tmp.name, "ioctl_map.json")
        with open(self.map_path, "w", newline="\n") as f:
            json.dump({"0xc020462a": "NV_ESC_RM_ALLOC"}, f, indent=2)
            f.write("\n")
        original = surface_verify.MAP_PATH
        surface_verify.MAP_PATH = self.map_path
        self.addCleanup(setattr, surface_verify, "MAP_PATH", original)

    def stamp(self):
        args = surface_verify.build_parser().parse_args(
            ["stamp", "--src", self.src])
        with redirect_stdout(io.StringIO()):
            return surface_verify.cmd_stamp(args)

    def test_the_stamped_map_carries_no_carriage_return(self):
        self.assertEqual(self.stamp(), 0)
        with open(self.map_path, "rb") as f:
            blob = f.read()
        self.assertNotIn(b"\r\n", blob)
        self.assertIn(b"comment_driver_version", blob)

    def test_stamping_twice_is_byte_stable(self):
        self.stamp()
        with open(self.map_path, "rb") as f:
            first = f.read()
        self.stamp()
        with open(self.map_path, "rb") as f:
            self.assertEqual(f.read(), first)

    def test_no_temporary_file_is_left_behind(self):
        self.stamp()
        self.assertFalse(os.path.exists(self.map_path + ".tmp"))

    def test_the_line_ending_is_pinned_rather_than_inherited(self):
        # The byte assertions above cannot fail on a platform whose default
        # translation is already LF, and the defect only appears on Windows.
        # object_graph.write_json and syzlang_gen.write_file pin it for the
        # same reason, so the pin itself is what is asserted here.
        source = inspect.getsource(surface_verify.cmd_stamp)
        # The open() call, not the comment above it that names the same
        # argument.
        self.assertIn(r'open(tmp, "w", encoding="utf-8", newline="\n")',
                      source)
        self.assertIn("os.fsync(fh.fileno())", source)


class TestImplScanFindsEveryDefinitionStyle(unittest.TestCase):
    """69 of the 531 control commands scored as CVE-cold because the scan
    missed their definitions, not because their files had never been touched.

    The old pattern was `^(\\w+)_IMPL\\s*\\(` over src/nvidia/src only, on the
    stated assumption that "only the definition sits in column zero". Three
    definition styles in this tree defeat it: a definition outside
    src/nvidia/src, a return type on the same line before the name, and a HAL
    suffix that is not _IMPL. An unresolved impl_file sets cve_file_releases
    to 0, so the CVE component of rank_score collapsed for all of them.
    """

    def scan(self, files):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        for rel, text in files.items():
            path = os.path.join(directory, rel.replace("/", os.sep))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        return ctrl_rank.scan_impl_definitions(directory)

    def test_a_definition_outside_src_nvidia_src_is_found(self):
        # The cliresCtrlCmdOsUnix* export and import family lives in
        # src/nvidia/arch/nvalloc/unix/src/os.c. 11 commands, and the
        # historically CVE-dense unprivileged path on this surface.
        found = self.scan({
            "src/nvidia/arch/nvalloc/unix/src/os.c":
                "NV_STATUS\ncliresCtrlCmdOsUnixExportObjectsToFd_IMPL\n(\n"
                "    RmClientResource *p\n)\n{\n}\n"})
        self.assertIn("cliresCtrlCmdOsUnixExportObjectsToFd", found)
        rel, line, suffix = found["cliresCtrlCmdOsUnixExportObjectsToFd"]
        self.assertEqual(rel, "src/nvidia/arch/nvalloc/unix/src/os.c")
        self.assertEqual(line, 2)
        self.assertEqual(suffix, "IMPL")

    def test_a_return_type_on_the_same_line_is_found(self):
        found = self.scan({
            "src/nvidia/src/kernel/a.c":
                "NV_STATUS ksmdbgssnCtrlCmdDebugExecRegOps_IMPL\n(\n"
                "    KernelSMDebuggerSession *p\n)\n{\n}\n"})
        self.assertIn("ksmdbgssnCtrlCmdDebugExecRegOps", found)
        self.assertEqual(found["ksmdbgssnCtrlCmdDebugExecRegOps"][1], 1)

    def test_the_hal_suffixes_are_found(self):
        # 42 of the 69 carried _VF, _KERNEL or _PHYSICAL rather than _IMPL.
        found = self.scan({
            "src/nvidia/src/kernel/gpu/perf/kern_perf_ctrl.c":
                "NV_STATUS\nsubdeviceCtrlCmdPerfGetGpumonPerfmonUtilSamplesV2_VF"
                "\n(\n    Subdevice *p\n)\n{\n}\n",
            "src/nvidia/src/kernel/b.c":
                "NV_STATUS someCmd_KERNEL(void *p)\n{\n}\n",
            "src/nvidia/src/kernel/c.c":
                "NV_STATUS otherCmd_PHYSICAL(void *p)\n{\n}\n"})
        self.assertEqual(
            found["subdeviceCtrlCmdPerfGetGpumonPerfmonUtilSamplesV2"][2],
            "VF")
        self.assertEqual(found["someCmd"][2], "KERNEL")
        self.assertEqual(found["otherCmd"][2], "PHYSICAL")

    def test_an_indented_call_is_not_read_as_a_definition(self):
        # The line anchor is what separates a definition from the NVOC
        # generated call, which sits inside a function body and is indented.
        # Dropping the anchor to admit the return type would match every call.
        found = self.scan({
            "src/nvidia/generated/g_thing_nvoc.c":
                "static NV_STATUS thing__EXPORT(void *p, void *q) {\n"
                "    return someHandler_IMPL(p, q);\n}\n"})
        self.assertNotIn("someHandler", found)

    def test_impl_wins_over_a_hal_variant_for_the_same_handler(self):
        # 8 handlers carry more than one definition. The resolution must not
        # depend on directory traversal order.
        found = self.scan({
            "src/nvidia/src/kernel/gpu/ce/kernel_ce_ctrl.c":
                "NV_STATUS subdeviceCtrlCmdCeGetCapsV2_VF(void *p)\n{\n}\n",
            "src/nvidia/src/kernel/gpu/ce/kernel_ce_shared.c":
                "NV_STATUS subdeviceCtrlCmdCeGetCapsV2_IMPL(void *p)\n{\n}\n"})
        rel, _line, suffix = found["subdeviceCtrlCmdCeGetCapsV2"]
        self.assertEqual(suffix, "IMPL")
        self.assertEqual(rel, "src/nvidia/src/kernel/gpu/ce/kernel_ce_shared.c")

    def test_kernel_wins_over_vf_where_there_is_no_impl(self):
        # _VF runs only in an SR-IOV guest; the bare-metal kernel-side half is
        # the one an unprivileged process on the target reaches.
        found = self.scan({
            "src/nvidia/src/a.c": "NV_STATUS h_VF(void *p)\n{\n}\n",
            "src/nvidia/src/b.c": "NV_STATUS h_KERNEL(void *p)\n{\n}\n"})
        self.assertEqual(found["h"][2], "KERNEL")

    def test_a_resolved_handler_carries_file_line_and_suffix(self):
        # Replaces TestControlRankScoring
        # .test_the_impl_suffix_is_what_joins_a_handler_to_a_hotspot, whose
        # impls fixture was a 2-tuple. build_records now takes the suffix too.
        rows = ctrl_rank.build_records(
            [_method("subdeviceCtrlCmdGpuGetInfoV2", "SubdevRes", "0x1")],
            {"subdeviceCtrlCmdGpuGetInfoV2": ("src/a.c", 641, "IMPL")},
            {"src/a.c": 6},
            {"subdeviceCtrlCmdGpuGetInfoV2_IMPL": {"releases": 3}},
            {"SubdevRes": (3, "SUBDEV", None)},
            {"P": 24})
        self.assertEqual(rows[0]["impl_file"], "src/a.c")
        self.assertEqual(rows[0]["impl_line"], 641)
        self.assertEqual(rows[0]["impl_suffix"], "IMPL")
        self.assertEqual(rows[0]["impl_state"], "resolved")
        self.assertEqual(rows[0]["cve_file_releases"], 6)
        self.assertEqual(rows[0]["cve_function_releases"], 3)
        # Carried over from the superseded test: the sizes map and the chain
        # map are read on the same call and nothing else asserts either.
        self.assertEqual(rows[0]["param_size"], 24)
        self.assertEqual(rows[0]["chain_length"], 3)

    def test_a_hal_handler_joins_the_hotspot_under_its_own_suffix(self):
        # by_function keys on the defined symbol, so a _VF handler is recorded
        # as handler_VF. Looking only for handler_IMPL missed it.
        rows = ctrl_rank.build_records(
            [_method("subdeviceCtrlCmdPerfGetGpumonPerfmonUtilSamplesV2",
                     "SubdevRes", "0x1")],
            {"subdeviceCtrlCmdPerfGetGpumonPerfmonUtilSamplesV2":
                ("src/p.c", 51, "VF")},
            {"src/p.c": 4},
            {"subdeviceCtrlCmdPerfGetGpumonPerfmonUtilSamplesV2_VF":
                {"releases": 7}},
            {"SubdevRes": (3, "SUBDEV", None)},
            {"P": 8})
        self.assertEqual(rows[0]["cve_function_releases"], 7)

    def test_a_handler_with_no_definition_says_so(self):
        # 13 of the 531 resolve to an NVOC generated inline with no release
        # history of its own. A bare null read as a scan that failed.
        rows = ctrl_rank.build_records(
            [_method("kchannelCtrlGetTpcPartitionMode", "SubdevRes", "0x1")],
            {}, {"src/a.c": 6}, {}, {"SubdevRes": (3, "SUBDEV", None)},
            {"P": 8})
        self.assertIsNone(rows[0]["impl_file"])
        self.assertIsNone(rows[0]["impl_suffix"])
        self.assertEqual(rows[0]["impl_state"], "no hand-written definition")
        self.assertEqual(rows[0]["cve_file_releases"], 0)


class TestDepthComponentStaysNormalised(unittest.TestCase):
    """The weighting documents every component as normalised to [0, 1].

    `lengths = [r["chain_length"] for r in rows if r["chain_length"]]` dropped
    0 as falsy, so a zero-length chain could not raise max_len and
    (max_len - 0) / (max_len - 1) went above 1.0. No record carries 0 today.
    """

    _rows = TestControlRankScoring._rows

    def test_a_zero_length_chain_does_not_exceed_one(self):
        rows = [self._rows(handler="zero", method_id="0x1", chain_length=0),
                self._rows(handler="deep", method_id="0x2", chain_length=5)]
        ctrl_rank.score_records(rows)
        by = {r["handler"]: r["rank_components"]["depth"] for r in rows}
        self.assertLessEqual(by["zero"], 1.0)
        self.assertEqual(by["zero"], 1.0)
        self.assertEqual(by["deep"], 0.0)

    def test_every_component_of_every_row_stays_in_range(self):
        rows = [self._rows(handler="a", method_id="0x1", chain_length=0,
                           cve_file_releases=40, param_size=229392),
                self._rows(handler="b", method_id="0x2", chain_length=5,
                           cve_function_releases=40),
                self._rows(handler="c", method_id="0x3", chain_length=None)]
        ctrl_rank.score_records(rows)
        for row in rows:
            for name, value in row["rank_components"].items():
                self.assertGreaterEqual(value, 0.0, name)
                self.assertLessEqual(value, 1.0, name)

    def test_the_documented_maximum_matches_the_committed_data(self):
        # The docstring stated a deepest chain of 7. The committed ranking
        # carries a maximum of 5, and score_records derives it per run.
        path = os.path.join(os.path.dirname(HERE), "surface", "rm-control-rank.json")
        if not os.path.isfile(path):
            self.skipTest("committed ranking not present")
        with open(path, encoding="utf-8") as fh:
            commands = json.load(fh)["commands"]
        lengths = [c["chain_length"] for c in commands
                   if c["chain_length"] is not None]
        self.assertEqual(max(lengths), 5)
        self.assertNotIn("costs 7", ctrl_rank.__doc__)


class TestAnyParentChainCostsAClient(unittest.TestCase):
    """allocatable_chain filtered ANY_PARENT out of the returned steps, so a
    class whose only parent is the sentinel reported a chain of length 1, the
    same as a class hanging off the file descriptor. allocatable_depths seeds
    the sentinel at depth 1 precisely because such a class needs a client
    first, so the chain understated the prologue by one allocation. 5 classes
    are parented only by RS_ANY_PARENT and 2 of them own control commands.
    """

    GRAPH = {"NV01_ROOT": [object_graph.ROOT],
             "NV01_EVENT": [object_graph.ANY_PARENT]}
    DEPTH = {object_graph.ROOT: 0, object_graph.ANY_PARENT: 1,
             "NV01_ROOT": 1, "NV01_EVENT": 2}

    def test_the_sentinel_resolves_to_a_client(self):
        # Replaces TestChainWalkTerminates
        # .test_the_any_parent_sentinel_ends_the_walk, which asserted ["E"].
        self.assertEqual(
            object_graph.allocatable_chain(self.GRAPH, self.DEPTH,
                                           "NV01_EVENT"),
            ["NV01_ROOT", "NV01_EVENT"])

    def test_the_chain_length_matches_the_allocatable_depth(self):
        # The invariant the old behaviour broke: a chain is the prologue, and
        # its length is what allocatable_depths already costed.
        steps = object_graph.allocatable_chain(self.GRAPH, self.DEPTH,
                                               "NV01_EVENT")
        self.assertEqual(len(steps), self.DEPTH["NV01_EVENT"])

    def test_the_substitute_is_the_cheapest_root_child_by_name(self):
        graph = dict(self.GRAPH, NV01_ROOT_CLIENT=[object_graph.ROOT])
        depth = dict(self.DEPTH, NV01_ROOT_CLIENT=1)
        self.assertEqual(object_graph.cheapest_root_child(depth), "NV01_ROOT")
        self.assertEqual(
            object_graph.allocatable_chain(graph, depth, "NV01_EVENT"),
            ["NV01_ROOT", "NV01_EVENT"])

    def test_the_root_sentinel_is_still_dropped(self):
        # ROOT is the file descriptor and not an allocation, so it stays out.
        self.assertEqual(
            object_graph.allocatable_chain(self.GRAPH, self.DEPTH,
                                           "NV01_ROOT"),
            ["NV01_ROOT"])

    def test_a_graph_with_nothing_on_the_descriptor_has_no_chain(self):
        # Nothing is allocatable at depth 1, so there is no object for the
        # sentinel to stand for and the class is genuinely unreachable.
        graph = {"E": [object_graph.ANY_PARENT]}
        depth = {object_graph.ROOT: 0, object_graph.ANY_PARENT: 1, "E": 2}
        self.assertIsNone(object_graph.cheapest_root_child(depth))
        self.assertIsNone(object_graph.allocatable_chain(graph, depth, "E"))

    def test_both_breadth_first_walks_iterate_in_the_same_order(self):
        # allocatable_depths sorted its neighbours and depths did not.
        source = inspect.getsource(object_graph.depths)
        self.assertIn("sorted(kids.get(node, []))", source)


class TestDisplayClassesAreChipGated(AllocExpansionFixture):
    """CHIP_EXCLUSIVE_PARENT_RE matched one family name. The object graph
    carries a second: NVC570_DISPLAY through NVCC70_DISPLAY are one display
    class per chip generation, and 38 classes list all eight as legal parents.
    parent_is_narrow called that set narrow, so --all-classes expanded it into
    266 variants of which at most 2 are live on any one GPU. All 38 are
    privileged, so the default path was unaffected and the masking was
    incidental.
    """

    DISPLAY = ["NVC570_DISPLAY", "NVC670_DISPLAY", "NVC770_DISPLAY",
               "NVC870_DISPLAY", "NVC970_DISPLAY", "NVCA70_DISPLAY",
               "NVCB70_DISPLAY", "NVCC70_DISPLAY"]

    def test_the_display_family_is_wide(self):
        self.assertFalse(syzlang_gen.parent_is_narrow(self.DISPLAY))
        self.assertFalse(syzlang_gen.parent_is_narrow(self.DISPLAY[:2]))

    def test_every_member_of_the_family_is_recognised(self):
        self.assertEqual(
            sorted(syzlang_gen.chip_exclusive_parents(self.DISPLAY)),
            sorted(self.DISPLAY))

    def test_one_display_parent_beside_ungated_ones_is_still_narrow(self):
        self.assertTrue(syzlang_gen.parent_is_narrow(
            ["NVC670_DISPLAY", "NV01_DEVICE_0"]))

    def test_the_unnumbered_display_classes_are_not_in_the_family(self):
        # NV04_DISPLAY_COMMON, NVC372_DISPLAY_SW and NVA083_GRID_DISPLAYLESS
        # are not chip-numbered. Reading them as gated would make a set naming
        # two of them wide for no reason.
        for name in ("NV04_DISPLAY_COMMON", "NVC372_DISPLAY_SW",
                     "NVA083_GRID_DISPLAYLESS", "NVC573_DISP_CAPABILITIES"):
            self.assertEqual(syzlang_gen.chip_exclusive_parents([name]), [],
                             name)
        self.assertTrue(syzlang_gen.parent_is_narrow(
            ["NV04_DISPLAY_COMMON", "NVC372_DISPLAY_SW"]))

    def test_a_conflict_in_one_family_does_not_borrow_from_another(self):
        # One GPFIFO parent and one display parent is one member of each
        # family, which is no exclusion in either. Counting them together
        # would call the set wide.
        self.assertTrue(syzlang_gen.parent_is_narrow(
            ["GF100_CHANNEL_GPFIFO", "NVC670_DISPLAY"]))
        self.assertEqual(
            [sorted(f) for f in syzlang_gen.chip_exclusive_by_family(
                ["GF100_CHANNEL_GPFIFO", "NVC670_DISPLAY"])],
            [["GF100_CHANNEL_GPFIFO"], ["NVC670_DISPLAY"]])

    def test_a_display_parented_class_emits_one_variant(self):
        graph = self.graph(extra=[
            self.record(name, ["NV01_DEVICE_0"], 3) for name in self.DISPLAY
        ] + [self.record("DISPLAY_CHILD", list(self.DISPLAY), 4)])
        _text, records, _skipped = self.emit(graph)
        self.assertEqual(self.names(records)["DISPLAY_CHILD"],
                         ["NV_ESC_RM_ALLOC_DISPLAY_CHILD"])


class TestEveryPinnedFieldIsChecked(unittest.TestCase):
    """require_pinned ran on cmd and hClass only. Three fields that
    render_struct pins by override were covered by neither pin gate:
    nv_ioctl_xfer_t.ptr, nv_ioctl_xfer_t.size and NVOS54_PARAMETERS.paramsSize.
    A field renamed in the driver header drops its override silently, and the
    cost is a stream of failed executions rather than a build error.
    """

    def rendered(self, text):
        emitter = types.SimpleNamespace(rendered={"v": text})
        return emitter

    def test_an_unpinned_size_is_rejected(self):
        emitter = self.rendered("v {\n\tcmd\tconst[1, int32]\n"
                                "\tsize\tint32\n\tptr\tptr64[inout, x]\n}")
        with self.assertRaises(SystemExit) as caught:
            syzlang_gen.require_pinned(emitter, "v", "size", "the XFER wrapper")
        self.assertIn("size", str(caught.exception))

    def test_an_integer_pointer_is_rejected(self):
        emitter = self.rendered("v {\n\tcmd\tconst[1, int32]\n"
                                "\tsize\tconst[8, int32]\n\tptr\tint64\n}")
        with self.assertRaises(SystemExit) as caught:
            syzlang_gen.require_pointer(emitter, "v", "ptr",
                                        "the XFER wrapper")
        self.assertIn("address", str(caught.exception))

    def test_a_real_pointer_passes(self):
        # Negative control: asserts by the absence of SystemExit, so it
        # also passes against a require_pointer body of `pass`. The
        # paired test_an_integer_pointer_is_rejected fails against one.
        emitter = self.rendered("v {\n\tptr\tptr64[inout, thing]\n}")
        syzlang_gen.require_pointer(emitter, "v", "ptr", "the XFER wrapper")

    def test_a_pinned_constant_is_not_accepted_as_a_pointer(self):
        # const[0, int64] is pinned but is not an address.
        emitter = self.rendered("v {\n\tptr\tconst[0, int64]\n}")
        with self.assertRaises(SystemExit):
            syzlang_gen.require_pointer(emitter, "v", "ptr", "the wrapper")

    def test_an_unrendered_variant_is_rejected_by_both_checks(self):
        emitter = types.SimpleNamespace(rendered={})
        for check in (syzlang_gen.require_pinned, syzlang_gen.require_pointer):
            with self.assertRaises(SystemExit) as caught:
                check(emitter, "missing", "ptr", "the wrapper")
            self.assertIn("never rendered", str(caught.exception))

    def test_the_xfer_emitter_refuses_a_dropped_size_override(self):
        # The committed-set assertions below check the artefact. This checks
        # the guard, which is what a renamed driver field would trip.
        emitter, command = self.xfer_fixture()
        original = syzlang_gen.variant_struct

        def drop_size(em, base, name, overrides):
            return original(em, base, name,
                            {k: v for k, v in overrides.items()
                             if k != "size"})

        syzlang_gen.variant_struct = drop_size
        self.addCleanup(setattr, syzlang_gen, "variant_struct", original)
        with self.assertRaises(SystemExit) as caught:
            syzlang_gen.xfer_variant_struct(emitter, command, "thing")
        self.assertIn("size", str(caught.exception))

    def test_the_xfer_emitter_refuses_a_dropped_ptr_override(self):
        emitter, command = self.xfer_fixture()
        original = syzlang_gen.variant_struct

        def drop_ptr(em, base, name, overrides):
            return original(em, base, name,
                            {k: v for k, v in overrides.items()
                             if k != "ptr"})

        syzlang_gen.variant_struct = drop_ptr
        self.addCleanup(setattr, syzlang_gen, "variant_struct", original)
        with self.assertRaises(SystemExit) as caught:
            syzlang_gen.xfer_variant_struct(emitter, command, "thing")
        self.assertIn("ptr", str(caught.exception))

    def test_the_xfer_emitter_accepts_every_override_in_place(self):
        emitter, command = self.xfer_fixture()
        name = syzlang_gen.xfer_variant_struct(emitter, command, "thing")
        self.assertTrue(name.startswith("nv_xfer_"))

    def xfer_fixture(self):
        """An emitter carrying nv_ioctl_xfer_t and one inner escape record."""
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        path = os.path.join(directory, "xfer.h")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("""
typedef struct
{
    NvU32 cmd;
    NvU32 size;
    NvU64 ptr;
} nv_ioctl_xfer_t;

typedef struct
{
    NvU32 field;
} thing;
""")
        index = syzlang_gen.TypeIndex()
        index.scan_file(path, "xfer.h")
        emitter = syzlang_gen.Emitter(index, {})
        command = {"name": "NV_ESC_RM_THING", "nr": 42, "param_size": 8}
        return emitter, command

    def test_the_committed_xfer_variants_pin_all_three_fields(self):
        path = os.path.join(os.path.dirname(HERE), "descriptions",
                            "nvidia_structs.txt")
        if not os.path.isfile(path):
            self.skipTest("committed description set not present")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        blocks = [b for b in text.split("\n\n") if b.startswith("nv_xfer_")]
        self.assertGreaterEqual(len(blocks), 31)
        for block in blocks:
            name = block.split(" ", 1)[0]
            self.assertTrue(syzlang_gen.pinned_field(block, "cmd"), name)
            self.assertTrue(syzlang_gen.pinned_field(block, "size"), name)
            self.assertTrue(syzlang_gen.pointer_field(block, "ptr"), name)

    def test_the_committed_control_variants_pin_params_size(self):
        path = os.path.join(os.path.dirname(HERE), "descriptions",
                            "nvidia_structs.txt")
        if not os.path.isfile(path):
            self.skipTest("committed description set not present")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        blocks = [b for b in text.split("\n\n")
                  if b.startswith("nvos54_ctrl_")]
        self.assertGreaterEqual(len(blocks), 531)
        for block in blocks:
            name = block.split(" ", 1)[0]
            self.assertTrue(syzlang_field_pinned(block, "paramsSize"), name)


def syzlang_field_pinned(block, field):
    """Local alias, so the assertion above reads as one call per field."""
    return syzlang_gen.pinned_field(block, field)


class TestControlVariantNamesCannotCollide(AllocExpansionFixture):
    """emit_alloc raises SystemExit when two allocation variants render alike
    and states why: "one description would silently overwrite the other".
    emit_control had no such guard, and Emitter.add_raw returns the existing
    struct unchanged rather than raising, so two control commands sharing a
    handler name would take the first command's parameter struct and emit two
    identical ioctl lines. Handler names are unique across all 1372 exported
    control methods today, so this cannot fire.
    """

    def emit_control(self, methods):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        path = os.path.join(directory, "ctrl.h")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("""
typedef struct
{
    NvU32 hClient;
    NvU32 hObject;
    NvU32 cmd;
    NvU32 flags;
    NvU64 params;
    NvU32 paramsSize;
    NvU32 status;
} NVOS54_PARAMETERS;

typedef struct
{
    NvU32 field;
} P;
""")
        index = syzlang_gen.TypeIndex()
        index.scan_file(path, "ctrl.h")
        emitter = syzlang_gen.Emitter(index, {})
        inventory = {"nodes": [{"commands": [
            {"name": syzlang_gen.CONTROL_ESCAPE,
             "requests": ["0xc020462a"]}]}]}
        return syzlang_gen.emit_control(
            emitter, inventory, {"methods": methods}, {},
            {"records": []}, None, 0, None)

    def test_two_handlers_rendering_alike_are_refused(self):
        methods = [_method("thing_one", "C", "0x1"),
                   _method("thing.one", "C", "0x2")]
        with self.assertRaises(SystemExit) as caught:
            self.emit_control(methods)
        message = str(caught.exception)
        self.assertIn("nvos54_ctrl_thing_one", message)
        self.assertIn("silently overwrite", message)

    def test_distinct_handlers_are_not_refused(self):
        # Negative control: asserts by the absence of SystemExit. The
        # paired test_two_handlers_rendering_alike_are_refused is the
        # half that fails when the collision guard is absent.
        self.emit_control([_method("thing_one", "C", "0x1"),
                           _method("thing_two", "C", "0x2")])


class TestNoCommittedArtefactCarriesAnAbsolutePath(unittest.TestCase):
    """Every path a committed artefact records is relative to the repository.

    An extractor that wrote os.path.abspath() into its provenance block put
    the author's home directory into a file that ships, and made the same
    source produce a different artefact under Windows and under WSL.
    """

    ROOT = os.path.dirname(HERE)
    DIRS = ("surface", "descriptions")
    ABSOLUTE = re.compile(
        r"(?:(?<![A-Za-z0-9])[A-Za-z]:[\/])"   # a Windows drive, not a URL scheme
        r"|(?:/mnt/[a-z]/)"                  # a WSL drive mount
        r"|(?:/(?:home|Users)/[^/\"]+)")    # a home directory

    def files(self):
        for name in self.DIRS:
            root = os.path.join(self.ROOT, name)
            if not os.path.isdir(root):
                continue
            for entry in sorted(os.listdir(root)):
                if entry.endswith((".json", ".txt", ".h", ".md")):
                    yield os.path.join(root, entry)

    def test_the_committed_artefacts_are_present(self):
        self.assertGreaterEqual(len(list(self.files())), 15)

    def test_no_committed_artefact_names_an_absolute_path(self):
        for path in self.files():
            with io.open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            hit = self.ABSOLUTE.search(text)
            self.assertIsNone(
                hit, "%s records the absolute path %r. Provenance blocks go "
                     "through repo_relative()."
                     % (os.path.relpath(path, self.ROOT),
                        hit.group(0) if hit else ""))

    def test_repo_relative_keeps_a_path_inside_the_tree_relative(self):
        for mod in (object_graph, ctrl_rank, ctrl_surface, ioctl_inventory):
            inside = os.path.join(mod.REPO_ROOT, "surface", "x.json")
            self.assertEqual(mod.repo_relative(inside), "surface/x.json",
                             mod.__name__)

    def test_repo_relative_leaves_a_path_outside_the_tree_absolute(self):
        outside = os.path.abspath(os.path.join(
            object_graph.REPO_ROOT, os.pardir, "elsewhere", "x.json"))
        self.assertEqual(object_graph.repo_relative(outside),
                         outside.replace(os.sep, "/"))


class TestProvenanceDigestsEveryInput(unittest.TestCase):
    """generation.json digested two of its five inputs and recorded no driver
    commit. The reasoning .gitignore gives for digesting rm-control-rank.json
    holds for the rest: a checkout without one regenerates a different set
    under the same provenance record. The object graph is the input whose
    collapse was P0-1 and it carried no digest at all.
    """

    def setUp(self):
        self.path = os.path.join(os.path.dirname(HERE), "descriptions",
                                 "generation.json")
        if not os.path.isfile(self.path):
            self.skipTest("committed generation record not present")
        with open(self.path, encoding="utf-8") as fh:
            self.record = json.load(fh)["generated_from"]

    def digest(self, path):
        with open(os.path.join(os.path.dirname(HERE), path), "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()

    def test_every_json_input_carries_a_digest(self):
        for key in ("escape_inventory", "control_inventory", "object_graph"):
            entry = self.record[key]
            self.assertIsInstance(entry, dict, key)
            self.assertIn("sha256", entry)
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")

    def test_the_object_graph_digest_matches_the_file_on_disk(self):
        entry = self.record["object_graph"]
        self.assertEqual(entry["sha256"], self.digest(entry["path"]))

    def test_the_escape_and_control_digests_match_the_files_on_disk(self):
        for key in ("escape_inventory", "control_inventory"):
            entry = self.record[key]
            self.assertEqual(entry["sha256"], self.digest(entry["path"]), key)

    def test_the_driver_commit_is_recorded(self):
        # --commit reached the banner text and never the provenance record, so
        # the file carried a driver_version and no commit. Two checkouts can
        # share one NVIDIA_VERSION and differ.
        self.assertIn("driver_commit", self.record)
        self.assertTrue(self.record["driver_commit"])

    def test_every_input_reaches_the_manifest_through_a_digest(self):
        # The committed record is an artefact of one run. The call sites are
        # what a later regeneration reads, so they are asserted directly.
        source = inspect.getsource(syzlang_gen.cmd_emit)
        for key in ("escape_inventory", "control_inventory", "object_graph"):
            self.assertIn('"%s": json_source_record(' % key, source)
        self.assertIn('"driver_commit": args.commit', source)

    def test_json_source_record_digests_and_counts(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        path = os.path.join(directory, "a.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"records": [1, 2, 3]}, fh)
        record = syzlang_gen.json_source_record(path, "records")
        self.assertEqual(record["records"], 3)
        with open(path, "rb") as fh:
            self.assertEqual(record["sha256"],
                             hashlib.sha256(fh.read()).hexdigest())

    def test_a_missing_count_key_is_recorded_as_none(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        path = os.path.join(directory, "a.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"other": 1}, fh)
        self.assertIsNone(
            syzlang_gen.json_source_record(path, "records")["records"])

    def test_each_digested_input_reports_its_record_count(self):
        self.assertEqual(self.record["object_graph"]["records"], 222)
        self.assertEqual(self.record["control_inventory"]["records"], 1372)


class TestInventoryDefaultsMatchItsSiblings(unittest.TestCase):
    """tools/surface_verify.py printed `python3 tools/ioctl_inventory.py --src
    <checkout>` as its own remedy, and that exited 2: ioctl_inventory was the
    only extractor with no default output path. A bare default would have made
    the printed command destructive instead, because the measured struct sizes
    were not in the repository and a build without them writes an inventory
    carrying no request numbers at all.
    """

    def parse(self, argv):
        return ioctl_inventory.build_parser().parse_args(argv)

    def test_the_default_out_is_the_committed_inventory(self):
        self.assertTrue(os.path.isabs(ioctl_inventory.DEFAULT_OUT))
        self.assertEqual(os.path.basename(ioctl_inventory.DEFAULT_OUT),
                         "ioctl-inventory.json")

    def test_the_default_sizes_file_is_committed(self):
        # Without it the printed remedy writes 0 measured sizes over 183.
        self.assertTrue(os.path.isfile(ioctl_inventory.DEFAULT_SIZES),
                        ioctl_inventory.DEFAULT_SIZES)
        with open(ioctl_inventory.DEFAULT_SIZES, encoding="utf-8") as fh:
            sizes = json.load(fh)
        measured = {k: v for k, v in sizes.items()
                    if not k.startswith("comment")}
        self.assertGreaterEqual(len(measured), 183)
        for name, value in measured.items():
            self.assertIsInstance(value, int, name)
            self.assertGreater(value, 0, name)

    def test_the_printed_remedy_needs_no_further_flags(self):
        args = self.parse(["--src", "x"])
        self.assertEqual(args.out, ioctl_inventory.DEFAULT_OUT)
        self.assertEqual(args.sizes, ioctl_inventory.DEFAULT_SIZES)

    def test_a_size_regression_is_refused(self):
        # The guard that keeps the default --out from being destructive.
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        out = os.path.join(directory, "inv.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump({"counts": {"sizes_measured": 183}}, fh)
        with self.assertRaises(ioctl_inventory.InventoryError) as caught:
            ioctl_inventory.refuse_size_regression(
                out, {"counts": {"sizes_measured": 0}})
        self.assertIn("183", str(caught.exception))

    def test_an_equal_or_better_build_is_allowed(self):
        # Negative control: asserts by the absence of InventoryError.
        # The refusal test above it is the half that discriminates.
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        out = os.path.join(directory, "inv.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump({"counts": {"sizes_measured": 183}}, fh)
        ioctl_inventory.refuse_size_regression(
            out, {"counts": {"sizes_measured": 183}})
        ioctl_inventory.refuse_size_regression(
            out, {"counts": {"sizes_measured": 200}})

    def test_a_first_write_is_allowed(self):
        # Negative control, as above: no prior file means no prior
        # count to regress against.
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        ioctl_inventory.refuse_size_regression(
            os.path.join(directory, "absent.json"),
            {"counts": {"sizes_measured": 0}})

    def test_every_command_the_guard_prints_carries_a_default(self):
        # A prompts agent writes these into AGENTS.md and agents/ verbatim.
        self.assertTrue(os.path.isabs(ctrl_rank.DEFAULT_OUT))
        self.assertTrue(os.path.isabs(object_graph.DEFAULT_GRAPH_OUT))
        self.assertTrue(os.path.isabs(object_graph.DEFAULT_CHAINS_OUT))
        self.assertTrue(os.path.isabs(ioctl_inventory.DEFAULT_OUT))


class TestToolsAreNotAnchoredOnTheWorkingDirectory(unittest.TestCase):
    """ctrl_rank.py and object_graph.py built their default paths with bare
    os.path.join, relative to the process working directory, while
    syzlang_gen.DEFAULT_CTRL_RANK is the absolute form of the same path. The
    producer and the consumer disagreed about where the file lives whenever
    the working directory was not the repository root.
    """

    def test_ctrl_rank_defaults_are_absolute(self):
        for name in ("DEFAULT_SRC", "DEFAULT_CONTROL", "DEFAULT_CHAINS",
                     "DEFAULT_HOTSPOTS", "DEFAULT_SIZES", "DEFAULT_OUT"):
            value = getattr(ctrl_rank, name)
            self.assertTrue(os.path.isabs(value), "%s = %s" % (name, value))

    def test_object_graph_defaults_are_absolute(self):
        for name in ("DEFAULT_SRC", "DEFAULT_GRAPH_OUT", "DEFAULT_CONTROL",
                     "DEFAULT_CHAINS_OUT"):
            value = getattr(object_graph, name)
            self.assertTrue(os.path.isabs(value), "%s = %s" % (name, value))

    def test_the_producer_and_the_consumer_name_one_file(self):
        self.assertEqual(os.path.normcase(os.path.abspath(
            ctrl_rank.DEFAULT_OUT)),
            os.path.normcase(os.path.abspath(syzlang_gen.DEFAULT_CTRL_RANK)))

    def test_object_graph_output_is_where_ctrl_rank_looks_for_it(self):
        self.assertEqual(os.path.normcase(os.path.abspath(
            object_graph.DEFAULT_CHAINS_OUT)),
            os.path.normcase(os.path.abspath(ctrl_rank.DEFAULT_CHAINS)))


class TestModelledStageNeedsNoCorpus(unittest.TestCase):
    """cmd_modelled and cmd_gaps --stage model both routed through
    _measure_args, which called measure and therefore corpus_source and
    `syz-db unpack`. Both reported a number that does not depend on the
    corpus, both paid a full corpus.db unpack for it, and both failed outright
    where syz-db is absent.
    """

    def setUp(self):
        self.calls = []
        original = surface_cov.corpus_source

        def spy(corpus=None, run_id=None):
            self.calls.append((corpus, run_id))
            return original(corpus, run_id)

        surface_cov.corpus_source = spy
        self.addCleanup(setattr, surface_cov, "corpus_source", original)

    def test_measure_without_a_corpus_resolves_none(self):
        desc = os.path.join(os.path.dirname(HERE), "descriptions" )
        if not os.path.isdir(desc):
            self.skipTest("committed description set not present")
        targets, _excluded, meta, modelled, exercised = surface_cov.measure(
            desc, with_corpus=False)
        self.assertEqual(self.calls, [])
        self.assertTrue(targets)
        self.assertTrue(modelled)
        self.assertEqual(exercised, set())
        self.assertIsNone(meta["corpus"])
        self.assertEqual(meta["corpus_programs"], 0)

    def test_the_modelled_count_is_the_same_either_way(self):
        desc = os.path.join(os.path.dirname(HERE), "descriptions" )
        if not os.path.isdir(desc):
            self.skipTest("committed description set not present")
        _t, _e, _m, without, _x = surface_cov.measure(desc, with_corpus=False)
        _t2, _e2, _m2, with_, _x2 = surface_cov.stages(desc, desc)
        self.assertEqual(without, with_)


class TestXferOnlyEscapesAreCredited(unittest.TestCase):
    """ioctl_inventory set rec["xfer_only"] on every escape record and
    documented it, and no module in tools/ read the field.

    IOC_SIZE_MAX is 16383 and NV_ABSOLUTE_MAX_IOCTL_SIZE is 16384, so an
    escape of exactly 16384 bytes has no direct request number and is
    reachable only through the wrapper. Its own name would then be targetable
    and not modelled, and coverage would fall below 764 of 764. The largest
    escape argument in this release is 15412 bytes, so the path is untaken.
    """

    def targets_for(self, param_size):
        inventory = {"nodes": [{
            "module": "nvidia", "paths": ["/dev/nvidiactl"],
            "commands": [{
                "name": "NV_ESC_RM_BIG", "nr": 99,
                "param_struct": "big_t", "param_size": param_size,
                "xfer_only": param_size > ioctl_inventory.IOC_SIZE_MAX,
                "dispatch_site": "escape.c:1"}]}]}
        return inventory

    def test_the_two_ceilings_differ_by_exactly_one_byte(self):
        self.assertEqual(ioctl_inventory.IOC_SIZE_MAX, 16383)
        self.assertEqual(syzlang_gen.XFER_MAX_ARG_SIZE, 16384)
        self.assertEqual(syzlang_gen.XFER_MAX_ARG_SIZE
                         - ioctl_inventory.IOC_SIZE_MAX, 1)

    def test_an_escape_at_the_boundary_is_xfer_only(self):
        inv = self.targets_for(16384)
        self.assertTrue(inv["nodes"][0]["commands"][0]["xfer_only"])
        inv = self.targets_for(16383)
        self.assertFalse(inv["nodes"][0]["commands"][0]["xfer_only"])

    def test_the_wrapper_name_is_derived_from_the_escape_name(self):
        self.assertEqual(
            surface_cov.XFER_VARIANT_PREFIX + "RM_BIG",
            "NV_ESC_IOCTL_XFER_CMD_RM_BIG")

    def test_a_wrapper_credits_its_escape(self):
        targets = {"NV_ESC_RM_BIG": {
            "variant": "NV_ESC_RM_BIG", "family": "escape",
            "xfer_only": True,
            "xfer_variant": "NV_ESC_IOCTL_XFER_CMD_RM_BIG"}}
        modelled = {"NV_ESC_IOCTL_XFER_CMD_RM_BIG"}
        surface_cov.credit_xfer_wrappers(targets, modelled)
        self.assertIn("NV_ESC_RM_BIG", modelled)

    def test_an_absent_wrapper_credits_nothing(self):
        targets = {"NV_ESC_RM_BIG": {
            "variant": "NV_ESC_RM_BIG", "family": "escape",
            "xfer_only": True,
            "xfer_variant": "NV_ESC_IOCTL_XFER_CMD_RM_BIG"}}
        modelled = set()
        surface_cov.credit_xfer_wrappers(targets, modelled)
        self.assertEqual(modelled, set())

    def test_stages_folds_the_credit_in_for_every_caller(self):
        # Calling credit_xfer_wrappers directly proves the helper works. The
        # field was unread because nothing called it, so the call site is what
        # matters: every stage below must read one consistent modelled set.
        source = inspect.getsource(surface_cov.stages)
        self.assertIn("credit_xfer_wrappers(targets, modelled)", source)

    def test_a_directly_reachable_escape_is_not_given_a_wrapper_name(self):
        # Only an xfer_only escape takes this route. Crediting every escape to
        # a wrapper would model a call the description set does not declare.
        targets = {"NV_ESC_RM_FREE": {
            "variant": "NV_ESC_RM_FREE", "family": "escape",
            "xfer_only": False, "xfer_variant": None}}
        modelled = {"NV_ESC_IOCTL_XFER_CMD_RM_FREE"}
        surface_cov.credit_xfer_wrappers(targets, modelled)
        self.assertNotIn("NV_ESC_RM_FREE", modelled)

    def test_no_committed_escape_is_xfer_only_today(self):
        path = os.path.join(os.path.dirname(HERE), "surface", "ioctl-inventory.json")
        if not os.path.isfile(path):
            self.skipTest("committed inventory not present")
        with open(path, encoding="utf-8") as fh:
            inventory = json.load(fh)
        # The _IOC encoding ceiling applies to the RM escape node. UVM
        # request numbers are the bare command numbers with no _IOC fields at
        # all, so a UVM parameter above 16383 bytes is not xfer_only.
        sizes = [c["param_size"] for node in inventory["nodes"]
                 if node["module"] == "nvidia"
                 for c in node["commands"] if c.get("param_size")]
        self.assertEqual(max(sizes), 15412)
        self.assertLessEqual(max(sizes), ioctl_inventory.IOC_SIZE_MAX)
        self.assertFalse(any(c.get("xfer_only") for node in inventory["nodes"]
                             for c in node["commands"]))


class TestDeadConstantsAreGone(unittest.TestCase):
    """CLASS_DIR, POINTER_FIELDS and FREE_ESCAPE had no reader anywhere in
    tools/. A constant naming a rule nothing applies reads as a rule that is
    in force."""

    def test_the_three_constants_are_removed(self):
        for name in ("CLASS_DIR", "POINTER_FIELDS", "FREE_ESCAPE"):
            self.assertFalse(hasattr(syzlang_gen, name), name)

    def test_the_constants_still_in_use_are_untouched(self):
        for name in ("CONTROL_ESCAPE", "ALLOC_ESCAPE", "XFER_ESCAPE",
                     "ROOT_SENTINEL", "ANY_PARENT_SENTINEL"):
            self.assertTrue(hasattr(syzlang_gen, name), name)


# ---------------------------------------------------------------------------
# Review wave 2, patch mining and the CI checks. From tmp/tests2/mining.py and
# tmp/fix/mining.md: the combined-diff parse, the five regression_check
# comparisons and their order, and the two register_check gaps. 13 classes,
# 91 tests.
# ---------------------------------------------------------------------------


class TestCombinedDiffsProduceNoRecord(unittest.TestCase):
    """gitmine M6: a combined diff produced a phantom file entry.

    The `@@@` hunk header was rejected and the `--- a/path` file header above
    it was not, so a merge diff parsed to a real file with no hunks plus an
    invented file named after a body line removed from both parents.
    """

    FRAGMENT = ("--- a/doc/notes.md\n"
                "+++ b/doc/notes.md\n"
                "@@@ -1,4 -1,4 +1,4 @@@\n"
                "  intro\n"
                "--- signed off by A\n"
                "+++ signed off by B\n"
                "  outro\n")

    WITH_HEADER = ("diff --cc doc/notes.md\n"
                   "index 1111111,2222222..3333333\n"
                   "mode 100644,100644..100644\n" + FRAGMENT)

    ORDINARY = ("diff --git a/src/first.c b/src/first.c\n"
                "index aaa..bbb 100644\n"
                "--- a/src/first.c\n"
                "+++ b/src/first.c\n"
                "@@ -1,3 +1,3 @@\n"
                " int a;\n"
                "-int b;\n"
                "+int c;\n")

    LAST = ("diff --git a/src/last.c b/src/last.c\n"
            "index ccc..ddd 100644\n"
            "--- a/src/last.c\n"
            "+++ b/src/last.c\n"
            "@@ -10,2 +10,3 @@ void go(void)\n"
            " int d;\n"
            "+int e;\n")

    # The two combined markers are redundant by design: git writes both
    # above a real combined entry, so reverting only the `diff --cc` half
    # leaves the `@@@` half dropping the record and no test fails. The
    # failability run reverts both.

    def paths(self, text):
        return [f.new_path or f.old_path
                for f in gitmine.parse_unified_diff(text)]

    def test_a_bare_combined_fragment_produces_no_record(self):
        self.assertEqual(self.paths(self.FRAGMENT), [])

    def test_no_phantom_entry_is_invented_from_a_body_line(self):
        for entry in gitmine.parse_unified_diff(self.FRAGMENT):
            self.assertNotIn("signed off", entry.new_path or "")
            self.assertNotIn("signed off", entry.old_path or "")

    def test_the_diff_cc_header_form_produces_no_record(self):
        self.assertEqual(self.paths(self.WITH_HEADER), [])

    def test_the_diff_combined_header_form_produces_no_record(self):
        text = self.WITH_HEADER.replace("diff --cc ", "diff --combined ")
        self.assertEqual(self.paths(text), [])

    def test_an_ordinary_entry_before_a_combined_one_keeps_its_hunks(self):
        files = gitmine.parse_unified_diff(self.ORDINARY + self.WITH_HEADER)
        self.assertEqual([f.new_path for f in files], ["src/first.c"])
        self.assertEqual(files[0].hunks[0].added, ["int c;"])
        self.assertEqual(files[0].hunks[0].removed, ["int b;"])

    def test_an_ordinary_entry_after_a_combined_one_is_parsed(self):
        files = gitmine.parse_unified_diff(
            self.ORDINARY + self.WITH_HEADER + self.LAST)
        self.assertEqual([f.new_path for f in files],
                         ["src/first.c", "src/last.c"])
        self.assertEqual(files[1].hunks[0].added, ["int e;"])
        self.assertEqual(files[1].hunks[0].context, "void go(void)")

    def test_an_ordinary_diff_is_unmoved_by_the_combined_branch(self):
        files = gitmine.parse_unified_diff(self.ORDINARY)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].status, "modified")
        self.assertEqual(len(files[0].hunks), 1)

    def test_a_body_line_that_reads_as_a_diff_header_stays_a_body_line(self):
        # The combined branch is read after the hunk budget, so a removed line
        # whose own text is `diff --git ...` is content and not structure.
        text = ("diff --git a/src/only.c b/src/only.c\n"
                "--- a/src/only.c\n"
                "+++ b/src/only.c\n"
                "@@ -1,2 +1,2 @@\n"
                "-diff --git a/x b/x\n"
                "+diff --cc y\n")
        files = gitmine.parse_unified_diff(text)
        self.assertEqual([f.new_path for f in files], ["src/only.c"])
        self.assertEqual(files[0].hunks[0].removed, ["diff --git a/x b/x"])
        self.assertEqual(files[0].hunks[0].added, ["diff --cc y"])

    def test_the_docstring_states_the_mechanism(self):
        self.assertIn("diff --cc", gitmine.__doc__)
        self.assertIn("@@@", gitmine.__doc__)


class TestAnUnexpectedExceptionIsExitTwo(unittest.TestCase):
    """regression_check M1: a check raising anything other than CheckInput
    exited 1 through the interpreter and abandoned every later check."""

    def boom(self):
        raise KeyError("a page the renderer did not produce")

    def with_checks(self, **replacements):
        saved = dict(regression_check.CHECKS)
        self.addCleanup(regression_check.CHECKS.update, saved)
        self.addCleanup(regression_check.CHECKS.clear)
        regression_check.CHECKS.update(replacements)

    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = regression_check.main(argv)
        return code, out.getvalue() + err.getvalue()

    def test_one_check_raising_is_exit_2_and_not_exit_1(self):
        self.with_checks(pages=self.boom)
        code, text = self.run_main(["pages"])
        self.assertEqual(code, 2)
        self.assertIn("cannot run", text)
        self.assertIn("KeyError", text)

    def test_the_remaining_checks_still_run_under_all(self):
        ran = []
        replacements = {name: (lambda n=name: (ran.append(n), 0)[1])
                        for name in regression_check.CHECKS}
        replacements["pages"] = self.boom
        self.with_checks(**replacements)
        code, _text = self.run_main(["all"])
        self.assertEqual(code, 2)
        self.assertEqual(sorted(ran),
                         sorted(set(regression_check.CHECKS) - {"pages"}))

    def test_a_worse_verdict_from_a_later_check_still_wins(self):
        ran = []
        replacements = {name: (lambda n=name: (ran.append(n), 0)[1])
                        for name in regression_check.CHECKS}
        replacements["names"] = self.boom
        self.with_checks(**replacements)
        code, _text = self.run_main(["all"])
        self.assertEqual(code, 2)
        self.assertIn("pages", ran)

    def test_the_traceback_reaches_stderr(self):
        self.with_checks(pages=self.boom)
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            regression_check.main(["pages"])
        self.assertIn("Traceback", err.getvalue())


class TestPinsSeesEveryCallInAGroup(unittest.TestCase):
    """regression_check M2: a call whose `arg` resolved to no declared struct
    was dropped from the examination with no record, so any number of calls
    short of a whole family could fall out unnoticed."""

    PINNED = (
        "ioctl$NV_ESC_RM_CONTROL_fooCtrlCmdBar(fd fd_nvidiactl, "
        "cmd const[0xc020462a], arg ptr[inout, nvos54_ctrl_foo])\n"
        "ioctl$NV_ESC_RM_ALLOC_FOO_A(fd fd_nv, cmd const[0xc030462b], "
        "arg ptr[inout, nvos64_alloc_foo])\n"
        "ioctl$NV_ESC_IOCTL_XFER_CMD_RM_FREE(fd fd_nvidiactl, "
        "cmd const[0xc01046d3], arg ptr[inout, nv_xfer_rm_free])\n"
        "\n"
        "nvos54_ctrl_foo {\n\tcmd\tconst[0x00000102, int32]\n} [packed]\n"
        "\n"
        "nvos64_alloc_foo {\n\thClass\tconst[0xc997, int32]\n} [packed]\n"
        "\n"
        "nv_xfer_rm_free {\n\tcmd\tconst[41, int32]\n} [packed]\n")

    def pins(self, text):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "nvidia_ctrl.txt")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)

        def clean():
            os.remove(path)
            os.rmdir(directory)
        self.addCleanup(clean)
        saved = regression_check.DESC_DIR
        regression_check.DESC_DIR = directory
        self.addCleanup(setattr, regression_check, "DESC_DIR", saved)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = regression_check.check_pins()
        return code, buffer.getvalue()

    def test_the_reference_set_passes(self):
        code, out = self.pins(self.PINNED)
        self.assertEqual(code, 0, out)

    def test_a_control_call_whose_arg_names_no_struct_fails(self):
        code, out = self.pins(self.PINNED.replace("nvos54_ctrl_foo])",
                                                  "nvos54_ctrl_gone])"))
        self.assertEqual(code, 1, out)
        self.assertIn("NV_ESC_RM_CONTROL_fooCtrlCmdBar", out)
        self.assertIn("nvos54_ctrl_gone", out)

    def test_an_alloc_call_whose_arg_names_no_struct_fails(self):
        code, out = self.pins(self.PINNED.replace("nvos64_alloc_foo])",
                                                  "nvos64_alloc_gone])"))
        self.assertEqual(code, 1, out)
        self.assertIn("NV_ESC_RM_ALLOC_FOO_A", out)

    def test_a_call_outside_every_group_is_counted_and_not_an_offender(self):
        code, out = self.pins(
            self.PINNED + "ioctl$NV_ESC_ATTACH_GPUS_TO_FD(fd fd_nvidiactl, "
                          "cmd const[0xc0044632], arg ptr[in, int32])\n")
        self.assertEqual(code, 0, out)
        self.assertIn("1 call(s) whose arg resolves to no declared struct",
                      out)
        self.assertIn("0 of them inside a reported group", out)

    def test_the_summary_counts_reconcile(self):
        code, out = self.pins(self.PINNED)
        self.assertEqual(code, 0, out)
        line = next(l for l in out.splitlines() if "examined across" in l)
        numbers = [int(n) for n in re.findall(r"\d+", line)]
        examined, control, alloc, xfer, outside = (
            numbers[0], numbers[2], numbers[3], numbers[4], numbers[5])
        self.assertEqual(examined, control + alloc + xfer + outside)


class TestPinsChecksTheValueAndNotOnlyTheForm(unittest.TestCase):
    """regression_check M5: `rendered.startswith("const[")` passed any
    constant, so a regenerated description set carrying a wrong cmd value
    reported a clean run."""

    HANDLER = "fooCtrlCmdBar"
    SET = ("ioctl$NV_ESC_RM_CONTROL_%s(fd fd_nvidiactl, cmd "
           "const[0xc020462a], arg ptr[inout, nvos54_ctrl_foo])\n"
           "ioctl$NV_ESC_RM_ALLOC_FOO_A(fd fd_nv, cmd const[0xc030462b], "
           "arg ptr[inout, nvos64_alloc_foo])\n"
           "ioctl$NV_ESC_IOCTL_XFER_CMD_RM_FREE(fd fd_nvidiactl, cmd "
           "const[0xc01046d3], arg ptr[inout, nv_xfer_rm_free])\n"
           "\n"
           "nvos54_ctrl_foo {\n\tcmd\tconst[%s, int32]\n} [packed]\n"
           "\n"
           "nvos64_alloc_foo {\n\thClass\tconst[0xc997, int32]\n} [packed]\n"
           "\n"
           "nv_xfer_rm_free {\n\tcmd\tconst[41, int32]\n} [packed]\n")

    def fake_targets(self, method_id="0x00000102"):
        variant = surface_cov.CONTROL_PREFIX + self.HANDLER
        targets = {variant: {"variant": variant, "family": "control",
                             "method_id": method_id}}
        saved = surface_cov.load_targets
        surface_cov.load_targets = lambda: (
            targets, {}, {"driver_version": "610.57.04"})
        self.addCleanup(setattr, surface_cov, "load_targets", saved)

    def pins(self, value):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "nvidia_ctrl.txt")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(self.SET % (self.HANDLER, value))

        def clean():
            os.remove(path)
            os.rmdir(directory)
        self.addCleanup(clean)
        saved = regression_check.DESC_DIR
        regression_check.DESC_DIR = directory
        self.addCleanup(setattr, regression_check, "DESC_DIR", saved)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = regression_check.check_pins()
        return code, buffer.getvalue()

    def test_the_right_constant_passes(self):
        self.fake_targets("0x00000102")
        code, out = self.pins("0x00000102")
        self.assertEqual(code, 0, out)

    def test_the_same_value_written_in_decimal_passes(self):
        self.fake_targets("0x00000102")
        code, out = self.pins("258")
        self.assertEqual(code, 0, out)

    def test_another_leafs_method_id_fails_and_names_both_values(self):
        self.fake_targets("0x00000102")
        code, out = self.pins("0x00900101")
        self.assertEqual(code, 1, out)
        self.assertIn("NV_ESC_RM_CONTROL_" + self.HANDLER, out)
        self.assertIn("0x00900101", out)
        self.assertIn("0x00000102", out)

    def test_a_const_whose_value_does_not_parse_fails(self):
        self.fake_targets("0x00000102")
        code, out = self.pins("NV0000_CTRL_CMD_SYSTEM_GET_CPU_INFO")
        self.assertEqual(code, 1, out)

    def test_a_variant_the_inventory_does_not_carry_is_counted(self):
        self.fake_targets("0x00000102")
        saved = surface_cov.load_targets
        surface_cov.load_targets = lambda: (
            {}, {}, {"driver_version": "610.57.04"})
        self.addCleanup(setattr, surface_cov, "load_targets", saved)
        code, out = self.pins("0xdeadbe")
        self.assertEqual(code, 0, out)
        self.assertIn("1 call(s) the inventory does not carry", out)

    def test_the_committed_set_agrees_with_the_committed_inventory(self):
        # The committed artefacts, so a regeneration that moved either one is
        # reported here and not only by the CI step.
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = regression_check.check_pins()
        self.assertEqual(code, 0, buffer.getvalue())
        self.assertIn("0 call(s) the inventory does not carry",
                      buffer.getvalue())


class TestCoverageNoticesAShrinkingDenominator(unittest.TestCase):
    """regression_check M3 and I4: the check compared the description set
    against whatever load_targets returned, so a bump that dropped targets
    left both sides smaller and the run read clean. The function docstring
    named 764 and no constant or assertion carried it."""

    def coverage(self, targets):
        saved = surface_cov.load_targets
        surface_cov.load_targets = lambda: (
            targets, {}, {"driver_version": "610.57.04"})
        self.addCleanup(setattr, surface_cov, "load_targets", saved)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = regression_check.check_coverage()
        return code, buffer.getvalue()

    def committed_targets(self):
        saved = surface_cov.load_targets
        surface_cov.load_targets = saved
        targets, _excluded, _meta = surface_cov.load_targets()
        return targets

    def test_the_committed_denominator_meets_the_floor(self):
        code, out = self.coverage(self.committed_targets())
        self.assertEqual(code, 0, out)

    def test_a_family_below_its_floor_fails(self):
        targets = dict(self.committed_targets())
        control = [n for n, r in targets.items() if r["family"] == "control"]
        for name in control[:50]:
            del targets[name]
        code, out = self.coverage(targets)
        self.assertEqual(code, 1)
        self.assertIn("floor", out)
        self.assertIn("control", out)

    def test_the_floor_names_every_family_the_module_counts(self):
        self.assertEqual(sorted(regression_check.TARGET_FLOOR),
                         sorted(surface_cov.FAMILIES))

    def test_the_floor_sums_to_the_number_the_docstring_used_to_name(self):
        self.assertEqual(sum(regression_check.TARGET_FLOOR.values()), 764)

    def test_the_function_docstring_no_longer_names_a_bare_count(self):
        self.assertNotIn("764", regression_check.check_coverage.__doc__)
        self.assertIn("TARGET_FLOOR", regression_check.check_coverage.__doc__)


class TestDerivedReadsTheRankingsOwnStructure(unittest.TestCase):
    """regression_check M4: `rank_implies` collected handler names and
    discarded everything else, so the check held against a ranking reversed,
    renumbered, or with every score zeroed."""

    PATH = "rm-control-rank.json"

    def doc(self, count=4):
        return {
            "schema": "gspwn.rm-control-rank/1",
            "weighting": {"cve": 0.3, "depth": 0.5, "size": 0.2},
            "commands": [{
                "handler": "h%d" % index,
                "rank": index + 1,
                "no_chain_reason": None,
                "rank_components": {"cve": 0.0, "depth": 1.0 - index * 0.1,
                                    "size": 0.0},
                "rank_score": round(0.5 * (1.0 - index * 0.1), 6),
            } for index in range(count)],
        }

    def problems(self, doc):
        return regression_check.rank_consistency(doc, self.PATH)

    def test_a_consistent_ranking_reports_nothing(self):
        self.assertEqual(self.problems(self.doc()), [])

    def test_a_reversed_ranking_is_reported(self):
        doc = self.doc()
        doc["commands"].reverse()
        for index, command in enumerate(doc["commands"]):
            command["rank"] = index + 1
        self.assertTrue(self.problems(doc))

    def test_a_renumbered_rank_is_reported(self):
        doc = self.doc()
        doc["commands"][2]["rank"] = 99
        problems = self.problems(doc)
        self.assertTrue(any("rank 99" in p for p in problems))

    def test_a_zeroed_score_is_reported_against_its_components(self):
        doc = self.doc()
        for command in doc["commands"]:
            command["rank_score"] = 0.0
        self.assertTrue(self.problems(doc))

    def test_a_component_the_weighting_does_not_price_is_reported(self):
        doc = self.doc()
        doc["commands"][0]["rank_components"]["novelty"] = 1.0
        self.assertTrue(any("novelty" in p for p in self.problems(doc)))

    def test_the_unchained_run_starts_its_own_score_sequence(self):
        doc = self.doc()
        doc["commands"][2]["no_chain_reason"] = "no RS_ENTRY row"
        doc["commands"][3]["no_chain_reason"] = "no RS_ENTRY row"
        doc["commands"][2]["rank_components"]["depth"] = 1.0
        doc["commands"][2]["rank_score"] = 0.5
        doc["commands"][3]["rank_components"]["depth"] = 0.9
        doc["commands"][3]["rank_score"] = 0.45
        self.assertEqual(self.problems(doc), [])

    def test_a_chained_command_after_an_unchained_one_is_reported(self):
        doc = self.doc()
        doc["commands"][1]["no_chain_reason"] = "no RS_ENTRY row"
        self.assertTrue(any("follows a command that carries none" in p
                            for p in self.problems(doc)))

    def test_an_artefact_carrying_no_score_is_read_on_its_names_alone(self):
        doc = {"schema": "gspwn.rm-control-rank/1",
               "commands": [{"handler": "h0", "rank": 1},
                            {"handler": "h1", "rank": 2}]}
        self.assertEqual(self.problems(doc), [])

    def test_a_field_on_part_of_the_array_is_reported(self):
        doc = self.doc()
        del doc["commands"][2]["rank_score"]
        self.assertTrue(any("2 of 4" in p or "3 of 4" in p
                            for p in self.problems(doc)))

    def test_a_scored_artefact_with_no_weighting_block_exits_2(self):
        doc = self.doc()
        del doc["weighting"]
        with self.assertRaises(regression_check.CheckInput):
            self.problems(doc)

    def test_the_committed_ranking_is_consistent(self):
        with open(regression_check.CTRL_RANK, encoding="utf-8") as handle:
            doc = json.load(handle)
        self.assertEqual(self.problems(doc), [])


class TestDerivedReadsTheChainsOwnStructure(unittest.TestCase):
    """regression_check M4: a chain that lost its last step passed, because
    the allocation class that step named is reached through another chain."""

    PATH = "rm-chains.json"

    def doc(self):
        return {
            "schema": "gspwn.rm-chains/1",
            "chains": [{
                "internal_class": "Subdevice",
                "target_external_class": "NV20_SUBDEVICE_0",
                "chain_length": 3,
                "chain": [{"external_class": "NV01_ROOT"},
                          {"external_class": "NV01_DEVICE_0"},
                          {"external_class": "NV20_SUBDEVICE_0"}],
                "command_count": 2,
                "commands": [{"handler": "h0"}, {"handler": "h1"}],
            }],
            "unresolved_owning_classes": [
                {"owning_class": "Memory", "command_count": 1,
                 "commands": ["h2"]}],
        }

    def problems(self, doc):
        return regression_check.chains_consistency(doc, self.PATH)

    def test_a_consistent_artefact_reports_nothing(self):
        self.assertEqual(self.problems(self.doc()), [])

    def test_a_chain_that_lost_its_last_step_is_reported(self):
        doc = self.doc()
        record = doc["chains"][0]
        record["chain"] = record["chain"][:-1]
        record["chain_length"] = 2
        self.assertTrue(any("no longer reaches the class" in p
                            for p in self.problems(doc)))

    def test_a_chain_length_that_does_not_match_the_steps_is_reported(self):
        doc = self.doc()
        doc["chains"][0]["chain_length"] = 9
        self.assertTrue(any("chain_length 9" in p
                            for p in self.problems(doc)))

    def test_an_unallocatable_chain_carries_a_null_length(self):
        doc = self.doc()
        doc["chains"][0]["chain"] = []
        doc["chains"][0]["chain_length"] = None
        doc["chains"][0]["target_external_class"] = "NV_SOMETHING"
        self.assertEqual(self.problems(doc), [])

    def test_an_empty_chain_with_a_length_is_reported(self):
        doc = self.doc()
        doc["chains"][0]["chain"] = []
        self.assertTrue(any("empty chain" in p for p in self.problems(doc)))

    def test_a_miscounted_command_list_is_reported(self):
        doc = self.doc()
        doc["chains"][0]["command_count"] = 7
        self.assertTrue(any("command_count 7" in p
                            for p in self.problems(doc)))

    def test_a_miscounted_unresolved_block_is_reported(self):
        doc = self.doc()
        doc["unresolved_owning_classes"][0]["command_count"] = 5
        self.assertTrue(any("unresolved_owning_classes[0]" in p
                            for p in self.problems(doc)))

    def test_an_artefact_carrying_no_restatement_is_read_on_names_alone(self):
        doc = {"schema": "gspwn.rm-chains/1",
               "chains": [{"chain": [{"external_class": "NV01_ROOT"}],
                           "commands": [{"handler": "h0"}]}],
               "unresolved_owning_classes": []}
        self.assertEqual(self.problems(doc), [])

    def test_the_committed_chains_are_consistent(self):
        with open(regression_check.CHAINS, encoding="utf-8") as handle:
            doc = json.load(handle)
        self.assertEqual(self.problems(doc), [])


class TestDerivedRefusesAMalformedRecordByPosition(unittest.TestCase):
    """regression_check L4 and the fourth M1 path: a chain step or a command
    missing its field was reported as `chains[N]`, the index of the enclosing
    record, and a command normalised to an object reached a string
    concatenation and raised TypeError."""

    def doc(self):
        return {
            "schema": "gspwn.rm-chains/1",
            "chains": [
                {"chain": [{"external_class": "NV01_ROOT"}],
                 "commands": [{"handler": "h0"}]},
                {"chain": [{"external_class": "NV01_ROOT"},
                           {"external_class": "NV01_DEVICE_0"},
                           {"nothing": "here"}],
                 "commands": [{"handler": "h1"}, {"handler": "h2"}]},
            ],
            "unresolved_owning_classes": [
                {"owning_class": "Memory", "commands": ["h3"]}],
        }

    def test_a_step_reports_its_own_index_and_not_the_chains(self):
        with self.assertRaises(regression_check.CheckInput) as caught:
            regression_check.chains_implies(self.doc(), "rm-chains.json")
        self.assertIn("chains[1].chain[2]", str(caught.exception))

    def test_a_command_reports_its_own_index(self):
        doc = self.doc()
        doc["chains"][1]["chain"][2] = {"external_class": "NV20_SUBDEVICE_0"}
        del doc["chains"][1]["commands"][1]["handler"]
        with self.assertRaises(regression_check.CheckInput) as caught:
            regression_check.chains_implies(doc, "rm-chains.json")
        self.assertIn("chains[1].commands[1]", str(caught.exception))

    def test_an_unresolved_command_holding_an_object_exits_2(self):
        doc = self.doc()
        doc["chains"][1]["chain"][2] = {"external_class": "NV20_SUBDEVICE_0"}
        doc["unresolved_owning_classes"][0]["commands"] = [{"handler": "h3"}]
        with self.assertRaises(regression_check.CheckInput) as caught:
            regression_check.chains_implies(doc, "rm-chains.json")
        self.assertIn("unresolved_owning_classes[0].commands[0]",
                      str(caught.exception))

    def test_a_handler_that_is_not_a_string_exits_2(self):
        doc = {"schema": "gspwn.rm-control-rank/1",
               "commands": [{"handler": ["h0"], "rank": 1}]}
        with self.assertRaises(regression_check.CheckInput) as caught:
            regression_check.rank_implies(doc, "rm-control-rank.json")
        self.assertIn("commands[0]", str(caught.exception))
        self.assertIn("list", str(caught.exception))


class TestTheCheckOrderMatchesTheDocumentedOne(unittest.TestCase):
    """regression_check L1 and L2: `all` ran the checks alphabetically while
    the docstring and the CI steps presented another order, and `-v` was
    refused after the subcommand."""

    def test_all_runs_the_checks_in_the_documented_order(self):
        self.assertEqual(regression_check.check_order(),
                         ["names", "pins", "coverage", "derived", "pages"])

    def test_every_registered_check_is_in_the_order(self):
        self.assertEqual(sorted(regression_check.check_order()),
                         sorted(regression_check.CHECKS))

    def test_a_check_absent_from_the_order_still_runs_last(self):
        saved = dict(regression_check.CHECKS)
        self.addCleanup(regression_check.CHECKS.update, saved)
        self.addCleanup(regression_check.CHECKS.clear)
        regression_check.CHECKS["zzz"] = lambda: 0
        self.assertEqual(regression_check.check_order()[-1], "zzz")

    def test_the_docstring_lists_the_checks_in_the_same_order(self):
        text = regression_check.__doc__
        positions = [text.index("\n    %s " % name)
                     for name in regression_check.CHECK_ORDER]
        self.assertEqual(positions, sorted(positions))

    def test_the_workflow_steps_run_them_in_the_same_order(self):
        path = os.path.join(regression_check.REPO_ROOT, ".github", "workflows",
                            "selftest.yml")
        with open(path, encoding="utf-8") as handle:
            workflow = handle.read()
        positions = [workflow.index("python3 tools/regression_check.py %s"
                                    % name)
                     for name in regression_check.CHECK_ORDER]
        self.assertEqual(positions, sorted(positions))

    def test_verbose_is_accepted_before_the_subcommand(self):
        args = regression_check.build_parser().parse_args(["-v", "names"])
        self.assertTrue(args.verbose)

    def test_verbose_is_accepted_after_the_subcommand(self):
        args = regression_check.build_parser().parse_args(["names", "-v"])
        self.assertTrue(args.verbose)

    def test_verbose_defaults_to_false(self):
        args = regression_check.build_parser().parse_args(["names"])
        self.assertFalse(args.verbose)

    def test_the_long_form_works_on_both_sides(self):
        parser = regression_check.build_parser()
        self.assertTrue(parser.parse_args(["--verbose", "pins"]).verbose)
        self.assertTrue(parser.parse_args(["pins", "--verbose"]).verbose)


class TestTheCiToolsRunOnTheWorkstation(unittest.TestCase):
    """regression_check M8: GitminePosixFreeTest asserted the property for
    gitmine.py and nothing asserted it for regression_check.py or refgen.py,
    which regression_check imports at module scope and which makes the same
    claim in its own docstring."""

    BANNED = ("import fcntl", "import pipeline_state", "import termios",
              "import pwd", "import grp", "import resource")

    def assert_posix_free(self, module):
        with open(module.__file__, encoding="utf-8") as handle:
            source = handle.read()
        for banned in self.BANNED:
            self.assertNotIn(banned, source,
                             "%s imports %s" % (module.__name__, banned))
        self.assertNotIn("fcntl", vars(module))
        self.assertNotIn("pipeline_state", vars(module))

    def test_regression_check_imports_nothing_posix_only(self):
        self.assert_posix_free(regression_check)

    def test_refgen_imports_nothing_posix_only(self):
        self.assert_posix_free(refgen)

    def test_register_check_imports_nothing_posix_only(self):
        self.assert_posix_free(register_check)

    def test_regression_check_states_the_property(self):
        self.assertIn("pipeline_state", regression_check.__doc__)

    def test_the_transitive_imports_carry_no_posix_module(self):
        # regression_check imports refgen and surface_cov at module scope, so
        # a later fcntl import into either takes the whole tool off the
        # workstation with no test failing.
        for module in (regression_check, refgen, surface_cov, register_check,
                       gitmine):
            self.assertNotIn("fcntl", vars(module), module.__name__)


class TestTheRegisterCheckSeesAcrossALineWrap(unittest.TestCase):
    """register_check: the patterns carried a literal space and the
    documentation tree wraps at 80 columns, so four cleft constructions
    survived the whole tree unreported."""

    def hits(self, text, rule="cleft construction"):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "case.md")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text + "\n")

        def clean():
            os.remove(path)
            os.rmdir(directory)
        self.addCleanup(clean)
        return [h for h in register_check.check_file(path, "scratch/case.md")
                if h[0] == rule]

    def test_a_cleft_on_one_line_is_caught(self):
        self.assertTrue(self.hits("The tool that writes it is what it fails "
                                  "on."))

    def test_the_same_cleft_across_a_line_wrap_is_caught(self):
        self.assertTrue(self.hits("The tool that writes it is\nwhat it fails "
                                  "on."))

    def test_the_hit_reports_the_line_the_construction_starts_on(self):
        hits = self.hits("filler\nfiller\nThe tool that writes it is\nwhat it "
                         "fails on.")
        self.assertEqual([h[1] for h in hits], [3])

    def test_a_paragraph_break_is_not_a_line_wrap(self):
        self.assertEqual(self.hits("The tool that writes it is\n\nwhat "
                                   "follows is another paragraph."), [])

    def test_a_wrapped_marketing_adjective_is_caught(self):
        self.assertTrue(self.hits("The interface is\ncomprehensive across "
                                  "every family.", "marketing adjective"))

    def test_wrap_tolerant_leaves_a_pattern_with_no_space_alone(self):
        self.assertEqual(register_check.wrap_tolerant(r"\brather\b"),
                         r"\brather\b")

    def test_wrap_tolerant_rewrites_every_literal_space(self):
        rewritten = register_check.wrap_tolerant(r"\bas opposed to\b")
        self.assertEqual(rewritten.count(register_check.WRAP), 2)
        self.assertEqual(rewritten.replace(register_check.WRAP, "|"),
                         r"\bas|opposed|to\b")

    def test_no_pattern_writes_a_space_inside_a_character_class(self):
        # The substitution is textual, so a space inside [...] would be
        # corrupted by it.
        for rule, pattern in register_check.PATTERNS:
            for klass in re.findall(r"\[[^\]]*\]", pattern):
                self.assertNotIn(" ", klass, rule)

    def test_every_pattern_still_compiles_after_the_rewrite(self):
        # Asserts by the absence of re.error, and still discriminates:
        # a wrap_tolerant returning None makes re.compile raise.
        for _rule, pattern in register_check.PATTERNS:
            re.compile(register_check.wrap_tolerant(pattern))


class TestTheRegisterCheckTellsACleftFromADeterminer(unittest.TestCase):
    """register_check: an inline code span was blanked to spaces, which is
    right for a reproduction and wrong for the cleft pattern, because a cleft
    is routinely completed by an identifier."""

    DETERMINERS = [
        ("architecture/crash-identity.md", 183),
        ("architecture/durability.md", 163),
        ("architecture/loops.md", 460),
        ("reference/cli/campaign-ctl.md", 188),
        ("reference/cli/orchestrator-ctl.md", 118),
    ]

    def hits(self, text):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "case.md")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text + "\n")

        def clean():
            os.remove(path)
            os.rmdir(directory)
        self.addCleanup(clean)
        return [h for h in register_check.check_file(path, "scratch/case.md")
                if h[0] == "cleft construction"]

    def test_a_cleft_completed_by_a_code_span_is_caught(self):
        self.assertTrue(self.hits(
            "The grouping rule is the one `cumulative_reach` is computed "
            "with."))

    def test_the_same_cleft_across_a_line_wrap_is_caught(self):
        self.assertTrue(self.hits(
            "The grouping rule is the one\n`cumulative_reach` is computed "
            "with."))

    def test_a_determiner_on_one_line_passes(self):
        self.assertEqual(
            self.hits("`reset` is the one command allowed to start over."), [])

    def test_a_determiner_across_a_line_wrap_passes(self):
        self.assertEqual(
            self.hits("`reset` is the one\ncommand allowed to start over."),
            [])

    def test_a_determiner_wrapped_into_a_list_indent_passes(self):
        self.assertEqual(
            self.hits("- `reset` is the one\n  command allowed to start "
                      "over."), [])

    def test_the_determiner_pages_report_no_cleft(self):
        # Located by the phrase and not by the line number the review
        # recorded, because these pages belong to another partition and a
        # line number goes stale on the next edit. The count guard keeps the
        # test from passing over a corpus that has moved away entirely.
        root = os.path.join(register_check.REPO_ROOT, "docs", "src",
                            "content", "docs")
        checked = 0
        for rel, _line in self.DETERMINERS:
            path = os.path.join(root, *rel.split("/"))
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as handle:
                lines = handle.read().split("\n")
            carrying = [i + 1 for i, text in enumerate(lines)
                        if "is the one" in text]
            if not carrying:
                continue
            hits = [h for h in register_check.check_file(path, rel)
                    if h[0] == "cleft construction" and h[1] in carrying]
            self.assertEqual(hits, [], rel)
            checked += 1
        self.assertGreaterEqual(checked, 3)

    def test_a_code_span_is_still_exempt_from_every_other_rule(self):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "case.md")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("The flag is `--rather-comprehensive` here.\n")

        def clean():
            os.remove(path)
            os.rmdir(directory)
        self.addCleanup(clean)
        self.assertEqual(register_check.check_file(path, "scratch/case.md"),
                         [])

    def test_the_placeholder_is_kept_out_of_the_reported_detail(self):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "case.md")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("The rule is the one `reach` is computed with.\n")

        def clean():
            os.remove(path)
            os.rmdir(directory)
        self.addCleanup(clean)
        for _rule, _line, detail in register_check.check_file(
                path, "scratch/case.md"):
            self.assertNotIn(register_check.CODE_SPAN, detail)

    def test_blanking_preserves_the_line_count(self):
        source = "one `two`\n```\nthree\n```\nfour `five`\n"
        self.assertEqual(
            register_check.strip_exempt_regions(source).count("\n"),
            source.count("\n"))


class TestThePromptCheckSeesAFlagOnlyInvocation(unittest.TestCase):
    """selftest.yml M7: the pattern required a lowercase word directly after
    the file name, so every invocation whose first argument is a flag was
    skipped entirely, along with its flags."""

    PATTERN = (r"tools/(\w+)\.py(?:\s+(?!--)([a-z][a-z0-9-]*))?"
               r"((?:\s+--[a-z-]+(?:\s+\S+)?|\s+\\\n\s*)*)")

    def workflow(self):
        path = os.path.join(regression_check.REPO_ROOT, ".github", "workflows",
                            "selftest.yml")
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def test_the_workflow_carries_the_optional_subcommand_pattern(self):
        self.assertIn(r"tools/(\w+)\.py(?:\s+(?!--)([a-z][a-z0-9-]*))?",
                      self.workflow())

    def test_the_pattern_reads_an_invocation_with_no_subcommand(self):
        match = re.search(
            self.PATTERN,
            "python3 tools/ioctl_inventory.py --src artifacts/src/open-gpu")
        self.assertEqual(match.group(1), "ioctl_inventory")
        self.assertIsNone(match.group(2))
        self.assertIn("--src", match.group(3))

    def test_the_pattern_still_reads_a_subcommand(self):
        match = re.search(self.PATTERN,
                          "python3 tools/cve_patch_map.py map --out x.json")
        self.assertEqual(match.group(2), "map")
        self.assertIn("--out", match.group(3))

    def test_a_flag_is_never_read_as_a_subcommand(self):
        match = re.search(self.PATTERN, "python3 tools/exec.py --log NAME")
        self.assertIsNone(match.group(2))

    def test_the_workflow_reports_a_bare_invocation_of_a_subcommand_tool(self):
        self.assertIn("is invoked with no subcommand and", self.workflow())

    def test_the_flag_loop_drops_the_subcommand_from_the_argv(self):
        # A bare invocation's flags are read against the tool's own --help,
        # where a subcommand's flags never appear.
        self.assertIn("if sub:\n                      argv.append(sub)",
                      self.workflow())


def pipeline_ctl_cmd_round_end(args):
    """Import lazily: pipeline_ctl reads config at parser-build time only."""
    import pipeline_ctl
    return pipeline_ctl.cmd_round_end(args)


if __name__ == "__main__":
    unittest.main(verbosity=2 if "-v" in sys.argv else 1,
                  argv=[a for a in sys.argv if a != "-v"])
