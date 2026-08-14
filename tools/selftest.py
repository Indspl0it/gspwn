#!/usr/bin/env python3
"""Offline self-test for the deterministic tools. Stdlib only, no hardware.

Covers the logic that does not need a GPU, a kernel build, or root: state
handling and its durability/locking contract, crash dedup and flagging, the
strace->syz-program conversion, and the pipeline_ctl CLI end to end.

What it cannot cover, by construction: anything touching the SUT (kernel
builds, systemd units, pstore/kdump harvest, real reproduction). Those are
exercised by the phase gates on the target machine.

Usage: python3 tools/selftest.py [-v]      exit 0 = all passed
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import campaign_ctl
import corpus_ctl
import coverage_ctl
import crash_parse
import gspwn_config
import repro_ctl
import pipeline_state as ps
import trace2seed

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


class StateTempMixin:
    """Point pipeline_state at a throwaway state file for each test."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_path = os.path.join(self.tmp.name, "state", "pipeline.json")
        self._orig = ps.STATE_PATH
        ps.STATE_PATH = self.state_path
        self.addCleanup(lambda: setattr(ps, "STATE_PATH", self._orig))


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
        self.assertIn("FLAG same-stack-different-title", out)
        self.assertEqual(len(st["crashes"]), 2)

    def test_flags_same_title_different_stack(self):
        st = ps.default_state()
        self.reg(st, "K", "same title", "hash-1")
        out = self.reg(st, "K", "same title", "hash-2")
        self.assertIn("FLAG same-title-different-stack", out)

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
        # Nothing of `before` survives, so there is no honest delta. The
        # remaining buffer holds *earlier* runs' crash reports: scanning it
        # would score a hit on every later run.
        delta, wrapped = repro_ctl.dmesg_delta("old" * 400, "totally new")
        self.assertTrue(wrapped)

    def test_matched_signature_agrees_with_hit_counting(self):
        # The bug this guards: counting a hit on a generic pattern while the
        # log line said "clean" because it only checked the title keyword.
        self.assertEqual(repro_ctl.matched_signature("KASAN: bad", "nv_free"),
                         "KASAN:")
        self.assertEqual(repro_ctl.matched_signature("oops nv_free here",
                                                     "nv_free"), "nv_free")
        self.assertIsNone(repro_ctl.matched_signature("all quiet", "nv_free"))


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
        d, why = ps.loop_decision(st, max_rounds=9, max_total_run_hours=216)
        self.assertEqual(d, "stop")
        self.assertIn("budget", why)

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
                f.write("%d,,%d,,,,test\n" % (base + off * 60, edges))

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
                f.write("%d,,,,,,unreachable\n" % (1_700_000_000 + i * 3600))
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


class TestPipelineCtlCLI(unittest.TestCase):
    """End-to-end CLI coverage via GSPWN_STATE redirection."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = os.path.join(self.tmp.name, "state", "pipeline.json")
        self.env = dict(os.environ, GSPWN_STATE=self.state)

    def ctl(self, *args, expect=0):
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, "pipeline_ctl.py")] +
            list(args), env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, expect,
                         "args=%s\nstdout=%s\nstderr=%s"
                         % (list(args), r.stdout, r.stderr))
        return r.stdout + r.stderr

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
        # A typo used to print "no crashes match" and exit 0, which reads as
        # "there are no unique crashes".
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
        self.assertEqual(cfg["cost"]["idle_stop_minutes"], 120)

    def test_a_typo_in_a_cap_is_rejected_not_defaulted(self):
        # The failure this prevents: operator sets `max_rouds: 10`, believes
        # the cap took effect, and the loop silently runs on the default.
        with self.assertRaises(gspwn_config.ConfigError) as cm:
            gspwn_config.load(self.write("loop:\n  max_rouds: 10\n"))
        self.assertIn("max_rouds", str(cm.exception))

    def test_nonsense_caps_are_rejected(self):
        for bad in ("loop:\n  max_rounds: 0\n",
                    "loop:\n  max_total_run_hours: -5\n",
                    "loop:\n  plateau_min_growth: 40\n",
                    "loop:\n  corpus_policy: sometimes\n",
                    "cost:\n  idle_stop_minutes: 0\n"):
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
                f.write("%d,,%d,,,,json:/stats\n" % (ts, edges))

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

    def test_an_explicit_flag_still_overrides_the_measurement(self):
        base = 1_700_000_000
        self.write_curve("r1-k1", [(base + i * 3600, 1000 + i * 300)
                                   for i in range(11)])
        with redirect_stdout(io.StringIO()):
            pipeline_ctl_cmd_round_end(
                self.Args(from_run="r1-k1", coverage_verdict="plateaued"))
        self.assertEqual(ps.load()["rounds"][-1]["coverage_verdict"],
                         "plateaued")


class TestTrackUCoverage(unittest.TestCase):
    """Track U has to be in the loop's view, or a round stops while the
    container-toolkit harnesses are still finding coverage."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._orig = coverage_ctl.RUNS_DIR
        coverage_ctl.RUNS_DIR = os.path.join(self.tmp.name, "runs")
        self.addCleanup(lambda: setattr(coverage_ctl, "RUNS_DIR", self._orig))

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
                f.write("%d,,%d,,,,,src\n" % (ts, edges))

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


class TestPlateauAcrossRestarts(unittest.TestCase):
    """The fuzzer restarts by design: units are Restart=always and the box
    panics. Edge counts reset to zero when it does."""

    def rows(self, edges, step=3600):
        base = 1_700_000_000
        return [{"ts": base + i * step, "edges": e}
                for i, e in enumerate(edges)]

    def test_restart_inside_the_window_is_not_a_plateau(self):
        # Climbing hard, then the fuzzer restarts and climbs again. Comparing
        # across the reset gave -75% growth -> "plateaued" -> the loop stopped
        # a campaign that was in fact still finding new edges fast.
        rows = self.rows([6000, 10000, 14000, 18000, 22000, 24000, 25000,
                          26000, 500, 2500, 4500, 6500])
        verdict, detail = coverage_ctl.plateau_verdict(rows, 240, 0.02)
        self.assertNotEqual(verdict, "plateaued", detail)
        self.assertNotIn("-", detail.split("=")[-1])   # no negative growth

    def test_growth_after_a_restart_is_measured_from_the_restart(self):
        rows = self.rows([20000, 24000, 26000,
                          500, 3000, 6000, 9000, 12000, 15000])
        verdict, detail = coverage_ctl.plateau_verdict(rows, 240, 0.02)
        self.assertEqual(verdict, "growing")
        self.assertIn("since a fuzzer restart", detail)

    def test_a_flat_run_after_a_restart_still_plateaus(self):
        rows = self.rows([20000, 24000, 26000,
                          9000, 9010, 9020, 9030, 9040, 9050])
        self.assertEqual(coverage_ctl.plateau_verdict(rows, 240, 0.02)[0],
                         "plateaued")

    def test_too_little_data_since_a_restart_is_unknown(self):
        rows = self.rows([20000, 24000, 26000, 28000, 30000, 500, 900])
        verdict, detail = coverage_ctl.plateau_verdict(rows, 240, 0.02)
        self.assertEqual(verdict, "unknown")
        self.assertIn("restarted", detail)

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
                    'cost:\n  idle_stop_minutes: "120"\n'):
            with self.assertRaises(gspwn_config.ConfigError, msg=bad):
                gspwn_config.load(self.write(bad))


class TestWorklistHandoff(StateTempMixin, unittest.TestCase):
    """The learning handoff is state, not a filename two prompts agree on."""

    def test_worklist_carries_into_the_next_round(self):
        st = ps.default_state()
        ps.end_round(st, verdict="growing",
                     worklist="artifacts/eval/r1-k1/worklist.md")
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
        ps.end_round(st, verdict="growing", worklist="artifacts/eval/gone.md")
        ps.record_decision(st, "continue", "x")
        ps.advance_round(st)
        ps.save(st)
        args = types.SimpleNamespace()
        with redirect_stdout(io.StringIO()) as out:
            rc = pipeline_ctl.cmd_worklist(args)
        self.assertEqual(rc, 1)              # recorded but not on disk
        self.assertIn("MISSING", out.getvalue())


def pipeline_ctl_cmd_round_end(args):
    """Import lazily: pipeline_ctl reads config at parser-build time only."""
    import pipeline_ctl
    return pipeline_ctl.cmd_round_end(args)


if __name__ == "__main__":
    unittest.main(verbosity=2 if "-v" in sys.argv else 1,
                  argv=[a for a in sys.argv if a != "-v"])
