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
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import crash_parse
import repro_ctl
import pipeline_state as ps
import trace2seed


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
        self.assertEqual(repro_ctl.dmesg_delta("aaa", "aaabbb"), "bbb")

    def test_dmesg_delta_survives_evicted_head(self):
        """Ring buffer dropped its head: anchor on the tail of `before`.

        A plain length-slice returns the wrong window here and would miss the
        reproduction entirely.
        """
        before = "head-noise " * 40 + "T" * 800   # tail exceeds the anchor
        after = before[200:] + "NEW CRASH TEXT"   # first 200 chars evicted
        self.assertEqual(repro_ctl.dmesg_delta(before, after), "NEW CRASH TEXT")
        self.assertNotEqual(after[len(before):], "NEW CRASH TEXT")

    def test_dmesg_delta_full_wrap_is_conservative(self):
        # Nothing of `before` survives: return everything rather than miss it.
        self.assertEqual(repro_ctl.dmesg_delta("old" * 400, "totally new"),
                         "totally new")

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

    def setUp(self):
        super().setUp()
        self._orig_root = repro_ctl.REPO_ROOT
        repro_ctl.REPO_ROOT = self.tmp.name
        self.addCleanup(lambda: setattr(repro_ctl, "REPO_ROOT",
                                        self._orig_root))
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

    def run_verify(self, runs, restart=False):
        with redirect_stdout(io.StringIO()) as out:
            repro_ctl.cmd_verify(self.cid, runs, restart)
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

    def test_interrupted_run_is_recovered_as_a_reproduction(self):
        """A run that panicked the box must not be silently lost."""
        with ps.transaction() as st:
            st["crashes"][self.cid]["repro_progress"] = {
                "runs_done": 1, "hits": 0, "in_flight": True}
        out = self.run_verify(2)
        self.assertIn("machine went down mid-run", out)
        c = ps.load()["crashes"][self.cid]
        self.assertEqual(c["repro_progress"]["hits"], 1)  # recovered run counts
        self.assertEqual(c["status"], "flaky")            # 1/2, not 0/2

    def test_restart_discards_partial_progress(self):
        with ps.transaction() as st:
            st["crashes"][self.cid]["repro_progress"] = {
                "runs_done": 1, "hits": 1, "in_flight": True}
        self.run_verify(2, restart=True)
        c = ps.load()["crashes"][self.cid]
        self.assertEqual(c["repro_progress"]["hits"], 0)
        self.assertEqual(c["status"], "unreproducible")


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


if __name__ == "__main__":
    unittest.main(verbosity=2 if "-v" in sys.argv else 1,
                  argv=[a for a in sys.argv if a != "-v"])
