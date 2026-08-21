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
import time
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
import ioctl_inventory
import knowledge_ctl
import orchestrator_ctl
import repro_ctl
import pipeline_state as ps
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

    def test_map_keys_are_what_trace2seed_looks_up(self):
        inventory = {"nodes": [{"commands": [
            {"name": "NV_ESC_RM_CONTROL", "requests": ["0xc020462a"],
             "is_argument_array": False, "syzlang": "ioctl$NV_ESC_RM_CONTROL"},
        ]}]}
        mapping, _ = ioctl_inventory.build_map(inventory)
        loaded = {k.lower(): v for k, v in mapping.items()
                  if not k.startswith("comment")}
        prog = trace2seed.convert(
            'openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3\n'
            'ioctl(3, 0xc020462a, 0x7ffd) = 0\n', loaded)
        self.assertIn("ioctl$NV_ESC_RM_CONTROL(r0, 0xc020462a", prog)


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
        def run(cmd, **kw):
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
        repro_ctl._refuse_live_campaign(False)

    def test_the_override_is_honoured(self):
        self.fake_is_active("active")
        repro_ctl._refuse_live_campaign(True)


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


def pipeline_ctl_cmd_round_end(args):
    """Import lazily: pipeline_ctl reads config at parser-build time only."""
    import pipeline_ctl
    return pipeline_ctl.cmd_round_end(args)


if __name__ == "__main__":
    unittest.main(verbosity=2 if "-v" in sys.argv else 1,
                  argv=[a for a in sys.argv if a != "-v"])
