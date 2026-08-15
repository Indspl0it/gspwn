#!/usr/bin/env python3
"""Harvest crashes from both tracks and dedup into state/pipeline.json.

Dedup (spec Phase 4): primary key = normalized report title (syzkaller
'description' file / ASan summary line / kernel report-start line).
Secondary = stack hash (sha1 of the top triage.stack_hash_frames function
frames, addresses and offsets stripped). Both keys are normalized identically
across sources, so the same bug found in the syz workdir and again in a
harvested dmesg/pstore log collides instead of double-registering. A collision
in only one key is flagged for manual review; an empty stack hash is *no
evidence* and never drives a stack-based decision.
"""
import argparse
import glob
import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gspwn_config
import pipeline_state as ps

REPO_ROOT = ps.REPO_ROOT
# Syzkaller/ASan style:    "#0 0x1 in nv_uvm_free" / "#1 0x... in foo /s.c:3"
SYZ_FRAME_RE = re.compile(r"#\d+\s+(?:0x[0-9a-f]+\s+)?(?:in\s+)?([\w.~]+)\s*\+?")
# Kernel call-trace style: "nv_uvm_free+0x12/0x34 [nvidia_uvm]" (also matches
# the RIP line, which carries the innermost frame).
TRACE_FRAME_RE = re.compile(r"(?:^|[\s?!:])([\w.~]+)\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+")
# Sanitizer signatures a Track U artifact must carry to be a crash at all.
SAN_TITLE_RES = [
    re.compile(r"^(?:==\d+==\s*)?(ERROR: (?:Address|Memory|Leak|Thread|"
               r"UndefinedBehavior)?Sanitizer[^\n]*)", re.M),
    re.compile(r"^(?:==\d+==\s*)?(SUMMARY: [^\n]*)", re.M),
    re.compile(r"^([^\n:]*:\d+(?::\d+)?: runtime error:[^\n]*)", re.M),
    re.compile(r"^(?:==\d+==\s*)?(SEGV on unknown address[^\n]*)", re.M),
]
NVRM_RE = re.compile(r"NVRM: (Xid[^\n]*|GPU at[^\n]*error[^\n]*)", re.I)
# Volatile Xid fields: the same recurring Xid must dedup across pids/channels.
XID_VOLATILE_RE = re.compile(r"\s*,?\s*(?:pid=[^,\s]+|ch(?:annel)?\s*[= ]\s*"
                             r"[0-9a-fA-Fx]+)", re.I)
# The GPU the Xid came from. Which card faulted is provenance, not identity:
# on a multi-GPU box the same driver bug on two cards is one bug, and leaving
# the bus id in the title registers it once per card. Kept in the notes.
XID_BUSID_RE = re.compile(r"\s*\((?:PCI:)?[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:"
                          r"[0-9a-fA-F]{2}(?:\.[0-9a-fA-F])?\)")
# "NVRM: Xid (PCI:0000:00:1e): 13, pid=..." -> 13. The bus id in the optional
# parenthesised group carries its own colons, so it has to be consumed as a
# group rather than skipped with [^:]* — that reads the first field of the bus
# id as the Xid number and classifies every crash as an unknown Xid 0.
XID_NUM_RE = re.compile(r"\bXid\b\s*(?:\([^)]*\))?\s*:?\s*(\d+)", re.I)

# What a given Xid means for this campaign. A fuzzer generates bad pointers and
# illegal instructions by design, so the Xids that report exactly that are its
# own exhaust: harvesting them as findings buries the real signal under
# thousands of entries and makes "crashes found" meaningless.
#
# Classes:
#   noise   the fuzzer caused it on purpose; not a finding on its own
#   signal  security-relevant or memory-integrity relevant; triage it
#   health  the GPU or the box is degraded; blocks measurement, not a finding
#   review  everything else, including every Xid not listed here
#
# The default is deliberately 'review', never 'noise'. A new driver branch can
# introduce an Xid this table has never seen, and defaulting it to exhaust
# would silently discard the one class of finding this campaign exists to
# produce. Confirm the numbers against NVIDIA's Xid documentation for the
# driver branch under test; the meanings below are the widely published ones
# and are not derived from this repo's own sources.
XID_CLASS = {
    8:   ("noise",  "GPU stopped processing (video engine), app-caused"),
    13:  ("noise",  "graphics engine exception: illegal instruction/address"),
    31:  ("noise",  "GPU memory page fault: illegal address by the app"),
    43:  ("noise",  "GPU stopped processing, channel error caused by the app"),
    45:  ("noise",  "preemptive channel cleanup, usually a killed process"),
    69:  ("noise",  "graphics engine class error"),
    12:  ("review", "driver error handling exception"),
    32:  ("signal", "invalid or corrupted push buffer stream (DMA)"),
    38:  ("signal", "driver firmware error"),
    48:  ("signal", "double-bit ECC error"),
    61:  ("signal", "internal micro-controller breakpoint or warning"),
    62:  ("signal", "internal micro-controller halt"),
    92:  ("signal", "high single-bit ECC error rate"),
    94:  ("signal", "contained ECC error"),
    95:  ("signal", "uncontained ECC error"),
    119: ("signal", "GSP RPC timeout"),
    120: ("signal", "GSP error"),
    140: ("signal", "unrecovered ECC error"),
    63:  ("health", "ECC page retirement or row remapping"),
    64:  ("health", "ECC page retirement or row remapping failure"),
    74:  ("health", "NVLink error"),
    79:  ("health", "GPU has fallen off the bus"),
}


def xid_class(title):
    """-> (class, why) for an NVRM title, or (None, '') if it carries no Xid.

    'GPU at ... error' lines and anything else NVRM_RE catches without an Xid
    number are left unclassified rather than guessed at.
    """
    m = XID_NUM_RE.search(title or "")
    if not m:
        return None, ""
    n = int(m.group(1))
    if n in XID_CLASS:
        cls, meaning = XID_CLASS[n]
        return cls, "Xid %d: %s" % (n, meaning)
    return "review", ("Xid %d is not in the classification table — treated as "
                      "review, not exhaust, so a new signal is never silently "
                      "discarded" % n)


REPORT_START_RE = re.compile(
    r"(BUG: [^\n]*|KASAN: [^\n]*|Kernel panic[^\n]*|Oops[^\n]*)")
END_TRACE_RE = re.compile(r"---\[ end ")
TS_RE = re.compile(r"^\s*(?:\[\s*\d+\.\d+\]\s*)+")
TITLE_PREFIX_RE = re.compile(r"^(?:kernel|NVRM)\s+", re.I)
HEX_RE = re.compile(r"0x[0-9a-fA-F]+|\b[0-9a-fA-F]{8,}\b")

# Fields a kernel report prologue prints that differ on every occurrence of the
# SAME bug. They have to be blanked before the frameless signature is hashed,
# or one recurring trace-less panic registers as a brand-new bug each time it
# fires. That is the expensive direction: triage and rca both run per
# registered crash, so the flood costs the phases that matter and buries the
# real findings underneath it.
#
# Only the standard oops prologue is covered. A frameless report is all
# prologue by definition, which is why this matters here and not for the frame
# hash, where these lines are never reached.
REPORT_VOLATILE_RE = re.compile(
    r"\bpid=\S+"                # NVRM's lowercase form
    r"|\[#\d+\]"                # oops counter: increments per oops per boot
    r"|\bCPU:\s*\d+"            # whichever core happened to fault
    r"|\bPID:\s*\d+"            # the faulting task
    r"|\bTainted:(?:\s+[A-Z-])+"  # gains D after the first die on this boot
)
# syz-executor.4 -> syz-executor. The suffix is the executor index, which is
# per-occurrence; the name is not, and a panic in modprobe is not the same bug
# as a panic in syz-executor.
COMM_INDEX_RE = re.compile(r"(\bComm:\s*\S+?)\.\d+\b")
# The faulting instruction pointer. In a report with no decodable call trace
# this is the only field naming *where* the fault happened, so it has to be
# part of the identity: without it two different faulting functions behind the
# same fault type produce the same title and the same signature, and the
# second is registered as a duplicate that never reaches rca.
#
# Found by pattern rather than by line number, because how much prologue
# precedes it varies with the fault type — a fixed line count cannot reach it
# reliably, and raising the count far enough to try would drag in lines that
# vary per occurrence. The offset is dropped for the same reason stack_frames
# drops it: it moves with the build, and the same bug in two builds is one
# bug. An unresolved RIP (a bare address, module not loaded) matches nothing
# and leaves the signature as it was.
RIP_RE = re.compile(r"\bRIP:\s*[0-9a-fA-F]{4}:(?:\s*\[<[0-9a-fA-F]+>\])?\s*"
                    r"([A-Za-z_][\w.]*)")


def norm_title(t):
    return re.sub(r"\s+", " ", t.strip())


def canon_title(t):
    """Source-independent title: same bug, same title, wherever it was seen.

    Strips the source prefixes scan_dmesg used to need ('kernel '/'NVRM '),
    folds 'BUG: KASAN: ...' into syzkaller's 'KASAN: ...' form, and blanks
    out hex addresses/pc values so the same ASan or paging-fault report at a
    different address still collides.
    """
    t = TITLE_PREFIX_RE.sub("", norm_title(t))
    t = re.sub(r"^BUG:\s+(?=(?:KASAN|UBSAN):)", "", t)
    return norm_title(HEX_RE.sub("0xADDR", t))


def stack_frames(text):
    """Function names in log order, addresses/offsets/modules stripped.

    Reads both syzkaller's '#N in func' reports and raw kernel call traces
    ('func+0xoff/0xsize'), so a syz 'report' file and the dmesg block of the
    same crash yield the same sequence.
    """
    frames = []
    for line in text.splitlines():
        m = SYZ_FRAME_RE.search(line) or TRACE_FRAME_RE.search(line)
        if m:
            frames.append(m.group(1))
    return frames


def stack_hash(report_text, depth=None):
    """sha1 of the top frames; '' when the text carries no frames at all.

    '' means 'no evidence': register() never lets it drive a FLAG/DUP stack
    decision, so report-less syz crashes and signature-only Track U inputs
    can no longer alias each other through a constant hash.

    How many frames is triage.stack_hash_frames in config/campaign.yaml,
    because it decides what counts as the same bug and therefore what reaches
    rca. `depth` overrides it for callers that need to compare two settings.
    """
    if depth is None:
        depth = gspwn_config.triage()["stack_hash_frames"]
    frames = stack_frames(report_text)[:depth]
    if not frames:
        return ""
    return hashlib.sha1("|".join(frames).encode()).hexdigest()[:16]


def existing_keys(state):
    """-> (title->cid, hash->cid, (title, hash, dir)->cid)

    Duplicates stay out of the title/hash indexes so later sightings link
    against the surviving finding, not against an absorbed duplicate. The
    full (title, hash, dir) key is what makes re-scans idempotent: the same
    sighting read again from the same source is a DUP, not a new entry.
    """
    by_title, by_hash, seen = {}, {}, {}
    for cid, c in state["crashes"].items():
        seen[(c["title"], c["stack_hash"], c["dir"])] = cid
        if c.get("status") == "duplicate":
            continue
        by_title.setdefault(c["title"], cid)
        if c["stack_hash"]:
            by_hash.setdefault(c["stack_hash"], cid)
    return by_title, by_hash, seen


def register(state, track, title, shash, srcdir, signal=None,
             signal_note=""):
    """Add a crash to the registry, or explain why it was not added.

    A collision in one key but not the other may be a second bug or the same
    bug reported twice; distinguishing them requires reading both reports.
    Such a crash is registered as `flagged`, so it persists in the registry
    and `crash-list --status flagged` serves as the review queue. A crash
    reported only in log output would not be addressable once that output is
    gone. When neither side carries a stack there is no evidence to confirm
    identity, so even an exact title match is flagged rather than silently
    DUPed — unless it is the identical sighting re-read from the identical
    source (a re-scan), which stays a plain DUP.
    """
    # Stamp what the registry's hashes mean before adding to them. Self-
    # guarded: written once, at the first registration, so `validate` can say
    # later that the dedup settings moved underneath the stored hashes.
    ps.stamp_triage_settings(state, gspwn_config.triage())
    title = canon_title(title)
    by_title, by_hash, seen = existing_keys(state)
    prior = seen.get((title, shash, srcdir))
    if prior:
        # Identical title AND identical evidence from the identical source:
        # the same sighting scanned again. Re-scans must be idempotent —
        # harvest runs after every reboot.
        print("DUP %s -> %s" % (title, prior))
        return None
    other_cid = None
    reason = None
    if title in by_title:
        other_cid = by_title[title]
        other = state["crashes"][other_cid]
        if shash and shash == other["stack_hash"]:
            # Same title AND same stack from a new source: the same bug
            # sighted again (e.g. syz workdir + harvested dmesg of the same
            # panic). Keep one finding; register this sighting as its
            # duplicate so both sources stay addressable and the link is
            # durable state, not just stdout.
            cid = ps.register_crash(state, {
                "track": track, "title": title, "stack_hash": shash,
                "status": "duplicate", "dir": srcdir, "repro_rate": None,
                "duplicate_of": other_cid, "disclosure": "pending",
                "signal": signal or "unclassified",
                "notes": "same crash as %s, sighted via %s"
                         % (other_cid, srcdir)})
            link = "also sighted via %s (%s)" % (srcdir, cid)
            if link not in other["notes"]:
                other["notes"] = "; ".join(
                    x for x in (other["notes"], link) if x)
            print("DUP %s -> %s (registered %s as duplicate; sources linked)"
                  % (title, other_cid, cid))
            return cid
        if not shash and not other["stack_hash"]:
            reason = ("same title as %s, neither sighting has a stack — "
                      "cannot confirm it is the same bug" % other_cid)
        elif not shash or not other["stack_hash"]:
            reason = ("same title as %s, only one sighting has a stack"
                      % other_cid)
        else:
            reason = "same title as %s, different stack" % other_cid
    elif shash and shash in by_hash:
        other_cid = by_hash[shash]
        reason = "same stack as %s, different title" % other_cid
    status = "flagged" if other_cid else "unique"
    notes = [n for n in (reason if other_cid else None, signal_note) if n]
    cid = ps.register_crash(state, {
        "track": track, "title": title, "stack_hash": shash,
        "status": status, "dir": srcdir, "repro_rate": None,
        "duplicate_of": None, "disclosure": "pending",
        "signal": signal or "unclassified",
        "notes": "; ".join(notes)})
    tag = "" if not signal else " [%s]" % signal
    if other_cid:
        print("FLAG %s %s%s (%s) — decide with: pipeline_ctl.py crash-set %s "
              "--duplicate-of %s | --status unique"
              % (cid, title, tag, reason, cid, other_cid))
    else:
        print("NEW %s %s%s" % (cid, title, tag))
    return cid


def scan_syz(state, workdir):
    for cdir in sorted(glob.glob(os.path.join(workdir, "crashes", "*"))):
        desc = os.path.join(cdir, "description")
        report = os.path.join(cdir, "report")
        if not os.path.exists(desc):
            continue
        title = norm_title(read_text(desc))
        rtext = read_text(report) if os.path.exists(report) else ""
        register(state, "K", title, stack_hash(rtext), cdir)


def sanitizer_title(text):
    """Title from the artifact's sanitizer signature, or None if it has none.

    A file with no signature is not a crash — logs, manifests and READMEs in
    the crash dir must not become phantom 'libfuzzer-crash:' uniques.
    """
    for rx in SAN_TITLE_RES:
        m = rx.search(text)
        if m:
            return m.group(1)
    return None


def scan_track_u(state, udir):
    for f in sorted(glob.glob(os.path.join(udir, "*"))):
        if not os.path.isfile(f):
            continue
        text = read_text(f)
        title = sanitizer_title(text)
        if title is None:
            print("WARN: %s carries no sanitizer signature — skipped, not "
                  "registered" % f)
            continue
        register(state, "U", title, stack_hash(text), f)


def read_text(path):
    with open(path, errors="replace") as f:
        return f.read()


def strip_ts(line):
    return TS_RE.sub("", line)


def report_blocks(text):
    """Yield (start_line, block_text): one kernel report per block.

    A block runs from a report-start line (BUG:/KASAN:/Oops/Kernel panic)
    through the end of its call trace, so one KASAN report is one registry
    entry rather than one per matching line. Oops/panic lines before the
    first frame (the BUG: -> Oops: -> panic prologue of one oops) and a
    Kernel panic trailing a traced report are part of the report they belong
    to; a fresh BUG:/KASAN: line always starts the next report.
    """
    blocks, cur, state = [], [], "closed"
    for raw in text.splitlines():
        s = strip_ts(raw)
        m = REPORT_START_RE.search(s)
        if m:
            # 'bug' introduces a report; 'oops'/'panic' can also be the
            # prologue tail or death rattle of the report already open.
            kind = ("panic" if s.startswith("Kernel panic")
                    else "oops" if s.startswith("Oops") else "bug")
            if not cur or (state == "open" and kind == "bug") \
                    or (state in ("traced", "ended") and kind != "panic"):
                if cur:
                    blocks.append(cur)
                cur, state = [], "closed"
            cur.append(raw)
            state = "open" if state == "closed" else state
            continue
        if END_TRACE_RE.search(s):
            if cur:
                cur.append(raw)
                state = "ended"
            continue
        if cur:
            cur.append(raw)
            if state == "open" and (TRACE_FRAME_RE.search(s)
                                    or SYZ_FRAME_RE.search(s)):
                state = "traced"
    if cur:
        blocks.append(cur)
    for block in blocks:
        yield strip_ts(block[0]), "\n".join(block)


def block_signature(block, lines=None, chars=None):
    """Title+context hash for a report block with no usable frames.

    Generic prologue lines (a lone 'BUG: unable to handle ...', a trace-less
    panic) carry no stack, so the distinguishing evidence is the normalized
    wording around the start line — timestamps, hex and pids blanked out.

    How many lines and how much of them is triage.frameless_signature_lines /
    _chars in config/campaign.yaml, because this is the whole of what decides
    whether two trace-less panics are the same bug. `lines` and `chars`
    override them for callers comparing two settings.
    """
    cfg = gspwn_config.triage()
    lines = cfg["frameless_signature_lines"] if lines is None else lines
    chars = cfg["frameless_signature_chars"] if chars is None else chars
    head = [strip_ts(l) for l in block.splitlines()[:lines]]
    # Volatile fields go before the hex blanking, not after: an 8-digit pid
    # would otherwise be eaten as an address first and never recognised as a
    # pid, so the same panic would split on task id alone.
    ctx = COMM_INDEX_RE.sub(r"\1", REPORT_VOLATILE_RE.sub("", " ".join(head)))
    ctx = norm_title(HEX_RE.sub("0xADDR", ctx))[:chars]
    # After the cut, never inside it. The faulting symbol is the strongest
    # evidence a frameless report carries, so a long prologue must not be able
    # to push it out of the identity.
    rip = RIP_RE.search(block)
    if rip:
        ctx += " RIP:" + rip.group(1)
    return hashlib.sha1(ctx.encode()).hexdigest()[:16]


def scan_dmesg(state, path):
    text = read_text(path)
    for m in NVRM_RE.finditer(text):
        body = norm_title(XID_VOLATILE_RE.sub("", m.group(1))).strip(" ,")
        # Classify before dropping the bus id: XID_NUM_RE reads past it, but
        # the note is more useful with the card it came from named.
        cls, why = xid_class(body)
        bus = XID_BUSID_RE.search(body)
        if bus:
            why = "; ".join(x for x in (why, "on %s" % bus.group(0).strip(" ()"))
                            if x)
        body = norm_title(XID_BUSID_RE.sub("", body)).strip(" ,")
        register(state, "K", "NVRM " + body,
                 hashlib.sha1(body.encode()).hexdigest()[:16], path,
                 signal=cls, signal_note=why)
    for start_line, block in report_blocks(text):
        shash = stack_hash(block) or block_signature(block)
        register(state, "K", start_line, shash, path)


def resolve_workdir(a, state):
    """Per-run workdir: explicit path, else --run-id, else this round's last run."""
    if a.syz_workdir:
        return a.syz_workdir
    rid = a.run_id
    if not rid:
        run_ids = ps.current_round(state)["run_ids"]
        rid = run_ids[-1] if run_ids else None
    if not rid:
        return None
    return os.path.join(REPO_ROOT, "artifacts", "runs", rid, "workdir")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", dest="run_id",
                    help="scan artifacts/runs/<id>/workdir (default: the last "
                         "run registered in the current round)")
    ap.add_argument("--syz-workdir", default=None,
                    help="explicit workdir path, overriding --run-id")
    ap.add_argument("--track-u-dir",
                    default=os.path.join(REPO_ROOT, "artifacts", "harnesses",
                                         "crashes"))
    ap.add_argument("--dmesg", default=None)
    a = ap.parse_args()
    # One locked read-modify-write: triage may run while the fuzz monitor and
    # other phase agents are also touching the registry.
    with ps.transaction() as state:
        wd = resolve_workdir(a, state)
        if wd is None:
            print("WARN: no run id given and none registered in this round — "
                  "skipping the syzkaller workdir. Pass --run-id, or register "
                  "the run with pipeline_ctl.py round-add-run.")
        elif not os.path.isdir(os.path.join(wd, "crashes")):
            print("WARN: no crashes dir under %s — nothing scanned for Track "
                  "K. Check the run id." % wd)
        else:
            scan_syz(state, wd)
        if os.path.isdir(a.track_u_dir):
            scan_track_u(state, a.track_u_dir)
        else:
            print("WARN: %s missing — nothing scanned for Track U."
                  % a.track_u_dir)
        if a.dmesg:
            if os.path.exists(a.dmesg):
                scan_dmesg(state, a.dmesg)
            else:
                print("WARN: --dmesg %s not found — nothing scanned from "
                      "kernel logs." % a.dmesg)
        total = len(state["crashes"])
        flagged = sum(1 for c in state["crashes"].values()
                      if c["status"] == "flagged")
    print("registry now holds %d crashes" % total)
    if flagged:
        print("%d flagged — every one needs a decision before the triage gate "
              "holds: python3 tools/pipeline_ctl.py crash-list --status flagged"
              % flagged)


if __name__ == "__main__":
    main()
