#!/usr/bin/env python3
"""Enumerate the /dev/dri command space from the driver source.

nvidia-drm is a DRM driver, so its commands do not multiplex through one
request number the way the modeset family does. Each command carries its own
ioctl request number, built by the DRM macros at DRM_COMMAND_BASE, and the
permission a caller needs sits in the flag word of the dispatch table entry.

Two files hold the answer and neither holds all of it. The declared space is
the run of `#define DRM_NVIDIA_<NAME>` command numbers in
`kernel-open/nvidia-drm/nv_drm_common_ioctl.h`, each paired with a
`#define DRM_IOCTL_NVIDIA_<NAME>` macro naming a direction and a parameter
struct. The populated space is `nv_drm_ioctls[]` in
`kernel-open/nvidia-drm/nvidia-drm-drv.c`, built from DRM_IOCTL_DEF_DRV:

    DRM_IOCTL_DEF_DRV(NVIDIA_GET_DEV_INFO,
                      nv_drm_get_dev_info_ioctl,
                      DRM_RENDER_ALLOW|DRM_UNLOCKED),

The two sources are read separately and reconciled. A declared command with
no table entry is never dispatched: drm_ioctl() indexes the driver table by
_IOC_NR and a slot the table does not fill carries no handler. Such a command
is recorded `dispatched: false`.

    python3 tools/drm_inventory.py --out surface/drm-command-inventory.json

The reconciled count, 24 dispatched of 28 declared, feeds the campaign
denominator. A drift in it changes a published coverage figure, so the count
is asserted against EXPECTED_DECLARED and EXPECTED_DISPATCHED and a mismatch
is a hard failure naming what was found.

The flag split is asserted beside the total, because the flags decide which
device node reaches a command and the denominator is stated per node type.
drm_ioctl_permit() in the DRM core refuses a render client any command whose
flag word omits DRM_RENDER_ALLOW, and refuses any caller a DRM_MASTER command
unless that caller is the current master. The per-node reachability each
record carries is derived from the scraped flag word alone, so a driver that
reflags a command moves the reachability with it.

DRM_COMMAND_BASE and DRM_IOCTL_BASE are declared here as constants because
they live in the kernel's own include/uapi/drm/drm.h, which this repository
does not vendor. Both are recorded in the artefact so a consumer deriving a
request number reads the base it was built against.

This tool records the number, the direction and the parameter struct, and
never the request number itself. The request number needs sizeof(param
struct), which only the size probe in tools/syzlang_gen.py can measure, and a
number computed twice is a number that can disagree with itself.
"""
import argparse
import json
import logging
import os
import re
import sys

logger = logging.getLogger(__name__)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def repo_relative(path):
    """A path as the repository sees it, in forward slashes.

    An artefact that recorded an absolute path carried the author's home
    directory into a committed file, and differed between two checkouts of
    the same tree. A path outside the repository is returned absolute,
    because relative to nothing is worse than long.
    """
    absolute = os.path.abspath(path)
    try:
        rel = os.path.relpath(absolute, REPO_ROOT)
    except ValueError:                      # a different drive on Windows
        return absolute.replace(os.sep, "/")
    if rel.split(os.sep)[0] == os.pardir:
        return absolute.replace(os.sep, "/")
    return rel.replace(os.sep, "/")


DEFAULT_SRC = os.path.join(REPO_ROOT, "artifacts", "src",
                           "open-gpu-kernel-modules")
DEFAULT_OUT = os.path.join(REPO_ROOT, "surface",
                           "drm-command-inventory.json")

SCHEMA = "gspwn.drm-command-inventory/1"

# Paths inside the driver tree, relative to --src. Both are required: a
# missing one means --src does not point at open-gpu-kernel-modules, and one
# source alone cannot be reconciled against anything.
IOCTL_HEADER = os.path.join("kernel-open", "nvidia-drm",
                            "nv_drm_common_ioctl.h")
DISPATCH_SOURCE = os.path.join("kernel-open", "nvidia-drm",
                               "nvidia-drm-drv.c")
VERSION_MK = "version.mk"

# The reconciled count for driver 610.57.04. Both values are asserted on
# every run.
EXPECTED_DECLARED = 28
EXPECTED_DISPATCHED = 24

# The flag split, asserted beside the totals. These decide the per-node
# denominator, so a change in them is a change in a published figure.
EXPECTED_RENDER_ALLOW = 21
EXPECTED_MASTER = 2

# The ioctl encoding the DRM core applies to a driver command. Both come from
# the kernel's include/uapi/drm/drm.h, which this repository does not vendor:
# DRM_IOCTL_BASE at drm.h:1076 and DRM_COMMAND_BASE at drm.h:1363. A driver
# command number is an offset from the second, and drm_ioctl() subtracts it
# back off before indexing the driver table.
DRM_IOCTL_BASE = ord("d")
DRM_COMMAND_BASE = 0x40
DRM_COMMAND_END = 0xA0

# The command the header declares no number for. 0x07 sits between
# GEM_PRIME_FENCE_ATTACH and GET_CLIENT_CAPABILITY and is declared by nothing,
# so the declared range has a hole in it and the declared count is not the
# highest number plus one. Recorded so a reader confirms the arithmetic.
UNUSED_NUMBERS_REASON = "no DRM_NVIDIA_ define declares this number"

UNDISPATCHED_REASON = "no entry in nv_drm_ioctls[]"

# The flag names drm_ioctl_permit() reads. DRM_UNLOCKED carries no permission
# and is recorded on the record without entering any reachability decision.
RENDER_ALLOW_FLAG = "DRM_RENDER_ALLOW"
MASTER_FLAG = "DRM_MASTER"

# A declared command number. The trailing comment some of them carry is
# stripped by blank_comments before this runs.
DECLARE_RE = re.compile(
    r"^#define\s+DRM_(NVIDIA_[A-Z0-9_]+)\s+(0[xX][0-9a-fA-F]+|\d+)\s*$", re.M)

# A request-number macro and the DRM direction macro it expands to. The
# definition wraps across continuation lines, and four of them wrap inside the
# parenthesised sum as well, so every separator matches a newline. The Solaris
# arm of the NV_LINUX conditional defines two of these names as a bare `0`,
# which carries no direction macro and is excluded by this pattern's shape.
REQUEST_MACRO_RE = re.compile(
    r"^#define\s+DRM_IOCTL_(NVIDIA_[A-Z0-9_]+)\s*\\?\s*\n?"
    r"\s*(DRM_IOWR|DRM_IOW|DRM_IOR|DRM_IO)\s*\(",
    re.M)

# The struct a request macro names. DRM_IO takes no struct at all, so the
# group is optional and a record for such a command carries a null.
REQUEST_STRUCT_RE = re.compile(r"struct\s+([a-z_][a-z0-9_]*)")

# A dispatch table entry. The flag word runs to the closing parenthesis and
# every entry in the real table wraps across three lines.
ENTRY_RE = re.compile(
    r"DRM_IOCTL_DEF_DRV\s*\(\s*"
    r"([A-Z0-9_]+)\s*,\s*"
    r"([a-z_][A-Za-z0-9_]*)\s*,\s*"
    r"([^)]*?)\s*\)\s*,", re.S)

TABLE_ANCHOR = "nv_drm_ioctls[] = {"

VERSION_RE = re.compile(r"^NVIDIA_VERSION\s*=\s*(\S+)", re.M)


class SourceError(Exception):
    """The driver tree is not shaped the way this tool requires."""


def read_text(path, what):
    """Read a file that must exist, naming it in the failure."""
    if not os.path.isfile(path):
        raise SourceError("%s not found at %s: --src must point at a checkout "
                          "of open-gpu-kernel-modules" % (what, path))
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError as e:
        raise SourceError("cannot read %s at %s: %s" % (what, path, e))


def read_driver_version(src_root):
    """Return the NVIDIA_VERSION string, or None when version.mk is absent."""
    path = os.path.join(src_root, VERSION_MK)
    if not os.path.isfile(path):
        logger.warning("no %s in %s: inventory will carry no driver version",
                       VERSION_MK, src_root)
        return None
    m = VERSION_RE.search(read_text(path, "driver version file"))
    if not m:
        logger.warning("%s defines no NVIDIA_VERSION", path)
        return None
    return m.group(1)


def blank_comments(text):
    """Replace every C comment with blanks, keeping newlines in place.

    Offsets and line numbers survive the substitution, so a match found in
    the returned text points at the same position in the original.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out.append("".join(c if c == "\n" else " " for c in text[i:end]))
            i = end
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            out.append(" " * (end - i))
            i = end
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def line_of(text, offset):
    """The 1-based line number holding a byte offset."""
    return text.count("\n", 0, offset) + 1


def parse_declared(text):
    """Return one record per declared command number, in number order.

    Each record carries the command name, its driver-relative number, and the
    line it was declared on. A number declared twice is a defect the caller
    reports, because two names sharing a number means one of them can never
    be reached.
    """
    stripped = blank_comments(text)
    records = []
    for m in DECLARE_RE.finditer(stripped):
        records.append({
            "command": m.group(1),
            "nr": int(m.group(2), 0),
            "line": line_of(stripped, m.start()),
        })
    if not records:
        raise SourceError(
            "no `#define DRM_NVIDIA_` command numbers found: the header this "
            "tool reads is %s inside the driver checkout" % IOCTL_HEADER)

    by_number = {}
    for record in records:
        if record["nr"] in by_number:
            raise SourceError(
                "DRM_%s and DRM_%s both declare number 0x%02x: "
                "drm_ioctl() indexes the driver table by that number and one "
                "of the two can never be reached"
                % (by_number[record["nr"]], record["command"], record["nr"]))
        by_number[record["nr"]] = record["command"]

    records.sort(key=lambda r: r["nr"])
    logger.info("read %d declared command numbers from the header",
                len(records))
    return records


def parse_request_macros(text):
    """Return {command name: (direction macro, parameter struct or None)}.

    The Solaris arm of the NV_LINUX conditional redefines two of these names
    as a bare `0`. That arm carries no direction macro, so it never matches,
    and the Linux definition is the only one read.
    """
    stripped = blank_comments(text)
    macros = {}
    for m in REQUEST_MACRO_RE.finditer(stripped):
        name = m.group(1)
        if name in macros:
            raise SourceError(
                "DRM_IOCTL_%s carries two direction macros, at lines "
                "%d and %d: the request number this tool reports would depend "
                "on which one the compiler took"
                % (name, macros[name][2], line_of(stripped, m.start())))
        # The struct, when there is one, sits between this macro's opening
        # parenthesis and the start of the next directive.
        tail_end = stripped.find("\n#define", m.end())
        tail = stripped[m.end():tail_end if tail_end > 0 else len(stripped)]
        struct = REQUEST_STRUCT_RE.search(tail)
        macros[name] = (m.group(2), struct.group(1) if struct else None,
                        line_of(stripped, m.start()))
    if not macros:
        raise SourceError(
            "no `#define DRM_IOCTL_NVIDIA_` request macros found in %s: "
            "without them no direction or parameter struct can be recorded"
            % IOCTL_HEADER)
    logger.info("read %d request-number macros from the header", len(macros))
    return macros


def table_region(text):
    """Return the nv_drm_ioctls[] initialiser body and the line it opens on."""
    start = text.find(TABLE_ANCHOR)
    if start < 0:
        raise SourceError(
            "no `%s` initialiser found: the dispatch table this tool reads "
            "is in %s inside the driver checkout"
            % (TABLE_ANCHOR, DISPATCH_SOURCE))
    brace = start + len(TABLE_ANCHOR) - 1
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace:index + 1], line_of(text, brace)
    raise SourceError(
        "the `%s` initialiser never closes: brace matching from line %d "
        "reached the end of the file" % (TABLE_ANCHOR, line_of(text, brace)))


def parse_table(text):
    """Return one record per dispatch table entry, in table order.

    Each record carries the command name, the handler symbol, the flag names
    the entry sets, and the line it was read from.
    """
    stripped = blank_comments(text)
    body, base_line = table_region(stripped)

    records = []
    for m in ENTRY_RE.finditer(body):
        flags = [f.strip() for f in m.group(3).split("|") if f.strip()]
        if not flags:
            raise SourceError(
                "the entry for %s carries an empty flag word: a driver ioctl "
                "always renders at least a 0 there, so the scrape has lost "
                "the third macro argument" % m.group(1))
        records.append({
            "command": m.group(1),
            "handler": m.group(2),
            "flags": flags,
            "line": base_line + body.count("\n", 0, m.start()),
        })

    if not records:
        raise SourceError(
            "the `%s` initialiser holds no DRM_IOCTL_DEF_DRV use: the table "
            "is built by a macro this tool no longer recognises"
            % TABLE_ANCHOR)
    logger.info("read %d dispatch entries from the table", len(records))
    return records


def reachability(flags):
    """-> what each device node grants a command carrying `flags`.

    Derived from drm_ioctl_permit() in the DRM core, drm_ioctl.c:611-633:

      * a render client is refused any command whose flag word omits
        DRM_RENDER_ALLOW, which is the last of the four tests
      * a DRM_MASTER command is refused unless the caller is current master,
        and a render client is never one

    A primary node client is subject to neither the render test nor, unless
    the command sets DRM_MASTER, the master test. drm_master_open() at
    drm_auth.c:317-335 makes the opening file the master when the device has
    none, so a tenant that opens the card node first on a host running no
    display server holds master and reaches the DRM_MASTER commands. That is
    a property of the host at the moment of the open and never a guarantee,
    so the condition is recorded and the command is not counted as plainly
    reachable.
    """
    render_allow = RENDER_ALLOW_FLAG in flags
    master = MASTER_FLAG in flags
    render = {
        "reachable": render_allow,
        "condition": None,
        "reason": None if render_allow else
                  "drm_ioctl_permit refuses a render client any command whose "
                  "flag word omits %s" % RENDER_ALLOW_FLAG,
    }
    card = {
        "reachable": True,
        "condition": "the opening file must be the current DRM master, which "
                     "drm_master_open grants only when the device has none"
                     if master else None,
        "reason": None,
    }
    return {"card": card, "render": render}


def cross_check(declared, entries, expect_declared, expect_dispatched):
    """Reconcile the header against the table, or fail naming the difference.

    Six conditions, in the order a defect is easiest to read from:
    a command dispatched twice, a command dispatched without being declared,
    the declared total, the dispatched total, every number inside the range
    the DRM core reserves for a driver, and the flag split.
    """
    declared_set = {d["command"] for d in declared}
    numbers = {d["command"]: d["nr"] for d in declared}

    seen = {}
    for entry in entries:
        if entry["command"] in seen:
            raise SourceError(
                "%s is dispatched twice, at lines %d and %d: one command "
                "occupies one table slot and the second entry silently "
                "overwrites the first"
                % (entry["command"], seen[entry["command"]], entry["line"]))
        seen[entry["command"]] = entry["line"]

    undeclared = sorted(n for n in seen if n not in declared_set)
    if undeclared:
        raise SourceError(
            "the dispatch table names %d command(s) the header declares no "
            "number for: %s" % (len(undeclared), ", ".join(undeclared)))

    if len(declared) != expect_declared:
        raise SourceError(
            "the header declares %d command numbers, expected %d: the "
            "declared total feeds the campaign denominator and a change in "
            "it is not a silent one" % (len(declared), expect_declared))

    if len(entries) != expect_dispatched:
        missing = sorted(declared_set - set(seen))
        raise SourceError(
            "the dispatch table carries %d entries, expected %d: %d declared "
            "command(s) have no entry (%s). The dispatched total feeds the "
            "campaign denominator and a change in it is not a silent one"
            % (len(entries), expect_dispatched,
               len(missing), ", ".join(missing) or "none"))

    out_of_range = sorted(
        "%s (0x%02x)" % (name, numbers[name]) for name in numbers
        if not 0 <= numbers[name] <= DRM_COMMAND_END - DRM_COMMAND_BASE)
    if out_of_range:
        raise SourceError(
            "%d declared command number(s) fall outside the range the DRM "
            "core reserves for a driver, 0 to 0x%02x: %s. drm_ioctl() routes "
            "a request outside it to the core table and the driver never "
            "sees it" % (len(out_of_range), DRM_COMMAND_END - DRM_COMMAND_BASE,
                         ", ".join(out_of_range)))

    render_allow = sum(1 for e in entries if RENDER_ALLOW_FLAG in e["flags"])
    master = sum(1 for e in entries if MASTER_FLAG in e["flags"])
    both = [e["command"] for e in entries
            if RENDER_ALLOW_FLAG in e["flags"] and MASTER_FLAG in e["flags"]]
    if both:
        raise SourceError(
            "%d command(s) set both %s and %s: %s. The per-node denominator "
            "reads the two as exclusive and would count them twice"
            % (len(both), RENDER_ALLOW_FLAG, MASTER_FLAG, ", ".join(both)))
    if render_allow != EXPECTED_RENDER_ALLOW or master != EXPECTED_MASTER:
        raise SourceError(
            "the flag split reads %d %s and %d %s, expected %d and %d. The "
            "flags decide which device node reaches a command and the "
            "denominator is stated per node type, so a change in them is a "
            "change in a published figure"
            % (render_allow, RENDER_ALLOW_FLAG, master, MASTER_FLAG,
               EXPECTED_RENDER_ALLOW, EXPECTED_MASTER))

    logger.info("cross-check passed: %d dispatched of %d declared, "
                "%d %s and %d %s", len(entries), len(declared),
                render_allow, RENDER_ALLOW_FLAG, master, MASTER_FLAG)
    return {"render_allow": render_allow, "master": master,
            "flagless": len(entries) - render_allow - master}


def unused_numbers(declared):
    """-> every number inside the declared range that no define claims.

    The declared range runs from the lowest number to the highest, and 0x07
    sits inside it with no name. A reader confirming 28 against the highest
    number needs the hole named or the arithmetic does not close.
    """
    claimed = {d["nr"] for d in declared}
    low, high = min(claimed), max(claimed)
    return [{"nr": n, "reason": UNUSED_NUMBERS_REASON}
            for n in range(low, high + 1) if n not in claimed]


def build_records(declared, entries, macros):
    """Build one record per declared command, dispatched or not."""
    by_command = {e["command"]: e for e in entries}
    records = []
    for item in declared:
        name = item["command"]
        entry = by_command.get(name)
        direction, param_struct, _macro_line = macros.get(
            name, (None, None, None))
        record = {
            "command": name,
            "number_macro": "DRM_%s" % name,
            "request_macro": "DRM_IOCTL_%s" % name,
            "nr": item["nr"],
            "command_nr": DRM_COMMAND_BASE + item["nr"],
            "direction": direction,
            "param_struct": param_struct,
            "dispatched": entry is not None,
            "handler": entry["handler"] if entry else None,
            "flags": entry["flags"] if entry else None,
            "render_allow": (RENDER_ALLOW_FLAG in entry["flags"]
                             if entry else None),
            "master": MASTER_FLAG in entry["flags"] if entry else None,
            "reachable_on": reachability(entry["flags"]) if entry else None,
            "undispatched_reason": None if entry else UNDISPATCHED_REASON,
            "source": ("%s:%d" % (DISPATCH_SOURCE.replace(os.sep, "/"),
                                  entry["line"])) if entry else
                      ("%s:%d" % (IOCTL_HEADER.replace(os.sep, "/"),
                                  item["line"])),
        }
        records.append(record)
    return records


def summarise(records, checked, declared):
    """The counts this phase claims, with the excluded commands named.

    undispatched_commands carries the name and the number of every command
    the table leaves out, so a reader confirms 24 against 28 from the
    artefact and the header without re-running the scrape. The per-node
    counts are carried apart because the two nodes do not grant the same set
    and collapsing them would state one number for two different things.
    """
    dispatched = [r for r in records if r["dispatched"]]
    card = [r for r in dispatched if r["reachable_on"]["card"]["reachable"]]
    card_conditional = [r for r in card
                        if r["reachable_on"]["card"]["condition"]]
    render = [r for r in dispatched
              if r["reachable_on"]["render"]["reachable"]]
    return {
        "declared": len(records),
        "dispatched": len(dispatched),
        "undispatched": len(records) - len(dispatched),
        "render_allow": checked["render_allow"],
        "master": checked["master"],
        "flagless": checked["flagless"],
        "reachable_card": len(card),
        "reachable_card_unconditional": len(card) - len(card_conditional),
        "reachable_card_conditional": len(card_conditional),
        "reachable_render": len(render),
        "undispatched_commands": [
            {"command": r["command"], "nr": r["nr"],
             "reason": r["undispatched_reason"]}
            for r in records if not r["dispatched"]],
        "unreachable_on_render": [
            {"command": r["command"], "nr": r["nr"],
             "reason": r["reachable_on"]["render"]["reason"]}
            for r in dispatched
            if not r["reachable_on"]["render"]["reachable"]],
        "conditional_on_card": [
            {"command": r["command"], "nr": r["nr"],
             "condition": r["reachable_on"]["card"]["condition"]}
            for r in card_conditional],
        "unused_numbers": unused_numbers(declared),
    }


def collect(src_root, expect_declared=EXPECTED_DECLARED,
            expect_dispatched=EXPECTED_DISPATCHED):
    """Read both sources, reconcile them, and build the inventory."""
    header_path = os.path.join(src_root, IOCTL_HEADER)
    source_path = os.path.join(src_root, DISPATCH_SOURCE)
    header_text = read_text(header_path, "the nvidia-drm ioctl header")
    source_text = read_text(source_path, "the nvidia-drm dispatch source")

    declared = parse_declared(header_text)
    macros = parse_request_macros(header_text)
    entries = parse_table(source_text)
    checked = cross_check(declared, entries, expect_declared,
                          expect_dispatched)

    missing_macro = sorted(d["command"] for d in declared
                           if d["command"] not in macros)
    if missing_macro:
        raise SourceError(
            "%d declared command(s) carry no DRM_IOCTL_NVIDIA_ request "
            "macro: %s. Without one there is no direction and no parameter "
            "struct, and no request number can be derived"
            % (len(missing_macro), ", ".join(missing_macro)))

    records = build_records(declared, entries, macros)
    source_stripped = blank_comments(source_text)
    return {
        "schema": SCHEMA,
        "source": {
            "src_root": repo_relative(src_root),
            "driver_version": read_driver_version(src_root),
            "ioctl_header": IOCTL_HEADER.replace(os.sep, "/"),
            "dispatch_source": DISPATCH_SOURCE.replace(os.sep, "/"),
        },
        "scan": {
            "table_line": table_region(source_stripped)[1],
            "ioctl_base": DRM_IOCTL_BASE,
            "ioctl_base_char": chr(DRM_IOCTL_BASE),
            "command_base": DRM_COMMAND_BASE,
            "command_end": DRM_COMMAND_END,
            "encoding": "request = dir<<30 | sizeof(param_struct)<<16 | "
                        "ioctl_base<<8 | (command_base + nr)",
            "encoding_source": "include/uapi/drm/drm.h:1076 and :1363 in the "
                               "kernel tree, which this repository does not "
                               "vendor",
        },
        "summary": summarise(records, checked, declared),
        "commands": records,
    }


def write_json(inventory, out_path):
    """Write the inventory, creating the parent directory if needed."""
    parent = os.path.dirname(os.path.abspath(out_path))
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as e:
        raise SourceError("cannot create output directory %s: %s"
                          % (parent, e))
    tmp = out_path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(inventory, f, indent=2, sort_keys=False)
            f.write("\n")
        os.replace(tmp, out_path)
    except OSError as e:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise SourceError("cannot write %s: %s" % (out_path, e))
    logger.info("wrote %s", out_path)


def main():
    ap = argparse.ArgumentParser(
        description="Enumerate the /dev/dri command space from the "
                    "DRM_NVIDIA_ command numbers and the nv_drm_ioctls[] "
                    "dispatch table in the driver source.")
    ap.add_argument("--src", default=DEFAULT_SRC,
                    help="open-gpu-kernel-modules checkout (default: %s)"
                         % os.path.relpath(DEFAULT_SRC, REPO_ROOT))
    ap.add_argument("--out", default=DEFAULT_OUT,
                    help="JSON inventory to write (default: %s)"
                         % os.path.relpath(DEFAULT_OUT, REPO_ROOT))
    ap.add_argument("--expect-declared", type=int, default=EXPECTED_DECLARED,
                    help="declared command count to assert (default: "
                         "%(default)s)")
    ap.add_argument("--expect-dispatched", type=int,
                    default=EXPECTED_DISPATCHED,
                    help="dispatched command count to assert (default: "
                         "%(default)s)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log every entry read")
    a = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if a.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)

    if not os.path.isdir(a.src):
        print("error: --src %s is not a directory" % a.src, file=sys.stderr)
        return 2
    try:
        inventory = collect(a.src, a.expect_declared, a.expect_dispatched)
        write_json(inventory, a.out)
    except SourceError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2

    s = inventory["summary"]
    print("%d dispatched of %d declared nvidia-drm commands (%s)"
          % (s["dispatched"], s["declared"],
             inventory["source"]["driver_version"] or "unknown version"))
    print("  %-24s %d" % ("DRM_RENDER_ALLOW", s["render_allow"]))
    print("  %-24s %d" % ("DRM_MASTER", s["master"]))
    print("  %-24s %d" % ("no permission flag", s["flagless"]))
    print("  %-24s %d (%d unconditional, %d while master)"
          % ("reachable on cardN", s["reachable_card"],
             s["reachable_card_unconditional"],
             s["reachable_card_conditional"]))
    print("  %-24s %d" % ("reachable on renderDN", s["reachable_render"]))
    print("  %-24s %d" % ("undispatched", s["undispatched"]))
    for item in s["undispatched_commands"]:
        print("      0x%02x %s (%s)"
              % (item["nr"], item["command"], item["reason"]))
    print("  %-24s %d" % ("unused numbers", len(s["unused_numbers"])))
    for item in s["unused_numbers"]:
        print("      0x%02x (%s)" % (item["nr"], item["reason"]))
    print("wrote %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
