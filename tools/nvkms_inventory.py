#!/usr/bin/env python3
"""Enumerate the /dev/nvidia-modeset command space from the driver source.

One ioctl carries every NVKMS call. The kernel request number is a single
NVKMS_IOCTL_CMD, and the sub-command sits in the `cmd` field of the
NvKmsIoctlParams envelope, so the command space has to be enumerated before
the describe phase can attach a parameter struct per sub-command.

Two files hold the answer and neither holds all of it. The declared space is
`enum NvKmsIoctlCommand` in `src/nvidia-modeset/interface/nvkms-api.h`. The
populated space is the `dispatch[]` designated-initialiser array in
`nvKmsIoctl()` in `src/nvidia-modeset/src/nvkms.c`, built from two macros:

    #define ENTRY(_cmd, _func)                                              \\
            _ENTRY_WITH_USER(_cmd, _func, NULL, NULL, 0)

    #define ENTRY_CUSTOM_USER(_cmd, _func)                                  \\
            _ENTRY_WITH_USER(_cmd, _func,                                   \\
                             _func##PrepUser, _func##DoneUser,              \\
                             sizeof(struct NvKms##_func##ExtraUserState))

        ENTRY(NVKMS_IOCTL_ALLOC_DEVICE, AllocDevice),
        ENTRY_CUSTOM_USER(NVKMS_IOCTL_FLIP, Flip),

The two sources are read separately and reconciled. A declared command with
no entry leaves its array slot zero-initialised, `dispatch[cmd].proc` reads
NULL, and `nvKmsIoctl()` rejects the call. Such a command is recorded
`dispatched: false`. `ARRAY_LEN(dispatch)` bounds the index space ahead of
that lookup, and every declared ordinal has to fall inside it.

    python3 tools/nvkms_inventory.py --out surface/nvkms-command-inventory.json

The reconciled count, 64 dispatched of 66 declared, feeds the campaign
denominator. A drift in it changes a published coverage figure, so the count
is asserted against EXPECTED_DECLARED and EXPECTED_DISPATCHED and a mismatch
is a hard failure naming what was found.

The plain and custom-user macro counts are asserted separately, and their sum
against the dispatched total. Both macro names appear as `#define` lines
inside the initialiser, so a scrape that counts a definition as a use reads
58 plain and 6 custom-user. That sums to 64 and passes a total-only check.
The split is the check that catches it. Macro definitions are excluded
structurally, by their column-zero `#`, by the preprocessor continuation run
they start, and by the command argument pattern, and never by line number.
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
                           "nvkms-command-inventory.json")

SCHEMA = "gspwn.nvkms-command-inventory/1"

# Paths inside the driver tree, relative to --src. Both are required: a
# missing one means --src does not point at open-gpu-kernel-modules, and one
# source alone cannot be reconciled against anything.
API_HEADER = os.path.join("src", "nvidia-modeset", "interface", "nvkms-api.h")
DISPATCH_SOURCE = os.path.join("src", "nvidia-modeset", "src", "nvkms.c")
VERSION_MK = "version.mk"

# The reconciled count for driver 610.57.04. Both values are asserted on
# every run. See the module docstring for why the macro split is asserted
# beside the total.
EXPECTED_DECLARED = 66
EXPECTED_DISPATCHED = 64

# The two commands the header declares and the table leaves out.
UNDISPATCHED_REASON = "no handler in the dispatch table"

ENUM_RE = re.compile(r"\benum\s+NvKmsIoctlCommand\s*\{(.*?)\}\s*;", re.S)

# The initialiser opens on the line that closes the anonymous struct. Brace
# matching starts from the trailing brace of this anchor.
DISPATCH_ANCHOR = "dispatch[] = {"

# The bound nvKmsIoctl() applies before it reads dispatch[cmd].proc. Without
# it a command declared past the end of the array would index out of bounds,
# and this tool's array_len figure would describe nothing the kernel enforces.
ARRAY_BOUND = "ARRAY_LEN(dispatch)"

COMMAND_NAME_RE = re.compile(r"^NVKMS_IOCTL_[A-Za-z0-9_]+$")

# A table use, anchored to the indentation that precedes it. A `#define` sits
# at column zero, so the leading run of blanks excludes both definitions on
# its own. The command argument pattern excludes them a second time, because
# a definition names its parameter `_cmd`.
#
# Six of the uses in the real table wrap after the command argument, because
# the command name and the proc symbol together run past the column limit:
#
#         ENTRY(NVKMS_IOCTL_DECLARE_DYNAMIC_DPY_INTEREST,
#               DeclareDynamicDpyInterest),
#
# so the separators inside the parentheses match newlines as well as blanks.
ENTRY_USE_RE = re.compile(
    r"^[ \t]+(ENTRY|ENTRY_CUSTOM_USER)\s*\(\s*"
    r"(NVKMS_IOCTL_[A-Za-z0-9_]+)\s*,\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*,", re.M)

PLAIN_MACRO = "ENTRY"
CUSTOM_USER_MACRO = "ENTRY_CUSTOM_USER"

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


def parse_enum(text):
    """Return one record per declared command, in ordinal order.

    Each record carries the command name, its ordinal, and the line it was
    declared on. The enum in this header names no explicit initialiser, so an
    entry that is anything other than a bare NVKMS_IOCTL_ identifier means
    the ordinals can no longer be read off the declaration order.
    """
    stripped = blank_comments(text)
    m = ENUM_RE.search(stripped)
    if m is None:
        raise SourceError(
            "no `enum NvKmsIoctlCommand` declaration found: the header this "
            "tool reads is %s inside the driver checkout" % API_HEADER)

    records = []
    offset = m.start(1)
    for piece in m.group(1).split(","):
        name = piece.strip()
        if name:
            if not COMMAND_NAME_RE.match(name):
                raise SourceError(
                    "enum NvKmsIoctlCommand declares %r at line %d, which is "
                    "not a bare NVKMS_IOCTL_ name: ordinals are read off the "
                    "declaration order and an explicit initialiser breaks "
                    "that" % (name, line_of(stripped, offset)))
            records.append({
                "command": name,
                "ordinal": len(records),
                "line": line_of(stripped,
                                offset + piece.index(name)),
            })
        offset += len(piece) + 1

    if not records:
        raise SourceError("enum NvKmsIoctlCommand declares no commands")
    logger.info("read %d declared commands from the enum", len(records))
    return records


def blank_preprocessor(text):
    """Replace every preprocessor directive with blanks, keeping newlines.

    A directive runs from a line whose first non-blank character is `#` to
    the end of its backslash continuation. The two macro definitions inside
    the dispatch initialiser are removed this way, by their own structure, so
    a shift in the file cannot bring them back into the count. Offsets and
    line numbers survive, so a match in the returned text points at the same
    position in the original.
    """
    out = []
    continuing = False
    for line in text.split("\n"):
        if continuing or line.lstrip().startswith("#"):
            continuing = line.endswith("\\")
            out.append(" " * len(line))
        else:
            continuing = False
            out.append(line)
    return "\n".join(out)


def dispatch_region(text):
    """Return the dispatch[] initialiser body and the line it opens on."""
    start = text.find(DISPATCH_ANCHOR)
    if start < 0:
        raise SourceError(
            "no `%s` initialiser found: the dispatch table this tool reads "
            "is in %s inside the driver checkout"
            % (DISPATCH_ANCHOR, DISPATCH_SOURCE))
    brace = start + len(DISPATCH_ANCHOR) - 1
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
        "reached the end of the file" % (DISPATCH_ANCHOR, line_of(text, brace)))


def parse_dispatch(text):
    """Return one record per dispatch table entry, in table order.

    Each record carries the command name, the proc symbol, the macro that
    built it, and the line it was read from.
    """
    stripped = blank_comments(text)
    body, base_line = dispatch_region(stripped)
    body = blank_preprocessor(body)

    records = [{
        "command": m.group(2),
        "proc": m.group(3),
        "macro": m.group(1),
        "line": base_line + body.count("\n", 0, m.start()),
    } for m in ENTRY_USE_RE.finditer(body)]

    if not records:
        raise SourceError(
            "the `%s` initialiser holds no ENTRY or ENTRY_CUSTOM_USER use: "
            "the table is built by macros this tool no longer recognises"
            % DISPATCH_ANCHOR)
    logger.info("read %d dispatch entries from the table", len(records))
    return records


def check_array_bound(text):
    """Confirm nvKmsIoctl() bounds the index before the proc lookup."""
    if ARRAY_BOUND not in text:
        raise SourceError(
            "%s carries no `%s` bound: without it the array length this tool "
            "reports is not the limit the kernel applies to a command number"
            % (DISPATCH_SOURCE, ARRAY_BOUND))


def cross_check(declared, entries, expect_declared, expect_dispatched):
    """Reconcile the enum against the table, or fail naming the difference.

    Six conditions, in the order a defect is easiest to read from:
    a command dispatched twice, a command dispatched without being declared,
    the declared total, the dispatched total, the array bound, and the macro
    split against the dispatched total.
    """
    declared_names = [d["command"] for d in declared]
    declared_set = set(declared_names)
    ordinals = {d["command"]: d["ordinal"] for d in declared}

    seen = {}
    for entry in entries:
        if entry["command"] in seen:
            raise SourceError(
                "%s is dispatched twice, at lines %d and %d: one command "
                "occupies one array slot and the second use silently "
                "overwrites the first"
                % (entry["command"], seen[entry["command"]], entry["line"]))
        seen[entry["command"]] = entry["line"]

    undeclared = sorted(n for n in seen if n not in declared_set)
    if undeclared:
        raise SourceError(
            "the dispatch table names %d command(s) the enum does not "
            "declare: %s" % (len(undeclared), ", ".join(undeclared)))

    if len(declared) != expect_declared:
        raise SourceError(
            "enum NvKmsIoctlCommand declares %d commands, expected %d: the "
            "declared total feeds the campaign denominator and a change in "
            "it is not a silent one"
            % (len(declared), expect_declared))

    if len(entries) != expect_dispatched:
        missing = sorted(declared_set - set(seen))
        raise SourceError(
            "the dispatch table carries %d entries, expected %d: %d declared "
            "command(s) have no entry (%s). The dispatched total feeds the "
            "campaign denominator and a change in it is not a silent one"
            % (len(entries), expect_dispatched,
               len(missing), ", ".join(missing) or "none"))

    array_len = max(ordinals[n] for n in seen) + 1
    past_bound = [n for n in declared_names if ordinals[n] >= array_len]
    if past_bound:
        raise SourceError(
            "%d declared command(s) sit past the end of the dispatch array, "
            "which is %d slots long: %s. nvKmsIoctl() rejects them on the %s "
            "bound before it reads a handler"
            % (len(past_bound), array_len, ", ".join(past_bound), ARRAY_BOUND))

    plain = sum(1 for e in entries if e["macro"] == PLAIN_MACRO)
    custom = sum(1 for e in entries if e["macro"] == CUSTOM_USER_MACRO)
    if plain + custom != len(entries):
        raise SourceError(
            "the macro split does not reconcile: %d plain and %d custom-user "
            "against %d entries. A macro this tool does not recognise builds "
            "part of the table" % (plain, custom, len(entries)))

    logger.info("cross-check passed: %d dispatched of %d declared, "
                "%d plain and %d custom-user, array length %d",
                len(entries), len(declared), plain, custom, array_len)
    return {"array_len": array_len, "plain": plain, "custom_user": custom}


def build_records(declared, entries):
    """Build one record per declared command, dispatched or not.

    The parameter, request and reply struct names come from the macro
    expansion, which pastes the proc symbol into NvKms<Func>Params,
    NvKms<Func>Request and NvKms<Func>Reply. Recording them here keeps the
    naming convention in one place, and a consumer reads the field.
    """
    by_command = {e["command"]: e for e in entries}
    records = []
    for item in declared:
        entry = by_command.get(item["command"])
        if entry is None:
            records.append({
                "command": item["command"],
                "ordinal": item["ordinal"],
                "dispatched": False,
                "macro": None,
                "custom_user": False,
                "proc": None,
                "param_struct": None,
                "param_size": None,
                "request_struct": None,
                "reply_struct": None,
                "extra_user_state_struct": None,
                "undispatched_reason": UNDISPATCHED_REASON,
                "source": "%s:%d" % (API_HEADER.replace(os.sep, "/"),
                                     item["line"]),
            })
            continue
        func = entry["proc"]
        custom = entry["macro"] == CUSTOM_USER_MACRO
        records.append({
            "command": item["command"],
            "ordinal": item["ordinal"],
            "dispatched": True,
            "macro": entry["macro"],
            "custom_user": custom,
            "proc": func,
            "param_struct": "NvKms%sParams" % func,
            "param_size": "sizeof(struct NvKms%sParams)" % func,
            "request_struct": "NvKms%sRequest" % func,
            "reply_struct": "NvKms%sReply" % func,
            "extra_user_state_struct":
                ("NvKms%sExtraUserState" % func) if custom else None,
            "undispatched_reason": None,
            "source": "%s:%d" % (DISPATCH_SOURCE.replace(os.sep, "/"),
                                 entry["line"]),
        })
    return records


def summarise(records, checked):
    """The count this phase claims, with the two excluded commands named.

    undispatched_commands carries the name and the ordinal of every command
    the table leaves out, so a reader confirms 64 against 66 from the
    artefact and the header without re-running the scrape.
    """
    dispatched = [r for r in records if r["dispatched"]]
    return {
        "declared": len(records),
        "dispatched": len(dispatched),
        "undispatched": len(records) - len(dispatched),
        "entries_plain": checked["plain"],
        "entries_custom_user": checked["custom_user"],
        "undispatched_commands": [
            {"command": r["command"], "ordinal": r["ordinal"]}
            for r in records if not r["dispatched"]],
    }


def collect(src_root, expect_declared=EXPECTED_DECLARED,
            expect_dispatched=EXPECTED_DISPATCHED):
    """Read both sources, reconcile them, and build the inventory."""
    header_path = os.path.join(src_root, API_HEADER)
    source_path = os.path.join(src_root, DISPATCH_SOURCE)
    header_text = read_text(header_path, "NVKMS API header")
    source_text = read_text(source_path, "NVKMS dispatch source")

    declared = parse_enum(header_text)
    entries = parse_dispatch(source_text)
    check_array_bound(source_text)
    checked = cross_check(declared, entries, expect_declared,
                          expect_dispatched)

    records = build_records(declared, entries)
    header_stripped = blank_comments(header_text)
    source_stripped = blank_comments(source_text)
    return {
        "schema": SCHEMA,
        "source": {
            "src_root": repo_relative(src_root),
            "driver_version": read_driver_version(src_root),
            "api_header": API_HEADER.replace(os.sep, "/"),
            "dispatch_source": DISPATCH_SOURCE.replace(os.sep, "/"),
        },
        "scan": {
            "enum_line": line_of(header_stripped,
                                 ENUM_RE.search(header_stripped).start()),
            "dispatch_line": dispatch_region(source_stripped)[1],
            "array_len": checked["array_len"],
            "array_bound_expression": ARRAY_BOUND,
        },
        "summary": summarise(records, checked),
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
        description="Enumerate the /dev/nvidia-modeset command space from "
                    "the NvKmsIoctlCommand enum and the dispatch table in "
                    "the driver source.")
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
    print("%d dispatched of %d declared NVKMS commands (%s)"
          % (s["dispatched"], s["declared"],
             inventory["source"]["driver_version"] or "unknown version"))
    print("  %-16s %d" % ("plain", s["entries_plain"]))
    print("  %-16s %d" % ("custom user", s["entries_custom_user"]))
    print("  %-16s %d" % ("array length", inventory["scan"]["array_len"]))
    print("  %-16s %d" % ("undispatched", s["undispatched"]))
    for item in s["undispatched_commands"]:
        print("      [%d] %s (%s)"
              % (item["ordinal"], item["command"], UNDISPATCHED_REASON))
    print("wrote %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
