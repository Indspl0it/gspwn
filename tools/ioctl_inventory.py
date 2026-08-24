#!/usr/bin/env python3
"""Derive the in-scope ioctl inventory from the open-gpu-kernel-modules tree.

The describe phase needs one command per syzlang description and the seeds
phase needs the 32-bit request number strace prints for each. Both come from
the driver source, and both go stale when the driver branch moves, so this
tool re-reads a checkout on every run and carries no table of its own.

Three device-node families are in scope for the command inventory (docs threat
model): /dev/nvidiactl and /dev/nvidiaN, /dev/nvidia-uvm,
/dev/nvidia-uvm-tools. nvidia-drm and /dev/dri/* are excluded.

/dev/nvidia-modeset is handled by `--emit-map` alone. Its whole command set
multiplexes through one kernel request number, so the map records that number
and this tool's inventory and counts stay as they were.
tools/nvkms_inventory.py enumerates the command set behind it.

That number resolves the family for triage and never the sub-command. Every
call on the node carries it, and the command itself is NvKmsIoctlParams.cmd,
which sits in the payload and appears in no ioctl trace. This is F18, accepted
as a permanent limitation of this branch, so a crash matched on this number is
matched at family level and a reader must not take it for a command-level
match.

Two numbering schemes appear, and conflating them produces request numbers the
driver never sees:

  RM escapes    Linux _IOC encoding, request = dir<<30 | size<<16 | type<<8 |
                nr, with type NV_IOCTL_MAGIC and nr the NV_ESC_* number.
                Direction is _IOWR, from the __NV_IOWR macro in nv.h; the
                driver reads only _IOC_NR and _IOC_SIZE and never checks it.
  UVM           uvm.c switches on the raw `cmd` argument, and UVM_IOCTL_BASE(i)
                expands to i on Linux, so the request number is the bare
                command number with no _IOC fields at all.

Argument sizes are measured, never counted by hand. `--emit-probe DIR` writes
a C program per header group plus a runner; the runner compiles them for
x86-64, runs them, and writes the sizes JSON this tool reads back through
`--sizes`. A struct whose size is absent is reported as unresolved and its
request number is omitted. No size is ever guessed to fill a row.

The measured sizes are committed as surface/ioctl-sizes.json and are
the default `--sizes`, so a checkout regenerates the inventory without a
compiler:

    python3 tools/ioctl_inventory.py --src artifacts/src/open-gpu-kernel-modules

Re-measuring against a new driver release takes the full route:

    python3 tools/ioctl_inventory.py --src artifacts/src/open-gpu-kernel-modules \
        --emit-probe tmp/surface/probe
    bash tmp/surface/probe/measure_sizes.sh          # on a machine with gcc
    cp tmp/surface/probe/sizes.json surface/ioctl-sizes.json
    python3 tools/ioctl_inventory.py --src artifacts/src/open-gpu-kernel-modules

Every request number is derived from a measured size, so a build with fewer
sizes than the committed inventory records is refused rather than written.
"""
import argparse
import json
import logging
import os
import re
import subprocess
import sys

logger = logging.getLogger(__name__)

# Source files the inventory is derived from, relative to --src. Every one is
# required: a missing file means the checkout is not the tree this tool parses,
# and a partial inventory built from the rest would look complete.
ESCAPE_NUMBER_FILES = [
    "kernel-open/common/inc/nv-ioctl-numbers.h",
    "kernel-open/common/inc/nv-ioctl-numa.h",
    "src/nvidia/arch/nvalloc/unix/include/nv_escape.h",
]
ESCAPE_C = "src/nvidia/arch/nvalloc/unix/src/escape.c"
OSAPI_C = "src/nvidia/arch/nvalloc/unix/src/osapi.c"
NV_C = "kernel-open/nvidia/nv.c"
NV_H = "kernel-open/common/inc/nv.h"
UVM_IOCTL_H = "kernel-open/nvidia-uvm/uvm_ioctl.h"
UVM_LINUX_IOCTL_H = "kernel-open/nvidia-uvm/uvm_linux_ioctl.h"
UVM_TEST_IOCTL_H = "kernel-open/nvidia-uvm/uvm_test_ioctl.h"
UVM_C = "kernel-open/nvidia-uvm/uvm.c"
UVM_TOOLS_C = "kernel-open/nvidia-uvm/uvm_tools.c"
UVM_TEST_C = "kernel-open/nvidia-uvm/uvm_test.c"
UVM_API_H = "kernel-open/nvidia-uvm/uvm_api.h"
VERSION_MK = "version.mk"

# The modeset envelope, in both places the tree publishes it. The kernel
# module compiles against the kernel-open copy and the user-mode side against
# the interface copy, so a tree where the two differ carries two request
# numbers for one node. nvkms_request() requires them to agree.
NVKMS_IOCTL_H = "kernel-open/nvidia-modeset/nvkms-ioctl.h"
NVKMS_IOCTL_H_INTERFACE = "src/nvidia-modeset/interface/nvkms-ioctl.h"

# The key tools/surface_verify.py reads out of tools/ioctl_map.json,
# and the format its `stamp` subcommand writes. --emit-map rewrites the
# whole map, so a stamp applied by that subcommand is dropped on the next
# regeneration unless this module emits it too.
MAP_VERSION_KEY = "comment_driver_version"

# The section of tools/ioctl_map.json holding the multiplexer request numbers.
# Its key starts with "comment" so that both readers of the map skip it where
# they iterate request-number entries: tools/trace2seed.py's loader and
# tools/regression_check.py's read_ioctl_map(). trace2seed reads the section
# by name.
MAP_MULTIPLEXER_KEY = "comment_multiplexers"

# The section of tools/ioctl_map.json holding /dev/nvidia-modeset's one
# request number. Its key starts with "comment" for the same reason the
# multiplexer section's does: no description declares a call for the number,
# so a top-level entry would be looked up as a call name by trace2seed and
# checked against the description set by regression_check. It hangs under its
# own key and not under MAP_MULTIPLEXER_KEY because that section is rendered
# as the RM escapes page's multiplexer table, whose leaf counts are the RM
# control and allocation totals and do not describe this node.
MAP_MODESET_KEY = "comment_modeset"

# Escapes whose request number names a dispatcher and not a command, mapped to
# the parameter-struct field that selects the leaf. The describe phase emits one
# syzlang variant per leaf, so no single call name is correct for the request
# number, and putting one in the name map produces seeds naming a syscall
# syzkaller does not know. tools/surface_cov.py carries the same set as
# MULTIPLEXERS, without the field names.
MULTIPLEXER_SELECTOR = {
    "NV_ESC_RM_CONTROL": "cmd",
    "NV_ESC_RM_ALLOC": "hClass",
}

REQUIRED_FILES = ESCAPE_NUMBER_FILES + [
    ESCAPE_C, OSAPI_C, NV_C, NV_H, UVM_IOCTL_H, UVM_LINUX_IOCTL_H,
    UVM_TEST_IOCTL_H, UVM_C, UVM_TOOLS_C, UVM_TEST_C, UVM_API_H,
    NVKMS_IOCTL_H, NVKMS_IOCTL_H_INTERFACE,
]

# Include paths that make the driver's parameter headers compile standalone
# for x86-64 userspace, established by compiling them.
PROBE_INCLUDES_RM = [
    "kernel-open/common/inc",
    "src/common/sdk/nvidia/inc",
    "src/common/inc",
    # nv-unix-nvos-params-wrappers.h and nv-ioctl-lockless-diag.h live with the
    # RM Unix layer, not with the shared headers. Three entries in
    # RmIoctlsTable name types that are declared only here.
    "src/nvidia/arch/nvalloc/unix/include",
]
PROBE_INCLUDES_UVM = ["kernel-open/nvidia-uvm"] + PROBE_INCLUDES_RM

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


# Anchored on the repository and not the process working directory, so the
# producer and every consumer agree about where the file lives whatever
# directory the tool is invoked from. ctrl_surface.py, surface_cov.py,
# refgen.py, surface_verify.py and syzlang_gen.py all derive theirs the same
# way.
DEFAULT_OUT = os.path.join(REPO_ROOT, "surface", "ioctl-inventory.json")
DEFAULT_SIZES = os.path.join(REPO_ROOT, "surface", "ioctl-sizes.json")

# _IOC_SIZE is a 14-bit field, so the direct ioctl path cannot express an
# argument larger than this. NV_ESC_IOCTL_XFER_CMD carries the size in its own
# payload and is bounded by NV_ABSOLUTE_MAX_IOCTL_SIZE instead.
#
# The two ceilings differ by one byte and both are correct. IOC_SIZE_MAX is
# 16383, the largest size the _IOC encoding can carry, so an argument above it
# has no direct request number. NV_ABSOLUTE_MAX_IOCTL_SIZE is 16384 and
# kernel-open/nvidia/nv.c:2513 rejects only what exceeds it, so 16384 passes
# through XFER. An escape of exactly 16384 bytes is therefore reachable only
# through the wrapper. syzlang_gen.XFER_MAX_ARG_SIZE holds the second value
# and surface_cov reads xfer_only to credit such an escape to its wrapper.
IOC_SIZE_BITS = 14
IOC_SIZE_MAX = (1 << IOC_SIZE_BITS) - 1

# The direction field. The kernel driver ignores it, since nv_validate_ioctls()
# passes only _IOC_NR(cmd) and _IOC_SIZE(cmd) on, but the encoding the user-mode
# driver is expected to use is stated in the tree: __NV_IOWR(nr, type) at
# DIRECTION_SOURCE expands to _IOWR(NV_IOCTL_MAGIC, nr, type), and _IOWR sets
# _IOC_READ|_IOC_WRITE, which is 3. Nothing in the open modules calls that
# macro, so it is a contract with a closed component. A trace showing a
# different direction for some escape is a correction to make here.
DIRECTION_BITS = 3
DIRECTION_SOURCE = "kernel-open/common/inc/nv.h:84 (__NV_IOWR)"

# The direct path's size ceiling is the 14-bit _IOC_SIZE field on Linux, but
# __NV_IOWR_ASSERT also refuses any type over NV_PLATFORM_MAX_IOCTL_SIZE, and
# that constant is defined nowhere in the open modules. The size at which the
# user-mode driver actually switches to NV_ESC_IOCTL_XFER_CMD therefore cannot
# be derived from this tree; only the architectural ceiling below can.
PLATFORM_SIZE_LIMIT_NOTE = (
    "NV_PLATFORM_MAX_IOCTL_SIZE, the per-platform ceiling __NV_IOWR_ASSERT "
    "enforces, is not defined in the open modules. IOC_SIZE_MAX is the "
    "architectural limit; the real switchover to XFER may happen lower.")

# Escapes the user-mode driver reaches only through NV_ESC_IOCTL_XFER_CMD are
# still one dispatch case, so they are not a separate scheme. What XFER adds is
# an argument size above IOC_SIZE_MAX, recorded per command as xfer_only.
XFER_ESCAPE = "NV_ESC_IOCTL_XFER_CMD"

# /dev/nvidia-modeset is the opposite case to XFER above, and it is the same
# shape as an RM multiplexer. XFER gives each sub-command its own request
# number because its argument size differs. The modeset node gives its whole
# command set one number, because the envelope is a fixed 16 bytes whatever
# command travels in it. nvkms_ioctl() at NVKMS_DISPATCH_SOURCE compares
# _IOC_NR against NVKMS_IOCTL_CMD and _IOC_SIZE against sizeof(struct
# NvKmsIoctlParams), returns -ENOTTY for anything else, and passes params.cmd
# on as the command. Magic and direction are read by nothing there, exactly as
# on the RM path, so NVKMS_IOCTL_IOWR is the encoding the user-mode driver is
# expected to use and a trace showing another is a correction to make here.
#
# The number therefore resolves the family for triage and never the
# sub-command, because params.cmd sits in the payload and no ioctl trace
# carries it. That is F18, accepted as a permanent limitation of this branch.
# A triaged crash matched on this number is matched at family level only, and
# MODESET_DOC states that inside the artefact so a reader of the map cannot
# mistake it for a command-level match.
NVKMS_DISPATCH_SOURCE = (
    "kernel-open/nvidia-modeset/nvidia-modeset-linux.c:1981 (nvkms_ioctl)")
NVKMS_NODE = "/dev/nvidia-modeset"
NVKMS_ESCAPE = "NVKMS_IOCTL_CMD"
NVKMS_PARAM_STRUCT = "NvKmsIoctlParams"
NVKMS_SELECTOR_FIELD = "cmd"

# Fixed-width scalar types the modeset envelope declares, as (size, alignment)
# on x86-64. The set is small on purpose: a member of any other type raises,
# because sizing it would take a rule this table does not state and the whole
# request number is derived from the total.
NVKMS_SCALARS = {
    "NvU8": (1, 1), "NvS8": (1, 1), "NvBool": (1, 1),
    "NvU16": (2, 2), "NvS16": (2, 2),
    "NvU32": (4, 4), "NvS32": (4, 4),
    "NvU64": (8, 8), "NvS64": (8, 8),
}

RE_NVKMS_MAGIC = re.compile(r"^#define\s+NVKMS_IOCTL_MAGIC\s+'(.)'", re.M)
RE_NVKMS_CMD = re.compile(r"^#define\s+NVKMS_IOCTL_CMD\s+(\d+)\s*$", re.M)
RE_NVKMS_PARAMS = re.compile(
    r"struct\s+NvKmsIoctlParams\s*\{(?P<body>[^}]*)\}\s*;")
RE_NVKMS_MEMBER = re.compile(
    r"^\s*(?P<type>\w+)\s+(?P<name>\w+)"
    r"(?:\s+NV_ALIGN_BYTES\(\s*(?P<align>\d+)\s*\))?\s*;\s*$", re.M)

DEV_NVIDIA = ["/dev/nvidiactl", "/dev/nvidiaN"]
DEV_UVM = ["/dev/nvidia-uvm"]
DEV_UVM_TOOLS = ["/dev/nvidia-uvm-tools"]

RE_ESC_BASE = re.compile(
    r"^#define\s+(NV_ESC_\w+)\s+\(\s*NV_IOCTL_BASE\s*\+\s*(\d+)\s*\)", re.M)
RE_ESC_HEX = re.compile(r"^#define\s+(NV_ESC_\w+)\s+(0[xX][0-9A-Fa-f]+)\s*$", re.M)
RE_MAGIC = re.compile(r"^#define\s+NV_IOCTL_MAGIC\s+'(.)'", re.M)
RE_BASE = re.compile(r"^#define\s+NV_IOCTL_BASE\s+(\d+)", re.M)
RE_MAX_SIZE = re.compile(r"^#define\s+NV_ABSOLUTE_MAX_IOCTL_SIZE\s+(\d+)", re.M)
RE_NVIDIA_VERSION = re.compile(r"^NVIDIA_VERSION\s*=\s*(\S+)", re.M)

# Validation-table entries. The macro definition lines carry the placeholder
# names _cmd/_type, which cannot match NV_ESC_\w+, so they drop out here.
RE_RM_ESC_ENTRY = re.compile(
    r"_RM_ESC_IOCTL_ENTRY\(\s*(NV_ESC_\w+)\s*,\s*(\w+)\s*\)")
RE_RM_ENTRY = re.compile(r"_RM_IOCTL_ENTRY\(\s*(NV_ESC_\w+)\s*,\s*(\w+)\s*\)")
RE_NV_ENTRY = re.compile(
    r"_NV_IOCTL_ENTRY\(\s*(NV_ESC_\w+)\s*,\s*(\w+)\s*,\s*(NV_TRUE|NV_FALSE)\s*\)")
RE_ALLOC_SPECIAL = re.compile(
    r"size\s*==\s*sizeof\(\s*(\w+)\s*\)\s*\|\|\s*size\s*==\s*sizeof\(\s*(\w+)\s*\)")

RE_CASE = re.compile(r"^\s*case\s+(NV_ESC_\w+)\s*:")
RE_EARLY_CMP = re.compile(r"arg_cmd\s*==\s*(NV_ESC_\w+)")

# Node and privilege restrictions asserted inside a dispatch case body. These
# decide which device node a description attaches to and whether an
# unprivileged tenant reaches the handler at all, so a description authored
# without them wastes executions on a node that always rejects the call.
RE_CTL_ONLY = re.compile(r"\bNV_CTL_DEVICE_ONLY\s*\(")
RE_ACTUAL_ONLY = re.compile(r"\bNV_ACTUAL_DEVICE_ONLY\s*\(")
RE_ADMIN = re.compile(r"\bosIsAdministrator\s*\(\s*\)")

RE_UVM_DEFINE = re.compile(r"^#define\s+(UVM_\w+)\s+UVM_IOCTL_BASE\(\s*(\d+)\s*\)", re.M)
RE_UVM_TEST_DEFINE = re.compile(
    r"^#define\s+(UVM_TEST_\w+)\s+UVM_TEST_IOCTL_BASE\(\s*(\d+)\s*\)", re.M)
RE_UVM_LINUX_DEFINE = re.compile(r"^#define\s+(UVM_\w+)\s+(0[xX][0-9A-Fa-f]+)\s*$", re.M)
RE_UVM_TEST_BASE = re.compile(
    r"^#define\s+UVM_TEST_IOCTL_BASE\(i\)\s+UVM_IOCTL_BASE\(\s*(\d+)\s*\+\s*i\s*\)", re.M)
RE_UVM_ROUTE = re.compile(
    r"UVM_ROUTE_CMD_(STACK|ALLOC)_(NO_INIT_CHECK|INIT_CHECK)\("
    r"\s*(UVM_\w+)\s*,\s*(\w+)\s*\)")
RE_UVM_CASE = re.compile(r"^\s*case\s+(UVM_\w+)\s*:")
RE_UVM_STACK_LIMIT = re.compile(
    r"^#define\s+UVM_MAX_IOCTL_PARAM_STACK_SIZE\s+(\d+)", re.M)
RE_UVM_TEST_GATE = re.compile(r"if\s*\(\s*!\s*(uvm_enable_builtin_tests)\s*\)")


class InventoryError(Exception):
    """A fact the inventory needs is absent or unparseable in the source tree."""


def driver_version(src):
    """NVIDIA_VERSION from version.mk, so the output can be version-checked.

    Every escape number, parameter struct and measured size in the output
    belongs to one driver release. A record that does not name its release
    cannot be checked against the driver under test by
    tools/surface_verify.py, and a mismatch there is silent: the map parses,
    the descriptions compile, and the campaign measures the wrong driver.

    A missing version.mk is a warning and not a failure. The inventory is
    still correct for whatever tree was parsed; it just cannot be guarded.
    """
    path = os.path.join(src, VERSION_MK)
    if not os.path.isfile(path):
        logger.warning("no %s under %s, output will carry no version",
                       VERSION_MK, src)
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            m = RE_NVIDIA_VERSION.search(fh.read())
    except OSError as e:
        logger.warning("cannot read %s: %s, output will carry no version",
                       path, e)
        return None
    if not m:
        logger.warning("%s defines no NVIDIA_VERSION", path)
        return None
    logger.info("driver version %s from %s", m.group(1), path)
    return m.group(1)


def checkout_commit(src):
    """Short HEAD of the checkout, or None when it is not a git tree.

    Recorded alongside the version because a driver release is cut from many
    commits, and the artefacts have to name the exact tree they were parsed
    from when two runs of the same release disagree.
    """
    if not os.path.isdir(os.path.join(src, ".git")):
        return None
    try:
        out = subprocess.run(
            ["git", "-C", src, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning("git rev-parse failed for %s: %s", src, e)
        return None
    return out.stdout.strip() or None


def version_stamp(src):
    """The version string for the map, in the format `stamp` writes."""
    version = driver_version(src)
    if not version:
        return None
    commit = checkout_commit(src)
    return version + ((" (commit %s)" % commit) if commit else "")


def read_source(src, rel):
    """Return the text of one required source file.

    A missing or unreadable file is fatal: every caller below derives numbers
    that end up in fuzzer descriptions, and a silently skipped file yields an
    inventory that is short by a whole device node with nothing to say so.
    """
    path = os.path.join(src, rel)
    if not os.path.isfile(path):
        raise InventoryError(
            "required source file missing: %s (looked under --src %s; is this "
            "an open-gpu-kernel-modules checkout?)" % (rel, src))
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as e:
        raise InventoryError("cannot read %s: %s" % (path, e))


def line_of(text, offset):
    """1-based line number of a character offset, for file:line references."""
    return text.count("\n", 0, offset) + 1


def parse_escape_numbers(src):
    """Return {NV_ESC_* name: nr} from the three headers that define them.

    NV_IOCTL_BASE-relative numbers come from nv-ioctl-numbers.h and
    nv-ioctl-numa.h; the NV_ESC_RM_* set is written as bare hex in nv_escape.h.
    """
    numbers_text = read_source(src, ESCAPE_NUMBER_FILES[0])
    magic_m = RE_MAGIC.search(numbers_text)
    base_m = RE_BASE.search(numbers_text)
    if not magic_m or not base_m:
        raise InventoryError(
            "NV_IOCTL_MAGIC or NV_IOCTL_BASE not found in %s; the header "
            "changed shape and the request numbers below would be wrong"
            % ESCAPE_NUMBER_FILES[0])
    magic = ord(magic_m.group(1))
    base = int(base_m.group(1))
    logger.info("ioctl magic '%s' (0x%02x), base %d",
                magic_m.group(1), magic, base)

    numbers = {}
    origin = {}
    for rel in ESCAPE_NUMBER_FILES:
        text = read_source(src, rel)
        for m in RE_ESC_BASE.finditer(text):
            name, off = m.group(1), int(m.group(2))
            numbers[name] = base + off
            origin[name] = "%s:%d" % (rel, line_of(text, m.start()))
        for m in RE_ESC_HEX.finditer(text):
            name = m.group(1)
            numbers[name] = int(m.group(2), 16)
            origin[name] = "%s:%d" % (rel, line_of(text, m.start()))

    if not numbers:
        raise InventoryError(
            "no NV_ESC_* definitions parsed from %s" % ", ".join(ESCAPE_NUMBER_FILES))
    over = sorted(n for n, v in numbers.items() if v > 0xFF)
    if over:
        raise InventoryError(
            "NV_ESC_* number exceeds the 8-bit _IOC_NR field, which the "
            "driver masks with 0xFF: %s" % ", ".join(over))
    logger.info("parsed %d NV_ESC_* numbers", len(numbers))
    return magic, base, numbers, origin


def parse_validation_tables(src):
    """Return {NV_ESC_* name: record} from the three argument-size tables.

    The tables are the authoritative command-to-struct mapping: an escape that
    reaches a dispatch switch without an entry here is rejected before it ever
    gets there.
    """
    table = {}

    escape_text = read_source(src, ESCAPE_C)
    for m in RE_RM_ESC_ENTRY.finditer(escape_text):
        table[m.group(1)] = {
            "param_struct": m.group(2),
            "is_argument_array": False,
            "validation_site": "%s:%d" % (ESCAPE_C, line_of(escape_text, m.start())),
        }
    alloc_m = RE_ALLOC_SPECIAL.search(escape_text)
    if not alloc_m:
        raise InventoryError(
            "the NV_ESC_RM_ALLOC dual-size check was not found in %s; that "
            "escape takes either NVOS64_PARAMETERS or NVOS21_PARAMETERS and "
            "emitting one request number for it would miss half the traffic"
            % ESCAPE_C)
    table["NV_ESC_RM_ALLOC"] = {
        "param_struct": alloc_m.group(1),
        "param_struct_alt": alloc_m.group(2),
        "is_argument_array": False,
        "validation_site": "%s:%d" % (ESCAPE_C, line_of(escape_text, alloc_m.start())),
    }

    osapi_text = read_source(src, OSAPI_C)
    for m in RE_RM_ENTRY.finditer(osapi_text):
        table[m.group(1)] = {
            "param_struct": m.group(2),
            "is_argument_array": False,
            "validation_site": "%s:%d" % (OSAPI_C, line_of(osapi_text, m.start())),
        }

    nv_text = read_source(src, NV_C)
    for m in RE_NV_ENTRY.finditer(nv_text):
        table[m.group(1)] = {
            "param_struct": m.group(2),
            "is_argument_array": m.group(3) == "NV_TRUE",
            "validation_site": "%s:%d" % (NV_C, line_of(nv_text, m.start())),
        }

    if not table:
        raise InventoryError(
            "no validation-table entries parsed; the _RM_ESC_IOCTL_ENTRY / "
            "_RM_IOCTL_ENTRY / _NV_IOCTL_ENTRY macros changed shape")
    logger.info("parsed %d validation-table entries", len(table))
    return table


def strip_c_noise(text):
    """Blank out comments and literals, preserving line structure.

    Brace counting below has to see only real braces, and the block/line
    distinction cannot be made with two independent regexes: escape.c opens a
    banner with `//*****`, whose second and third characters are a valid `/*`
    that a block-comment pattern then runs to the next `*/` anywhere in the
    file. A single left-to-right scan gets it right, so this is a scanner.

    Every removed character becomes a space, so line numbering survives the
    pass unchanged, which the file:line references depend on.
    """
    out = []
    i = 0
    n = len(text)
    state = "code"
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "*":
                state = "block"
                out.append("  ")
                i += 2
                continue
            if c == "/" and nxt == "/":
                state = "line"
                out.append("  ")
                i += 2
                continue
            if c == '"':
                state = "string"
                out.append(" ")
                i += 1
                continue
            if c == "'":
                state = "char"
                out.append(" ")
                i += 1
                continue
            out.append(c)
            i += 1
            continue
        if state == "block":
            if c == "*" and nxt == "/":
                state = "code"
                out.append("  ")
                i += 2
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if state == "line":
            if c == "\n":
                state = "code"
                out.append("\n")
                i += 1
                continue
            out.append(" ")
            i += 1
            continue
        # string or char literal
        if c == "\\" and nxt:
            out.append("  ")
            i += 2
            continue
        if (state == "string" and c == '"') or (state == "char" and c == "'"):
            state = "code"
            out.append(" ")
            i += 1
            continue
        # An unterminated literal would otherwise run to the end of the
        # file. A newline closes it here, matching the C preprocessor's rule.
        if c == "\n":
            state = "code"
            out.append("\n")
            i += 1
            continue
        out.append(" ")
        i += 1
    return "".join(out)


def case_blocks(text):
    """Yield (label, line_index, unconditional_body, full_body) per case label.

    Brace depth separates a case in the escape switch from a case in a switch
    nested inside one of its bodies. NV_ESC_RM_ALLOC contains such a nested
    switch on hClass, and a line-only scan either truncates its body at the
    first inner label or attributes an inner assertion to the whole case.

    unconditional_body holds the lines sitting at the case body's own brace
    depth, so an assertion found there applies to every call of that command.
    full_body holds everything up to the next case at the same depth.
    """
    clean = strip_c_noise(text).splitlines()
    raw = text.splitlines()
    depths = []
    depth = 0
    for line in clean:
        depths.append(depth)
        depth += line.count("{") - line.count("}")

    labels = []
    for n, line in enumerate(clean):
        m = re.match(r"^\s*case\s+(\w+)\s*:", line)
        if m:
            labels.append((n, depths[n], m.group(1)))

    for i, (n, d, label) in enumerate(labels):
        end = len(raw)
        for n2, d2, _ in labels[i + 1:]:
            if d2 <= d:
                end = n2
                break
        # The body depth is one level in from the case label when the case
        # opens a block, and the label's own depth when it does not.
        body_depth = d
        for k in range(n + 1, end):
            if "{" in clean[k]:
                body_depth = d + 1
                break
            if clean[k].strip() not in ("", ):
                break
        uncond = [raw[k] for k in range(n, end) if depths[k] == body_depth]
        yield label, n + 1, "\n".join(uncond), "\n".join(raw[n:end])


def parse_case_restrictions(src):
    """Return {NV_ESC_* name: {node_restriction, requires_admin, ...}}.

    NV_CTL_DEVICE_ONLY and NV_ACTUAL_DEVICE_ONLY return early unless the fd is
    the right node, and osIsAdministrator() gates the handler on privilege.
    Both are recorded twice: once for the unconditional case body, and once for
    the whole case including nested blocks. An assertion that appears only in
    the nested form applies to some arguments and not others, which is a
    different instruction to the describe phase than a flat refusal.
    """
    out = {}
    for rel in (ESCAPE_C, OSAPI_C, NV_C):
        text = read_source(src, rel)
        for label, _, uncond, full in case_blocks(text):
            if not label.startswith("NV_ESC_") or label in out:
                continue

            def restriction(body):
                if RE_CTL_ONLY.search(body):
                    return "control_device_only"
                if RE_ACTUAL_ONLY.search(body):
                    return "actual_device_only"
                return None

            flat = restriction(uncond)
            nested = restriction(full)
            out[label] = {
                "node_restriction": flat,
                "node_restriction_conditional": (
                    nested if flat is None and nested is not None else None),
                "requires_admin": bool(RE_ADMIN.search(uncond)),
                "requires_admin_conditional": bool(
                    RE_ADMIN.search(full)) and not bool(RE_ADMIN.search(uncond)),
            }
    logger.info("parsed node/privilege restrictions for %d escapes", len(out))
    return out


def parse_rm_dispatch(src):
    """Return {NV_ESC_* name: 'file:line'} for every escape actually dispatched.

    Three switches handle the escapes, and nvidia_ioctl() also handles two
    before its switch: NV_ESC_IOCTL_XFER_CMD, which rewrites the command and
    size, and NV_ESC_WAIT_OPEN_COMPLETE, which answers without a GPU attached.
    An `if (arg_cmd == ...)` is as much a dispatch site as a case label, so
    both forms are collected.
    """
    sites = {}
    for rel in (ESCAPE_C, OSAPI_C, NV_C):
        text = read_source(src, rel)
        for n, line in enumerate(text.splitlines(), start=1):
            m = RE_CASE.match(line)
            if m:
                sites.setdefault(m.group(1), "%s:%d" % (rel, n))

    nv_text = read_source(src, NV_C)
    for n, line in enumerate(nv_text.splitlines(), start=1):
        m = RE_EARLY_CMP.search(line)
        if m:
            sites.setdefault(m.group(1), "%s:%d" % (NV_C, n))

    if not sites:
        raise InventoryError("no NV_ESC_* dispatch sites found in %s, %s, %s"
                             % (ESCAPE_C, OSAPI_C, NV_C))
    logger.info("parsed %d NV_ESC_* dispatch sites", len(sites))
    return sites


def parse_uvm_numbers(src):
    """Return {UVM_* name: (number, 'file:line')} across the three UVM headers.

    UVM_IOCTL_BASE(i) expands to i on Linux, so these numbers are already the
    request numbers. UVM_INITIALIZE and UVM_DEINITIALIZE sit outside that
    scheme in uvm_linux_ioctl.h with values above 0x30000000.
    """
    numbers = {}

    text = read_source(src, UVM_IOCTL_H)
    if "#   define UVM_IOCTL_BASE(i) i" not in text:
        raise InventoryError(
            "the Linux UVM_IOCTL_BASE(i) -> i definition was not found in %s; "
            "UVM request numbers are that identity and would be wrong without it"
            % UVM_IOCTL_H)
    for m in RE_UVM_DEFINE.finditer(text):
        numbers[m.group(1)] = (int(m.group(2)),
                               "%s:%d" % (UVM_IOCTL_H, line_of(text, m.start())))

    linux_text = read_source(src, UVM_LINUX_IOCTL_H)
    for m in RE_UVM_LINUX_DEFINE.finditer(linux_text):
        numbers[m.group(1)] = (int(m.group(2), 16),
                               "%s:%d" % (UVM_LINUX_IOCTL_H,
                                          line_of(linux_text, m.start())))

    test_text = read_source(src, UVM_TEST_IOCTL_H)
    base_m = RE_UVM_TEST_BASE.search(test_text)
    if not base_m:
        raise InventoryError(
            "UVM_TEST_IOCTL_BASE was not found in %s" % UVM_TEST_IOCTL_H)
    test_base = int(base_m.group(1))
    for m in RE_UVM_TEST_DEFINE.finditer(test_text):
        numbers[m.group(1)] = (test_base + int(m.group(2)),
                               "%s:%d" % (UVM_TEST_IOCTL_H,
                                          line_of(test_text, m.start())))

    if not numbers:
        raise InventoryError("no UVM_* command numbers parsed")
    logger.info("parsed %d UVM_* command numbers (test base %d)",
                len(numbers), test_base)
    return numbers


def parse_uvm_dispatch(src, rel, known):
    """Return {UVM_* name: record} for one UVM dispatch switch.

    UVM_ROUTE_CMD_* takes the command name and derives the parameter type by
    pasting _PARAMS onto it, so the struct name follows from the command name
    and never appears in the switch. The STACK and ALLOC variants differ only
    in where the copy lands, which UVM_MAX_IOCTL_PARAM_STACK_SIZE decides.
    """
    text = read_source(src, rel)
    out = {}
    for m in RE_UVM_ROUTE.finditer(text):
        storage, init_check, cmd, handler = m.groups()
        out[cmd] = {
            "param_struct": cmd + "_PARAMS",
            "handler": handler,
            "copy_storage": storage.lower(),
            "requires_initialized_fd": init_check == "INIT_CHECK",
            "dispatch_site": "%s:%d" % (rel, line_of(text, m.start())),
        }
    for n, line in enumerate(text.splitlines(), start=1):
        m = RE_UVM_CASE.match(line)
        # These files switch on UVM_* enumerators unrelated to ioctls
        # (uvm_fd_type_t, uvm_va_space_mm_state_t). Requiring the label to be
        # a command number defined in the ioctl headers keeps those out.
        if m and m.group(1) in known and m.group(1) not in out:
            # A bare case label with no UVM_ROUTE_CMD_* wrapper takes no
            # parameter struct at all. UVM_DEINITIALIZE has this form and
            # returns 0 without touching arg.
            out[m.group(1)] = {
                "param_struct": None,
                "handler": None,
                "copy_storage": "none",
                "requires_initialized_fd": False,
                "dispatch_site": "%s:%d" % (rel, n),
            }
    logger.info("parsed %d UVM dispatch entries from %s", len(out), rel)
    return out


def rm_request(magic, nr, size):
    """Linux ioctl request number, matching tools/trace2seed.py's decoder."""
    return (DIRECTION_BITS << 30) | (size << 16) | (magic << 8) | nr


def build_rm_commands(src, magic, numbers, origin, table, sites, sizes,
                      restrictions):
    """Join numbers, validation entries, dispatch sites and measured sizes."""
    commands = []
    for name in sorted(sites, key=lambda n: numbers.get(n, 0)):
        if name not in numbers:
            raise InventoryError(
                "%s is dispatched at %s but no header defines its number"
                % (name, sites[name]))
        entry = table.get(name, {})
        struct = entry.get("param_struct")
        size = sizes.get(struct) if struct else None
        rec = {
            "name": name,
            "nr": numbers[name],
            "defined_at": origin[name],
            "dispatch_site": sites[name],
            "validation_site": entry.get("validation_site"),
            "param_struct": struct,
            "param_size": size,
            "is_argument_array": bool(entry.get("is_argument_array")),
            # Absent from `restrictions` means the escape has no case body to
            # scan, which is a different fact from a case body that asserts
            # nothing. NV_ESC_IOCTL_XFER_CMD and NV_ESC_WAIT_OPEN_COMPLETE are
            # handled by an `if` ahead of the switch and land here.
            "restriction_source": ("case_body" if name in restrictions
                                   else "no_case_body"),
            "node_restriction": restrictions.get(name, {}).get("node_restriction"),
            "node_restriction_conditional": restrictions.get(name, {}).get(
                "node_restriction_conditional"),
            "requires_admin": restrictions.get(name, {}).get("requires_admin", False),
            "requires_admin_conditional": restrictions.get(name, {}).get(
                "requires_admin_conditional", False),
            "syzlang": "ioctl$" + name,
        }
        if entry.get("param_struct_alt"):
            alt = entry["param_struct_alt"]
            rec["param_struct_alt"] = alt
            rec["param_size_alt"] = sizes.get(alt)

        requests = []
        if rec["is_argument_array"]:
            # arg_size is validated as a nonzero multiple of paramSize, so the
            # request number carries an element count and no single value
            # represents the command. The one-element form is the smallest
            # legal request and the only one a fixed map key can name.
            if size:
                rec["request_one_element"] = hex(rm_request(magic, rec["nr"], size))
                rec["max_direct_elements"] = IOC_SIZE_MAX // size
        elif size is not None:
            requests.append(rm_request(magic, rec["nr"], size))
        if rec.get("param_size_alt") is not None:
            requests.append(rm_request(magic, rec["nr"], rec["param_size_alt"]))
        rec["requests"] = [hex(v) for v in requests]

        sizes_needed = [s for s in (size, rec.get("param_size_alt")) if s is not None]
        rec["xfer_only"] = bool(sizes_needed) and min(sizes_needed) > IOC_SIZE_MAX
        rec["size_source"] = "measured" if sizes_needed else "unresolved"
        if struct is None:
            rec["size_source"] = "no_parameter_struct"
        commands.append(rec)
    return commands


def build_uvm_commands(numbers, dispatch, sizes, gated_by=None):
    """UVM request numbers are the bare command numbers, so no encoding runs."""
    commands = []
    for name in sorted(dispatch, key=lambda n: numbers.get(n, (0, ""))[0]):
        if name not in numbers:
            raise InventoryError(
                "%s is dispatched at %s but no UVM header defines its number"
                % (name, dispatch[name]["dispatch_site"]))
        nr, defined_at = numbers[name]
        rec = dict(dispatch[name])
        struct = rec["param_struct"]
        size = sizes.get(struct) if struct else None
        rec.update({
            "name": name,
            "nr": nr,
            "defined_at": defined_at,
            "param_size": size,
            "is_argument_array": False,
            "xfer_only": False,
            "requests": [hex(nr)],
            "syzlang": "ioctl$" + name,
            "size_source": ("no_parameter_struct" if struct is None
                            else "measured" if size is not None else "unresolved"),
        })
        if gated_by:
            rec["reachable"] = False
            rec["reachability_gate"] = gated_by
        else:
            rec["reachable"] = True
        commands.append(rec)
    return commands


def check_uvm_storage(commands, stack_limit):
    """Cross-check every UVM command against the BUILD_BUG_ON in its macro.

    __UVM_ROUTE_CMD_STACK asserts sizeof(params) <= UVM_MAX_IOCTL_PARAM_STACK_SIZE
    and __UVM_ROUTE_CMD_ALLOC asserts the opposite, so a measured size on the
    wrong side of that limit means the parameter struct paired with the command
    here is not the one the driver compiles against.
    """
    wrong = []
    for c in commands:
        size = c.get("param_size")
        if size is None:
            continue
        if c["copy_storage"] == "stack" and size > stack_limit:
            wrong.append("%s: %s is %d bytes, over the %d-byte stack limit, "
                         "but is routed with UVM_ROUTE_CMD_STACK_*"
                         % (c["name"], c["param_struct"], size, stack_limit))
        elif c["copy_storage"] == "alloc" and size <= stack_limit:
            wrong.append("%s: %s is %d bytes, within the %d-byte stack limit, "
                         "but is routed with UVM_ROUTE_CMD_ALLOC_*"
                         % (c["name"], c["param_struct"], size, stack_limit))
    if wrong:
        raise InventoryError(
            "measured UVM parameter sizes contradict the driver's own "
            "BUILD_BUG_ON, so the command-to-struct pairing is wrong:\n  - %s"
            % "\n  - ".join(wrong))
    logger.info("UVM stack/alloc storage agrees with measured sizes for %d "
                "commands", len(commands))


def find_dead_escapes(numbers, sites):
    """NV_ESC_* names defined in a header that no switch and no table mentions.

    Declared and unreachable is a different thing from undocumented, and it
    decides whether a description for that escape is worth authoring.
    """
    return sorted(n for n in numbers if n not in sites)


def collect_structs(rm_commands, uvm_groups):
    """Every parameter type whose size the inventory needs, split by probe."""
    rm = set()
    for c in rm_commands:
        if c["param_struct"]:
            rm.add(c["param_struct"])
        if c.get("param_struct_alt"):
            rm.add(c["param_struct_alt"])
    uvm = set()
    for group in uvm_groups:
        for c in group:
            if c["param_struct"]:
                uvm.add(c["param_struct"])
    return sorted(rm), sorted(uvm)


PROBE_MAIN = """/* Generated by tools/ioctl_inventory.py --emit-probe. Do not edit.
 * Prints one "<struct> <sizeof>" line per parameter type so the inventory
 * carries measured sizes and never hand-counted ones. */
#include <stdio.h>
%(includes)s

int main(void)
{
%(lines)s
    return 0;
}
"""

PROBE_RUNNER = """#!/bin/sh
# Generated by tools/ioctl_inventory.py --emit-probe. Do not edit.
# Compiles and runs the size probes for x86-64 and writes %(out)s.
#
# Run it from the same working directory the inventory tool was run from, or
# pass the open-gpu-kernel-modules path as the first argument. The path is
# stored relative on purpose: --emit-probe may run on one machine (Windows)
# and this script on another (WSL, the SUT), where an absolute path from the
# first would not resolve.
set -e
SRC="${1:-%(src)s}"
if [ ! -d "$SRC/kernel-open" ]; then
    echo "not an open-gpu-kernel-modules tree: $SRC" >&2
    echo "usage: $0 [path-to-open-gpu-kernel-modules]" >&2
    exit 2
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
CC="${CC:-gcc}"

run_probe() {
    name="$1"; shift
    if "$CC" -m64 -o "$HERE/$name" "$HERE/$name.c" "$@" 2> "$HERE/$name.err"; then
        "$HERE/$name"
    else
        echo "probe $name failed to compile; see $HERE/$name.err" >&2
        return 1
    fi
}

: > "$HERE/sizes.txt"
run_probe probe_rm %(inc_rm)s >> "$HERE/sizes.txt"
run_probe probe_uvm %(inc_uvm)s >> "$HERE/sizes.txt"

python3 - "$HERE/sizes.txt" > "$HERE/%(out)s" <<'PY'
import json, sys
sizes = {}
with open(sys.argv[1]) as f:
    for line in f:
        parts = line.split()
        if len(parts) == 2:
            sizes[parts[0]] = int(parts[1])
json.dump(sizes, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\\n")
PY
echo "wrote $HERE/%(out)s ($(grep -c . "$HERE/sizes.txt") sizes)" >&2
"""

SIZES_FILENAME = "sizes.json"


def emit_probe(src, out_dir, rm_structs, uvm_structs):
    """Write the C size probes and their runner into out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name, includes, structs in (
            ("probe_rm", ['#include <nv-ioctl.h>',
                          '#include <nvos.h>',
                          '#include <nv-unix-nvos-params-wrappers.h>',
                          '#include <nv-ioctl-lockless-diag.h>'], rm_structs),
            ("probe_uvm", ['#include "uvm_linux_ioctl.h"',
                           '#include "uvm_test_ioctl.h"'], uvm_structs)):
        lines = "\n".join(
            '    printf("%s %%zu\\n", sizeof(%s));' % (s, s) for s in structs)
        path = os.path.join(out_dir, name + ".c")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(PROBE_MAIN % {"includes": "\n".join(includes), "lines": lines})
        written.append(path)
        logger.info("wrote %s (%d structs)", path, len(structs))

    def inc(dirs):
        return " ".join('"-I$SRC/%s"' % d for d in dirs)

    runner = os.path.join(out_dir, "measure_sizes.sh")
    with open(runner, "w", encoding="utf-8", newline="\n") as f:
        f.write(PROBE_RUNNER % {
            # Stored as given, not resolved: see the runner's own comment.
            "src": src.replace("\\", "/"),
            "inc_rm": inc(PROBE_INCLUDES_RM),
            "inc_uvm": inc(PROBE_INCLUDES_UVM),
            "out": SIZES_FILENAME,
        })
    os.chmod(runner, 0o755)
    written.append(runner)
    logger.info("wrote %s", runner)
    return written


MAP_COMMENTS = {
    "comment": (
        "Generated by tools/ioctl_inventory.py --emit-map from an "
        "open-gpu-kernel-modules checkout. Keys are ioctl request numbers "
        "formatted as tools/trace2seed.py formats them, hex(value) "
        "lowercase, and values are syzlang description names. Every number "
        "here is a sizeof() measured by compiling the driver headers, and a "
        "driver-branch change moves them. Regenerate this file after such a "
        "change. Hand-editing it reintroduces the error class the placeholder "
        "carried."),
    "comment_direction": (
        "RM escape keys carry _IOC_READ|_IOC_WRITE, from __NV_IOWR at "
        "kernel-open/common/inc/nv.h:84, which expands to "
        "_IOWR(NV_IOCTL_MAGIC, nr, type). The kernel itself reads only "
        "_IOC_NR and _IOC_SIZE, so nothing enforces the direction bits and "
        "an RM escape showing up unmapped in a trace should be checked "
        "against this first."),
    "comment_arrays": (
        "NV_ESC_CARD_INFO and NV_ESC_ATTACH_GPUS_TO_FD take argument arrays: "
        "the driver accepts any nonzero multiple of the element size, so the "
        "request number carries an element count and no fixed key covers the "
        "command. The keys below are the one-element form. A trace using more "
        "elements reports the command as unmapped, which is a trace2seed "
        "limitation and not a gap in this map."),
    "comment_uvm": (
        "UVM keys are bare command numbers, not _IOC-encoded: uvm.c switches "
        "on the raw cmd and UVM_IOCTL_BASE(i) expands to i on Linux. They are "
        "small integers, so they are matched on any nvidia fd trace2seed "
        "tracks, including /dev/nvidiactl where they mean nothing."),
    "comment_excluded": (
        "The UVM_TEST_* commands are omitted. uvm_test_ioctl() refuses every "
        "one of them unless the module is loaded with "
        "uvm_enable_builtin_tests=1. Their numbers are in the inventory JSON "
        "if a build turns them on."),
}

MULTIPLEXER_DOC = (
    "NV_ESC_RM_CONTROL and NV_ESC_RM_ALLOC dispatch on a field inside the "
    "parameter struct, so their request numbers name a dispatcher and not a "
    "command. The describe phase emits one syzlang variant per leaf, 531 "
    "control commands and 155 allocation classes, and no single call name "
    "covers the request number. Naming the bare escape here produced seeds "
    "calling a syscall no description declares. strace cannot decode the "
    "parameter struct, so the selector field never appears in a trace and no "
    "entry in the name map above can recover it. tools/trace2seed.py reads "
    "this section to write an honest comment for a traced multiplexer call, "
    "and its `chains` subcommand builds the command-targeted programs from "
    "surface/rm-chains.json instead.")


def build_map(inventory, stamp=None, modeset=None):
    """Return the trace2seed request-number map for this inventory.

    Commands whose size did not resolve are left out: a key that names the
    wrong request number silently converts one ioctl into a description for
    another, which is worse than the unmapped count that omitting it produces.

    The two multiplexers in MULTIPLEXER_SELECTOR are left out of the name map
    for the same reason and recorded under MAP_MULTIPLEXER_KEY instead. Their
    request numbers carry 686 of the 764 targets between them and dominate a
    real CUDA trace, and the name the escape used to carry is declared by no
    description.

    `modeset` is nvkms_request()'s section, or None where it was not derived.
    It records the one request number /dev/nvidia-modeset accepts, and it goes
    under MAP_MODESET_KEY for the same reason again: the number covers the
    whole modeset command set and no call name resolves it.
    """
    out = dict(MAP_COMMENTS)
    multiplexers = {}
    if stamp:
        out[MAP_VERSION_KEY] = stamp
    else:
        logger.warning(
            "no driver version available, so the map carries no %s and "
            "tools/surface_verify.py cannot check it", MAP_VERSION_KEY)
    collisions = []
    skipped = []
    for node in inventory["nodes"]:
        if node.get("reachability_gate"):
            skipped.extend(c["name"] for c in node["commands"])
            continue
        for c in node["commands"]:
            keys = list(c.get("requests") or [])
            if c["is_argument_array"] and c.get("request_one_element"):
                keys = [c["request_one_element"]]
            if not keys:
                skipped.append(c["name"])
                continue
            if c["name"] in MULTIPLEXER_SELECTOR:
                multiplexers.update(multiplexer_entries(c, keys))
                continue
            for k in keys:
                if k in out and out[k] != c["syzlang"]:
                    collisions.append("%s and %s both claim %s"
                                      % (out[k], c["syzlang"], k))
                out[k] = c["syzlang"]
    if collisions:
        raise InventoryError(
            "two commands resolve to the same request number, so the map "
            "cannot represent both:\n  - %s" % "\n  - ".join(collisions))
    if multiplexers:
        out[MAP_MULTIPLEXER_KEY] = {"doc": MULTIPLEXER_DOC,
                                    "requests": multiplexers}
    if modeset:
        out[MAP_MODESET_KEY] = modeset
    logger.info("map covers %d request numbers, %d multiplexer request "
                "numbers; %d commands omitted (%s)",
                sum(1 for k in out if not k.startswith("comment")),
                len(multiplexers), len(skipped), "gated or size unresolved")
    # Every comment key first, then the request numbers, whatever order the
    # keys were added in. The multiplexer and modeset sections are only known
    # after the loop above, so insertion order alone would append them below
    # the numbers and every regeneration would move forty lines of a
    # generated file around the one line that actually changed.
    comments = [k for k in out if k.startswith("comment")]
    numbers = [k for k in out if not k.startswith("comment")]
    return {k: out[k] for k in comments + numbers}, skipped


def multiplexer_entries(command, keys):
    """-> {request number: multiplexer record} for one dispatching escape.

    Every request number a multiplexer carries gets a record naming the
    parameter struct that request number's size came from, so a reader can tell
    the 48-byte NVOS64 allocation form from the 32-byte NVOS21 one. The size
    field is read back out of the request number rather than taken from the
    order of `requests`, so a change to how that list is assembled cannot
    silently pair a number with the wrong struct.
    """
    if command.get("param_size") is None or not command.get("param_struct"):
        raise InventoryError(
            "%s dispatches on a field inside its parameter struct, so the map "
            "records the struct instead of a call name, and this inventory "
            "record carries no param_struct/param_size pair to record. The "
            "request numbers %s were built from a measured size, so a record "
            "that has them and not the size it was measured from is "
            "malformed." % (command["name"], ", ".join(keys)))
    by_size = {command["param_size"]: command["param_struct"]}
    if command.get("param_size_alt") is not None:
        by_size[command["param_size_alt"]] = command["param_struct_alt"]
    out = {}
    for key in keys:
        size = (int(key, 0) >> 16) & 0x3FFF
        struct = by_size.get(size)
        if struct is None:
            raise InventoryError(
                "%s request number %s encodes size %d, which matches neither "
                "its parameter struct %s (%s bytes) nor its alternate form"
                % (command["name"], key, size, command["param_struct"],
                   command["param_size"]))
        out[key] = {
            "escape": command["name"],
            "param_struct": struct,
            "selector_field": MULTIPLEXER_SELECTOR[command["name"]],
            "variant_prefix": command["syzlang"] + "_",
        }
    return out


MODESET_DOC = (
    "/dev/nvidia-modeset accepts one kernel ioctl request number for its "
    "whole command set. nvkms_ioctl() refuses any other _IOC_NR or _IOC_SIZE "
    "with -ENOTTY, and the command itself is NvKmsIoctlParams.cmd, read after "
    "copy_from_user. The number below resolves the family for triage and "
    "never the sub-command, because the selector sits in the payload and no "
    "ioctl trace carries it. That is F18, accepted as a permanent limitation "
    "of this branch: a crash or a traced call matched on this number is "
    "matched at family level, and taking it for a command-level match is an "
    "error. tools/nvkms_inventory.py enumerates the commands behind it. No "
    "single call name covers the number, so it is recorded here and never in "
    "the name map above, where trace2seed and regression_check would read it "
    "as a description name.")


def nvkms_struct_size(body, where):
    """-> sizeof the modeset envelope, from its own member declarations.

    Sizes elsewhere in this tool are measured by compiling the header, and
    that route needs the RM and UVM header set on the include path. The
    modeset envelope declares fixed-width scalars and one alignment
    attribute, so the declaration states its layout in full. A member of any
    type NVKMS_SCALARS does not carry raises, so a driver branch that puts a
    union or a nested struct in the envelope stops the run and never produces
    a request number built on an assumed width. The measured JSON still wins
    where it carries this struct; see nvkms_request().
    """
    members = list(RE_NVKMS_MEMBER.finditer(body))
    if not members:
        raise InventoryError(
            "%s declares struct %s with no member this parser recognises, so "
            "its size cannot be derived and neither can the one request "
            "number %s accepts" % (where, NVKMS_PARAM_STRUCT, NVKMS_NODE))
    offset, widest = 0, 1
    for member in members:
        kind = member.group("type")
        if kind not in NVKMS_SCALARS:
            raise InventoryError(
                "%s declares %s.%s as %s, which is not one of the "
                "fixed-width scalars this parser sizes (%s). The request "
                "number is derived from sizeof(%s), and no size is ever "
                "guessed to fill a row."
                % (where, NVKMS_PARAM_STRUCT, member.group("name"), kind,
                   ", ".join(sorted(NVKMS_SCALARS)), NVKMS_PARAM_STRUCT))
        width, align = NVKMS_SCALARS[kind]
        forced = member.group("align")
        if forced:
            align = max(align, int(forced))
        offset = -(-offset // align) * align + width
        widest = max(widest, align)
    return -(-offset // widest) * widest


def nvkms_request(src, sizes=None):
    """-> the modeset section of the map, derived from the driver headers.

    Both copies of nvkms-ioctl.h are read and required to agree, because a
    tree where they differ carries two request numbers for one node and the
    map holds one.

    `sizes` cross-checks the derived envelope size wherever the measured JSON
    carries this struct. A disagreement raises: one of the two readings is
    then wrong, and the request number is built from the size.
    """
    readings = {}
    for relative in (NVKMS_IOCTL_H, NVKMS_IOCTL_H_INTERFACE):
        path = os.path.join(src, *relative.split("/"))
        if not os.path.isfile(path):
            raise InventoryError(
                "the modeset envelope header is missing from --src: %s. "
                "--emit-map records the one request number %s accepts, and "
                "that number is derived from this file."
                % (relative, NVKMS_NODE))
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        magic = RE_NVKMS_MAGIC.search(text)
        number = RE_NVKMS_CMD.search(text)
        params = RE_NVKMS_PARAMS.search(text)
        absent = [name for name, found in
                  (("NVKMS_IOCTL_MAGIC", magic), ("NVKMS_IOCTL_CMD", number),
                   ("struct " + NVKMS_PARAM_STRUCT, params)) if not found]
        if absent:
            raise InventoryError(
                "%s does not declare %s, so the request number %s accepts "
                "cannot be derived from it"
                % (relative, ", ".join(absent), NVKMS_NODE))
        readings[relative] = (magic.group(1), int(number.group(1)),
                              nvkms_struct_size(params.group("body"), relative))
    kernel, published = readings[NVKMS_IOCTL_H], readings[NVKMS_IOCTL_H_INTERFACE]
    if kernel != published:
        raise InventoryError(
            "the two copies of nvkms-ioctl.h disagree, so this checkout "
            "carries two request numbers for one node and the map holds one: "
            "%s gives magic %r, nr %d, %d-byte envelope; %s gives magic %r, "
            "nr %d, %d-byte envelope"
            % ((NVKMS_IOCTL_H,) + kernel + (NVKMS_IOCTL_H_INTERFACE,)
               + published))
    magic, number, size = kernel
    measured = (sizes or {}).get(NVKMS_PARAM_STRUCT)
    if measured is not None and measured != size:
        raise InventoryError(
            "the measured sizes give %s %d bytes and %s declares a %d-byte "
            "layout. The request number is derived from the size, so the two "
            "readings have to agree before either is written."
            % (NVKMS_PARAM_STRUCT, measured, NVKMS_IOCTL_H, size))
    if size > IOC_SIZE_MAX:
        raise InventoryError(
            "%s declares a %d-byte %s, above the %d-byte ceiling the 14-bit "
            "_IOC_SIZE field can carry, so no direct request number encodes "
            "it" % (NVKMS_IOCTL_H, size, NVKMS_PARAM_STRUCT, IOC_SIZE_MAX))
    # The same encoder the RM escapes use. NVKMS_IOCTL_IOWR is _IOWR like
    # __NV_IOWR, and a second copy of the formula here is the error class the
    # numbering-scheme note at the top of this module exists to prevent.
    request = hex(rm_request(ord(magic), number, size))
    logger.info("modeset: %s = _IOWR('%s', %d, %d-byte %s) for %s",
                request, magic, number, size, NVKMS_PARAM_STRUCT, NVKMS_NODE)
    return {
        "doc": MODESET_DOC,
        "requests": {request: {
            "node": NVKMS_NODE,
            "escape": NVKMS_ESCAPE,
            "param_struct": NVKMS_PARAM_STRUCT,
            "param_size": size,
            "selector_field": NVKMS_SELECTOR_FIELD,
            "magic": magic,
            "nr": number,
            "resolves": "family",
            "source": NVKMS_IOCTL_H,
            "dispatch_source": NVKMS_DISPATCH_SOURCE,
        }},
    }


def refuse_size_regression(out_path, inventory):
    """Refuse to replace a fully measured inventory with a less measured one.

    Every request number is derived from a measured struct size, so an
    inventory built without --sizes parses, validates and writes cleanly while
    carrying no request numbers at all. Downstream that is silent: syzlang_gen
    emits fewer variants, surface_cov reports a smaller surface, and nothing
    names the cause. The committed artefact is the only record of those
    measurements, so overwriting it with an unmeasured build destroys them.
    """
    if not os.path.isfile(out_path):
        return
    try:
        with open(out_path, encoding="utf-8") as fh:
            existing = json.load(fh)
    except (OSError, ValueError) as exc:
        logger.warning("could not read the existing inventory at %s: %s",
                       out_path, exc)
        return
    was = existing.get("counts", {}).get("sizes_measured", 0)
    now = inventory["counts"]["sizes_measured"]
    if now >= was:
        return
    raise InventoryError(
        "refusing to overwrite %s: it records %d measured struct size(s) and "
        "this run measured %d. Request numbers are derived from those sizes, "
        "so writing this build would drop %d of them and every consumer would "
        "report a smaller surface without saying why. Pass --sizes pointing "
        "at the measured sizes, or --out pointing somewhere else."
        % (out_path, was, now, was - now))


def load_sizes(path):
    """Read the measured sizes JSON, rejecting anything that is not a size."""
    if path is None:
        logger.warning("no --sizes given; every request number will be omitted "
                       "and every command reported as unresolved")
        return {}
    if not os.path.isfile(path):
        raise InventoryError(
            "sizes file not found: %s (run the runner that --emit-probe writes, "
            "then pass its %s here)" % (path, SIZES_FILENAME))
    with open(path, encoding="utf-8") as f:
        try:
            raw = json.load(f)
        except ValueError as e:
            raise InventoryError("%s is not valid JSON: %s" % (path, e))
    if not isinstance(raw, dict):
        raise InventoryError(
            "%s must hold a JSON object mapping struct name to size, got %s"
            % (path, type(raw).__name__))
    sizes = {}
    for name, value in raw.items():
        if name.startswith("comment"):
            continue
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise InventoryError(
                "%s: size for %s must be a positive integer, got %r"
                % (path, name, value))
        sizes[name] = value
    logger.info("loaded %d measured struct sizes from %s", len(sizes), path)
    return sizes


# ---------------------------------------------------------------------------
# Entry points: the file_operations tables the driver registers
# ---------------------------------------------------------------------------

ENTRY_POINTS_SCHEMA = "gspwn.entry-points/1"

# One `.member = symbol,` inside a file_operations initialiser.
RE_FOPS_MEMBER = re.compile(r"^\s*\.\s*(\w+)\s*=\s*([A-Za-z_]\w*)\s*,?\s*$")

# `.owner = THIS_MODULE` names the module holding a reference on the table and
# dispatches no call, so it is not an entry point. `.fop_flags` is an unsigned
# bitmask the VFS reads, added in 6.12 and set to FOP_UNSIGNED_OFFSET by
# nv_drm_fops, and it carries no function pointer either.
FOPS_NON_ENTRY = frozenset(["owner", "fop_flags"])

NVLINK_C = "kernel-open/nvidia/nvlink_linux.c"
NVSWITCH_C = "kernel-open/nvidia/linux_nvswitch.c"
NV_CAPS_C = "kernel-open/nvidia/nv-caps.c"
NV_CAPS_IMEX_C = "kernel-open/nvidia/nv-caps-imex.c"
NVKMS_C = "kernel-open/nvidia-modeset/nvidia-modeset-linux.c"
NV_DRM_C = "kernel-open/nvidia-drm/nvidia-drm-drv.c"

# The container's own device set. lookup_devices creates exactly nvidiactl,
# nvidia-uvm, nvidia-uvm-tools and nvidia-modeset, and the per-GPU
# /dev/nvidiaN nodes alongside them. A node absent from that function is
# absent from a default container and therefore outside the tenant surface.
TENANT_DEVICE_SOURCE = "libnvidia-container/src/nvc_info.c:515"

OUTSIDE_TENANT_SURFACE = (
    "lookup_devices at %s creates /dev/nvidiactl, /dev/nvidia-uvm, "
    "/dev/nvidia-uvm-tools and /dev/nvidia-modeset only, so a default "
    "container carries no node served by this table." % TENANT_DEVICE_SOURCE)

# Device node to file_operations table. The binding is declared here and every
# table named is read from source: a table this list names and the checkout
# does not define is fatal. The binding itself is not derivable statically,
# because the driver joins a table to a node through cdev_init and
# register_chrdev at module init and no node path appears in either call.
#
# `modelled` is true for the nodes descriptions/nvidia.txt opens.
# `tenant_surface` records whether the node exists inside a default container.
# The two are independent, and they are independent per entry point:
# /dev/nvidia-modeset is inside the tenant surface and its commands are
# modelled, while the mmap and poll this table registers are not, so it is
# recorded here as unmodelled and its `reason` says which half is which.
# /dev/dri reaches a default tenant on the CDI injection path, and the
# campaign does not model its command surface. Both halves are stated here
# because the pair is the finding: reachable surface that no description
# covers is surface every coverage figure is measured against wrongly.
#
# The CDI path adds every DRM node found for a GPU's PCI bus id to that
# device's spec, with no capability argument anywhere on the call chain:
# nvidia-container-toolkit/internal/platform-support/dgpu/nvml.go:48 calls
# drm.GetDeviceNodesByBusID, :53 appends the result beside the nvidia node
# and :55 makes char device discoverers of all of them. The only capability
# check for DRM nodes, internal/modifier/graphics.go:71, sits behind the
# "graphics" modifier, and internal/modifier/mode.go:26 omits that modifier
# from both CDI modes, so internal/modifier/factory.go:117 is unreachable
# there. internal/edits/device.go:76 grants the injected nodes rwm.
#
# The nodes exist whenever nvidia-drm registers a device, which it does for
# every GPU nvidia-modeset enumerates
# (kernel-open/nvidia-drm/nvidia-drm-drv.c:2176). The modeset module
# parameter that upgrades the driver past PRIME-only defaults to true at
# kernel-open/nvidia-drm/nvidia-drm-os-interface.c:45, and registration at
# :2079 does not depend on it.
#
# 24 driver ioctls are declared in nv_drm_ioctls[] at
# kernel-open/nvidia-drm/nvidia-drm-drv.c:1806. 21 carry DRM_RENDER_ALLOW
# and are reachable on a render node by a client holding no master, 2 carry
# DRM_MASTER, and NVIDIA_GET_CLIENT_CAPABILITY carries neither.
#
# Whether one host actually presents the nodes is a measurement, not a
# reading: tools/verify_tenant_surface.py takes it, and agents/provision.md
# runs it before a campaign spends anything.
DRM_TENANT_SURFACE = (
    "the CDI injection path adds every /dev/dri node found for the GPU's PCI "
    "bus id to that device's spec with no capability check, at "
    "nvidia-container-toolkit/internal/platform-support/dgpu/nvml.go:48-55, "
    "and internal/edits/device.go:76 grants them rwm. The legacy path never "
    "injects them: libnvidia-container carries no reference to /dev/dri. "
    "nvidia-drm registers a device for every GPU nvidia-modeset enumerates "
    "(kernel-open/nvidia-drm/nvidia-drm-drv.c:2176). The campaign models the "
    "24 dispatched driver ioctls at nvidia-drm-drv.c:1806 as the drm family, "
    "and they are inside the denominator. 21 carry DRM_RENDER_ALLOW and are "
    "reachable on both node types; the other 3 are reachable on cardN alone, "
    "2 of them only while the opening file is the current DRM master"
)


FOPS_TABLES = (
    {
        "fops": "nvidia_fops",
        "source": NV_C,
        "module": "nvidia",
        "paths": ["/dev/nvidiactl", "/dev/nvidiaN"],
        "modelled": True,
        "tenant_surface": True,
        "reason": None,
        # One table serves two nodes, and the two are not equally reachable
        # through it. The control node clears both early exits in
        # nvidia_poll that the actual device faces: nv.c:2292 skips the
        # nv_is_open_complete POLLERR gate at nv.c:2294 for it, and
        # nvidia_ctl_open sets nvlfp->nvptr unconditionally at nv.c:3141,
        # where the actual device leaves it NULL at nv.c:1898 until
        # nv_add_open_file fills it at nv.c:1733 and meets the POLLERR at
        # nv.c:2298 in the meantime. Both nodes therefore carry a poll call.
        "notes": {
            "poll": "nv.c:2292 skips the nv_is_open_complete gate at "
                    "nv.c:2294 for the control device, and nv.c:3141 sets "
                    "nvlfp->nvptr on it unconditionally where nv.c:1898 "
                    "leaves it NULL for the actual device until nv.c:1733. "
                    "/dev/nvidiactl reaches the poll body directly after "
                    "open; /dev/nvidiaN meets POLLERR at nv.c:2298 until "
                    "the open completes.",
        },
    },
    {
        "fops": "uvm_fops",
        "source": UVM_C,
        "module": "nvidia-uvm",
        "paths": ["/dev/nvidia-uvm"],
        "modelled": True,
        "tenant_surface": True,
        "reason": None,
    },
    {
        "fops": "uvm_tools_fops",
        "source": UVM_TOOLS_C,
        "module": "nvidia-uvm",
        "paths": ["/dev/nvidia-uvm-tools"],
        "modelled": True,
        "tenant_surface": True,
        "reason": None,
    },
    {
        "fops": "nvkms_fops",
        "source": NVKMS_C,
        "module": "nvidia-modeset",
        "paths": ["/dev/nvidia-modeset"],
        "modelled": False,
        "tenant_surface": True,
        # Reachability here is path-dependent, and TENANT_DEVICE_SOURCE
        # above does not settle it. lookup_devices builds the host-side
        # driver info list; the mount decision for this node is a separate
        # gate in nvc_mount.c, and the CDI generator is a second injection
        # path that does not consult it at all. Both paths are cited in the
        # reason below, because a reader who takes either one for the whole
        # picture gets the opposite answer about a default tenant.
        "reason": "The node reaches a default tenant on the CDI path. "
                  "controlDeviceNodeDiscoverer at "
                  "nvidia-container-toolkit/pkg/nvcdi/common-nvml.go:52-63 "
                  "lists it beside /dev/nvidiactl, /dev/nvidia-uvm and "
                  "/dev/nvidia-uvm-tools with no capability check, and "
                  "nvidia-container-toolkit/internal/info/auto.go:89 makes "
                  "that path the default runtime mode. The legacy path needs "
                  "the display capability: "
                  "libnvidia-container/src/nvc_mount.c:786 skips the modeset "
                  "minor unless OPT_DISPLAY is set, "
                  "libnvidia-container/src/options.h:92 sets that flag from "
                  "the display capability alone, and "
                  "libnvidia-container/src/options.h:100 leaves display out "
                  "of the default capability set. The description set opens "
                  "a descriptor on the node and its 64 commands are inside "
                  "the denominator. The mmap and poll entry points of this "
                  "table are not modelled.",
    },
    {
        "fops": "nvlink_fops",
        "source": NVLINK_C,
        "module": "nvidia",
        "paths": ["/dev/nvidia-nvlink"],
        "modelled": False,
        "tenant_surface": False,
        "reason": OUTSIDE_TENANT_SURFACE,
    },
    {
        "fops": "device_fops",
        "source": NVSWITCH_C,
        "module": "nvidia",
        "paths": ["/dev/nvidia-nvswitchN"],
        "modelled": False,
        "tenant_surface": False,
        "reason": OUTSIDE_TENANT_SURFACE,
    },
    {
        "fops": "ctl_fops",
        "source": NVSWITCH_C,
        "module": "nvidia",
        "paths": ["/dev/nvidia-nvswitchctl"],
        "modelled": False,
        "tenant_surface": False,
        "reason": OUTSIDE_TENANT_SURFACE,
    },
    {
        "fops": "g_nv_cap_drv_fops",
        "source": NV_CAPS_C,
        "module": "nvidia",
        "paths": ["/dev/nvidia-caps/nvidia-capN"],
        "modelled": False,
        "tenant_surface": False,
        "reason": "libnvidia-container/src/nvc.c:218 creates a capability "
                  "node only for a MIG-partitioned GPU, and only for the "
                  "partitions the container was given. A default container "
                  "on an unpartitioned GPU carries none.",
    },
    {
        "fops": "g_nv_caps_imex_fops",
        "source": NV_CAPS_IMEX_C,
        "module": "nvidia",
        "paths": ["/dev/nvidia-caps-imex-channels/channelN"],
        "modelled": False,
        "tenant_surface": False,
        "reason": OUTSIDE_TENANT_SURFACE,
    },
    {
        "fops": "nv_drm_fops",
        "source": NV_DRM_C,
        "module": "nvidia-drm",
        "paths": ["/dev/dri/cardN", "/dev/dri/renderDN"],
        "modelled": True,
        "tenant_surface": True,
        "reason": DRM_TENANT_SURFACE,
    },
)



def _fops_initialiser(symbol):
    """The opening of one file_operations initialiser.

    The brace sits on the same line under kernel-open/nvidia and on the next
    line under kernel-open/nvidia-uvm, so the newline between `=` and `{` is
    optional. Requiring the `=` and the brace keeps a forward declaration such
    as uvm.c:47, which ends at the semicolon, from matching.
    """
    return re.compile(r"struct\s+file_operations\s+" + re.escape(symbol)
                      + r"\s*=\s*\{")


def parse_fops_table(text, symbol):
    """-> [{operation, handler, line, conditional}] for one fops initialiser.

    Read from the initialiser and never from a kept list, so a driver release
    that adds or drops an entry point moves the artefact. `conditional` names
    the preprocessor condition a member sits under, because .compat_ioctl is
    registered on two architectures only and counting it unconditionally
    overstates what a given build serves.
    """
    match = _fops_initialiser(symbol).search(text)
    if match is None:
        raise InventoryError(
            "no file_operations initialiser named %s was found. The entry "
            "point census reads each table from its own initialiser, so a "
            "table that was renamed or removed has to move this tool rather "
            "than be skipped without a record." % symbol)
    first_line = line_of(text, match.end())
    entries, guards, depth = [], [], 1
    for offset, line in enumerate(text[match.end():].splitlines()):
        stripped = line.strip()
        if stripped.startswith("#"):
            head, _, rest = stripped[1:].strip().partition(" ")
            if head in ("if", "ifdef", "ifndef"):
                guards.append(rest.strip() or head)
            elif head in ("elif", "elifdef", "elifndef"):
                if guards:
                    guards[-1] = rest.strip()
                else:
                    guards.append(rest.strip())
            elif head == "endif" and guards:
                guards.pop()
            continue
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            break
        member = RE_FOPS_MEMBER.match(line)
        if member is None or member.group(1) in FOPS_NON_ENTRY:
            continue
        entries.append({
            "operation": member.group(1),
            "handler": member.group(2),
            "line": first_line + offset,
            "conditional": " && ".join(guards) if guards else None,
        })
    return entries


def build_entry_points(src):
    """-> the entry-point artefact for one checkout.

    Every table FOPS_TABLES names is read from its own source file. The
    modelled tables are the three serving the four device nodes the
    description set opens; the rest are recorded with the reason each is not
    modelled, so the artefact carries the whole registered surface and the
    scope decision is visible in it rather than only in a plan.
    """
    tables = []
    for record in FOPS_TABLES:
        text = read_source(src, record["source"])
        match = _fops_initialiser(record["fops"]).search(text)
        entries = parse_fops_table(text, record["fops"])
        tables.append({
            "fops": record["fops"],
            "declared_at": "%s:%d" % (record["source"],
                                      line_of(text, match.start())),
            "module": record["module"],
            "paths": list(record["paths"]),
            "modelled": record["modelled"],
            "tenant_surface": record["tenant_surface"],
            "reason": record["reason"],
            "notes": record.get("notes") or {},
            "entry_points": entries,
        })
    modelled = [t for t in tables if t["modelled"]]
    payload = {
        "schema": ENTRY_POINTS_SCHEMA,
        "source": {
            "driver_version": driver_version(src),
            "commit": checkout_commit(src),
        },
        "tables": tables,
        "counts": {
            "tables": len(tables),
            "modelled_tables": len(modelled),
            "modelled_nodes": sum(len(t["paths"]) for t in modelled),
            "entry_points": sum(len(t["entry_points"]) for t in tables),
            "modelled_entry_points": sum(len(t["entry_points"])
                                         for t in modelled),
        },
    }
    logger.info("read %d file_operations table(s), %d modelled, %d entry "
                "point(s) on the modelled ones",
                payload["counts"]["tables"],
                payload["counts"]["modelled_tables"],
                payload["counts"]["modelled_entry_points"])
    return payload


def build_inventory(src, sizes):
    """Return the whole inventory as a JSON-serialisable dict."""
    magic, base, numbers, origin = parse_escape_numbers(src)
    table = parse_validation_tables(src)
    sites = parse_rm_dispatch(src)
    restrictions = parse_case_restrictions(src)
    rm_commands = build_rm_commands(src, magic, numbers, origin, table, sites,
                                    sizes, restrictions)

    uvm_numbers = parse_uvm_numbers(src)
    uvm_dispatch = parse_uvm_dispatch(src, UVM_C, uvm_numbers)
    tools_dispatch = parse_uvm_dispatch(src, UVM_TOOLS_C, uvm_numbers)
    test_dispatch = parse_uvm_dispatch(src, UVM_TEST_C, uvm_numbers)

    test_text = read_source(src, UVM_TEST_C)
    gate_m = RE_UVM_TEST_GATE.search(test_text)
    if not gate_m:
        raise InventoryError(
            "the uvm_enable_builtin_tests gate was not found in %s; without it "
            "the UVM_TEST_* commands would be recorded as reachable" % UVM_TEST_C)
    test_gate = "%s module parameter (%s:%d)" % (
        gate_m.group(1), UVM_TEST_C, line_of(test_text, gate_m.start()))

    uvm_api_h = read_source(src, UVM_API_H)
    stack_m = RE_UVM_STACK_LIMIT.search(uvm_api_h)
    stack_limit = int(stack_m.group(1)) if stack_m else None

    uvm_commands = build_uvm_commands(uvm_numbers, uvm_dispatch, sizes)
    tools_commands = build_uvm_commands(uvm_numbers, tools_dispatch, sizes)
    test_commands = build_uvm_commands(uvm_numbers, test_dispatch, sizes,
                                       gated_by=test_gate)

    if stack_limit is not None:
        check_uvm_storage(uvm_commands + tools_commands + test_commands,
                          stack_limit)

    nv_h = read_source(src, NV_H)
    max_m = RE_MAX_SIZE.search(nv_h)
    if not max_m:
        raise InventoryError(
            "NV_ABSOLUTE_MAX_IOCTL_SIZE not found in %s" % NV_H)

    all_commands = (rm_commands + uvm_commands + tools_commands + test_commands)
    unresolved = sorted({c["param_struct"] for c in all_commands
                         if c["size_source"] == "unresolved"})

    return {
        # source_tree predates the source block. No tool in this repository
        # reads it; it is kept for a consumer outside the tree. The block
        # below is the shape tools/surface_verify.py and the other two
        # surface artefacts agree on.
        "source_tree": repo_relative(src),
        "source": {
            "path": repo_relative(src),
            "driver_version": driver_version(src),
        },
        "encoding": {
            "ioctl_magic": magic,
            "ioctl_base": base,
            "direction_bits": DIRECTION_BITS,
            "direction_bits_source": DIRECTION_SOURCE,
            "platform_size_limit_note": PLATFORM_SIZE_LIMIT_NOTE,
            "ioc_size_bits": IOC_SIZE_BITS,
            "ioc_size_max": IOC_SIZE_MAX,
            "absolute_max_ioctl_size": int(max_m.group(1)),
            "uvm_max_ioctl_param_stack_size": stack_limit,
            "xfer_escape": XFER_ESCAPE,
        },
        "nodes": [
            {
                "paths": DEV_NVIDIA,
                "module": "nvidia",
                "entry": "nvidia_unlocked_ioctl -> nvidia_ioctl (%s)" % NV_C,
                "scheme": "linux_ioc",
                "commands": rm_commands,
            },
            {
                "paths": DEV_UVM,
                "module": "nvidia-uvm",
                "entry": "uvm_unlocked_ioctl_entry (%s)" % UVM_C,
                "scheme": "bare_command_number",
                "commands": uvm_commands,
            },
            {
                "paths": DEV_UVM_TOOLS,
                "module": "nvidia-uvm",
                "entry": "uvm_tools_unlocked_ioctl_entry (%s)" % UVM_TOOLS_C,
                "scheme": "bare_command_number",
                "commands": tools_commands,
            },
            {
                "paths": DEV_UVM,
                "module": "nvidia-uvm",
                "entry": "uvm_test_ioctl (%s), fallthrough from uvm_ioctl" % UVM_TEST_C,
                "scheme": "bare_command_number",
                "reachability_gate": test_gate,
                "commands": test_commands,
            },
        ],
        "dead_escapes": find_dead_escapes(numbers, sites),
        "unresolved_param_structs": unresolved,
        "counts": {
            "rm_escapes_dispatched": len(rm_commands),
            "uvm_commands_dispatched": len(uvm_commands),
            "uvm_tools_commands_dispatched": len(tools_commands),
            "uvm_test_commands_dispatched": len(test_commands),
            "sizes_measured": sum(1 for c in all_commands
                                  if c["size_source"] == "measured"),
            "sizes_unresolved": sum(1 for c in all_commands
                                    if c["size_source"] == "unresolved"),
        },
    }


def write_json(path, payload):
    """Write JSON through a temp file in the same directory.

    An interrupted run leaves the previous file intact and never a truncated
    one. tools/ioctl_map.json is committed data the seeds phase reads on a
    machine where regenerating it needs a compiler.
    """
    out_dir = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
        logger.info("created output directory %s", out_dir)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(payload, f, indent=2, sort_keys=False)
            f.write("\n")
        os.replace(tmp, path)
    except OSError as e:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise InventoryError("cannot write %s: %s" % (path, e))


def build_parser():
    """The argument parser, separated so the defaults are testable.

    Every sibling tool in this partition exposes one. The defaults here are
    what makes `python3 tools/ioctl_inventory.py --src <checkout>` runnable as
    the version guard prints it, so they are worth asserting directly rather
    than through a full run that would rewrite the committed inventory.
    """
    ap = argparse.ArgumentParser(
        description="Derive the in-scope ioctl inventory from an "
                    "open-gpu-kernel-modules checkout.")
    ap.add_argument("--src", required=True,
                    help="path to the open-gpu-kernel-modules checkout")
    ap.add_argument("--out", default=DEFAULT_OUT,
                    help="write the inventory JSON here (default: %s). "
                         "--emit-map writes the request-number map as well as "
                         "this file."
                         % os.path.relpath(DEFAULT_OUT, REPO_ROOT))
    ap.add_argument("--sizes", default=DEFAULT_SIZES,
                    help="JSON of measured struct sizes, from the runner that "
                         "--emit-probe writes (default: %s)"
                         % os.path.relpath(DEFAULT_SIZES, REPO_ROOT))
    ap.add_argument("--emit-probe", metavar="DIR",
                    help="write the C size probes and their runner into DIR "
                         "and exit")
    ap.add_argument("--emit-map", metavar="PATH",
                    help="also write the trace2seed request-number map here "
                         "(tools/ioctl_map.json)")
    ap.add_argument("--emit-entry-points", metavar="PATH",
                    help="also write the file_operations entry-point census "
                         "here (surface/entry-points.json). Entry points are "
                         "counted beside the command denominator and never "
                         "inside it")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log every parsing step")
    return ap


def main(argv=None):
    a = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if a.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)

    if not os.path.isdir(a.src):
        logger.error("--src is not a directory: %s", a.src)
        return 2
    missing = [r for r in REQUIRED_FILES if not os.path.isfile(os.path.join(a.src, r))]
    if missing:
        logger.error("--src %s is missing %d required source file(s): %s",
                     a.src, len(missing), ", ".join(missing))
        return 2

    try:
        sizes = load_sizes(a.sizes)
        inventory = build_inventory(a.src, sizes)
        if a.emit_probe:
            rm_structs, uvm_structs = collect_structs(
                inventory["nodes"][0]["commands"],
                [n["commands"] for n in inventory["nodes"][1:]])
            emit_probe(a.src, a.emit_probe, rm_structs, uvm_structs)
            print("probe written to %s; run measure_sizes.sh, then pass its %s "
                  "to --sizes" % (a.emit_probe, SIZES_FILENAME))
            return 0
    except InventoryError as e:
        logger.error("%s", e)
        return 1

    try:
        if a.emit_map:
            modeset = nvkms_request(a.src, sizes)
            mapping, skipped = build_map(inventory, version_stamp(a.src),
                                         modeset)
            write_json(a.emit_map, mapping)
            requests = sum(1 for k in mapping if not k.startswith("comment"))
            muxes = len(mapping.get(MAP_MULTIPLEXER_KEY, {}).get("requests", {}))
            print("wrote %s (%d request numbers, %d multiplexer request "
                  "numbers carrying no call name, %d commands omitted)"
                  % (a.emit_map, requests, muxes, len(skipped)))
            for request, record in sorted(modeset["requests"].items()):
                print("  %s is %s's one request number, family %s only: the "
                      "sub-command is %s.%s and no trace carries it (F18)"
                      % (request, record["node"], record["escape"],
                         record["param_struct"], record["selector_field"]))
        if a.emit_entry_points:
            entry_points = build_entry_points(a.src)
            write_json(a.emit_entry_points, entry_points)
            counts = entry_points["counts"]
            print("wrote %s (%d file_operations table(s), %d modelled over "
                  "%d device node(s), %d entry point(s) on the modelled "
                  "tables of %d registered in total)"
                  % (a.emit_entry_points, counts["tables"],
                     counts["modelled_tables"], counts["modelled_nodes"],
                     counts["modelled_entry_points"], counts["entry_points"]))
        refuse_size_regression(a.out, inventory)
        write_json(a.out, inventory)
    except InventoryError as e:
        logger.error("%s", e)
        return 1

    c = inventory["counts"]
    print("wrote %s" % a.out)
    print("  %d RM escapes, %d UVM, %d UVM-tools, %d UVM-test (gated)"
          % (c["rm_escapes_dispatched"], c["uvm_commands_dispatched"],
             c["uvm_tools_commands_dispatched"], c["uvm_test_commands_dispatched"]))
    print("  %d sizes measured, %d unresolved"
          % (c["sizes_measured"], c["sizes_unresolved"]))
    if inventory["dead_escapes"]:
        print("  dead escapes (declared, never dispatched): %s"
              % ", ".join(inventory["dead_escapes"]))
    if inventory["unresolved_param_structs"]:
        print("  unresolved param structs: %s"
              % ", ".join(inventory["unresolved_param_structs"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
