#!/usr/bin/env python3
"""Enumerate the NV_ESC_RM_CONTROL command space from the driver source.

One ioctl (NV_ESC_RM_CONTROL, escape 0x2A) carries every RM control call, and
its `cmd` field selects which of them runs. Modeling that ioctl as an opaque
buffer wastes a campaign, so the command space has to be enumerated before the
describe phase can attach per-command parameter structs.

The enumeration is already in the tree. NVOC generates one
`NVOC_EXPORTED_METHOD_DEF` table per resource class into
`src/nvidia/generated/g_*_nvoc.c`, and each entry carries the command number,
the flags that decide who may call it, the handler, and the parameter struct:

    {               /*  [0] */
    #if NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG(0x30118u)
        /*pFunc=*/      (void (*)(void)) NULL,
    #else
        /*pFunc=*/      (void (*)(void)) &subdeviceCtrlCmdGpuGetInfoV2__EXPORT,
    #endif // NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG(0x30118u)
        /*flags=*/      0x30118u,
        /*accessRight=*/0x0u,
        /*methodId=*/   0x20800102u,
        /*paramSize=*/  sizeof(NV2080_CTRL_GPU_GET_INFO_V2_PARAMS),
        /*pClassInfo=*/ &(__nvoc_class_def_Subdevice.classInfo),
    #if NV_PRINTF_STRINGS_ALLOWED
        /*func=*/       "subdeviceCtrlCmdGpuGetInfoV2"
    #endif
    },

Flag and access-right names are read from the driver headers at run time,
because both move between driver branches.

    python3 tools/ctrl_surface.py --out artifacts/surface/rm-control-inventory.json

Entries the parser cannot read are counted and listed in the output under
`scan.rejected`, and the count is logged. A silently truncated inventory is
worse than a smaller honest one.
"""
import argparse
import json
import logging
import os
import re
import sys

logger = logging.getLogger(__name__)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SRC = os.path.join(REPO_ROOT, "artifacts", "src",
                           "open-gpu-kernel-modules")
DEFAULT_OUT = os.path.join(REPO_ROOT, "artifacts", "surface",
                           "rm-control-inventory.json")

SCHEMA = "gspwn.rm-control-inventory/1"

# Paths inside the driver tree, relative to --src. Each is required: a missing
# one means --src does not point at open-gpu-kernel-modules, and guessing past
# it would produce an inventory with no flag names in it.
GENERATED_DIR = os.path.join("src", "nvidia", "generated")
CONTROL_H = os.path.join("src", "nvidia", "inc", "kernel", "rmapi", "control.h")
RS_ACCESS_H = os.path.join("src", "common", "sdk", "nvidia", "inc",
                           "rs_access.h")
VERSION_MK = "version.mk"

# control.h defines RMCTRL_FLAGS_NONE and RMCTRL_FLAGS_KERNEL_PRIVILEGED as
# zero, and composite names such as RMCTRL_FLAGS_CACHEABLE_ANY as expressions.
# Only single hex literals are bit definitions; the rest cannot be decoded out
# of a bitmask and are excluded by the pattern below.
FLAG_DEF_RE = re.compile(
    r"^#define\s+RMCTRL_FLAGS_([A-Z0-9_]+)\s+(0x[0-9a-fA-F]+)\s*(?://.*)?$",
    re.M)
ACCESS_DEF_RE = re.compile(
    r"^#define\s+RS_ACCESS_([A-Z0-9_]+)\s+(\d+)U\s*(?://.*)?$", re.M)
# RS_ACCESS_COUNT is the size of the enumeration. It names no right.
ACCESS_NOT_A_RIGHT = {"COUNT"}
VERSION_RE = re.compile(r"^NVIDIA_VERSION\s*=\s*(\S+)\s*$", re.M)

TABLE_START_RE = re.compile(
    r"^static const struct NVOC_EXPORTED_METHOD_DEF\s+"
    r"__nvoc_exported_method_def_(\w+)\[\]")
TABLE_END_RE = re.compile(r"^\};")
ENTRY_START_RE = re.compile(r"^\s*\{\s*/\*\s*\[(\d+)\]\s*\*/")
ENTRY_END_RE = re.compile(r"^\s*\},?\s*$")

GATE_RE = re.compile(
    r"^#if NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG\((0x[0-9a-fA-F]+)u?\)", re.M)
EXPORT_SYM_RE = re.compile(r"/\*pFunc=\*/\s*\(void \(\*\)\(void\)\)\s*&(\w+)")
FLAGS_RE = re.compile(r"/\*flags=\*/\s*(0x[0-9a-fA-F]+)u?")
ACCESS_RIGHT_RE = re.compile(r"/\*accessRight=\*/\s*(0x[0-9a-fA-F]+)u?")
METHOD_ID_RE = re.compile(r"/\*methodId=\*/\s*(0x[0-9a-fA-F]+)u?")
PARAM_SIZEOF_RE = re.compile(r"/\*paramSize=\*/\s*sizeof\((\w+)\)")
PARAM_ZERO_RE = re.compile(r"/\*paramSize=\*/\s*0\b")
CLASS_INFO_RE = re.compile(
    r"/\*pClassInfo=\*/\s*&\(__nvoc_class_def_(\w+)\.classInfo\)")
FUNC_NAME_RE = re.compile(r'/\*func=\*/\s*"([^"]*)"')

# Flag names this tool reasons about. The values come from control.h at run
# time. serverControl_ValidateCookie() and
# rmControlValidateClientPrivilegeAccess() in src/nvidia/src/kernel/rmapi/
# control.c branch on these names.
F_NO_GPUS_ACCESS = "NO_GPUS_ACCESS"
F_PRIVILEGED = "PRIVILEGED"
F_NON_PRIVILEGED = "NON_PRIVILEGED"
F_PRIV_IF_RS_OFF = "PRIVILEGED_IF_RS_ACCESS_DISABLED"
F_ROUTE_TO_PHYSICAL = "ROUTE_TO_PHYSICAL"
F_INTERNAL = "INTERNAL"
F_VGPU_GUEST = "PHYSICAL_IMPLEMENTED_ON_VGPU_GUEST"
F_TEST_ONLY = "RM_TEST_ONLY_CODE"

REQUIRED_FLAG_NAMES = (
    F_PRIVILEGED, F_NON_PRIVILEGED, F_PRIV_IF_RS_OFF, F_ROUTE_TO_PHYSICAL,
    F_INTERNAL, F_VGPU_GUEST, F_TEST_ONLY,
)

# Reachability from a caller holding an open file descriptor on /dev/nvidiactl
# or /dev/nvidiaX, derived from the dispatch order in control.c:
#
#   serverControl_ValidateCookie()          INTERNAL      -> NV_ERR_NOT_SUPPORTED
#   rmControlValidateClientPrivilegeAccess()PRIVILEGED    -> privLevel >= USER_ROOT
#                                           default       -> privLevel >= KERNEL
#
# INTERNAL is tested first and rejects any caller whose RmApi instance did not
# set bApiLockInternal or bGpuLockInternal, which the ioctl path never does.
# PRIVILEGED is tested before the default, so a command carrying both
# PRIVILEGED and NON_PRIVILEGED still demands root.
REACH_INTERNAL = "internal"
REACH_PRIVILEGED = "privileged"
REACH_NON_PRIVILEGED = "non_privileged"
REACH_KERNEL_ONLY = "kernel_only"


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


def load_flag_defs(src_root):
    """Return {bit value: flag name} from control.h.

    Zero-valued names (NONE, KERNEL_PRIVILEGED) carry no bit and are absent
    by construction. KERNEL_PRIVILEGED is the behaviour of an empty mask, and
    no bit in a mask records it.
    """
    path = os.path.join(src_root, CONTROL_H)
    text = read_text(path, "RM control flag header")
    defs = {}
    for name, value in FLAG_DEF_RE.findall(text):
        bits = int(value, 16)
        if bits == 0:
            continue
        if bits & (bits - 1):
            raise SourceError(
                "RMCTRL_FLAGS_%s in %s is %s, which is not a single bit: this "
                "tool decodes flags as a bitmask" % (name, path, value))
        if bits in defs:
            raise SourceError(
                "%s defines two names for bit %s: %s and %s"
                % (path, value, defs[bits], name))
        defs[bits] = name
    missing = [n for n in REQUIRED_FLAG_NAMES if n not in defs.values()]
    if missing:
        raise SourceError(
            "%s defines no bit for %s: this driver branch names the privilege "
            "flags differently and the reachability classification would be "
            "wrong" % (path, ", ".join(missing)))
    logger.info("read %d flag bits from %s", len(defs), path)
    return defs


def load_access_right_defs(src_root):
    """Return {bit value: access right name} from rs_access.h.

    The table field holds NVBIT(RS_ACCESS_x), so the header's index becomes a
    bit position. See the ACCESS_RIGHTS macro in control.h.
    """
    path = os.path.join(src_root, RS_ACCESS_H)
    text = read_text(path, "resource-server access right header")
    defs = {}
    for name, index in ACCESS_DEF_RE.findall(text):
        if name in ACCESS_NOT_A_RIGHT:
            continue
        defs[1 << int(index)] = name
    if not defs:
        raise SourceError("%s defines no RS_ACCESS_* rights: expected at least "
                          "one #define RS_ACCESS_<NAME> <index>U" % path)
    logger.info("read %d access rights from %s", len(defs), path)
    return defs


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


def decode_bits(value, defs):
    """Return the names for the set bits, plus any bit with no name."""
    names = []
    unknown = 0
    for bit in range(value.bit_length()):
        mask = 1 << bit
        if not value & mask:
            continue
        if mask in defs:
            names.append(defs[mask])
        else:
            unknown |= mask
    return names, unknown


def classify_reachability(flag_names):
    """Return how a userspace ioctl caller is treated by control.c."""
    if F_INTERNAL in flag_names:
        return REACH_INTERNAL
    if F_PRIVILEGED in flag_names:
        return REACH_PRIVILEGED
    if F_NON_PRIVILEGED in flag_names:
        return REACH_NON_PRIVILEGED
    return REACH_KERNEL_ONLY


def parse_entry(lines, first_line_no, rel_path, table_class):
    """Turn one table entry's lines into a raw field dict.

    Returns (fields, error). Every field the inventory records is required:
    an entry missing one means the entry boundaries were misread, and emitting
    a partial record would put a wrong command number in the inventory.
    """
    body = "\n".join(lines)
    fields = {}

    m = GATE_RE.search(body)
    if not m:
        return None, "no NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG gate"
    fields["gate"] = int(m.group(1), 16)

    for key, pattern in (("flags", FLAGS_RE),
                         ("access_right", ACCESS_RIGHT_RE),
                         ("method_id", METHOD_ID_RE)):
        m = pattern.search(body)
        if not m:
            return None, "no %s field" % key
        fields[key] = int(m.group(1), 16)

    m = PARAM_SIZEOF_RE.search(body)
    if m:
        fields["param_struct"] = m.group(1)
    elif PARAM_ZERO_RE.search(body):
        fields["param_struct"] = None
    else:
        return None, "no paramSize field"

    m = CLASS_INFO_RE.search(body)
    if not m:
        return None, "no pClassInfo field"
    fields["class_info"] = m.group(1)

    m = FUNC_NAME_RE.search(body)
    if not m:
        return None, "no func name string"
    fields["handler"] = m.group(1)

    m = EXPORT_SYM_RE.search(body)
    fields["export_symbol"] = m.group(1) if m else None

    # The generator writes the entry's own flags into the #if that decides
    # whether the handler is compiled in. A disagreement means the lines
    # collected here span two entries, so the entry is rejected.
    if fields["gate"] != fields["flags"]:
        return None, ("gate constant 0x%x does not match flags 0x%x"
                      % (fields["gate"], fields["flags"]))
    if fields["class_info"] != table_class:
        return None, ("pClassInfo names %s in the %s table"
                      % (fields["class_info"], table_class))

    fields["source"] = "%s:%d" % (rel_path, first_line_no)
    return fields, None


def scan_file(path, rel_path):
    """Return (entries, tables, rejected) for one generated source file."""
    entries = []
    rejected = []
    tables = []
    with open(path, "r", errors="replace") as f:
        lines = f.readlines()

    table_class = None
    entry_lines = None
    entry_start = 0
    for n, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if table_class is None:
            m = TABLE_START_RE.match(line)
            if m:
                table_class = m.group(1)
                tables.append(table_class)
                logger.debug("%s:%d table for class %s", rel_path, n,
                             table_class)
            continue
        if entry_lines is None:
            if TABLE_END_RE.match(line):
                table_class = None
                continue
            if ENTRY_START_RE.match(line):
                entry_lines = [line]
                entry_start = n
            continue
        if ENTRY_END_RE.match(line):
            fields, err = parse_entry(entry_lines, entry_start, rel_path,
                                      table_class)
            if err:
                rejected.append({"source": "%s:%d" % (rel_path, entry_start),
                                 "class": table_class, "reason": err})
                logger.warning("%s:%d rejected: %s", rel_path, entry_start, err)
            else:
                entries.append(fields)
            entry_lines = None
            continue
        entry_lines.append(line)

    if entry_lines is not None:
        rejected.append({"source": "%s:%d" % (rel_path, entry_start),
                         "class": table_class,
                         "reason": "entry not closed before end of file"})
        logger.warning("%s:%d rejected: entry not closed", rel_path, entry_start)
    return entries, tables, rejected


def build_record(fields, flag_defs, access_defs):
    """Turn raw entry fields into one inventory record."""
    flags = fields["flags"]
    flag_names, unknown_flag_bits = decode_bits(flags, flag_defs)
    right_names, unknown_right_bits = decode_bits(fields["access_right"],
                                                  access_defs)
    method_id = fields["method_id"]
    routed_to_physical = F_ROUTE_TO_PHYSICAL in flag_names
    # NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG in control.h: the handler is
    # compiled to NULL when the call is routed to physical RM and is not also
    # implemented for a vGPU guest. Dispatch never reaches the function
    # pointer for those; resControl_Prologue forwards the call instead.
    handler_compiled_out = (routed_to_physical
                            and F_VGPU_GUEST not in flag_names)
    return {
        "method_id": "0x%08x" % method_id,
        "method_id_int": method_id,
        "class_id": "0x%04x" % (method_id >> 16),
        "sdk_prefix": "NV%04X" % (method_id >> 16),
        "owning_class": fields["class_info"],
        "handler": fields["handler"],
        "export_symbol": fields["export_symbol"],
        "param_struct": fields["param_struct"],
        "param_size_zero": fields["param_struct"] is None,
        "flags": "0x%x" % flags,
        "flags_int": flags,
        "flag_names": flag_names,
        "unknown_flag_bits": ("0x%x" % unknown_flag_bits
                              if unknown_flag_bits else None),
        "access_right": "0x%x" % fields["access_right"],
        "access_right_names": right_names,
        "unknown_access_right_bits": ("0x%x" % unknown_right_bits
                                      if unknown_right_bits else None),
        "reachability": classify_reachability(flag_names),
        "privileged_when_rs_access_disabled": F_PRIV_IF_RS_OFF in flag_names,
        "test_only": F_TEST_ONLY in flag_names,
        "routed_to_physical": routed_to_physical,
        "handler_compiled_out": handler_compiled_out,
        "source": fields["source"],
    }


def summarise(records):
    """Counts the knowledgebase page and the log line both report."""
    by_class = {}
    by_reach = {}
    by_sdk_prefix = {}
    for r in records:
        by_class[r["owning_class"]] = by_class.get(r["owning_class"], 0) + 1
        by_reach[r["reachability"]] = by_reach.get(r["reachability"], 0) + 1
        by_sdk_prefix[r["sdk_prefix"]] = by_sdk_prefix.get(r["sdk_prefix"], 0) + 1
    ids = {}
    for r in records:
        ids.setdefault(r["method_id"], []).append(r["owning_class"])
    duplicates = {k: v for k, v in ids.items() if len(v) > 1}
    return {
        "methods": len(records),
        "distinct_method_ids": len(ids),
        "duplicate_method_ids": duplicates,
        "by_owning_class": dict(sorted(by_class.items(),
                                       key=lambda kv: (-kv[1], kv[0]))),
        "by_reachability": dict(sorted(by_reach.items())),
        "by_sdk_prefix": dict(sorted(by_sdk_prefix.items(),
                                     key=lambda kv: (-kv[1], kv[0]))),
        "test_only": sum(1 for r in records if r["test_only"]),
        "routed_to_physical": sum(1 for r in records
                                  if r["routed_to_physical"]),
        "handler_compiled_out": sum(1 for r in records
                                    if r["handler_compiled_out"]),
        "param_size_zero": sum(1 for r in records if r["param_size_zero"]),
        "with_access_rights": sum(1 for r in records
                                  if r["access_right_names"]),
        "privileged_when_rs_access_disabled": sum(
            1 for r in records if r["privileged_when_rs_access_disabled"]),
    }


def collect(src_root):
    """Walk the NVOC generated directory and build the inventory."""
    generated = os.path.join(src_root, GENERATED_DIR)
    if not os.path.isdir(generated):
        raise SourceError(
            "no NVOC generated directory at %s: expected --src to be a "
            "checkout of open-gpu-kernel-modules containing %s"
            % (generated, GENERATED_DIR))

    flag_defs = load_flag_defs(src_root)
    access_defs = load_access_right_defs(src_root)

    sources = sorted(n for n in os.listdir(generated) if n.endswith(".c"))
    if not sources:
        raise SourceError("%s holds no .c files: the tree looks unpopulated"
                          % generated)

    records = []
    rejected = []
    files_with_table = 0
    tables = 0
    for name in sources:
        rel = os.path.join(GENERATED_DIR, name).replace(os.sep, "/")
        entries, file_tables, file_rejected = scan_file(
            os.path.join(generated, name), rel)
        rejected.extend(file_rejected)
        if file_tables:
            files_with_table += 1
            tables += len(file_tables)
        for fields in entries:
            records.append(build_record(fields, flag_defs, access_defs))

    records.sort(key=lambda r: (r["method_id_int"], r["owning_class"]))
    logger.info("scanned %d files, %d carried a table, %d tables, %d methods, "
                "%d entries rejected", len(sources), files_with_table, tables,
                len(records), len(rejected))
    if rejected:
        logger.warning("%d table entries could not be parsed and are absent "
                       "from the inventory; see scan.rejected in the output",
                       len(rejected))
    if not records:
        raise SourceError(
            "no exported control methods found under %s: expected tables "
            "named __nvoc_exported_method_def_<Class>" % generated)

    return {
        "schema": SCHEMA,
        "source": {
            "src_root": os.path.abspath(src_root),
            "driver_version": read_driver_version(src_root),
            "generated_dir": GENERATED_DIR.replace(os.sep, "/"),
            "flag_header": CONTROL_H.replace(os.sep, "/"),
            "access_right_header": RS_ACCESS_H.replace(os.sep, "/"),
        },
        "flag_definitions": {"0x%x" % k: v
                             for k, v in sorted(flag_defs.items())},
        "access_right_definitions": {"0x%x" % k: v
                                     for k, v in sorted(access_defs.items())},
        "scan": {
            "files_scanned": len(sources),
            "files_with_table": files_with_table,
            "tables": tables,
            "rejected_count": len(rejected),
            "rejected": rejected,
        },
        "summary": summarise(records),
        "methods": records,
    }


def write_json(inventory, out_path):
    """Write the inventory, creating the parent directory if needed."""
    parent = os.path.dirname(os.path.abspath(out_path))
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as e:
        raise SourceError("cannot create output directory %s: %s" % (parent, e))
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
        description="Enumerate the RM control command space from the NVOC "
                    "exported method tables in the driver source.")
    ap.add_argument("--src", default=DEFAULT_SRC,
                    help="open-gpu-kernel-modules checkout (default: %s)"
                         % os.path.relpath(DEFAULT_SRC, REPO_ROOT))
    ap.add_argument("--out", default=DEFAULT_OUT,
                    help="JSON inventory to write (default: %s)"
                         % os.path.relpath(DEFAULT_OUT, REPO_ROOT))
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log every table found")
    a = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if a.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)

    if not os.path.isdir(a.src):
        print("error: --src %s is not a directory" % a.src, file=sys.stderr)
        return 2
    try:
        inventory = collect(a.src)
        write_json(inventory, a.out)
    except SourceError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2

    s = inventory["summary"]
    print("%d exported control methods across %d classes (%s)"
          % (s["methods"], len(s["by_owning_class"]),
             inventory["source"]["driver_version"] or "unknown version"))
    for reach in (REACH_NON_PRIVILEGED, REACH_PRIVILEGED, REACH_KERNEL_ONLY,
                  REACH_INTERNAL):
        print("  %-16s %d" % (reach, s["by_reachability"].get(reach, 0)))
    print("  %-16s %d" % ("test only", s["test_only"]))
    print("  %-16s %d" % ("no local impl", s["handler_compiled_out"]))
    print("  %-16s %d" % ("rejected", inventory["scan"]["rejected_count"]))
    print("wrote %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
