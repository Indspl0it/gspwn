#!/usr/bin/env python3
"""Derive value families for bare integer parameter fields, and audit them.

A bare integer field in a parameter struct reaches its real values only by
mutation. A field bound to the right value family reaches them by
construction. A field bound to the wrong family is worse than a bare integer,
because the bare integer still reaches its values by mutation and the wrong
family never does. Every family this tool derives is therefore written to an
audit file as `accepted` or `rejected`, and only the accepted set is fit to
emit.

Two rules derive a family. Neither is a substring match on a class prefix; a
class-prefix rule binds 265 fields and 210 of them to defines belonging to a
different field.

Rule 1, struct-or-stem anchored. A define joins the family of struct S field F
when its name begins with S, or with S stripped of a trailing `_PARAMS`,
`_PARAMETERS` or `_INFO`, followed by F in upper snake case and a separator.
The anchor is the whole struct name, so a define belonging to a neighbouring
command cannot reach the field.

Rule 2, handler switch statements. A `switch (pParams->field)` inside the
handler for a known control command enumerates the values that handler
distinguishes. No name matching takes part. The binding to a struct comes from
`surface/rm-control-inventory.json`: the handler names a row, the row names a
`param_struct`, and the switch variable is checked against that struct's type
in the handler's own parameter list. Keying a switch on a bare field name
would give every struct with a field called `flags` one family, which is the
defect Rule 1 exists to avoid.

Four exclusions apply to both rules.

A define a longer-anchored sibling field of the same struct also matches
belongs to that sibling. `NV2080_CTRL_GPU_GET_PIDS_PARAMS` declares `id` and
`idType`, and the anchor for `id` reaches every `<STEM>_ID_TYPE_*` define,
which is the same class of error as the class-prefix rule at one field's
remove. The longer anchor wins and the shorter field keeps what is left.

`_MESSAGE_ID` defines are RPC message identifiers and never values.

A define whose body is a `hi:lo` bit range states a bit position, and an
integer parse of one produces nothing an emitted set can use. 796 of the 10369
defines under `src/common/sdk/nvidia/inc/ctrl` carry that form, 7.7%, with
`NV0000_CTRL_GPU_ID_INFO_IN_USE  0:0` among them; 41622 carry it across the
whole in-scope header set. Such defines are dropped before a family is
assembled and the dropped count is recorded in the artefact summary.

Depth then decides what the surviving members mean. A bit range whose name is
the field's own anchor describes the whole field, so its members are the
field's values:
`NV0080_CTRL_FIFO_GET_ENGINE_CONTEXT_PROPERTIES_ENGINE_ID` is `4:0` and its 26
members are the engine ids. A bit range whose name extends that anchor
describes one bit inside the word, so its members are that bit's states:
`NV2080_CTRL_PERF_BOOST_FLAGS_ASYNC` is `5:5` and its `_NO` and `_YES` members
would constrain the whole `flags` word to 0 and 1. The second shape is
rejected as a bitfield even though two values pass the distinct-value test
below. A family the switch rule derived is exempt, because the handler
compares the field itself against those values.

A family of fewer than two distinct resolved values is dropped. One constant
is a pin and pins are handled elsewhere. Deduplication runs on the resolved
value, so two names for one value are one value.

Scope is the escape, uvm, uvm_tools, control and alloc families. The modeset
and drm families are out of scope and both are recorded in the audit artefact
with that reason, so a later reader finds a decision and not an omission.

    python3 tools/value_families.py --out surface/value-families.json \\
        --audit-out surface/value-families-audit.json

The audit verdicts come from two places. The rejection rules named above are
mechanical, the tool applies them, and acceptance is the branch a family
reaches when none of them fires. A verdict recorded by hand overrides the
mechanical one through MANUAL_VERDICTS below and carries
`verdict_source: "read"`, which is the only place the record claims a header
was read for that family. MANUAL_VERDICTS holds two entries, both rejections,
against 53 families accepted mechanically. A rejection reason names what the
defines actually belong to, and "not a match" is not a reason.
"""
import argparse
import bisect
import collections
import json
import logging
import os
import re
import sys

logger = logging.getLogger(__name__)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))

import atomic_write  # noqa: E402  (path set above so the tool runs from anywhere)
import syzlang_gen  # noqa: E402

SCHEMA = "gspwn.value-families/1"
AUDIT_SCHEMA = "gspwn.value-families-audit/1"

DEFAULT_SRC = os.path.join(REPO_ROOT, "artifacts", "src",
                           "open-gpu-kernel-modules")
DEFAULT_DESCRIPTIONS = os.path.join(REPO_ROOT, "descriptions")
DEFAULT_CONTROL_INVENTORY = os.path.join(REPO_ROOT, "surface",
                                         "rm-control-inventory.json")
DEFAULT_OUT = os.path.join(REPO_ROOT, "surface", "value-families.json")
DEFAULT_AUDIT_OUT = os.path.join(REPO_ROOT, "surface",
                                 "value-families-audit.json")

VERSION_MK = "version.mk"

# The description files carrying the in-scope families. nvidia_structs.txt
# holds every parameter struct including the modeset and drm ones, so file
# membership does not decide scope. The header a struct is defined in does,
# through scope_of().
DESCRIPTION_FILES = ("nvidia.txt", "nvidia_ctrl.txt", "nvidia_uvm.txt",
                     "nvidia_structs.txt")

# Header roots read for define names. The modeset and drm interface trees are
# absent because their families are out of scope.
DEFINE_ROOTS = (
    "src/common/sdk",
    "src/common/inc",
    "src/common/unix",
    "kernel-open/nvidia-uvm",
    "kernel-open/common/inc",
    "src/nvidia/arch/nvalloc/unix/include",
)

# Source roots walked for handler bodies.
HANDLER_ROOTS = ("src/nvidia", "src/common")

STEM_SUFFIXES = ("_PARAMS", "_PARAMETERS", "_INFO")
MESSAGE_ID_SUFFIX = "_MESSAGE_ID"
MIN_DISTINCT_VALUES = 2

RULE_ANCHORED = "struct-or-stem-anchored"
RULE_SWITCH = "handler-switch"

# Header provenance placing a struct in an out-of-scope family. A modeset
# struct reaches the description set from three places: the modeset interface
# tree, the nvkms headers shared with kernel-open, and the two display headers
# under src/common/unix that only the modeset path uses.
DRM_HEADER_PREFIXES = ("kernel-open/nvidia-drm/",)
MODESET_HEADER_PREFIXES = ("src/nvidia-modeset/",)
MODESET_BASENAME_PREFIXES = ("nvkms",)
MODESET_BASENAMES = ("nv_mode_timings.h", "nv_dpy_id.h")

OUT_OF_SCOPE_FAMILIES = {
    "modeset": "Value-family recovery does not run over the modeset family. "
               "The family landed after the cost of this work was estimated, "
               "and re-estimating it is scope growth beyond what folding the "
               "family in required. The exclusion is a decision, not a gap in "
               "the derivation.",
    "drm": "Value-family recovery does not run over the drm family. The "
           "family landed after the modeset family on the same reasoning and "
           "inherits the same exclusion. The exclusion is a decision, not a "
           "gap in the derivation.",
}

BIT_RANGE_RE = re.compile(r"^\(?\s*(\d+)\s*:\s*(\d+)\s*\)?$")
DEFINE_RE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+(\S.*?)"
                       r"[ \t]*$", re.M)
STRUCT_LINE_RE = re.compile(r"^(\w+)\s*\{$")
FIELD_LINE_RE = re.compile(r"^\t(\w+)\s+(.+?)\s*$")
BARE_INT_RE = re.compile(r"int\d+$")
# A field this rule already owns, rendered by a previous emission. The set
# name is checked against the one set_name computes for that struct and field,
# so a field carrying one of the sets written by hand stays outside the
# universe. Without this the universe would be a moving target: the emitter
# retypes an accepted field, the next derivation no longer sees a bare integer
# there, and the family the audit accepted disappears.
OWN_FLAGS_RE = re.compile(r"^flags\[([A-Za-z_]\w*),\s*int\d+\]$")
CASE_RE = re.compile(r"\bcase\s+([A-Za-z_]\w*|0[xX][0-9a-fA-F]+|\d+)\s*:")
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
# A control constant is sometimes an enumerator and not a macro:
# `NV0080_CTRL_FB_DEFAULT_VIDMEM_PHYSICALITY_DEFAULT = 0,` in ctrl0080fb.h.
# The enumerator carries no #define site, so its line is recorded separately
# and used only when no macro of that name exists.
ENUMERATOR_RE = re.compile(r"^[ \t]*([A-Za-z_]\w*)[ \t]*(?:=[^,\n]*)?,", re.M)
BOOLEAN_SUFFIXES = ("_FALSE", "_TRUE")

# NVOC generates a thunk under the exported handler name and puts the body in
# a function suffixed _IMPL. The inventory records the exported name, so a
# scan anchored on that name alone reaches 3 of the 1315 handlers.
IMPL_SUFFIX = "_IMPL"

DefineSite = collections.namedtuple("DefineSite", "name expr header line")
DefineScan = collections.namedtuple(
    "DefineScan",
    "sites enumerators bit_range_names dropped_bit_range headers")


class SourceError(Exception):
    """A source tree or artefact could not be read as this tool expects."""


# ---------------------------------------------------------------------------
# Hand-recorded verdicts
# ---------------------------------------------------------------------------

# Keyed on (struct, field). Each entry overrides the mechanical verdict and
# was written after reading the header named in its evidence. The `always`
# flag records a family in the audit even when neither rule derives it, so a
# known defect stays visible as a decision.
MANUAL_VERDICTS = {
    ("NV2080_CTRL_PERF_BOOST_PARAMS", "duration"): {
        "verdict": "rejected",
        "reason":
            "NV2080_CTRL_PERF_BOOST_DURATION_MAX and "
            "NV2080_CTRL_PERF_BOOST_DURATION_INFINITE at "
            "src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080perf.h:92-93 are "
            "an upper bound and a sentinel, and the header says so: the "
            "comment on MAX reads \"The duration can be specified up to 1 "
            "hour\" and the comment on INFINITE reads \"If set this way, the "
            "boost will last until cleared\". duration is a free integer of "
            "seconds over 0 to 3600 plus that sentinel. A set holding 3600 "
            "and 0xffffffff would remove every legal duration between them.",
        "evidence": {
            "header":
                "src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080perf.h",
            "lines": [92, 93],
            "defines": ["NV2080_CTRL_PERF_BOOST_DURATION_MAX",
                        "NV2080_CTRL_PERF_BOOST_DURATION_INFINITE"],
            "values": [3600, 4294967295],
        },
    },
    ("NV0000_CTRL_GPU_ACTIVE_DEVICE", "gpuId"): {
        "verdict": "rejected",
        "always": True,
        "rule": RULE_ANCHORED,
        "reason":
            "The 23 NV0000_CTRL_GPU_ID_INFO_* defines at "
            "src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000gpu.h:189-211 "
            "belong to the gpuId bitfield of NV0000_CTRL_GPU_ID_INFO_PARAMS, "
            "a different field in a different struct. They are also not "
            "values: NV0000_CTRL_GPU_ID_INFO_IN_USE is the bit range 0:0 and "
            "the _FALSE and _TRUE members are that one bit's two states. The "
            "gpuId of NV0000_CTRL_GPU_ACTIVE_DEVICE, declared at "
            "ctrl0000gpu.h:995, is an opaque identifier the driver returns "
            "and carries no enumeration. A class-prefix rule bound the two "
            "together; the struct-or-stem anchor does not derive the family "
            "at all, and this record states the decision so the defect stays "
            "visible.",
        "evidence": {
            "header": "src/common/sdk/nvidia/inc/ctrl/ctrl0000/ctrl0000gpu.h",
            "lines": [189, 211, 995],
            "defines": ["NV0000_CTRL_GPU_ID_INFO_IN_USE",
                        "NV0000_CTRL_GPU_ID_INFO_IN_USE_FALSE",
                        "NV0000_CTRL_GPU_ID_INFO_IN_USE_TRUE"],
            "values": [],
        },
    },
}


# ---------------------------------------------------------------------------
# Reading the source tree
# ---------------------------------------------------------------------------

def read_driver_version(src_root):
    """The NVIDIA_VERSION string from version.mk, or None when it is absent."""
    path = os.path.join(src_root, VERSION_MK)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        raise SourceError("cannot read %s: %s" % (path, exc))
    m = re.search(r"^NVIDIA_VERSION\s*=\s*(\S+)", text, re.M)
    return m.group(1) if m else None


def is_bit_range(expr):
    """True when a define body states a `hi:lo` bit range and not a value.

    NVIDIA writes bitfield positions as `0:0` and `4:3`. An integer parse of
    one produces nothing an emitted set can use, so these are dropped before a
    family is assembled.
    """
    return BIT_RANGE_RE.match(expr.strip()) is not None


def scope_of(header):
    """The out-of-scope family a header belongs to, or None when in scope."""
    if header is None:
        return None
    header = header.replace(os.sep, "/")
    base = header.rsplit("/", 1)[-1]
    if header.startswith(DRM_HEADER_PREFIXES):
        return "drm"
    if header.startswith(MODESET_HEADER_PREFIXES):
        return "modeset"
    if base.startswith(MODESET_BASENAME_PREFIXES) or base in MODESET_BASENAMES:
        return "modeset"
    return None


def scan_defines(src):
    """-> a DefineScan over the in-scope header roots.

    Every define is recorded with the header and line it was written on, so an
    audit entry can cite them. A define whose body is a bit range is counted,
    its name kept in `bit_range_names`, and the define itself dropped.
    """
    sites = collections.defaultdict(list)
    enumerators = {}
    bit_range_names = set()
    dropped_bit_range = 0
    headers = 0
    for root_rel in DEFINE_ROOTS:
        root = os.path.join(src, root_rel.replace("/", os.sep))
        if not os.path.isdir(root):
            raise SourceError(
                "define root not found: %s\nExpected a checkout of "
                "NVIDIA/open-gpu-kernel-modules at %s. Pass --src if it lives "
                "elsewhere." % (root, src))
        for dirpath, _dirnames, filenames in os.walk(root):
            for filename in filenames:
                if not filename.endswith(".h"):
                    continue
                path = os.path.join(dirpath, filename)
                rel = os.path.relpath(path, src).replace(os.sep, "/")
                if scope_of(rel) is not None:
                    continue
                try:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                except OSError as exc:
                    raise SourceError("cannot read %s: %s" % (path, exc))
                headers += 1
                line_of = _line_index(text)
                for m in DEFINE_RE.finditer(text):
                    name, expr = m.group(1), m.group(2)
                    expr = re.sub(r"/\*.*", "", expr).strip()
                    if is_bit_range(expr):
                        dropped_bit_range += 1
                        bit_range_names.add(name)
                        continue
                    sites[name].append(
                        DefineSite(name, expr, rel, line_of(m.start(1))))
                for m in ENUMERATOR_RE.finditer(text):
                    name = m.group(1)
                    if name not in enumerators:
                        enumerators[name] = DefineSite(
                            name, "", rel, line_of(m.start(1)))
    logger.info("read %d headers: %d define names, %d bit-range defines "
                "dropped over %d names", headers, len(sites),
                dropped_bit_range, len(bit_range_names))
    return DefineScan(dict(sites), enumerators, bit_range_names,
                      dropped_bit_range, headers)


def bitfield_stem(name, bit_range_names):
    """-> the bit-range define this name is a state of, or None.

    `NV0000_CTRL_GPU_ID_INFO_IN_USE_TRUE` is a state of
    `NV0000_CTRL_GPU_ID_INFO_IN_USE`, whose body is the bit range `0:0`. The
    longest matching stem is returned so a nested bitfield reports the
    innermost one.
    """
    parts = name.split("_")
    for i in range(len(parts) - 1, 0, -1):
        stem = "_".join(parts[:i])
        if stem in bit_range_names:
            return stem
    return None


def _line_index(text):
    """-> a function mapping a character offset to a 1-based line number."""
    starts = [0]
    for m in re.finditer(r"\n", text):
        starts.append(m.end())

    def line_of(offset):
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1
    return line_of


def in_scope_field(struct, field, rendered):
    """Whether one emitted field is inside the universe this rule constrains.

    A bare intN is, and so is a field already bound to the set this rule names
    for it. A handle, a pinned const, an array or one of the sets written by
    hand is outside, so an accepted family never displaces one of those.

    The second case makes the derivation a fixed point over its own output.
    Reading a bare integer alone would make each emission shrink the universe
    the next derivation sees, and every family the audit accepted would
    disappear on the run after the one that bound it.
    """
    if BARE_INT_RE.match(rendered):
        return True
    match = OWN_FLAGS_RE.match(rendered)
    return match is not None and match.group(1) == set_name(struct, field)


def load_bare_int_fields(descriptions_dir):
    """-> struct name -> [field name] for every in-scope field emitted.

    The universe this phase constrains, as in_scope_field defines it.
    """
    return _load_fields(descriptions_dir, bare_only=True)


def load_struct_fields(descriptions_dir):
    """-> struct name -> [field name] for every field the struct declares.

    Read beside the bare-integer universe because a sibling field decides
    whether an anchored define belongs to the field that matched it. `id` and
    `idType` share the anchor `<STEM>_ID_`, and every define under it belongs
    to `idType`.
    """
    return _load_fields(descriptions_dir, bare_only=False)


def _load_fields(descriptions_dir, bare_only):
    bare = collections.OrderedDict()
    for name in DESCRIPTION_FILES:
        path = os.path.join(descriptions_dir, name)
        if not os.path.isfile(path):
            raise SourceError(
                "description file not found at %s\nRegenerate the description "
                "set first; this tool never falls back to a built-in copy."
                % path)
        current = None
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    m = STRUCT_LINE_RE.match(line)
                    if m:
                        current = m.group(1)
                        continue
                    if line.startswith("}"):
                        current = None
                        continue
                    if current is None:
                        continue
                    f = FIELD_LINE_RE.match(line)
                    if not f:
                        continue
                    if bare_only and not in_scope_field(current, f.group(1),
                                                        f.group(2)):
                        continue
                    bare.setdefault(current, [])
                    if f.group(1) not in bare[current]:
                        bare[current].append(f.group(1))
        except OSError as exc:
            raise SourceError("cannot read %s: %s" % (path, exc))
    return bare


def load_json(path, what):
    """-> the artefact at `path` as an object.

    Every caller inside this module and every caller outside it indexes the
    result by name. A file holding a list or a bare number is valid JSON and
    fails later as an AttributeError or a TypeError from inside a
    comprehension, naming neither the file nor the field, so the top-level
    shape is checked here where the path is still in hand.
    """
    if not os.path.isfile(path):
        raise SourceError(
            "%s not found at %s\nRegenerate it first; this tool never falls "
            "back to a stale or built-in copy." % (what, path))
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as exc:
        raise SourceError("cannot read %s: %s" % (path, exc))
    except ValueError as exc:
        raise SourceError("%s at %s is not valid JSON: %s"
                          % (what, path, exc))
    if not isinstance(doc, dict):
        raise SourceError(
            "%s at %s holds a %s at the top level, and this tool reads it as "
            "an object with named fields."
            % (what, path, type(doc).__name__))
    return doc


# ---------------------------------------------------------------------------
# Rule 1: struct-or-stem anchored defines
# ---------------------------------------------------------------------------

def upper_snake(field):
    """-> a struct field name in the upper snake case the defines use."""
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", field)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", text)
    return text.upper()


def stems(struct):
    """-> the struct name and the anchors derived by dropping one suffix."""
    out = [struct]
    for suffix in STEM_SUFFIXES:
        if struct.endswith(suffix) and len(struct) > len(suffix):
            stem = struct[:-len(suffix)]
            if stem not in out:
                out.append(stem)
    return out


def anchored_defines(struct, field, define_names):
    """-> the define names anchored to this struct and field, sorted.

    A name qualifies when it begins with an anchor, then the field in upper
    snake case, then a separator. The trailing separator keeps the base define
    of a bitfield out: `<ANCHOR>_<FIELD>` alone names the field, and only
    `<ANCHOR>_<FIELD>_<SOMETHING>` names one of its values.

    `define_names` is a sorted sequence, so each anchor costs a bisect and not
    a pass over the define table. Any other collection is sorted on entry.
    """
    if not isinstance(define_names, list):
        define_names = sorted(define_names)
    hits = set()
    for prefix in anchors(struct, field):
        start = bisect.bisect_left(define_names, prefix)
        for i in range(start, len(define_names)):
            if not define_names[i].startswith(prefix):
                break
            hits.add(define_names[i])
    return sorted(hits)


def anchors(struct, field):
    """-> the define-name prefixes that bind a define to this field."""
    snake = upper_snake(field)
    return tuple(stem + "_" + snake + "_" for stem in stems(struct))


def sibling_owned(struct, field, siblings, names):
    """-> the names a longer-anchored sibling field of the same struct owns.

    `NV2080_CTRL_GPU_GET_PIDS_PARAMS` declares `id` and `idType`. The anchor
    for `id` is `<STEM>_ID_`, which every `<STEM>_ID_TYPE_*` define starts
    with, so `id` matches defines belonging to `idType`. The longer anchor
    wins: a define reachable from a sibling whose upper snake name extends
    this field's is that sibling's, and is subtracted here.
    """
    snake = upper_snake(field)
    owned = set()
    for other in siblings:
        other_snake = upper_snake(other)
        if other_snake == snake or not other_snake.startswith(snake + "_"):
            continue
        owned.update(name for name in names
                     if name.startswith(anchors(struct, other)))
    return owned


# ---------------------------------------------------------------------------
# Rule 2: handler switch statements
# ---------------------------------------------------------------------------

def handler_param_structs(inventory):
    """-> handler name -> param struct, for handlers naming exactly one.

    A handler that several inventory rows give different parameter structs is
    omitted: the switch could not be bound to one struct without choosing, and
    choosing is the defect this rule exists to avoid.
    """
    seen = collections.defaultdict(set)
    for method in inventory.get("methods", []):
        handler = method.get("handler")
        struct = method.get("param_struct")
        if handler and struct:
            seen[handler].add(struct)
    return {h: next(iter(v)) for h, v in seen.items() if len(v) == 1}


def match_brace(text, open_index):
    """-> the index just past the brace closing the one at open_index."""
    depth = 0
    i = open_index
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise SourceError("unbalanced brace at offset %d" % open_index)


def params_variable(param_list, struct):
    """-> the parameter name declared with this struct type, or None."""
    for decl in param_list.split(","):
        decl = decl.strip()
        if not decl:
            continue
        words = re.findall(r"[A-Za-z_]\w*", decl.replace("*", " * "))
        if not words:
            continue
        name = words[-1]
        types = set(words[:-1])
        if struct in types:
            return name
    return None


def top_level_cases(body):
    """-> the case labels of a switch body, excluding any nested switch.

    Depth is counted in braces from the start of the body, so a case inside a
    nested switch or a compound statement is skipped.
    """
    labels = []
    depth = 0
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        elif depth == 0:
            m = CASE_RE.match(body, i)
            if m:
                labels.append(m.group(1))
                i = m.end()
                continue
        i += 1
    return labels


def scan_switches(src, handler_structs):
    """-> (struct, field) -> sorted case labels, plus the scan counters.

    A switch counts only when its subject variable is the parameter declared
    with the struct the command's inventory row names. A switch over some
    other pointer in the same handler is skipped and counted.
    """
    found = collections.defaultdict(set)
    counters = collections.Counter()
    if not handler_structs:
        return {}, counters
    for root_rel in HANDLER_ROOTS:
        root = os.path.join(src, root_rel.replace("/", os.sep))
        if not os.path.isdir(root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            for filename in filenames:
                if not filename.endswith(".c"):
                    continue
                path = os.path.join(dirpath, filename)
                rel = os.path.relpath(path, src).replace(os.sep, "/")
                try:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        raw = fh.read()
                except OSError as exc:
                    raise SourceError("cannot read %s: %s" % (path, exc))
                counters["c_files_read"] += 1
                if "switch" not in raw:
                    continue
                text = syzlang_gen.strip_comments(raw)
                _scan_file_switches(text, rel, handler_structs, found,
                                    counters)
    return ({k: sorted(v) for k, v in found.items()}, counters)


def _scan_file_switches(text, rel, handler_structs, found, counters):
    """Read every handler definition in one translation unit.

    Function names are matched generically and looked up in the handler set,
    so the pass costs one scan of the file whatever the size of that set.
    """
    seen_file = False
    for m in CALL_RE.finditer(text):
        name = m.group(1)
        handler = (name[:-len(IMPL_SUFFIX)] if name.endswith(IMPL_SUFFIX)
                   else name)
        if handler not in handler_structs:
            continue
        if not seen_file:
            counters["files_with_a_handler"] += 1
            seen_file = True
        close = text.find(")", m.end())
        if close < 0:
            continue
        tail = text[close + 1:close + 64].lstrip()
        if not tail.startswith("{"):
            continue
        counters["handler_definitions"] += 1
        open_index = text.index("{", close + 1)
        try:
            end = match_brace(text, open_index)
        except SourceError:
            counters["unbalanced_handler_bodies"] += 1
            continue
        struct = handler_structs[handler]
        variable = params_variable(text[m.end():close], struct)
        if variable is None:
            counters["handlers_without_a_typed_params_argument"] += 1
            continue
        body = text[open_index + 1:end - 1]
        switch_re = re.compile(
            r"switch\s*\(\s*(?:\(\s*\w+\s*\)\s*)?%s\s*->\s*(\w+)\s*\)\s*\{"
            % re.escape(variable))
        for sw in switch_re.finditer(body):
            counters["switches_bound"] += 1
            try:
                sw_end = match_brace(body, body.index("{", sw.end() - 1))
            except (SourceError, ValueError):
                counters["unbalanced_switch_bodies"] += 1
                continue
            labels = top_level_cases(body[sw.end():sw_end - 1])
            if labels:
                found[(struct, sw.group(1))].update(labels)
                counters["switches_with_a_case"] += 1
        logger.debug("%s: read handler %s", rel, handler)


# ---------------------------------------------------------------------------
# Assembling and filtering a family
# ---------------------------------------------------------------------------

def resolve_values(index, names):
    """-> ([(name, value)], [unresolved name]).

    A name whose expression is not an integer is unresolved. An emitted set
    needs the number, so an unresolved member cannot join a family.
    """
    resolved = []
    unresolved = []
    for name in names:
        value = index.const(name) if name in index.defines else None
        if value is None and re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", name):
            value = int(name, 0)
        if value is None:
            unresolved.append(name)
        else:
            resolved.append((name, value))
    return resolved, unresolved


def set_name(struct, field):
    """-> the syzlang identifier for this family's flags set."""
    return "%s_%s" % (struct.lower(), upper_snake(field).lower())


def build_family(struct, field, rule, names, index, define_sites,
                 bit_range_names, siblings=(), enumerator_sites=None):
    """-> one derived family record, or None when an exclusion drops it."""
    owned = sibling_owned(struct, field, siblings, names)
    kept = [n for n in names if n not in owned]
    dropped_sibling = len(owned)
    before = len(kept)
    kept = [n for n in kept if not n.endswith(MESSAGE_ID_SUFFIX)]
    dropped_message_id = before - len(kept)
    before = len(kept)
    kept = [n for n in kept if n not in bit_range_names]
    dropped_bit_range = before - len(kept)
    resolved, unresolved = resolve_values(index, kept)
    distinct = sorted({v for _n, v in resolved})
    if len(distinct) < MIN_DISTINCT_VALUES:
        return None
    enumerator_sites = enumerator_sites or {}
    sites = []
    for name, value in resolved:
        site = (define_sites.get(name) or [enumerator_sites.get(name)])[0]
        sites.append({
            "define": name,
            "value": value,
            "header": site.header if site else None,
            "line": site.line if site else None,
            "bitfield_stem": bitfield_stem(name, bit_range_names),
        })
    headers = sorted({s["header"] for s in sites if s["header"]})
    return {
        "struct": struct,
        "field": field,
        "rule": rule,
        "set_name": set_name(struct, field),
        "defines": [s["define"] for s in sites],
        "values": distinct,
        "source_file": headers[0] if headers else None,
        "source_files": headers,
        "define_sites": sites,
        "excluded": {
            "sibling_owned": dropped_sibling,
            "message_id": dropped_message_id,
            "bit_range": dropped_bit_range,
            "unresolved": unresolved,
        },
    }


def is_bitfield_family(record):
    """True when every member is a state of a bit inside the field's word.

    Depth decides. `NV0080_CTRL_FIFO_GET_ENGINE_CONTEXT_PROPERTIES_ENGINE_ID`
    is the bit range `4:0` and its name is the field's own anchor, so the
    range describes the whole of `engineId` and its 26 members are the values
    that field takes. `NV2080_CTRL_PERF_BOOST_FLAGS_ASYNC` is the bit range
    `5:5` and its name extends the anchor for `flags`, so it describes one bit
    inside the word and its `_NO` and `_YES` members are that bit's states.
    Emitting the second as a value family would constrain the whole word to 0
    and 1.

    A family the switch rule derived is never a bitfield by this test. The
    handler compares the field itself against those values, which is direct
    evidence about the field and outranks any shape its define names carry.
    """
    if RULE_SWITCH in (record.get("rule") or ""):
        return False
    sites = record.get("define_sites") or []
    if not sites:
        return False
    field_anchors = tuple(a.rstrip("_") for a in
                          anchors(record["struct"], record["field"]))
    for site in sites:
        stem = site.get("bitfield_stem")
        if not stem or stem in field_anchors:
            return False
    return True


def bitfield_stems(record):
    """-> the bit-range defines this family's members are states of."""
    return sorted({site["bitfield_stem"]
                   for site in record.get("define_sites") or []
                   if site.get("bitfield_stem")})


def is_boolean_family(record):
    """True when the family is exactly a `_FALSE` and `_TRUE` pair."""
    if sorted(record["values"]) != [0, 1]:
        return False
    return all(name.endswith(BOOLEAN_SUFFIXES)
               for name in record["defines"])


# ---------------------------------------------------------------------------
# Derivation
# ---------------------------------------------------------------------------

def derive(src, descriptions_dir, control_inventory_path):
    """-> the value-families artefact as a dict.

    Both rules run over the same universe: bare intN fields of in-scope
    parameter structs in the committed description set.
    """
    index = syzlang_gen.scan_headers(src)
    scan = scan_defines(src)
    define_sites = scan.sites
    bit_range_names = scan.bit_range_names
    sorted_names = sorted(define_sites)
    bare = load_bare_int_fields(descriptions_dir)
    declared = load_struct_fields(descriptions_dir)
    inventory = load_json(control_inventory_path, "RM control inventory")
    # `methods` is read by name three lines down and every row is indexed by
    # name. Checked here, where the path is still in hand, so a truncated or
    # hand-edited inventory names itself.
    methods = inventory.get("methods")
    if not isinstance(methods, list):
        raise SourceError(
            "the RM control inventory at %s holds a %s under `methods`, and "
            "that field is the list of control methods. Regenerate it with "
            "`python3 tools/ioctl_inventory.py control`."
            % (control_inventory_path, type(methods).__name__))
    for index_of_row, row in enumerate(methods):
        if not isinstance(row, dict):
            raise SourceError(
                "the RM control inventory at %s holds a %s at `methods[%d]`, "
                "and each row is an object carrying `handler` and "
                "`param_struct`."
                % (control_inventory_path, type(row).__name__, index_of_row))
    handler_structs = handler_param_structs(inventory)
    switches, switch_counters = scan_switches(src, handler_structs)

    in_scope = collections.OrderedDict()
    out_of_scope_fields = collections.Counter()
    no_home = 0
    for struct, fields in bare.items():
        header = index.source.get(struct)
        if header is None:
            header = index.source.get(index.canonical_struct(struct))
        if header is None:
            no_home += 1
            continue
        family = scope_of(header)
        if family is not None:
            out_of_scope_fields[family] += len(fields)
            continue
        in_scope[struct] = (header, fields)

    records = []
    anchored_hits = 0
    switch_hits = 0
    for struct, (header, fields) in in_scope.items():
        for field in fields:
            names = anchored_defines(struct, field, sorted_names)
            cases = switches.get((struct, field), [])
            rule = None
            if names and cases:
                rule = "%s+%s" % (RULE_ANCHORED, RULE_SWITCH)
                names = sorted(set(names) | set(cases))
            elif names:
                rule = RULE_ANCHORED
            elif cases:
                rule = RULE_SWITCH
                names = cases
            if rule is None:
                continue
            record = build_family(struct, field, rule, names, index,
                                  define_sites, bit_range_names,
                                  declared.get(struct, ()), scan.enumerators)
            if record is None:
                continue
            record["struct_header"] = header
            records.append(record)
            if RULE_ANCHORED in rule:
                anchored_hits += 1
            if RULE_SWITCH in rule:
                switch_hits += 1

    records.sort(key=lambda r: (r["struct"], r["field"]))
    switch_bound_fields = sorted(
        {"%s.%s" % (s, f) for (s, f) in switches
         if s in in_scope and f in in_scope[s][1]})

    return {
        "schema": SCHEMA,
        "source": {
            "src_root": os.path.relpath(src, REPO_ROOT).replace(os.sep, "/"),
            "driver_version": read_driver_version(src),
            "descriptions": os.path.relpath(
                descriptions_dir, REPO_ROOT).replace(os.sep, "/"),
            "control_inventory": os.path.relpath(
                control_inventory_path, REPO_ROOT).replace(os.sep, "/"),
            "define_roots": list(DEFINE_ROOTS),
            "handler_roots": list(HANDLER_ROOTS),
        },
        "scan": {
            "headers_read": scan.headers,
            "define_names": len(define_sites),
            "bit_range_defines_dropped": scan.dropped_bit_range,
            "bit_range_define_names": len(bit_range_names),
            "description_files": list(DESCRIPTION_FILES),
            "structs_with_a_bare_int": len(bare),
            "structs_with_no_located_header": no_home,
            "structs_in_scope": len(in_scope),
            "bare_int_fields_in_scope": sum(len(f) for _h, f in
                                            in_scope.values()),
            "bare_int_fields_out_of_scope": dict(out_of_scope_fields),
            "control_handlers_with_one_param_struct": len(handler_structs),
            "switch_scan": dict(switch_counters),
            "switch_bound_fields": len(switches),
            "switch_bound_fields_in_universe": len(switch_bound_fields),
            "stem_suffixes": list(STEM_SUFFIXES),
            "min_distinct_values": MIN_DISTINCT_VALUES,
        },
        "summary": {
            "families": len(records),
            "matched_by_anchored_rule": anchored_hits,
            "matched_by_switch_rule": switch_hits,
            "distinct_values": sum(len(r["values"]) for r in records),
        },
        "families": records,
    }


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def mechanical_verdict(record):
    """-> (verdict, reason) from the rules that need no header read.

    The reason states what these rules establish and no more. Acceptance is
    this function's default branch, so every accepted family reaches it, and a
    reason claiming a header read would put that claim on all of them: the
    audit records 53 accepted families and every one carries
    `verdict_source: "mechanical"`. A header read is recorded only under
    `verdict_source: "read"`, which MANUAL_VERDICTS supplies.

    The grounds differ by rule. The switch rule reads a handler comparing the
    field, and is_bitfield_family declines to run on a family it derived, so
    an accepted switch family has passed one mechanical test and an accepted
    anchored family has passed two.
    """
    if is_bitfield_family(record):
        return ("rejected",
                "Every define in this set is a state of the bit range "
                "%s, so the set describes bit positions inside the word and "
                "never the values the field takes. Emitting it would "
                "constrain the whole field to those bits' states."
                % ", ".join(bitfield_stems(record)))
    if is_boolean_family(record):
        return ("rejected",
                "The set is a _FALSE and _TRUE pair resolving to 0 and 1. It "
                "states one boolean, and the field it sits on holds more than "
                "that boolean.")
    rule = record.get("rule") or ""
    grounds = []
    if RULE_ANCHORED in rule:
        grounds.append("the define names are anchored on the struct name or "
                       "a stem of it")
    if RULE_SWITCH in rule:
        grounds.append("a control handler switches on this field and "
                       "compares it against these defines")
    ground = ", and ".join(grounds) or "the field carries this define set"
    if RULE_SWITCH in rule:
        tests = ("The set passes the boolean-pair test. The bit-range "
                 "decomposition test is not applied to a family the switch "
                 "rule derived, because the handler compares the field "
                 "itself.")
    else:
        tests = ("The set passes the bit-range decomposition test and the "
                 "boolean-pair test.")
    return ("accepted",
            "%s%s. %s No header was read for this family, and the verdict "
            "rests on those mechanical tests."
            % (ground[0].upper(), ground[1:], tests))


def audit(derivation):
    """-> the audit artefact as a dict.

    Every derived family appears with a verdict. The out-of-scope families
    appear beside them so a later reader finds a decision and not an omission.
    """
    entries = []
    counts = collections.Counter()
    for record in derivation["families"]:
        key = (record["struct"], record["field"])
        verdict, reason = mechanical_verdict(record)
        source = "mechanical"
        manual = MANUAL_VERDICTS.get(key)
        if manual:
            verdict = manual["verdict"]
            reason = manual["reason"]
            source = "read"
        counts[verdict] += 1
        entries.append({
            "struct": record["struct"],
            "field": record["field"],
            "rule": record["rule"],
            "set_name": record["set_name"],
            "verdict": verdict,
            "verdict_source": source,
            "reason": reason,
            "evidence": {
                "header": record["source_file"],
                "struct_header": record.get("struct_header"),
                "lines": [s["line"] for s in record["define_sites"]],
                "defines": record["defines"],
                "values": record["values"],
            },
        })

    derived = {(r["struct"], r["field"]) for r in derivation["families"]}
    for key, manual in sorted(MANUAL_VERDICTS.items()):
        if key in derived or not manual.get("always"):
            continue
        counts[manual["verdict"]] += 1
        counts["not_derived"] += 1
        entries.append({
            "struct": key[0],
            "field": key[1],
            "rule": manual.get("rule"),
            "set_name": set_name(*key),
            "verdict": manual["verdict"],
            "verdict_source": "read",
            "derived": False,
            "reason": manual["reason"],
            "evidence": manual["evidence"],
        })

    entries.sort(key=lambda e: (e["struct"], e["field"]))
    out_of_scope = [{"family": name, "verdict": "out_of_scope",
                     "reason": reason,
                     "bare_int_fields": derivation["scan"]
                     ["bare_int_fields_out_of_scope"].get(name, 0)}
                    for name, reason in sorted(OUT_OF_SCOPE_FAMILIES.items())]

    return {
        "schema": AUDIT_SCHEMA,
        "source": {
            "derivation": os.path.relpath(
                DEFAULT_OUT, REPO_ROOT).replace(os.sep, "/"),
            "derivation_schema": derivation["schema"],
            "src_root": derivation["source"]["src_root"],
            "driver_version": derivation["source"]["driver_version"],
        },
        "scan": {
            "families_derived": len(derivation["families"]),
            "families_recorded": len(entries),
            "recorded_without_derivation": counts["not_derived"],
            "verdicts_read_by_hand": sum(1 for e in entries
                                         if e["verdict_source"] == "read"),
        },
        "summary": {
            "accepted": counts["accepted"],
            "rejected": counts["rejected"],
            "out_of_scope_families": len(out_of_scope),
        },
        "out_of_scope": out_of_scope,
        "audit": entries,
    }


def accepted_families(derivation, audit_doc):
    """-> the derived records the audit accepted, for the emitter to bind.

    The join is on (struct, field). A record with no accepted audit entry is
    absent, so nothing reaches the emitter that the audit did not pass.
    """
    ok = {(e["struct"], e["field"]) for e in audit_doc.get("audit", [])
          if e.get("verdict") == "accepted"}
    return [r for r in derivation.get("families", [])
            if (r["struct"], r["field"]) in ok]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_json(document, out_path):
    """Serialise a document and hand the text to the shared durable writer.

    indent=2, sort_keys=False and the trailing newline are the committed shape
    of both family artefacts and regression_check.py stale hashes each one, so
    all three stay here where the document is serialised. atomic_write_text
    owns the temporary file, the LF line endings, the two fsyncs and the
    rename.
    """
    parent = os.path.dirname(os.path.abspath(out_path))
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as exc:
        raise SourceError("cannot create output directory %s: %s"
                          % (parent, exc))
    text = json.dumps(document, indent=2, sort_keys=False) + "\n"
    try:
        atomic_write.atomic_write_text(out_path, text)
    except OSError as exc:
        raise SourceError("cannot write %s: %s" % (out_path, exc))
    logger.info("wrote %s", out_path)


def main():
    ap = argparse.ArgumentParser(
        description="Derive value families for bare integer parameter fields "
                    "from the SDK headers and from control handler switch "
                    "statements, and write the audit decision record.")
    ap.add_argument("--src", default=DEFAULT_SRC,
                    help="open-gpu-kernel-modules checkout (default: %s)"
                         % os.path.relpath(DEFAULT_SRC, REPO_ROOT))
    ap.add_argument("--descriptions", default=DEFAULT_DESCRIPTIONS,
                    help="committed description set (default: %s)"
                         % os.path.relpath(DEFAULT_DESCRIPTIONS, REPO_ROOT))
    ap.add_argument("--control-inventory", default=DEFAULT_CONTROL_INVENTORY,
                    help="RM control inventory (default: %s)"
                         % os.path.relpath(DEFAULT_CONTROL_INVENTORY,
                                           REPO_ROOT))
    ap.add_argument("--out", default=DEFAULT_OUT,
                    help="derived families to write (default: %s)"
                         % os.path.relpath(DEFAULT_OUT, REPO_ROOT))
    ap.add_argument("--audit-out", default=DEFAULT_AUDIT_OUT,
                    help="audit record to write (default: %s)"
                         % os.path.relpath(DEFAULT_AUDIT_OUT, REPO_ROOT))
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log every handler read")
    a = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if a.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)

    if not os.path.isdir(a.src):
        print("error: --src %s is not a directory" % a.src, file=sys.stderr)
        return 2
    try:
        derivation = derive(a.src, a.descriptions, a.control_inventory)
        audit_doc = audit(derivation)
        write_json(derivation, a.out)
        write_json(audit_doc, a.audit_out)
    except SourceError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    scan = derivation["scan"]
    summary = derivation["summary"]
    print("%d value families over %d in-scope bare integer fields"
          % (summary["families"], scan["bare_int_fields_in_scope"]))
    print("  %-40s %d" % ("matched by the anchored rule",
                          summary["matched_by_anchored_rule"]))
    print("  %-40s %d" % ("matched by the switch rule",
                          summary["matched_by_switch_rule"]))
    print("  %-40s %d" % ("bit-range defines dropped",
                          scan["bit_range_defines_dropped"]))
    for family, count in sorted(scan["bare_int_fields_out_of_scope"].items()):
        print("  %-40s %d bare integer fields" % ("out of scope: " + family,
                                                  count))
    print("%d accepted, %d rejected"
          % (audit_doc["summary"]["accepted"],
             audit_doc["summary"]["rejected"]))
    print("wrote %s" % a.out)
    print("wrote %s" % a.audit_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
