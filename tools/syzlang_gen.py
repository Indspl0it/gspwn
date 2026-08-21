#!/usr/bin/env python3
"""Generate a first-cut syzlang description set from the measured inventories.

`agents/describe.md` calls this phase the one where fuzzing quality is decided,
and it starts from nothing on a live SUT. Three extractors have already
measured what it would otherwise transcribe by hand: `ioctl_inventory.py` has
the dispatched escapes and their request numbers, `ctrl_surface.py` has the RM
control command space with its privilege classification, and
`object_graph.py` has the allocation DAG that decides whether a generated
program reaches past the first handle check. This tool turns those three
records into syzlang, so the describe phase spends its SUT time on correction
and depth.

What the emitted set covers:

  Resources        one per RM object class, all deriving from nv_handle. The
                   client handle is produced by the NV01_ROOT allocation and
                   consumed by every later alloc, control and free.
  Device nodes     /dev/nvidiactl, /dev/nvidiaN, /dev/nvidia-uvm and
                   /dev/nvidia-uvm-tools. nvidia-drm, nvidia-modeset and
                   /dev/dri/* are excluded by the threat model, and a seed
                   referencing them fails the syzkaller parse gate.
  Escapes          one ioctl description per dispatched NV_ESC_*, carrying the
                   32-bit request number the inventory computed.
  Allocation       one NV_ESC_RM_ALLOC variant per unprivileged object class,
                   with hClass pinned to the class number, hObjectParent typed
                   as the legal parent's resource, and hObjectNew producing the
                   class's own resource.
  Control          one NV_ESC_RM_CONTROL variant per covered command, with the
                   command number pinned and the real parameter struct
                   attached. Modeling this ioctl as an opaque buffer wastes the
                   campaign (`agents/describe.md` step 4b).
  UVM              the /dev/nvidia-uvm and /dev/nvidia-uvm-tools commands,
                   whose numbers are bare `nr` values: UVM_IOCTL_BASE(i)
                   expands to i on Linux, so they carry no _IOC fields.

Struct layout is the part that cannot be copied from the inventories, which
carry struct names and sizes and no field layout. Layout is parsed out of the
driver headers here and the result is checked against the measured sizeof for
every struct. A struct whose parsed layout does not total its measured size is
wrong, and shipping it silently produces descriptions that compile, run and
never reach the driver, so every mismatch is reported and the struct falls back
to a correctly sized opaque array. `--strict` turns any mismatch into a
non-zero exit.

Control parameter structs are not in the escape inventory's measured set, so
this tool carries its own size probe in the same shape `ioctl_inventory.py`
uses:

    python3 tools/syzlang_gen.py emit-probe --probe-dir tmp/surface/syzprobe
    bash tmp/surface/syzprobe/measure_sizes.sh      # on a machine with gcc
    python3 tools/syzlang_gen.py emit \\
        --ctrl-sizes tmp/surface/syzprobe/sizes.json

The set is generated offline from a source checkout. No GPU, no SUT. It has
not been through syz-compile, which is the describe phase's first gate.

Subcommands:
  emit        write the description set, the _IOWR header and the manifest
  emit-probe  write the C size probes for the structs this tool needs
  verify      report the size-match table and nothing else
  summary     counts per category

Exit codes: 0 success, 1 bad input or unreadable source, 2 strict-mode
size mismatch.
"""
import argparse
import collections
import json
import logging
import os
import re
import sys

logger = logging.getLogger(__name__)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SRC = os.path.join(REPO_ROOT, "artifacts", "src",
                           "open-gpu-kernel-modules")
DEFAULT_SURFACE = os.path.join(REPO_ROOT, "artifacts", "surface")
DEFAULT_OUT = os.path.join(REPO_ROOT, "artifacts", "descriptions")

SCHEMA = "gspwn.syzlang-generation/1"

# openat's first argument. AT_FDCWD is -100, which syzkaller writes as the
# unsigned 64-bit value. A description missing this argument does not parse.
# tools/trace2seed.py documents the same failure on the seeds side.
AT_FDCWD = "0xffffffffffffff9c"

# Header trees the struct parser reads, relative to --src, longest include
# root first so a header's include path is computed against the right one.
INCLUDE_ROOTS = [
    os.path.join("kernel-open", "nvidia-uvm"),
    os.path.join("kernel-open", "common", "inc"),
    os.path.join("src", "common", "sdk", "nvidia", "inc"),
    os.path.join("src", "common", "inc"),
    os.path.join("src", "nvidia", "arch", "nvalloc", "unix", "include"),
]

# The include search path the probe compiles against. The SDK include
# directory comes ahead of kernel-open on purpose: two rs_access.h files exist
# with different include guards, and nvos.h picks up its own sibling copy
# through the quoted-include rule. A control header three directories down has
# no sibling and falls through to the -I order, so with kernel-open first the
# translation unit gets both copies and every RS_ACCESS type is a redefinition.
PROBE_INCLUDES = [
    os.path.join("kernel-open", "nvidia-uvm"),
    os.path.join("src", "common", "sdk", "nvidia", "inc"),
    os.path.join("kernel-open", "common", "inc"),
    os.path.join("src", "common", "inc"),
    os.path.join("src", "nvidia", "arch", "nvalloc", "unix", "include"),
]

# Class-number defines live under class/, and a few allocation parameter
# structs live beside them.
CLASS_DIR = os.path.join("src", "common", "sdk", "nvidia", "inc", "class")

# Base type sizes and alignments for x86-64 System V, which is the only
# architecture this campaign builds for. The driver's own nvtypes.h selects
# these through a stack of compiler conditionals; the table below is checked
# against the compiler on every run through the size probe, so a wrong entry
# shows up as a mismatch and never as a silently wrong description.
BASE_TYPES = {
    "void": (0, 1),
    "char": (1, 1), "signed char": (1, 1), "unsigned char": (1, 1),
    "NvU8": (1, 1), "NvS8": (1, 1), "NvV8": (1, 1), "NvBool": (1, 1),
    "uint8_t": (1, 1), "int8_t": (1, 1),
    "short": (2, 2), "unsigned short": (2, 2), "short int": (2, 2),
    "NvU16": (2, 2), "NvS16": (2, 2), "NvV16": (2, 2), "NvWchar": (2, 2),
    "uint16_t": (2, 2), "int16_t": (2, 2),
    "int": (4, 4), "unsigned int": (4, 4), "unsigned": (4, 4),
    "signed int": (4, 4), "float": (4, 4),
    "NvU32": (4, 4), "NvS32": (4, 4), "NvV32": (4, 4), "NvHandle": (4, 4),
    "NvF32": (4, 4), "NvBool32": (4, 4),
    "uint32_t": (4, 4), "int32_t": (4, 4),
    "long": (8, 8), "unsigned long": (8, 8), "long int": (8, 8),
    "long long": (8, 8), "unsigned long long": (8, 8), "double": (8, 8),
    "NvU64": (8, 8), "NvS64": (8, 8), "NvP64": (8, 8), "NvF64": (8, 8),
    "NvLength": (8, 8), "NvUPtr": (8, 8), "NvSPtr": (8, 8),
    "uint64_t": (8, 8), "int64_t": (8, 8), "size_t": (8, 8),
}

SYZ_INT = {1: "int8", 2: "int16", 4: "int32", 8: "int64"}

# NvP64 fields that carry a pointer to a further parameter buffer. Modeling
# them as a plain 64-bit integer stops the chain at the escape, so the two the
# ABI defines are typed as pointers where the pointee is known.
POINTER_FIELDS = {
    ("NVOS64_PARAMETERS", "pAllocParms"),
    ("NVOS21_PARAMETERS", "pAllocParms"),
    ("NVOS54_PARAMETERS", "params"),
}

# The escape whose parameter struct selects a further command number.
CONTROL_ESCAPE = "NV_ESC_RM_CONTROL"
ALLOC_ESCAPE = "NV_ESC_RM_ALLOC"
FREE_ESCAPE = "NV_ESC_RM_FREE"

ROOT_SENTINEL = "<root fd>"
ANY_PARENT_SENTINEL = "<any parent>"

# Allocation privilege values the modelled attacker does not hold. The three
# records carrying no RS_FLAGS_ALLOC_* flag at all are absent from this set on
# purpose: they are the root client classes, and every chain starts with one.
PRIVILEGED_ALLOC = {"privileged", "kernel"}

# The root client class. Its handle is the one every later call consumes.
ROOT_CLASS = "NV01_ROOT"

MAX_STRUCT_DEPTH = 24

# syzkaller refuses an array longer than this in a single field, and a
# description carrying one fails at the compile gate. Larger fixed arrays are
# emitted as a single opaque byte array.
MAX_ARRAY_ELEMENTS = 4096


class LayoutError(Exception):
    """A struct whose field layout could not be derived from the headers."""


Member = collections.namedtuple(
    "Member", "type name dims align inline_kind inline_members")

Field = collections.namedtuple("Field", "name offset size syz")

Layout = collections.namedtuple("Layout", "size align fields")


# ---------------------------------------------------------------------------
# C header parsing
# ---------------------------------------------------------------------------

COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
DEFINE_RE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+(\w+)[ \t]+(.+?)[ \t]*$", re.M)
AGGREGATE_RE = re.compile(r"\b(struct|union)\b(?:\s+(\w+))?\s*\{")
DECL_RE = re.compile(
    r"^(?P<type>[A-Za-z_][\w \t*]*?)[ \t*]+(?P<name>\w+)"
    r"(?P<dims>(?:\s*\[[^\]]*\])*)$")
ALIGN_BYTES_RE = re.compile(r"NV_ALIGN_BYTES\s*\(\s*(\d+)\s*\)")
# nv-ioctl-numa.h spells the same thing __aligned(8), and a few members carry
# a bare gcc attribute that changes no size.
ALIGNED_ATTR_RE = re.compile(r"__aligned\s*\(\s*(\d+)\s*\)")
ATTRIBUTE_RE = re.compile(r"__attribute__\s*\(\(.*?\)\)|\b__restrict\b|"
                          r"\bvolatile\b|\bconst\b")
ENUM_RE = re.compile(r"\benum\b(?:\s+(\w+))?\s*\{")
DECLARE_ALIGNED_RE = re.compile(r"^NV_DECLARE_ALIGNED\s*\((.*),\s*(\d+)\s*\)$",
                                re.S)
DIM_RE = re.compile(r"\[([^\]]*)\]")
# A hex literal contains letters, so an identifier pattern without the
# left-hand guard matches "x0" inside "0x0" and a macro expression that is
# already a plain number gets reported as unresolvable.
IDENT_RE = re.compile(r"(?<![\w.])[A-Za-z_]\w*")


def strip_comments(text):
    """Replace comments with a space so token boundaries survive."""
    return COMMENT_RE.sub(" ", text)


def select_first_branch(text):
    """Drop every preprocessor directive, keeping the first arm of each
    conditional block.

    The headers use conditionals for compiler and platform selection, and
    keeping every arm would double-count fields. The first arm is kept, which
    is the x86-64 gcc arm in every header this tool reads. A header where that
    is untrue shows up as a size mismatch, never as a wrong description.

    Directives are removed as well as the arms, because nvos.h places #define
    lines inside struct bodies. Leaving them in makes the member splitter read
    a define and the field after it as one declaration, and the whole struct
    is rejected.
    """
    out, skipping = [], []
    continuing = False
    for line in text.splitlines():
        stripped = line.lstrip()
        if continuing:
            continuing = line.rstrip().endswith("\\")
            continue
        if stripped.startswith("#if"):
            skipping.append(False)
            continuing = line.rstrip().endswith("\\")
            continue
        if stripped.startswith(("#else", "#elif")) and skipping:
            skipping[-1] = True
            continuing = line.rstrip().endswith("\\")
            continue
        if stripped.startswith("#endif"):
            if skipping:
                skipping.pop()
            continue
        if stripped.startswith("#"):
            continuing = line.rstrip().endswith("\\")
            continue
        if any(skipping):
            continue
        out.append(line)
    return "\n".join(out)


def match_brace(text, open_index):
    """Index just past the brace closing the one at open_index."""
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    raise LayoutError("unbalanced braces starting at offset %d" % open_index)


def split_statements(body):
    """Split a struct body into member statements at top-level semicolons."""
    parts, depth, cur = [], 0, []
    for ch in body:
        if ch in "{([":
            depth += 1
        elif ch in "})]":
            depth -= 1
        if ch == ";" and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return [p.strip() for p in parts if p.strip()]


def parse_dims(text):
    """Array dimensions as a list of expression strings."""
    return [d.strip() for d in DIM_RE.findall(text or "")]


def parse_member_statement(stmt):
    """One struct member statement as a list of Member records.

    Raises LayoutError for a construct whose layout cannot be derived, which
    at present means a bitfield: bitfield packing is compiler-defined and a
    guessed offset produces a description that reaches the wrong field.
    """
    stmt = " ".join(stmt.split())
    m = DECLARE_ALIGNED_RE.match(stmt)
    forced_align = None
    if m:
        stmt = " ".join(m.group(1).split())
        forced_align = int(m.group(2))
    for pattern in (ALIGN_BYTES_RE, ALIGNED_ATTR_RE):
        am = pattern.search(stmt)
        if am:
            forced_align = max(forced_align or 0, int(am.group(1)))
            stmt = " ".join(pattern.sub(" ", stmt).split())
    stmt = " ".join(ATTRIBUTE_RE.sub(" ", stmt).split())
    if ":" in stmt and "::" not in stmt:
        raise LayoutError("bitfield member %r" % stmt)
    if stmt.startswith(("typedef", "static", "enum ")):
        raise LayoutError("unsupported member declaration %r" % stmt)

    agg = AGGREGATE_RE.search(stmt)
    if agg and agg.start() == 0:
        end = match_brace(stmt, stmt.index("{", agg.start()))
        inner = stmt[stmt.index("{", agg.start()) + 1:end - 1]
        declarators = stmt[end:].strip()
        inline_members = []
        for sub in split_statements(inner):
            inline_members.extend(parse_member_statement(sub))
        kind = agg.group(1)
        if not declarators:
            return [Member("", "", [], forced_align, kind, inline_members)]
        out = []
        for decl in declarators.split(","):
            decl = decl.strip()
            dm = re.match(r"^(?P<name>\w+)(?P<dims>(?:\s*\[[^\]]*\])*)$", decl)
            if not dm:
                raise LayoutError("inline aggregate declarator %r" % decl)
            out.append(Member("", dm.group("name"), parse_dims(dm.group("dims")),
                              forced_align, kind, inline_members))
        return out

    # A plain declaration, possibly with several comma-separated declarators.
    head, _, rest = stmt.partition(",")
    first = DECL_RE.match(head.strip())
    if not first:
        raise LayoutError("member declaration %r" % stmt)
    base_type = " ".join(first.group("type").split())
    stars = head.count("*")
    if stars:
        base_type = base_type.replace("*", "").strip() + " *"
    members = [Member(base_type, first.group("name"),
                      parse_dims(first.group("dims")), forced_align,
                      None, None)]
    for decl in (d.strip() for d in rest.split(",") if d.strip()):
        dm = re.match(r"^\*?\s*(?P<name>\w+)(?P<dims>(?:\s*\[[^\]]*\])*)$",
                      decl)
        if not dm:
            raise LayoutError("declarator %r in %r" % (decl, stmt))
        members.append(Member(base_type, dm.group("name"),
                              parse_dims(dm.group("dims")), forced_align,
                              None, None))
    return members


class TypeIndex:
    """Struct definitions, typedef aliases and macro constants from headers.

    Thread-safety: not thread-safe. One instance per process.
    """

    def __init__(self):
        self.structs = {}       # name -> (kind, [Member])
        self.source = {}        # name -> header path relative to --src
        self.aliases = {}       # typedef name -> underlying type name
        self.alias_source = {}  # typedef name -> header declaring the alias
        self.defines = {}       # macro name -> expression text
        self.enums = set()      # enumeration type names
        self.parse_failures = collections.Counter()

    def scan_file(self, path, rel_path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        text = strip_comments(raw)
        for name, expr in DEFINE_RE.findall(text):
            if "(" in name:
                continue
            self.defines.setdefault(name, expr.strip())
        text = select_first_branch(text)
        self._scan_enums(text)
        self._scan_aggregates(text, rel_path)
        self._scan_typedef_aliases(text, rel_path)

    def _scan_enums(self, text):
        """Register enumeration type names.

        gcc on x86-64 gives an enumeration whose values fit in an int the size
        and alignment of unsigned int. An enumeration wide enough to need more
        would make its containing struct's total disagree with the measured
        sizeof, which the size check reports.
        """
        pos = 0
        while True:
            m = ENUM_RE.search(text, pos)
            if not m:
                return
            open_index = text.index("{", m.start())
            try:
                end = match_brace(text, open_index)
            except LayoutError:
                return
            self._record_enumerators(text[open_index + 1:end - 1])
            if m.group(1):
                self.enums.add(m.group(1))
            tail = re.match(r"\s*([^;{}]*);", text[end:])
            if tail:
                for decl in tail.group(1).split(","):
                    decl = decl.strip().lstrip("*").strip()
                    if re.fullmatch(r"\w+", decl):
                        self.enums.add(decl)
            pos = end

    def _scan_aggregates(self, text, rel_path):
        pos = 0
        while True:
            agg = AGGREGATE_RE.search(text, pos)
            if not agg:
                return
            open_index = text.index("{", agg.start())
            try:
                end = match_brace(text, open_index)
            except LayoutError as exc:
                logger.debug("%s: %s", rel_path, exc)
                return
            body = text[open_index + 1:end - 1]
            tag = agg.group(2)
            kind = agg.group(1)
            tail = text[end:]
            tm = re.match(r"\s*([^;{}]*);", tail)
            names = []
            if tag:
                names.append(tag)
            if tm:
                for decl in tm.group(1).split(","):
                    decl = decl.strip().lstrip("*").strip()
                    if re.fullmatch(r"\w+", decl):
                        names.append(decl)
            try:
                members = []
                for stmt in split_statements(body):
                    members.extend(parse_member_statement(stmt))
            except LayoutError as exc:
                for name in names:
                    self.parse_failures[name] += 1
                logger.debug("%s: %s", rel_path, exc)
                members = None
            for name in names:
                if name in BASE_TYPES:
                    # nvtypes.h has a type-safety build where NvHandle is a
                    # one-field struct. It is four bytes either way, and
                    # registering it as a struct would emit a syzlang wrapper
                    # around a plain handle.
                    continue
                if members is None:
                    self.structs.pop(name, None)
                    continue
                if name not in self.structs:
                    self.structs[name] = (kind, members)
                    self.source[name] = rel_path
            pos = end

    def _record_enumerators(self, body):
        """Record enumerator names as constants.

        An enumerator is a legal array bound, and ctrl2080gr.h uses one:
        `NvU64 vMemPtrs[NV2080_CTRL_CMD_GR_CTXSW_PREEMPTION_BIND_BUFFERS_END]`.
        Without the enumerator's value the bound does not evaluate and the
        whole containing struct falls back to an opaque array.
        """
        counter = 0
        depth = 0
        item = []
        items = []
        for ch in body:
            if ch in "({[":
                depth += 1
            elif ch in ")}]":
                depth -= 1
            if ch == "," and depth == 0:
                items.append("".join(item))
                item = []
                continue
            item.append(ch)
        items.append("".join(item))
        for entry in items:
            entry = entry.strip()
            if not entry:
                continue
            name, _, expr = entry.partition("=")
            name = name.strip()
            if not re.fullmatch(r"\w+", name):
                continue
            if expr.strip():
                value = self.const(expr)
                if value is None:
                    counter += 1
                    continue
                counter = value
            self.defines.setdefault(name, str(counter))
            counter += 1

    def _scan_typedef_aliases(self, text, rel_path):
        for m in re.finditer(r"\btypedef\s+([\w ]+?)\s+(\w+)\s*;", text):
            under, name = " ".join(m.group(1).split()), m.group(2)
            if name == under or "{" in under:
                continue
            if name not in self.aliases:
                self.aliases[name] = under
                self.alias_source[name] = rel_path

    # -- constant evaluation ------------------------------------------------

    def const(self, expr, depth=0):
        """Integer value of a macro expression, or None when it is not one."""
        if depth > 16:
            return None
        expr = expr.strip()
        if not expr:
            return None
        expr = re.sub(r"/\*.*?\*/", " ", expr)
        expr = re.sub(r"\b(\d+)[uUlL]+\b", r"\1", expr)
        expr = re.sub(r"\b(0[xX][0-9a-fA-F]+)[uUlL]+\b", r"\1", expr)
        expr = expr.replace("(NvU32)", "").replace("(NvU64)", "")
        names = set(IDENT_RE.findall(expr))
        for name in names:
            if name not in self.defines:
                return None
            value = self.const(self.defines[name], depth + 1)
            if value is None:
                return None
            expr = re.sub(r"(?<![\w.])%s\b" % re.escape(name),
                          "(%d)" % value, expr)
        if not re.fullmatch(r"[0-9xXa-fA-F()+\-*/ <>|&]*", expr):
            return None
        try:
            value = eval(expr, {"__builtins__": {}}, {})  # noqa: S307
        except (SyntaxError, NameError, TypeError, ZeroDivisionError,
                ValueError):
            return None
        return value if isinstance(value, int) else None

    # -- layout -------------------------------------------------------------

    def resolve_alias(self, name, depth=0):
        seen = set()
        while name in self.aliases and name not in seen and depth < 16:
            seen.add(name)
            name = self.aliases[name]
            depth += 1
        return name

    def canonical_struct(self, name):
        """The struct a name resolves to through typedef aliases.

        A control parameter type is often an alias for another command's
        struct: `typedef NV0080_CTRL_GR_GET_INFO_V2_PARAMS
        NV2080_CTRL_GR_GET_INFO_V2_PARAMS;`. Looking the alias up in the
        struct table alone reports 41 parameter types as undefined.
        """
        if name in self.structs:
            return name
        resolved = self.resolve_alias(name)
        for prefix in ("struct ", "union ", "enum "):
            if resolved.startswith(prefix):
                resolved = resolved[len(prefix):].strip()
        if resolved in self.structs:
            return resolved
        # nvos.h aliases a few allocation parameter types with the
        # preprocessor: `#define NV_BSP_ALLOCATION_PARAMETERS
        # NV_NVDEC_ALLOCATION_PARAMETERS`.
        seen = set()
        while resolved not in self.structs and resolved not in seen:
            seen.add(resolved)
            expr = self.defines.get(resolved)
            if expr is None or not re.fullmatch(r"\w+", expr.strip()):
                break
            resolved = self.resolve_alias(expr.strip())
        return resolved

    def size_align(self, type_name, depth):
        """(size, align, syzlang element type) for a non-array member type."""
        type_name = " ".join(type_name.split())
        if type_name.endswith("*"):
            return (8, 8, "int64")
        canonical = self.resolve_alias(type_name)
        if canonical in BASE_TYPES:
            size, align = BASE_TYPES[canonical]
            return (size, align, SYZ_INT.get(size, "int8"))
        for prefix in ("struct ", "union ", "enum "):
            if canonical.startswith(prefix):
                canonical = canonical[len(prefix):].strip()
        if canonical in self.enums and canonical not in self.structs:
            return (4, 4, "int32")
        if canonical in self.structs:
            sub = self.layout(canonical, depth + 1)
            return (sub.size, sub.align, canonical)
        raise LayoutError("unknown type %r" % type_name)

    def member_layout(self, member, owner, index, depth):
        """(size, align, syzlang type) for one member, arrays flattened."""
        if member.inline_kind:
            synthetic = "%s_%s%d" % (owner, member.inline_kind[0], index)
            self.structs[synthetic] = (member.inline_kind,
                                       member.inline_members)
            self.source.setdefault(synthetic, self.source.get(owner))
            sub = self.layout(synthetic, depth + 1)
            size, align, elem = sub.size, sub.align, synthetic
        else:
            size, align, elem = self.size_align(member.type, depth)
        count = 1
        for dim in member.dims:
            value = self.const(dim)
            if value is None or value <= 0:
                raise LayoutError(
                    "array dimension %r on %s.%s did not evaluate to a "
                    "positive integer" % (dim, owner, member.name))
            count *= value
        if count == 1:
            syz = elem
        elif count > MAX_ARRAY_ELEMENTS and elem in SYZ_INT.values():
            syz = "array[int8, %d]" % (size * count)
        else:
            syz = "array[%s, %d]" % (elem, count)
        if member.align:
            align = max(align, member.align)
        return (size * count, align, syz)

    def layout(self, name, depth=0):
        """Flat field layout of a struct or union, with offsets and padding.

        Raises LayoutError when any member's type or array bound could not be
        resolved. Nothing is guessed to complete a layout.
        """
        if depth > MAX_STRUCT_DEPTH:
            raise LayoutError("struct nesting deeper than %d at %r"
                              % (MAX_STRUCT_DEPTH, name))
        name = self.canonical_struct(name)
        if name not in self.structs:
            raise LayoutError("no definition for struct %r" % name)
        kind, members = self.structs[name]
        fields, offset, max_align = [], 0, 1
        union_size = 0
        for index, member in enumerate(members):
            size, align, syz = self.member_layout(member, name, index, depth)
            max_align = max(max_align, align)
            if kind == "union":
                fields.append(Field(member.name or "u%d" % index, 0, size,
                                    syz))
                union_size = max(union_size, size)
                continue
            padded = (offset + align - 1) // align * align
            if padded != offset:
                fields.append(Field("pad%d" % index, offset, padded - offset,
                                    None))
                offset = padded
            fields.append(Field(member.name or "f%d" % index, offset, size,
                                syz))
            offset += size
        total = union_size if kind == "union" else offset
        total = (total + max_align - 1) // max_align * max_align
        if kind != "union" and total != offset:
            fields.append(Field("pad_tail", offset, total - offset, None))
        return Layout(total, max_align, fields)


def scan_headers(src):
    """Parse every header under the include roots into one TypeIndex."""
    index = TypeIndex()
    scanned = 0
    for root_rel in INCLUDE_ROOTS:
        root = os.path.join(src, root_rel)
        if not os.path.isdir(root):
            raise SystemExit(
                "include root not found: %s\n"
                "Expected a checkout of NVIDIA/open-gpu-kernel-modules at %s. "
                "Pass --src if it lives elsewhere." % (root, src))
        for dirpath, _dirnames, filenames in os.walk(root):
            for filename in filenames:
                if not filename.endswith(".h"):
                    continue
                path = os.path.join(dirpath, filename)
                rel = os.path.relpath(path, src).replace(os.sep, "/")
                index.scan_file(path, rel)
                scanned += 1
    logger.info("parsed %d headers: %d aggregate definitions, %d macro "
                "constants, %d definitions rejected by the member parser",
                scanned, len(index.structs), len(index.defines),
                len(index.parse_failures))
    return index


def include_path(src, rel_path):
    """The #include spelling for a header, relative to a probe include root."""
    for root_rel in PROBE_INCLUDES:
        prefix = root_rel.replace(os.sep, "/") + "/"
        if rel_path.startswith(prefix):
            return rel_path[len(prefix):]
    return None


# ---------------------------------------------------------------------------
# Inventory loading
# ---------------------------------------------------------------------------

def load_json(path, what):
    if not os.path.isfile(path):
        raise SystemExit(
            "%s not found at %s\n"
            "Regenerate it first; this tool never falls back to a stale or "
            "built-in copy." % (what, path))
    with open(path, encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except ValueError as exc:
            raise SystemExit("%s at %s is not valid JSON: %s"
                             % (what, path, exc))


def require_keys(record, keys, what, path):
    missing = [k for k in keys if k not in record]
    if missing:
        raise SystemExit(
            "%s from %s is missing %s. Expected the schema written by the "
            "extractor in this repository; regenerate it."
            % (what, path, ", ".join(missing)))


def class_numbers(index, wanted):
    """External class name -> class number, read from the class headers.

    Only the names the object graph carries are resolved. A name whose define
    evaluates outside the 16-bit class space is rejected and reported.
    NV_ESC_RM_ALLOC dispatches on the class number, so a wrong one allocates a
    different object or nothing at all.
    """
    out, rejected = {}, {}
    for name in wanted:
        expr = index.defines.get(name)
        if expr is None:
            continue
        value = index.const(expr)
        if value is None:
            rejected[name] = expr
            continue
        if value < 0 or value > 0xFFFF:
            rejected[name] = "0x%x is outside the 16-bit class space" % value
            continue
        out[name] = value
    if rejected:
        logger.info("class numbers that did not evaluate: %d (%s)",
                    len(rejected), ", ".join(sorted(rejected)[:6]))
    return out


# ---------------------------------------------------------------------------
# syzlang emission
# ---------------------------------------------------------------------------

def resource_name(external_class):
    return "nvh_" + external_class.lower()


def syz_ident(text):
    return re.sub(r"[^A-Za-z0-9_]", "_", text)


def pad_field(size):
    if size == 1:
        return "const[0, int8]"
    return "array[const[0, int8], %d]" % size


def render_struct(name, layout, overrides=None):
    """A syzlang struct with explicit padding, marked packed.

    Explicit padding plus [packed] makes the emitted size exactly the C size.
    Leaving syzkaller to insert padding would make the description's size
    depend on its alignment rules agreeing with the compiler's, which is a
    difference no compile gate would catch.
    """
    overrides = overrides or {}
    lines = ["%s {" % name]
    width = max([len(f.name) for f in layout.fields] + [4])
    for field in layout.fields:
        if field.syz is None:
            lines.append("\t%-*s\t%s" % (width, field.name,
                                         pad_field(field.size)))
            continue
        syz = overrides.get(field.name, field.syz)
        lines.append("\t%-*s\t%s" % (width, field.name, syz))
    lines.append("} [packed]")
    return "\n".join(lines)


def render_opaque(name, size):
    return "%s {\n\topaque\tarray[int8, %d]\n} [packed]" % (name, size)


class Emitter:
    """Accumulates syzlang struct definitions and reports what went opaque."""

    def __init__(self, index, sizes):
        self.index = index
        self.sizes = sizes
        self.rendered = {}
        self.order = []
        self.size_match = []
        self.size_mismatch = []
        self.opaque = []
        self.unresolved = []

    def measured(self, struct_name):
        size = self.sizes.get(struct_name)
        if size is None:
            canonical = self.index.canonical_struct(struct_name)
            size = self.sizes.get(canonical)
        return size

    def ensure(self, struct_name, overrides=None):
        """Emit a struct and every struct it references. Returns its name.

        Aliases resolve to the struct they name, so two control commands whose
        parameter types are typedefs of one struct share a single definition
        and both descriptions point at it.

        Returns None when neither a layout nor a measured size is available,
        which is the case where a description would have to guess and this
        tool declines to emit one.
        """
        struct_name = self.index.canonical_struct(struct_name)
        if struct_name in self.rendered:
            return struct_name
        measured = self.measured(struct_name)
        try:
            layout = self.index.layout(struct_name)
        except LayoutError as exc:
            if measured is None:
                if struct_name not in dict(self.unresolved):
                    self.unresolved.append((struct_name, str(exc)))
                logger.debug("no layout and no measured size for %s: %s",
                             struct_name, exc)
                return None
            self.rendered[struct_name] = render_opaque(struct_name, measured)
            self.order.append(struct_name)
            self.opaque.append((struct_name, measured, str(exc)))
            return struct_name
        if measured is not None and layout.size != measured:
            self.rendered[struct_name] = render_opaque(struct_name, measured)
            self.order.append(struct_name)
            self.size_mismatch.append((struct_name, layout.size, measured))
            self.opaque.append((struct_name, measured,
                                "parsed layout totalled %d against a measured "
                                "%d" % (layout.size, measured)))
            return struct_name
        if measured is not None:
            self.size_match.append((struct_name, measured))
        # Reserve the name before recursing so a self-referential struct
        # cannot loop.
        self.rendered[struct_name] = ""
        for field in layout.fields:
            if field.syz is None:
                continue
            for referenced in re.findall(r"[A-Za-z_]\w*", field.syz):
                if referenced in self.index.structs and referenced != struct_name:
                    self.ensure(referenced)
        self.rendered[struct_name] = render_struct(struct_name, layout,
                                                   overrides)
        self.order.append(struct_name)
        return struct_name

    def add_raw(self, name, text):
        if name in self.rendered:
            return name
        self.rendered[name] = text
        self.order.append(name)
        return name

    def blocks(self):
        return [self.rendered[name] for name in self.order
                if self.rendered[name]]


def variant_struct(emitter, base, name, overrides):
    """A copy of a base struct with named fields retyped.

    Allocation and control both reuse one parameter struct across every class
    and command. The fields carrying the handle, the class number and the
    command number turn one ioctl into a chained description, and they take
    their types from a per-variant copy of the base layout.
    """
    try:
        layout = emitter.index.layout(base)
    except LayoutError as exc:
        raise SystemExit(
            "the %s layout could not be derived, so no allocation or control "
            "descriptions can be emitted: %s" % (base, exc))
    return emitter.add_raw(name, render_struct(name, layout, overrides))


# ---------------------------------------------------------------------------
# Description set assembly
# ---------------------------------------------------------------------------

NODE_RESOURCES = {
    "control_device_only": "fd_nvidiactl",
    "actual_device_only": "fd_nvidia",
    None: "fd_nv",
}

FILE_HEADER = """# Generated by tools/syzlang_gen.py from the measured
# inventories. Do not edit by hand: regenerate, or the next run overwrites the
# correction. Driver %s, checkout %s.
#
# Request numbers are literal here because the syzkaller tree carrying
# syz-extract is absent from this repository, so a .const file could not be
# produced against a format this tool can check. %s holds
# the same numbers as _IOWR macros for syz-extract to consume on the SUT.
"""


def build_openat_block():
    lines = [
        "resource fd_nv[fd]",
        "resource fd_nvidiactl[fd_nv]",
        "resource fd_nvidia[fd_nv]",
        "resource fd_nvidia_uvm[fd]",
        "resource fd_nvidia_uvm_tools[fd]",
        "",
    ]
    opens = [
        ("openat$nvidiactl", "/dev/nvidiactl", "fd_nvidiactl"),
        ("openat$nvidia", "/dev/nvidia#", "fd_nvidia"),
        ("openat$nvidia_uvm", "/dev/nvidia-uvm", "fd_nvidia_uvm"),
        ("openat$nvidia_uvm_tools", "/dev/nvidia-uvm-tools",
         "fd_nvidia_uvm_tools"),
    ]
    for name, path, res in opens:
        lines.append(
            '%s(fd const[%s], file ptr[in, string["%s"]], '
            "flags const[0x2], mode const[0]) %s"
            % (name, AT_FDCWD, path, res))
    return "\n".join(lines)


def escape_request(command):
    """The request number to emit for an escape, and a note when it is one of
    several the escape accepts."""
    if command["requests"]:
        return command["requests"][0], None
    one = command.get("request_one_element")
    if one:
        return one, ("argument is an array; %s is the one-element request, "
                     "up to %s elements fit the direct path"
                     % (one, command.get("max_direct_elements")))
    return None, None


def emit_escapes(emitter, inventory, class_map, graph, want_control,
                 want_alloc):
    """Escape descriptions, excluding the two multiplexers."""
    node = inventory["nodes"][0]
    blocks, records = [], []
    for command in node["commands"]:
        name = command["name"]
        if name == CONTROL_ESCAPE and want_control:
            continue
        if name == ALLOC_ESCAPE and want_alloc:
            continue
        request, note = escape_request(command)
        if request is None:
            records.append({"escape": name, "emitted": False,
                            "reason": "no request number computed"})
            continue
        fd_res = NODE_RESOURCES.get(command["node_restriction"], "fd_nv")
        struct = command["param_struct"]
        overrides = handle_overrides(struct)
        arg = None
        base = base_param_type(emitter.index, struct)
        if base is not None:
            # NV_ESC_ATTACH_GPUS_TO_FD takes an array of bare NvU32, which has
            # no struct to lay out.
            arg = "ptr[inout, %s]" % base[1]
        elif struct:
            emitted = emitter.ensure(struct, overrides)
            if emitted is not None:
                arg = "ptr[inout, %s]" % emitted
        if arg is None and command["param_size"]:
            opaque = syz_ident(name.lower()) + "_arg"
            emitter.add_raw(opaque,
                            render_opaque(opaque, command["param_size"]))
            emitter.opaque.append(
                (opaque, command["param_size"],
                 "no header definition found for %s" % struct))
            arg = "ptr[inout, %s]" % opaque
        if arg is None:
            records.append({"escape": name, "emitted": False,
                            "reason": "no parameter struct and no size"})
            continue
        line = "ioctl$%s(fd %s, cmd const[%s], arg %s)" % (
            name, fd_res, request, arg)
        if note:
            blocks.append("# " + note)
        if command["requires_admin"]:
            blocks.append("# root-only escape, kept for completeness")
        blocks.append(line)
        records.append({"escape": name, "emitted": True, "request": request,
                        "fd": fd_res, "param_struct": struct})
    return "\n".join(blocks), records


# Handle-carrying fields, by the struct that declares them. The type on the
# left of each pair turns a flat parameter struct into a chained one.
HANDLE_FIELDS = {
    "NVOS00_PARAMETERS": {"hRoot": "nvh_nv01_root",
                          "hObjectParent": "nv_handle",
                          "hObjectOld": "nv_handle"},
    "NVOS05_PARAMETERS": {"hRoot": "nvh_nv01_root",
                          "hObjectParent": "nv_handle"},
    "NVOS55_PARAMETERS": {"hClient": "nvh_nv01_root",
                          "hParent": "nv_handle",
                          "hObject": "nv_handle",
                          "hClientSrc": "nvh_nv01_root",
                          "hObjectSrc": "nv_handle"},
    "NVOS57_PARAMETERS": {"hClient": "nvh_nv01_root",
                          "hObject": "nv_handle"},
    "NVOS30_PARAMETERS": {"hClient": "nvh_nv01_root",
                          "hDevice": "nv_handle",
                          "hChannel": "nv_handle"},
    "NVOS32_PARAMETERS": {"hRoot": "nvh_nv01_root",
                          "hObjectParent": "nv_handle"},
    "NVOS34_PARAMETERS": {"hClient": "nvh_nv01_root",
                          "hDevice": "nv_handle",
                          "hMemory": "nv_handle"},
    "NVOS38_PARAMETERS": {"hClient": "nvh_nv01_root",
                          "hObject": "nv_handle"},
    "NVOS39_PARAMETERS": {"hObjectParent": "nv_handle",
                          "hSubDevice": "nv_handle"},
    "NVOS41_PARAMETERS": {"hClient": "nvh_nv01_root"},
    "NVOS46_PARAMETERS": {"hClient": "nvh_nv01_root",
                          "hDevice": "nv_handle",
                          "hMemory": "nv_handle",
                          "hDma": "nv_handle"},
    "NVOS47_PARAMETERS": {"hClient": "nvh_nv01_root",
                          "hDevice": "nv_handle",
                          "hMemory": "nv_handle",
                          "hDma": "nv_handle"},
    "NVOS49_PARAMETERS": {"hClient": "nvh_nv01_root",
                          "hChannel": "nv_handle",
                          "hCtxDma": "nv_handle"},
    "NVOS56_PARAMETERS": {"hClient": "nvh_nv01_root",
                          "hDevice": "nv_handle",
                          "hMemory": "nv_handle"},
    "NVOS_I2C_ACCESS_PARAMS": {"hClient": "nvh_nv01_root",
                               "hDevice": "nv_handle"},
    "nv_ioctl_nvos02_parameters_with_fd": {},
    "nv_ioctl_nvos33_parameters_with_fd": {},
}


def handle_overrides(struct):
    return dict(HANDLE_FIELDS.get(struct, {}))


def base_param_type(index, name):
    """(size, syzlang type) when an allocation parameter is a base type."""
    if not name:
        return None
    canonical = index.resolve_alias(name)
    if canonical not in BASE_TYPES:
        return None
    size, _align = BASE_TYPES[canonical]
    if size not in SYZ_INT:
        return None
    return (size, SYZ_INT[size])


def parent_resource(record, by_class, class_map):
    """The resource a class's hObjectParent field takes.

    A class with one legal parent gets that parent's own resource, which is
    the tightest chain the table supports. A class with several gets the
    generic nv_handle, because a syzlang field carries one type and pinning it
    to one of several legal parents would make the other chains unreachable.
    """
    parents = record.get("parents") or []
    concrete = [p for p in parents
                if p not in (ROOT_SENTINEL, ANY_PARENT_SENTINEL)
                and p in by_class]
    if ROOT_SENTINEL in parents:
        return "fd_root", None
    if len(concrete) == 1:
        return resource_name(concrete[0]), concrete[0]
    if concrete:
        return "nv_handle", None
    if ANY_PARENT_SENTINEL in parents:
        return "nv_handle", None
    return None, None


def emit_alloc(emitter, inventory, graph, class_map, limit_privilege):
    """One NV_ESC_RM_ALLOC variant per allocatable class."""
    node = inventory["nodes"][0]
    command = next((c for c in node["commands"] if c["name"] == ALLOC_ESCAPE),
                   None)
    if command is None:
        raise SystemExit(
            "%s is absent from the escape inventory, so no allocation chain "
            "can be built. The inventory is the wrong shape or the driver "
            "branch dropped the escape." % ALLOC_ESCAPE)
    requests = command["requests"]
    if len(requests) != 2:
        logger.warning("%s reported %d request numbers; the ABI defines two, "
                       "one per parameter struct size", ALLOC_ESCAPE,
                       len(requests))
    request64 = requests[0] if requests else None
    request21 = requests[1] if len(requests) > 1 else None

    by_class = {r["external_class"]: r for r in graph["records"]}
    blocks, records, unclassified = [], [], []
    skipped = collections.Counter()

    for record in sorted(graph["records"], key=lambda r: r["external_class"]):
        cls = record["external_class"]
        if limit_privilege and record["alloc_privilege"] in PRIVILEGED_ALLOC:
            skipped["privileged"] += 1
            continue
        if record["alloc_privilege"] == "unclassified":
            # Three records name no RS_FLAGS_ALLOC_* privilege flag, and all
            # three are the root client classes. Dropping them drops the
            # allocation every later call depends on, so they are emitted and
            # counted, never filtered with the privileged ones.
            unclassified.append(cls)
        if record["depth"] is None:
            skipped["not connected to the root"] += 1
            continue
        number = class_map.get(cls)
        if number is None:
            skipped["class number not found in the headers"] += 1
            records.append({"class": cls, "emitted": False,
                            "reason": "class number not found"})
            continue
        parent_res, _parent_cls = parent_resource(record, by_class, class_map)
        if parent_res is None:
            skipped["no legal parent"] += 1
            continue
        if parent_res == "fd_root":
            # An RS_ROOT_OBJECT class hangs off the file descriptor and has no
            # parent handle, so hRoot and hObjectParent are both the client
            # handle the call is about to create.
            parent_res = "const[0, int32]"

        param_struct = record["alloc_param_struct"]
        param_kind = record["alloc_param_kind"]
        param_type = "const[0, int64]"
        param_size = 0
        param_state = "null"
        base = base_param_type(emitter.index, param_struct)
        if base is not None:
            # RS_OPTIONAL(NvHandle) on the three root classes points at a bare
            # handle, which has no struct definition to lay out.
            param_type = "ptr64[in, %s]" % base[1]
            param_size = base[0]
            param_state = "base type %s" % param_struct
        elif param_struct:
            emitted = emitter.ensure(param_struct)
            if emitted is not None:
                param_type = "ptr64[in, %s]" % emitted
                param_size = emitter.measured(param_struct)
                if param_size is None:
                    try:
                        param_size = emitter.index.layout(param_struct).size
                        param_state = "parsed, size unmeasured"
                    except LayoutError:
                        param_size = 0
                        param_state = "size unknown"
                else:
                    param_state = "measured"
            elif param_kind == "required":
                skipped["required alloc param with no layout"] += 1
                records.append({"class": cls, "emitted": False,
                                "reason": "required alloc param %s has no "
                                          "layout and no measured size"
                                          % param_struct})
                continue
            else:
                param_state = "null (optional, no layout)"

        is_root_object = ROOT_SENTINEL in (record.get("parents") or [])
        overrides = {
            "hRoot": "const[0, int32]" if is_root_object else "nvh_nv01_root",
            "hObjectParent": parent_res,
            "hObjectNew": resource_name(cls),
            "hClass": "const[0x%x, int32]" % number,
            "pAllocParms": param_type,
            "paramsSize": "const[%d, int32]" % (param_size or 0),
            "pRightsRequested": "const[0, int64]",
            "flags": "flags[nvos64_alloc_flags, int32]",
            "status": "int32",
        }
        variant = "nvos64_alloc_%s" % cls.lower()
        variant_struct(emitter, "NVOS64_PARAMETERS", variant, overrides)
        if request64:
            blocks.append(
                "ioctl$NV_ESC_RM_ALLOC_%s(fd fd_nv, cmd const[%s], "
                "arg ptr[inout, %s])" % (cls, request64, variant))
        records.append({"class": cls, "emitted": True,
                        "class_number": "0x%x" % number,
                        "parent_resource": parent_res,
                        "alloc_param_struct": param_struct,
                        "alloc_param_state": param_state,
                        "resource": resource_name(cls)})

    # The 32-bit-parameter variant of the same escape. Both sizes dispatch,
    # and a set covering only one leaves half the escape's validation
    # untouched. NV01_ROOT carries it because the client allocation is the
    # call every chain starts from.
    if request21:
        overrides21 = {
            "hRoot": "nvh_nv01_root",
            "hObjectParent": "const[0, int32]",
            "hObjectNew": resource_name(ROOT_CLASS),
            "hClass": "const[0x%x, int32]" % class_map.get(ROOT_CLASS, 0),
            "pAllocParms": "const[0, int64]",
            "paramsSize": "const[0, int32]",
            "status": "int32",
        }
        variant_struct(emitter, "NVOS21_PARAMETERS",
                       "nvos21_alloc_nv01_root", overrides21)
        blocks.append(
            "ioctl$NV_ESC_RM_ALLOC_NVOS21(fd fd_nv, cmd const[%s], "
            "arg ptr[inout, nvos21_alloc_nv01_root])" % request21)

    for reason, count in sorted(skipped.items()):
        logger.info("allocation variants skipped, %s: %d", reason, count)
    if unclassified:
        logger.info("emitted %d classes whose RS_ENTRY names no "
                    "RS_FLAGS_ALLOC_* privilege flag: %s", len(unclassified),
                    ", ".join(sorted(unclassified)))
    return "\n".join(blocks), records, dict(skipped)


def control_object_resource(class_id_int, number_to_class):
    cls = number_to_class.get(class_id_int)
    if cls is None:
        return "nv_handle", None
    return resource_name(cls), cls


def emit_control(emitter, inventory, control, number_to_class, max_commands,
                 order):
    """One NV_ESC_RM_CONTROL variant per covered command."""
    node = inventory["nodes"][0]
    command = next((c for c in node["commands"]
                    if c["name"] == CONTROL_ESCAPE), None)
    if command is None:
        raise SystemExit(
            "%s is absent from the escape inventory, so the control "
            "multiplexer cannot be modelled." % CONTROL_ESCAPE)
    if not command["requests"]:
        raise SystemExit(
            "%s carries no computed request number in the inventory. "
            "Regenerate it with --sizes so the parameter size is measured."
            % CONTROL_ESCAPE)
    request = command["requests"][0]

    reachable = [m for m in control["methods"]
                 if m["reachability"] == "non_privileged"
                 and not m["handler_compiled_out"]]
    logger.info("%d control commands are non-privileged with a kernel-side "
                "handler, out of %d exported", len(reachable),
                len(control["methods"]))

    ranked = rank_commands(reachable, number_to_class, order)
    blocks, records = [], []
    covered = 0
    skipped = collections.Counter()

    for method in ranked:
        if max_commands and covered >= max_commands:
            skipped["over the --max-control cap"] += 1
            continue
        struct = method["param_struct"]
        params_type = "const[0, int64]"
        params_size = 0
        if struct:
            emitted = emitter.ensure(struct)
            if emitted is None:
                skipped["parameter struct has no layout and no measured "
                        "size"] += 1
                records.append({"method_id": method["method_id"],
                                "handler": method["handler"],
                                "emitted": False,
                                "reason": "no layout and no measured size "
                                          "for %s" % struct})
                continue
            params_type = "ptr64[inout, %s]" % emitted
            params_size = emitter.measured(struct)
            if params_size is None:
                try:
                    params_size = emitter.index.layout(struct).size
                except LayoutError:
                    skipped["parameter size unknown"] += 1
                    continue
        elif not method["param_size_zero"]:
            skipped["no parameter struct named"] += 1
            continue

        object_res, _cls = control_object_resource(int(method["class_id"], 16),
                                                   number_to_class)
        overrides = {
            "hClient": "nvh_nv01_root",
            "hObject": object_res,
            "cmd": "const[%s, int32]" % method["method_id"],
            "flags": "int32",
            "params": params_type,
            "paramsSize": "const[%d, int32]" % params_size,
            "status": "int32",
        }
        suffix = syz_ident(method["handler"])
        variant = "nvos54_ctrl_%s" % suffix
        variant_struct(emitter, "NVOS54_PARAMETERS", variant, overrides)
        blocks.append(
            "ioctl$NV_ESC_RM_CONTROL_%s(fd fd_nvidiactl, cmd const[%s], "
            "arg ptr[inout, %s])" % (suffix, request, variant))
        records.append({"method_id": method["method_id"],
                        "handler": method["handler"],
                        "owning_class": method["owning_class"],
                        "sdk_prefix": method["sdk_prefix"],
                        "param_struct": struct,
                        "param_size": params_size,
                        "object_resource": object_res,
                        "routed_to_physical": method["routed_to_physical"],
                        "emitted": True})
        covered += 1

    for reason, count in sorted(skipped.items()):
        logger.info("control commands skipped, %s: %d", reason, count)
    return "\n".join(blocks), records, dict(skipped), len(reachable)


def rank_commands(methods, number_to_class, order):
    """Order the control commands by how early a chain reaches their object.

    Reachability comes from the object graph: a command on the client itself
    needs one allocation, a command on the device needs two, and one on a
    channel needs the full prologue. Alphabetical order would put the deepest
    objects first and spend the cap on commands nothing reaches.
    """
    if order == "source":
        return list(methods)

    def key(method):
        class_id = int(method["class_id"], 16)
        cls = number_to_class.get(class_id)
        depth = 99 if cls is None else 1
        if class_id == 0x0000:
            depth = 1
        elif class_id == 0x0080:
            depth = 2
        elif class_id == 0x2080:
            depth = 3
        elif cls is not None:
            depth = 4
        gsp = 1 if method["routed_to_physical"] else 0
        return (depth, gsp, method["method_id"])

    return sorted(methods, key=key)


def emit_uvm(emitter, inventory, include_test):
    """UVM and UVM-tools descriptions.

    UVM_IOCTL_BASE(i) expands to i on Linux, so these request numbers are bare
    command numbers and carry none of the _IOC direction, type or size fields
    the RM escapes carry. Encoding them the RM way produces numbers the driver
    never sees.
    """
    blocks, records = [], []
    for node in inventory["nodes"]:
        if node["scheme"] != "bare_command_number":
            continue
        paths = node["paths"]
        if "/dev/nvidia-uvm-tools" in paths:
            fd_res = "fd_nvidia_uvm_tools"
            group = "uvm_tools"
        elif "/dev/nvidia-uvm" in paths:
            fd_res = "fd_nvidia_uvm"
            group = "uvm"
        else:
            logger.warning("UVM node with unexpected paths %s, skipped", paths)
            continue
        is_test = "uvm_test.c" in node["entry"]
        if is_test and not include_test:
            logger.info("skipped %d UVM test commands: they are compiled out "
                        "unless the module is built for test",
                        len(node["commands"]))
            continue
        if is_test:
            blocks.append("# %s: compiled out unless the module is built for "
                          "test" % node["entry"])
        for command in node["commands"]:
            name = command["name"]
            if not command["requests"]:
                records.append({"command": name, "group": group,
                                "emitted": False,
                                "reason": "no request number computed"})
                continue
            request = command["requests"][0]
            struct = command["param_struct"]
            arg = "const[0, intptr]"
            if struct:
                emitted = emitter.ensure(struct)
                if emitted is not None:
                    arg = "ptr[inout, %s]" % emitted
                elif command["param_size"]:
                    opaque = syz_ident(name.lower()) + "_arg"
                    emitter.add_raw(
                        opaque, render_opaque(opaque, command["param_size"]))
                    emitter.opaque.append(
                        (opaque, command["param_size"],
                         "no header definition found for %s" % struct))
                    arg = "ptr[inout, %s]" % opaque
                else:
                    records.append({"command": name, "group": group,
                                    "emitted": False,
                                    "reason": "no layout and no size for %s"
                                              % struct})
                    continue
            blocks.append("ioctl$%s(fd %s, cmd const[%s], arg %s)"
                          % (name, fd_res, request, arg))
            records.append({"command": name, "group": group, "emitted": True,
                            "request": request, "param_struct": struct})
    return "\n".join(blocks), records


def emit_resources(graph, class_map, limit_privilege):
    lines = ["resource nv_handle[int32]"]
    for record in sorted(graph["records"], key=lambda r: r["external_class"]):
        cls = record["external_class"]
        if cls not in class_map:
            continue
        if limit_privilege and record["alloc_privilege"] in PRIVILEGED_ALLOC:
            continue
        lines.append("resource %s[nv_handle]" % resource_name(cls))
    return "\n".join(lines)


def emit_flags_sets(index):
    none = index.const(index.defines.get("NVOS64_FLAGS_NONE", ""))
    finn = index.const(index.defines.get("NVOS64_FLAGS_FINN_SERIALIZED", ""))
    values = [v for v in (none, finn) if v is not None]
    if not values:
        raise SystemExit(
            "NVOS64_FLAGS_* were not found in the headers, so the allocation "
            "flags set cannot be emitted from source. Check --src points at "
            "an open-gpu-kernel-modules checkout.")
    return "nvos64_alloc_flags = %s" % ", ".join("0x%x" % v for v in values)


# ---------------------------------------------------------------------------
# The _IOWR header
# ---------------------------------------------------------------------------

def emit_header(inventory):
    """The header syz-extract consumes, defining every emitted number."""
    encoding = inventory["encoding"]
    magic = encoding["ioctl_magic"]
    lines = [
        "/* Generated by tools/syzlang_gen.py. Do not edit.",
        " *",
        " * The NV_* ioctl command numbers this campaign models, as _IOWR",
        " * macros for syz-extract. Numbers are derived from a checkout of",
        " * NVIDIA/open-gpu-kernel-modules and go stale when the branch moves;",
        " * regenerate with tools/ioctl_inventory.py followed by this tool.",
        " *",
        " * RM escapes use the Linux _IOC encoding with magic '%s' (0x%02x)."
        % (chr(magic), magic),
        " * UVM commands do not: UVM_IOCTL_BASE(i) expands to i on Linux, so",
        " * a UVM number is the bare command number with no _IOC fields.",
        " */",
        "#ifndef GSPWN_NVIDIA_IOCTL_H",
        "#define GSPWN_NVIDIA_IOCTL_H",
        "",
        "#include <linux/ioctl.h>",
        "",
        "#define NV_IOCTL_MAGIC 0x%02x" % magic,
        "",
    ]
    for node in inventory["nodes"]:
        label = ", ".join(node["paths"])
        lines.append("/* %s */" % label)
        for command in node["commands"]:
            request, _note = escape_request(command)
            if request is None:
                lines.append("/* %s: no single request number; the argument "
                             "is an array */" % command["name"])
                continue
            if node["scheme"] == "linux_ioc":
                size = command["param_size"]
                lines.append(
                    "#define %-40s _IOWR(NV_IOCTL_MAGIC, %d, "
                    "char[%d]) /* %s */"
                    % (command["name"], command["nr"], size, request))
                alt = command.get("param_size_alt")
                if alt is not None and len(command["requests"]) > 1:
                    # NV_ESC_RM_ALLOC dispatches on two parameter sizes, so it
                    # has two request numbers and a set covering one leaves
                    # half the escape's validation untouched.
                    lines.append(
                        "#define %-40s _IOWR(NV_IOCTL_MAGIC, %d, "
                        "char[%d]) /* %s */"
                        % (command["name"] + "_ALT", command["nr"], alt,
                           command["requests"][1]))
            else:
                lines.append("#define %-40s %s"
                             % (command["name"], request))
        lines.append("")
    lines.append("#endif /* GSPWN_NVIDIA_IOCTL_H */")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# The size probe
# ---------------------------------------------------------------------------

PROBE_RUNNER = """#!/bin/sh
# Generated by tools/syzlang_gen.py emit-probe. Do not edit.
# Compiles and runs the struct size probe for x86-64 and writes sizes.json.
#
# The path to the driver checkout is stored relative on purpose: the probe may
# be written on one machine and run on another, where an absolute path from
# the first would not resolve.
set -e
SRC="${1:-%(src_rel)s}"
if [ ! -d "$SRC/kernel-open" ]; then
    echo "not an open-gpu-kernel-modules tree: $SRC" >&2
    echo "usage: $0 [path-to-open-gpu-kernel-modules]" >&2
    exit 2
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
CC="${CC:-gcc}"
INCLUDES="%(includes)s"

: > "$HERE/sizes.txt"
failed=0
for probe in "$HERE"/probe_*.c; do
    name="$(basename "$probe" .c)"
    # shellcheck disable=SC2086
    if "$CC" -m64 -w -o "$HERE/$name" "$probe" $(for i in $INCLUDES; do \\
            printf -- "-I%%s/%%s " "$SRC" "$i"; done) \\
            2> "$HERE/$name.err"; then
        "$HERE/$name" >> "$HERE/sizes.txt"
    else
        echo "probe $name failed to compile; see $HERE/$name.err" >&2
        failed=$((failed + 1))
    fi
done

python3 - "$HERE/sizes.txt" > "$HERE/sizes.json" <<'PY'
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
echo "wrote $HERE/sizes.json ($(grep -c . "$HERE/sizes.txt") sizes, \\
$failed probes failed)" >&2
"""


def wanted_structs(inventory, control, graph, index):
    """Every struct name a description in this set would reference."""
    names = set()
    for node in inventory["nodes"]:
        for command in node["commands"]:
            if command["param_struct"]:
                names.add(command["param_struct"])
            if command.get("param_struct_alt"):
                names.add(command["param_struct_alt"])
    for method in control["methods"]:
        if method["reachability"] == "non_privileged" \
                and not method["handler_compiled_out"] \
                and method["param_struct"]:
            names.add(method["param_struct"])
    for record in graph["records"]:
        if record["alloc_param_struct"]:
            names.add(record["alloc_param_struct"])
    # An alias is measured under its own name so the size check can be keyed on
    # whichever spelling an inventory used.
    return {n for n in names if index.canonical_struct(n) in index.structs}


def cmd_emit_probe(args):
    index = scan_headers(args.src)
    inventory = load_json(args.inventory, "the escape inventory")
    control = load_json(args.control, "the control inventory")
    graph = load_json(args.graph, "the object graph")
    names = wanted_structs(inventory, control, graph, index)

    by_header = collections.defaultdict(list)
    extra_includes = collections.defaultdict(set)
    unplaced = []
    for name in sorted(names):
        # A name may need two headers: the one declaring it, when it is a
        # typedef alias, and the one defining the struct that alias names.
        canonical = index.canonical_struct(name)
        own = index.alias_source.get(name) or index.source.get(name)
        target = index.source.get(canonical)
        inc = include_path(args.src, own) if own else None
        target_inc = include_path(args.src, target) if target else None
        if inc is None:
            inc = target_inc
        if inc is None:
            unplaced.append(name)
            continue
        by_header[inc].append(name)
        if target_inc and target_inc != inc:
            extra_includes[inc].add(target_inc)

    os.makedirs(args.probe_dir, exist_ok=True)
    # The runner globs probe_*.c, so a unit left by an earlier run with a
    # different grouping would still be compiled and would contribute sizes
    # for structs this set no longer references.
    for stale in sorted(os.listdir(args.probe_dir)):
        if stale.startswith("probe_") and stale.endswith((".c", ".err")):
            os.remove(os.path.join(args.probe_dir, stale))
            logger.debug("removed stale probe %s", stale)
    # One translation unit per SDK group keeps a single header that refuses to
    # compile from taking the whole measurement with it.
    groups = collections.defaultdict(list)
    for inc, struct_names in by_header.items():
        top = inc.split("/")[0].replace(".h", "")
        groups[top].append((inc, struct_names))

    written = 0
    for group, entries in sorted(groups.items()):
        path = os.path.join(args.probe_dir, "probe_%s.c" % syz_ident(group))
        lines = ["/* Generated by tools/syzlang_gen.py emit-probe. "
                 "Do not edit. */",
                 "#include <stdio.h>"]
        for inc, _ in sorted(entries):
            lines.append('#include "%s"' % inc)
        for inc, _ in sorted(entries):
            for extra in sorted(extra_includes.get(inc, ())):
                lines.append('#include "%s"' % extra)
        lines.append("")
        lines.append("int main(void)")
        lines.append("{")
        for _, struct_names in sorted(entries):
            for name in sorted(struct_names):
                lines.append('    printf("%s %%zu\\n", sizeof(%s));'
                             % (name, name))
        lines.append("    return 0;")
        lines.append("}")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
        written += 1

    runner = os.path.join(args.probe_dir, "measure_sizes.sh")
    src_rel = os.path.relpath(args.src, REPO_ROOT).replace(os.sep, "/")
    with open(runner, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(PROBE_RUNNER % {
            "src_rel": src_rel,
            "includes": " ".join(p.replace(os.sep, "/")
                                 for p in PROBE_INCLUDES),
        })
    os.chmod(runner, 0o755)
    logger.info("wrote %d probe translation units to %s", written,
                args.probe_dir)
    print("%d structs across %d probes -> %s" % (len(names), written,
                                                 args.probe_dir))
    if unplaced:
        print("no include path resolved for %d structs (%s%s)"
              % (len(unplaced), ", ".join(unplaced[:8]),
                 ", ..." if len(unplaced) > 8 else ""))
    print("run: bash %s" % runner.replace(os.sep, "/"))
    return 0


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def load_all(args):
    inventory = load_json(args.inventory, "the escape inventory")
    require_keys(inventory, ["nodes", "encoding", "counts"],
                 "the escape inventory", args.inventory)
    control = load_json(args.control, "the control inventory")
    require_keys(control, ["methods", "source"], "the control inventory",
                 args.control)
    graph = load_json(args.graph, "the object graph")
    require_keys(graph, ["records"], "the object graph", args.graph)
    if not inventory["nodes"]:
        raise SystemExit(
            "the escape inventory names no device nodes at %s; regenerate it"
            % args.inventory)
    return inventory, control, graph


def merged_sizes(inventory, extra_paths):
    """Measured sizes from the inventory plus any probe output."""
    sizes = {}
    for node in inventory["nodes"]:
        for command in node["commands"]:
            if command["param_struct"] and command["param_size"] is not None \
                    and command.get("size_source") == "measured":
                sizes[command["param_struct"]] = command["param_size"]
            if command.get("param_struct_alt") \
                    and command.get("param_size_alt") is not None:
                sizes[command["param_struct_alt"]] = command["param_size_alt"]
    for path in extra_paths or []:
        if not os.path.isfile(path):
            raise SystemExit(
                "measured sizes not found at %s. Run `emit-probe` and then "
                "its measure_sizes.sh on a machine with a compiler, or drop "
                "the --ctrl-sizes argument to generate without control "
                "parameter sizes." % path)
        with open(path, encoding="utf-8") as fh:
            extra = json.load(fh)
        if not isinstance(extra, dict):
            raise SystemExit("%s is not a JSON object of struct name to size"
                             % path)
        for name, value in extra.items():
            if not isinstance(value, int) or value < 0:
                raise SystemExit(
                    "size for %s in %s is %r; expected a non-negative integer"
                    % (name, path, value))
            sizes[name] = value
    logger.info("%d measured struct sizes available", len(sizes))
    return sizes


def build(args):
    """Everything both `emit` and `verify` need. Returns a result dict."""
    inventory, control, graph = load_all(args)
    index = scan_headers(args.src)
    sizes = merged_sizes(inventory, args.ctrl_sizes)
    class_map = class_numbers(
        index, {r["external_class"] for r in graph["records"]})
    number_to_class = {}
    for record in graph["records"]:
        cls = record["external_class"]
        if cls in class_map:
            number_to_class.setdefault(class_map[cls], cls)
    missing = [r["external_class"] for r in graph["records"]
               if r["external_class"] not in class_map]
    if missing:
        logger.warning("no class number found in the headers for %d classes "
                       "(%s%s)", len(missing), ", ".join(sorted(missing)[:6]),
                       ", ..." if len(missing) > 6 else "")

    emitter = Emitter(index, sizes)
    resources = emit_resources(graph, class_map, not args.all_classes)
    flags = emit_flags_sets(index)
    alloc_text, alloc_records, alloc_skipped = emit_alloc(
        emitter, inventory, graph, class_map, not args.all_classes)
    ctrl_text, ctrl_records, ctrl_skipped, ctrl_reachable = emit_control(
        emitter, inventory, control, number_to_class, args.max_control,
        args.control_order)
    escape_text, escape_records = emit_escapes(
        emitter, inventory, class_map, graph, True, True)
    uvm_text, uvm_records = emit_uvm(emitter, inventory, args.uvm_test)

    return {
        "inventory": inventory, "control": control, "graph": graph,
        "index": index, "emitter": emitter, "sizes": sizes,
        "class_map": class_map, "missing_class_numbers": missing,
        "resources": resources, "flags": flags,
        "alloc_text": alloc_text, "alloc_records": alloc_records,
        "alloc_skipped": alloc_skipped,
        "ctrl_text": ctrl_text, "ctrl_records": ctrl_records,
        "ctrl_skipped": ctrl_skipped, "ctrl_reachable": ctrl_reachable,
        "escape_text": escape_text, "escape_records": escape_records,
        "uvm_text": uvm_text, "uvm_records": uvm_records,
    }


def write_file(path, text):
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
        logger.info("created output directory %s", directory)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, path)
    logger.info("wrote %s (%d bytes)", path, len(text))


def cmd_emit(args):
    result = build(args)
    emitter = result["emitter"]
    inventory = result["inventory"]
    version = result["control"]["source"].get("driver_version", "unknown")
    commit = args.commit or "see version.mk"
    banner = FILE_HEADER % (version, commit, args.header_name)

    core = "\n\n".join([
        banner,
        "# Device nodes. nvidia-drm, nvidia-modeset and /dev/dri/* are out of\n"
        "# scope in the threat model, so nothing here opens them.\n"
        + build_openat_block(),
        "# One resource per RM object class. Every handle derives from\n"
        "# nv_handle, so a field typed nv_handle accepts any of them and a\n"
        "# field typed to one class accepts only that class's handle.\n"
        + result["resources"],
        result["flags"],
        "# Escapes other than the two multiplexers.\n"
        + result["escape_text"],
        "# Object allocation. hClass is pinned per class, hObjectParent takes\n"
        "# the legal parent's handle, and hObjectNew produces the class's own\n"
        "# resource, which chains one allocation to the next.\n"
        + result["alloc_text"],
    ]) + "\n"

    structs = "\n\n".join([
        banner,
        "# Parameter structs for every description in this set. Padding is\n"
        "# explicit and every struct is packed, so the emitted size is the\n"
        "# measured size and does not depend on syzkaller's alignment rules\n"
        "# agreeing with the compiler's.",
        "\n\n".join(emitter.blocks()),
    ]) + "\n"

    ctrl = "\n\n".join([
        banner,
        "# The NV_ESC_RM_CONTROL multiplexer. One description per command,\n"
        "# with the command number pinned and its parameter struct attached.\n"
        + result["ctrl_text"],
    ]) + "\n"

    uvm = "\n\n".join([
        banner,
        "# UVM and UVM tools. UVM_IOCTL_BASE(i) expands to i on Linux, so\n"
        "# these request numbers carry no _IOC direction, type or size field.\n"
        + result["uvm_text"],
    ]) + "\n"

    out = args.out_dir
    write_file(os.path.join(out, "nvidia.txt"), core)
    write_file(os.path.join(out, "nvidia_structs.txt"), structs)
    write_file(os.path.join(out, "nvidia_ctrl.txt"), ctrl)
    write_file(os.path.join(out, "nvidia_uvm.txt"), uvm)
    write_file(os.path.join(out, args.header_name), emit_header(inventory))

    manifest = {
        "schema": SCHEMA,
        "generated_from": {
            "escape_inventory": os.path.relpath(args.inventory, REPO_ROOT),
            "control_inventory": os.path.relpath(args.control, REPO_ROOT),
            "object_graph": os.path.relpath(args.graph, REPO_ROOT),
            "driver_version": version,
        },
        "counts": {
            "escapes_emitted": sum(1 for r in result["escape_records"]
                                   if r["emitted"]),
            "escapes_total": len(result["escape_records"]),
            "alloc_variants": sum(1 for r in result["alloc_records"]
                                  if r["emitted"]),
            "control_variants": sum(1 for r in result["ctrl_records"]
                                    if r["emitted"]),
            "control_reachable": result["ctrl_reachable"],
            "uvm_emitted": sum(1 for r in result["uvm_records"]
                               if r["emitted"]),
            "uvm_total": len(result["uvm_records"]),
            "structs_emitted": len(emitter.order),
            "size_match": len(emitter.size_match),
            "size_mismatch": len(emitter.size_mismatch),
            "opaque": len(emitter.opaque),
            "unresolved": len(emitter.unresolved),
        },
        "size_mismatch": [{"struct": n, "parsed": p, "measured": m}
                          for n, p, m in sorted(emitter.size_mismatch)],
        "opaque": [{"struct": n, "size": s, "reason": r}
                   for n, s, r in sorted(emitter.opaque)],
        "unresolved": [{"struct": n, "reason": r}
                       for n, r in sorted(emitter.unresolved)],
        "skipped": {"allocation": result["alloc_skipped"],
                    "control": result["ctrl_skipped"]},
        "missing_class_numbers": sorted(result["missing_class_numbers"]),
        "escapes": result["escape_records"],
        "allocations": result["alloc_records"],
        "control": result["ctrl_records"],
        "uvm": result["uvm_records"],
    }
    write_file(os.path.join(out, "generation.json"),
               json.dumps(manifest, indent=1, sort_keys=True) + "\n")

    counts = manifest["counts"]
    print("wrote the description set to %s" % out)
    print("  escapes            %d of %d dispatched"
          % (counts["escapes_emitted"], counts["escapes_total"]))
    print("  alloc variants     %d" % counts["alloc_variants"])
    print("  control variants   %d of %d reachable"
          % (counts["control_variants"], counts["control_reachable"]))
    print("  UVM commands       %d of %d"
          % (counts["uvm_emitted"], counts["uvm_total"]))
    print("  structs            %d emitted, %d size-matched, %d mismatched, "
          "%d opaque" % (counts["structs_emitted"], counts["size_match"],
                         counts["size_mismatch"], counts["opaque"]))
    if emitter.size_mismatch:
        print("size mismatches (parsed layout against measured sizeof):")
        for name, parsed, measured in sorted(emitter.size_mismatch):
            print("  %-56s parsed %-7d measured %d" % (name, parsed, measured))
        if args.strict:
            return 2
    return 0


def cmd_verify(args):
    result = build(args)
    emitter = result["emitter"]
    total = len(emitter.size_match) + len(emitter.size_mismatch)
    print("structs with a measured size : %d" % total)
    print("  layout matched             : %d" % len(emitter.size_match))
    print("  layout did not match       : %d" % len(emitter.size_mismatch))
    print("emitted opaque               : %d" % len(emitter.opaque))
    print("no layout and no size        : %d" % len(emitter.unresolved))
    for name, parsed, measured in sorted(emitter.size_mismatch):
        print("  MISMATCH %-52s parsed %-7d measured %d"
              % (name, parsed, measured))
    if emitter.size_mismatch and args.strict:
        return 2
    return 0


def cmd_summary(args):
    result = build(args)
    emitter = result["emitter"]
    print("escapes emitted    : %d of %d"
          % (sum(1 for r in result["escape_records"] if r["emitted"]),
             len(result["escape_records"])))
    print("alloc variants     : %d"
          % sum(1 for r in result["alloc_records"] if r["emitted"]))
    print("control variants   : %d of %d reachable"
          % (sum(1 for r in result["ctrl_records"] if r["emitted"]),
             result["ctrl_reachable"]))
    print("UVM commands       : %d of %d"
          % (sum(1 for r in result["uvm_records"] if r["emitted"]),
             len(result["uvm_records"])))
    print("structs emitted    : %d" % len(emitter.order))
    print("size matched       : %d" % len(emitter.size_match))
    print("size mismatched    : %d" % len(emitter.size_mismatch))
    print("opaque             : %d" % len(emitter.opaque))
    by_prefix = collections.Counter(
        r["sdk_prefix"] for r in result["ctrl_records"] if r["emitted"])
    print("control coverage by SDK prefix:")
    for prefix, count in by_prefix.most_common(12):
        print("  %-10s %d" % (prefix, count))
    return 0


def add_common(parser):
    parser.add_argument("--src", default=DEFAULT_SRC,
                        help="open-gpu-kernel-modules checkout "
                             "(default: %(default)s)")
    parser.add_argument("--inventory",
                        default=os.path.join(DEFAULT_SURFACE,
                                             "ioctl-inventory.json"),
                        help="output of tools/ioctl_inventory.py")
    parser.add_argument("--control",
                        default=os.path.join(DEFAULT_SURFACE,
                                             "rm-control-inventory.json"),
                        help="output of tools/ctrl_surface.py")
    parser.add_argument("--graph",
                        default=os.path.join(DEFAULT_SURFACE,
                                             "rm-object-graph.json"),
                        help="output of tools/object_graph.py extract")
    parser.add_argument("--ctrl-sizes", action="append",
                        help="JSON of measured struct sizes from the probe "
                             "runner; may be given more than once")
    parser.add_argument("--max-control", type=int, default=0,
                        help="cap the number of control variants, 0 for all "
                             "that can be modelled correctly")
    parser.add_argument("--control-order", choices=("reachability", "source"),
                        default="reachability",
                        help="order control commands by chain depth or by "
                             "table order (default: %(default)s)")
    parser.add_argument("--uvm-test", action="store_true",
                        help="also emit the 104 UVM test commands, which are "
                             "compiled out unless the module is built for "
                             "test")
    parser.add_argument("--all-classes", action="store_true",
                        help="emit allocation variants for privileged classes "
                             "as well; they need capabilities the modelled "
                             "attacker does not have")
    parser.add_argument("--strict", action="store_true",
                        help="exit 2 when any struct's parsed layout does not "
                             "match its measured size")


def build_parser():
    ap = argparse.ArgumentParser(
        prog="syzlang_gen.py",
        description="Generate syzlang descriptions from the measured "
                    "NVIDIA driver inventories.")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log at DEBUG")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("emit", help="write the description set")
    add_common(p)
    p.add_argument("--out-dir", default=DEFAULT_OUT,
                   help="directory for the descriptions (default: %(default)s)")
    p.add_argument("--header-name", default="nvidia_gspwn.h",
                   help="name of the generated _IOWR header")
    p.add_argument("--commit", help="driver commit to record in the banner")
    p.set_defaults(func=cmd_emit)

    p = sub.add_parser("verify", help="report the size-match table")
    add_common(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("summary", help="counts per category")
    add_common(p)
    p.set_defaults(func=cmd_summary)

    p = sub.add_parser("emit-probe",
                       help="write the C size probes and their runner")
    add_common(p)
    p.add_argument("--probe-dir", required=True,
                   help="directory to write the probes into")
    p.set_defaults(func=cmd_emit_probe)
    return ap


def main():
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
