#!/usr/bin/env python3
"""Five CI checks over the committed surface artefacts.

Each one catches a class of defect that reached the repository unnoticed
because nothing compared two artefacts that have to agree:

    names       every variant named by tools/ioctl_map.json is declared by
                the description set. A trace converted through a name no
                description declares produces a program syz-db rejects, or
                one that runs and attributes to nothing.
    pins        every emitted call whose parameter struct carries a leaf
                selector renders that selector as a const, and a control
                variant's `cmd` renders as the method id the control inventory
                carries for the handler the variant is named for. A control
                variant with a free `cmd`, or an allocation variant with a free
                `hClass`, reaches all 1372 exported commands or all 155
                classes from one description and defeats the per-leaf
                denominator. A control variant pinned to another leaf's method
                id reaches one wrong leaf and reports as one right one.
    coverage    the description set still declares a variant for every one of
                the targets the inventories enumerate.
    derived     rm-chains.json and rm-control-rank.json still account for the
                control inventory command for command, every call name they
                imply is declared, and each artefact still agrees with its own
                record structure: the ranking's order follows from its scores
                and its scores from its components, and a chain still ends on
                the class it targets. Nothing in CI runs the two tools that
                produce them, so a driver bump that moves the inventories
                leaves both stale, and the seeds phase is otherwise the first
                thing to notice, at run time, on the target.
    pages       the generated reference pages under
                docs/src/content/docs/reference/surface/ still match what
                tools/refgen.py produces from the artefacts. The check
                regenerates into a temporary directory and diffs, so it
                catches both a page edited by hand and an artefact
                regenerated without regenerating the pages. A digest stored
                alongside the pages would not: whoever edits the page is
                positioned to update the digest, and the digest of a stale
                page still matches itself.

Run one, or all five:

    python3 tools/regression_check.py names
    python3 tools/regression_check.py pins
    python3 tools/regression_check.py coverage
    python3 tools/regression_check.py derived
    python3 tools/regression_check.py pages
    python3 tools/regression_check.py all

`-v` logs what each artefact read contributed, and is accepted on either side
of the subcommand:

    python3 tools/regression_check.py -v derived
    python3 tools/regression_check.py derived -v

`all` runs them in the order above, which is the order the dependency between
them reads in, and the order the CI steps carry. A check registered in CHECKS
and absent from CHECK_ORDER runs last.

Exit codes: 0 when the check passes, 1 when it finds an offending entry, 2
when an artefact the check needs is absent, unreadable, or shaped in a way the
check did not anticipate. CI fails on both non-zero codes. An unexpected
exception is exit 2 as well, and `all` continues with the remaining checks
after one: a traceback out of the process would exit 1, which reads as "an
offending entry was found", and it would hide every verdict after it.

Deliberately no pipeline_state import, for the reason tools/surface_cov.py
gives at its own import block: that module needs fcntl and would stop this
running on a Windows workstation. Everything here reads committed files only,
so it needs no GPU, no kernel and no network.
"""
import argparse
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import refgen  # noqa: E402  (path set above so the tool runs from anywhere)
import surface_cov  # noqa: E402

logger = logging.getLogger("regression_check")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IOCTL_MAP = os.path.join(REPO_ROOT, "tools", "ioctl_map.json")
DESC_DIR = surface_cov.DEFAULT_DESC
CHAINS = os.path.join(surface_cov.SURFACE_DIR, "rm-chains.json")
CTRL_RANK = os.path.join(surface_cov.SURFACE_DIR, "rm-control-rank.json")
PAGES_DIR = refgen.DEFAULT_OUT
PAGES_REMEDY = "python3 tools/refgen.py"
# The line separator every committed file in the repository carries, declared
# by .gitattributes. Named so the byte comparison below reads as a comparison
# and not as an escape sequence buried in a split call.
LF = b"\n"

# Each derived artefact, its schema stamp, and the array `derived` reads. Both
# are produced from surface/rm-control-inventory.json, so both go
# stale against the same driver bump.
DERIVED = [
    ("rm-chains.json", CHAINS, "gspwn.rm-chains/1", "chains",
     "tools/object_graph.py chains"),
    ("rm-control-rank.json", CTRL_RANK, "gspwn.rm-control-rank/1", "commands",
     "tools/ctrl_rank.py rank"),
]

# A syzlang call line and the struct its `arg` points at. The description set
# writes both on one line, so one pattern reads the whole call.
CALL_RE = re.compile(r"^ioctl\$([A-Za-z0-9_]+)\((?P<args>[^\n]*)\)\s*$", re.M)
ARG_STRUCT_RE = re.compile(r"\barg\s+ptr\d*\[\w+,\s*([A-Za-z0-9_]+)\s*\]")
STRUCT_OPEN_RE = re.compile(r"^([A-Za-z0-9_]+)\s*\{\s*$")
STRUCT_FIELD_RE = re.compile(r"^\s+([A-Za-z0-9_]+)\s+(.+?)\s*$")

# The two fields that select which driver leaf a call reaches. `cmd` is
# NVOS54_PARAMETERS.cmd on a control call and the inner escape number on an
# XFER wrapper; `hClass` is NVOS64_PARAMETERS.hClass on an allocation.
SELECTORS = ("cmd", "hClass")

# The value inside a pinned rendering, `const[0x00900101, int32]`. A pin the
# check cannot read the value of is reported as a mismatch and never passed
# over, because an unreadable value is the same blind spot as a free field.
CONST_VALUE_RE = re.compile(r"^const\[\s*(0[xX][0-9a-fA-F]+|\d+)\s*[,\]]")

# Only the control `cmd` is compared against a value. Its authority is
# rm-control-inventory.json, where every method row pairs the handler symbol
# the variant is named for with the method id. An allocation `hClass` has no
# such authority in any committed artefact: the object graph names the
# allocation class and carries no number for it, and the class id
# surface_cov.load_targets joins onto an alloc target is the owning class's
# SDK class id, which differs from the allocation class number on 17 of the
# 62 alloc targets that carry one. Comparing against it would report those 17
# as defects. The XFER inner cmd has no committed authority either.
VALUE_CHECKED = ("cmd", surface_cov.CONTROL_PREFIX)

# The denominator the committed inventories carry, per family, measured on
# driver 610.57.04. `coverage` compares the description set against whatever
# surface_cov.load_targets() returns, so a driver bump that drops targets, or a
# defect in an inventory parser, shrinks both sides together and the comparison
# still reads clean. This floor makes the denominator itself an assertion.
# A bump that legitimately retires a target moves these numbers, and moving
# them is the change to review.
TARGET_FLOOR = {
    "escape": 32,
    "uvm": 39,
    "uvm_tools": 7,
    "control": 531,
    "alloc": 155,
}

# Variant name prefix -> reporting group. A group with no members at all means
# the emitter stopped producing that family or the parser stopped matching the
# emitted form, and either way the check has gone silent, so `pins` fails on an
# empty group instead of reporting a clean run over nothing.
GROUPS = [
    ("control", "NV_ESC_RM_CONTROL_"),
    ("alloc", "NV_ESC_RM_ALLOC_"),
    ("xfer", "NV_ESC_IOCTL_XFER_CMD_"),
]

# Calls whose selector field is free on purpose, keyed by (variant, struct,
# field) so that renaming any of the three retires the entry and the check
# fires again. All four are escape-family targets: surface_cov counts each as
# one target and never decomposes it per leaf, so the field is a fuzzable
# input to a single handler and not a name for another call.
UNPINNED_BY_DESIGN = {
    ("NV_ESC_CHECK_VERSION_STR", "nv_ioctl_rm_api_version_t", "cmd"):
        "selects the version comparison mode inside one handler",
    ("NV_ESC_RM_LOCKLESS_DIAGNOSTIC", "NV_LOCKLESS_DIAGNOSTIC_PARAMS", "cmd"):
        "selects a diagnostic sub-operation inside one root-only handler",
    ("NV_ESC_RM_ALLOC_OBJECT", "NVOS05_PARAMETERS", "hClass"):
        "the escape is one target; the alloc family decomposes NV_ESC_RM_ALLOC",
    ("NV_ESC_RM_ALLOC_CONTEXT_DMA2", "NVOS39_PARAMETERS", "hClass"):
        "the escape is one target; the alloc family decomposes NV_ESC_RM_ALLOC",
}


class CheckInput(Exception):
    """An artefact the check reads is absent or does not parse."""


def _description_files():
    files = surface_cov._files(DESC_DIR, (".txt",))
    if not files:
        raise CheckInput(
            "no .txt description files under %s. The description set is a "
            "committed artefact; a checkout missing it cannot run this check. "
            "Regenerate with tools/syzlang_gen.py emit against a driver source "
            "checkout, or restore the committed files." % DESC_DIR)
    return files


def parse_structs(text):
    """-> {struct name: {field name: rendered type}} over one syzlang file."""
    structs = {}
    current = None
    for line in text.splitlines():
        opened = STRUCT_OPEN_RE.match(line)
        if opened:
            current = {}
            structs[opened.group(1)] = current
            continue
        if line.startswith("}"):
            current = None
            continue
        if current is not None:
            field = STRUCT_FIELD_RE.match(line)
            if field:
                current[field.group(1)] = field.group(2)
    return structs


def parse_calls(text):
    """-> {variant name: struct its arg points at, or None}."""
    calls = {}
    for match in CALL_RE.finditer(text):
        pointee = ARG_STRUCT_RE.search(match.group("args"))
        calls[match.group(1)] = pointee.group(1) if pointee else None
    return calls


def read_descriptions():
    """-> (calls, structs) merged over every committed description file."""
    calls, structs = {}, {}
    files = _description_files()
    for path in files:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        structs.update(parse_structs(text))
        calls.update(parse_calls(text))
    logger.info("descriptions: %d file(s), %d call(s), %d struct(s)",
                len(files), len(calls), len(structs))
    return calls, structs


def read_ioctl_map():
    """-> [(request number, variant name)] from the committed map."""
    try:
        with open(IOCTL_MAP, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError) as exc:
        raise CheckInput("%s: %s" % (IOCTL_MAP, exc))
    entries, malformed = [], []
    for key, value in raw.items():
        if key.startswith("comment"):
            continue
        if not isinstance(value, str) or not value.startswith("ioctl$"):
            malformed.append((key, value))
            continue
        entries.append((key, value[len("ioctl$"):]))
    if malformed:
        raise CheckInput(
            "%s holds %d entry value(s) that are not a syzlang call name: %s"
            % (IOCTL_MAP, len(malformed),
               ", ".join("%s=%r" % pair for pair in sorted(malformed))))
    return sorted(entries)


def check_names():
    """Every name in tools/ioctl_map.json is declared by the descriptions."""
    entries = read_ioctl_map()
    calls, _structs = read_descriptions()
    declared = set(calls)

    offenders = [(key, name) for key, name in entries if name not in declared]
    print("names: %d map entry/entries over %d distinct name(s), %d declared "
          "call(s) in the description set"
          % (len(entries), len({n for _k, n in entries}), len(declared)))
    if not offenders:
        print("names: OK")
        return 0

    print("names: %d entry/entries name a call no description declares"
          % len(offenders))
    print()
    print("  %-12s %s" % ("request", "variant"))
    print("  %-12s %s" % ("-" * 12, "-" * 40))
    for key, name in offenders:
        note = ""
        if name in surface_cov.MULTIPLEXERS:
            note = ("  <- a multiplexer; its leaves are counted in the %s "
                    "family" % ("control" if name.endswith("CONTROL")
                                else "alloc"))
        print("  %-12s %s%s" % (key, name, note))
    print()
    print("tools/trace2seed.py reads this map to name the call a traced "
          "request becomes. A name no description declares produces a program "
          "syz-db rejects, or one that runs and attributes to no target.")
    print("Fix the map, not this check.")
    return 1


def const_value(rendered):
    """-> the integer inside a `const[...]` rendering, or None."""
    match = CONST_VALUE_RE.match(rendered)
    return int(match.group(1), 0) if match else None


def _group_of(variant):
    """-> the reporting group a variant name falls in, or None."""
    for group, prefix in GROUPS:
        if variant.startswith(prefix):
            return group
    return None


def control_method_ids():
    """-> {control variant name: the method id the inventory carries}.

    The join key is the handler symbol, which is what both the inventory row
    and the variant name are built from. Both the targetable commands and the
    excluded ones are read: a control_gsp command is still declared by the
    description set and its pinned cmd still has to be the right one.
    """
    try:
        targets, excluded, _meta = surface_cov.load_targets()
    except surface_cov.SurfaceError as exc:
        raise CheckInput(str(exc))
    ids = {}
    for record in list(excluded.values()) + list(targets.values()):
        if not record["variant"].startswith(surface_cov.CONTROL_PREFIX):
            continue
        method_id = record.get("method_id")
        if method_id:
            ids[record["variant"]] = method_id
    return ids


def check_pins():
    """Every emitted leaf selector renders as a const, and a control cmd
    renders as the method id the control inventory carries for its handler."""
    calls, structs = read_descriptions()
    method_ids = control_method_ids()

    examined, free, group_counts = 0, [], {name: 0 for name, _p in GROUPS}
    used_allowlist = set()
    unresolved, wrong, unmatched, values = [], [], 0, {}
    for variant in sorted(calls):
        struct = calls[variant]
        fields = structs.get(struct)
        if not fields:
            # No field of this call is examined at all, so the call is
            # invisible to the rest of the check. Inside a decomposed family
            # that is the check going silent one call at a time, and the
            # empty-group guard below only fires once a whole family reaches
            # zero. A change to the emitted `arg ptr[...]` form does exactly
            # this, which is why the count is reported and a group member is
            # an offender.
            unresolved.append((variant, struct, _group_of(variant)))
            continue
        for field in SELECTORS:
            if field not in fields:
                continue
            examined += 1
            group = _group_of(variant)
            if group:
                group_counts[group] += 1
            rendered = fields[field]
            if rendered.startswith("const["):
                if (field == VALUE_CHECKED[0]
                        and variant.startswith(VALUE_CHECKED[1])):
                    value = const_value(rendered)
                    values.setdefault(value, []).append(variant)
                    expected = method_ids.get(variant)
                    if expected is None:
                        unmatched += 1
                    elif value is None or value != int(expected, 0):
                        wrong.append((variant, struct, rendered, expected))
                continue
            key = (variant, struct, field)
            if key in UNPINNED_BY_DESIGN:
                used_allowlist.add(key)
                continue
            free.append((variant, struct, field, rendered))

    # An allowlist entry whose call is present and now renders const has been
    # fixed and the entry has to go, or it would mask a later regression on the
    # same field. An entry whose call is absent says nothing: the check also
    # runs against a partial set in the tests.
    stale = sorted(key for key in UNPINNED_BY_DESIGN
                   if key not in used_allowlist
                   and calls.get(key[0]) == key[1]
                   and structs.get(key[1], {}).get(key[2], "")
                   .startswith("const["))
    empty = sorted(name for name, count in group_counts.items() if not count)
    blind = sorted(row for row in unresolved if row[2])

    grouped = sum(group_counts.values())
    print("pins: %d selector field(s) examined across %d call(s) (%s, "
          "outside every group %d)"
          % (examined, len(calls),
             ", ".join("%s %d" % (name, group_counts[name])
                       for name, _p in GROUPS), examined - grouped))
    print("pins: %d control cmd(s) checked against the inventory's method id "
          "over %d distinct value(s), %d call(s) the inventory does not carry"
          % (sum(len(v) for v in values.values()), len(values), unmatched))
    print("pins: %d call(s) whose arg resolves to no declared struct, %d of "
          "them inside a reported group" % (len(unresolved), len(blind)))
    if not free and not stale and not empty and not wrong and not blind:
        print("pins: OK, %d field(s) unpinned by design"
              % len(UNPINNED_BY_DESIGN))
        return 0

    if wrong:
        print("pins: %d control cmd(s) pinned to a value the control "
              "inventory does not carry for that handler" % len(wrong))
        print()
        print("  %-46s %-34s %-24s %s"
              % ("variant", "struct", "rendered as", "inventory method id"))
        print("  %-46s %-34s %-24s %s"
              % ("-" * 46, "-" * 34, "-" * 24, "-" * 19))
        for variant, struct, rendered, expected in wrong:
            print("  %-46s %-34s %-24s %s"
                  % (variant, struct, rendered, expected))
        print()
        print("A pinned selector carrying the wrong constant reaches another "
              "leaf than the one the variant is named for, and every later "
              "measurement joins on the name. Regenerate the description set "
              "with tools/syzlang_gen.py emit against the same checkout the "
              "control inventory was built from.")
    for variant, struct, group in blind:
        print("pins: %s is in the %s group and its arg resolves to %r, which "
              "no description declares as a struct. No field of it is "
              "examined, so this check is silent about it."
              % (variant, group, struct))
    if free:
        print("pins: %d selector field(s) render free" % len(free))
        print()
        print("  %-46s %-34s %-8s %s"
              % ("variant", "struct", "field", "rendered as"))
        print("  %-46s %-34s %-8s %s"
              % ("-" * 46, "-" * 34, "-" * 8, "-" * 12))
        for variant, struct, field, rendered in free:
            print("  %-46s %-34s %-8s %s"
                  % (variant, struct, field, rendered))
        print()
        print("A free selector lets one description reach every leaf behind "
              "its multiplexer, which is the hole the per-leaf denominator "
              "exists to close. tools/syzlang_gen.py carries require_pinned() "
              "for the same rule at emission; this check covers a set edited "
              "after generation.")
    for variant, struct, field in stale:
        print("pins: %s.%s on %s is pinned now, so its UNPINNED_BY_DESIGN "
              "entry is stale. Remove it." % (struct, field, variant))
    for group in empty:
        print("pins: the %s group holds no call at all. Either the emitter "
              "stopped producing that family or the parser no longer matches "
              "the emitted form, and either way this check has gone silent."
              % group)
    return 1


def check_coverage():
    """The description set declares a variant for every enumerated target, and
    no family's target count has fallen below TARGET_FLOOR."""
    try:
        targets, excluded, meta = surface_cov.load_targets()
    except surface_cov.SurfaceError as exc:
        raise CheckInput(str(exc))
    modelled = set(surface_cov.scan_variants(_description_files(),
                                             "descriptions"))

    rows, missing, shrunk = [], [], []
    for family in surface_cov.FAMILIES:
        names = sorted(n for n, r in targets.items() if r["family"] == family)
        gap = [n for n in names if n not in modelled]
        missing.extend((family, n) for n in gap)
        rows.append((family, len(names), len(names) - len(gap), len(gap)))
        floor = TARGET_FLOOR.get(family)
        if floor is not None and len(names) < floor:
            shrunk.append((family, len(names), floor))

    total = len(targets)
    print("coverage: driver %s, %d targetable across %d families, %d modelled"
          % (meta.get("driver_version") or "unknown", total,
             len(surface_cov.FAMILIES), total - len(missing)))
    print()
    print("  %-12s %10s %10s %8s"
          % ("family", "targetable", "modelled", "gap"))
    print("  %-12s %10s %10s %8s"
          % ("-" * 12, "-" * 10, "-" * 10, "-" * 8))
    for family, targetable, covered, gap in rows:
        print("  %-12s %10d %10d %8d" % (family, targetable, covered, gap))
    print()

    extra = sorted(n for n in modelled
                   if n not in targets and n not in excluded)
    print("coverage: %d declared variant(s) outside the denominator "
          "(alternate calling forms and wrapper routes to counted targets)"
          % len(extra))
    print("coverage: denominator floor %d target(s) across %d family/families"
          % (sum(TARGET_FLOOR.values()), len(TARGET_FLOOR)))

    if not missing and not shrunk:
        print("coverage: OK")
        return 0

    for family, counted, floor in shrunk:
        print("coverage: the %s family enumerates %d target(s) against a "
              "floor of %d. The denominator shrank, so this check compares "
              "the description set against fewer targets than the release it "
              "was written for carried, and a gap opened by the missing "
              "targets does not appear above. Either an inventory was "
              "regenerated from a partial checkout, or the driver retired "
              "them and TARGET_FLOOR is the record to move."
              % (family, counted, floor))
    if shrunk:
        print()
    if not missing:
        return 1

    print("coverage: %d target(s) the description set no longer declares"
          % len(missing))
    print()
    shown = missing[:40]
    for family, name in shown:
        print("  %-12s %s" % (family, name))
    if len(missing) > len(shown):
        print("  ... and %d more" % (len(missing) - len(shown)))
    print()
    print("The denominator comes from the inventories under surface "
          "and the numerator from descriptions. A gap means the "
          "describe phase lost a target, or the two were generated from "
          "different driver checkouts.")
    return 1


def _load_derived(label, path, schema, array, remedy):
    """-> one derived artefact, refusing every shape the check cannot read.

    A wrong shape is exit 2 and not exit 1: the check has no opinion to
    report about a file it could not parse as the thing it claims to be.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
    except (OSError, ValueError) as exc:
        raise CheckInput("%s: %s. Produce it with `%s`." % (path, exc, remedy))
    if not isinstance(doc, dict):
        raise CheckInput("%s is not a JSON object, so it is not %s. Produce "
                         "it with `%s`." % (path, label, remedy))
    stamp = doc.get("schema")
    if stamp != schema:
        raise CheckInput(
            "%s carries schema %r and this check reads %r. Either the "
            "producer's format moved and this check has to move with it, or "
            "the path names a different artefact. Produce it with `%s`."
            % (path, stamp, schema, remedy))
    records = doc.get(array)
    if not isinstance(records, list) or not records:
        raise CheckInput(
            "%s carries no `%s` array with anything in it. A run over an "
            "empty artefact reads as a clean run and reports nothing, so it "
            "is refused. Produce it with `%s`." % (path, array, remedy))
    return doc


def _record_field(path, where, record, field):
    """One field of one record, or exit 2 naming where the record sits.

    `where` locates the record holding the field and not only the enclosing
    array entry, so a step inside a chain reports as `chains[7].chain[2]` and
    a reader knows which element to open.
    """
    if not isinstance(record, dict) or field not in record:
        raise CheckInput("%s: %s carries no `%s`, so the check cannot read it."
                         % (path, where, field))
    return record[field]


def _record_name(path, where, record, field):
    """One field that has to be a string, because a call name is built from
    it. A producer that normalises the field to an object would otherwise
    reach the concatenation below and raise a TypeError."""
    value = _record_field(path, where, record, field)
    if not isinstance(value, str):
        raise CheckInput(
            "%s: %s carries `%s` as %s and this check builds a call name from "
            "it, which needs a string." % (path, where, field,
                                           type(value).__name__))
    return value


def chains_implies(doc, path):
    """-> (call names the chain artefact implies, control variants it accounts
    for).

    The names are the ones tools/trace2seed.py chains emits: one allocation
    variant per chain step and one control variant per command. The account is
    every command the artefact places, whether under a chain or under the
    unresolved block, which is the set the control inventory has to match.
    """
    implied, accounted = set(), set()
    for index, record in enumerate(doc["chains"]):
        at = "chains[%d]" % index
        for step_index, step in enumerate(
                _record_field(path, at, record, "chain") or []):
            implied.add(surface_cov.ALLOC_PREFIX + _record_name(
                path, "%s.chain[%d]" % (at, step_index), step,
                "external_class"))
        for command_index, command in enumerate(
                _record_field(path, at, record, "commands") or []):
            handler = _record_name(path, "%s.commands[%d]"
                                   % (at, command_index), command, "handler")
            implied.add(surface_cov.CONTROL_PREFIX + handler)
            accounted.add(surface_cov.CONTROL_PREFIX + handler)
    unresolved = doc.get("unresolved_owning_classes")
    if not isinstance(unresolved, list):
        raise CheckInput(
            "%s carries no `unresolved_owning_classes` array. The commands of "
            "an owning class with no RS_ENTRY row appear under no chain "
            "record at all, so without that block the account silently loses "
            "them." % path)
    for index, row in enumerate(unresolved):
        at = "unresolved_owning_classes[%d]" % index
        commands = _record_field(path, at, row, "commands")
        if not isinstance(commands, list):
            raise CheckInput("%s: %s carries `commands` as %s, and this check "
                             "reads a list of handler names."
                             % (path, at, type(commands).__name__))
        for command_index, handler in enumerate(commands):
            if not isinstance(handler, str):
                raise CheckInput(
                    "%s: %s.commands[%d] is %s and this check builds a call "
                    "name from it, which needs a string."
                    % (path, at, command_index, type(handler).__name__))
            accounted.add(surface_cov.CONTROL_PREFIX + handler)
    return implied, accounted


def rank_implies(doc, path):
    """-> (call names the ranking implies, control variants it accounts for)."""
    implied, accounted = set(), set()
    for index, command in enumerate(doc["commands"]):
        handler = _record_name(path, "commands[%d]" % index, command,
                               "handler")
        implied.add(surface_cov.CONTROL_PREFIX + handler)
        accounted.add(surface_cov.CONTROL_PREFIX + handler)
    return implied, accounted


# How far a stored rank_score may sit from the weighted sum of its own
# components. tools/ctrl_rank.py rounds each component to six decimal places
# and rounds the score again, so 33 of the 531 committed records land one unit
# in the last place away from a sum computed here.
SCORE_TOLERANCE = 1.5e-6


def _partial_fields(path, array, records, fields):
    """-> [problem] for a field some records carry and others do not.

    Each restatement below is read only when the artefact carries it, so a
    producer whose schema predates one is compared on the command set alone
    and nothing here is silent about a field it did see. A field present on
    part of an array is the case that would otherwise pass unnoticed, so it is
    reported here and the field is then read on the records that carry it.
    """
    problems = []
    for field in fields:
        carried = [i for i, r in enumerate(records)
                   if isinstance(r, dict) and field in r]
        if carried and len(carried) != len(records):
            problems.append(
                "%s carries `%s` on %d of %d record(s), so it is neither a "
                "field of this artefact nor absent from it"
                % (array, field, len(carried), len(records)))
    return problems


def _carried(records, field):
    """Is field on every record of a non-empty array?"""
    return bool(records) and all(isinstance(r, dict) and field in r
                                 for r in records)


def rank_consistency(doc, path):
    """-> [problem] for rm-control-rank.json's own ordering and arithmetic.

    The command set comparison in `derived` reads handler names and discards
    everything else, so it holds against a ranking reversed, renumbered, or
    with every score zeroed. tools/syzlang_gen.py emit reads this file for the
    order it emits the control family in, and generation.json records its
    sha256 as an input of the committed set, so the order has downstream
    effect and needs an assertion of its own.

    Three properties, none of which needs the tool that produced the file:

      rank is 1..N in array order
      rank_score is the weighted sum of rank_components
      rank_score does not increase along the array, within each of the runs
        the file is built from: the commands carrying a chain first, then the
        ones carrying none
    """
    commands = doc["commands"]
    fields = ("rank", "rank_score", "rank_components", "no_chain_reason")
    problems = _partial_fields(path, "commands", commands, fields)
    ranked = _carried(commands, "rank")
    scored = _carried(commands, "rank_score")
    priced = _carried(commands, "rank_components")
    grouped = _carried(commands, "no_chain_reason")

    weighting = doc.get("weighting")
    if scored and priced and not isinstance(weighting, dict):
        raise CheckInput(
            "%s carries rank_score and rank_components on every record and no "
            "`weighting` object, and the score is the weighted sum of those "
            "components, so it cannot be checked against them." % path)

    previous_score, previous_chained = None, None
    for index, command in enumerate(commands):
        at = "commands[%d]" % index
        handler = _record_name(path, at, command, "handler")
        if ranked and command["rank"] != index + 1:
            problems.append("%s (%s) carries rank %r at array position %d"
                            % (at, handler, command["rank"], index + 1))
        score = command.get("rank_score") if scored else None
        if scored and priced:
            components = command["rank_components"]
            if not isinstance(components, dict) or not isinstance(
                    score, (int, float)):
                problems.append(
                    "%s (%s) carries rank_score %r over components %r"
                    % (at, handler, score, components))
                continue
            unpriced = sorted(k for k in components if k not in weighting)
            if unpriced:
                problems.append("%s (%s) carries component(s) %s the "
                                "weighting block does not price"
                                % (at, handler, ", ".join(unpriced)))
                continue
            expected = sum(weighting[k] * components[k] for k in components)
            if abs(expected - score) > SCORE_TOLERANCE:
                problems.append("%s (%s) carries rank_score %.6f against "
                                "%.6f from its own components and weighting"
                                % (at, handler, score, expected))
        if not (scored and grouped):
            continue
        chained = command["no_chain_reason"] is None
        if previous_chained is not None and chained and not previous_chained:
            problems.append("%s (%s) carries a chain and follows a command "
                            "that carries none" % (at, handler))
        elif previous_chained and not chained:
            # The two runs are ranked separately, so the score resets here.
            previous_score = None
        if (previous_score is not None
                and score > previous_score + SCORE_TOLERANCE):
            problems.append("%s (%s) scores %.6f above the %.6f before it"
                            % (at, handler, score, previous_score))
        previous_score, previous_chained = score, chained
    return problems


def chains_consistency(doc, path):
    """-> [problem] for rm-chains.json's own record structure.

    The command set comparison holds against a chain that loses its last step,
    because the allocation class that step named is reached through another
    chain. Each record restates its own chain, and those restatements tie a
    step list to the class the chain exists to reach.
    """
    records = doc["chains"]
    problems = _partial_fields(path, "chains", records,
                               ("chain", "chain_length",
                                "target_external_class", "command_count"))
    lengths = _carried(records, "chain_length")
    targets = _carried(records, "target_external_class")
    counts = _carried(records, "command_count")

    for index, record in enumerate(records):
        at = "chains[%d]" % index
        steps = record.get("chain") or []
        target = record.get("target_external_class")
        if steps and targets:
            tail = _record_name(path, "%s.chain[%d]" % (at, len(steps) - 1),
                                steps[-1], "external_class")
            if tail != target:
                problems.append("%s ends on %s and targets %s, so the chain "
                                "no longer reaches the class it exists for"
                                % (at, tail, target))
        if lengths:
            length = record["chain_length"]
            if steps and length != len(steps):
                problems.append("%s (%s) declares chain_length %r over %d "
                                "step(s)" % (at, target, length, len(steps)))
            elif not steps and length is not None:
                problems.append("%s (%s) carries an empty chain and "
                                "chain_length %r, where an unallocatable "
                                "class carries null" % (at, target, length))
        if counts and record["command_count"] != len(record.get("commands")
                                                     or []):
            problems.append("%s (%s) declares command_count %r over %d "
                            "command(s)"
                            % (at, target, record["command_count"],
                               len(record.get("commands") or [])))

    unresolved = doc.get("unresolved_owning_classes") or []
    problems.extend(_partial_fields(path, "unresolved_owning_classes",
                                    unresolved, ("command_count",)))
    if _carried(unresolved, "command_count"):
        for index, row in enumerate(unresolved):
            if row["command_count"] != len(row.get("commands") or []):
                problems.append("unresolved_owning_classes[%d] declares "
                                "command_count %r over %d command(s)"
                                % (index, row["command_count"],
                                   len(row.get("commands") or [])))
    return problems


def _report_set(heading, names, limit=30):
    print(heading)
    print()
    for name in sorted(names)[:limit]:
        print("  %s" % name)
    if len(names) > limit:
        print("  ... and %d more" % (len(names) - limit))
    print()


def check_derived():
    """The chain and ranking artefacts still match the control inventory."""
    try:
        targets, _excluded, meta = surface_cov.load_targets()
    except surface_cov.SurfaceError as exc:
        raise CheckInput(str(exc))
    control = {name for name, rec in targets.items()
               if rec["family"] == "control"}
    declared = set(read_descriptions()[0])

    # Every artefact is read before anything is printed, so the summary table
    # leads the step's log and the offending entries follow it.
    readers = {"rm-chains.json": chains_implies,
               "rm-control-rank.json": rank_implies}
    # The command set comparison holds against a reordered ranking and against
    # a chain that loses its last step, because neither moves the set of
    # handler names. Each artefact restates its own structure, and these read
    # that restatement against the records it describes.
    auditors = {"rm-chains.json": chains_consistency,
                "rm-control-rank.json": rank_consistency}
    rows, offenders, internal = [], [], []
    for label, path, schema, array, remedy in DERIVED:
        doc = _load_derived(label, path, schema, array, remedy)
        implied, accounted = readers[label](doc, path)
        problems = auditors[label](doc, path)
        undeclared = implied - declared
        stale = accounted - control
        unaccounted = control - accounted
        rows.append((label, len(doc[array]), len(implied), len(accounted),
                     len(undeclared), len(stale) + len(unaccounted),
                     len(problems)))
        if undeclared or stale or unaccounted:
            offenders.append((label, remedy, undeclared, stale, unaccounted))
        if problems:
            internal.append((label, remedy, problems))

    print("derived: driver %s, %d targetable control command(s)"
          % (meta.get("driver_version") or "unknown", len(control)))
    print()
    print("  %-22s %8s %8s %10s %11s %9s %9s"
          % ("artefact", "records", "implies", "accounts", "undeclared",
             "mismatch", "internal"))
    print("  %-22s %8s %8s %10s %11s %9s %9s"
          % ("-" * 22, "-" * 8, "-" * 8, "-" * 10, "-" * 11, "-" * 9,
             "-" * 9))
    for row in rows:
        print("  %-22s %8d %8d %10d %11d %9d %9d" % row)
    print()

    for label, remedy, problems in internal:
        print("derived: %s contradicts its own record structure in %d place(s)"
              % (label, len(problems)))
        print()
        for problem in problems[:30]:
            print("  %s" % problem)
        if len(problems) > 30:
            print("  ... and %d more" % (len(problems) - 30))
        print()
        print("Regenerate with `%s`." % remedy)
        print()

    for label, remedy, undeclared, stale, unaccounted in offenders:
        if undeclared:
            _report_set(
                "derived: %s implies %d call name(s) no description declares"
                % (label, len(undeclared)), undeclared)
        if stale:
            _report_set(
                "derived: %s names %d control command(s) the inventory no "
                "longer carries as targetable" % (label, len(stale)), stale)
        if unaccounted:
            _report_set(
                "derived: %d targetable control command(s) appear nowhere in "
                "%s" % (len(unaccounted), label), unaccounted)
        print("Regenerate with `%s`." % remedy)
        print()

    if not offenders and not internal:
        print("derived: OK")
        return 0
    print("Nothing in CI runs the two producing tools, so both artefacts go "
          "stale against a driver bump that moves the control inventory. "
          "tools/trace2seed.py chains and tools/syzlang_gen.py emit read them "
          "and neither reports the drift.")
    return 1


def _first_difference(committed, generated):
    """-> (line number, committed line, generated line) for the first line the
    two differ on, or None.

    Compared as raw bytes and split on the line feed, so a page rewritten
    with CRLF endings reports the line it first differs on and not a
    whole-file mismatch with no location.
    """
    left = committed.split(LF)
    right = generated.split(LF)
    for index in range(max(len(left), len(right))):
        one = left[index] if index < len(left) else None
        two = right[index] if index < len(right) else None
        if one != two:
            return (index + 1,
                    "(page ends here)" if one is None
                    else one.decode("utf-8", "replace"),
                    "(generated output ends here)" if two is None
                    else two.decode("utf-8", "replace"))
    return None


def check_pages():
    """The generated reference pages still match the surface artefacts."""
    try:
        pages, rows = refgen.render()
    except refgen.RefgenError as exc:
        raise CheckInput(str(exc))

    # Regenerating through refgen.write and reading the result back covers the
    # writer as well as the renderer: a page written with the platform's
    # native line endings differs from the committed LF copy, and that is a
    # real defect the repository's .gitattributes exists to prevent.
    scratch = tempfile.mkdtemp(prefix="refgen-check-")
    try:
        refgen.write(pages, scratch)
        fresh = {}
        for name in sorted(pages):
            with open(os.path.join(scratch, name), "rb") as handle:
                fresh[name] = handle.read()
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    committed = {}
    if os.path.isdir(PAGES_DIR):
        for name in sorted(os.listdir(PAGES_DIR)):
            if not name.endswith(".md"):
                continue
            with open(os.path.join(PAGES_DIR, name), "rb") as handle:
                committed[name] = handle.read()

    table, offenders = [], []
    for name in sorted(fresh):
        on_disk = committed.get(name)
        if on_disk is None:
            state = "absent"
            offenders.append((name, "no committed page at "
                                    "docs/src/content/docs/reference/surface/"
                                    + name, None))
        elif on_disk == fresh[name]:
            state = "OK"
        else:
            state = "differs"
            offenders.append((name, "the committed page and the regenerated "
                                    "one differ",
                              _first_difference(on_disk, fresh[name])))
        table.append((name, rows[name], len(fresh[name]),
                      len(on_disk) if on_disk is not None else 0, state))

    for name in sorted(set(committed) - set(fresh)):
        offenders.append((name, "a committed page tools/refgen.py no longer "
                                "produces", None))
        table.append((name, 0, 0, len(committed[name]), "orphan"))

    print("pages: %d generated page(s) against %s"
          % (len(fresh), os.path.relpath(PAGES_DIR, REPO_ROOT).replace(
              os.sep, "/")))
    print()
    print("  %-24s %8s %11s %11s %9s"
          % ("page", "records", "generated", "committed", "state"))
    print("  %-24s %8s %11s %11s %9s"
          % ("-" * 24, "-" * 8, "-" * 11, "-" * 11, "-" * 9))
    for row in table:
        print("  %-24s %8d %11d %11d %9s" % row)
    print()

    if not offenders:
        print("pages: OK")
        return 0

    for name, problem, difference in offenders:
        print("pages: %s: %s" % (name, problem))
        if difference:
            line, left, right = difference
            print()
            print("  first difference at line %d" % line)
            print("    committed   %s" % left)
            print("    regenerated %s" % right)
        print()
    print("A page is generated output and never an editable file. Regenerate "
          "with `%s`, which rewrites all five from the artefacts under "
          "surface. If the artefacts moved, that is the change to "
          "review; if the page was edited by hand, the edit belongs in "
          "tools/refgen.py." % PAGES_REMEDY)
    return 1


CHECKS = {
    "names": check_names,
    "pins": check_pins,
    "coverage": check_coverage,
    "derived": check_derived,
    "pages": check_pages,
}

# The order `all` runs them in, and the order the module docstring and the CI
# steps present them in. It follows the dependency between them: names and
# pins read the description set alone, coverage and derived join it against
# the inventories, and pages renders the artefacts the other four compare.
CHECK_ORDER = ("names", "pins", "coverage", "derived", "pages")


def check_order():
    """-> every registered check, in CHECK_ORDER, unlisted ones last.

    A check added to CHECKS and not to CHECK_ORDER still runs. Dropping it
    would make the registry and this tuple disagree silently, which is the
    class of defect the whole tool exists to report.
    """
    return ([name for name in CHECK_ORDER if name in CHECKS]
            + sorted(set(CHECKS) - set(CHECK_ORDER)))


def build_parser():
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(__doc__.splitlines()[1:]))
    # -v is declared twice on purpose: once on the main parser and once on
    # every subcommand through this parent, so both `-v names` and `names -v`
    # work. argparse refuses the flag after the subcommand otherwise, and the
    # usage line gives no hint that the position matters.
    verbose = argparse.ArgumentParser(add_help=False)
    # SUPPRESS, so an absent flag on the subcommand leaves the namespace
    # alone. A store_true default of False here would overwrite the main
    # parser's True and silence `regression_check.py -v names`.
    verbose.add_argument("-v", "--verbose", action="store_true",
                         default=argparse.SUPPRESS,
                         help="log what each artefact read contributed")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="log what each artefact read contributed")
    sub = parser.add_subparsers(dest="check", required=True)
    for name in check_order():
        sub.add_parser(name, parents=[verbose],
                       help=(CHECKS[name].__doc__ or "").strip())
    sub.add_parser("all", parents=[verbose],
                   help="run every check and fail if any one fails")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s")

    order = check_order() if args.check == "all" else [args.check]
    worst = 0
    for index, name in enumerate(order):
        if index:
            print()
        if len(order) > 1:
            print("== %s ==" % name)
        try:
            worst = max(worst, CHECKS[name]())
        except CheckInput as exc:
            print("%s: cannot run: %s" % (name, exc), file=sys.stderr)
            worst = max(worst, 2)
        except Exception:  # noqa: BLE001  (the reason is below)
            # An artefact shaped in a way the check did not anticipate is the
            # same condition as an absent one: the check could not run, which
            # is exit 2. Letting it propagate exits 1, which CI reads as an
            # offending entry, and under `all` it abandons every check after
            # this one, so one broken artefact hides four working verdicts.
            # The traceback goes to stderr, because the shape that produced it
            # is the thing to fix and the line number names it.
            print("%s: cannot run: unexpected %s"
                  % (name, sys.exc_info()[1].__class__.__name__),
                  file=sys.stderr)
            traceback.print_exc()
            worst = max(worst, 2)
    return worst


if __name__ == "__main__":
    sys.exit(main())
