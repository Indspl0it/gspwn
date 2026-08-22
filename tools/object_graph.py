#!/usr/bin/env python3
"""RM object model extractor: the allocation DAG the describe phase must model.

`agents/describe.md` step 5 requires generated programs to build valid object
trees, because a description set without resource chaining produces programs
that fail at the first handle check. The chaining rules are not folklore: the
driver declares them in one table.

`src/nvidia/src/kernel/rmapi/resource_list.h` holds one RS_ENTRY record per
allocatable RsResource subclass. Four of its eight fields decide what a
syzlang description emits:

  External Class          the class number passed to NV_ESC_RM_ALLOC
  Parents                 RS_ROOT_OBJECT, RS_ANY_PARENT, or
                          RS_LIST(classId(...)); the legal parent handles,
                          which is the resource chain
  Alloc Param Info        RS_NONE | RS_OPTIONAL(T) | RS_REQUIRED(T); whether
                          pAllocParms may be null and which struct it points at
  Flags                   carries RS_FLAGS_ALLOC_NON_PRIVILEGED,
                          RS_FLAGS_ALLOC_PRIVILEGED or
                          RS_FLAGS_ALLOC_KERNEL_PRIVILEGED

The privilege gate is in Flags. All 222 records carry RS_ACCESS_NONE in
Required Access Rights, so that field separates nothing, and a tool keyed on it
reports every class as reachable. Flags splits the table 152 unprivileged, 62
privileged, 5 kernel-only, 3 naming no privilege flag at all.

The split is necessary and not sufficient. A class constructor carries its own
checks on top, and chip gating is invisible here: the table lists classes
across generations and gpuGetClassByClassId decides at runtime which exist on
the installed part.

This runs entirely off the source tree. No GPU, no SUT.

Subcommands:
  extract [--src DIR] [--out PATH]   parse the table, write JSON records
  summary [--src DIR]                depth distribution and widest parents
  chain CLASS [--src DIR]            shortest allocation chain to one class
  targets [--src DIR] [--top N]      parents ranked by reachable subtree size
  chains [--control PATH] [--out PATH]
                                     one chain record per internal class,
                                     joined to the control commands that class
                                     owns, plus the cumulative-reach curve

The `chains` subcommand performs a join nothing else performs. The control
inventory carries `owning_class`, the NVOC internal class name, and this table
carries `internal_class` on every record. Commands sharing an owning class
share an allocation chain, so one program can build the chain once and issue
every command that class owns against it. `chains` measures what that is worth:
one allocation reaches 91 of the 531 targetable commands and three reach 315.

Exit codes: 0 success, 1 bad input or unreadable source, 2 class not found.
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
# producer and every consumer agree about where a file lives whatever
# directory the tool is invoked from.
DEFAULT_SRC = os.path.join(REPO_ROOT, "artifacts", "src",
                           "open-gpu-kernel-modules")
DEFAULT_GRAPH_OUT = os.path.join(REPO_ROOT, "surface", "rm-object-graph.json")
DEFAULT_CONTROL = os.path.join(REPO_ROOT, "surface", "rm-control-inventory.json")
DEFAULT_CHAINS_OUT = os.path.join(REPO_ROOT, "surface", "rm-chains.json")
TABLE_REL = os.path.join("src", "nvidia", "src", "kernel", "rmapi",
                         "resource_list.h")

# The comment labels RS_ENTRY records carry, in declaration order: each field
# runs from its own label to the next one, and the order splits them.
# The label pattern is a regex because the source is not consistent. 15 records
# spell the last field "Required Access Right" without the plural, and a parser
# keyed on the plural silently drops the field on every one of them.
FIELDS = [
    ("external_class", r"External Class"),
    ("internal_class", r"Internal Class"),
    ("multi_instance", r"Multi-Instance"),
    ("parents", r"Parents"),
    ("alloc_param", r"Alloc Param Info"),
    ("free_priority", r"Resource Free Priority"),
    ("flags", r"Flags"),
    ("access_rights", r"Required Access Rights?"),
]

ROOT = "<root fd>"
ANY_PARENT = "<any parent>"

ENTRY_RE = re.compile(r"RS_ENTRY\(\s*(.*?)\n\s*\)\s*\n", re.S)
CLASSID_RE = re.compile(r"classId\((\w+)\)")
PARAM_RE = re.compile(r"RS_(NONE|OPTIONAL|REQUIRED)\s*(?:\(\s*(\w+)\s*\))?")

# The allocation privilege gate. This lives in the Flags field, not in Required
# Access Rights: all 222 records carry RS_ACCESS_NONE, so that field separates
# nothing. RS_FLAGS_ALLOC_* is the field that does.
PRIV_FLAGS = [
    ("kernel", "RS_FLAGS_ALLOC_KERNEL_PRIVILEGED"),
    ("privileged", "RS_FLAGS_ALLOC_PRIVILEGED"),
    ("unprivileged", "RS_FLAGS_ALLOC_NON_PRIVILEGED"),
]


def driver_version(src):
    """NVIDIA_VERSION from version.mk, so the output can be version-checked.

    Every class number, parent list and privilege flag in the output belongs to
    one driver release. A record that does not name its release cannot be
    checked against the driver under test by tools/surface_verify.py.
    """
    path = os.path.join(src, "version.mk")
    if not os.path.isfile(path):
        logger.warning("no version.mk under %s, output will carry no version",
                       src)
        return None
    with open(path, encoding="utf-8", errors="replace") as fh:
        m = re.search(r"^NVIDIA_VERSION\s*=\s*(\S+)", fh.read(), re.M)
    if not m:
        logger.warning("version.mk at %s defines no NVIDIA_VERSION", path)
        return None
    return m.group(1)


def table_path(src):
    """Absolute path to resource_list.h, validated at the boundary."""
    path = os.path.join(src, TABLE_REL)
    if not os.path.isfile(path):
        raise SystemExit(
            "resource_list.h not found at %s\n"
            "Expected a checkout of NVIDIA/open-gpu-kernel-modules at %s. "
            "Pass --src if it lives elsewhere." % (path, src))
    return path


def parse_entries(src):
    """Return one dict per RS_ENTRY record, fields stripped of whitespace."""
    path = table_path(src)
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    blocks = ENTRY_RE.findall(text)
    if not blocks:
        raise SystemExit(
            "no RS_ENTRY records matched in %s. The table format has changed; "
            "this parser needs updating before its output can be trusted."
            % path)

    entries, dropped = [], collections.Counter()
    for blk in blocks:
        rec = {}
        for i, (key, label) in enumerate(FIELDS):
            nxt = FIELDS[i + 1][1] if i + 1 < len(FIELDS) else None
            pat = r"/\*\s*" + label + r"\s*\*/\s*(.*?)"
            pat += (r"(?=/\*\s*" + nxt + r")") if nxt else r"\Z"
            m = re.search(pat, blk, re.S)
            rec[key] = " ".join(m.group(1).split()).rstrip(",") if m else None
            if m is None:
                dropped[key] += 1
        if not rec["external_class"]:
            logger.warning("RS_ENTRY record with no External Class, skipped")
            continue
        entries.append(rec)

    if dropped:
        # A field the labels did not match is a hole in the model, so it is
        # counted and reported. Silence here reads as a complete inventory.
        logger.warning("fields not matched by their labels: %s", dict(dropped))
    logger.info("parsed %d RS_ENTRY records from %s", len(entries), path)
    return entries


def alloc_param(rec):
    """('none'|'optional'|'required'|'unparsed', struct name or None)."""
    m = PARAM_RE.search(rec["alloc_param"] or "")
    if not m:
        return ("unparsed", None)
    return (m.group(1).lower(), m.group(2))


def privilege(rec):
    """Allocation privilege required, read from the Flags field.

    'unclassified' means the record names no RS_FLAGS_ALLOC_* privilege flag,
    which is reported and never treated as unprivileged.
    """
    flags = rec["flags"] or ""
    for name, token in PRIV_FLAGS:
        if token in flags:
            return name
    return "unclassified"


def build_graph(entries):
    """Return (graph, internal-to-external map).

    graph maps an external class to its legal parent external classes. A class
    whose Parents field is RS_ROOT_OBJECT hangs directly off the file
    descriptor and is given the sentinel parent ROOT.

    The internal-to-external map holds a list per internal class. The relation
    is one-to-many in the table: 18 internal classes export more than one
    external class, DispChannelDma exports 23 and KernelChannel 11. A Parents
    field naming classId(KernelChannel) therefore admits all 11 GPFIFO classes,
    and keeping only the first declaration would drop the other 10 from every
    chain built through it. Order follows the table, and duplicates are
    dropped, so the output stays stable across runs.
    """
    int2ext = {}
    for rec in entries:
        exported = int2ext.setdefault(rec["internal_class"], [])
        if rec["external_class"] not in exported:
            exported.append(rec["external_class"])

    graph, unresolved = {}, collections.Counter()
    for rec in entries:
        parents_field = rec["parents"] or ""
        if "RS_ROOT_OBJECT" in parents_field:
            graph[rec["external_class"]] = [ROOT]
            continue
        if "RS_ANY_PARENT" in parents_field:
            # Event classes attach under any object. The sentinel keeps them
            # out of the depth ranking, where an "any" edge would flatten the
            # tree and hide the real chain length.
            graph[rec["external_class"]] = [ANY_PARENT]
            continue
        names = CLASSID_RE.findall(parents_field)
        resolved = []
        for name in names:
            if name in int2ext:
                for ext in int2ext[name]:
                    if ext not in resolved:
                        resolved.append(ext)
            else:
                unresolved[name] += 1
        graph[rec["external_class"]] = resolved

    if unresolved:
        # Reported, never silently dropped: an unresolved parent is a hole in
        # the chain a description would be built from.
        logger.warning("unresolved parent internal classes: %s",
                       dict(unresolved))
    return graph, int2ext


def children_of(graph):
    kids = collections.defaultdict(list)
    for cls, parents in graph.items():
        for parent in parents:
            kids[parent].append(cls)
    return kids


def depths(graph):
    """Breadth-first depth from the file descriptor, ROOT being depth 0."""
    kids = children_of(graph)
    # RS_ANY_PARENT classes attach under any object, so the shallowest one they
    # can reach is a client at depth 1. Seeding the sentinel there puts them at
    # depth 2 without adding an edge that would flatten the rest of the tree.
    depth = {ROOT: 0, ANY_PARENT: 1}
    queue = collections.deque([ROOT, ANY_PARENT])
    while queue:
        node = queue.popleft()
        # Sorted for the same reason allocatable_depths sorts. Breadth-first
        # depth is independent of neighbour order, so this changes no value;
        # it keeps the two walks reading alike.
        for child in sorted(kids.get(node, [])):
            if child not in depth:
                depth[child] = depth[node] + 1
                queue.append(child)
    return depth


def subtree(kids, node):
    seen, stack = set(), [node]
    while stack:
        cur = stack.pop()
        for child in kids.get(cur, []):
            if child not in seen:
                seen.add(child)
                stack.append(child)
    return seen


def shortest_chain(graph, depth, cls):
    """Allocation chain from the file descriptor to cls, shallowest parent."""
    chain, seen = [cls], {cls}
    cur = cls
    while cur != ROOT:
        options = [p for p in graph.get(cur, [])
                   if p in depth and p not in seen]
        if not options:
            break
        cur = min(options, key=lambda p: depth[p])
        seen.add(cur)
        chain.append(cur)
    chain.reverse()
    return chain


def records(entries, graph, depth):
    out = []
    for rec in entries:
        cls = rec["external_class"]
        kind, struct = alloc_param(rec)
        out.append({
            "external_class": cls,
            "internal_class": rec["internal_class"],
            "multi_instance": rec["multi_instance"],
            "parents": graph.get(cls, []),
            "alloc_param_kind": kind,
            "alloc_param_struct": struct,
            "alloc_privilege": privilege(rec),
            "flags": rec["flags"],
            "access_rights": rec["access_rights"],
            "depth": depth.get(cls),
        })
    return out


# The two privilege values that stop an unprivileged process allocating a
# class. "unclassified" is admitted: the three root classes name no
# RS_FLAGS_ALLOC_* flag at all, they are the first step of every chain, and
# excluding them empties the whole chain set. Every chain carrying an
# unclassified step records it in `unclassified_steps`.
BLOCKING_PRIVILEGE = ("privileged", "kernel")


def allocatable_depths(graph, by_ext):
    """Depth from the file descriptor over allocatable classes only.

    depths() walks every edge and answers where a class sits in the table.
    This walks only classes an unprivileged process can allocate, so the
    answer is the prologue length a program actually pays. The two differ
    wherever the shallowest parent is privileged.
    """
    kids = children_of(graph)
    depth = {ROOT: 0, ANY_PARENT: 1}
    queue = collections.deque([ROOT, ANY_PARENT])
    while queue:
        node = queue.popleft()
        for child in sorted(kids.get(node, [])):
            if child in depth:
                continue
            rec = by_ext.get(child)
            if rec is None or privilege(rec) in BLOCKING_PRIVILEGE:
                continue
            depth[child] = depth[node] + 1
            queue.append(child)
    return depth


def cheapest_root_child(alloc_depth):
    """The cheapest class allocatable directly on the file descriptor.

    NV01_ROOT, NV01_ROOT_CLIENT and NV01_ROOT_NON_PRIV all sit here; the name
    breaks the tie so the chain is stable across runs.
    """
    candidates = sorted(c for c, d in alloc_depth.items()
                        if d == 1 and c not in (ROOT, ANY_PARENT))
    return candidates[0] if candidates else None


def allocatable_chain(graph, alloc_depth, cls):
    """Allocation steps from the file descriptor to cls, shallowest parent.

    Returns the external classes to allocate in order. ROOT is dropped, being
    the file descriptor itself and not an allocation. ANY_PARENT is replaced by
    the cheapest class allocatable on the descriptor, because it is not free:
    allocatable_depths seeds it at depth 1 for exactly that reason, so a class
    whose only parent is the sentinel still needs a client allocated first.
    Dropping it reported such a class at chain length 1, the same as a class
    that hangs off the descriptor, understating the prologue by one
    allocation. Returns None when cls is not allocatable or not connected. The
    `seen` set bounds the walk, so a parent cycle terminates instead of
    looping.
    """
    if cls not in alloc_depth:
        return None
    steps, seen, cur = [cls], {cls}, cls
    while cur not in (ROOT, ANY_PARENT):
        options = [p for p in graph.get(cur, [])
                   if p in alloc_depth and p not in seen]
        if not options:
            return None
        cur = min(options, key=lambda p: (alloc_depth[p], p))
        seen.add(cur)
        steps.append(cur)
    steps.reverse()
    substitute = cheapest_root_child(alloc_depth)
    out = []
    for step in steps:
        if step == ROOT:
            continue
        if step == ANY_PARENT:
            if substitute is None:
                return None
            out.append(substitute)
            continue
        out.append(step)
    return out


def cheapest_chain(entries, graph, alloc_depth, internal_class):
    """Shortest allocatable chain over every external class of one internal class.

    Ties break on the external class name so the output is stable across runs.
    """
    best = None
    for rec in entries:
        if rec["internal_class"] != internal_class:
            continue
        cls = rec["external_class"]
        steps = allocatable_chain(graph, alloc_depth, cls)
        if steps is None:
            continue
        key = (len(steps), cls)
        if best is None or key < best[0]:
            best = (key, cls, steps)
    if best is None:
        return None, None
    return best[1], best[2]


def chain_records(entries, graph, alloc_depth, depth, commands_by_class):
    """One record per internal class, with its chain and the commands it unlocks."""
    by_ext = {e["external_class"]: e for e in entries}
    out = []
    for internal in sorted({e["internal_class"] for e in entries}):
        exported = [e for e in entries if e["internal_class"] == internal]
        target, steps = cheapest_chain(entries, graph, alloc_depth, internal)
        commands = commands_by_class.get(internal, [])
        record = {
            "internal_class": internal,
            "external_classes": [{
                "external_class": e["external_class"],
                "alloc_privilege": privilege(e),
                "depth": depth.get(e["external_class"]),
            } for e in sorted(exported, key=lambda e: e["external_class"])],
            "target_external_class": target,
            "chain": None,
            "chain_length": None,
            "unallocatable_reason": None,
            "unclassified_steps": [],
            "commands": commands,
            "command_count": len(commands),
        }
        if steps is None:
            record["unallocatable_reason"] = (
                "every external class requires allocation privilege"
                if all(privilege(e) in BLOCKING_PRIVILEGE for e in exported)
                else "no external class connects to the file descriptor")
        else:
            record["chain"] = [{
                "external_class": cls,
                "alloc_param_struct": alloc_param(by_ext[cls])[1],
                "alloc_param_kind": alloc_param(by_ext[cls])[0],
                "alloc_privilege": privilege(by_ext[cls]),
            } for cls in steps]
            record["chain_length"] = len(steps)
            record["unclassified_steps"] = [
                cls for cls in steps if privilege(by_ext[cls]) == "unclassified"]
        out.append(record)
    return out


def cumulative_reach(chain_recs):
    """Greedy curve: allocations paid against control commands unlocked.

    Each step picks the class with the highest command count per allocation
    the built set does not already hold, so a class whose whole chain is
    already built costs nothing and is taken first. Every class already
    allocated along the way is credited, which is why the curve rises at an
    allocation count no single chain has.
    """
    remaining = {r["internal_class"]: r for r in chain_recs
                 if r["chain"] is not None and r["command_count"]}
    built, total, curve = set(), 0, []
    while remaining:
        best = None
        for internal, rec in remaining.items():
            new = [s["external_class"] for s in rec["chain"]
                   if s["external_class"] not in built]
            cost = len(new)
            yield_per = (rec["command_count"] / cost) if cost else float("inf")
            key = (-yield_per, cost, internal)
            if best is None or key < best[0]:
                best = (key, internal, new)
        _, internal, new = best
        rec = remaining.pop(internal)
        built.update(new)
        total += rec["command_count"]
        curve.append({
            "allocations": len(built),
            "commands": total,
            "class_added": internal,
            "new_allocations": len(new),
        })
    return curve


def commands_by_owning_class(control_path):
    """Targetable control commands grouped by the NVOC class that owns them.

    Targetable is the definition surface_cov.py uses: non-privileged
    reachability and a handler that is not compiled out.
    """
    with open(control_path, encoding="utf-8") as fh:
        control = json.load(fh)
    if "methods" not in control:
        raise SystemExit("%s carries no `methods` array, so it is not a "
                         "control inventory." % control_path)
    grouped = collections.defaultdict(list)
    for method in control["methods"]:
        if method["reachability"] != "non_privileged":
            continue
        if method["handler_compiled_out"]:
            continue
        grouped[method["owning_class"]].append({
            "method_id": method["method_id"],
            "handler": method["handler"],
        })
    for commands in grouped.values():
        commands.sort(key=lambda c: c["handler"])
    return dict(grouped)


def cmd_chains(args):
    entries = parse_entries(args.src)
    graph, _ = build_graph(entries)
    depth = depths(graph)
    by_ext = {e["external_class"]: e for e in entries}
    alloc_depth = allocatable_depths(graph, by_ext)

    if not os.path.isfile(args.control):
        raise SystemExit(
            "the control inventory %s is missing, so no chain can name the "
            "commands it unlocks. Run tools/ctrl_surface.py, or pass "
            "--control PATH." % args.control)
    commands_by_class = commands_by_owning_class(args.control)
    total_commands = sum(len(v) for v in commands_by_class.values())

    recs = chain_records(entries, graph, alloc_depth, depth, commands_by_class)
    by_internal = {r["internal_class"]: r for r in recs}

    unresolved = []
    for owning, commands in sorted(commands_by_class.items()):
        rec = by_internal.get(owning)
        if rec is None:
            reason = "no RS_ENTRY row for this class"
        elif rec["chain"] is None:
            reason = rec["unallocatable_reason"]
        else:
            continue
        unresolved.append({
            "owning_class": owning,
            "reason": reason,
            "command_count": len(commands),
            "commands": [c["handler"] for c in commands],
        })

    curve = cumulative_reach(recs)
    reached = sum(r["command_count"] for r in recs if r["chain"] is not None)
    payload = {
        "schema": "gspwn.rm-chains/1",
        "source": {
            "table": repo_relative(os.path.join(args.src, TABLE_REL)),
            "control_inventory": repo_relative(args.control),
            "driver_version": driver_version(args.src),
        },
        "counts": {
            "internal_classes": len(recs),
            "chained": sum(1 for r in recs if r["chain"] is not None),
            "unallocatable": sum(1 for r in recs if r["chain"] is None),
            "targetable_commands": total_commands,
            "commands_with_a_chain": reached,
            "commands_without_a_chain": total_commands - reached,
            "owning_classes": len(commands_by_class),
        },
        "cumulative_reach": curve,
        "unresolved_owning_classes": unresolved,
        "chains": recs,
    }
    write_json(args.out, payload)
    logger.info("wrote %d chain records to %s", len(recs), args.out)
    print("%d chain records -> %s" % (len(recs), args.out))
    print("%d of %d targetable control commands resolve to a chain"
          % (reached, total_commands))
    # Several classes can land at the same allocation count, because a class
    # whose chain is already built costs nothing. Print the total each count
    # reaches, which is the last row carrying it.
    at_count = {}
    for row in curve:
        at_count[row["allocations"]] = row
    for allocations in sorted(at_count):
        row = at_count[allocations]
        print("  %3d allocations -> %3d commands (%.0f%%), last class added %s"
              % (allocations, row["commands"],
                 100.0 * row["commands"] / max(total_commands, 1),
                 row["class_added"]))
    for row in unresolved:
        print("  no chain: %-16s %2d commands, %s"
              % (row["owning_class"], row["command_count"], row["reason"]))
    return 0


def write_json(path, payload):
    """Write JSON through a temp file in the same directory, then rename.

    A reader that opens the artefact while it is being rewritten sees either
    the old file or the new one and never a truncated prefix.
    """
    out_dir = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
        logger.info("created output directory %s", out_dir)
    tmp = os.path.abspath(path) + ".tmp"
    try:
        # newline="\n" so a run on Windows and a run under WSL produce the
        # same bytes.
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(payload, fh, indent=1, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def cmd_extract(args):
    entries = parse_entries(args.src)
    graph, _ = build_graph(entries)
    depth = depths(graph)
    payload = {
        "source": {
            # Forward slashes on every platform, the form cmd_chains already
            # writes. A backslash path here made the artefact differ between a
            # Windows run and a WSL run over identical source.
            "path": repo_relative(os.path.join(args.src, TABLE_REL)),
            "driver_version": driver_version(args.src),
        },
        "record_count": len(entries),
        "records": records(entries, graph, depth),
    }
    write_json(args.out, payload)
    unreached = [r["external_class"] for r in payload["records"]
                 if r["depth"] is None]
    logger.info("wrote %d records to %s", len(entries), args.out)
    print("%d records -> %s" % (len(entries), args.out))
    if unreached:
        print("not connected to the root by this parse: %d (%s)"
              % (len(unreached), ", ".join(sorted(unreached))))
    return 0


def cmd_summary(args):
    entries = parse_entries(args.src)
    graph, _ = build_graph(entries)
    depth = depths(graph)
    kids = children_of(graph)

    print("RS_ENTRY records            : %d" % len(entries))

    priv = collections.Counter(privilege(e) for e in entries)
    print("allocation privilege (RS_FLAGS_ALLOC_*):")
    for value, count in priv.most_common():
        print("  %-14s %3d" % (value, count))

    access = collections.Counter(e["access_rights"] for e in entries)
    for value, count in access.most_common():
        print("  access rights %-24s %d" % (value or "unparsed", count))

    params = collections.Counter(alloc_param(e)[0] for e in entries)
    print("alloc param requirement     : %s" % dict(params))

    print("\ndepth from the file descriptor:")
    byd = collections.Counter(depth[c] for c in graph if c in depth)
    for d in sorted(byd):
        print("  depth %d : %3d classes" % (d, byd[d]))
    unreached = sorted(c for c in graph if c not in depth)
    print("  not connected: %d %s" % (len(unreached), unreached))

    print("\nwidest parents:")
    ranked = sorted(kids.items(), key=lambda kv: -len(kv[1]))
    for parent, direct in ranked[:10]:
        print("  %-34s %3d direct  %3d subtree"
              % (parent, len(direct), len(subtree(kids, parent))))
    return 0


def cmd_chain(args):
    entries = parse_entries(args.src)
    graph, _ = build_graph(entries)
    depth = depths(graph)
    if args.klass not in graph:
        print("no RS_ENTRY record for class %r" % args.klass, file=sys.stderr)
        return 2
    by_class = {e["external_class"]: e for e in entries}
    chain = shortest_chain(graph, depth, args.klass)
    for step, cls in enumerate(chain):
        if cls == ROOT:
            print("%d. open the device node" % step)
            continue
        if cls == ANY_PARENT:
            print("%d. any already-allocated object is a legal parent" % step)
            continue
        rec = by_class[cls]
        kind, struct = alloc_param(rec)
        print("%d. NV_ESC_RM_ALLOC %-34s %-12s param %s%s"
              % (step, cls, privilege(rec), kind,
                 " " + struct if struct else ""))
    return 0


def cmd_targets(args):
    entries = parse_entries(args.src)
    graph, _ = build_graph(entries)
    kids = children_of(graph)
    by_class = {e["external_class"]: e for e in entries}
    ranked = sorted(((p, len(subtree(kids, p))) for p in kids
                     if p not in (ROOT, ANY_PARENT)),
                    key=lambda kv: -kv[1])
    print("%-36s %-14s %-9s %s"
          % ("parent class", "alloc priv", "unlocked", "unpriv subtree"))
    for parent, size in ranked[:args.top]:
        reach = subtree(kids, parent)
        unpriv = sum(1 for c in reach if c in by_class
                     and privilege(by_class[c]) == "unprivileged")
        pv = privilege(by_class[parent]) if parent in by_class else "?"
        print("%-36s %-14s %-9d %d" % (parent, pv, size, unpriv))
    return 0


def add_shared(sub_parser):
    """Accept --src and -v after the subcommand as well as before it.

    argparse binds a parent-level option before the subcommand only, so
    `object_graph.py extract --src DIR` is a usage error while
    `object_graph.py --src DIR extract` works. Both orders read naturally and
    the documentation uses the first, so each subparser repeats the options
    with SUPPRESS defaults, which leaves the parent's value in place when the
    subcommand does not carry one.
    """
    sub_parser.add_argument("--src", default=argparse.SUPPRESS,
                            help="open-gpu-kernel-modules checkout")
    sub_parser.add_argument("-v", "--verbose", action="store_true",
                            default=argparse.SUPPRESS, help="log at DEBUG")
    return sub_parser


def build_parser():
    ap = argparse.ArgumentParser(
        prog="object_graph.py",
        description="Extract the RM allocation DAG from resource_list.h.")
    ap.add_argument("--src", default=DEFAULT_SRC,
                    help="open-gpu-kernel-modules checkout (default: %s)"
                         % os.path.relpath(DEFAULT_SRC, REPO_ROOT))
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log at DEBUG")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = add_shared(sub.add_parser("extract", help="write the JSON records"))
    p.add_argument("--out", default=DEFAULT_GRAPH_OUT,
                   help="default: %s" % os.path.relpath(DEFAULT_GRAPH_OUT,
                                                        REPO_ROOT))
    p.set_defaults(func=cmd_extract)

    p = add_shared(sub.add_parser("summary", help="depth distribution and widest parents"))
    p.set_defaults(func=cmd_summary)

    p = add_shared(sub.add_parser("chain", help="shortest allocation chain to a class"))
    p.add_argument("klass", metavar="CLASS")
    p.set_defaults(func=cmd_chain)

    p = add_shared(sub.add_parser("targets", help="parents ranked by subtree size"))
    p.add_argument("--top", type=int, default=15)
    p.set_defaults(func=cmd_targets)

    p = add_shared(sub.add_parser(
        "chains", help="allocation chain per class, with the commands it unlocks"))
    p.add_argument("--control", default=DEFAULT_CONTROL,
                   help="output of tools/ctrl_surface.py (default: %s)"
                        % os.path.relpath(DEFAULT_CONTROL, REPO_ROOT))
    p.add_argument("--out", default=DEFAULT_CHAINS_OUT,
                   help="default: %s" % os.path.relpath(DEFAULT_CHAINS_OUT,
                                                        REPO_ROOT))
    p.set_defaults(func=cmd_chains)
    return ap


def main():
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
