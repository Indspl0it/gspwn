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

DEFAULT_SRC = os.path.join("artifacts", "src", "open-gpu-kernel-modules")
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
    """
    int2ext = {}
    for rec in entries:
        int2ext.setdefault(rec["internal_class"], rec["external_class"])

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
                resolved.append(int2ext[name])
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
        for child in kids.get(node, []):
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


def cmd_extract(args):
    entries = parse_entries(args.src)
    graph, _ = build_graph(entries)
    depth = depths(graph)
    payload = {
        "source": os.path.join(args.src, TABLE_REL),
        "record_count": len(entries),
        "records": records(entries, graph, depth),
    }
    out_dir = os.path.dirname(os.path.abspath(args.out))
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
        logger.info("created output directory %s", out_dir)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1, sort_keys=True)
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


def build_parser():
    ap = argparse.ArgumentParser(
        prog="object_graph.py",
        description="Extract the RM allocation DAG from resource_list.h.")
    ap.add_argument("--src", default=DEFAULT_SRC,
                    help="open-gpu-kernel-modules checkout (default: %s)"
                         % DEFAULT_SRC)
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log at DEBUG")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help="write the JSON records")
    p.add_argument("--out", default=os.path.join("artifacts", "surface",
                                                 "rm-object-graph.json"))
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("summary", help="depth distribution and widest parents")
    p.set_defaults(func=cmd_summary)

    p = sub.add_parser("chain", help="shortest allocation chain to a class")
    p.add_argument("klass", metavar="CLASS")
    p.set_defaults(func=cmd_chain)

    p = sub.add_parser("targets", help="parents ranked by subtree size")
    p.add_argument("--top", type=int, default=15)
    p.set_defaults(func=cmd_targets)
    return ap


def main():
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
