#!/usr/bin/env python3
"""Generate the surface reference pages from the committed surface artefacts.

The documentation site describes the tools that enumerate the attack surface.
It did not render the surface itself, so a reader asking which escapes exist,
or where a given control command ranks, had to open a 1.2 MB JSON file. This
tool turns the committed artefacts into five browsable pages under
docs/src/content/docs/reference/surface/:

    index.md               the five pages, their record counts and sources
    escapes.md             the 34 dispatched RM escapes and the 3 dead ones
    control-commands.md    the 531 targetable control commands, ranked
    allocation-classes.md  the 155 allocatable classes and the 98 chains
    driver-cves.md         the 61 disclosures classified as reaching Track K

Run it:

    python3 tools/refgen.py
    python3 tools/refgen.py --out tmp/pages

Output is deterministic. Every table is sorted on a key the page states, no
value is derived from the clock or the environment, and every file is written
with LF endings, so two runs over one set of artefacts produce byte-identical
files. tools/regression_check.py pages relies on that: it regenerates into a
temporary directory and diffs against the committed pages, so a page edited by
hand and an artefact moved underneath a page both fail CI.

Exit codes: 0 when every page was written, 2 when an artefact this tool needs
is absent or unreadable.

Sources, all of them committed:

    surface/ioctl-inventory.json
    surface/rm-control-inventory.json
    surface/rm-control-rank.json
    surface/rm-object-graph.json
    surface/rm-chains.json
    surface/prior-cves.json
    surface/cve-hotspots.json
    tools/ioctl_map.json

driver-cves.md joins the last two. prior-cves.json classifies the disclosure
and carries NVIDIA's bulletin sentence; cve-hotspots.json carries what reading
the fixing diff established, per disclosure: the release brackets, the other
disclosures sharing that patch set, the functions the fix touched where the
diff isolates them, and whether the fixed path is reachable by the modelled
attacker. The join is what makes the page a working reference: a CVE row
without it states a weakness class and no location in the driver.

The join renders a per-disclosure function list only for the 8 the mining
narrowed. For the other 53 the artefact's own verdict says the diff attributes
no hunk to any one disclosure, so the page states the verdict, the patch set
those disclosures share, and how many entry points that whole patch set
touched.

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
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import surface_cov  # noqa: E402  (path set above so the tool runs from anywhere)

logger = logging.getLogger("refgen")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join(REPO_ROOT, "docs", "src", "content", "docs",
                           "reference", "surface")
IOCTL_MAP = os.path.join(REPO_ROOT, "tools", "ioctl_map.json")
CHAINS = os.path.join(surface_cov.SURFACE_DIR, "rm-chains.json")
CTRL_RANK = os.path.join(surface_cov.SURFACE_DIR, "rm-control-rank.json")
PRIOR_CVES = os.path.join(surface_cov.SURFACE_DIR, "prior-cves.json")
HOTSPOTS = os.path.join(surface_cov.SURFACE_DIR, "cve-hotspots.json")
HOTSPOTS_SCHEMA = "gspwn.cve-hotspots/1"

TOOL = "python3 tools/refgen.py"
CHECK = "python3 tools/regression_check.py pages"

# The key each multiplexer record hangs under in tools/ioctl_map.json. The
# section is a comment key by design, so both readers of the map skip it.
MAP_MULTIPLEXER_KEY = "comment_multiplexers"

# node_restriction -> the device node the escape is reachable on. The
# extractor records the restriction the case body enforces and not the path,
# because the path is a property of the module and the restriction is a
# property of the command.
NODES = {
    "control_device_only": "/dev/nvidiactl",
    "actual_device_only": "/dev/nvidiaN",
    None: "/dev/nvidiactl, /dev/nvidiaN",
}

# The leading product-and-version preamble and the trailing impact clause of
# an NVIDIA bulletin sentence. Cutting both leaves NVIDIA's own words for the
# component and the fault, which is what driver-cves.md renders. This is a
# selection and never a paraphrase: every character that survives is a
# character NVIDIA published.
CVE_HEAD = re.compile(r"^.*?\bcontains a vulnerability\s+", re.S)
CVE_TAIL = re.compile(r"(,\s+(which|and this)\s+(may|can|might|could)\s+"
                      r"(lead to|result in)\b.*"
                      r"|\.?\s*A successful exploit\b.*)$", re.S)


class RefgenError(Exception):
    """An artefact this tool needs is absent, unreadable, or the wrong shape."""


def _load(path, label):
    try:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
    except (OSError, ValueError) as exc:
        raise RefgenError("%s (%s): %s" % (path, label, exc))
    if not isinstance(doc, dict):
        raise RefgenError("%s (%s) is not a JSON object" % (path, label))
    return doc


def _need(doc, path, key, kind=list):
    value = doc.get(key)
    if not isinstance(value, kind) or not value:
        raise RefgenError(
            "%s carries no `%s` %s with anything in it. A page generated from "
            "an empty artefact reads as a complete page and states nothing, "
            "so it is refused." % (path, key, kind.__name__))
    return value


def load_all():
    """-> every artefact the five pages read, keyed by its short name."""
    docs = {
        "ioctl": _load(surface_cov.IOCTL_INV, "the ioctl inventory"),
        "ctrl": _load(surface_cov.CTRL_INV, "the RM control inventory"),
        "graph": _load(surface_cov.OBJ_GRAPH, "the RM object graph"),
        "rank": _load(CTRL_RANK, "the control command ranking"),
        "chains": _load(CHAINS, "the allocation chains"),
        "cves": _load(PRIOR_CVES, "the classified CVE record"),
        "hotspots": _load(HOTSPOTS, "the patch-mining output"),
        "map": _load(IOCTL_MAP, "the ioctl name map"),
    }
    _need(docs["ioctl"], surface_cov.IOCTL_INV, "nodes")
    _need(docs["ctrl"], surface_cov.CTRL_INV, "methods")
    _need(docs["graph"], surface_cov.OBJ_GRAPH, "records")
    _need(docs["rank"], CTRL_RANK, "commands")
    _need(docs["chains"], CHAINS, "chains")
    _need(docs["cves"], PRIOR_CVES, "records")
    _need(docs["hotspots"], HOTSPOTS, "records")
    stamp = docs["hotspots"].get("schema")
    if stamp != HOTSPOTS_SCHEMA:
        raise RefgenError(
            "%s carries schema %r and this tool reads %r. Either the "
            "producer's format moved and driver-cves.md has to move with it, "
            "or the path names a different artefact. Produce it with "
            "`tools/cve_patch_map.py`." % (HOTSPOTS, stamp, HOTSPOTS_SCHEMA))
    # The two CVE artefacts have to describe one population. cve_patch_map.py
    # reads prior-cves.json to choose the disclosures it mines, so a
    # divergence means one of them was regenerated and the other was not, and
    # the joined table would silently drop or invent rows.
    classified = {r.get("cve") for r in docs["cves"]["records"]
                  if r.get("classification") == "K"}
    mined = {r.get("cve") for r in docs["hotspots"]["records"]}
    if classified != mined:
        raise RefgenError(
            "%s classifies %d disclosure(s) as K and %s mines %d, and the two "
            "sets differ. Only in the classified record: %s. Only in the "
            "patch-mining output: %s. Regenerate the mining against the "
            "current record with `tools/cve_patch_map.py`."
            % (PRIOR_CVES, len(classified), HOTSPOTS, len(mined),
               ", ".join(sorted(classified - mined)) or "(none)",
               ", ".join(sorted(mined - classified)) or "(none)"))
    muxes = docs["map"].get(MAP_MULTIPLEXER_KEY, {}).get("requests")
    if not isinstance(muxes, dict) or not muxes:
        raise RefgenError(
            "%s carries no `%s.requests` block, so the selector field each "
            "multiplexer dispatches on cannot be read and escapes.md would "
            "name a dispatcher with no target."
            % (IOCTL_MAP, MAP_MULTIPLEXER_KEY))
    try:
        docs["targets"], docs["excluded"], docs["meta"] = \
            surface_cov.load_targets()
    except surface_cov.SurfaceError as exc:
        raise RefgenError(str(exc))
    return docs


# --------------------------------------------------------------------------
# Markdown helpers. Every identifier goes in a code span: it keeps angle
# brackets such as `<any parent>` out of the markdown HTML parser, and
# tools/register_check.py blanks code spans, so a driver identifier is never
# read as prose.
# --------------------------------------------------------------------------

def code(value):
    """-> value in a code span, or an em-less placeholder when it is absent."""
    if value is None or value == "":
        return "(none)"
    return "`%s`" % value


def num(value):
    return "(none)" if value is None else str(value)


def cell(value):
    """-> one table cell, with the column separator escaped."""
    return str(value).replace("|", "\\|")


def table(headers, rows):
    """-> a markdown table. Column labels name a quantity, never a question."""
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        if len(row) != len(headers):
            raise RefgenError("table row has %d cells and the header has %d"
                              % (len(row), len(headers)))
        out.append("| " + " | ".join(cell(v) for v in row) + " |")
    return "\n".join(out)


def frontmatter(title, description):
    return "---\ntitle: %s\ndescription: \"%s\"\n---" % (
        title, description.replace('"', "'"))


def provenance(sources):
    """The line every generated page carries, naming its producer and inputs."""
    return ("Generated by `%s` from %s. `%s` regenerates the page and fails "
            "when the result differs from the committed copy."
            % (TOOL, ", ".join("`%s`" % s for s in sources), CHECK))


# --------------------------------------------------------------------------
# escapes.md
# --------------------------------------------------------------------------

def escape_family(name, targets, excluded):
    record = targets.get(name) or excluded.get(name)
    family = record.get("family") if record else None
    return {"escape": "target",
            "escape_mux": "multiplexer",
            "escape_dead": "declared, no dispatch site"}.get(family, "(none)")


def page_escapes(docs):
    inv = docs["ioctl"]
    targets, excluded = docs["targets"], docs["excluded"]
    nodes = inv["nodes"]
    rm = nodes[0]["commands"]
    muxes = docs["map"][MAP_MULTIPLEXER_KEY]["requests"]
    encoding = inv.get("encoding", {})
    counts = inv.get("counts", {})

    parts = [
        frontmatter("Escapes",
                    "The 34 dispatched RM escapes, their request numbers, "
                    "measured parameter sizes and device nodes, the two "
                    "multiplexers, and the 3 declared escapes no switch "
                    "dispatches."),
        "",
        provenance(["surface/ioctl-inventory.json",
                    "tools/ioctl_map.json"]),
        "",
        "An escape is one `case` of the `switch` in `nvidia_ioctl`. The RM "
        "node carries %d of them. The three UVM nodes use a different "
        "numbering scheme and are enumerated by the same artefact under their "
        "own entry points." % len(rm),
        "",
        "## Device nodes",
        "",
        table(["Module", "Device node", "Entry point", "Numbering",
               "Commands"],
              [[code(n.get("module")), code(", ".join(n.get("paths", []))),
                code(n.get("entry")), code(n.get("scheme")),
                len(n.get("commands", []))] for n in nodes]),
        "",
        "## Request number encoding",
        "",
        "The RM node encodes a Linux `_IOWR` request number over the bare "
        "escape number and the measured size of the parameter struct. The "
        "three UVM nodes pass the bare command number and encode nothing.",
        "",
        table(["Field", "Value", "Source"],
              [["`ioctl` magic", num(encoding.get("ioctl_magic")),
                code("NV_IOCTL_MAGIC")],
               ["Escape number base", num(encoding.get("ioctl_base")),
                code("NV_IOCTL_BASE")],
               ["Direction bits", num(encoding.get("direction_bits")),
                code(encoding.get("direction_bits_source"))],
               ["Size field width, bits", num(encoding.get("ioc_size_bits")),
                code("_IOC_SIZEBITS")],
               ["Largest encodable size, bytes",
                num(encoding.get("ioc_size_max")), code("_IOC_SIZEMASK")],
               ["UVM stack parameter ceiling, bytes",
                num(encoding.get("uvm_max_ioctl_param_stack_size")),
                code("UVM_MAX_IOCTL_PARAM_STACK_SIZE")],
               ["Oversize transfer escape",
                code(encoding.get("xfer_escape")), code("nv_ioctl_xfer_t")]]),
        "",
        "The artefact records one limit note against this encoding:",
        "",
        "> " + encoding.get("platform_size_limit_note", ""),
        "",
        "## Dispatched escapes",
        "",
        "Sorted by escape number. Every size is measured from the compiled "
        "driver headers and none is inferred: the artefact records %d sizes "
        "measured and %d unresolved. The verdict column carries the surface "
        "family `tools/surface_cov.py` places the escape in, and a "
        "multiplexer holds no target of its own because its leaves are "
        "counted in the control and allocation families."
        % (counts.get("sizes_measured", 0), counts.get("sizes_unresolved", 0)),
        "",
        table(["Escape", "Escape number", "Request number",
               "Parameter struct", "Measured size, bytes", "Device node",
               "Verdict"],
              [[code(c["name"]),
                "%d (`0x%02x`)" % (c["nr"], c["nr"]),
                ", ".join(code(r) for r in c.get("requests") or [])
                or "(none, see below)",
                code(c.get("param_struct")),
                num(c.get("param_size")),
                code(NODES.get(c.get("node_restriction"),
                               c.get("node_restriction"))),
                escape_family(c["name"], targets, excluded)]
               for c in sorted(rm, key=lambda c: c["nr"])]),
        "",
        "## Multiplexer selectors",
        "",
        "Two escapes dispatch on a field inside the parameter struct, so "
        "their request numbers name a dispatcher and no single call covers "
        "either one. `NV_ESC_RM_ALLOC` carries two request numbers because it "
        "accepts two parameter structs of different sizes.",
        "",
        table(["Request number", "Escape", "Parameter struct",
               "Selector field", "Variant prefix", "Leaves"],
              [[code(request), code(m.get("escape")),
                code(m.get("param_struct")), code(m.get("selector_field")),
                code(m.get("variant_prefix")),
                "531 control commands" if m.get("selector_field") == "cmd"
                else "155 allocatable classes"]
               for request, m in sorted(muxes.items())]),
        "",
        "## Escapes carrying an argument array",
        "",
        "The parameter of these two is validated as a nonzero multiple of one "
        "element, so the request number carries an element count and no "
        "single value names the command. The artefact records the "
        "one-element request and the largest element count the size field "
        "encodes.",
        "",
        table(["Escape", "Element struct", "Element size, bytes",
               "One-element request", "Largest direct element count"],
              [[code(c["name"]), code(c.get("param_struct")),
                num(c.get("param_size")),
                code(c.get("request_one_element")),
                num(c.get("max_direct_elements"))]
               for c in sorted(rm, key=lambda c: c["nr"])
               if c.get("is_argument_array")]),
        "",
        "## Escapes requiring privilege",
        "",
        table(["Escape", "Privilege gate", "Gate location"],
              [[code(c["name"]),
                "capability check in the case body"
                if not c.get("requires_admin_conditional")
                else "capability check under a build condition",
                code(c.get("validation_site") or c.get("dispatch_site"))]
               for c in sorted(rm, key=lambda c: c["nr"])
               if c.get("requires_admin")]),
        "",
        "## Declared escapes with no dispatch site",
        "",
        "These names are defined in `nv_escape.h` and mentioned by no switch "
        "and no table. Declared and unreachable is a separate state from "
        "undocumented, and it decides whether a description for the escape is "
        "worth authoring. The artefact records the name alone, because with "
        "no dispatch site there is no case body to read a parameter struct "
        "or a device-node restriction from.",
        "",
        table(["Escape", "Verdict"],
              [[code(name), escape_family(name, targets, excluded)]
               for name in sorted(inv.get("dead_escapes", []))]),
        "",
        "## See also",
        "",
        "- [Control commands](/gspwn/reference/surface/control-commands/)",
        "- [Allocation classes](/gspwn/reference/surface/allocation-classes/)",
        "- [`ioctl_inventory.py`]"
        "(/gspwn/architecture/components/ioctl-inventory/)",
        "- [Attack surface](/gspwn/architecture/attack-surface/)",
    ]
    return "\n".join(parts).rstrip() + "\n", len(rm) + len(
        inv.get("dead_escapes", []))


# --------------------------------------------------------------------------
# control-commands.md
# --------------------------------------------------------------------------

def graph_depths(graph):
    """internal class -> the shallowest depth any external class it exports
    sits at. An internal class exporting several external classes is reachable
    at the shallowest of them, so the minimum is the honest reading."""
    depths = {}
    for record in graph["records"]:
        internal = record.get("internal_class")
        depth = record.get("depth")
        if internal is None or depth is None:
            continue
        if internal not in depths or depth < depths[internal]:
            depths[internal] = depth
    return depths


def page_control(docs):
    rank, ctrl = docs["rank"], docs["ctrl"]
    commands = rank["commands"]
    summary = ctrl.get("summary", {})
    reach = summary.get("by_reachability", {})
    depths = graph_depths(docs["graph"])
    weighting = rank.get("weighting", {})
    counts = rank.get("counts", {})

    with_entry = sum(1 for c in commands if c["owning_class"] in depths)
    with_chain = sum(1 for c in commands if c.get("chain_length") is not None)
    reasons = {}
    for command in commands:
        reasons[command.get("no_chain_reason")] = \
            reasons.get(command.get("no_chain_reason"), 0) + 1

    gsp = summary.get("methods", 0) - sum(reach.values()) if not reach else (
        reach.get("non_privileged", 0) - len(commands))

    parts = [
        frontmatter("Control commands",
                    "The 531 targetable RM control commands with their "
                    "owning class, object graph depth, allocation chain "
                    "length, measured parameter size and rank, and the "
                    "populations excluded from the targetable set."),
        "",
        provenance(["surface/rm-control-rank.json",
                    "surface/rm-control-inventory.json",
                    "surface/rm-object-graph.json"]),
        "",
        "A control command is one leaf of `NV_ESC_RM_CONTROL`, selected by "
        "the `cmd` field of `NVOS54_PARAMETERS`. The control inventory "
        "enumerates %d exported commands. %d of them are targetable by an "
        "unprivileged local process against a driver built with GSP offload, "
        "and this page lists those %d."
        % (summary.get("methods", 0), len(commands), len(commands)),
        "",
        "## Excluded populations",
        "",
        "Each row states a population the targetable set omits and the field "
        "the inventory records it under. The populations are disjoint and "
        "reduce the exported set to the targetable one.",
        "",
        table(["Population", "Commands", "Inventory field"],
              [["Exported by the generated `_nvoc.c` tables",
                summary.get("methods", 0), code("methods")],
               ["Callable only from an internal RM client",
                reach.get("internal", 0), "`reachability` = `internal`"],
               ["Callable only from kernel space",
                reach.get("kernel_only", 0), "`reachability` = `kernel_only`"],
               ["Gated on a privileged client",
                reach.get("privileged", 0), "`reachability` = `privileged`"],
               ["Routed to GSP, so the CPU-side handler is compiled out",
                gsp, code("handler_compiled_out")],
               ["Targetable", len(commands), "(the set below)"]]),
        "",
        "## Chain availability",
        "",
        "Three counts over the same %d commands. They differ, and a "
        "measurement quoting one where another belongs is off by up to %d "
        "commands." % (len(commands), len(commands) - with_chain),
        "",
        table(["Measure", "Commands", "Basis"],
              [["Naming an owning class", len(commands),
                "every ranked record carries `owning_class`"],
               ["Whose owning class has an `RS_ENTRY` row", with_entry,
                "the owning class appears in `rm-object-graph.json`"],
               ["With a chain an unprivileged process can build", with_chain,
                "`no_chain_reason` is null"]]),
        "",
        table(["`no_chain_reason`", "Commands"],
              [[code(reason) if reason else "`null`, a chain exists",
                count]
               for reason, count in sorted(
                   reasons.items(), key=lambda kv: (-kv[1], str(kv[0])))]),
        "",
        "## Ranking",
        "",
        "`tools/ctrl_rank.py rank` scores each command on three normalised "
        "components and sorts on the weighted sum. Rank 1 is the highest "
        "score.",
        "",
        table(["Component", "Weight", "Measure"],
              [["`cve`", num(weighting.get("cve")),
                "releases in which the handler's file, or the handler itself, "
                "was touched by a security fix"],
               ["`depth`", num(weighting.get("depth")),
                "the allocation chain length, inverted, so a shallow target "
                "scores higher"],
               ["`size`", num(weighting.get("size")),
                "the measured parameter struct size"],
               ["Function match multiplier",
                num(weighting.get("function_match_weight")),
                "applied when the hotspot resolves to the handler symbol, "
                "above a match on its file alone"]]),
        "",
        table(["Measure", "Value"],
              [[code(key), num(value)]
               for key, value in sorted(counts.items())]),
        "",
        "## Ranked commands",
        "",
        "Sorted by rank. The name of a control command in this project is its "
        "handler symbol, because the generated `_nvoc.c` export tables carry "
        "that symbol and every later stage joins on the syzlang variant "
        "`ioctl$NV_ESC_RM_CONTROL_<handler>`. Graph depth is the shallowest "
        "depth any external class the owning class exports sits at. Chain "
        "length is the number of allocations the chain builder found. The two "
        "diverge where a class declares `<any parent>`.",
        "",
        table(["Rank", "Handler", "Class id", "Method id", "Owning class",
               "Graph depth", "Chain length", "Parameter struct",
               "Parameter size, bytes", "Score", "`cve`", "`depth`", "`size`"],
              [[c["rank"], code(c["handler"]), code(c["class_id"]),
                code(c["method_id"]), code(c["owning_class"]),
                num(depths.get(c["owning_class"])),
                num(c.get("chain_length")),
                code(c.get("param_struct")), num(c.get("param_size")),
                num(c.get("rank_score")),
                num((c.get("rank_components") or {}).get("cve")),
                num((c.get("rank_components") or {}).get("depth")),
                num((c.get("rank_components") or {}).get("size"))]
               for c in sorted(commands, key=lambda c: c["rank"])]),
        "",
        "## Commands with no buildable chain",
        "",
        "Sorted by owning class, then handler. These %d commands are exported "
        "and non-privileged, and no allocation chain reaches an object that "
        "owns them, so a program calling one holds no valid `hObject`."
        % (len(commands) - with_chain),
        "",
        table(["Handler", "Owning class", "Method id", "Reason"],
              [[code(c["handler"]), code(c["owning_class"]),
                code(c["method_id"]), code(c["no_chain_reason"])]
               for c in sorted(commands,
                               key=lambda c: (c["owning_class"],
                                              c["handler"]))
               if c.get("no_chain_reason")]),
        "",
        "## See also",
        "",
        "- [Allocation classes](/gspwn/reference/surface/allocation-classes/)",
        "- [Escapes](/gspwn/reference/surface/escapes/)",
        "- [`ctrl_rank.py`](/gspwn/architecture/components/ctrl-rank/)",
        "- [`ctrl_surface.py`](/gspwn/architecture/components/ctrl-surface/)",
    ]
    return "\n".join(parts).rstrip() + "\n", len(commands)


# --------------------------------------------------------------------------
# allocation-classes.md
# --------------------------------------------------------------------------

def parent_sets(alloc_records):
    """-> (key by parent tuple, ordered rows).

    63 of the 155 allocatable classes declare the same 11 GPFIFO parents and
    14 distinct sets cover all of them, so the sets go in their own table and
    each class names one by key. Ordered by member count descending, then by
    the joined member names, so the keys are stable across runs.
    """
    seen = {}
    for record in alloc_records:
        seen[tuple(record.get("parents") or [])] = \
            seen.get(tuple(record.get("parents") or []), 0) + 1
    order = sorted(seen, key=lambda members: (-seen[members], len(members),
                                              members))
    keys = {members: "P%d" % (index + 1) for index, members in
            enumerate(order)}
    rows = [[keys[members], len(members), seen[members],
             ", ".join(code(m) for m in members)] for members in order]
    return keys, rows


def page_alloc(docs):
    graph, chains = docs["graph"], docs["chains"]
    targets = docs["targets"]
    by_class = {r["external_class"]: r for r in graph["records"]}
    alloc = sorted((t for t in targets.values() if t["family"] == "alloc"),
                   key=lambda t: t["external_class"])
    records = [by_class[t["external_class"]] for t in alloc]
    keys, set_rows = parent_sets(records)
    counts = chains.get("counts", {})
    reach = chains.get("cumulative_reach", [])
    unresolved = chains.get("unresolved_owning_classes", [])
    class_id = {t["external_class"]: t.get("class_id") for t in alloc}

    parts = [
        frontmatter("Allocation classes",
                    "The 155 classes an unprivileged process can allocate, "
                    "their legal parents and depth, the 98 allocation chains "
                    "with the commands each unlocks, and the cumulative reach "
                    "curve over the control surface."),
        "",
        provenance(["surface/rm-object-graph.json",
                    "surface/rm-chains.json"]),
        "",
        "The `RS_ENTRY` table in `resource_list.h` declares %d classes. A "
        "class is allocatable by an unprivileged process when its "
        "`RS_FLAGS_ALLOC_*` reading is `unprivileged`, and %d classes qualify "
        "once the three depth-1 root classes parented by the file descriptor "
        "itself are counted, which carry no privilege flag because the file "
        "descriptor is the gate. Allocating a class is the prologue every "
        "control command that class owns depends on."
        % (graph.get("record_count", len(graph["records"])), len(alloc)),
        "",
        "## Allocatable classes",
        "",
        "Sorted by external class name. The parent set column names a row of "
        "[Parent sets](#parent-sets). A class id is present only where the "
        "owning internal class also exports control methods, because the "
        "object graph carries no numeric field of its own.",
        "",
        table(["External class", "Internal class", "Class id",
               "Allocation privilege", "Depth", "Parent set",
               "Allocation parameter", "Parameter struct"],
              [[code(r["external_class"]), code(r["internal_class"]),
                code(class_id.get(r["external_class"])),
                code(r.get("alloc_privilege")), num(r.get("depth")),
                code(keys[tuple(r.get("parents") or [])]),
                code(r.get("alloc_param_kind")),
                code(r.get("alloc_param_struct"))]
               for r in records]),
        "",
        "## Parent sets",
        "",
        "The legal parents each allocatable class declares, one row per "
        "distinct set. `<root fd>` is the file descriptor itself and "
        "`<any parent>` is the table's own wildcard.",
        "",
        table(["Key", "Parent count", "Classes using it",
               "Legal parents"],
              set_rows),
        "",
        "## Allocation chains",
        "",
        "`tools/object_graph.py chains` groups the control surface by owning "
        "internal class and builds the shortest allocation sequence that "
        "reaches one. Sorted by internal class. The prologue column is that "
        "sequence, root first.",
        "",
        table(["Internal class", "Target external class", "Chain length",
               "Prologue", "Commands unlocked", "Unallocatable reason"],
              [[code(c["internal_class"]), code(c.get("target_external_class")),
                num(c.get("chain_length")),
                " > ".join(code(step["external_class"])
                           for step in c.get("chain") or []) or "(none)",
                num(c.get("command_count")),
                code(c.get("unallocatable_reason"))
                if c.get("unallocatable_reason") else "(none)"]
               for c in sorted(chains["chains"],
                               key=lambda c: c["internal_class"])]),
        "",
        table(["Measure", "Value"],
              [[code(key), num(value)]
               for key, value in sorted(counts.items())]),
        "",
        "## Cumulative reach",
        "",
        "Adding one owning class at a time, in the order that reaches the "
        "most commands soonest, against the number of allocations the "
        "prologues need in total. The curve flattens: the first two classes "
        "reach %d of the %d commands with %d allocations, and the remaining "
        "%d classes cost %d further allocations."
        % (reach[1]["commands"] if len(reach) > 1 else 0,
           reach[-1]["commands"] if reach else 0,
           reach[1]["allocations"] if len(reach) > 1 else 0,
           max(len(reach) - 2, 0),
           (reach[-1]["allocations"] - reach[1]["allocations"])
           if len(reach) > 1 else 0),
        "",
        table(["Step", "Class added", "Commands reached",
               "Allocations in total", "Allocations added"],
              [[index + 1, code(row.get("class_added")),
                num(row.get("commands")), num(row.get("allocations")),
                num(row.get("new_allocations"))]
               for index, row in enumerate(reach)]),
        "",
        "## Owning classes with no chain",
        "",
        "An owning class the chain builder could not reach. The commands "
        "listed here appear under no chain record, and the block exists so "
        "the per-command account still totals %d."
        % counts.get("targetable_commands", 0),
        "",
        table(["Owning class", "Commands", "Reason", "Handlers"],
              [[code(row.get("owning_class")), num(row.get("command_count")),
                code(row.get("reason")),
                ", ".join(code(h) for h in row.get("commands") or [])]
               for row in sorted(unresolved,
                                 key=lambda r: r.get("owning_class") or "")]),
        "",
        "## See also",
        "",
        "- [Control commands](/gspwn/reference/surface/control-commands/)",
        "- [Escapes](/gspwn/reference/surface/escapes/)",
        "- [`object_graph.py`](/gspwn/architecture/components/object-graph/)",
        "- [Resource Manager object model]"
        "(/gspwn/knowledgebase/rm-object-model/)",
    ]
    return "\n".join(parts).rstrip() + "\n", len(alloc) + len(chains["chains"])


# --------------------------------------------------------------------------
# driver-cves.md
# --------------------------------------------------------------------------

def condense(sentence):
    """-> NVIDIA's component and fault clause, with nothing added.

    The bulletin sentences share one shape: a product-and-version preamble,
    the words "contains a vulnerability", the component and the fault, then an
    impact clause. Both ends are cut and what remains is a contiguous
    substring of what NVIDIA published, in NVIDIA's own casing. A sentence
    matching neither pattern is left whole, because a paraphrase would stop
    the row matching the bulletin.
    """
    text = (sentence or "").strip()
    if not text:
        return ""
    text = CVE_HEAD.sub("", text, count=1)
    return CVE_TAIL.sub("", text, count=1).strip().rstrip(",")


# The verdict tools/cve_patch_map.py records against each disclosure, and what
# the mining established to reach it. The artefact carries no vocabulary block
# of its own, so the readings are stated here and asserted against the record
# shape: every `unresolved` record carries a reason and no release pair, and
# every other verdict carries a basis.
VERDICT_READINGS = [
    ("located",
     "The bracketed releases isolate the hunk, and the functions it changed "
     "are named below."),
    ("plausible",
     "The bracketed releases carry a change matching the weakness the "
     "bulletin describes, and the bulletin fixes several kernel-mode "
     "disclosures in one release, so the attribution follows from the "
     "weakness class and not from the diff alone."),
    ("not_located",
     "One patch set answers for several disclosures in the bulletin, so the "
     "diff establishes the set of functions the fixes touched and nothing "
     "about which disclosure any hunk belongs to."),
    ("unresolved",
     "No release pair could be bracketed at all, for the reason recorded "
     "against the disclosure."),
]

# The three joins a changed function can carry to the modelled surface.
# `escape_file` is excluded from the entry-point table below, because the
# artefact's own note on that kind states the file-level join places the
# function on no single escape's path.
ENTRY_POINT_KINDS = ("rm_control", "uvm_command")


def _entry_points(record):
    """-> (control method ids, UVM command names) the patch set touched.

    A property of the whole patch set and not of the disclosure: for the 45
    records the mining could not narrow, several disclosures share one set.
    """
    control, uvm = set(), set()
    for changed in record.get("changed_functions") or []:
        for target in changed.get("targets") or []:
            if target.get("kind") == "rm_control":
                control.add(target.get("method_id"))
            elif target.get("kind") == "uvm_command":
                uvm.add(target.get("command"))
    return control, uvm


def _basis_keys(records):
    """-> (basis text -> key, ordered rows).

    19 distinct texts cover the 53 records that carry one, and bulletin 5415's
    runs to 19 records on its own. The texts go in their own table and each
    disclosure names one by key, ordered by the number of disclosures sharing
    it and then by the text, so the keys are stable across runs.
    """
    shared = {}
    for record in records:
        basis = record.get("verdict_basis")
        if basis:
            shared[basis] = shared.get(basis, 0) + 1
    order = sorted(shared, key=lambda text: (-shared[text], text))
    keys = {text: "B%d" % (index + 1) for index, text in enumerate(order)}
    rows = [[keys[text], shared[text],
             ", ".join(code(r["cve"]) for r in records
                       if r.get("verdict_basis") == text),
             text]
            for text in order]
    return keys, rows


def fix_location_sections(docs):
    """-> the markdown driver-cves.md carries below the bulletin tables.

    The join between the classified record and the patch-mining output. Every
    row states how far the mining got for one disclosure, which is the only
    honest way to render it: 45 of the 61 share a patch set with other
    disclosures in the same bulletin, and a per-CVE function list for those
    would attribute a hunk the diff does not attribute.
    """
    doc = docs["hotspots"]
    records = sorted(doc["records"],
                     key=lambda r: (r.get("bulletin_date") or "",
                                    r.get("cve") or ""))
    summary = doc.get("summary", {})
    verdicts = summary.get("verdict_counts", {})
    keys, basis_rows = _basis_keys(records)
    by_function = [f for f in doc.get("hotspots", {}).get("by_function", [])
                   if any(t.get("kind") in ENTRY_POINT_KINDS
                          for t in f.get("targets") or [])]

    named = [r for r in records if r.get("fix_functions")]
    unresolved = [r for r in records if r.get("unresolved_reason")]
    family = _family_lookup(docs)

    parts = [
        "## Fix location",
        "",
        "`tools/cve_patch_map.py` brackets each disclosure between the "
        "release that fixed it and the release before, over the branches the "
        "open-source repository carries, and reads the diff. %d of the %d "
        "resolved to a release pair, across %d distinct pairs, and %d "
        "resolved to a named function."
        % (summary.get("resolved_to_tag_pair", 0),
           summary.get("kernel_mode_cves", len(records)),
           summary.get("distinct_tag_pairs", 0),
           summary.get("resolved_to_named_function", 0)),
        "",
        table(["Verdict", "Disclosures", "Reading"],
              [[code(name), num(verdicts.get(name)), reading]
               for name, reading in VERDICT_READINGS]),
        "",
        "Sorted by bulletin date, then CVE identifier. The entry point counts "
        "are a property of the patch set and not of the disclosure: where "
        "several disclosures share one release, every one of them carries the "
        "same count. The basis column names a row of "
        "[Verdict basis](#verdict-basis).",
        "",
        table(["CVE", "Verdict", "Release brackets", "Disclosures sharing "
               "the patch set", "Fix functions named", "Control commands in "
               "the patch set", "UVM commands in the patch set", "Basis"],
              [_fix_row(r, keys) for r in records]),
        "",
        "## Verdict basis",
        "",
        "The reason the mining reached the verdict it did, one row per "
        "distinct text.",
        "",
        table(["Key", "Disclosures", "CVEs", "Basis"], basis_rows),
        "",
        "## Located fix functions",
        "",
        "The %d disclosures the mining narrowed to a function, one row per "
        "function. A `plausible` row names the function the release changed "
        "in the way the weakness class describes. For those the diff leaves "
        "the attribution open, and the basis above states so."
        % len(named),
        "",
        table(["CVE", "Verdict", "File", "Function"],
              [[code(r["cve"]), code(r["verdict"])] + list(_split_fn(fn))
               for r in named for fn in r["fix_functions"]]),
        "",
        "## Reachability of the located paths",
        "",
        "Whether the modelled attacker, an unprivileged local process in a "
        "`compute,utility` container, reaches the fixed code. The column "
        "carries this project's reading, recorded in the verdict overlay "
        "`tools/cve_fix_verdicts.json`.",
        "",
        table(["CVE", "Reachability of the fixed path"],
              [[code(r["cve"]), r["reachability_note"]]
               for r in records if r.get("reachability_note")]),
        "",
        "## Disclosures with no bracketed release",
        "",
        "The mining could not start on these %d. Neither the fixed release "
        "nor the release before it is present as a tag in the open-source "
        "repository, so there is no diff to read." % len(unresolved),
        "",
        table(["CVE", "Reason"],
              [[code(r["cve"]), r["unresolved_reason"]]
               for r in unresolved]),
        "",
        "## Fixed functions that are entry points",
        "",
        "Functions a security fix touched that are themselves a control "
        "command handler or a UVM command handler. %d of the %d ranked "
        "functions qualify. A function whose only join is `escape_file` is "
        "absent, because the artefact's own note on that kind states the "
        "file-level join places the function on no single escape's path. "
        "`Releases` counts the bracketed releases the function was changed "
        "in, which is the measure the `cve` rank component on "
        "[Control commands](/gspwn/reference/surface/control-commands/) is "
        "computed from. The family column carries the surface family "
        "`tools/surface_cov.py` places the command in, so a row outside the "
        "764-target model is visible as one."
        % (len(by_function),
           len(doc.get("hotspots", {}).get("by_function", []))),
        "",
        table(["Function", "File", "Releases", "Lines changed", "Signals",
               "Disclosures bracketing it", "Target", "Owning class",
               "Reachability", "Allocation depth", "Surface family"],
              [_entry_row(f, family) for f in sorted(
                  by_function, key=lambda f: (-f.get("releases", 0),
                                              f.get("function") or ""))]),
        "",
    ]
    return parts


def _split_fn(qualified):
    """-> (file, function) for a `path::name` entry in `fix_functions`."""
    path, _sep, name = qualified.rpartition("::")
    return code(path or "(none)"), code(name)


def _fix_row(record, keys):
    control, uvm = _entry_points(record)
    pairs = record.get("tag_pairs") or []
    shared = max((len(v) for v in
                  (record.get("shared_patch_set") or {}).values()), default=0)
    return [code(record["cve"]), code(record.get("verdict")),
            ", ".join(code("%s..%s" % (p.get("from"), p.get("to")))
                      + (" (cross-branch)" if p.get("cross_branch") else "")
                      for p in pairs) or "(none)",
            shared,
            len(record.get("fix_functions") or []),
            len(control), len(uvm),
            code(keys.get(record.get("verdict_basis")))]


def _family_lookup(docs):
    """-> a function turning one hotspot target into its surface family.

    The families are tools/surface_cov.py's, so a hot function's row states
    whether the command it handles sits in the denominator the campaign
    measures against, in an excluded population, or outside the model. A
    privileged control command belongs to none of the three, because the
    model starts from the non-privileged export flag.
    """
    handlers = {}
    for method in docs["ctrl"].get("methods", []):
        if method.get("method_id") and method.get("handler"):
            handlers.setdefault(method["method_id"], method["handler"])
    targets, excluded = docs["targets"], docs["excluded"]

    def family(target):
        if target.get("kind") == "rm_control":
            handler = handlers.get(target.get("method_id"))
            key = surface_cov.CONTROL_PREFIX + handler if handler else None
        else:
            key = target.get("command")
        record = targets.get(key) or excluded.get(key)
        return record["family"] if record else None
    return family


def _entry_row(function, family):
    target = [t for t in function.get("targets") or []
              if t.get("kind") in ENTRY_POINT_KINDS][0]
    name = (target.get("method_id") if target.get("kind") == "rm_control"
            else target.get("command"))
    placed = family(target)
    return [code(function.get("function")), code(function.get("file")),
            num(function.get("releases")), num(function.get("lines_changed")),
            ", ".join(code(s) for s in function.get("signals") or [])
            or "(none)",
            num(function.get("cve_count")),
            code(name), code(target.get("owning_class")),
            code(target.get("reachability")), num(target.get("alloc_depth")),
            code(placed) if placed else "(outside the model)"]


def page_cves(docs):
    doc = docs["cves"]
    by_class = doc.get("counts_by_classification", {})
    values = doc.get("classification_values", {})
    records = sorted((r for r in doc["records"] if r.get("classification")
                      == "K"),
                     key=lambda r: (r.get("bulletin_date") or "",
                                    r.get("cve") or ""))

    parts = [
        frontmatter("Driver CVEs",
                    "The 61 publicly disclosed vulnerabilities NVIDIA places "
                    "in the kernel modules this project fuzzes, with CWE, "
                    "CVSS, the bulletin sentence, and what reading the fixing "
                    "diff established about where each one lives."),
        "",
        provenance(["surface/prior-cves.json",
                    "surface/cve-hotspots.json"]),
        "",
        "The classified record holds %d disclosures across the NVIDIA GPU "
        "display driver and the NVIDIA Container Toolkit, bulletins dated %s "
        "to %s. This page lists the %d classified `K`, a value the artefact "
        "defines as:"
        % (doc.get("count", len(doc["records"])),
           min(r.get("bulletin_date") or "" for r in doc["records"]),
           max(r.get("bulletin_date") or "" for r in doc["records"]),
           by_class.get("K", len(records))),
        "",
        "> " + values.get("K", ""),
        "",
        "The %d classified `U`, the %d classified `ambiguous` and the %d "
        "classified `out` are absent here on purpose. "
        "[Prior vulnerabilities](/gspwn/knowledgebase/prior-vulnerabilities/) "
        "carries all %d with the classification method, the sources behind "
        "each verdict, the published research on the ones with technical "
        "detail, and the limits of the disclosed record. This page is the "
        "in-scope subset as a working reference and repeats none of that "
        "method text."
        % (by_class.get("U", 0), by_class.get("ambiguous", 0),
           by_class.get("out", 0), doc.get("count", len(doc["records"]))),
        "",
        "## Disclosures",
        "",
        "Sorted by bulletin date, then CVE identifier. The CVSS values are "
        "NVIDIA's own scoring as the CNA, reproduced from the bulletin.",
        "",
        table(["CVE", "Bulletin date", "Bulletin", "CWE", "CVSS base score",
               "CVSS vector", "Subsystem"],
              [["[%s](https://nvd.nist.gov/vuln/detail/%s)"
                % (r["cve"], r["cve"]),
                r.get("bulletin_date") or "(none)",
                "[%s](%s)" % (r.get("bulletin_id"), r.get("bulletin_url"))
                if r.get("bulletin_url") else num(r.get("bulletin_id")),
                code(r.get("cwe")), num(r.get("cvss_base_score")),
                code(r.get("cvss_vector")), code(r.get("subsystem"))]
               for r in records]),
        "",
        "## Component and fault",
        "",
        "The wording of the middle column is NVIDIA's. Each cell is a "
        "contiguous substring of the bulletin sentence, with the leading "
        "product-and-version preamble and the trailing impact clause removed "
        "and NVIDIA's own casing kept. The whole sentence and the impact list "
        "are in `surface/prior-cves.json` under "
        "`component_as_nvidia_words_it`. The basis column carries this "
        "project's reason for placing the disclosure in the kernel-module "
        "layer.",
        "",
        table(["CVE", "Component and fault, in NVIDIA's words",
               "Classification basis"],
              [[code(r["cve"]),
                condense(r.get("component_as_nvidia_words_it")),
                r.get("classification_basis") or "(none)"]
               for r in records]),
        "",
    ] + fix_location_sections(docs) + [
        "## See also",
        "",
        "- [Prior vulnerabilities]"
        "(/gspwn/knowledgebase/prior-vulnerabilities/)",
        "- [Control commands](/gspwn/reference/surface/control-commands/)",
        "- [Historical targeting](/gspwn/architecture/historical-targeting/)",
        "- [`cve_patch_map.py`]"
        "(/gspwn/architecture/components/cve-patch-map/)",
    ]
    return "\n".join(parts).rstrip() + "\n", len(records)


# --------------------------------------------------------------------------
# index.md
# --------------------------------------------------------------------------

PAGE_SOURCES = {
    "escapes.md": ["surface/ioctl-inventory.json",
                   "tools/ioctl_map.json"],
    "control-commands.md": ["surface/rm-control-rank.json",
                            "surface/rm-control-inventory.json",
                            "surface/rm-object-graph.json"],
    "allocation-classes.md": ["surface/rm-object-graph.json",
                              "surface/rm-chains.json"],
    "driver-cves.md": ["surface/prior-cves.json",
                       "surface/cve-hotspots.json"],
}

PAGE_TITLES = {
    "escapes.md": ("Escapes", "escapes",
                   "The dispatched RM escapes, the two multiplexers, and the "
                   "declared escapes no switch reaches"),
    "control-commands.md": ("Control commands", "control-commands",
                            "The targetable control commands, ranked, with "
                            "their owning class, depth and parameter size"),
    "allocation-classes.md": ("Allocation classes", "allocation-classes",
                              "The allocatable classes, the allocation "
                              "chains, and the cumulative reach curve"),
    "driver-cves.md": ("Driver CVEs", "driver-cves",
                       "The disclosures NVIDIA places in the kernel modules "
                       "this project fuzzes, and where reading the fixing "
                       "diff placed each one"),
}


def page_index(docs, rows):
    meta, targets = docs["meta"], docs["targets"]
    families = {}
    for record in targets.values():
        families[record["family"]] = families.get(record["family"], 0) + 1
    excluded = {}
    for record in docs["excluded"].values():
        excluded[record["family"]] = excluded.get(record["family"], 0) + 1

    parts = [
        frontmatter("Enumerated surface",
                    "The attack surface as browsable tables: escapes, "
                    "control commands, allocation classes and the prior "
                    "kernel-module CVEs, generated from the committed "
                    "artefacts."),
        "",
        provenance(sorted({s for sources in PAGE_SOURCES.values()
                           for s in sources})),
        "",
        "Four pages render the enumerated surface of driver %s. Every row is "
        "read from an artefact under `surface/`, and nothing on "
        "these pages is written by hand."
        % code(meta.get("driver_version") or "unknown"),
        "",
        "## Pages",
        "",
        table(["Page", "Records", "Contents", "Source artefacts"],
              [["[%s](/gspwn/reference/surface/%s/)" % (PAGE_TITLES[name][0],
                                                        PAGE_TITLES[name][1]),
                rows[name], PAGE_TITLES[name][2],
                ", ".join(code(s) for s in PAGE_SOURCES[name])]
               for name in sorted(PAGE_SOURCES)]),
        "",
        "## Surface model totals",
        "",
        "`tools/surface_cov.py` builds the denominator every later "
        "measurement joins against. A target holds one syzlang call name; an "
        "excluded population holds none, for the stated reason.",
        "",
        table(["Family", "Targets", "Meaning"],
              [[code(name), families[name], meaning]
               for name, meaning in
               [("escape", "one `case` of the RM `switch`"),
                ("uvm", "one command of `/dev/nvidia-uvm`"),
                ("uvm_tools", "one command of `/dev/nvidia-uvm-tools`"),
                ("control", "one leaf of `NV_ESC_RM_CONTROL`"),
                ("alloc", "one leaf of `NV_ESC_RM_ALLOC`")]
               if name in families]),
        "",
        table(["Excluded family", "Records", "Reason"],
              [[code(name), excluded[name], reason]
               for name, reason in
               [("control_gsp", "the CPU-side handler is compiled out under "
                                "GSP offload"),
                ("uvm_test", "gated behind a build-time test switch"),
                ("escape_mux", "a dispatcher whose leaves are counted in the "
                               "control and allocation families"),
                ("escape_dead", "declared in a header and dispatched by "
                                "nothing")]
               if name in excluded]),
        "",
        "Total targets: %d." % len(targets),
        "",
        "## Staleness",
        "",
        "`%s` regenerates all five pages into a temporary directory and "
        "compares them against the committed copies, naming the page and the "
        "first differing line when they disagree. It runs in the same offline "
        "CI job as the other four artefact checks, so an artefact "
        "regenerated against a new driver release without regenerating these "
        "pages fails the build." % CHECK,
        "",
        "## See also",
        "",
        "- [Attack surface](/gspwn/architecture/attack-surface/)",
        "- [Artifacts](/gspwn/reference/artifacts/)",
        "- [`surface_cov.py`](/gspwn/architecture/components/surface-cov/)",
    ]
    return "\n".join(parts).rstrip() + "\n"


# --------------------------------------------------------------------------
# Rendering and writing
# --------------------------------------------------------------------------

BUILDERS = [
    ("escapes.md", page_escapes),
    ("control-commands.md", page_control),
    ("allocation-classes.md", page_alloc),
    ("driver-cves.md", page_cves),
]


def render(docs=None):
    """-> ({filename: text}, {filename: record count}), fully deterministic."""
    docs = docs or load_all()
    pages, rows = {}, {}
    for name, builder in BUILDERS:
        pages[name], rows[name] = builder(docs)
    pages["index.md"] = page_index(docs, rows)
    rows["index.md"] = len(BUILDERS)
    return pages, rows


def write(pages, out_dir):
    """Write each page atomically with LF endings, creating out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name in sorted(pages):
        target = os.path.join(out_dir, name)
        handle = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=out_dir,
            prefix=name + ".", suffix=".tmp", delete=False)
        try:
            with handle:
                handle.write(pages[name])
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(handle.name, target)
        except BaseException:
            # Never leave a half-written page or a stray temp file behind: a
            # temp file inside the content directory is a page Starlight
            # would try to build.
            if os.path.exists(handle.name):
                os.unlink(handle.name)
            raise
        written.append(target)
        logger.info("wrote %s, %d bytes", target, len(pages[name]))
    return written


def build_parser():
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(__doc__.splitlines()[1:]))
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help="directory to write the pages into (default: "
                             "docs/src/content/docs/reference/surface)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="log every page written and its size")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s")
    try:
        pages, rows = render()
        write(pages, args.out)
    except RefgenError as exc:
        print("refgen: cannot run: %s" % exc, file=sys.stderr)
        return 2
    print("refgen: wrote %d page(s) to %s" % (len(pages), args.out))
    print()
    print("  %-24s %8s %10s" % ("page", "records", "bytes"))
    print("  %-24s %8s %10s" % ("-" * 24, "-" * 8, "-" * 10))
    for name in sorted(pages):
        print("  %-24s %8d %10d"
              % (name, rows[name], len(pages[name].encode("utf-8"))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
