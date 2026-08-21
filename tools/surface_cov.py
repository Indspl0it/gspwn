#!/usr/bin/env python3
"""Surface coverage: the share of the reachable command surface a corpus reaches.

`tools/coverage_ctl.py` measures edges. An edge count answers whether the
fuzzer is still finding new code and says nothing about which commands it never
tried, because the driver's edge space has no known size. That is why
`config/campaign.yaml` disclaims a "covered X% of the driver" reading of it.

A different denominator does exist. The driver enumerates its own command
surface, and `ioctl_inventory.py`, `ctrl_surface.py` and `object_graph.py`
extract it: 34 dispatched escapes, 46 UVM commands, 531 control commands that
are non-privileged and carry a kernel-side handler, and the unprivileged
allocatable classes. Counting how many of those a corpus names is a ratio over
a measured denominator, and it is a claim about the command surface and never
about lines of driver code.

The count decomposes into three stages, and a loss at each one has a different
fix:

  targetable   the inventories: what a default tenant may call at all
  modelled     artifacts/descriptions/: what syzlang declares a variant for
  exercised    the corpus: what programs actually name

modelled/targetable is the describe phase's own completeness. exercised over
modelled is whether the fuzzer builds programs valid enough to emit the call at
all, which a wrong resource chain sinks. Reporting only the headline hides
which stage lost the surface.

The measurement works because `syzlang_gen.py` names every control command as
its own syzlang variant, `ioctl$NV_ESC_RM_CONTROL_<handler>`, and never one
opaque `NV_ESC_RM_CONTROL` with a command field. The corpus text is therefore
self-describing and needs no KCOV, no syz-manager and no GPU.

Three groups sit outside the denominator and are reported separately, because
folding them in would move the ratio without any campaign changing:

  236 non-privileged control commands whose handler is compiled out and whose
      parameter buffer crosses the RPC queue to GSP. The tenant can call them
      and the marshalling is kernel-side, so they are worth fuzzing, and the
      handler runs on firmware KCOV cannot instrument. Effort spent here raises
      executions and never edges, which reads as a plateau.
  104 UVM test commands, which need uvm_enable_builtin_tests=1.
    3 declared escapes with no dispatch case.

The privilege flag is necessary and not sufficient, so `targetable` is an
upper bound. 16 of the 531 control commands carry a capability check inside
the handler body that the RMCTRL flag word does not show, reached through
rmclientIsCapableOrAdmin, rmclientIsCapable or rmclientIsAdmin.
subdeviceCtrlCmdGpuSetFabricAddr (0x2080016f) is flagged NON_PRIVILEGED and
then calls rmclientIsCapableOrAdmin(NV_RM_CAP_EXT_FABRIC_MGMT). That 16 is a
floor: the scan attributes a call to the function it sits in, so a check
inside a helper the handler calls is invisible to it. Whether any of them
refuses the modelled caller is a question only a call on the SUT settles, and
the command stays in the denominator because its rejection path is reachable
kernel code.

This runs entirely off committed artefacts. No GPU, no SUT.

Subcommands:
  targets [--json] [--out PATH]        the denominator, by family
  modelled [--desc DIR]                what the descriptions declare
  report [--desc DIR] [--corpus DIR]   the three-stage decomposition
  gaps [--stage STAGE] [--family F]    uncovered targets, worklist-ready
"""
import argparse
import json
import logging
import os
import re
import sys

logger = logging.getLogger("surface_cov")

# Deliberately no pipeline_state import: that module needs fcntl, and this tool
# reads only committed artefacts. Keeping it POSIX-free lets the describe agent
# check its own denominator on the workstation before the SUT exists.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SURFACE_DIR = os.path.join(REPO_ROOT, "artifacts", "surface")
DEFAULT_DESC = os.path.join(REPO_ROOT, "artifacts", "descriptions")
DEFAULT_CORPUS = os.path.join(REPO_ROOT, "artifacts", "seeds")

IOCTL_INV = os.path.join(SURFACE_DIR, "ioctl-inventory.json")
CTRL_INV = os.path.join(SURFACE_DIR, "rm-control-inventory.json")
OBJ_GRAPH = os.path.join(SURFACE_DIR, "rm-object-graph.json")

# A syzlang call line, and a call site inside a program. Both spell the variant
# the same way, so one pattern reads a description file and a corpus program.
VARIANT_RE = re.compile(r"\bioctl\$([A-Za-z0-9_]+)\s*\(")

# The sentinel object_graph.py writes for a class parented by the fd itself.
ROOT = "<root fd>"

CONTROL_PREFIX = "NV_ESC_RM_CONTROL_"
ALLOC_PREFIX = "NV_ESC_RM_ALLOC_"

# Families in report order. The first five are the denominator; the rest are
# counted and excluded, each for a reason `report` prints.
FAMILIES = ["escape", "uvm", "uvm_tools", "control", "alloc"]
EXCLUDED = ["control_gsp", "uvm_test", "escape_dead", "escape_mux"]

EXCLUSION_REASON = {
    "control_gsp": "handler compiled out; runs on GSP where KCOV cannot follow",
    "uvm_test": "needs uvm_enable_builtin_tests=1, which the target does not set",
    "escape_dead": "declared in nv_escape.h with no dispatch case",
    "escape_mux": "a multiplexer whose leaves are already counted in another family",
}

# Two escapes select the real target from a field in their own parameter
# struct, so counting the escape as one target and its leaves as more counts
# the same calls twice. NV_ESC_RM_CONTROL expands into the control family and
# NV_ESC_RM_ALLOC into alloc, which is why both denominators are per-leaf.
MULTIPLEXERS = {"NV_ESC_RM_CONTROL", "NV_ESC_RM_ALLOC"}

# Control commands flagged NON_PRIVILEGED whose handler body still calls
# rmclientIsCapableOrAdmin, rmclientIsCapable or rmclientIsAdmin. Measured by
# attributing every call site in src/nvidia/src to its enclosing function and
# joining on the exported method table. A floor, not a total: a check inside a
# helper the handler calls is not attributed to the handler. Measured against
# 610.57.04, the release every inventory here describes, so a driver change
# that surface_verify.py flags invalidates this count with the rest.
IN_HANDLER_CHECKS = 16


class SurfaceError(Exception):
    """An inventory is missing or lacks the fields this tool needs."""


def _load(path, what):
    if not os.path.exists(path):
        raise SurfaceError(
            "%s not found at %s. Regenerate it before measuring surface "
            "coverage: a missing inventory would silently shrink the "
            "denominator and inflate the ratio." % (what, path))
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as exc:
        raise SurfaceError("%s at %s could not be read: %s"
                           % (what, path, exc)) from exc


def _driver_version(obj):
    src = obj.get("source")
    if isinstance(src, dict):
        return src.get("driver_version")
    return None


def load_targets():
    """-> (targets, excluded, meta).

    targets maps a syzlang variant name to its record. The variant name is the
    join key for every stage, because it is what a description declares and
    what a corpus program names.
    """
    inv = _load(IOCTL_INV, "the ioctl inventory")
    ctrl = _load(CTRL_INV, "the RM control inventory")
    graph = _load(OBJ_GRAPH, "the RM object graph")

    versions = {p: _driver_version(o) for p, o in
                (("ioctl-inventory.json", inv),
                 ("rm-control-inventory.json", ctrl),
                 ("rm-object-graph.json", graph))}
    distinct = {v for v in versions.values() if v}
    if len(distinct) > 1:
        raise SurfaceError(
            "the inventories describe different driver releases (%s). A "
            "denominator mixed across releases counts commands that do not "
            "coexist. Regenerate them from one checkout, then re-run "
            "surface_verify.py check."
            % ", ".join("%s=%s" % kv for kv in sorted(versions.items())))

    targets, excluded = {}, {}

    for node in inv.get("nodes", []):
        module = node.get("module", "")
        paths = node.get("paths", [])
        # The UVM test commands share a node path and a module with the real
        # ones and are separated only by the gate the extractor recorded, so
        # the discriminator is `reachable` and never the command name.
        tools_node = any("uvm-tools" in p for p in paths)
        for command in node.get("commands", []):
            name = command.get("name")
            if not name:
                continue
            if module == "nvidia":
                family = "escape_mux" if name in MULTIPLEXERS else "escape"
            elif command.get("reachability_gate") or command.get(
                    "reachable") is False:
                family = "uvm_test"
            elif tools_node:
                family = "uvm_tools"
            else:
                family = "uvm"
            record = {
                "variant": name,
                "family": family,
                "label": name,
                "detail": command.get("param_struct") or "",
                "source": command.get("dispatch_site")
                or command.get("defined_at") or "",
            }
            (excluded if family in EXCLUDED else targets)[name] = record

    for name in inv.get("dead_escapes", []) or []:
        key = name if isinstance(name, str) else name.get("name")
        if key:
            excluded[key] = {"variant": key, "family": "escape_dead",
                             "label": key, "detail": "", "source": ""}
            targets.pop(key, None)

    for method in ctrl.get("methods", []):
        if method.get("reachability") != "non_privileged":
            continue
        handler = method.get("handler")
        if not handler:
            continue
        gsp = bool(method.get("handler_compiled_out"))
        variant = CONTROL_PREFIX + handler
        record = {
            "variant": variant,
            "family": "control_gsp" if gsp else "control",
            "label": "%s %s %s" % (method.get("sdk_prefix", "?"),
                                   method.get("method_id", "?"), handler),
            "detail": method.get("param_struct") or "",
            "owning_class": method.get("owning_class") or "",
            "method_id": method.get("method_id") or "",
            "source": method.get("source") or "",
        }
        (excluded if gsp else targets)[variant] = record

    for record in graph.get("records", []):
        # alloc_privilege carries the RS_FLAGS_ALLOC_* reading. The three
        # records spelling no privilege flag are "unclassified", and all three
        # are the depth-1 root classes parented by the fd itself: NV01_ROOT,
        # NV01_ROOT_NON_PRIV and NV01_ROOT_CLIENT. They carry no privilege flag
        # because the fd is the gate, and a default tenant allocates one as the
        # first call of every program. Excluding them would drop the entry
        # point of the whole DAG from the denominator.
        privilege = record.get("alloc_privilege")
        root = record.get("depth") == 1 and ROOT in record.get("parents", [])
        if privilege != "unprivileged" and not (
                privilege == "unclassified" and root):
            continue
        name = record.get("external_class")
        if not name:
            continue
        variant = ALLOC_PREFIX + str(name)
        # An escape of the same spelling wins: NV_ESC_RM_ALLOC_MEMORY is a
        # dispatched escape and not a class allocation, and counting it twice
        # would put one call in two families.
        if variant in targets:
            continue
        targets[variant] = {
            "variant": variant,
            "family": "alloc",
            "label": "class %s" % name,
            "detail": record.get("alloc_param_struct") or "",
            "source": "resource_list.h",
        }

    meta = {
        "driver_version": distinct.pop() if distinct else None,
        "inventories": versions,
    }
    logger.info("denominator: %d targets across %d families; %d excluded",
                len(targets), len(FAMILIES), len(excluded))
    return targets, excluded, meta


def scan_variants(paths, what):
    """-> {variant: [files it appears in]} over syzlang or program text."""
    seen = {}
    read = 0
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as exc:
            logger.warning("%s: %s (skipped)", path, exc)
            continue
        read += 1
        for match in VARIANT_RE.finditer(text):
            seen.setdefault(match.group(1), []).append(os.path.basename(path))
    logger.info("%s: %d file(s) read, %d distinct variant(s)",
                what, read, len(seen))
    if not read:
        logger.warning("%s: no files read; every stage below it reads as zero",
                       what)
    return seen


def _files(directory, suffixes):
    if not os.path.isdir(directory):
        return []
    out = []
    for root, _dirs, names in os.walk(directory):
        for name in sorted(names):
            if name.endswith(suffixes):
                out.append(os.path.join(root, name))
    return out


def _pct(part, whole):
    return 0.0 if not whole else 100.0 * part / whole


def _table(rows, headers):
    widths = [max(len(str(r[i])) for r in [headers] + rows)
              for i in range(len(headers))]
    print("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))


def cmd_targets(args):
    targets, excluded, meta = load_targets()
    if args.json or args.out:
        payload = {
            "schema": "gspwn.surface-targets/1",
            "driver_version": meta["driver_version"],
            "counts": {f: sum(1 for t in targets.values() if t["family"] == f)
                       for f in FAMILIES},
            "excluded": {f: sum(1 for t in excluded.values()
                                if t["family"] == f) for f in EXCLUDED},
            "targets": sorted(targets.values(), key=lambda t: t["variant"]),
        }
        text = json.dumps(payload, indent=1)
        if args.out:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".",
                        exist_ok=True)
            tmp = args.out + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(text + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, args.out)
            print("wrote %s" % args.out)
        else:
            print(text)
        return 0

    print("driver %s" % (meta["driver_version"] or "unknown"))
    rows = [[f, sum(1 for t in targets.values() if t["family"] == f)]
            for f in FAMILIES]
    rows.append(["total", len(targets)])
    _table(rows, ["family", "targets"])
    print()
    print("counted separately, outside the denominator:")
    _table([[f, sum(1 for t in excluded.values() if t["family"] == f),
             EXCLUSION_REASON[f]] for f in EXCLUDED],
           ["group", "count", "reason"])
    return 0


def stages(desc_dir, corpus_dir):
    targets, excluded, meta = load_targets()
    modelled = scan_variants(_files(desc_dir, (".txt",)), "descriptions")
    corpus_files = _files(corpus_dir, (".syz", ".prog"))
    exercised = scan_variants(corpus_files, "corpus")
    meta["corpus_programs"] = len(corpus_files)
    return targets, excluded, meta, set(modelled), set(exercised)


def cmd_modelled(args):
    targets, _excluded, meta, modelled, _ = stages(args.desc, args.corpus)
    covered = {v for v in targets if v in modelled}
    extra = modelled - set(targets)
    print("driver %s" % (meta["driver_version"] or "unknown"))
    rows = []
    for family in FAMILIES:
        total = [v for v, t in targets.items() if t["family"] == family]
        hit = [v for v in total if v in modelled]
        rows.append([family, len(hit), len(total),
                     "%.1f%%" % _pct(len(hit), len(total))])
    rows.append(["total", len(covered), len(targets),
                 "%.1f%%" % _pct(len(covered), len(targets))])
    _table(rows, ["family", "modelled", "targetable", "share"])
    if extra:
        print()
        print("%d variant(s) declared that no inventory names. An alternate "
              "calling form of a counted target is expected here, because one "
              "class can take two parameter structs. Anything else is either "
              "a description outside the tenant surface or a stale inventory:"
              % len(extra))
        for name in sorted(extra)[:args.top]:
            print("  %s" % name)
        if len(extra) > args.top:
            print("  ... %d more" % (len(extra) - args.top))
    return 0


def cmd_report(args):
    targets, excluded, meta, modelled, exercised = stages(args.desc,
                                                          args.corpus)
    rows = []
    for family in FAMILIES:
        total = [v for v, t in targets.items() if t["family"] == family]
        m = [v for v in total if v in modelled]
        e = [v for v in m if v in exercised]
        rows.append([family, len(total), len(m), len(e),
                     "%.1f%%" % _pct(len(e), len(total))])
    all_m = [v for v in targets if v in modelled]
    all_e = [v for v in targets if v in exercised]
    rows.append(["total", len(targets), len(all_m), len(all_e),
                 "%.1f%%" % _pct(len(all_e), len(targets))])

    if args.json:
        print(json.dumps({
            "schema": "gspwn.surface-coverage/1",
            "driver_version": meta["driver_version"],
            "descriptions": args.desc,
            "corpus": args.corpus,
            "by_family": {r[0]: {"targetable": r[1], "modelled": r[2],
                                 "exercised": r[3]} for r in rows[:-1]},
            "total": {"targetable": len(targets), "modelled": len(all_m),
                      "exercised": len(all_e)},
            "excluded": {f: sum(1 for t in excluded.values()
                                if t["family"] == f) for f in EXCLUDED},
        }, indent=1))
        return 0

    print("driver %s" % (meta["driver_version"] or "unknown"))
    print("descriptions %s" % args.desc)
    print("corpus       %s" % args.corpus)
    print()
    _table(rows, ["family", "targetable", "modelled", "exercised", "reached"])
    print()
    lost_model = len(targets) - len(all_m)
    lost_corpus = len(all_m) - len(all_e)
    print("%d targetable command(s) have no description: describe phase work."
          % lost_model)
    if not meta["corpus_programs"]:
        # An empty corpus is the pre-fuzz state, and reading it as a modelling
        # failure would send the describe agent to fix a description set that
        # nothing has run yet.
        print("The corpus at %s holds no programs, so the exercised column is "
              "empty by construction and says nothing about the descriptions. "
              "Re-read it after the first campaign." % args.corpus)
    else:
        print("%d modelled command(s) never appear in the %d corpus "
              "program(s): the programs do not build the state the call "
              "needs, which is a resource-chain problem before it is a seed "
              "problem." % (lost_corpus, meta["corpus_programs"]))
    print()
    print("outside the denominator: " + ", ".join(
        "%d %s" % (sum(1 for t in excluded.values() if t["family"] == f), f)
        for f in EXCLUDED))
    gsp = sum(1 for t in excluded.values() if t["family"] == "control_gsp")
    print("A corpus drifting onto the %d GSP-routed command(s) raises "
          "executions and never edges, so read a plateau verdict against this "
          "table before believing it." % gsp)
    print("targetable is an upper bound: %d control command(s) carry a "
          "capability check inside the handler that the RMCTRL flag word does "
          "not show, and that count is itself a floor." % IN_HANDLER_CHECKS)
    return 0


def cmd_gaps(args):
    targets, _excluded, _meta, modelled, exercised = stages(args.desc,
                                                            args.corpus)
    if args.stage == "model":
        missing = [t for v, t in targets.items() if v not in modelled]
        heading = "targetable, not modelled"
    else:
        missing = [t for v, t in targets.items()
                   if v in modelled and v not in exercised]
        heading = "modelled, not exercised"
    if args.family:
        missing = [t for t in missing if t["family"] == args.family]
    missing.sort(key=lambda t: (t["family"], t["variant"]))
    print("%s: %d" % (heading, len(missing)))
    if not missing:
        return 0
    print()
    for target in missing[:args.top]:
        print("- [surface] %s %s" % (target["family"], target["label"]))
    if len(missing) > args.top:
        print("... %d more (raise --top)" % (len(missing) - args.top))
    return 0


def add_shared(sub_parser):
    sub_parser.add_argument("--desc", default=DEFAULT_DESC,
                            help="description directory")
    sub_parser.add_argument("--corpus", default=DEFAULT_CORPUS,
                            help="corpus or seed-bank directory")
    sub_parser.add_argument("-v", "--verbose", action="store_true",
                            default=argparse.SUPPRESS, help="log at DEBUG")
    return sub_parser


def build_parser():
    ap = argparse.ArgumentParser(
        prog="surface_cov.py",
        description="Measure corpus coverage of the enumerated command surface.")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log at DEBUG")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = add_shared(sub.add_parser("targets", help="the denominator, by family"))
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.add_argument("--out", help="write the JSON to a file")
    p.set_defaults(func=cmd_targets)

    p = add_shared(sub.add_parser("modelled",
                                  help="what the descriptions declare"))
    p.add_argument("--top", type=int, default=20,
                   help="how many unmatched variants to list")
    p.set_defaults(func=cmd_modelled)

    p = add_shared(sub.add_parser("report",
                                  help="the three-stage decomposition"))
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.set_defaults(func=cmd_report)

    p = add_shared(sub.add_parser("gaps", help="uncovered targets"))
    p.add_argument("--stage", choices=["model", "corpus"], default="model",
                   help="which stage lost the target")
    p.add_argument("--family", choices=FAMILIES, help="restrict to one family")
    p.add_argument("--top", type=int, default=40, help="how many to list")
    p.set_defaults(func=cmd_gaps)
    return ap


def main():
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False)
        else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")
    try:
        return args.func(args)
    except SurfaceError as exc:
        print("surface_cov: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
