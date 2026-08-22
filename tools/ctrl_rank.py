#!/usr/bin/env python3
"""Rank the targetable RM control commands by how much a campaign should want them.

`tools/syzlang_gen.py --max-control N` emits the first N control commands of an
ordering, and the describe phase's work order asks for the same ordering. Until
this tool existed the ordering came from a four-value ladder on the SDK class
id, hardcoded in the generator, which put 337 of the 531 commands in one bucket
and separated nothing inside it.

Three measurements separate them, and all three are already on disk.

  chain_length     allocations an unprivileged process must make before the
                   command's owning object exists, from
                   surface/rm-chains.json. A command on the client
                   costs 1 and a command on a subdevice costs 3. The maximum
                   is whatever the joined data carries, 5 in this release, and
                   score_records derives it per run rather than assuming a
                   ceiling. A shorter prologue is a higher execution rate for
                   the same number of syscalls.
  cve_releases     how many driver releases changed the file the handler is
                   implemented in, and where the handler itself was changed,
                   how many changed that function, from
                   surface/cve-hotspots.json. Code that has been
                   fixed repeatedly is code the vendor keeps finding bugs in.
  param_size       bytes of attacker-controlled parameter struct, from
                   surface/ctrl-param-sizes.json. A larger struct is
                   more fields to get wrong.

The CVE join needs one thing the control inventory does not carry. Control
handlers are declared in the NVOC generated tables the inventory reads and
defined elsewhere under a suffix: `subdeviceCtrlCmdGpuGetInfoV2` is defined as
`subdeviceCtrlCmdGpuGetInfoV2_IMPL`. The hot-spot file names implementation
files, so joining on the inventory's `source` field matches nothing. This tool
scans `src` for definitions and records `impl_file`, `impl_line` and
`impl_suffix` per command, which is provenance worth having on its own.

A handler carries one hand-written definition under one of four suffixes.
`_IMPL` is the sole implementation where there is no HAL split; where there is,
the table dispatches to `_KERNEL`, `_PHYSICAL` or `_VF` instead. 13 of the 531
have no hand-written definition at all and resolve to an NVOC generated inline
under `src/nvidia/generated`, which has no release history of its own; those
carry `impl_state` "no hand-written definition" so a null `impl_file` cannot be
read as a scan that failed.

Weighting
---------

    rank_score = 0.50 * depth + 0.30 * cve + 0.20 * size

Each component is normalised to [0, 1] with 1 meaning rank earliest.

  depth   (max_chain_length - chain_length) / (max_chain_length - 1).
          A command with no chain scores 0. Reachability is also the leading
          term of the sort key, so the 17 commands with no chain sort after
          every command that has one whatever their other components say.
  cve     log2(releases + 1) / log2(max_releases + 1), taking the function
          record's release count when the handler itself appears in
          by_function and the file's count otherwise. A function-level match
          is scaled up by FUNCTION_WEIGHT because it names the changed code
          and not just the file holding it.
  size    log2(param_size + 1) / log2(max_param_size + 1). The distribution is
          heavily skewed, median 16 bytes against a maximum of 229392, so a
          raw byte count would put a handful of enormous diagnostic structs at
          the top of every campaign and the log flattens that.

The weights are a judgement no measurement settles, which is why all four
components are written out alongside the score. A consumer that disagrees can
re-sort on the components without re-running the scan.

Ties break on chain_length, then cve_releases descending, then method_id, so
the ordering is stable across runs and across hosts.

This runs entirely off the source tree and committed artefacts. No GPU, no SUT.

Subcommands:
  rank [--src DIR] [--out PATH]   write the ranked records
  report [--rank PATH] [--top N]  print the head of the ranking

Exit codes: 0 success, 1 bad input or a missing artefact.
"""
import argparse
import collections
import json
import logging
import math
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


# Anchored on the repository and not the process working directory. Every
# other tool in this partition derives its paths from a repository root, and
# syzlang_gen.DEFAULT_CTRL_RANK is the absolute form of DEFAULT_OUT, so a
# working-directory anchor here put the producer and the consumer at different
# paths whenever the tool ran from anywhere but the root.
DEFAULT_SRC = os.path.join(REPO_ROOT, "artifacts", "src",
                           "open-gpu-kernel-modules")
DEFAULT_CONTROL = os.path.join(REPO_ROOT, "surface", "rm-control-inventory.json")
DEFAULT_CHAINS = os.path.join(REPO_ROOT, "surface", "rm-chains.json")
DEFAULT_HOTSPOTS = os.path.join(REPO_ROOT, "surface", "cve-hotspots.json")
DEFAULT_SIZES = os.path.join(REPO_ROOT, "surface", "ctrl-param-sizes.json")
DEFAULT_OUT = os.path.join(REPO_ROOT, "surface", "rm-control-rank.json")

# The whole checkout is scanned. Restricting the walk to src/nvidia/src lost
# the cliresCtrlCmdOsUnix* export and import family, defined in
# src/nvidia/arch/nvalloc/unix/src/os.c, which is the historically CVE-dense
# unprivileged path on this surface.
IMPL_REL = "src"

# A control handler's definition, at the start of a line, with an optional
# same-line return type before the name. NVOC generated code calls the symbol
# from inside a function body and is therefore indented, so the line anchor is
# what separates a definition from a call. Dropping the anchor to catch
# `NV_STATUS foo_IMPL(` would match every call site as well, so the anchor
# stays and the return type is admitted in front of the name instead.
#
# Four suffixes, because a handler has one hand-written definition under
# exactly one of them. _IMPL is the sole implementation where there is no HAL
# split. Where there is, the NVOC table dispatches to a per-variant symbol
# instead: _KERNEL and _PHYSICAL divide the kernel-side and GSP-side halves,
# and _VF is the SR-IOV guest variant. All four are real code with their own
# release history, which is the only thing the CVE join needs from them.
IMPL_SUFFIXES = ("IMPL", "KERNEL", "PHYSICAL", "VF")
IMPL_RE = re.compile(
    r"^(?:[A-Za-z_]\w*[\w \t\*]*?[ \t\*])?(\w+)_(%s)\s*\("
    % "|".join(IMPL_SUFFIXES), re.MULTILINE)

# Which definition wins when a handler carries more than one. _IMPL first
# because it is the sole implementation wherever it exists. Among the HAL
# variants the bare-metal kernel-side half is the one an unprivileged process
# on the system under test reaches, so _KERNEL outranks _PHYSICAL, and _VF
# runs only in an SR-IOV guest. Ties below that fall to sorted path order and
# then line number, so the result does not depend on traversal order.
SUFFIX_RANK = {name: i for i, name in enumerate(IMPL_SUFFIXES)}

WEIGHT_DEPTH = 0.50
WEIGHT_CVE = 0.30
WEIGHT_SIZE = 0.20

# A hot-spot record naming the handler itself is stronger evidence than one
# naming only the file it lives in, so a function-level match is scaled up.
FUNCTION_WEIGHT = 1.5


def load_json(path, what):
    if not os.path.isfile(path):
        raise SystemExit("%s is missing at %s. The ranking cannot be computed "
                         "without it." % (what, path))
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise SystemExit("could not read %s at %s: %s" % (what, path, exc))


def scan_impl_definitions(src):
    """Map every control handler definition under src/ to file, line and suffix.

    Returns {name without the suffix: (path relative to src, 1-based line,
    suffix)}. A name defined more than once resolves by SUFFIX_RANK, then
    sorted path order, then line number, so the result does not depend on
    directory traversal order.
    """
    root = os.path.join(src, IMPL_REL)
    if not os.path.isdir(root):
        raise SystemExit(
            "%s does not exist, so no control handler implementation can be "
            "located. Point --src at an open-gpu-kernel-modules checkout."
            % root)
    best = {}
    scanned = 0
    paths = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name.endswith((".c", ".cpp")):
                paths.append(os.path.join(dirpath, name))
    for path in sorted(paths):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            logger.warning("could not read %s: %s", path, exc)
            continue
        scanned += 1
        rel = os.path.relpath(path, src).replace(os.sep, "/")
        for match in IMPL_RE.finditer(text):
            name, suffix = match.group(1), match.group(2)
            line = text.count("\n", 0, match.start()) + 1
            key = (SUFFIX_RANK[suffix], rel, line)
            if name not in best or key < best[name][0]:
                best[name] = (key, (rel, line, suffix))
    found = {name: value for name, (_key, value) in best.items()}
    by_suffix = collections.Counter(suffix for _r, _l, suffix in found.values())
    logger.info("scanned %d source files, found %d handler definition(s) (%s)",
                scanned, len(found),
                ", ".join("%s %d" % (s, by_suffix[s])
                          for s in IMPL_SUFFIXES if by_suffix[s]))
    return found


def hotspot_index(hotspots):
    """Two lookups over cve-hotspots.json.

    Both `by_file` and `by_function` are arrays of objects, not maps, so a
    consumer indexing them as dictionaries silently reads nothing.
    """
    payload = hotspots.get("hotspots")
    if not isinstance(payload, dict):
        raise SystemExit("cve-hotspots.json carries no `hotspots` object.")
    by_file = {}
    for rec in payload.get("by_file", []):
        by_file[rec["file"]] = rec.get("releases", 0)
    by_function = {}
    for rec in payload.get("by_function", []):
        by_function.setdefault(rec["function"], rec)
    return by_file, by_function


def chain_index(chains):
    """{internal class: (chain_length, target external class, reason)}."""
    out = {}
    for rec in chains.get("chains", []):
        out[rec["internal_class"]] = (rec.get("chain_length"),
                                      rec.get("target_external_class"),
                                      rec.get("unallocatable_reason"))
    return out


def targetable(control):
    """The 531: non-privileged reachability and a handler that is compiled in."""
    return [m for m in control["methods"]
            if m["reachability"] == "non_privileged"
            and not m["handler_compiled_out"]]


def normalise_log(value, ceiling):
    if not ceiling or value <= 0:
        return 0.0
    return math.log2(value + 1) / math.log2(ceiling + 1)


def build_records(methods, impls, by_file, by_function, chains, sizes):
    rows = []
    for method in methods:
        handler = method["handler"]
        impl = impls.get(handler)
        impl_file, impl_line, impl_suffix = impl if impl else (None, None, None)
        # A handler with no hand-written definition anywhere in the tree is
        # dispatched to an NVOC generated inline in src/nvidia/generated/, which
        # has no release history of its own. Recorded as its own state so a
        # null impl_file cannot be read as a scan that failed.
        impl_state = "resolved" if impl else "no hand-written definition"

        function_rec = None
        for suffix in ("_" + s for s in IMPL_SUFFIXES):
            function_rec = by_function.get(handler + suffix)
            if function_rec:
                break
        function_rec = function_rec or by_function.get(handler)
        file_releases = by_file.get(impl_file, 0) if impl_file else 0
        function_releases = function_rec.get("releases", 0) if function_rec else 0

        struct = method["param_struct"]
        param_size = sizes.get(struct) if struct else 0
        param_size_state = "measured"
        if struct and param_size is None:
            param_size = 0
            param_size_state = "unmeasured"
        elif not struct:
            param_size = 0
            param_size_state = "no parameter struct"

        chain_length, target, reason = chains.get(
            method["owning_class"], (None, None, "no RS_ENTRY row for this class"))

        rows.append({
            "method_id": method["method_id"],
            "handler": handler,
            "owning_class": method["owning_class"],
            "sdk_prefix": method["sdk_prefix"],
            "class_id": method["class_id"],
            "routed_to_physical": method["routed_to_physical"],
            "impl_file": impl_file,
            "impl_line": impl_line,
            "impl_suffix": impl_suffix,
            "impl_state": impl_state,
            "param_struct": struct,
            "param_size": param_size,
            "param_size_state": param_size_state,
            "chain_length": chain_length,
            "chain_target_class": target,
            "no_chain_reason": reason if chain_length is None else None,
            "cve_file_releases": file_releases,
            "cve_function_releases": function_releases,
            "cve_function": function_rec,
        })
    return rows


def score_records(rows):
    """Attach rank_score and a dense rank, in place, and return the sorted list.

    max_len is derived from the data, so the depth component's range follows
    whatever chain lengths the join produced. Two things keep the component
    inside the [0, 1] the weighting documents: the `is not None` test admits a
    chain of 0, which is falsy and was dropped before, and the cap below
    bounds what the fixed denominator would otherwise return for it. No record
    carries 0 in this release.
    """
    lengths = [r["chain_length"] for r in rows if r["chain_length"] is not None]
    max_len = max(lengths) if lengths else 1
    max_size = max((r["param_size"] or 0) for r in rows) or 1
    max_releases = max(
        max((r["cve_file_releases"] for r in rows), default=0),
        max((r["cve_function_releases"] for r in rows), default=0)) or 1

    for row in rows:
        length = row["chain_length"]
        if length is None:
            depth_component = 0.0
        elif max_len <= 1:
            depth_component = 1.0
        else:
            # Capped at 1.0. The denominator assumes the shortest chain is 1,
            # which is the shortest the object graph can currently produce; a
            # chain of 0 would otherwise score above the [0, 1] the weighting
            # documents. 1.0 is the right value for it either way, a chain of
            # 0 being the cheapest prologue there is.
            depth_component = min(
                1.0, (max_len - length) / float(max_len - 1))

        if row["cve_function_releases"]:
            cve_component = min(
                1.0,
                FUNCTION_WEIGHT * normalise_log(row["cve_function_releases"],
                                                max_releases))
        else:
            cve_component = normalise_log(row["cve_file_releases"],
                                          max_releases)

        size_component = normalise_log(row["param_size"] or 0, max_size)

        row["rank_components"] = {
            "depth": round(depth_component, 6),
            "cve": round(cve_component, 6),
            "size": round(size_component, 6),
        }
        row["rank_score"] = round(
            WEIGHT_DEPTH * depth_component
            + WEIGHT_CVE * cve_component
            + WEIGHT_SIZE * size_component, 6)

    ordered = sorted(rows, key=sort_key)
    for position, row in enumerate(ordered, 1):
        row["rank"] = position
    return ordered


def sort_key(row):
    """Reachable first, then the highest score, then the shallowest chain.

    Reachability leads the key rather than riding on the depth component,
    because the depth component of a command at the maximum chain length is
    also 0. Without the leading term an unreachable command carrying a large
    parameter struct and a long CVE history outscores a reachable one at the
    bottom of the chain, and a campaign cannot execute what it cannot reach.

    method_id closes the key so two commands with identical measurements keep
    a fixed order across runs.
    """
    return (0 if row["chain_length"] is not None else 1,
            -row["rank_score"],
            row["chain_length"] if row["chain_length"] is not None else 1 << 30,
            -max(row["cve_function_releases"], row["cve_file_releases"]),
            row["method_id"])


def write_json(path, payload):
    """Temp file in the same directory, fsync, rename."""
    out_dir = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
        logger.info("created output directory %s", out_dir)
    tmp = os.path.abspath(path) + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(payload, fh, indent=1, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def cmd_rank(args):
    control = load_json(args.control, "the control inventory")
    if "methods" not in control:
        raise SystemExit("%s carries no `methods` array." % args.control)
    chains = load_json(args.chains, "the chain records")
    hotspots = load_json(args.hotspots, "the CVE hot-spot file")
    sizes = load_json(args.sizes, "the measured parameter sizes")

    methods = targetable(control)
    logger.info("%d targetable control commands out of %d exported",
                len(methods), len(control["methods"]))

    impls = scan_impl_definitions(args.src)
    by_file, by_function = hotspot_index(hotspots)
    rows = build_records(methods, impls, by_file, by_function,
                         chain_index(chains), sizes)
    ordered = score_records(rows)

    resolved_impl = sum(1 for r in ordered if r["impl_file"])
    in_hot_file = sum(1 for r in ordered if r["cve_file_releases"])
    function_match = sum(1 for r in ordered if r["cve_function_releases"])
    no_chain = sum(1 for r in ordered if r["chain_length"] is None)

    payload = {
        "schema": "gspwn.rm-control-rank/1",
        "source": {
            "control_inventory": repo_relative(args.control),
            "chains": repo_relative(args.chains),
            "hotspots": repo_relative(args.hotspots),
            "param_sizes": repo_relative(args.sizes),
            "src": repo_relative(args.src),
        },
        "weighting": {
            "depth": WEIGHT_DEPTH,
            "cve": WEIGHT_CVE,
            "size": WEIGHT_SIZE,
            "function_match_weight": FUNCTION_WEIGHT,
        },
        "counts": {
            "ranked": len(ordered),
            "handlers_resolved_to_an_implementation": resolved_impl,
            "handlers_in_a_hot_file": in_hot_file,
            "handlers_matching_a_hot_function": function_match,
            "commands_without_a_chain": no_chain,
            "impl_definitions_scanned": len(impls),
        },
        "commands": ordered,
    }
    write_json(args.out, payload)
    print("%d control commands ranked -> %s" % (len(ordered), args.out))
    print("implementation located for %d, in a hot file %d, "
          "matching a hot function %d, no chain %d"
          % (resolved_impl, in_hot_file, function_match, no_chain))
    return 0


def cmd_report(args):
    payload = load_json(args.rank, "the control ranking")
    commands = payload["commands"]
    print("%-5s %-11s %-5s %-7s %-6s %s"
          % ("rank", "method", "chain", "cve", "bytes", "handler"))
    for row in commands[:args.top]:
        print("%-5d %-11s %-5s %-7s %-6d %s"
              % (row["rank"], row["method_id"],
                 row["chain_length"] if row["chain_length"] is not None else "-",
                 max(row["cve_function_releases"], row["cve_file_releases"]),
                 row["param_size"], row["handler"]))
    spread = collections.Counter(
        r["chain_length"] if r["chain_length"] is not None else "none"
        for r in commands)
    print("\nchain length over the whole set: %s"
          % dict(sorted(spread.items(), key=lambda kv: str(kv[0]))))
    return 0


def build_parser():
    ap = argparse.ArgumentParser(
        prog="ctrl_rank.py",
        description="Rank the targetable RM control commands.")
    ap.add_argument("-v", "--verbose", action="store_true", help="log at DEBUG")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("rank", help="write the ranked records")
    p.add_argument("--src", default=DEFAULT_SRC,
                   help="open-gpu-kernel-modules checkout (default: %(default)s)")
    p.add_argument("--control", default=DEFAULT_CONTROL)
    p.add_argument("--chains", default=DEFAULT_CHAINS)
    p.add_argument("--hotspots", default=DEFAULT_HOTSPOTS)
    p.add_argument("--sizes", default=DEFAULT_SIZES)
    p.add_argument("--out", default=DEFAULT_OUT)
    p.set_defaults(func=cmd_rank)

    p = sub.add_parser("report", help="print the head of the ranking")
    p.add_argument("--rank", default=DEFAULT_OUT)
    p.add_argument("--top", type=int, default=25)
    p.set_defaults(func=cmd_report)
    return ap


def main():
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
