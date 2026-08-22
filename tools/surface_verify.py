#!/usr/bin/env python3
"""Version guard for the statically derived ioctl surface.

`tools/ioctl_map.json` is committed, and `tools/ioctl_inventory.py`,
`tools/ctrl_surface.py` and `tools/object_graph.py` derive everything the
describe and seeds phases model from a driver source checkout. Every number in
them is tied to one driver release: escape numbers move between branches,
parameter structs gain fields, control commands are added and removed, and
class privilege flags change.

A mismatch between the release the artefacts were built from and the release
running on the target is silent. The map still parses, syzkaller still runs,
the descriptions still compile, and the campaign measures a driver that is not
the one under test. This module makes that mismatch loud.

Four version sources, checked in whatever combination is available:

  artefact   the version recorded in tools/ioctl_map.json, in any inventory
             JSON under surface/, and in the generation record under
             descriptions/
  checkout   NVIDIA_VERSION in version.mk of the source tree
  running    /proc/driver/nvidia/version on the target, or nvidia-smi
  declared   driver_branch in config/machine.yaml, written by provision

Two independent sources are the minimum for a verdict. A single source is
consistent with itself and establishes nothing, so `check` fails on it. Pass
--allow-single-source where the single source is deliberate and known.

Independence is counted by group, not by file. Every committed artefact takes
its driver_version from the version.mk of the checkout that produced it:
ioctl_inventory.py, ctrl_surface.py and object_graph.py each read one tree,
and descriptions/generation.json copies the value out of the control
inventory. The six of them are one observation recorded six times, so they
count once. The other three groups each observe the release by a route that
can return a different answer: a checkout can be updated without regenerating,
a loaded driver reports what the kernel actually holds, and machine.yaml
records what provisioning intended.

Subcommands:
  check [--src DIR] [--allow-single-source] [--no-running]
                                 compare every available source, report the
                                 verdict, exit non-zero on disagreement and on
                                 fewer than two independent sources
  stamp [--src DIR]              record the checkout's version into
                                 tools/ioctl_map.json, for use after
                                 regenerating it
  show                           print each source and where it was read from

Exit codes: 0 agreement, 1 bad input, 3 disagreement, 4 fewer than two
independent sources. 3 and 4 are separate because their remedies are separate:
3 means regenerate the artefacts, 4 means bring a second source up.
"""
import argparse
import json
import logging
import os
import re
import subprocess
import sys

logger = logging.getLogger(__name__)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SRC = os.path.join(REPO, "artifacts", "src", "open-gpu-kernel-modules")
MAP_PATH = os.path.join(REPO, "tools", "ioctl_map.json")
MACHINE_YAML = os.path.join(REPO, "config", "machine.yaml")
SURFACE_DIR = os.path.join(REPO, "surface" )
DESCRIPTIONS_DIR = os.path.join(REPO, "descriptions" )

# trace2seed.py drops every key beginning with "comment", so the stamp lives
# under that prefix and cannot be mistaken for a request number.
VERSION_KEY = "comment_driver_version"

# Artefacts that describe something other than one driver build, and therefore
# carry no driver version by design. Warning about these would train the reader
# to ignore the warning that matters.
NOT_VERSION_TIED = {
    "surface/prior-cves.json",
    # Maps CVEs to release tag pairs, so it spans versions by construction.
    "surface/cve-hotspots.json",
}

DISAGREE = 3

# Kept apart from DISAGREE because the operator actions differ. DISAGREE means
# the artefacts model a release the target is not running, and the fix is to
# regenerate. INSUFFICIENT means the guard could not compare anything, and the
# fix is to bring a second source up. Collapsing the two loses the distinction
# the printed remedy already draws. The value is 4 because argparse exits 2 on
# a usage error, and a mistyped flag must not read as a verdict.
INSUFFICIENT = 4

VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")


def checkout_version(src):
    """NVIDIA_VERSION from version.mk, or None when the tree is absent."""
    path = os.path.join(src, "version.mk")
    if not os.path.isfile(path):
        logger.debug("no version.mk at %s", path)
        return None
    with open(path, encoding="utf-8", errors="replace") as fh:
        m = re.search(r"^NVIDIA_VERSION\s*=\s*(\S+)", fh.read(), re.M)
    if not m:
        raise SystemExit(
            "version.mk at %s defines no NVIDIA_VERSION. The file format has "
            "changed and this guard cannot read it." % path)
    return m.group(1)


def checkout_commit(src):
    if not os.path.isdir(os.path.join(src, ".git")):
        return None
    try:
        out = subprocess.run(["git", "-C", src, "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("git rev-parse failed for %s: %s", src, exc)
        return None
    return out.stdout.strip() or None


def _find_driver_version(obj, depth=0):
    """A driver_version recorded anywhere in the first two levels of a record.

    The extractors were written separately and record provenance differently:
    one nests it under "source", another may put it at the top level. Searching
    for the key by name keeps this guard working when a new extractor lands
    with its own shape.
    """
    if not isinstance(obj, dict) or depth > 2:
        return None
    value = obj.get("driver_version")
    if isinstance(value, str) and value.strip():
        return value.strip()
    for nested in obj.values():
        found = _find_driver_version(nested, depth + 1)
        if found:
            return found
    return None


def _scan_json_dir(directory, prefix, found, unversioned):
    """Record the driver version in every JSON artefact directly under one dir.

    Non-recursive, so artifacts/bulletins/ stays invisible: those are
    cached vendor HTML and belong to no driver build.
    """
    if not os.path.isdir(directory):
        return
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        rel = prefix + name
        path = os.path.join(directory, name)
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            logger.warning("could not read %s: %s", rel, exc)
            unversioned.append(rel)
            continue
        version = _find_driver_version(data)
        if version:
            found[rel] = version
        else:
            unversioned.append(rel)


def artefact_versions():
    """Every version recorded in a committed or generated artefact.

    Artefacts carrying no version are counted and logged, never skipped in
    silence: an unversioned inventory cannot be checked, and a guard that says
    nothing about it reports agreement it did not establish.

    descriptions/generation.json is included because the description
    set is the artefact syzkaller consumes, so its staleness carries most. A
    fresh inventory paired with descriptions generated from an older checkout
    used to pass this check cleanly. The four .txt files carry the same version
    in their headers, written by the same syzlang_gen.py run that writes the
    generation record, so reading the record covers them.
    """
    found, unversioned = {}, []
    if os.path.isfile(MAP_PATH):
        with open(MAP_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        if VERSION_KEY in data:
            found["tools/ioctl_map.json"] = str(data[VERSION_KEY]).split()[0]
        else:
            unversioned.append("tools/ioctl_map.json")
    _scan_json_dir(SURFACE_DIR, "surface/", found, unversioned)
    _scan_json_dir(DESCRIPTIONS_DIR, "descriptions/", found,
                   unversioned)
    for rel in unversioned:
        if rel in NOT_VERSION_TIED:
            continue
        logger.warning("%s records no driver_version, so it cannot be checked",
                       rel)
    return found


def running_version():
    """The driver loaded on this machine, or None when there is none."""
    proc = "/proc/driver/nvidia/version"
    if os.path.isfile(proc):
        with open(proc, encoding="utf-8", errors="replace") as fh:
            m = VERSION_RE.search(fh.read())
        if m:
            return m.group(1)
        logger.warning("%s held no recognisable version", proc)
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("nvidia-smi unavailable: %s", exc)
        return None
    if out.returncode != 0:
        logger.debug("nvidia-smi exited %d: %s", out.returncode,
                     out.stderr.strip()[:200])
        return None
    return out.stdout.strip().splitlines()[0].strip() or None


def declared_version():
    """driver_branch from config/machine.yaml, written by the provision phase."""
    if not os.path.isfile(MACHINE_YAML):
        return None
    with open(MACHINE_YAML, encoding="utf-8", errors="replace") as fh:
        m = re.search(r"^driver_branch:\s*\"?([^\"#\n]*)", fh.read(), re.M)
    value = (m.group(1).strip() if m else "")
    return value or None


# The four independence groups, in the order `check` prints them. The value is
# the operator-facing name of the group; ARTEFACT_GROUP holds however many
# files carry a stamp and still counts once, because one version.mk produced
# all of them. Counting files instead of groups is what let six copies of one
# stamp satisfy the two-source gate.
ARTEFACT_GROUP = "artefacts"
CHECKOUT_GROUP = "checkout version.mk"
RUNNING_GROUP = "running driver"
DECLARED_GROUP = "config/machine.yaml driver_branch"


def source_groups(artefacts, checkout, running, declared):
    """Every available version source, partitioned into independent groups.

    Returns an ordered list of (group name, [(label, value), ...]). A group is
    independent when its answer can differ from every other group's answer.
    The artefacts cannot differ from each other for any reason except a
    partial regeneration, which `check` reports separately, so they are one
    observation however many files record it.
    """
    groups = []
    if artefacts:
        groups.append((ARTEFACT_GROUP, sorted(artefacts.items())))
    for name, value in ((CHECKOUT_GROUP, checkout),
                        (RUNNING_GROUP, running),
                        (DECLARED_GROUP, declared)):
        if value:
            groups.append((name, [(name, value)]))
    return groups


def collect(src):
    sources = {}
    for label, value in artefact_versions().items():
        sources[label] = value
    for label, value in (("checkout version.mk", checkout_version(src)),
                         ("running driver", running_version()),
                         ("config/machine.yaml driver_branch",
                          declared_version())):
        if value:
            sources[label] = value
    return sources


def cmd_show(args):
    sources = collect(args.src)
    commit = checkout_commit(args.src)
    if not sources:
        print("no version source available")
        return 0
    width = max(len(k) for k in sources)
    for label, value in sources.items():
        print("%-*s  %s" % (width, label, value))
    if commit:
        print("%-*s  %s" % (width, "checkout commit", commit))
    return 0


def cmd_check(args):
    artefacts = artefact_versions()
    checkout = checkout_version(args.src)
    running = None if args.no_running else running_version()
    declared = declared_version()

    groups = source_groups(artefacts, checkout, running, declared)
    rows = [row for _name, members in groups for row in members]
    if not rows:
        print("no version source available")
        print()
        print("Nothing was compared. tools/ioctl_map.json carries no %s, no "
              "version.mk was found under %s, no driver reports a version on "
              "this machine, and config/machine.yaml declares no driver_branch."
              % (VERSION_KEY, args.src))
        print("--allow-single-source covers one deliberate source, not none.")
        logger.error("no version source available, --src %s", args.src)
        return INSUFFICIENT

    width = max(len(k) for k, _ in rows)
    for label, value in rows:
        print("%-*s  %s" % (width, label, value))
    print()

    # The two comparisons answer different questions and have different
    # remedies, so a single verdict over all four sources is not actionable.
    problems = []

    art_values = sorted(set(artefacts.values()))
    if len(art_values) > 1:
        problems.append(
            ("artefacts disagree with each other: %s" % ", ".join(art_values),
             "Regenerate all of them from one checkout."))
    if checkout and art_values and art_values != [checkout]:
        problems.append(
            ("artefacts were built from %s, the checkout is %s"
             % (", ".join(art_values), checkout),
             "Regenerate the artefacts from this checkout."))

    target = running or declared
    target_label = "the running driver" if running else "config/machine.yaml"
    if target and art_values and target not in art_values:
        problems.append(
            ("artefacts describe %s, %s reports %s"
             % (", ".join(art_values), target_label, target),
             "Check out the driver source matching %s and regenerate."
             % target))

    if not problems:
        compared = len(groups)
        if compared < 2:
            only = groups[0][0]
            if only == ARTEFACT_GROUP:
                print("only the artefacts carry a version, and %d file(s) "
                      "built from one checkout are one source" % len(rows))
            else:
                print("only one version source available, nothing to compare")
            if args.allow_single_source:
                logger.warning(
                    "one independent source (%s), accepted under "
                    "--allow-single-source", only)
                return 0
            print()
            print("A single source agrees with itself and establishes nothing. "
                  "The artefacts count once however many of them carry a "
                  "stamp, because ioctl_inventory.py, ctrl_surface.py and "
                  "object_graph.py all read one version.mk and "
                  "generation.json copies the value out of the control "
                  "inventory. Bring a genuinely second source up: load the "
                  "driver so nvidia-smi or /proc/driver/nvidia/version "
                  "answers, set driver_branch in config/machine.yaml, or "
                  "point --src at an open-gpu-kernel-modules checkout so "
                  "version.mk can be read. Where the single source is "
                  "deliberate and known, pass --allow-single-source.")
            logger.error("1 independent version source (%s), fewer than the 2 "
                         "needed to compare", only)
            return INSUFFICIENT
        print("agreement across %d independent sources: %s"
              % (compared,
                 ", ".join("%s (%d files)" % (name, len(members))
                           if name == ARTEFACT_GROUP else name
                           for name, members in groups)))
        return 0

    print("DISAGREEMENT")
    for statement, remedy in problems:
        print("  %s" % statement)
        print("    %s" % remedy)
    print()
    print("Escape numbers, parameter struct sizes, control command numbers and "
          "class privilege flags all move between releases. Descriptions and "
          "the ioctl map built against one release model a different driver "
          "when run against another, and they fail silently: the map parses, "
          "syzkaller runs, and the campaign measures the wrong target.")
    print()
    # In dependency order: the three extractors first, then the joins that read
    # them, then the description set, then the stamp. Every command writes to
    # its own default path, so each runs exactly as printed.
    print("  python3 tools/ioctl_inventory.py --src <checkout>")
    print("  python3 tools/ctrl_surface.py --src <checkout>")
    print("  python3 tools/object_graph.py extract --src <checkout>")
    print("  python3 tools/object_graph.py chains --src <checkout>")
    print("  python3 tools/ctrl_rank.py rank --src <checkout>")
    print("  python3 tools/syzlang_gen.py emit --src <checkout>")
    print("  python3 tools/surface_verify.py stamp --src <checkout>")
    logger.error("%d version problem(s) across %d independent source(s)",
                 len(problems), len(groups))
    return DISAGREE


def cmd_stamp(args):
    version = checkout_version(args.src)
    if not version:
        raise SystemExit(
            "no version.mk under %s, so there is no version to stamp. Pass "
            "--src pointing at an open-gpu-kernel-modules checkout." % args.src)
    if not os.path.isfile(MAP_PATH):
        raise SystemExit("no ioctl map at %s" % MAP_PATH)
    with open(MAP_PATH, encoding="utf-8") as fh:
        data = json.load(fh)
    commit = checkout_commit(args.src)
    data[VERSION_KEY] = version + ((" (commit %s)" % commit) if commit else "")
    # Written whole and replaced, so an interrupted write cannot leave the map
    # half-rewritten and unparseable by the seeds phase. newline="\n" is
    # explicit for the same reason object_graph.write_json pins it: a stamp run
    # on Windows and one under WSL must produce the same bytes, and the default
    # translation would rewrite every line of the map with CRLF. fsync before
    # the replace, so a crash cannot leave the new name pointing at unwritten
    # data.
    tmp = MAP_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, MAP_PATH)
    logger.info("stamped %s into %s", data[VERSION_KEY], MAP_PATH)
    print("%s -> %s" % (data[VERSION_KEY], os.path.relpath(MAP_PATH, REPO)))
    return 0


def add_shared(sub_parser):
    """Accept --src and -v after the subcommand as well as before it.

    argparse binds a parent-level option before the subcommand only, so
    `tool.py extract --src DIR` is a usage error while `tool.py --src DIR
    extract` works. Both orders read naturally and the documentation uses the
    first, so each subparser repeats the options with SUPPRESS defaults, which
    leaves the parent's value in place when the subcommand does not carry one.
    """
    sub_parser.add_argument("--src", default=argparse.SUPPRESS,
                            help="open-gpu-kernel-modules checkout")
    sub_parser.add_argument("-v", "--verbose", action="store_true",
                            default=argparse.SUPPRESS, help="log at DEBUG")
    return sub_parser


def build_parser():
    ap = argparse.ArgumentParser(
        prog="surface_verify.py",
        description="Confirm the static ioctl surface matches the driver "
                    "under test.")
    ap.add_argument("--src", default=DEFAULT_SRC,
                    help="open-gpu-kernel-modules checkout (default: %s)"
                         % os.path.relpath(DEFAULT_SRC, REPO))
    ap.add_argument("-v", "--verbose", action="store_true", help="log at DEBUG")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = add_shared(sub.add_parser("check",
                   help="compare every available version source"))
    p.add_argument("--allow-single-source", action="store_true",
                   help="accept a single version source. Fewer than two "
                        "sources is a failure by default, because one source "
                        "agrees with itself and establishes nothing")
    p.add_argument("--no-running", action="store_true",
                   help="skip the loaded-driver comparison, for a workstation "
                        "whose own GPU is not the target")
    p.set_defaults(func=cmd_check)

    p = add_shared(sub.add_parser("stamp",
                   help="record the checkout version in the map"))
    p.set_defaults(func=cmd_stamp)

    p = add_shared(sub.add_parser("show",
                   help="print every version source"))
    p.set_defaults(func=cmd_show)
    return ap


def main():
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
