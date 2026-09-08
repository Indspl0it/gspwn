#!/usr/bin/env python3
"""Measure the device nodes a container actually receives, and compare them
against the tenant surface `surface/entry-points.json` records.

The threat model states which device nodes reach a container tenant. That
statement was derived by reading `libnvidia-container` and
`nvidia-container-toolkit` source, and it is path-dependent: the legacy
injection path and the CDI path disagree about `/dev/nvidia-modeset`, and the
CDI path reads no capability variable at all. Source reading settles what the
code can do. It does not settle what one deployment does.

This tool settles it on the machine the campaign will run on, before the
campaign runs. It starts a container the way the threat model says a tenant
starts one, lists the NVIDIA device nodes inside it, and compares that list
against the committed artefact.

Two kinds of disagreement matter, and they are not symmetric.

| Disagreement | Meaning |
|---|---|
| A node present in the container, recorded outside the tenant surface | Reachable surface the campaign does not model. The threat model understates the attacker |
| A node absent from the container, recorded inside the tenant surface | Modelled surface the tenant cannot reach. Campaign effort is spent where no attacker goes |

The first is a correctness failure of the threat model. The second wastes
effort. Both exit non-zero.

Subcommands:

  expected      print the tenant surface the artefact records. Reads files
                only, needs no container runtime and no GPU
  runtime-mode  report which injection path the host is configured for
  measure       start a container, list its device nodes, compare, and exit
                non-zero on any disagreement

`measure` needs a working container runtime and a GPU on the host. The other
two run anywhere.
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys

logger = logging.getLogger(__name__)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRY_POINTS = os.path.join("surface", "entry-points.json")

# The capability set a CUDA image requests by default, and the set the threat
# model's Track K attacker is defined against. Overridable so an operator can
# measure a deployment that requests more.
DEFAULT_CAPABILITIES = os.getenv("GSPWN_VERIFY_CAPABILITIES", "compute,utility")

# An image small enough to pull on a fresh instance and containing a shell.
# It needs no CUDA runtime: the device nodes are injected by the container
# runtime before any process starts, so listing /dev is enough.
DEFAULT_IMAGE = os.getenv("GSPWN_VERIFY_IMAGE", "ubuntu:22.04")

DEFAULT_RUNTIME = os.getenv("GSPWN_VERIFY_RUNTIME", "docker")

# How long to wait for the container to start and list a directory. A pull on
# a cold instance is slower than the listing, and is timed separately.
RUN_TIMEOUT_SECONDS = int(os.getenv("GSPWN_VERIFY_RUN_TIMEOUT", "120"))
PULL_TIMEOUT_SECONDS = int(os.getenv("GSPWN_VERIFY_PULL_TIMEOUT", "600"))

# Paths in the artefact carry a trailing N where the driver creates one node
# per device: /dev/nvidiaN, /dev/nvidia-nvswitchN, /dev/dri/cardN. A measured
# listing carries the real numbers, so the comparison matches on a pattern.
_N_SUFFIX = re.compile(r"N$")


class VerifyError(Exception):
    """A condition that stops the measurement, stated for an operator."""


def artefact_path(root=None):
    return os.path.join(root or REPO_ROOT, ENTRY_POINTS)


def load_tables(root=None):
    """-> the fops table records from surface/entry-points.json.

    Raises VerifyError naming the file when it is absent or unparseable,
    because every caller here is an operator on a fresh instance for whom a
    stack trace is not the useful output.
    """
    path = artefact_path(root)
    if not os.path.isfile(path):
        raise VerifyError(
            "%s does not exist. It is written by "
            "`python3 tools/ioctl_inventory.py --emit-entry-points`, and the "
            "campaign's tenant surface is not defined without it" % path)
    try:
        with open(path, encoding="utf-8") as fh:
            record = json.load(fh)
    except ValueError as exc:
        raise VerifyError("%s is not valid JSON: %s" % (path, exc))
    tables = record.get("tables")
    if not isinstance(tables, list):
        raise VerifyError(
            "%s carries no `tables` list, so it is not an entry-point "
            "artefact this tool understands" % path)
    return tables


def path_to_pattern(declared):
    """-> a compiled pattern matching the real nodes a declared path covers.

    `/dev/nvidiaN` covers `/dev/nvidia0` and `/dev/nvidia11`. A declared path
    with no trailing N matches itself exactly.
    """
    if _N_SUFFIX.search(declared):
        return re.compile("^" + re.escape(declared[:-1]) + r"\d+$")
    return re.compile("^" + re.escape(declared) + "$")


def expected_surface(tables):
    """-> (inside, outside), each a list of (declared_path, fops, pattern).

    `tenant_surface` is the artefact's own field. This tool never re-derives
    it: the point of the comparison is that the artefact is the claim under
    test, and a tool that recomputed the claim would be testing itself.
    """
    inside, outside = [], []
    for table in tables:
        fops = table.get("fops") or table.get("table") or "(unnamed)"
        for declared in table.get("paths") or []:
            entry = (declared, fops, path_to_pattern(declared))
            if table.get("tenant_surface"):
                inside.append(entry)
            else:
                outside.append(entry)
    return inside, outside


def which_runtime(runtime):
    found = shutil.which(runtime)
    if found is None:
        raise VerifyError(
            "%r is not on PATH. Pass --runtime with the container runtime "
            "this host uses, or set GSPWN_VERIFY_RUNTIME" % runtime)
    return found


def run(argv, timeout, what):
    """Run a command, returning (returncode, stdout, stderr) as text.

    Every external call in this module comes through here so that the timeout
    and the failure log are not forgotten at one call site.
    """
    logger.debug("running %s", " ".join(argv))
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        raise VerifyError(
            "%s did not finish within %ds: %s" % (what, timeout,
                                                  " ".join(argv)))
    except OSError as exc:
        raise VerifyError("%s could not start: %s" % (what, exc))
    if proc.returncode != 0:
        logger.warning("%s exited %d: %s", what, proc.returncode,
                       (proc.stderr or "").strip()[:400])
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def detect_runtime_mode():
    """-> (mode, evidence) describing the injection path this host will use.

    Returns the mode as the toolkit spells it, or None when it cannot be
    read. The caller states the uncertainty; this function never guesses.
    """
    ctk = shutil.which("nvidia-ctk")
    config_paths = ["/etc/nvidia-container-runtime/config.toml",
                    "/usr/share/nvidia-container-runtime/config.toml"]
    for path in config_paths:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            logger.warning("could not read %s: %s", path, exc)
            continue
        match = re.search(r'^\s*mode\s*=\s*"([^"]+)"', text, re.M)
        if match:
            return match.group(1), "%s sets mode = %r" % (path,
                                                          match.group(1))
        return None, ("%s carries no explicit `mode`, so the toolkit resolves "
                      "it automatically. On an NVML platform that resolves to "
                      "jit-cdi" % path)
    if ctk:
        return None, ("nvidia-ctk is installed at %s and no config.toml was "
                      "found at %s. The toolkit default applies"
                      % (ctk, " or ".join(config_paths)))
    return None, ("neither a container-runtime config.toml nor nvidia-ctk was "
                  "found, so this host is not configured for GPU containers "
                  "yet")


def measure_nodes(runtime, image, capabilities, pull):
    """-> the NVIDIA device node paths visible inside a container.

    The listing comes from inside the container. A runtime's own report of
    what it injected is a second-hand account, and the measurement this tool
    exists to take is what a tenant process can open.
    """
    which_runtime(runtime)
    if pull:
        code, _, err = run([runtime, "pull", image], PULL_TIMEOUT_SECONDS,
                           "image pull")
        if code != 0:
            raise VerifyError("could not pull %s: %s" % (image, err.strip()))

    script = (
        "for d in /dev /dev/dri /dev/nvidia-caps /dev/nvidia-caps-imex-channels; do "
        "  [ -d \"$d\" ] && for f in \"$d\"/*; do [ -e \"$f\" ] && echo \"$f\"; done; "
        "done")
    argv = [runtime, "run", "--rm", "--gpus", "all",
            "-e", "NVIDIA_DRIVER_CAPABILITIES=" + capabilities,
            image, "sh", "-c", script]
    code, out, err = run(argv, RUN_TIMEOUT_SECONDS, "container run")
    if code != 0:
        raise VerifyError(
            "the container did not run, so nothing was measured. %s exited "
            "%d: %s" % (runtime, code, err.strip()[:600]))

    nodes = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("/dev/nvidia") or line.startswith("/dev/dri/"):
            nodes.append(line)
    return sorted(set(nodes))


def compare(measured, inside, outside):
    """-> (unmodelled, unreachable, matched) as lists of description strings.

    `unmodelled` is the finding that invalidates a threat model: a node the
    tenant holds that the artefact places outside the tenant surface.
    """
    unmodelled, unreachable, matched = [], [], []
    claimed = inside + outside
    for node in measured:
        hit = next((e for e in claimed if e[2].match(node)), None)
        if hit is None:
            unmodelled.append("%s (no fops table in the artefact covers it)"
                              % node)
        elif hit in outside:
            unmodelled.append("%s (%s, recorded outside the tenant surface)"
                              % (node, hit[1]))
        else:
            matched.append("%s (%s)" % (node, hit[1]))
    for declared, fops, pattern in inside:
        if not any(pattern.match(n) for n in measured):
            unreachable.append("%s (%s, recorded inside the tenant surface)"
                               % (declared, fops))
    return unmodelled, unreachable, matched


def cmd_expected(args):
    tables = load_tables(args.root)
    inside, outside = expected_surface(tables)
    print("tenant surface recorded in %s" % artefact_path(args.root))
    print()
    print("  inside, the campaign models an attacker holding these:")
    for declared, fops, _ in inside:
        print("    %-44s %s" % (declared, fops))
    print()
    print("  outside, the campaign assumes the tenant never holds these:")
    for declared, fops, _ in outside:
        print("    %-44s %s" % (declared, fops))
    print()
    print("Run `measure` on the instance the campaign will use to confirm "
          "this against reality.")
    return 0


def cmd_runtime_mode(args):
    mode, evidence = detect_runtime_mode()
    print("injection path")
    print()
    if mode is None:
        print("  mode      not stated on this host")
    else:
        print("  mode      %s" % mode)
    print("  evidence  %s" % evidence)
    print()
    if mode == "legacy":
        print("The legacy path withholds /dev/nvidia-modeset unless the "
              "display capability is requested.")
    elif mode in ("cdi", "jit-cdi") or mode is None:
        print("The CDI path injects /dev/nvidia-modeset with no capability "
              "check. A tenant surface derived from the legacy path "
              "understates what this host gives a container.")
    return 0


def cmd_measure(args):
    tables = load_tables(args.root)
    inside, outside = expected_surface(tables)
    mode, evidence = detect_runtime_mode()
    measured = measure_nodes(args.runtime, args.image, args.capabilities,
                             args.pull)
    unmodelled, unreachable, matched = compare(measured, inside, outside)

    print("measured on this host")
    print()
    print("  runtime       %s" % args.runtime)
    print("  image         %s" % args.image)
    print("  capabilities  NVIDIA_DRIVER_CAPABILITIES=%s" % args.capabilities)
    print("  injection     %s" % (mode or "not stated"))
    print("  evidence      %s" % evidence)
    print()
    print("  nodes the container received: %d" % len(measured))
    for node in measured:
        print("    %s" % node)
    print()
    if matched:
        print("  agreeing with the artefact: %d" % len(matched))
        for line in matched:
            print("    %s" % line)
        print()
    if unmodelled:
        print("  REACHABLE AND NOT MODELLED: %d" % len(unmodelled))
        for line in unmodelled:
            print("    %s" % line)
        print()
        print("  The threat model understates the attacker. Every node above "
              "is one a tenant can open and the campaign does not model.")
        print()
    if unreachable:
        print("  MODELLED AND NOT REACHABLE: %d" % len(unreachable))
        for line in unreachable:
            print("    %s" % line)
        print()
        print("  Campaign effort is budgeted for surface this tenant cannot "
              "reach.")
        print()
    if not unmodelled and not unreachable:
        print("  The measured node set matches the recorded tenant surface.")
        return 0
    return 1


def build_parser():
    parser = argparse.ArgumentParser(
        prog="verify_tenant_surface.py",
        description="Compare the device nodes a container receives against "
                    "the tenant surface surface/entry-points.json records.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=None,
                        help="repository root holding surface/entry-points"
                             ".json (default: this tool's own repository)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="log every external command before running it")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("expected",
                       help="print the recorded tenant surface, reading files "
                            "only")
    p.set_defaults(func=cmd_expected)

    p = sub.add_parser("runtime-mode",
                       help="report which injection path this host uses")
    p.set_defaults(func=cmd_runtime_mode)

    p = sub.add_parser("measure",
                       help="start a container and compare its device nodes "
                            "against the record")
    p.add_argument("--runtime", default=DEFAULT_RUNTIME,
                   help="container runtime binary (default: %(default)s)")
    p.add_argument("--image", default=DEFAULT_IMAGE,
                   help="image to start (default: %(default)s)")
    p.add_argument("--capabilities", default=DEFAULT_CAPABILITIES,
                   help="NVIDIA_DRIVER_CAPABILITIES value the container "
                        "requests (default: %(default)s)")
    p.add_argument("--no-pull", dest="pull", action="store_false",
                   default=True,
                   help="skip pulling the image, for a host already holding "
                        "it or with no registry access")
    p.set_defaults(func=cmd_measure)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")
    if getattr(args, "func", None) is None:
        build_parser().print_help()
        return 2
    try:
        return args.func(args)
    except VerifyError as exc:
        logger.error("%s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
