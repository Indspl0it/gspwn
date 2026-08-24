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

# How the container is given the GPU. The two ways reach different injection
# code and hand the container different device nodes, so a measurement that
# does not record which one it used states nothing.
#
# `--runtime=nvidia` runs the nvidia-container-runtime binary, whose default
# mode is jit-cdi from toolkit 1.18.0 onward
# (internal/runtime/runtime_factory.go:111, internal/info/auto.go:89). ECS and
# EKS both wire their GPU containers this way, so it is the production path.
#
# `--gpus all` on Docker Engine 29.1.x and older injects the
# nvidia-container-runtime-hook prestart hook, and the hook pins its own
# default to legacy (cmd/nvidia-container-runtime-hook/hook_config.go:120-123).
# The legacy path withholds /dev/nvidia-modeset without the display capability
# and withholds /dev/dri without display or graphics. Docker 29.2.0 and later
# reads /var/run/cdi/nvidia.yaml and lands on the CDI device set again.
#
# Measuring only `--gpus all` on an older Docker therefore reports a device
# set the campaign's own deployment will not see.
VIA_RUNTIME = "runtime"
VIA_GPUS = "gpus"
VIA_CHOICES = (VIA_RUNTIME, VIA_GPUS, "both")
DEFAULT_VIA = os.getenv("GSPWN_VERIFY_VIA", VIA_RUNTIME)

# Docker Engine version at which `--gpus` stops using the hook and starts
# reading a CDI specification.
DOCKER_CDI_BOUNDARY = (29, 2, 0)

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


def docker_version(runtime):
    """-> ((major, minor, patch), raw) for the server, or (None, reason)."""
    code, out, err = run([runtime, "version", "--format",
                          "{{.Server.Version}}"], RUN_TIMEOUT_SECONDS,
                         "version query")
    if code != 0:
        return None, (err or out).strip()[:200]
    raw = out.strip()
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", raw)
    if not match:
        return None, raw
    return tuple(int(g) for g in match.groups()), raw


def gpus_flag_path(version):
    """-> what `--gpus` reaches on this Docker, as a sentence."""
    if version is None:
        return ("the Docker version could not be read, so what `--gpus` "
                "reaches is unknown")
    if version >= DOCKER_CDI_BOUNDARY:
        return ("Docker %s reads a CDI specification for `--gpus`, so it "
                "reaches the same device set as --runtime=nvidia"
                % ".".join(str(p) for p in version))
    return ("Docker %s injects the prestart hook for `--gpus`, and the hook "
            "defaults to legacy, which withholds /dev/nvidia-modeset and "
            "/dev/dri" % ".".join(str(p) for p in version))


def measure_nodes(runtime, image, capabilities, pull, via):
    """-> the NVIDIA device node paths visible inside a container.

    The listing comes from inside the container. A runtime's own report of
    what it injected is a second-hand account, and this tool exists to
    measure what a tenant process can open.

    `via` selects how the GPU is given to the container. The two ways reach
    different injection code, so the caller records which one produced a
    reading.
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
    if via == VIA_RUNTIME:
        gpu_args = ["--runtime=nvidia", "-e", "NVIDIA_VISIBLE_DEVICES=all"]
    else:
        gpu_args = ["--gpus", "all"]
    argv = ([runtime, "run", "--rm"] + gpu_args +
            ["-e", "NVIDIA_DRIVER_CAPABILITIES=" + capabilities,
             image, "sh", "-c", script])
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


def report_one(via, measured, inside, outside):
    """Print one path's reading. -> that path's exit contribution."""
    unmodelled, unreachable, matched = compare(measured, inside, outside)
    label = ("--runtime=nvidia" if via == VIA_RUNTIME else "--gpus all")
    print("  path measured: %s" % label)
    print("  nodes received: %d" % len(measured))
    for node in measured:
        print("    %s" % node)
    print()
    if matched:
        print("    agreeing with the artefact: %d" % len(matched))
    if unmodelled:
        print("    REACHABLE AND NOT MODELLED: %d" % len(unmodelled))
        for line in unmodelled:
            print("      %s" % line)
        print()
        print("    The threat model understates the attacker. Every node "
              "above is one a tenant can open and the campaign does not "
              "model.")
    if unreachable:
        print("    MODELLED AND NOT REACHABLE: %d" % len(unreachable))
        for line in unreachable:
            print("      %s" % line)
        print()
        print("    Campaign effort is budgeted for surface this tenant "
              "cannot reach.")
    if not unmodelled and not unreachable:
        print("    The measured node set matches the recorded tenant "
              "surface.")
    print()
    return 1 if (unmodelled or unreachable) else 0


def cmd_measure(args):
    tables = load_tables(args.root)
    inside, outside = expected_surface(tables)
    mode, evidence = detect_runtime_mode()
    which_runtime(args.runtime)
    version, raw = docker_version(args.runtime)

    print("measured on this host")
    print()
    print("  runtime       %s" % args.runtime)
    print("  server        %s" % (raw or "unknown"))
    print("  image         %s" % args.image)
    print("  capabilities  NVIDIA_DRIVER_CAPABILITIES=%s" % args.capabilities)
    print("  config mode   %s" % (mode or "not stated"))
    print("  evidence      %s" % evidence)
    print("  --gpus        %s" % gpus_flag_path(version))
    print()

    paths = ([VIA_RUNTIME, VIA_GPUS] if args.via == "both" else [args.via])
    status = 0
    for via in paths:
        try:
            measured = measure_nodes(args.runtime, args.image,
                                     args.capabilities, args.pull, via)
        except VerifyError as exc:
            print("  path measured: %s" % via)
            print("    the measurement could not be taken: %s" % exc)
            print()
            status = 2
            continue
        status = max(status, report_one(via, measured, inside, outside))
        args.pull = False
    return status


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
    p.add_argument("--via", default=DEFAULT_VIA, choices=VIA_CHOICES,
                   help="how the container is given the GPU. `runtime` uses "
                        "--runtime=nvidia, which ECS and EKS both use and "
                        "which resolves to jit-cdi. `gpus` uses --gpus all, "
                        "which on Docker before 29.2.0 injects the hook and "
                        "resolves to legacy, withholding the modeset and DRM "
                        "nodes. `both` measures each and reports them apart "
                        "(default: %(default)s)")
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
