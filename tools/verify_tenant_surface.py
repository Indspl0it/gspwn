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

Measured nodes are canonical paths. The CDI `create-symlinks` hook creates
`/dev/dri/by-path` inside the container and fills it with symlinks onto
`/dev/dri/card*` and `/dev/dri/renderD*`, so the same node is reachable under
two names. The container script resolves every entry with `readlink -f` before
printing it, and `/dev/dri/by-path/pci-0000:00:1e.0-card` is therefore measured
as the `/dev/dri/card0` it points at. An alias never counts twice, and the
artefact declares no pattern for an alias path: declaring one would record a
second attack surface where one node exists and would double the count of
reachable nodes.

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

# How long to wait for a probe container to be removed. The removal runs in a
# `finally` after a failure the caller is already reporting, so it is bounded
# separately and never becomes the reason the gate hangs.
REMOVE_TIMEOUT_SECONDS = int(os.getenv("GSPWN_VERIFY_REMOVE_TIMEOUT", "30"))

# The last line the container script prints, and the only evidence that the
# listing ran to the end. The device listing cannot signal completion through
# an exit status: the candidate directory list ends with
# /dev/nvidia-caps-imex-channels, which is absent on a host with no IMEX
# domain, so the loop's own status is the status of a false `[ -d ]` test and
# a valid reading exits 1. An unconditional `exit 0` would answer that by
# hiding a container that was killed or lacks a shell, which is the condition
# the exit-status check exists to catch. The two signals are separated: the
# script exits 0 and states completion in its output. The token carries no
# leading slash and no `/dev` prefix, so it cannot collide with a device path.
LISTING_SENTINEL = "__GSPWN_LISTING_COMPLETE__"

# The name given to the probe container. `docker run --rm` removes it on a
# normal exit, and the name reaches it when the Python side times out first
# and the container is still running.
CONTAINER_NAME_PREFIX = "gspwn-tenant-probe-"

# The directories a tenant's NVIDIA device nodes appear in. Two of them are
# absent on a host that is correctly configured: /dev/nvidia-caps exists only
# where MIG capabilities are exposed, and /dev/nvidia-caps-imex-channels only
# where an IMEX domain is configured. Their absence is a valid reading, not a
# failed one.
CANDIDATE_DIRECTORIES = ("/dev", "/dev/dri", "/dev/nvidia-caps",
                         "/dev/nvidia-caps-imex-channels")

# A candidate directory reaches a shell command line, so it is checked before
# it is interpolated. Absolute path, no whitespace, no shell metacharacter.
_SAFE_DIRECTORY = re.compile(r"^/[A-Za-z0-9_./-]*$")

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


def listing_script(directories=CANDIDATE_DIRECTORIES):
    """-> the shell program the probe container runs, as a single line.

    The program prints one canonical device path per line and the sentinel
    last, and it exits 0 on every reading a correctly configured host can
    produce.

    Three constructs carry the measurement.

    The `[ -d "$d" ]` test skips a candidate directory with `continue`, so an
    absent or empty directory contributes nothing and decides no exit status.
    The old form ended the loop body on a false test, and the loop's status
    was that test's, so a valid reading exited 1.

    The `[ -c "$f" ]` and `[ -b "$f" ]` tests admit character and block
    devices alone. Both follow a symlink, so an entry under /dev/dri/by-path
    is listed while the by-path directory itself is dropped.

    `readlink -f` prints the node an entry names, so an alias and its target
    arrive as one path and the caller's set counts them once.

    Raises VerifyError naming the value where a directory is not an absolute
    path built from characters a shell reads literally, because the value is
    interpolated into a command line.
    """
    for directory in directories:
        if not _SAFE_DIRECTORY.match(directory):
            raise VerifyError(
                "%r is not a candidate directory this tool will list. A "
                "candidate is an absolute path of letters, digits, and the "
                "characters _ . / and -, because it is interpolated into the "
                "container's shell command line" % (directory,))
    return (
        "for d in " + " ".join(directories) + "; do "
        "  [ -d \"$d\" ] || continue; "
        "  for f in \"$d\"/*; do "
        "    if [ -c \"$f\" ] || [ -b \"$f\" ]; then "
        "      readlink -f \"$f\" 2>/dev/null || echo \"$f\"; "
        "    fi; "
        "  done; "
        "done; "
        "echo " + LISTING_SENTINEL)


def remove_container(runtime, name):
    """Remove a probe container by name. Never raises.

    Called from a `finally`, where an exception would replace the failure the
    caller is already reporting with one about cleanup. The removal is bounded
    by its own timeout, and it does not go through `run` because `run` raises
    on a timeout.

    `docker run --rm` removes the container itself on a normal exit, so a
    non-zero status here usually means the container was already gone. That is
    logged at debug level. A timeout or a runtime that cannot start is logged
    as a warning, because it leaves a container behind on the instance.
    """
    argv = [runtime, "rm", "-f", name]
    logger.debug("running %s", " ".join(argv))
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=REMOVE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        logger.warning(
            "removing probe container %s did not finish within %ds, so it may "
            "still be running on this host", name, REMOVE_TIMEOUT_SECONDS)
        return
    except OSError as exc:
        logger.warning("could not run %s to remove probe container %s: %s",
                       runtime, name, exc)
        return
    if proc.returncode != 0:
        logger.debug("probe container %s was already removed: %s", name,
                     (proc.stderr or "").strip()[:200])


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

    script = listing_script()
    if via == VIA_RUNTIME:
        gpu_args = ["--runtime=nvidia", "-e", "NVIDIA_VISIBLE_DEVICES=all"]
    else:
        gpu_args = ["--gpus", "all"]
    name = CONTAINER_NAME_PREFIX + str(os.getpid())
    argv = ([runtime, "run", "--rm", "--name", name] + gpu_args +
            ["-e", "NVIDIA_DRIVER_CAPABILITIES=" + capabilities,
             image, "sh", "-c", script])
    try:
        code, out, err = run(argv, RUN_TIMEOUT_SECONDS, "container run")
    finally:
        remove_container(runtime, name)
    if code != 0:
        raise VerifyError(
            "the container did not run, so nothing was measured. %s exited "
            "%d: %s" % (runtime, code, err.strip()[:600]))

    lines = [line.strip() for line in out.splitlines()]
    if LISTING_SENTINEL not in lines:
        raise VerifyError(
            "the device listing was truncated. The container exited 0 and "
            "printed %d line(s), and none of them is the %s line the listing "
            "script prints last, so the reading is partial and nothing can be "
            "compared against it. A container that was killed, that lacks a "
            "shell, or that died part way through the listing produces this"
            % (len([line for line in lines if line]), LISTING_SENTINEL))

    nodes = []
    for line in lines:
        if not line or line == LISTING_SENTINEL:
            continue
        if line.startswith("/dev/nvidia") or line.startswith("/dev/dri/"):
            nodes.append(line)
    # The script prints canonical paths, so an alias and the node it points at
    # arrive as the same string and the set collapses them into one node.
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


# What a container receives on each mode the toolkit accepts. A mode absent
# from this table still reaches a verdict through mode_verdict, because a
# branch chain that falls through prints nothing, and nothing reads as
# agreement to an operator checking the gate.
#
# `auto` is the value the toolkit packages write into config.toml at install
# time, so it is the reading a stock instance produces.
# nvidia-container-toolkit/internal/info/auto.go:89 resolves it to jit-cdi on
# an NVML platform from toolkit 1.18.0 onward.
CDI_VERDICT = (
    "The CDI path injects /dev/nvidia-modeset and every /dev/dri node found "
    "for the GPU's PCI bus id, with no capability check. That is the device "
    "set surface/entry-points.json records as the tenant surface.")

LEGACY_VERDICT = (
    "The legacy path withholds /dev/nvidia-modeset unless the display "
    "capability is requested, and injects no /dev/dri node at all. A tenant "
    "on this host holds less than the recorded tenant surface, and the "
    "campaign would budget effort against surface it cannot reach.")

MODE_VERDICTS = {
    "auto": "This host resolves auto to jit-cdi. " + CDI_VERDICT,
    "cdi": CDI_VERDICT,
    "jit-cdi": CDI_VERDICT,
    "legacy": LEGACY_VERDICT,
    "csv": ("The csv path mounts the files listed under "
            "/etc/nvidia-container-runtime/host-files-for-container.d, so "
            "the device set is whatever those files name and neither the CDI "
            "nor the legacy reading applies. Only `measure` settles it."),
}

UNSTATED_VERDICT = (
    "No mode is stated, so the toolkit default applies, which is jit-cdi on "
    "an NVML platform from 1.18.0 onward. " + CDI_VERDICT)


def mode_verdict(mode):
    """-> what a container receives on this mode, as a paragraph.

    Never returns an empty string. A mode this module has not seen is
    reported as unrecognised together with the two device nodes that
    distinguish the paths, because an operator reading a blank verdict
    concludes the host agrees with the record.
    """
    if mode is None:
        return UNSTATED_VERDICT
    known = MODE_VERDICTS.get(mode)
    if known is not None:
        return known
    return ("%r is not a mode this tool recognises, so which injection path "
            "it takes is unknown. The two paths differ over "
            "/dev/nvidia-modeset and /dev/dri, and the display capability "
            "gates the first of them on the legacy path. Run `measure` to "
            "settle it." % mode)


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
    print(mode_verdict(mode))
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
