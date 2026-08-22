#!/usr/bin/env python3
"""CVE-to-patch mapper: the third steering signal, derived from release diffs.

The campaign steers on two signals. Coverage says where the fuzzer has not
been. Findings say where bugs have been found in this campaign. In round 1 the
findings signal is empty, so the campaign follows coverage alone across the 531
non-privileged control commands that have a kernel-side handler.

A third signal exists in public data. NVIDIA's PSIRT bulletins name, per CVE
and per driver branch, the version that carries the fix. NVIDIA squashes each
driver release into one commit in `open-gpu-kernel-modules`, so the diff from
the previous release tag to the fixing release tag IS that release's complete
patch set, and the security fix is inside it.

What that establishes, and what it does not:

  established    the release that carries the fix, when the bulletin names a
                 Linux branch and an updated version present as a tag
  established    the set of ioctl-reachable functions that release changed
  NOT given      which hunk in that set is the security fix. NVIDIA ships
                 feature work and refactoring in the same release and labels
                 neither
  NOT given      per-CVE attribution when one bulletin fixes many CVEs in one
                 release. Bulletins 5415 and 5452 fix 19 and 12 kernel-mode
                 CVEs in a single version each, so one patch set answers for
                 all of them at once

This tool produces the mechanical half and marks the judgement half as open. It
scores each changed function against a table of security-shaped edits (a bounds
check added, a length compared before a copy, a NULL test added, a lock widened,
a refcount taken, a handle validated, a signedness change), and a score is a
prompt to read the hunk. The verdict on which hunk is the fix comes from
`--verdicts`, a curated file whose entries carry a `basis` string naming the
evidence. An unverdicted CVE stays `unresolved` in the output and never
graduates by accumulating signal points.

The join to the inventories turns a changed function into a target:

  `surface/rm-control-inventory.json`  handler -> methodId, privilege
  `surface/ioctl-inventory.json`       handler -> UVM command; file ->
                                                 the escapes dispatched there
  `surface/rm-object-graph.json`       owning class -> alloc depth

Subcommands:
  fetch    [--cache DIR]                  download PSIRT bulletin markdown
  resolve  [--src] [--cves] [--cache]     CVE -> fixing version -> tag pair
  diff     --from TAG --to TAG [--src]    one tag pair, ioctl-reachable only
  map      [--src] [--cves] [--out]       the full join, written as JSON
  hotspots [--map PATH] [--top N]         the ranking from a written map
  worklist [--map PATH] [--out PATH]      the round-1 worklist agents read

Everything except `fetch` runs offline against the checkout. No GPU, no SUT.

Exit codes: 0 success, 1 bad input or unreadable source, 2 nothing resolved.
"""
import argparse
import collections
import json
import logging
import os
import re
import sys
import urllib.error
import urllib.request

import gitmine

logger = logging.getLogger(__name__)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SRC = os.path.join("artifacts", "src", "open-gpu-kernel-modules")
DEFAULT_CVES = os.path.join("surface", "prior-cves.json")
DEFAULT_CACHE = os.path.join("surface", "bulletins")
DEFAULT_OUT = os.path.join("surface", "cve-hotspots.json")
DEFAULT_VERDICTS = os.path.join("tools", "cve_fix_verdicts.json")
CONTROL_INVENTORY = os.path.join("surface", "rm-control-inventory.json")
IOCTL_INVENTORY = os.path.join("surface", "ioctl-inventory.json")
OBJECT_GRAPH = os.path.join("surface", "rm-object-graph.json")

SCHEMA = "gspwn.cve-hotspots/1"

PSIRT_TREE_URL = ("https://api.github.com/repos/NVIDIA/product-security/"
                  "git/trees/main?recursive=1")
PSIRT_RAW = ("https://raw.githubusercontent.com/NVIDIA/product-security/main/"
             "%s")
HTTP_TIMEOUT_SECONDS = int(os.environ.get("GSPWN_HTTP_TIMEOUT_SECONDS", "45"))

# Path prefixes inside the driver tree that an ioctl on /dev/nvidiactl,
# /dev/nvidiaN, /dev/nvidia-uvm or /dev/nvidia-uvm-tools can reach. The RM
# control handlers live under src/nvidia/src/kernel, which is why the filter
# cannot stop at the unix arch layer.
REACHABLE_PREFIXES = (
    "kernel-open/nvidia/",
    "kernel-open/nvidia-uvm/",
    "kernel-open/common/inc/",
    "src/nvidia/arch/nvalloc/unix/",
    "src/nvidia/interface/",
    "src/nvidia/src/kernel/",
    "src/nvidia/src/libraries/",
    "src/common/sdk/nvidia/inc/",
    "src/common/nvswitch/",
)

# Excluded with the reason each is excluded.
#   nvidia-drm, nvidia-modeset      out of scope by threat model: the nodes
#                                   exist only under the graphics or display
#                                   container capability
#   nvidia-peermem                  an RDMA peer-memory shim with no ioctl of
#                                   its own
#   src/nvidia/generated            NVOC output, regenerated wholesale on every
#                                   release. Real churn there is mechanical and
#                                   swamps the ranking. Opt back in with
#                                   --include-generated
EXCLUDED_PREFIXES = (
    "kernel-open/nvidia-drm/",
    "kernel-open/nvidia-modeset/",
    "kernel-open/nvidia-peermem/",
    "src/nvidia-modeset/",
)
GENERATED_PREFIX = "src/nvidia/generated/"

# Products whose Linux rows in a bulletin's Security Updates table ship the
# open kernel modules. Virtual GPU Manager is the host-side vGPU package and
# carries a separate version line, so its rows resolve to versions absent from
# this repository.
LINUX_PRODUCT_RE = re.compile(
    r"GeForce|RTX|Quadro|NVS|Tesla|Guest driver|Studio", re.I)
LINUX_PRODUCT_EXCLUDE_RE = re.compile(r"Virtual GPU Manager", re.I)
BULLETIN_TABLE_HEADER_RE = re.compile(r"^\|\s*\*\*CVE IDs Addressed\*\*")
VERSION_LEAD_RE = re.compile(r"^\s*(\d+\.\d+(?:\.\d+)?)")
BRANCH_RE = re.compile(r"^(\d+)\.")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

# A C function definition in this tree opens its brace in column 0. The name is
# the first identifier followed by an open parenthesis in the declarator above
# it, which holds for both `static NV_STATUS foo(args)` and the multi-line
# `NV_STATUS\nmemdescCreate\n(\n args \n)` form the RM sources use. The three
# functions implementing that rule live in `gitmine` and are named here because
# this module is where they are called and tested from.
function_ranges = gitmine.function_ranges
declarator_name = gitmine.declarator_name
enclosing = gitmine.enclosing

# Suffixes NVOC appends to a handler symbol. The inventory records the base
# name and the source defines the suffixed one.
HANDLER_SUFFIXES = ("__EXPORT", "_IMPL", "_KERNEL", "_PHYSICAL", "_VF")

# Security-shaped edits. Each entry is (signal, applies-to-added-lines,
# pattern). A signal is a reason to read the hunk and never a verdict on it.
SIGNAL_PATTERNS = (
    ("null_check", True,
     r"(==|!=)\s*NULL|\bNULL\s*(==|!=)|\bif\s*\(\s*!\s*p[A-Z]\w*\s*\)"),
    ("bounds_check", True,
     r"\b(NV_CHECK_OR_RETURN|NV_ASSERT_OR_RETURN|NV_CHECK_OK_OR_RETURN|"
     r"NV_ASSERT_OR_ELSE)\b.*(<|>|<=|>=)"),
    ("size_validation", True,
     r"\b\w*([Ss]ize|[Ll]ength|[Ll]en|[Cc]ount|[Oo]ffset|[Ii]ndex)\w*\s*"
     r"(<|>|<=|>=|==)\s*"),
    ("overflow_guard", True,
     r"\bportSafe\w+|\boverflow\b|NV_U32_MAX|NV_U64_MAX|MAX_\w+\s*[/-]"),
    ("copy_bound", True,
     r"\b(portMemCopy|portMemExCopy|copy_from_user|copy_to_user|"
     r"NV_COPY_(FROM|TO)_USER|os_mem_copy)\b"),
    ("refcount", True,
     r"\b\w*[Rr]ef[Cc]ount\w*|\bserverutilRef\w*|\b\w*(IncRef|DecRef)\w*|"
     r"\bportAtomic\w*(Increment|Decrement)"),
    ("locking", True,
     r"\b\w*([Ll]ock|[Mm]utex|[Ss]emaphore|[Ss]pinlock)\w*(Acquire|Release|"
     r"_acquire|_release|_lock|_unlock)|\brmapiLock\w+|\bGPU_LOCK\w*"),
    ("handle_validation", True,
     r"\bserverutilValidate\w*|\bclientValidate\w*|\brefFind\w*|"
     r"\bserverGetClientUnderLock\b|\bRES_GET_HANDLE\b|\bhClient\b.*(==|!=)"),
    ("signedness", True,
     r"\b(NvU8|NvU16|NvU32|NvU64|NvS8|NvS16|NvS32|NvS64|unsigned|size_t)\b"),
    ("uninitialized_memory", True,
     r"\b(portMemSet|memset|os_mem_set|NV_ZERO_STRUCT|portMemSetPattern)\b"),
    ("free_ordering", True,
     r"\b(portMemFree|objDelete|os_free_mem|kfree|uvm_kvfree)\b|"
     r"=\s*NULL\s*;"),
    ("user_pointer", True,
     r"\bNvP64\b|\bNvP64_VALUE\b|\b__user\b|\bpUserParams\b"),
)
# A hunk larger than this reads as feature work. The threshold only orders the
# reading queue, so a large hunk is still recorded with its signals.
SMALL_HUNK_LINES = 40

VERDICT_VALUES = ("located", "plausible", "not_located", "unresolved")


class SourceError(Exception):
    """The driver checkout or an inventory could not be used as given."""


def repo_path(path):
    """Absolute path for a repository-relative argument."""
    return path if os.path.isabs(path) else os.path.join(REPO_ROOT, path)


def git(src, *args):
    """Run one git command in the checkout and return its stdout.

    A non-zero exit or a timeout is a SourceError carrying the command and
    stderr. A silent empty result would read as an empty diff. Diff-format
    configuration and the timeout come from `gitmine.run_git`.
    """
    return gitmine.run_git(src, args, error=SourceError)


def check_src(src):
    """Validate that src is an open-gpu-kernel-modules checkout with tags."""
    full = repo_path(src)
    if not os.path.isdir(os.path.join(full, ".git")):
        raise SourceError(
            "no git checkout at %s: --src must point at a clone of "
            "open-gpu-kernel-modules with its release tags fetched" % full)
    marker = os.path.join(full, "src", "nvidia", "arch", "nvalloc", "unix")
    if not os.path.isdir(marker):
        raise SourceError(
            "%s has no src/nvidia/arch/nvalloc/unix: --src does not point at "
            "open-gpu-kernel-modules" % full)
    tags = gitmine.list_tags(full, error=SourceError)
    if not tags:
        raise SourceError(
            "%s has no tags. Release bracketing needs them: fetch with "
            "`git fetch --tags`" % full)
    logger.info("driver checkout %s carries %d release tags", full, len(tags))
    return full, set(tags)


def load_json(path, what):
    """Read one JSON file, with the failure naming what was being loaded."""
    full = repo_path(path)
    if not os.path.exists(full):
        raise SourceError("%s not found at %s" % (what, full))
    try:
        with open(full, encoding="utf-8") as handle:
            return json.load(handle)
    except ValueError as exc:
        raise SourceError("%s at %s is not valid JSON: %s"
                          % (what, full, exc))


def kernel_mode_cves(cves_path):
    """The Track K records from prior-cves.json, in bulletin order."""
    doc = load_json(cves_path, "the classified CVE record")
    records = doc.get("records")
    if not isinstance(records, list):
        raise SourceError(
            "%s has no `records` list: expected the output of the CVE "
            "classifier that wrote prior-cves.json" % repo_path(cves_path))
    kernel = [r for r in records if r.get("classification") == "K"]
    if not kernel:
        raise SourceError(
            "%s holds %d records and none classified K. Nothing to map."
            % (repo_path(cves_path), len(records)))
    logger.info("%d of %d CVE records classified kernel-mode",
                len(kernel), len(records))
    return kernel


def http_get(url):
    """Fetch one URL as text, with the failure naming the URL."""
    request = urllib.request.Request(
        url, headers={"User-Agent": "gspwn-cve-patch-map"})
    try:
        with urllib.request.urlopen(request,
                                    timeout=HTTP_TIMEOUT_SECONDS) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise SourceError("GET %s returned HTTP %s" % (url, exc.code))
    except urllib.error.URLError as exc:
        raise SourceError("GET %s failed: %s" % (url, exc.reason))


def cmd_fetch(args):
    """Download the PSIRT bulletin markdown for every bulletin the CVEs name.

    This is the one subcommand that needs the network. Its output is a cache
    the rest of the tool reads offline.
    """
    kernel = kernel_mode_cves(args.cves)
    wanted = sorted({r.get("bulletin_id") for r in kernel
                     if r.get("bulletin_id")})
    logger.info("%d bulletins named by the kernel-mode CVEs", len(wanted))

    tree = json.loads(http_get(PSIRT_TREE_URL))
    if tree.get("truncated"):
        logger.warning("the PSIRT repository tree came back truncated; some "
                       "bulletins may be missed")
    paths = [e["path"] for e in tree.get("tree", ())
             if e.get("type") == "blob"]
    cache = repo_path(args.cache)
    os.makedirs(cache, exist_ok=True)

    found, absent = 0, []
    for bulletin in wanted:
        match = [p for p in paths
                 if p.endswith("/%s/%s.md" % (bulletin, bulletin))]
        if not match:
            absent.append(bulletin)
            continue
        body = http_get(PSIRT_RAW % match[0])
        target = os.path.join(cache, "%s.md" % bulletin)
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(body)
        found += 1
        logger.debug("cached bulletin %s from %s", bulletin, match[0])

    print("cached %d of %d bulletins into %s" % (found, len(wanted), cache))
    if absent:
        print("absent from the PSIRT repository (published before it opened "
              "in 2022): %s" % ", ".join(absent))
    return 0


def parse_bulletin(path):
    """Return the Security Updates rows of one bulletin, keyed by CVE.

    Each row is (product, platform, affected_versions, updated_version), the
    last four columns of the five-column table NVIDIA publishes.
    """
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    starts = [n for n, line in enumerate(lines)
              if BULLETIN_TABLE_HEADER_RE.match(line)]
    if not starts:
        raise SourceError(
            "%s has no Security Updates table. The parser keys on the "
            "`CVE IDs Addressed` header row; NVIDIA may have changed the "
            "bulletin layout" % path)
    rows = collections.defaultdict(list)
    for start in starts:
        n = start + 2
        while n < len(lines) and lines[n].startswith("|"):
            cells = [c.strip() for c in lines[n].strip().strip("|").split("|")]
            if len(cells) == 5 and CVE_RE.match(cells[0]):
                rows[cells[0]].append(tuple(cells[1:]))
            n += 1
    return rows


def load_bulletins(cache):
    """Read every cached bulletin into one CVE-keyed row table."""
    full = repo_path(cache)
    if not os.path.isdir(full):
        raise SourceError(
            "no bulletin cache at %s. Populate it once with "
            "`cve_patch_map.py fetch`, which is the only step needing the "
            "network" % full)
    names = sorted(n for n in os.listdir(full) if n.endswith(".md"))
    if not names:
        raise SourceError("%s holds no bulletin markdown" % full)
    rows = collections.defaultdict(list)
    for name in names:
        for cve, cve_rows in parse_bulletin(os.path.join(full, name)).items():
            rows[cve].extend(cve_rows)
    logger.info("%d cached bulletins carry rows for %d CVEs",
                len(names), len(rows))
    return rows


def linux_fix_versions(rows):
    """The Linux driver versions a bulletin says carry the fix for one CVE."""
    versions = set()
    for product, platform, _affected, updated in rows:
        if "Linux" not in platform:
            continue
        if LINUX_PRODUCT_EXCLUDE_RE.search(product):
            continue
        if not LINUX_PRODUCT_RE.search(product):
            continue
        match = VERSION_LEAD_RE.match(updated)
        if match:
            versions.add(match.group(1))
    return versions


def bracket(src, tag):
    """The tag pair whose diff is the release that carries tag.

    The predecessor comes from git ancestry and never from a version sort.
    NVIDIA maintains its branches as separate lines of history, so the
    numerically previous tag is frequently on another branch, and its diff
    would report a whole branch divergence as one release.
    """
    try:
        previous = gitmine.previous_tag(src, "%s^" % tag, error=SourceError)
    except SourceError as exc:
        logger.warning("no ancestor tag for %s: %s", tag, exc)
        return None
    if not previous:
        return None
    return previous, tag


def resolve_cves(src, tags, kernel, rows):
    """Map each kernel-mode CVE to the tag pairs that bracket its fixes."""
    resolved = []
    for record in kernel:
        cve = record["cve"]
        cve_rows = rows.get(cve, [])
        versions = linux_fix_versions(cve_rows)
        present = sorted(v for v in versions if v in tags)
        pairs = []
        for version in present:
            pair = bracket(src, version)
            if not pair:
                continue
            branch = BRANCH_RE.match(version).group(1)
            from_branch = BRANCH_RE.match(pair[0])
            cross = bool(from_branch) and from_branch.group(1) != branch
            pairs.append({"branch": branch, "from": pair[0], "to": pair[1],
                          "cross_branch": cross})
            if cross:
                logger.warning(
                    "%s brackets %s to %s, which opens branch %s from branch "
                    "%s. That diff is a branch divergence and carries no "
                    "usable evidence about one fix",
                    cve, pair[0], pair[1], branch, from_branch.group(1))
        if cve_rows and not versions:
            reason = ("the bulletin names no Linux row for a product that "
                      "ships the open kernel modules")
        elif versions and not present:
            reason = ("the fixing versions %s predate the open-source "
                      "repository or belong to a branch it does not carry"
                      % ", ".join(sorted(versions)))
        elif not cve_rows:
            reason = ("no bulletin markdown is cached for bulletin %s; NVIDIA "
                      "backfilled the PSIRT repository only to 2022"
                      % record.get("bulletin_id"))
        else:
            reason = None
        resolved.append({
            "cve": cve,
            "bulletin_id": record.get("bulletin_id"),
            "bulletin_date": record.get("bulletin_date"),
            "cwe": record.get("cwe"),
            "subsystem": record.get("subsystem"),
            "component_as_nvidia_words_it":
                record.get("component_as_nvidia_words_it"),
            "fix_versions_stated": sorted(versions),
            "fix_versions_present_as_tag": present,
            "tag_pairs": pairs,
            "unresolved_reason": reason,
        })
    with_pair = sum(1 for r in resolved if r["tag_pairs"])
    logger.info("%d of %d kernel-mode CVEs bracket to at least one tag pair",
                with_pair, len(resolved))
    return resolved


def path_in_scope(path, include_generated):
    """Is one changed path inside the ioctl-reachable set."""
    if path.startswith(EXCLUDED_PREFIXES):
        return False
    if path.startswith(GENERATED_PREFIX):
        return include_generated
    return path.startswith(REACHABLE_PREFIXES)


def hunk_signals(added, removed):
    """The security-shaped signals one hunk carries."""
    fired = []
    added_text = "\n".join(added)
    removed_text = "\n".join(removed)
    for name, on_added, pattern in SIGNAL_PATTERNS:
        body = added_text if on_added else removed_text
        if re.search(pattern, body):
            fired.append(name)
    if "signedness" in fired:
        # A type name appearing in an added line is ordinary. The signal only
        # means something when the same declaration changed its signedness.
        added_types = set(re.findall(r"\bNv[SU]\d+\b", added_text))
        removed_types = set(re.findall(r"\bNv[SU]\d+\b", removed_text))
        if not (added_types - removed_types) or not (removed_types
                                                     - added_types):
            fired.remove("signedness")
    return fired


def diff_pair(src, from_tag, to_tag, include_generated=False):
    """Every ioctl-reachable function one release changed, with its signals."""
    names = git(src, "diff", "--name-only", from_tag, to_tag).splitlines()
    in_scope = [p for p in names if path_in_scope(p, include_generated)]
    logger.info("%s..%s changed %d files, %d ioctl-reachable",
                from_tag, to_tag, len(names), len(in_scope))
    changed = []
    for path in in_scope:
        changed.extend(diff_file(src, from_tag, to_tag, path))
    return {"from": from_tag, "to": to_tag,
            "files_changed_total": len(names),
            "files_changed_in_scope": len(in_scope),
            "files_in_scope": in_scope,
            "functions": changed}


def diff_file(src, from_tag, to_tag, path):
    """The changed functions of one file, each with its hunk signals."""
    try:
        post = git(src, "show", "%s:%s" % (to_tag, path))
    except SourceError:
        # Deleted by this release. Attribute the hunks to the pre-image.
        try:
            post = git(src, "show", "%s:%s" % (from_tag, path))
        except SourceError as exc:
            logger.warning("neither side of %s is readable: %s", path, exc)
            return []
        ranges = function_ranges(post)
        side = "pre"
    else:
        ranges = function_ranges(post)
        side = "post"

    body = git(src, "diff", "-U0", from_tag, to_tag, "--", path)
    outside = "%s (outside any function)" % os.path.basename(path)
    per_function = collections.defaultdict(
        lambda: {"hunks": set(), "added": [], "removed": []})

    # An added line carries its own post-image position, so a hunk that adds
    # three whole functions splits three ways. A removed line has no post-image
    # position and goes to the function at the hunk anchor. A hunk that only
    # removes lines from the head of the file anchors at 0, and the pre-image
    # is 1-based, so the anchor is floored.
    hunk_index = 0
    for entry in gitmine.parse_unified_diff(body):
        for hunk in entry.hunks:
            hunk_index += 1
            for offset, text in enumerate(hunk.added):
                name = enclosing(ranges, hunk.new_start + offset) or outside
                slot = per_function[name]
                slot["added"].append(text)
                slot["hunks"].add(hunk_index)
            if hunk.removed:
                anchor = max(1, hunk.new_start)
                name = enclosing(ranges, anchor) or outside
                slot = per_function[name]
                slot["removed"].extend(hunk.removed)
                slot["hunks"].add(hunk_index)

    out = []
    for name, slot in sorted(per_function.items()):
        fired = hunk_signals(slot["added"], slot["removed"])
        size = len(slot["added"]) + len(slot["removed"])
        out.append({
            "file": path,
            "function": name,
            "attributed_to": side,
            "hunks": len(slot["hunks"]),
            "lines_added": len(slot["added"]),
            "lines_removed": len(slot["removed"]),
            "signals": fired,
            "small_signal_hunks": 1 if fired and size <= SMALL_HUNK_LINES
                                  else 0,
        })
    return out


def normalise_handler(name):
    """Strip the suffixes NVOC appends, so a definition matches an inventory."""
    out = name
    changed = True
    while changed:
        changed = False
        for suffix in HANDLER_SUFFIXES:
            if out.endswith(suffix) and len(out) > len(suffix):
                out = out[:-len(suffix)]
                changed = True
    return out


def build_joins():
    """Index the three surface inventories by the keys a diff produces."""
    control = load_json(CONTROL_INVENTORY, "the RM control inventory")
    ioctls = load_json(IOCTL_INVENTORY, "the ioctl inventory")
    objects = load_json(OBJECT_GRAPH, "the RM object graph")

    by_handler = collections.defaultdict(list)
    for method in control.get("methods", ()):
        handler = method.get("handler")
        if handler:
            by_handler[normalise_handler(handler)].append(method)

    uvm_by_handler = {}
    escapes_by_file = collections.defaultdict(list)
    for node in ioctls.get("nodes", ()):
        for command in node.get("commands", ()):
            handler = command.get("handler")
            if handler:
                uvm_by_handler[handler] = {
                    "command": command.get("name"),
                    "node": node.get("paths"),
                    "param_struct": command.get("param_struct"),
                    "syzlang": command.get("syzlang"),
                }
            for key in ("dispatch_site", "validation_site"):
                site = command.get(key)
                if not site or ":" not in site:
                    continue
                source_file = site.rsplit(":", 1)[0]
                if source_file.endswith(".c"):
                    escapes_by_file[source_file].append(command.get("name"))

    class_by_internal = {}
    for record in objects.get("records", ()):
        internal = record.get("internal_class")
        if internal:
            class_by_internal[internal] = {
                "external_class": record.get("external_class"),
                "depth": record.get("depth"),
                "alloc_privilege": record.get("alloc_privilege"),
                "parents": record.get("parents"),
            }

    logger.info("joins indexed: %d control handlers, %d UVM handlers, "
                "%d escape-bearing files, %d object classes",
                len(by_handler), len(uvm_by_handler), len(escapes_by_file),
                len(class_by_internal))
    return {"control": by_handler, "uvm": uvm_by_handler,
            "escape_files": {k: sorted(set(v))
                             for k, v in escapes_by_file.items()},
            "classes": class_by_internal}


def join_function(entry, joins):
    """Attach the ioctl target a changed function serves, when one is known."""
    base = normalise_handler(entry["function"])
    methods = joins["control"].get(base, [])
    if methods:
        out = []
        for method in methods:
            owner = joins["classes"].get(method.get("owning_class"), {})
            out.append({
                "kind": "rm_control",
                "method_id": method.get("method_id"),
                "sdk_prefix": method.get("sdk_prefix"),
                "owning_class": method.get("owning_class"),
                "external_class": owner.get("external_class"),
                "alloc_depth": owner.get("depth"),
                "param_struct": method.get("param_struct"),
                "reachability": method.get("reachability"),
                "routed_to_physical": method.get("routed_to_physical"),
                "kernel_side_handler": not method.get("routed_to_physical")
                and not method.get("handler_compiled_out"),
            })
        return out
    uvm = joins["uvm"].get(base)
    if uvm:
        return [dict(kind="uvm_command", **uvm)]
    escapes = joins["escape_files"].get(entry["file"])
    if escapes:
        return [{"kind": "escape_file",
                 "escapes_dispatched_in_file": escapes,
                 "note": "file-level join: the function sits in a file that "
                         "dispatches these escapes, which does not by itself "
                         "place it on any one escape's path"}]
    return []


def load_verdicts(path):
    """Read the curated per-CVE verdicts, or an empty overlay when absent."""
    full = repo_path(path)
    if not os.path.exists(full):
        logger.warning("no verdict file at %s; every CVE stays unresolved",
                       full)
        return {}
    doc = load_json(path, "the curated fix verdicts")
    verdicts = doc.get("verdicts", {})
    for cve, verdict in verdicts.items():
        value = verdict.get("verdict")
        if value not in VERDICT_VALUES:
            raise SourceError(
                "verdict %r for %s in %s is not one of %s"
                % (value, cve, full, ", ".join(VERDICT_VALUES)))
        if value != "not_located" and not verdict.get("basis"):
            raise SourceError(
                "verdict %s for %s in %s carries no `basis`. A located or "
                "plausible verdict without the evidence behind it is the one "
                "thing this file exists to prevent" % (value, cve, full))
    logger.info("%d curated verdicts loaded from %s", len(verdicts), full)
    return verdicts


def cmd_resolve(args):
    """Print the CVE-to-tag-pair resolution and where it fails."""
    src, tags = check_src(args.src)
    kernel = kernel_mode_cves(args.cves)
    rows = load_bulletins(args.cache)
    resolved = resolve_cves(src, tags, kernel, rows)
    print("%-18s %-9s %-28s %s"
          % ("cve", "bulletin", "fix tags present", "pairs"))
    for record in resolved:
        pairs = ", ".join("%s..%s" % (p["from"], p["to"])
                          for p in record["tag_pairs"])
        print("%-18s %-9s %-28s %s"
              % (record["cve"], record["bulletin_id"] or "-",
                 ", ".join(record["fix_versions_present_as_tag"]) or "-",
                 pairs or record["unresolved_reason"] or "-"))
    with_pair = sum(1 for r in resolved if r["tag_pairs"])
    print("\n%d of %d kernel-mode CVEs resolved to a tag pair"
          % (with_pair, len(resolved)))
    return 0 if with_pair else 2


def cmd_diff(args):
    """Print one tag pair's ioctl-reachable changed functions."""
    src, tags = check_src(args.src)
    for tag in (args.from_tag, args.to_tag):
        if tag not in tags:
            print("%s is not a tag in %s" % (tag, src), file=sys.stderr)
            return 1
    result = diff_pair(src, args.from_tag, args.to_tag, args.include_generated)
    print("%s..%s: %d files changed, %d ioctl-reachable"
          % (result["from"], result["to"], result["files_changed_total"],
             result["files_changed_in_scope"]))
    ordered = sorted(result["functions"],
                     key=lambda f: (-f["small_signal_hunks"],
                                    f["lines_added"] + f["lines_removed"]))
    print("%-6s %-6s %-42s %-46s %s"
          % ("+", "-", "function", "file", "signals"))
    for entry in ordered:
        print("%-6d %-6d %-42s %-46s %s"
              % (entry["lines_added"], entry["lines_removed"],
                 entry["function"][:42], entry["file"][-46:],
                 ",".join(entry["signals"])))
    return 0


def cmd_map(args):
    """Write the CVE-to-hotspot join, the deliverable the worklist reads."""
    src, tags = check_src(args.src)
    kernel = kernel_mode_cves(args.cves)
    rows = load_bulletins(args.cache)
    resolved = resolve_cves(src, tags, kernel, rows)
    joins = build_joins()
    verdicts = load_verdicts(args.verdicts)

    pair_cache = {}
    pair_cves = collections.defaultdict(list)
    cross_branch_pairs = set()
    for record in resolved:
        for pair in record["tag_pairs"]:
            key = (pair["from"], pair["to"])
            pair_cves[key].append(record["cve"])
            if pair["cross_branch"]:
                cross_branch_pairs.add(key)

    for key in sorted(pair_cves):
        pair_cache[key] = diff_pair(src, key[0], key[1],
                                    args.include_generated)
        pair_cache[key]["cross_branch"] = key in cross_branch_pairs

    out_records = []
    for record in resolved:
        entry = dict(record)
        entry["shared_patch_set"] = {}
        entry["changed_functions"] = []
        seen = {}
        # A branch counts toward the intersection only when its pair is a
        # same-branch release with a non-empty ioctl-reachable diff. A
        # branch-opening pair changes hundreds of functions and would make the
        # intersection meaningless; a version-bump-only pair changes none and
        # would empty it.
        usable = set()
        for pair in record["tag_pairs"]:
            key = (pair["from"], pair["to"])
            result = pair_cache[key]
            entry["shared_patch_set"]["%s..%s" % key] = sorted(
                set(pair_cves[key]))
            if not pair["cross_branch"] and result["files_changed_in_scope"]:
                usable.add(pair["branch"])
            for function in result["functions"]:
                fid = (function["file"], function["function"])
                if fid not in seen:
                    joined = dict(function)
                    joined["branches"] = []
                    joined["targets"] = join_function(function, joins)
                    seen[fid] = joined
                    entry["changed_functions"].append(joined)
                seen[fid]["branches"].append(pair["branch"])
        entry["branches_usable_for_intersection"] = sorted(usable)
        for function in entry["changed_functions"]:
            function["branches"] = sorted(set(function["branches"]))
            function["in_every_branch"] = (
                len(usable) > 1
                and usable.issubset(set(function["branches"])))
        verdict = verdicts.get(record["cve"], {})
        entry["verdict"] = verdict.get("verdict", "unresolved")
        entry["verdict_basis"] = verdict.get("basis")
        entry["fix_functions"] = verdict.get("fix_functions", [])
        entry["reachability_note"] = verdict.get("reachability_note")
        out_records.append(entry)

    hotspots = rank_hotspots(pair_cache, pair_cves, joins,
                             args.max_scope_files)
    doc = {
        "schema": SCHEMA,
        "source": {
            "driver_checkout": os.path.relpath(src, REPO_ROOT),
            "head": git(src, "rev-parse", "--short", "HEAD").strip(),
            "tags_present": len(tags),
            "cve_record": args.cves,
            "bulletin_cache": args.cache,
            "verdict_overlay": args.verdicts,
            "include_generated": bool(args.include_generated),
        },
        "scope": {
            "reachable_prefixes": list(REACHABLE_PREFIXES),
            "excluded_prefixes": list(EXCLUDED_PREFIXES),
            "generated_prefix": GENERATED_PREFIX,
        },
        "summary": {
            "kernel_mode_cves": len(out_records),
            "resolved_to_tag_pair": sum(1 for r in out_records
                                        if r["tag_pairs"]),
            "distinct_tag_pairs": len(pair_cache),
            "verdict_counts": dict(collections.Counter(
                r["verdict"] for r in out_records)),
            "resolved_to_named_function": sum(
                1 for r in out_records if r["fix_functions"]),
        },
        "records": out_records,
        "hotspots": hotspots,
    }
    out = repo_path(args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(doc, handle, indent=1, sort_keys=False)
        handle.write("\n")
    os.replace(tmp, out)
    logger.info("wrote %s", out)
    print("%d kernel-mode CVEs, %d resolved to a tag pair, %d tag pairs "
          "diffed, %d with a named fix function -> %s"
          % (doc["summary"]["kernel_mode_cves"],
             doc["summary"]["resolved_to_tag_pair"],
             doc["summary"]["distinct_tag_pairs"],
             doc["summary"]["resolved_to_named_function"],
             os.path.relpath(out, REPO_ROOT)))
    return 0


def rank_hotspots(pair_cache, pair_cves, joins, max_scope_files):
    """The empirical ranking: what security-fixing point releases keep editing.

    Two filters decide the ranking, and both exist because raw frequency
    measures release churn. Every release edits `nvidia.Kbuild`, the version
    headers and the GSP RPC poll loop, so those top an unfiltered count while
    carrying nothing about memory safety.

      pair filter        only same-branch releases whose ioctl-reachable
                         footprint is at most max_scope_files. A branch-opening
                         release rebases hundreds of files and swamps the count
      function filter    only named functions carrying at least one
                         security-shaped signal. A build file and a header
                         hunk outside any function stay in the per-CVE records
                         and out of the ranking
    """
    by_function = {}
    by_file = collections.Counter()
    by_subsystem = collections.Counter()
    excluded = []
    for key, result in sorted(pair_cache.items()):
        if result.get("cross_branch"):
            excluded.append({"pair": "%s..%s" % key,
                             "reason": "cross-branch: the predecessor tag is "
                                       "on another branch, so the diff is a "
                                       "branch divergence",
                             "functions_skipped": len(result["functions"])})
            continue
        if result["files_changed_in_scope"] > max_scope_files:
            excluded.append({"pair": "%s..%s" % key,
                             "reason": "%d ioctl-reachable files exceeds the "
                                       "--max-scope-files ceiling of %d, so "
                                       "the release is dominated by work "
                                       "other than its fixes"
                                       % (result["files_changed_in_scope"],
                                          max_scope_files),
                             "functions_skipped": len(result["functions"])})
            continue
        cves = sorted(set(pair_cves[key]))
        for function in result["functions"]:
            if not function["signals"]:
                continue
            if function["function"].endswith("(outside any function)"):
                continue
            fid = "%s::%s" % (function["file"], function["function"])
            slot = by_function.setdefault(fid, {
                "file": function["file"],
                "function": function["function"],
                "releases": 0,
                "signal_hunks": 0,
                "lines_changed": 0,
                "signals": set(),
                "cves": set(),
                "pairs": [],
                "targets": join_function(function, joins),
            })
            slot["releases"] += 1
            slot["signal_hunks"] += function["small_signal_hunks"]
            slot["lines_changed"] += (function["lines_added"]
                                      + function["lines_removed"])
            slot["signals"].update(function["signals"])
            slot["cves"].update(cves)
            slot["pairs"].append("%s..%s" % key)
            by_file[function["file"]] += 1
            by_subsystem[subsystem_of(function["file"])] += 1
    ranked = []
    for slot in by_function.values():
        slot["signals"] = sorted(slot["signals"])
        slot["cves"] = sorted(slot["cves"])
        slot["cve_count"] = len(slot["cves"])
        ranked.append(slot)
    ranked.sort(key=lambda s: (-s["signal_hunks"], -s["releases"],
                               s["function"]))
    logger.info("hotspot ranking over %d of %d tag pairs, %d functions",
                len(pair_cache) - len(excluded), len(pair_cache), len(ranked))
    return {
        "max_scope_files": max_scope_files,
        "excluded_pairs": excluded,
        "by_function": ranked,
        "by_file": [{"file": f, "releases": n}
                    for f, n in by_file.most_common()],
        "by_subsystem": [{"subsystem": s, "changed_functions": n}
                         for s, n in by_subsystem.most_common()],
    }


def subsystem_of(path):
    """A coarse subsystem label for one source path."""
    if path.startswith("kernel-open/nvidia-uvm/"):
        return "uvm"
    if path.startswith("kernel-open/nvidia/"):
        return "kernel-open glue"
    if path.startswith("src/nvidia/arch/nvalloc/unix/"):
        return "unix arch layer"
    if path.startswith("src/common/nvswitch/"):
        return "nvswitch"
    parts = path.split("/")
    if path.startswith("src/nvidia/src/kernel/") and len(parts) > 5:
        return "rm/%s" % "/".join(parts[4:6])
    return "/".join(parts[:3])


def cmd_hotspots(args):
    """Print the ranking from an already-written map."""
    doc = load_json(args.map, "the CVE hotspot map")
    ranked = doc.get("hotspots", {}).get("by_function", [])
    if not ranked:
        print("%s carries no hotspot ranking" % repo_path(args.map),
              file=sys.stderr)
        return 2
    print("%-6s %-6s %-44s %-40s %s"
          % ("rel", "cves", "function", "file", "target"))
    for slot in ranked[:args.top]:
        targets = slot.get("targets") or []
        label = "-"
        if targets:
            first = targets[0]
            label = (first.get("method_id") or first.get("command")
                     or first.get("kind"))
        print("%-6d %-6d %-44s %-40s %s"
              % (slot["releases"], slot["cve_count"], slot["function"][:44],
                 slot["file"][-40:], label))
    print()
    for row in doc["hotspots"]["by_subsystem"][:args.top]:
        print("%-40s %d changed functions"
              % (row["subsystem"], row["changed_functions"]))
    return 0


DEFAULT_WORKLIST = os.path.join("surface", "worklist-round1.md")


def _relative(path):
    """-> the path as written in the repository.

    The generated worklist is committed and read on another machine, so an
    absolute path from whoever ran the tool is noise at best and a broken
    pointer at worst.
    """
    try:
        return os.path.relpath(os.path.abspath(path), REPO_ROOT).replace(
            os.sep, "/")
    except ValueError:
        return path


def _variant(function):
    """-> the syzlang variant name for a patched control handler.

    NVOC spells the handler `fooCtrlCmdBar_IMPL` in the source and
    `fooCtrlCmdBar` in the exported method table, and syzlang_gen.py names the
    variant after the table. Stripping the suffix keeps an item here
    checkable with `surface_cov.py gaps`.
    """
    base = function[:-5] if function.endswith("_IMPL") else function
    return "NV_ESC_RM_CONTROL_" + base


def _reachable(target):
    """A default tenant can call this, and KCOV can see the handler run."""
    return (target.get("reachability") == "non_privileged"
            and target.get("kernel_side_handler"))


def _located_items(doc):
    """Worklist lines for the CVEs whose fix hunk was read and identified.

    A frequency rank says a release touched a function. A located verdict says
    which edit in that release closed a specific vulnerability, so these lead
    the list. The reachability note travels with the item, because several
    located fixes sit behind a check the privilege flag does not show.
    """
    items = []
    for record in doc.get("records", ()):
        if record.get("verdict") not in ("located", "plausible"):
            continue
        if not record.get("fix_functions"):
            continue
        note = record.get("reachability_note")
        items.append(
            "- [history %s] %s: %s. Fix in %s%s"
            % (record["cve"], record.get("verdict"), record.get("cwe", "?"),
               ", ".join(f.split("::")[-1] for f in record["fix_functions"]),
               ". " + note if note else ""))
    return sorted(items)


def cmd_worklist(args):
    """Emit the round-1 worklist from the CVE hotspot join.

    Rounds after the first get their worklist from refine, which derives it
    from the round's own coverage and findings. Round 1 has neither, and was
    steered by the structural priority order in agents/describe.md alone.
    Patch history is the one empirical signal available before any campaign
    runs, and round 1 has nothing else to add.
    """
    doc = load_json(args.map, "the CVE hotspot map")
    ranked = doc.get("hotspots", {}).get("by_function", [])
    if not ranked:
        print("%s carries no hotspot ranking. Run `cve_patch_map.py map` "
              "first: an empty worklist would read as a history that suggests "
              "nothing, when the truth is that nothing was mined."
              % repo_path(args.map), file=sys.stderr)
        return 2

    slots = [x for x in ranked
             if x.get("targets") and x.get("releases", 0) >= args.min_releases]
    slots.sort(key=lambda x: (-x.get("releases", 0), -x.get("cve_count", 0),
                              x["function"]))

    describe, seeds, out_of_reach = [], [], []
    chains = {}
    # Every patched function in a file resolves to the same escape list, so
    # keying these by function would print osapi.c once per function and read
    # as five targets where there are three. Merge on the file and carry the
    # union of the evidence.
    by_file = {}
    for slot in slots:
        cves = slot.get("cves") or ["unattributed"]
        tag = "[history %s]" % cves[0]
        if len(cves) > 1:
            tag = "[history %s +%d]" % (cves[0], len(cves) - 1)
        why = "patched across %d release(s), %d CVE(s), signals: %s" % (
            slot.get("releases", 0), slot.get("cve_count", 0),
            ", ".join(slot.get("signals") or []) or "none recorded")
        for target in slot["targets"]:
            kind = target.get("kind")
            if kind == "rm_control":
                label = "%s %s %s" % (target.get("sdk_prefix", "?"),
                                      target.get("method_id", "?"),
                                      _variant(slot["function"]))
                if not _reachable(target):
                    reason = ("handler compiled out, so it runs on GSP"
                              if target.get("reachability") == "non_privileged"
                              else "%s" % target.get("reachability", "?"))
                    out_of_reach.append(
                        "- %s %s: %s, so no round should model it"
                        % (tag, label, reason))
                    continue
                describe.append("- %s control %s: %s" % (tag, label, why))
                klass = target.get("external_class")
                if klass:
                    chains.setdefault(klass, set()).add(
                        (target.get("alloc_depth"), tag))
            elif kind == "uvm_command":
                command = target.get("command", "?")
                if command.startswith("UVM_TEST"):
                    out_of_reach.append(
                        "- %s uvm %s: a test command, gated behind "
                        "uvm_enable_builtin_tests=1" % (tag, command))
                    continue
                describe.append("- %s uvm %s: %s" % (tag, command, why))
            elif kind == "escape_file":
                name = slot["file"].split("/")[-1]
                entry = by_file.setdefault(name, {
                    "escapes": set(), "cves": set(), "signals": set(),
                    "functions": set(), "releases": 0,
                })
                entry["escapes"].update(
                    target.get("escapes_dispatched_in_file") or [])
                entry["cves"].update(cves)
                entry["signals"].update(slot.get("signals") or [])
                entry["functions"].add(slot["function"])
                entry["releases"] = max(entry["releases"],
                                        slot.get("releases", 0))

    for name, entry in sorted(by_file.items(),
                              key=lambda kv: (-kv[1]["releases"],
                                              -len(kv[1]["cves"]), kv[0])):
        escapes = sorted(entry["escapes"])
        shown = ", ".join(escapes[:6])
        if len(escapes) > 6:
            shown += " +%d more" % (len(escapes) - 6)
        oldest = sorted(entry["cves"])[0]
        tag = "[history %s]" % oldest
        if len(entry["cves"]) > 1:
            tag = "[history %s +%d]" % (oldest, len(entry["cves"]) - 1)
        describe.append(
            "- %s escapes dispatched in %s (%s): %d function(s) patched "
            "across %d release(s), %d CVE(s), signals: %s"
            % (tag, name, shown, len(entry["functions"]), entry["releases"],
               len(entry["cves"]), ", ".join(sorted(entry["signals"]))
               or "none recorded"))

    for klass, entries in sorted(chains.items()):
        depths = sorted(d for d, _ in entries if d is not None)
        tags = sorted({t for _, t in entries})
        seeds.append(
            "- %s allocate %s%s so the commands above are callable at all"
            % (tags[0], klass,
               " (allocation depth %d)" % depths[0] if depths else ""))

    subsystems = doc.get("hotspots", {}).get("by_subsystem", [])[:args.top]
    summary = doc.get("summary", {})

    lines = [
        "# Round-1 worklist: patch history",
        "",
        "Generated by `tools/cve_patch_map.py worklist` from `%s`. "
        "Regenerate it; edits here are overwritten." % _relative(args.map),
        "",
        "Rounds after the first read the worklist refine wrote, which is "
        "derived from that round's own coverage and findings. Round 1 has "
        "neither. These items come from where NVIDIA has actually shipped "
        "kernel-mode fixes, which is the only empirical signal that exists "
        "before a campaign runs. They rank alongside the structural priority "
        "order in `agents/describe.md` step 4 and never replace it: a "
        "function patched five times is a place the vendor found bugs, and it "
        "is not evidence that one remains.",
        "",
        "%d kernel-mode CVE(s) classified, %d resolved to a tag pair, %d "
        "changed function(s) ranked, %d of which reach a named ioctl target."
        % (summary.get("kernel_mode_cves", 0),
           summary.get("resolved_to_tag_pair", 0), len(ranked),
           sum(1 for x in ranked if x.get("targets"))),
        "",
        "## describe",
        "",
    ]
    located = _located_items(doc)
    if located:
        lines.extend([
            "The items below the rule rank by how often a release touched a "
            "function. These first ones rank above them all, because the fix "
            "hunk itself was read and identified. `located` means the hunk is "
            "named with its evidence; `plausible` means the hunk matches the "
            "CWE and the release carries other work the diff cannot separate "
            "from it. Evidence strings are in "
            "`tools/cve_fix_verdicts.json`.",
            "",
        ])
        lines.extend(located)
        lines.extend(["", "---", ""])
    lines.extend(describe or ["- nothing: no patched function resolved to a "
                             "reachable command"])
    lines.extend([
        "",
        "## seeds",
        "",
        "Each item is the object state a control command above needs before "
        "it can be called. A trace that does not build the chain leaves the "
        "command unreachable however well it is modelled.",
        "",
    ])
    lines.extend(seeds or ["- nothing: no reachable target named an "
                          "allocation chain"])
    if out_of_reach:
        lines.extend([
            "",
            "## Outside the tenant surface",
            "",
            "Recorded so a later round does not rediscover them, and so the "
            "report's scope claims stay accurate.",
            "",
        ])
        lines.extend(sorted(set(out_of_reach)))
    lines.extend([
        "",
        "## Subsystems by patched function count",
        "",
        "No single command carries these. They rank where a round should "
        "spend depth once the named items above are modelled.",
        "",
        "| Subsystem | Changed functions |",
        "|---|---|",
    ])
    for row in subsystems:
        lines.append("| %s | %d |" % (row["subsystem"],
                                      row["changed_functions"]))
    text = "\n".join(lines) + "\n"

    out = args.out
    os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, out)
    logger.info("%d describe item(s), %d seeds item(s), %d outside the "
                "tenant surface", len(describe), len(seeds),
                len(set(out_of_reach)))
    print("wrote %s" % repo_path(out))
    return 0


def build_parser():
    ap = argparse.ArgumentParser(
        prog="cve_patch_map.py",
        description="Map kernel-mode CVEs to the release diffs that fixed "
                    "them, and join the changed functions to the ioctl "
                    "surface.")
    ap.add_argument("--src", default=DEFAULT_SRC,
                    help="open-gpu-kernel-modules checkout with release tags "
                         "(default: %s)" % DEFAULT_SRC)
    ap.add_argument("--cves", default=DEFAULT_CVES,
                    help="classified CVE record (default: %s)" % DEFAULT_CVES)
    ap.add_argument("--cache", default=DEFAULT_CACHE,
                    help="PSIRT bulletin markdown cache (default: %s)"
                         % DEFAULT_CACHE)
    ap.add_argument("--include-generated", action="store_true",
                    help="also diff %s, which NVOC regenerates wholesale"
                         % GENERATED_PREFIX)
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log at DEBUG")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("fetch",
                       help="download the bulletin markdown (needs network)")
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("resolve",
                       help="CVE -> fixing version -> bracketing tag pair")
    p.set_defaults(func=cmd_resolve)

    p = sub.add_parser("diff",
                       help="one tag pair, filtered to ioctl-reachable paths")
    p.add_argument("--from", dest="from_tag", required=True, metavar="TAG")
    p.add_argument("--to", dest="to_tag", required=True, metavar="TAG")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("map", help="write the full CVE-to-hotspot join")
    p.add_argument("--out", default=DEFAULT_OUT,
                   help="output JSON (default: %s)" % DEFAULT_OUT)
    p.add_argument("--verdicts", default=DEFAULT_VERDICTS,
                   help="curated per-CVE fix verdicts (default: %s)"
                        % DEFAULT_VERDICTS)
    p.add_argument("--max-scope-files", type=int, default=80,
                   help="ceiling on a release's ioctl-reachable footprint "
                        "for the hotspot ranking (default: 80)")
    p.set_defaults(func=cmd_map)

    p = sub.add_parser("hotspots", help="print the ranking from a map")
    p.add_argument("--map", default=DEFAULT_OUT)
    p.add_argument("--top", type=int, default=30)
    p.set_defaults(func=cmd_hotspots)

    p = sub.add_parser("worklist",
                       help="write the round-1 worklist from patch history")
    p.add_argument("--map", default=DEFAULT_OUT)
    p.add_argument("--out", default=DEFAULT_WORKLIST,
                   help="output markdown (default: %s)" % DEFAULT_WORKLIST)
    p.add_argument("--top", type=int, default=12,
                   help="subsystem rows to carry into the table")
    p.add_argument("--min-releases", type=int, default=1,
                   help="drop functions patched in fewer releases than this")
    p.set_defaults(func=cmd_worklist)
    return ap


def main():
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")
    try:
        return args.func(args)
    except SourceError as exc:
        logger.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
