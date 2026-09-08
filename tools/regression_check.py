#!/usr/bin/env python3
"""Twelve CI checks over the committed surface artefacts.

Each one catches a class of defect that reached the repository unnoticed
because nothing compared two artefacts that have to agree:

    names       every variant named by tools/ioctl_map.json is declared by
                the description set. A trace converted through a name no
                description declares produces a program syz-db rejects, or
                one that runs and attributes to nothing.
    pins        every emitted call whose parameter struct carries a leaf
                selector renders that selector as a const, and a control
                variant's `cmd` renders as the method id the control inventory
                carries for the handler the variant is named for. A control
                variant with a free `cmd`, or an allocation variant with a free
                `hClass`, reaches all 1372 exported commands or all 155
                classes from one description and defeats the per-leaf
                denominator. A control variant pinned to another leaf's method
                id reaches one wrong leaf and reports as one right one.
    coverage    the description set still declares a variant for every one of
                the targets the inventories enumerate.
    derived     rm-chains.json and rm-control-rank.json still account for the
                control inventory command for command, every call name they
                imply is declared, and each artefact still agrees with its own
                record structure: the ranking's order follows from its scores
                and its scores from its components, and a chain still ends on
                the class it targets. Nothing in CI runs the two tools that
                produce them, so a driver bump that moves the inventories
                leaves both stale, and the seeds phase is otherwise the first
                thing to notice, at run time, on the target.
    families    every field bound to a value family carries a family the
                audit in surface/value-families-audit.json accepted, and
                every accepted family is bound to its field with its own set
                emitted. A field bound to the wrong family is worse than a
                bare integer, because the bare integer still reaches its real
                values by mutation and a wrong family never does. The check
                joins the two artefacts through
                value_families.accepted_families, the same door the emitter
                binds through, so the emitted name and the checked name have
                one source. It also reads every flags set the description set
                defines against every one it references, which covers the
                five sets written by hand.
    pages       the generated reference pages under
                docs/src/content/docs/reference/surface/ still match what
                tools/refgen.py produces from the artefacts. The check
                regenerates into a temporary directory and diffs, so it
                catches both a page edited by hand and an artefact
                regenerated without regenerating the pages. A digest stored
                alongside the pages would not: whoever edits the page is
                positioned to update the digest, and the digest of a stale
                page still matches itself.
    stale       every input descriptions/generation.json records still hashes
                to the digest the record carries, and the recorded driver
                version and commit are reported beside them. Five sha256
                values sat in that record with no reader. A surface artefact
                regenerated without regenerating the description set leaves
                the record naming bytes that no longer exist, and every tool
                that reads either one still reports success.
    harnesses   the four Track U target lists still name the same harnesses:
                track_u.targets in config/campaign.yaml, the C_TARGETS array
                in harnesses/run_all.sh, the Harness column in
                harnesses/TARGETS.md, and the directories under harnesses/
                that hold a build.sh. A target added to one and not the others
                is built and never run, or run and never built, and the fuzz
                phase reports the skip as a per-target note hours into a
                campaign. It also reads the index mode of every tracked .sh
                another tracked file invokes with no interpreter in front of
                it. The Track U unit ran /harnesses/run_all.sh as a bare
                container command while the file was mode 100644, so docker
                run exited 126 and systemd retried it to the campaign
                deadline.
    agents      every command line in agents/*.md resolves against the tool it
                names: the file exists, the subcommand is one the tool's
                argparse parser declares, every flag is declared on that
                subparser or on the main parser, a flag takes a value where
                the parser says it does, a literal value sits inside the
                declared choices and parses under the declared type, and an
                exit code the brief states is one the tool can return. Twelve
                phase briefs tell a coding agent which commands to run on a
                metered instance, and a wrong flag stalls the campaign there
                until a human notices, diagnoses and fixes it.
    figures     every surface figure a phase brief or a hand-written page
                states in prose matches what the inventories measure. Three
                stale figures survived every other check: a denominator
                enumeration summing to 828, an exclusion count of 347 and a
                compile verdict of 862 syscalls. `agents` reads the command
                lines out of a brief and checks them against the tool's own
                argparse parser, and nothing read the numbers, while a brief
                is executed by a model that takes them as fact. Three rules
                apply, in order of precision. A retired denominator stated as
                a current one is settled by the history in
                pipeline_state.DENOMINATOR_VERSIONS. A figure the surrounding
                words bind to a quantity is settled by the artefact that
                carries it. A family enumeration is checked by its own sum,
                which is the rule that catches a family added to the surface
                and left out of a brief, because the sum moves even when
                every listed figure is right.
    citations   every file and line number the documentation cites resolves
                in a vendored source tree, and the cited line is not blank.
                A citation reads as evidence, so one naming the wrong line
                sends a reader to unrelated code. Line numbers drift whenever
                a tree is re-vendored, and two had: `nv.c:2412` and
                `nv.c:2439` both pointed at blank lines, and
                `nvc_info.c:515` pointed at the blank line above the function
                it named. artifacts/ is gitignored, so this check settles
                nothing in a clean checkout and reports so. It runs on a
                provisioned machine, which is where the trees exist and where
                re-vendoring moves the numbers.
    commands    every tool invocation a page shows parses against the tool's
                own argparse parser, subcommand and flags alike. `agents`
                does this for the phase briefs, and the documentation is the
                other copy-paste surface: a reader following a stale command
                gets an argparse error, which reads as the tool being broken.
                One page told a reader to run `crash_ctl.py`, a tool that has
                never existed.

Run one, or all twelve:

    python3 tools/regression_check.py names
    python3 tools/regression_check.py pins
    python3 tools/regression_check.py coverage
    python3 tools/regression_check.py derived
    python3 tools/regression_check.py families
    python3 tools/regression_check.py pages
    python3 tools/regression_check.py stale
    python3 tools/regression_check.py harnesses
    python3 tools/regression_check.py agents
    python3 tools/regression_check.py figures
    python3 tools/regression_check.py citations
    python3 tools/regression_check.py commands
    python3 tools/regression_check.py all

`-v` logs what each artefact read contributed, and is accepted on either side
of the subcommand:

    python3 tools/regression_check.py -v derived
    python3 tools/regression_check.py derived -v

`all` runs them in the order above, which is the order the dependency between
them reads in, and the order the CI steps carry. A check registered in CHECKS
and absent from CHECK_ORDER runs last.

Exit codes: 0 when the check passes, 1 when it finds an offending entry, 2
when an artefact the check needs is absent, unreadable, or shaped in a way the
check did not anticipate. CI fails on both non-zero codes. An unexpected
exception is exit 2 as well, and `all` continues with the remaining checks
after one: a traceback out of the process would exit 1, which reads as "an
offending entry was found", and it would hide every verdict after it.

Deliberately no pipeline_state import, for the reason tools/surface_cov.py
gives at its own import block: that module needs fcntl and would stop this
running on a Windows workstation. Everything here reads committed files only,
so it needs no GPU, no kernel and no network.

`agents` and `families` are the two checks that import another tool. `agents`
verifies a command line against that tool's own parser, and `families` joins
the two value-family artefacts through value_families.accepted_families and
never repeats the join. Those imports sit inside the checks
and not at the top of this file, so the other seven still run on a Windows
workstation and `agents` reports the absent fcntl as exit 2 there.
"""
import argparse
import ast
import collections
import hashlib
import importlib
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gspwn_config  # noqa: E402  (path set above so the tool runs from anywhere)
import refgen  # noqa: E402
import surface_cov  # noqa: E402

logger = logging.getLogger("regression_check")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IOCTL_MAP = os.path.join(REPO_ROOT, "tools", "ioctl_map.json")
DESC_DIR = surface_cov.DEFAULT_DESC
CHAINS = os.path.join(surface_cov.SURFACE_DIR, "rm-chains.json")
CTRL_RANK = os.path.join(surface_cov.SURFACE_DIR, "rm-control-rank.json")
PAGES_DIR = refgen.DEFAULT_OUT
PAGES_REMEDY = "python3 tools/refgen.py"
GENERATION = os.path.join(DESC_DIR, "generation.json")
GENERATION_REMEDY = "python3 tools/syzlang_gen.py emit"
VALUE_FAMILIES = os.path.join(surface_cov.SURFACE_DIR, "value-families.json")
VALUE_FAMILIES_AUDIT = os.path.join(surface_cov.SURFACE_DIR,
                                    "value-families-audit.json")
VALUE_FAMILIES_REMEDY = "python3 tools/value_families.py"
CAMPAIGN_CONFIG = os.path.join(REPO_ROOT, "config", "campaign.yaml")
HARNESS_DIR = os.path.join(REPO_ROOT, "harnesses")
RUN_ALL = os.path.join(HARNESS_DIR, "run_all.sh")
TARGETS_DOC = os.path.join(HARNESS_DIR, "TARGETS.md")
AGENTS_DIR = os.path.join(REPO_ROOT, "agents")
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")
# The line separator every committed file in the repository carries, declared
# by .gitattributes. Named so the byte comparison below reads as a comparison
# and not as an escape sequence buried in a split call.
LF = b"\n"

# Each derived artefact, its schema stamp, and the array `derived` reads. Both
# are produced from surface/rm-control-inventory.json, so both go
# stale against the same driver bump.
DERIVED = [
    ("rm-chains.json", CHAINS, "gspwn.rm-chains/1", "chains",
     "tools/object_graph.py chains"),
    ("rm-control-rank.json", CTRL_RANK, "gspwn.rm-control-rank/1", "commands",
     "tools/ctrl_rank.py rank"),
]

# A syzlang call line and the struct its `arg` points at. The description set
# writes both on one line, so one pattern reads the whole call.
CALL_RE = re.compile(r"^ioctl\$([A-Za-z0-9_]+)\((?P<args>[^\n]*)\)\s*$", re.M)
ARG_STRUCT_RE = re.compile(r"\barg\s+ptr\d*\[\w+,\s*([A-Za-z0-9_]+)\s*\]")
STRUCT_OPEN_RE = re.compile(r"^([A-Za-z0-9_]+)\s*\{\s*$")
STRUCT_FIELD_RE = re.compile(r"^\s+([A-Za-z0-9_]+)\s+(.+?)\s*$")

# The two fields that select which driver leaf a call reaches. `cmd` is
# NVOS54_PARAMETERS.cmd on a control call and the inner escape number on an
# XFER wrapper; `hClass` is NVOS64_PARAMETERS.hClass on an allocation.
SELECTORS = ("cmd", "hClass")

# The value inside a pinned rendering, `const[0x00900101, int32]`. A pin the
# check cannot read the value of is reported as a mismatch and never passed
# over, because an unreadable value is the same blind spot as a free field.
CONST_VALUE_RE = re.compile(r"^const\[\s*(0[xX][0-9a-fA-F]+|\d+)\s*[,\]]")

# The families whose selector is compared against a committed authority, as
# (reporting group, field, lookup). A lookup returns {variant name: expected
# integer} and is called once per run.
#
# Two families have such an authority. A control `cmd` is checked against
# rm-control-inventory.json, where every method row pairs the handler symbol
# the variant is named for with the method id. A modeset `cmd` is checked
# against nvkms-command-inventory.json, where the dispatch ordinal is the
# array index itself and needs no name join at all.
#
# Two do not. An allocation `hClass` has no authority in any committed
# artefact: the object graph names the allocation class and carries no number
# for it, and the class id surface_cov.load_targets joins onto an alloc target
# is the owning class's SDK class id, which differs from the allocation class
# number on 17 of the 62 alloc targets that carry one. Comparing against it
# would report those 17 as defects. The XFER inner cmd has no committed
# authority either.
#
# Declared as a list so a third family joins by adding a row. This was one
# hardcoded tuple naming the control prefix, and a second hardcoded branch
# beside it would have left the same gap for the fourth.
# Where a family keeps the selector this check reads. A control or modeset
# selector is a field inside the call's parameter struct. A DRM selector is
# the ioctl request number itself: nvidia-drm gives every command its own
# number, its parameter structs carry no selector field, and two of its
# commands take no parameter at all. A family names which of the two it uses
# so a fourth joins by adding a row, and never by a branch on its name.
SELECTOR_IN_STRUCT = "struct"
SELECTOR_IN_REQUEST = "request"

VALUE_CHECKED = [
    ("control", "cmd", SELECTOR_IN_STRUCT, lambda: control_method_ids()),
    ("modeset", "cmd", SELECTOR_IN_STRUCT, lambda: modeset_ordinals()),
    ("drm", "request", SELECTOR_IN_REQUEST, lambda: drm_request_numbers()),
]

# The _IOC_SIZE field of a request number. drm_ioctl() indexes the driver
# table with _IOC_NR alone and reads _IOC_SIZE only to bound the copy, so the
# size selects no leaf and is masked off both sides of the comparison below.
# The struct sizes themselves are measured by the size probe in
# tools/syzlang_gen.py and checked by the compile gate.
IOC_SIZE_SHIFT = 16
IOC_SIZE_BITS = 14
IOC_SIZE_MASK = ((1 << IOC_SIZE_BITS) - 1) << IOC_SIZE_SHIFT
IOC_DIRECTION_SHIFT = 30

# The DRM direction macros and the _IOC direction bits each expands to.
DRM_DIRECTION_BITS = {
    "DRM_IO": 0, "DRM_IOW": 1, "DRM_IOR": 2, "DRM_IOWR": 3,
}

# The denominator the committed inventories carry, per family, measured on
# driver 610.57.04. `coverage` compares the description set against whatever
# surface_cov.load_targets() returns, so a driver bump that drops targets, or a
# defect in an inventory parser, shrinks both sides together and the comparison
# still reads clean. This floor makes the denominator itself an assertion.
# A bump that legitimately retires a target moves these numbers, and moving
# them is the change to review.
TARGET_FLOOR = {
    "escape": 32,
    "uvm": 39,
    "uvm_tools": 7,
    "control": 531,
    "alloc": 155,
    "modeset": 64,
    "drm": 24,
}

# Variant name prefix -> reporting group. A group with no members at all means
# the emitter stopped producing that family or the parser stopped matching the
# emitted form, and either way the check has gone silent, so `pins` fails on an
# empty group instead of reporting a clean run over nothing.
# Each row is (reporting group, variant name prefix, the surface_cov family
# it reports on, or None where the group is a calling form and not a family).
GROUPS = [
    ("control", "NV_ESC_RM_CONTROL_", "control"),
    ("alloc", "NV_ESC_RM_ALLOC_", "alloc"),
    ("xfer", "NV_ESC_IOCTL_XFER_CMD_", None),
    ("modeset", surface_cov.MODESET_PREFIX, "modeset"),
    ("drm", surface_cov.DRM_PREFIX, "drm"),
]

# Calls whose selector field is free on purpose, keyed by (variant, struct,
# field) so that renaming any of the three retires the entry and the check
# fires again. All four are escape-family targets: surface_cov counts each as
# one target and never decomposes it per leaf, so the field is a fuzzable
# input to a single handler and not a name for another call.
# The (group, field) pairs whose const selector reaches no authority, and why
# no artefact carries one. A selector reaching no authority is compared
# against nothing, and the count of them was reported and left out of the pass
# condition, so the check printed its own blind spot and exited OK.
#
# The allowance is these pairs and not a total. A total fails on a driver bump
# that adds an allocation class, which is a surface change and not a check
# going silent, and it makes the check unusable against any set but the
# committed one. The pair catches what a total exists to catch: a family whose
# authority is removed, or whose selector stops rendering as a const, appears
# under a pair that is not declared, whatever the count does.
#
# Measured over the committed set as it stands, 237 of the 860 selector fields
# examined reach no authority, decomposing as 205 alloc hClass, 31 xfer cmd,
# and the `cmd` of the bare NV_ESC_IOCTL_XFER_CMD multiplexer.
#
# The ledger records 241, being 207 alloc, 31 xfer and 3 outside every group.
# The two figures describe the same tree on two counting bases, and the whole
# of the difference is the four UNPINNED_BY_DESIGN fields below, which render
# `int32` and so never reach the authority lookup at all:
#
#     alloc hClass    207 examined, 205 const, 2 free
#     xfer cmd         31 examined,  31 const, 0 free
#     outside a group   3 examined,   1 const, 2 free
#
# So 237 plus those 4 is 241. Every one of the 207 alloc selector fields is an
# hClass, and the two that fall out are NV_ESC_RM_ALLOC_OBJECT and
# NV_ESC_RM_ALLOC_CONTEXT_DMA2. All three fields outside every group are still
# outside one, and the one reaching the const branch is NV_ESC_IOCTL_XFER_CMD,
# whose own cmd is pinned to the escape number; the other two are
# NV_ESC_CHECK_VERSION_STR and NV_ESC_RM_LOCKLESS_DIAGNOSTIC, both declared
# below. Nothing moved in the grouping.
#
# This is a different quantity from the per-group `unmatched` counter, which
# counts a variant an authority exists for and does not carry, reads 0 for all
# three checked families, and is an offence with no allowance.
PIN_NO_AUTHORITY = {
    ("alloc", "hClass"):
        "the allocation inventory carries a class number per class and no "
        "per-variant record, and the emitter pins hClass from the class map "
        "the same file records, so the two sides have one source and there "
        "is no second artefact to compare against",
    ("xfer", "cmd"):
        "an XFER variant carries the inner escape's own cmd, and the escape "
        "family counts each escape as one target, so no committed artefact "
        "holds a per-leaf authority for the inner value",
    (None, "cmd"):
        "the bare NV_ESC_IOCTL_XFER_CMD multiplexer, whose own cmd is pinned "
        "to the escape number and whose leaves the xfer group decomposes",
}

UNPINNED_BY_DESIGN = {
    ("NV_ESC_CHECK_VERSION_STR", "nv_ioctl_rm_api_version_t", "cmd"):
        "selects the version comparison mode inside one handler",
    ("NV_ESC_RM_LOCKLESS_DIAGNOSTIC", "NV_LOCKLESS_DIAGNOSTIC_PARAMS", "cmd"):
        "selects a diagnostic sub-operation inside one root-only handler",
    ("NV_ESC_RM_ALLOC_OBJECT", "NVOS05_PARAMETERS", "hClass"):
        "the escape is one target; the alloc family decomposes NV_ESC_RM_ALLOC",
    ("NV_ESC_RM_ALLOC_CONTEXT_DMA2", "NVOS39_PARAMETERS", "hClass"):
        "the escape is one target; the alloc family decomposes NV_ESC_RM_ALLOC",
}


# The keys under generated_from that record the driver checkout and not an
# input file. `stale` reports them in its header, so a reader sees which
# checkout the description set was generated from without opening the JSON.
CHECKOUT_KEYS = ("driver_version", "driver_commit")

# The count key an input record carries. tools/syzlang_gen.py names it after
# the array it counted, so the column reads the artefact's own word for a
# record. An input carrying none reports no count.
COUNT_KEYS = ("records", "commands", "entries")

# The four sources that carry the Track U target list, keyed by the name the
# reader uses and labelled by the file and the construct inside it. The label
# is what an offender line names, so a disagreement points at the line to edit
# and not merely at a difference between two lists.
HARNESS_SOURCES = (
    ("config", "config/campaign.yaml track_u.targets"),
    ("run", "harnesses/run_all.sh C_TARGETS"),
    ("doc", "harnesses/TARGETS.md"),
    ("build", "harnesses/<name>/build.sh"),
)

# Directories under harnesses/ that carry no Track U target, and the reason.
# The Go reason is the one config/campaign.yaml already records against
# track_u.targets, so the two texts state one fact. A directory holding no
# build.sh and named nowhere here is reported: the exclusions are the whole of
# what the check accepts as a known absence.
HARNESS_EXCLUSIONS = {
    "common":
        "a shared helper tree. It holds build_common.sh, which every harness "
        "build.sh sources, and builds no target of its own",
    "go_cudacompat_elf":
        "go test -fuzz writes no fuzzer_stats, so it produces no coverage "
        "output for the sampler to read",
}

HARNESS_SOURCE_KEYS = ("config", "run", "doc", "build")

# The sources each exclusion is dropped from, and what makes that its whole
# scope. An exclusion covers the sources its reason accounts for and no
# others, so a name absent from one source by design is still compared against
# the sources that do carry it.
#
# go_cudacompat_elf was dropped from all four while its reason accounts for
# two. It has a build.sh and a TARGETS.md row and is named by neither
# config/campaign.yaml nor run_all.sh, so the blanket drop compared the
# built-and-never-run shape this check exists to report against nothing.
#
# A name in HARNESS_EXCLUSIONS with no entry here raises, because defaulting
# it to all four sources is the defect this mapping was added to close.
HARNESS_EXCLUSION_SOURCES = {
    "common": (
        HARNESS_SOURCE_KEYS,
        "it names no target in any of the four, and holds no build.sh"),
    "go_cudacompat_elf": (
        ("config", "run"),
        "the fuzz phase reads config/campaign.yaml for the targets it samples "
        "coverage from, and run_all.sh iterates C_TARGETS, which is the C "
        "array. A Go fuzz target runs under `go test -fuzz` and is in "
        "neither. Its build.sh and its TARGETS.md row are still compared"),
}

# A shell script named as a command with no interpreter in front of it runs
# only when its index mode carries the execute bit. tools/campaign_ctl.py's
# Track U unit ran /harnesses/run_all.sh that way while every tracked .sh was
# mode 100644, so `docker run` exited 126, Restart=always with RestartSec=30
# retried to the campaign deadline, and the track produced nothing. The unit
# now names /bin/bash and the eleven executed scripts are 100755; this holds
# the pairing, because a mode is lost silently by any tool that rewrites a
# file without preserving it.
SCRIPT_MODE = "100755"

# Files that can execute a command. A Markdown page naming a script at the
# start of a line is citing it, not running it, so prose is not read here.
SCRIPT_CALLER_SUFFIXES = (".sh", ".py")

# The bash array run_all.sh iterates. Anchored on the opening and closing
# lines so a later array in the same file cannot be read in its place.
C_TARGETS_RE = re.compile(r"^C_TARGETS=\(\s*$(?P<body>.*?)^\)\s*$",
                          re.M | re.S)

# A markdown table row, and the cells it holds. TARGETS.md writes every
# harness name in a column headed Harness.
HARNESS_COLUMN = "Harness"
TABLE_RULE = set("-: ")


# A flags set definition sits at column zero and its members follow an equals
# sign. Anchored on the start of a line so a `name = ` inside a comment or
# inside a struct body cannot read as one.
FLAGS_DEFINE_RE = re.compile(r"^([a-z_][a-z0-9_]*)\s*=\s*\S", re.M)

# A reference to a set, from a struct field or from a syscall argument.
FLAGS_REFERENCE_RE = re.compile(r"flags\[([A-Za-z_]\w*)")

# One rendered field, when that field is bound to a set. The width is captured
# so a report can state it.
FLAGS_FIELD_RE = re.compile(r"^flags\[([A-Za-z_]\w*),\s*(int\d+)\]$")


class CheckInput(Exception):
    """An artefact the check reads is absent or does not parse."""


def _description_files():
    files = surface_cov._files(DESC_DIR, (".txt",))
    if not files:
        raise CheckInput(
            "no .txt description files under %s. The description set is a "
            "committed artefact; a checkout missing it cannot run this check. "
            "Regenerate with tools/syzlang_gen.py emit against a driver source "
            "checkout, or restore the committed files." % DESC_DIR)
    return files


def parse_structs(text):
    """-> {struct name: {field name: rendered type}} over one syzlang file."""
    structs = {}
    current = None
    for line in text.splitlines():
        opened = STRUCT_OPEN_RE.match(line)
        if opened:
            current = {}
            structs[opened.group(1)] = current
            continue
        if line.startswith("}"):
            current = None
            continue
        if current is not None:
            field = STRUCT_FIELD_RE.match(line)
            if field:
                current[field.group(1)] = field.group(2)
    return structs


def parse_calls(text):
    """-> {variant name: struct its arg points at, or None}."""
    calls = {}
    for match in CALL_RE.finditer(text):
        pointee = ARG_STRUCT_RE.search(match.group("args"))
        calls[match.group(1)] = pointee.group(1) if pointee else None
    return calls


def read_descriptions():
    """-> (calls, structs) merged over every committed description file.

    A name declared in two files raises. The merge was a dict.update per file,
    so the last file read won and nothing reported the loss: every check above
    then compared the surviving declaration while the emitted set carried two,
    and syzkaller reads the package as one namespace where a redeclaration is
    its own error. Raising here names both files and the name.
    """
    calls, structs = {}, {}
    origin = {}
    files = _description_files()
    for path in files:
        name = os.path.basename(path)
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for kind, parsed, into in (("struct", parse_structs(text), structs),
                                   ("call", parse_calls(text), calls)):
            for key, value in parsed.items():
                first = origin.get((kind, key))
                if first is not None:
                    raise CheckInput(
                        "the description set declares the %s %s in both %s "
                        "and %s. syzlang resolves the package as one "
                        "namespace, so one declaration wins and every check "
                        "here reads that one while the set carries two."
                        % (kind, key, first, name))
                origin[(kind, key)] = name
                into[key] = value
    logger.info("descriptions: %d file(s), %d call(s), %d struct(s)",
                len(files), len(calls), len(structs))
    return calls, structs


REQUEST_ARG_RE = re.compile(r"\bcmd\s+(const\[[^\]]*\])")


def parse_call_requests(text):
    """-> {variant name: the rendering of its ioctl request argument}."""
    requests = {}
    for match in CALL_RE.finditer(text):
        rendered = REQUEST_ARG_RE.search(match.group("args"))
        if rendered:
            requests[match.group(1)] = rendered.group(1)
    return requests


def read_call_requests():
    """-> the request argument of every call, over the committed set.

    Read apart from read_descriptions so that adding a request-selector
    family changes neither its shape nor any of its callers.
    """
    requests = {}
    for path in _description_files():
        with open(path, encoding="utf-8") as handle:
            requests.update(parse_call_requests(handle.read()))
    return requests


def read_ioctl_map():
    """-> [(request number, variant name)] from the committed map."""
    try:
        with open(IOCTL_MAP, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError) as exc:
        raise CheckInput("%s: %s" % (IOCTL_MAP, exc))
    entries, malformed = [], []
    for key, value in raw.items():
        if key.startswith("comment"):
            continue
        if not isinstance(value, str) or not value.startswith("ioctl$"):
            malformed.append((key, value))
            continue
        entries.append((key, value[len("ioctl$"):]))
    if malformed:
        raise CheckInput(
            "%s holds %d entry value(s) that are not a syzlang call name: %s"
            % (IOCTL_MAP, len(malformed),
               ", ".join("%s=%r" % pair for pair in sorted(malformed))))
    return sorted(entries)


def check_names():
    """Every name in tools/ioctl_map.json is declared by the descriptions, and
    every request number it is keyed on is the one that call renders."""
    entries = read_ioctl_map()
    calls, _structs = read_descriptions()
    requests = read_call_requests()
    declared = set(calls)

    offenders = [(key, name) for key, name in entries if name not in declared]

    # The key half of the same entry. read_call_requests() holds the request
    # number each call renders, so the map is checkable in both directions and
    # was checked in one: a single edited digit in a key left all twelve
    # checks green and made trace2seed.py convert that request to another
    # variant. Compared as whole request numbers, _IOC_SIZE included, because
    # trace2seed.py keys on the number the trace carries and nothing masks it.
    keyed, mismatched = 0, []
    for key, name in entries:
        if name not in declared:
            continue
        rendered = requests.get(name)
        if rendered is None:
            mismatched.append((key, name, "the description set declares this "
                                          "call and renders no request "
                                          "number for it"))
            continue
        value = const_value(rendered)
        try:
            stated = int(key, 0)
        except ValueError:
            mismatched.append((key, name, "the map key does not read as a "
                                          "request number"))
            continue
        if value is None:
            mismatched.append((key, name, "the call renders its request as "
                                          "%s, which is not a const"
                               % rendered))
        elif value != stated:
            mismatched.append((key, name, "the call renders request "
                                          "0x%08x" % value))
        else:
            keyed += 1

    print("names: %d map entry/entries over %d distinct name(s), %d declared "
          "call(s) in the description set"
          % (len(entries), len({n for _k, n in entries}), len(declared)))
    print("names: %d entry/entries keyed on the request number their call "
          "renders" % keyed)
    if not offenders and not mismatched:
        print("names: OK")
        return 0

    for key, name, why in mismatched:
        print("names: %s is mapped to %s and %s" % (key, name, why))
    if mismatched:
        print()
        print("tools/trace2seed.py picks the call name by the request number "
              "a trace carries. A key that is not the number its own call "
              "renders converts that request to another variant, and every "
              "later measurement joins on the name.")
        print()
    if not offenders:
        return 1

    print("names: %d entry/entries name a call no description declares"
          % len(offenders))
    print()
    print("  %-12s %s" % ("request", "variant"))
    print("  %-12s %s" % ("-" * 12, "-" * 40))
    for key, name in offenders:
        note = ""
        if name in surface_cov.MULTIPLEXERS:
            note = ("  <- a multiplexer; its leaves are counted in the %s "
                    "family" % ("control" if name.endswith("CONTROL")
                                else "alloc"))
        print("  %-12s %s%s" % (key, name, note))
    print()
    print("tools/trace2seed.py reads this map to name the call a traced "
          "request becomes. A name no description declares produces a program "
          "syz-db rejects, or one that runs and attributes to no target.")
    print("Fix the map, not this check.")
    return 1


def const_value(rendered):
    """-> the integer inside a `const[...]` rendering, or None."""
    match = CONST_VALUE_RE.match(rendered)
    return int(match.group(1), 0) if match else None


def _group_of(variant):
    """-> the reporting group a variant name falls in, or None."""
    for group, prefix, _family in GROUPS:
        if variant.startswith(prefix):
            return group
    return None


def control_method_ids():
    """-> {control variant name: the method id the inventory carries}.

    The join key is the handler symbol, which is what both the inventory row
    and the variant name are built from. Both the targetable commands and the
    excluded ones are read: a control_gsp command is still declared by the
    description set and its pinned cmd still has to be the right one.
    """
    try:
        targets, excluded, _meta = surface_cov.load_targets()
    except surface_cov.SurfaceError as exc:
        raise CheckInput(str(exc))
    ids = {}
    for record in list(excluded.values()) + list(targets.values()):
        if not record["variant"].startswith(surface_cov.CONTROL_PREFIX):
            continue
        method_id = record.get("method_id")
        if method_id:
            ids[record["variant"]] = method_id
    return ids


def modeset_ordinals():
    """-> {modeset variant name: the dispatch ordinal the inventory carries}.

    No join is needed. The ordinal is the index into the dispatch array that
    nvKmsIoctl reads NvKmsIoctlParams.cmd as, and the variant is named for the
    enumeration constant sitting at that index.
    """
    try:
        targets, excluded, _meta = surface_cov.load_targets()
    except surface_cov.SurfaceError as exc:
        raise CheckInput(str(exc))
    ordinals = {}
    for record in list(excluded.values()) + list(targets.values()):
        if not record["variant"].startswith(surface_cov.MODESET_PREFIX):
            continue
        if record.get("nr") is not None:
            ordinals[record["variant"]] = record["nr"]
    return ordinals


def drm_request_numbers():
    """-> {drm variant name: the request number its inventory row implies}.

    Built from the command number and the direction macro the inventory
    carries, over the ioctl and command bases the same artefact records, so
    the bases are read once and never restated here. The _IOC_SIZE field is
    left out, because drm_ioctl() dispatches on _IOC_NR and the size selects
    no leaf.
    """
    try:
        with open(surface_cov.DRM_INV, encoding="utf-8") as handle:
            inventory = json.load(handle)
    except (OSError, ValueError) as exc:
        raise CheckInput("%s: %s" % (surface_cov.DRM_INV, exc))
    scan = inventory.get("scan") or {}
    ioctl_base = scan.get("ioctl_base")
    command_base = scan.get("command_base")
    if not isinstance(ioctl_base, int) or not isinstance(command_base, int):
        raise CheckInput(
            "%s records no integer ioctl_base and command_base, so the "
            "request number a DRM variant should carry cannot be derived."
            % surface_cov.DRM_INV)
    numbers = {}
    for command in inventory.get("commands") or []:
        if not command.get("dispatched"):
            continue
        direction = DRM_DIRECTION_BITS.get(command.get("direction"))
        name = command.get("number_macro")
        if direction is None or not name:
            continue
        numbers[name] = ((direction << IOC_DIRECTION_SHIFT)
                         | (ioctl_base << 8)
                         | (command_base + command["nr"]))
    return numbers


def check_pins():
    """Every emitted leaf selector renders as a const, and a checked family's
    cmd renders as the value its own inventory carries for that variant."""
    calls, structs = read_descriptions()
    # (group, field) -> {variant: expected}. Read once, so a family whose
    # authority is unreadable fails the check and never passes it silently.
    expected_by = {(group, field): lookup()
                   for group, field, _location, lookup in VALUE_CHECKED}
    # Families whose selector is the request number. The struct loop below
    # cannot see them and the request loop after it examines them instead.
    request_groups = {group for group, _f, location, _l in VALUE_CHECKED
                      if location == SELECTOR_IN_REQUEST}
    request_field = {group: field for group, field, location, _l
                     in VALUE_CHECKED if location == SELECTOR_IN_REQUEST}

    examined, free = 0, []
    group_counts = {name: 0 for name, _p, _f in GROUPS}
    used_allowlist = set()
    unresolved, wrong = [], []
    unmatched = {group: 0 for group, _f, _loc, _l in VALUE_CHECKED}
    values = {group: {} for group, _f, _loc, _l in VALUE_CHECKED}
    # A const-rendered selector whose (group, field) no VALUE_CHECKED row
    # covers, so nothing compares it against anything.
    unauthored = []
    # (pinned cmd value, the resource hObject renders as) over the control
    # group. The driver exports one command number from three owning classes,
    # so the cmd value alone is not unique and requiring it to be would refuse
    # the real surface. The pair is what names one leaf.
    control_pairs = {}
    for variant in sorted(calls):
        struct = calls[variant]
        fields = structs.get(struct)
        if not fields:
            # No field of this call is examined at all, so the call is
            # invisible to the rest of the check. Inside a decomposed family
            # that is the check going silent one call at a time, and the
            # empty-group guard below only fires once a whole family reaches
            # zero. A change to the emitted `arg ptr[...]` form does exactly
            # this, which is why the count is reported and a group member is
            # an offender.
            # A request-selector family keeps nothing in the struct, and
            # two DRM commands take no parameter at all, so an absent struct
            # is the shape those calls are meant to have.
            if _group_of(variant) not in request_groups:
                unresolved.append((variant, struct, _group_of(variant)))
            continue
        for field in SELECTORS:
            if field not in fields:
                continue
            examined += 1
            group = _group_of(variant)
            if group:
                group_counts[group] += 1
            rendered = fields[field]
            if rendered.startswith("const["):
                authority = expected_by.get((group, field))
                if authority is None:
                    unauthored.append((variant, struct, field, group))
                else:
                    value = const_value(rendered)
                    values[group].setdefault(value, []).append(variant)
                    expected = authority.get(variant)
                    if expected is None:
                        unmatched[group] += 1
                    elif value is None or value != (
                            expected if isinstance(expected, int)
                            else int(expected, 0)):
                        wrong.append((variant, struct, rendered, expected))
                if group == "control" and field == "cmd":
                    # A struct declaring no hObject contributes None, which
                    # collides with any other such variant. That is the same
                    # defect the pair exists to report: two control variants
                    # the emitted set gives no way to tell apart.
                    control_pairs.setdefault(
                        (const_value(rendered), fields.get("hObject")), []
                    ).append(variant)
                continue
            key = (variant, struct, field)
            if key in UNPINNED_BY_DESIGN:
                used_allowlist.add(key)
                continue
            free.append((variant, struct, field, rendered))

    # The request-number selector, for the families that keep it there. The
    # value is compared with _IOC_SIZE masked off on both sides, because
    # drm_ioctl() reads _IOC_NR to pick a handler and the size only bounds the
    # copy that follows.
    for variant, rendered in sorted(read_call_requests().items()):
        group = _group_of(variant)
        if group not in request_groups:
            continue
        field = request_field[group]
        examined += 1
        group_counts[group] += 1
        authority = expected_by.get((group, field))
        if authority is None:
            unauthored.append((variant, "(request)", field, group))
            continue
        value = const_value(rendered)
        if value is not None:
            value &= ~IOC_SIZE_MASK
        values[group].setdefault(value, []).append(variant)
        expected = authority.get(variant)
        if expected is None:
            unmatched[group] += 1
        elif value is None or value != expected:
            wrong.append((variant, "(request)", rendered,
                          "0x%08x" % expected))

    # An allowlist entry whose call is present and now renders const has been
    # fixed and the entry has to go, or it would mask a later regression on the
    # same field. An entry whose call is absent says nothing: the check also
    # runs against a partial set in the tests.
    stale = sorted(key for key in UNPINNED_BY_DESIGN
                   if key not in used_allowlist
                   and calls.get(key[0]) == key[1]
                   and structs.get(key[1], {}).get(key[2], "")
                   .startswith("const["))
    empty = sorted(name for name, count in group_counts.items() if not count)
    blind = sorted(row for row in unresolved if row[2])
    colliding = sorted((pair, names) for pair, names in control_pairs.items()
                       if len(names) > 1)

    grouped = sum(group_counts.values())
    print("pins: %d selector field(s) examined across %d call(s) (%s, "
          "outside every group %d)"
          % (examined, len(calls),
             ", ".join("%s %d" % (name, group_counts[name])
                       for name, _p, _f in GROUPS), examined - grouped))
    for group, field, _location, _lookup in VALUE_CHECKED:
        seen = values[group]
        print("pins: %d %s %s(s) checked against the inventory over %d "
              "distinct value(s), %d call(s) the inventory does not carry"
              % (sum(len(v) for v in seen.values()), group, field, len(seen),
                 unmatched[group]))
    print("pins: %d call(s) whose arg resolves to no declared struct, %d of "
          "them inside a reported group" % (len(unresolved), len(blind)))
    undeclared = sorted({(row[3], row[2]) for row in unauthored}
                        - set(PIN_NO_AUTHORITY))
    by_pair = collections.Counter((row[3], row[2]) for row in unauthored)
    print("pins: %d const selector(s) reach no authority over %d declared "
          "pair(s) (%s)"
          % (len(unauthored), len(PIN_NO_AUTHORITY),
             ", ".join("%s %s %d" % (group or "outside every group", field,
                                     count)
                       for (group, field), count in sorted(
                           by_pair.items(), key=lambda kv: str(kv[0])))
             or "none"))
    print("pins: %d control command(s) over %d distinct (cmd, hObject) "
          "pair(s)" % (sum(len(n) for n in control_pairs.values()),
                       len(control_pairs)))

    # unmatched is an offence, not a report. It counts a variant the group's
    # own authority does not carry, so that variant's selector is compared
    # against nothing.
    #
    # `coverage` does not already cover it. Measured: `coverage` compares
    # targets against declared variants in one direction only, at :1023, and
    # the reverse at :1065 is printed as a count of declared variants outside
    # the denominator and is never an offence. A control variant added to the
    # description set under a handler the control inventory does not carry
    # leaves `coverage` at exit 0, reporting 82 such variants where it had
    # reported 81, while this counter reads 1.
    carried_unmatched = sum(unmatched.values())
    if (not free and not stale and not empty and not wrong and not blind
            and not colliding and not undeclared and not carried_unmatched):
        print("pins: OK, %d field(s) unpinned by design"
              % len(UNPINNED_BY_DESIGN))
        return 0

    for (value, handle), names in colliding:
        print("pins: %d control variants pin cmd 0x%08x and render hObject as "
              "%s, so the pair names no single leaf: %s"
              % (len(names), value, handle, ", ".join(sorted(names))))
        print("    The driver exports one command number from several owning "
              "classes, so the cmd value alone is not unique. The resource "
              "hObject renders as is what separates them, and it is typed "
              "from the owning class in tools/syzlang_gen.py. Variants "
              "colliding on both halves render byte-identical and all but "
              "one reach a handler they are not named for.")
        print()
    for group, count in sorted(unmatched.items()):
        if not count:
            continue
        print("pins: the %s authority does not carry %d of the variant(s) it "
              "was read for, so those selectors are compared against nothing"
              % (group, count))
        print("    A variant the inventory has no row for is a name the "
              "emitted set carries and the surface artefacts do not. "
              "`coverage` reports it as a declared variant outside the "
              "denominator and passes, so this is the check that fails on "
              "it. Regenerate the description set against the same "
              "inventories, or restore the inventory row.")
        print()
    for group, field in undeclared:
        print("pins: %d %s %s selector(s) render const and reach no "
              "authority, and PIN_NO_AUTHORITY declares no such pair"
              % (by_pair[(group, field)], group or "outside every group",
                 field))
        print("    A selector reaching no authority is compared against "
              "nothing, so the family it belongs to is counted and never "
              "checked. Either VALUE_CHECKED lost the row that carries its "
              "authority, or a new family renders a selector no artefact "
              "settles. Restore the authority, or declare the pair in "
              "PIN_NO_AUTHORITY with the reason no artefact carries one.")
        print()
    if wrong:
        print("pins: %d selector(s) pinned to a value their own inventory "
              "does not carry for that variant" % len(wrong))
        print()
        print("  %-46s %-34s %-24s %s"
              % ("variant", "struct", "rendered as", "inventory value"))
        print("  %-46s %-34s %-24s %s"
              % ("-" * 46, "-" * 34, "-" * 24, "-" * 19))
        for variant, struct, rendered, expected in wrong:
            print("  %-46s %-34s %-24s %s"
                  % (variant, struct, rendered, expected))
        print()
        print("A pinned selector carrying the wrong constant reaches another "
              "leaf than the one the variant is named for, and every later "
              "measurement joins on the name. Regenerate the description set "
              "with tools/syzlang_gen.py emit against the same checkout the "
              "inventories were built from.")
    for variant, struct, group in blind:
        print("pins: %s is in the %s group and its arg resolves to %r, which "
              "no description declares as a struct. No field of it is "
              "examined, so this check is silent about it."
              % (variant, group, struct))
    if free:
        print("pins: %d selector field(s) render free" % len(free))
        print()
        print("  %-46s %-34s %-8s %s"
              % ("variant", "struct", "field", "rendered as"))
        print("  %-46s %-34s %-8s %s"
              % ("-" * 46, "-" * 34, "-" * 8, "-" * 12))
        for variant, struct, field, rendered in free:
            print("  %-46s %-34s %-8s %s"
                  % (variant, struct, field, rendered))
        print()
        print("A free selector lets one description reach every leaf behind "
              "its multiplexer, which is the hole the per-leaf denominator "
              "exists to close. tools/syzlang_gen.py carries require_pinned() "
              "for the same rule at emission; this check covers a set edited "
              "after generation.")
    for variant, struct, field in stale:
        print("pins: %s.%s on %s is pinned now, so its UNPINNED_BY_DESIGN "
              "entry is stale. Remove it." % (struct, field, variant))
    for group in empty:
        print("pins: the %s group holds no call at all. Either the emitter "
              "stopped producing that family or the parser no longer matches "
              "the emitted form, and either way this check has gone silent."
              % group)
    return 1


def check_coverage():
    """The description set declares a variant for every enumerated target, and
    no family's target count has fallen below TARGET_FLOOR."""
    try:
        targets, excluded, meta = surface_cov.load_targets()
    except surface_cov.SurfaceError as exc:
        raise CheckInput(str(exc))
    modelled = set(surface_cov.scan_variants(_description_files(),
                                             "descriptions"))

    rows, missing, shrunk = [], [], []
    for family in surface_cov.FAMILIES:
        names = sorted(n for n, r in targets.items() if r["family"] == family)
        gap = [n for n in names if n not in modelled]
        missing.extend((family, n) for n in gap)
        rows.append((family, len(names), len(names) - len(gap), len(gap)))
        floor = TARGET_FLOOR.get(family)
        if floor is not None and len(names) < floor:
            shrunk.append((family, len(names), floor))

    total = len(targets)
    print("coverage: driver %s, %d targetable across %d families, %d modelled"
          % (meta.get("driver_version") or "unknown", total,
             len(surface_cov.FAMILIES), total - len(missing)))
    print()
    print("  %-12s %10s %10s %8s"
          % ("family", "targetable", "modelled", "gap"))
    print("  %-12s %10s %10s %8s"
          % ("-" * 12, "-" * 10, "-" * 10, "-" * 8))
    for family, targetable, covered, gap in rows:
        print("  %-12s %10d %10d %8d" % (family, targetable, covered, gap))
    print()

    # The entry points the driver registers on the modelled nodes, counted
    # apart from the command denominator above. A driver release that adds an
    # mmap or a poll to one of those tables fails here rather than leaving an
    # entry point with no description and nothing to say so.
    try:
        surface_cov.assert_outside_denominator(targets)
        ep_modelled, ep_registered, ep_tables = surface_cov.load_entry_points()
        ep_expected = surface_cov.entry_point_calls(ep_tables)
    except surface_cov.SurfaceError as exc:
        raise CheckInput(str(exc))
    ep_declared = set(surface_cov.scan_call_names(_description_files()))
    ep_missing = sorted(ep_expected - ep_declared)
    print("coverage: %d entry point(s) on the %d device node(s) whose entry "
          "points are modelled, of %d the driver registers in total. Counted "
          "apart from the command denominator above and never inside it. "
          "/dev/nvidia-modeset is opened for the modeset command family and "
          "its own mmap and poll are not modelled."
          % (ep_modelled, sum(len(t.get("paths") or []) for t in ep_tables),
             ep_registered))
    print("coverage: %d entry-point call(s) required, %d declared"
          % (len(ep_expected), len(ep_expected) - len(ep_missing)))

    extra = sorted(n for n in modelled
                   if n not in targets and n not in excluded)
    print("coverage: %d declared variant(s) outside the denominator "
          "(alternate calling forms and wrapper routes to counted targets)"
          % len(extra))
    print("coverage: denominator floor %d target(s) across %d family/families"
          % (sum(TARGET_FLOOR.values()), len(TARGET_FLOOR)))

    if not missing and not shrunk and not ep_missing:
        print("coverage: OK")
        return 0

    for name in ep_missing:
        print("coverage: the driver registers an entry point the description "
              "set does not declare: %s. Either a file_operations table "
              "gained a member, or the emitter stopped writing the call."
              % name)
    if ep_missing:
        print()

    for family, counted, floor in shrunk:
        print("coverage: the %s family enumerates %d target(s) against a "
              "floor of %d. The denominator shrank, so this check compares "
              "the description set against fewer targets than the release it "
              "was written for carried, and a gap opened by the missing "
              "targets does not appear above. Either an inventory was "
              "regenerated from a partial checkout, or the driver retired "
              "them and TARGET_FLOOR is the record to move."
              % (family, counted, floor))
    if shrunk:
        print()
    if not missing:
        return 1

    print("coverage: %d target(s) the description set no longer declares"
          % len(missing))
    print()
    shown = missing[:40]
    for family, name in shown:
        print("  %-12s %s" % (family, name))
    if len(missing) > len(shown):
        print("  ... and %d more" % (len(missing) - len(shown)))
    print()
    print("The denominator comes from the inventories under surface "
          "and the numerator from descriptions. A gap means the "
          "describe phase lost a target, or the two were generated from "
          "different driver checkouts.")
    return 1


def _load_derived(label, path, schema, array, remedy):
    """-> one derived artefact, refusing every shape the check cannot read.

    A wrong shape is exit 2 and not exit 1: the check has no opinion to
    report about a file it could not parse as the thing it claims to be.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
    except (OSError, ValueError) as exc:
        raise CheckInput("%s: %s. Produce it with `%s`." % (path, exc, remedy))
    if not isinstance(doc, dict):
        raise CheckInput("%s is not a JSON object, so it is not %s. Produce "
                         "it with `%s`." % (path, label, remedy))
    stamp = doc.get("schema")
    if stamp != schema:
        raise CheckInput(
            "%s carries schema %r and this check reads %r. Either the "
            "producer's format moved and this check has to move with it, or "
            "the path names a different artefact. Produce it with `%s`."
            % (path, stamp, schema, remedy))
    records = doc.get(array)
    if not isinstance(records, list) or not records:
        raise CheckInput(
            "%s carries no `%s` array with anything in it. A run over an "
            "empty artefact reads as a clean run and reports nothing, so it "
            "is refused. Produce it with `%s`." % (path, array, remedy))
    return doc


def _record_field(path, where, record, field):
    """One field of one record, or exit 2 naming where the record sits.

    `where` locates the record holding the field and not only the enclosing
    array entry, so a step inside a chain reports as `chains[7].chain[2]` and
    a reader knows which element to open.
    """
    if not isinstance(record, dict) or field not in record:
        raise CheckInput("%s: %s carries no `%s`, so the check cannot read it."
                         % (path, where, field))
    return record[field]


def _record_name(path, where, record, field):
    """One field that has to be a string, because a call name is built from
    it. A producer that normalises the field to an object would otherwise
    reach the concatenation below and raise a TypeError."""
    value = _record_field(path, where, record, field)
    if not isinstance(value, str):
        raise CheckInput(
            "%s: %s carries `%s` as %s and this check builds a call name from "
            "it, which needs a string." % (path, where, field,
                                           type(value).__name__))
    return value


def chains_implies(doc, path):
    """-> (call names the chain artefact implies, control variants it accounts
    for).

    The names are the ones tools/trace2seed.py chains emits: one allocation
    variant per chain step and one control variant per command. The account is
    every command the artefact places, whether under a chain or under the
    unresolved block, which is the set the control inventory has to match.
    """
    implied, accounted = set(), set()
    for index, record in enumerate(doc["chains"]):
        at = "chains[%d]" % index
        for step_index, step in enumerate(
                _record_field(path, at, record, "chain") or []):
            implied.add(surface_cov.ALLOC_PREFIX + _record_name(
                path, "%s.chain[%d]" % (at, step_index), step,
                "external_class"))
        for command_index, command in enumerate(
                _record_field(path, at, record, "commands") or []):
            handler = _record_name(path, "%s.commands[%d]"
                                   % (at, command_index), command, "handler")
            implied.add(surface_cov.CONTROL_PREFIX + handler)
            accounted.add(surface_cov.CONTROL_PREFIX + handler)
    unresolved = doc.get("unresolved_owning_classes")
    if not isinstance(unresolved, list):
        raise CheckInput(
            "%s carries no `unresolved_owning_classes` array. The commands of "
            "an owning class with no RS_ENTRY row appear under no chain "
            "record at all, so without that block the account silently loses "
            "them." % path)
    for index, row in enumerate(unresolved):
        at = "unresolved_owning_classes[%d]" % index
        commands = _record_field(path, at, row, "commands")
        if not isinstance(commands, list):
            raise CheckInput("%s: %s carries `commands` as %s, and this check "
                             "reads a list of handler names."
                             % (path, at, type(commands).__name__))
        for command_index, handler in enumerate(commands):
            if not isinstance(handler, str):
                raise CheckInput(
                    "%s: %s.commands[%d] is %s and this check builds a call "
                    "name from it, which needs a string."
                    % (path, at, command_index, type(handler).__name__))
            accounted.add(surface_cov.CONTROL_PREFIX + handler)
    return implied, accounted


def rank_implies(doc, path):
    """-> (call names the ranking implies, control variants it accounts for)."""
    implied, accounted = set(), set()
    for index, command in enumerate(doc["commands"]):
        handler = _record_name(path, "commands[%d]" % index, command,
                               "handler")
        implied.add(surface_cov.CONTROL_PREFIX + handler)
        accounted.add(surface_cov.CONTROL_PREFIX + handler)
    return implied, accounted


# How far a stored rank_score may sit from the weighted sum of its own
# components. tools/ctrl_rank.py rounds each component to six decimal places
# and rounds the score again, so 33 of the 531 committed records land one unit
# in the last place away from a sum computed here.
SCORE_TOLERANCE = 1.5e-6


def _partial_fields(path, array, records, fields):
    """-> [problem] for a field some records carry and others do not.

    Each restatement below is read only when the artefact carries it, so a
    producer whose schema predates one is compared on the command set alone
    and nothing here is silent about a field it did see. A field present on
    part of an array is the case that would otherwise pass unnoticed, so it is
    reported here and the field is then read on the records that carry it.
    """
    problems = []
    for field in fields:
        carried = [i for i, r in enumerate(records)
                   if isinstance(r, dict) and field in r]
        if carried and len(carried) != len(records):
            problems.append(
                "%s carries `%s` on %d of %d record(s), so it is neither a "
                "field of this artefact nor absent from it"
                % (array, field, len(carried), len(records)))
    return problems


def _carried(records, field):
    """Is field on every record of a non-empty array?"""
    return bool(records) and all(isinstance(r, dict) and field in r
                                 for r in records)


# The restatements each derived artefact carries beside its command set, and
# the array they sit on. Read by the auditor that compares them and by the
# summary line that reports how many of them were compared at all, so the two
# cannot disagree about what the check is meant to be reading.
RANK_RESTATEMENTS = ("rank", "rank_score", "rank_components",
                     "no_chain_reason")
CHAIN_RESTATEMENTS = ("chain", "chain_length", "target_external_class",
                      "command_count")
RESTATEMENTS = {
    "rm-chains.json": ("chains", CHAIN_RESTATEMENTS),
    "rm-control-rank.json": ("commands", RANK_RESTATEMENTS),
}


def _uncompared_fields(records, fields):
    """-> the fields no record of the array carries, in the caller's order.

    Every assertion in rank_consistency and chains_consistency is gated on the
    field being present, so a field absent from every record is read by
    nothing. That degrades the check from strong to weak: the command set is
    still compared, so it does not go vacuous, and the degradation is silent,
    which is the defect. The callers report this on every run.
    """
    if not records:
        return []
    return [field for field in fields
            if not any(isinstance(r, dict) and field in r for r in records)]


def _pinned_artefact(path, reference):
    """Is `path` the committed artefact rather than a caller's own file?

    The strong assertion runs against the real tree and the tolerance holds
    everywhere else, the way nvkms_inventory.py:352 gates its macro-split
    assertion on pinned_checkout. A fixture and a producer whose schema
    predates a field both still pass on the command set alone, which is what
    _partial_fields documents; the committed artefact has to carry every
    field it carries today.
    """
    try:
        return os.path.samefile(path, reference)
    except OSError:
        return False


def _absent_fields(path, array, records, fields, reference):
    """-> [problem] for a field the committed artefact carries and this one
    does not.

    The field set is read from `reference`, the committed artefact, rather
    than restated here, so a field added to the producer later is picked up
    without editing this check. Measured over the committed artefacts today:
    all four ranked fields over 531 commands, all four chain fields over 98
    records.
    """
    if not _pinned_artefact(path, reference):
        return []
    missing = _uncompared_fields(records, fields)
    return ["%s carries `%s` on none of its %d record(s), and this is the "
            "committed artefact. Every assertion this check makes about that "
            "field is gated on the field being present, so its absence reads "
            "as a pass. Either the producer stopped writing it, or it was "
            "retired and belongs out of this check's field list."
            % (array, field, len(records)) for field in missing]


def _committed_fields(reference, array, fields):
    """-> the field set a pinned artefact is held to, which is `fields` whole.

    Deriving the set by reading `reference` and keeping the fields it carries
    was the first shape of this function, and it made the assertion vacuous.
    On a real run `reference` is the file under test, so the derived set was
    read from the same records the set was then compared against, and the two
    could not disagree. A producer that stopped writing a field dropped it
    from both sides at once and the check reported 4 of 4.

    The declared tuple is the floor. A field retired for real is retired from
    RANK_RESTATEMENTS or CHAIN_RESTATEMENTS in the same change, which is one
    line a reviewer sees. `reference` and `array` stay in the signature
    because the counter below reports the artefact each figure belongs to.
    """
    return tuple(fields)


def rank_consistency(doc, path):
    """-> [problem] for rm-control-rank.json's own ordering and arithmetic.

    The command set comparison in `derived` reads handler names and discards
    everything else, so it holds against a ranking reversed, renumbered, or
    with every score zeroed. tools/syzlang_gen.py emit reads this file for the
    order it emits the control family in, and generation.json records its
    sha256 as an input of the committed set, so the order has downstream
    effect and needs an assertion of its own.

    Three properties, none of which needs the tool that produced the file:

      rank is 1..N in array order
      rank_score is the weighted sum of rank_components
      rank_score does not increase along the array, within each of the runs
        the file is built from: the commands carrying a chain first, then the
        ones carrying none
    """
    commands = doc["commands"]
    fields = RANK_RESTATEMENTS
    problems = (_partial_fields(path, "commands", commands, fields)
                + _absent_fields(path, "commands", commands,
                                 _committed_fields(CTRL_RANK, "commands",
                                                   fields),
                                 CTRL_RANK))
    ranked = _carried(commands, "rank")
    scored = _carried(commands, "rank_score")
    priced = _carried(commands, "rank_components")
    grouped = _carried(commands, "no_chain_reason")

    weighting = doc.get("weighting")
    if scored and priced and not isinstance(weighting, dict):
        raise CheckInput(
            "%s carries rank_score and rank_components on every record and no "
            "`weighting` object, and the score is the weighted sum of those "
            "components, so it cannot be checked against them." % path)

    previous_score, previous_chained = None, None
    for index, command in enumerate(commands):
        at = "commands[%d]" % index
        handler = _record_name(path, at, command, "handler")
        if ranked and command["rank"] != index + 1:
            problems.append("%s (%s) carries rank %r at array position %d"
                            % (at, handler, command["rank"], index + 1))
        score = command.get("rank_score") if scored else None
        if scored and priced:
            components = command["rank_components"]
            if not isinstance(components, dict) or not isinstance(
                    score, (int, float)):
                problems.append(
                    "%s (%s) carries rank_score %r over components %r"
                    % (at, handler, score, components))
                continue
            unpriced = sorted(k for k in components if k not in weighting)
            if unpriced:
                problems.append("%s (%s) carries component(s) %s the "
                                "weighting block does not price"
                                % (at, handler, ", ".join(unpriced)))
                continue
            expected = sum(weighting[k] * components[k] for k in components)
            if abs(expected - score) > SCORE_TOLERANCE:
                problems.append("%s (%s) carries rank_score %.6f against "
                                "%.6f from its own components and weighting"
                                % (at, handler, score, expected))
        if not (scored and grouped):
            continue
        chained = command["no_chain_reason"] is None
        if previous_chained is not None and chained and not previous_chained:
            problems.append("%s (%s) carries a chain and follows a command "
                            "that carries none" % (at, handler))
        elif previous_chained and not chained:
            # The two runs are ranked separately, so the score resets here.
            previous_score = None
        if (previous_score is not None
                and score > previous_score + SCORE_TOLERANCE):
            problems.append("%s (%s) scores %.6f above the %.6f before it"
                            % (at, handler, score, previous_score))
        previous_score, previous_chained = score, chained
    return problems


def chains_consistency(doc, path):
    """-> [problem] for rm-chains.json's own record structure.

    The command set comparison holds against a chain that loses its last step,
    because the allocation class that step named is reached through another
    chain. Each record restates its own chain, and those restatements tie a
    step list to the class the chain exists to reach.
    """
    records = doc["chains"]
    fields = CHAIN_RESTATEMENTS
    problems = (_partial_fields(path, "chains", records, fields)
                + _absent_fields(path, "chains", records,
                                 _committed_fields(CHAINS, "chains", fields),
                                 CHAINS))
    lengths = _carried(records, "chain_length")
    targets = _carried(records, "target_external_class")
    counts = _carried(records, "command_count")

    for index, record in enumerate(records):
        at = "chains[%d]" % index
        steps = record.get("chain") or []
        target = record.get("target_external_class")
        if steps and targets:
            tail = _record_name(path, "%s.chain[%d]" % (at, len(steps) - 1),
                                steps[-1], "external_class")
            if tail != target:
                problems.append("%s ends on %s and targets %s, so the chain "
                                "no longer reaches the class it exists for"
                                % (at, tail, target))
        if lengths:
            length = record["chain_length"]
            if steps and length != len(steps):
                problems.append("%s (%s) declares chain_length %r over %d "
                                "step(s)" % (at, target, length, len(steps)))
            elif not steps and length is not None:
                problems.append("%s (%s) carries an empty chain and "
                                "chain_length %r, where an unallocatable "
                                "class carries null" % (at, target, length))
        if counts and record["command_count"] != len(record.get("commands")
                                                     or []):
            problems.append("%s (%s) declares command_count %r over %d "
                            "command(s)"
                            % (at, target, record["command_count"],
                               len(record.get("commands") or [])))

    unresolved = doc.get("unresolved_owning_classes") or []
    problems.extend(_partial_fields(path, "unresolved_owning_classes",
                                    unresolved, ("command_count",)))
    if _carried(unresolved, "command_count"):
        for index, row in enumerate(unresolved):
            if row["command_count"] != len(row.get("commands") or []):
                problems.append("unresolved_owning_classes[%d] declares "
                                "command_count %r over %d command(s)"
                                % (index, row["command_count"],
                                   len(row.get("commands") or [])))
    return problems


def _report_set(heading, names, limit=30):
    print(heading)
    print()
    for name in sorted(names)[:limit]:
        print("  %s" % name)
    if len(names) > limit:
        print("  ... and %d more" % (len(names) - limit))
    print()


def check_derived():
    """The chain and ranking artefacts still match the control inventory."""
    try:
        targets, _excluded, meta = surface_cov.load_targets()
    except surface_cov.SurfaceError as exc:
        raise CheckInput(str(exc))
    control = {name for name, rec in targets.items()
               if rec["family"] == "control"}
    declared = set(read_descriptions()[0])

    # Every artefact is read before anything is printed, so the summary table
    # leads the step's log and the offending entries follow it.
    readers = {"rm-chains.json": chains_implies,
               "rm-control-rank.json": rank_implies}
    # The command set comparison holds against a reordered ranking and against
    # a chain that loses its last step, because neither moves the set of
    # handler names. Each artefact restates its own structure, and these read
    # that restatement against the records it describes.
    auditors = {"rm-chains.json": chains_consistency,
                "rm-control-rank.json": rank_consistency}
    rows, offenders, internal, silent = [], [], [], []
    for label, path, schema, array, remedy in DERIVED:
        doc = _load_derived(label, path, schema, array, remedy)
        implied, accounted = readers[label](doc, path)
        problems = auditors[label](doc, path)
        # Which restatements this artefact carries, and so which of the
        # assertions above ran at all. Every one of them is gated on its
        # field being present, and a field absent from every record leaves
        # that assertion silent while the command set is still compared. The
        # count is reported on every run, passing or failing.
        restated, fields = RESTATEMENTS[label]
        uncompared = _uncompared_fields(doc[restated], fields)
        if uncompared:
            silent.append((label, uncompared, fields))
        undeclared = implied - declared
        stale = accounted - control
        unaccounted = control - accounted
        rows.append((label, len(doc[array]), len(implied), len(accounted),
                     len(undeclared), len(stale) + len(unaccounted),
                     len(problems),
                     "%d of %d" % (len(fields) - len(uncompared),
                                   len(fields))))
        if undeclared or stale or unaccounted:
            offenders.append((label, remedy, undeclared, stale, unaccounted))
        if problems:
            internal.append((label, remedy, problems))

    print("derived: driver %s, %d targetable control command(s)"
          % (meta.get("driver_version") or "unknown", len(control)))
    print()
    print("  %-22s %8s %8s %10s %11s %9s %9s %10s"
          % ("artefact", "records", "implies", "accounts", "undeclared",
             "mismatch", "internal", "restated"))
    print("  %-22s %8s %8s %10s %11s %9s %9s %10s"
          % ("-" * 22, "-" * 8, "-" * 8, "-" * 10, "-" * 11, "-" * 9,
             "-" * 9, "-" * 10))
    for row in rows:
        print("  %-22s %8d %8d %10d %11d %9d %9d %10s" % row)
    print()
    for label, uncompared, fields in silent:
        print("derived: %s carries %d of its %d restatement(s), so the "
              "assertions over %s ran against nothing"
              % (label, len(fields) - len(uncompared), len(fields),
                 ", ".join(uncompared)))
    if silent:
        print()

    for label, remedy, problems in internal:
        print("derived: %s contradicts its own record structure in %d place(s)"
              % (label, len(problems)))
        print()
        for problem in problems[:30]:
            print("  %s" % problem)
        if len(problems) > 30:
            print("  ... and %d more" % (len(problems) - 30))
        print()
        print("Regenerate with `%s`." % remedy)
        print()

    for label, remedy, undeclared, stale, unaccounted in offenders:
        if undeclared:
            _report_set(
                "derived: %s implies %d call name(s) no description declares"
                % (label, len(undeclared)), undeclared)
        if stale:
            _report_set(
                "derived: %s names %d control command(s) the inventory no "
                "longer carries as targetable" % (label, len(stale)), stale)
        if unaccounted:
            _report_set(
                "derived: %d targetable control command(s) appear nowhere in "
                "%s" % (len(unaccounted), label), unaccounted)
        print("Regenerate with `%s`." % remedy)
        print()

    if not offenders and not internal:
        print("derived: OK")
        return 0
    print("Nothing in CI runs the two producing tools, so both artefacts go "
          "stale against a driver bump that moves the control inventory. "
          "tools/trace2seed.py chains and tools/syzlang_gen.py emit read them "
          "and neither reports the drift.")
    return 1


def _first_difference(committed, generated):
    """-> (line number, committed line, generated line) for the first line the
    two differ on, or None.

    Compared as raw bytes and split on the line feed, so a page rewritten
    with CRLF endings reports the line it first differs on and not a
    whole-file mismatch with no location.
    """
    left = committed.split(LF)
    right = generated.split(LF)
    for index in range(max(len(left), len(right))):
        one = left[index] if index < len(left) else None
        two = right[index] if index < len(right) else None
        if one != two:
            return (index + 1,
                    "(page ends here)" if one is None
                    else one.decode("utf-8", "replace"),
                    "(generated output ends here)" if two is None
                    else two.decode("utf-8", "replace"))
    return None


# A whole flags-set definition, with its value list. FLAGS_DEFINE_RE reads the
# name alone, which is all the name comparison needs; this reads what the set
# binds the field to.
FLAGS_VALUES_RE = re.compile(r"^([a-z_][a-z0-9_]*)\s*=\s*([^\n]+)$", re.M)


def read_flags_values():
    """-> {set name: (file, line, [value])} over the committed set.

    The values a set actually binds a field to. read_flags_sets reads the name
    and the reference; nothing read the members, so editing
    descriptions/nvidia.txt:239 from `= 0x1, 0x2` to `= 0x999999` left all
    twelve checks green and pointed the fuzzer at one value where the driver
    accepts two.

    A member that does not read as an integer comes back as the raw token, so
    the comparison reports it against the derivation rather than raising here.
    """
    values = {}
    for path in _description_files():
        name = os.path.basename(path)
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for match in FLAGS_VALUES_RE.finditer(text):
            if match.group(1) in values:
                continue
            members = []
            for token in match.group(2).split(","):
                token = token.strip()
                if not token:
                    continue
                try:
                    members.append(int(token, 0))
                except ValueError:
                    members.append(token)
            values[match.group(1)] = (
                name, text[:match.start()].count("\n") + 1, members)
    return values


def read_flags_sets():
    """-> ({set name: file}, {set name: [file]}) over the committed set.

    The first mapping holds every `name = value, value` definition, the second
    every `flags[name, ...]` reference. syzlang resolves a flags name across
    the whole package, so a set defined in one file and referenced from
    another is one pair here and not two.
    """
    defined, referenced = {}, {}
    for path in _description_files():
        name = os.path.basename(path)
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for match in FLAGS_DEFINE_RE.finditer(text):
            defined.setdefault(match.group(1), name)
        for match in FLAGS_REFERENCE_RE.finditer(text):
            referenced.setdefault(match.group(1), []).append(name)
    logger.info("descriptions: %d flags set(s) defined, %d referenced",
                len(defined), len(referenced))
    return defined, referenced


def read_value_families():
    """-> (the value_families module, the derivation, the audit).

    The module comes back with the documents because `accepted_families` is
    the only sanctioned join between them, and a caller that read the two
    files without it would be free to invent a second rule for which family
    an emitted field may carry.

    value_families is imported here and not at the top of the module, for the
    reason `agents` gives for its own imports: that module imports
    syzlang_gen, and the other checks read committed files alone.
    """
    try:
        value_families = importlib.import_module("value_families")
    except ImportError as exc:
        raise CheckInput(
            "tools/value_families.py could not be imported, so the accepted "
            "families cannot be read through accepted_families(): %s" % exc)
    try:
        derivation = value_families.load_json(VALUE_FAMILIES,
                                              "the derived value families")
        audit_doc = value_families.load_json(VALUE_FAMILIES_AUDIT,
                                             "the value-family audit")
    except value_families.SourceError as exc:
        raise CheckInput(str(exc))
    for document, path, key in ((derivation, VALUE_FAMILIES, "families"),
                                (audit_doc, VALUE_FAMILIES_AUDIT, "audit")):
        if not isinstance(document.get(key), list):
            raise CheckInput(
                "%s carries no %s array. `%s` writes it, and without it "
                "nothing records which families were derived and which the "
                "audit accepted."
                % (path, key, VALUE_FAMILIES_REMEDY))
    return value_families, derivation, audit_doc


def check_families():
    """Every emitted value family was accepted, and every accepted one emitted."""
    value_families, derivation, audit_doc = read_value_families()
    accepted = value_families.accepted_families(derivation, audit_doc)
    accepted_keys = {(r["struct"], r["field"]) for r in accepted}
    _calls, structs = read_descriptions()
    defined, referenced = read_flags_sets()
    members = read_flags_values()

    emitted, missing, wrong, leaked, dangling, unused, orphan = (
        [], [], [], [], [], [], [])
    divergent = []

    # Direction one: the audit accepted it, so the description set carries it.
    for record in accepted:
        struct, field = record["struct"], record["field"]
        set_name = record["set_name"]
        rendered = structs.get(struct, {}).get(field)
        if rendered is None:
            missing.append((struct, field, set_name,
                            "no field of that name in the emitted struct"))
            continue
        match = FLAGS_FIELD_RE.match(rendered)
        if match is None:
            missing.append((struct, field, set_name,
                            "renders as %s" % rendered))
            continue
        if match.group(1) != set_name:
            wrong.append((struct, field, set_name, match.group(1)))
            continue
        if set_name not in defined:
            missing.append((struct, field, set_name,
                            "the field references the set and no file "
                            "defines it"))
            continue
        emitted.append((struct, field, set_name))

        # Direction three: the set's members are the values the derivation
        # carries. Directions one and two compare the set's name, so a set
        # whose value list was edited keeps its name, keeps its binding, and
        # passes both. The fuzzer then drives whatever the edited list holds.
        source, line, carried = members.get(set_name, (None, None, None))
        if carried is None:
            missing.append((struct, field, set_name,
                            "no file defines it with a value list"))
            continue
        derived_values = record.get("values")
        if not isinstance(derived_values, list):
            raise CheckInput(
                "%s carries no `values` array for %s.%s. The derivation is "
                "the authority on what the emitted set binds the field to, "
                "and without it the set is compared against nothing."
                % (os.path.relpath(VALUE_FAMILIES, REPO_ROOT)
                   .replace(os.sep, "/"), struct, field))
        if list(carried) != list(derived_values):
            divergent.append((set_name, source, line, carried,
                              derived_values))

    # Direction two: the description set carries it, so the audit accepted it.
    # A derived family the audit rejected is the case this whole phase exists
    # to prevent, because a field bound to the wrong family never reaches its
    # real values and a bare integer still does by mutation.
    for record in derivation["families"]:
        struct, field = record["struct"], record["field"]
        if (struct, field) in accepted_keys:
            continue
        set_name = record["set_name"]
        rendered = structs.get(struct, {}).get(field)
        match = FLAGS_FIELD_RE.match(rendered) if rendered else None
        if match is not None and match.group(1) == set_name:
            leaked.append((struct, field, set_name,
                           "the field is bound to it"))
        elif set_name in defined:
            leaked.append((struct, field, set_name,
                           "%s defines the set" % defined[set_name]))

    # An accepted audit entry with no derived record binds nothing and reports
    # nothing, because accepted_families joins on (struct, field) and returns
    # derived records alone.
    derived_keys = {(r["struct"], r["field"]) for r in derivation["families"]}
    for entry in audit_doc["audit"]:
        if entry.get("verdict") != "accepted":
            continue
        if (entry["struct"], entry["field"]) not in derived_keys:
            orphan.append((entry["struct"], entry["field"],
                           entry.get("set_name")))

    # Both directions over the flags sets themselves, which also covers the
    # five sets written by hand. A reference to an undefined set does not
    # compile, and a definition nothing references is a set the emitter still
    # writes after its field stopped using it.
    for name, files in sorted(referenced.items()):
        if name not in defined:
            dangling.append((name, ", ".join(sorted(set(files)))))
    for name, source in sorted(defined.items()):
        if name not in referenced:
            unused.append((name, source))

    print("families: %d derived, %d accepted by the audit, %d bound to a "
          "field" % (len(derivation["families"]), len(accepted),
                     len(emitted)))
    print()
    print("  %-28s %8s %8s" % ("state", "families", "sets"))
    print("  %-28s %8s %8s" % ("-" * 28, "-" * 8, "-" * 8))
    print("  %-28s %8d %8d" % ("accepted and bound", len(emitted),
                               len(emitted)))
    print("  %-28s %8d %8d" % ("accepted and not bound", len(missing)
                               + len(wrong), 0))
    print("  %-28s %8d %8d"
          % ("rejected and reaching a set", len(leaked), len(leaked)))
    print("  %-28s %8d %8d" % ("defined by hand",
                               0, len(defined) - len(emitted)))
    print()

    print("families: %d bound set(s) compared against the derivation's own "
          "value list" % (len(emitted) - len(divergent)))
    print()

    offenders = (len(missing) + len(wrong) + len(leaked) + len(dangling)
                 + len(unused) + len(orphan) + len(divergent))
    if not offenders:
        print("families: every accepted family is bound to its field and "
              "every emitted set was accepted")
        print("families: OK")
        return 0

    for struct, field, set_name, problem in missing:
        print("families: %s.%s was accepted and is not bound: %s"
              % (struct, field, problem))
    for struct, field, set_name, found in wrong:
        print("families: %s.%s is bound to %s and the audit accepted %s"
              % (struct, field, found, set_name))
    for struct, field, set_name, problem in leaked:
        print("families: %s.%s reaches the description set and the audit did "
              "not accept it: %s" % (struct, field, problem))
    for struct, field, set_name in orphan:
        print("families: the audit accepts %s.%s and no derived record "
              "carries it, so nothing binds it" % (struct, field))
    for name, files in dangling:
        print("families: %s is referenced by %s and no file defines it"
              % (name, files))
    for name, source in unused:
        print("families: %s is defined in %s and no field references it"
              % (name, source))
    for set_name, source, line, carried, derived_values in divergent:
        print("families: %s at %s:%d binds %s and the derivation carries %s"
              % (set_name, source, line,
                 ", ".join(str(v) for v in carried),
                 ", ".join(str(v) for v in derived_values)))
    if divergent:
        print()
        print("A set whose members were edited keeps its name, so the two "
              "name comparisons above still pass while the field is bound to "
              "values the derivation never produced. Regenerate the "
              "description set with `%s`, or restore the edited line."
              % GENERATION_REMEDY)
    print()
    print("A field bound to a family the audit did not accept never reaches "
          "that field's real values, where a bare integer still reaches them "
          "by mutation, so the audit in %s is the only route from a derived "
          "family to an emitted set. Regenerate the derivation and the audit "
          "with `%s`, then the description set with `%s`."
          % (os.path.relpath(VALUE_FAMILIES_AUDIT, REPO_ROOT)
             .replace(os.sep, "/"), VALUE_FAMILIES_REMEDY, GENERATION_REMEDY))
    return 1


def check_pages():
    """The generated reference pages still match the surface artefacts."""
    try:
        pages, rows = refgen.render()
    except refgen.RefgenError as exc:
        raise CheckInput(str(exc))

    # Regenerating through refgen.write and reading the result back covers the
    # writer as well as the renderer: a page written with the platform's
    # native line endings differs from the committed LF copy, and that is a
    # real defect the repository's .gitattributes exists to prevent.
    scratch = tempfile.mkdtemp(prefix="refgen-check-")
    try:
        refgen.write(pages, scratch)
        fresh = {}
        for name in sorted(pages):
            with open(os.path.join(scratch, name), "rb") as handle:
                fresh[name] = handle.read()
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    committed = {}
    if os.path.isdir(PAGES_DIR):
        for name in sorted(os.listdir(PAGES_DIR)):
            if not name.endswith(".md"):
                continue
            with open(os.path.join(PAGES_DIR, name), "rb") as handle:
                committed[name] = handle.read()

    table, offenders = [], []
    for name in sorted(fresh):
        on_disk = committed.get(name)
        if on_disk is None:
            state = "absent"
            offenders.append((name, "no committed page at "
                                    "docs/src/content/docs/reference/surface/"
                                    + name, None))
        elif on_disk == fresh[name]:
            state = "OK"
        else:
            state = "differs"
            offenders.append((name, "the committed page and the regenerated "
                                    "one differ",
                              _first_difference(on_disk, fresh[name])))
        table.append((name, rows[name], len(fresh[name]),
                      len(on_disk) if on_disk is not None else 0, state))

    for name in sorted(set(committed) - set(fresh)):
        offenders.append((name, "a committed page tools/refgen.py no longer "
                                "produces", None))
        table.append((name, 0, 0, len(committed[name]), "orphan"))

    print("pages: %d generated page(s) against %s"
          % (len(fresh), os.path.relpath(PAGES_DIR, REPO_ROOT).replace(
              os.sep, "/")))
    print()
    print("  %-24s %8s %11s %11s %9s"
          % ("page", "records", "generated", "committed", "state"))
    print("  %-24s %8s %11s %11s %9s"
          % ("-" * 24, "-" * 8, "-" * 11, "-" * 11, "-" * 9))
    for row in table:
        print("  %-24s %8d %11d %11d %9s" % row)
    print()

    if not offenders:
        print("pages: OK")
        return 0

    for name, problem, difference in offenders:
        print("pages: %s: %s" % (name, problem))
        if difference:
            line, left, right = difference
            print()
            print("  first difference at line %d" % line)
            print("    committed   %s" % left)
            print("    regenerated %s" % right)
        print()
    print("A page is generated output and never an editable file. Regenerate "
          "with `%s`, which rewrites all five from the artefacts under "
          "surface. If the artefacts moved, that is the change to "
          "review; if the page was edited by hand, the edit belongs in "
          "tools/refgen.py." % PAGES_REMEDY)
    return 1


def read_generation():
    """-> (the generated_from record, the root its paths resolve against).

    Recorded paths are repository-relative and the record sits at
    descriptions/generation.json, so the root is the parent of the directory
    holding it. Deriving the root from the record's own location leaves the
    check pointable at a scratch tree through GENERATION alone.
    """
    try:
        with open(GENERATION, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError) as exc:
        raise CheckInput("%s: %s" % (GENERATION, exc))
    record = raw.get("generated_from")
    if not isinstance(record, dict):
        raise CheckInput(
            "%s carries no generated_from mapping. `%s` writes it, and "
            "without it nothing records which artefacts the description set "
            "was generated from." % (GENERATION, GENERATION_REMEDY))
    root = os.path.dirname(os.path.dirname(os.path.abspath(GENERATION)))
    return raw, record, root


def recorded_outputs(raw):
    """-> [(path, sha256, bytes)] over every file the run wrote.

    The digests of the outputs, beside the digests of the inputs. Nothing
    hashed what the run produced, so a hand edit to any descriptions/*.txt
    left all nine recorded inputs matching and all twelve checks green.

    A file digest was rejected for the inputs because it fails on a correct
    regeneration and names no moved value. That objection does not reach a
    digest recorded inside generation.json: the same run writes the file and
    the record, so a correct regeneration moves both together and only a hand
    edit moves one.

    The block is mandatory. A run whose writer does not record it leaves the
    outputs unhashed, which is the state this reader exists to end.
    """
    block = raw.get("generated")
    if not isinstance(block, dict) or not block:
        raise CheckInput(
            "%s carries no `generated` mapping. `%s` writes one record per "
            "file the run produced, each with a sha256 and a byte count, and "
            "without it nothing hashes the description set itself: a hand "
            "edit to any of those files leaves every recorded input matching."
            % (GENERATION, GENERATION_REMEDY))
    outputs = []
    for path in sorted(block):
        member = block[path]
        if not isinstance(member, dict) or "sha256" not in member:
            raise CheckInput(
                "%s: generated[%r] is not an output record. Every entry "
                "carries a sha256 and a byte count, and this one renders as "
                "%.120r" % (GENERATION, path, member))
        outputs.append((path, member["sha256"], member.get("bytes")))
    return outputs


def recorded_inputs(record):
    """-> [(key, path, sha256, count)] over every input generated_from names.

    ctrl_sizes is a list holding one member today. Reading a list member the
    same way as a mapping covers a second measured-size file from the run it
    is added in.
    """
    inputs = []
    for key in sorted(record):
        if key in CHECKOUT_KEYS:
            continue
        value = record[key]
        for member in (value if isinstance(value, list) else [value]):
            if (not isinstance(member, dict) or "path" not in member
                    or "sha256" not in member):
                raise CheckInput(
                    "%s: generated_from[%r] is not an input record. Every "
                    "entry outside %s carries a path and a sha256, either "
                    "directly or as a list member, and this one renders as "
                    "%.120r" % (GENERATION, key, " and ".join(CHECKOUT_KEYS),
                                member))
            count = None
            for name in COUNT_KEYS:
                if name in member:
                    count = member[name]
                    break
            inputs.append((key, member["path"], member["sha256"], count))
    return inputs


def _digest_mismatch(content, digest):
    """-> (state, why) for a file whose digest does not match its record.

    Line endings are separated from content because they fail asymmetrically.
    The repository normalises to LF through .gitattributes, so a committed
    artefact is LF in the blob whatever platform it was written on, and git
    reports a CRLF working copy as unmodified. A digest taken over that
    working copy therefore passes on the machine that recorded it and fails on
    every checkout of the same commit, which is the machine the pipeline
    actually runs on. Reported as a content mismatch it reads as a
    regeneration that was half applied, and the remedy printed for that
    ("regenerate the description set") rewrites a set that was never wrong.
    """
    lf = content.replace(b"\r\n", b"\n")
    if lf != content and hashlib.sha256(lf).hexdigest() == digest:
        return "crlf", ("the file on disk holds the recorded content with "
                        "CRLF line endings, so it hashes to another digest")
    crlf_form = lf.replace(b"\n", b"\r\n")
    if crlf_form != content and hashlib.sha256(crlf_form).hexdigest() == digest:
        return "crlf-record", ("the recorded digest was taken over a CRLF "
                               "copy of this file, and no checkout of this "
                               "commit reproduces it")
    return "differs", "the file on disk hashes to another digest"


def _digest_state(root, path, digest, expect_bytes=None):
    """-> (state, offender or None) for one recorded file against disk."""
    on_disk = os.path.join(root, *path.split("/"))
    if not os.path.isfile(on_disk):
        return "absent", (path, "no file at this path", digest, None)
    with open(on_disk, "rb") as handle:
        content = handle.read()
    measured = hashlib.sha256(content).hexdigest()
    if measured == digest:
        if expect_bytes is not None and len(content) != expect_bytes:
            return "size", (path, "the file holds %d bytes and the record "
                                  "carries %d, over a matching digest, so "
                                  "the record is internally inconsistent"
                            % (len(content), expect_bytes), digest, measured)
        return "OK", None
    state, why = _digest_mismatch(content, digest)
    return state, (path, why, digest, measured)


def check_stale():
    """Every file generation.json records, on both sides, still matches its
    digest: the artefacts the set was generated from, and the set itself."""
    raw, record, root = read_generation()
    inputs = recorded_inputs(record)
    outputs = recorded_outputs(raw)
    if not inputs:
        raise CheckInput(
            "%s records no input file. The description set is generated from "
            "the artefacts under surface/ and `%s` digests each one, so a "
            "record naming none has lost its provenance."
            % (GENERATION, GENERATION_REMEDY))

    table, offenders = [], []
    for key, path, digest, count in inputs:
        state, offender = _digest_state(root, path, digest)
        if offender:
            offenders.append(offender)
        table.append((key, path, count, state))

    # The output side. generation.json itself is not in the block, because it
    # carries the record and cannot hash itself.
    written = []
    for path, digest, size in outputs:
        state, offender = _digest_state(root, path, digest, size)
        if offender:
            offenders.append(offender)
        written.append((path, size, state))

    # The set on disk is enumerated beside generation.json and not through
    # DESC_DIR. The recorded output paths resolve against `root`, which is
    # derived from the record's own location, so reading the module constant
    # here compares two different trees: pointed at a scratch root it named
    # every committed file as unrecorded and missed the one file the scratch
    # tree had gained. Only .txt is enumerated, and the emitted header is
    # recorded without being scanned for.
    beside = os.path.dirname(os.path.abspath(GENERATION))
    on_disk = {os.path.relpath(p, root).replace(os.sep, "/")
               for p in surface_cov._files(beside, (".txt",))}
    unrecorded = sorted(on_disk - {path for path, _d, _s in outputs})

    checkout = {name: record.get(name) for name in CHECKOUT_KEYS}
    print("stale: %d recorded input(s) and %d recorded output(s) in %s, "
          "driver %s at commit %s"
          % (len(inputs), len(outputs),
             os.path.relpath(GENERATION, root).replace(os.sep, "/"),
             checkout["driver_version"] or "(not recorded)",
             checkout["driver_commit"] or "(not recorded)"))
    print()
    print("  %-20s %-40s %8s %9s"
          % ("input", "path", "records", "state"))
    print("  %-20s %-40s %8s %9s"
          % ("-" * 20, "-" * 40, "-" * 8, "-" * 9))
    for key, path, count, state in table:
        print("  %-20s %-40s %8s %9s"
              % (key, path, "" if count is None else count, state))
    print()
    print("  %-20s %-40s %8s %9s"
          % ("output", "path", "bytes", "state"))
    print("  %-20s %-40s %8s %9s"
          % ("-" * 20, "-" * 40, "-" * 8, "-" * 9))
    for path, size, state in written:
        print("  %-20s %-40s %8s %9s"
              % ("generated", path, "" if size is None else size, state))
    print()

    for path in unrecorded:
        print("stale: %s is a committed description file and `generated` "
              "records no digest for it, so an edit to it is hashed by "
              "nothing" % path)
    if not offenders and not unrecorded:
        print("stale: %d of %d recorded input(s) and %d of %d recorded "
              "output(s) match the digest generation.json carries"
              % (len(inputs), len(inputs), len(outputs), len(outputs)))
        print("stale: OK")
        return 0

    for path, problem, recorded, measured in offenders:
        print("stale: %s: %s" % (path, problem))
        print("    recorded  %s" % recorded)
        print("    measured  %s" % (measured or "(no file to hash)"))
        print()
    if any(state in ("crlf", "crlf-record") for _k, _p, _c, state in table):
        print("A crlf or crlf-record state is line endings and not content. "
              "This repository normalises to LF, so convert the working copy "
              "with `dos2unix` for crlf, and re-record the digest from an LF "
              "checkout for crlf-record. Regenerating the description set "
              "fixes neither.")
        print()
    print("The description set under %s was generated from these files and "
          "carries their digests. A digest that moved means one side was "
          "regenerated and the other was not. Regenerate the set with `%s` "
          "against the same driver checkout, or restore the artefact."
          % (os.path.relpath(os.path.dirname(os.path.abspath(GENERATION)),
                             root).replace(os.sep, "/"),
             GENERATION_REMEDY))
    return 1


def harness_config_targets():
    """-> track_u.targets from config/campaign.yaml."""
    try:
        config = gspwn_config.load(CAMPAIGN_CONFIG)
    except (gspwn_config.ConfigError, OSError) as exc:
        raise CheckInput("%s: %s" % (CAMPAIGN_CONFIG, exc))
    return list(config["track_u"]["targets"])


def harness_run_targets():
    """-> the C_TARGETS array in harnesses/run_all.sh."""
    try:
        with open(RUN_ALL, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise CheckInput("%s: %s" % (RUN_ALL, exc))
    match = C_TARGETS_RE.search(text)
    if not match:
        raise CheckInput(
            "%s declares no C_TARGETS=( ... ) array. The script iterates that "
            "array to run each harness, and this check reads the same one."
            % RUN_ALL)
    names = []
    for line in match.group("body").splitlines():
        names.extend(line.split("#", 1)[0].split())
    return names


def harness_doc_targets():
    """-> every name in a Harness column of harnesses/TARGETS.md.

    Three tables in that file carry the column: the ranked entry points, the
    sanitizer policy and the replay commands. The union of the three covers a
    harness dropped from the file. A harness carried by one table and absent
    from another is outside what this check reads.
    """
    try:
        with open(TARGETS_DOC, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise CheckInput("%s: %s" % (TARGETS_DOC, exc))
    names, column = [], None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            column = None
            continue
        cells = [cell.strip().strip("`")
                 for cell in stripped.strip("|").split("|")]
        if column is None:
            column = (cells.index(HARNESS_COLUMN)
                      if HARNESS_COLUMN in cells else -1)
            continue
        if column < 0 or set("".join(cells)) <= TABLE_RULE:
            continue
        if column < len(cells) and cells[column]:
            names.append(cells[column])
    if column is None and not names:
        raise CheckInput(
            "%s holds no table with a %s column. Every harness name in that "
            "file sits in one." % (TARGETS_DOC, HARNESS_COLUMN))
    return names


def harness_directories():
    """-> (directories under harnesses/ holding a build.sh, those holding none)."""
    try:
        entries = sorted(os.listdir(HARNESS_DIR))
    except OSError as exc:
        raise CheckInput("%s: %s" % (HARNESS_DIR, exc))
    built, bare = [], []
    for name in entries:
        path = os.path.join(HARNESS_DIR, name)
        if not os.path.isdir(path):
            continue
        if os.path.isfile(os.path.join(path, "build.sh")):
            built.append(name)
        else:
            bare.append(name)
    return built, bare


def tracked_script_modes():
    """-> {repository-relative path: index mode} for every tracked .sh.

    The index mode is the one that decides whether a bare invocation runs on
    the campaign machine. A working copy's own permission bits say nothing
    about it: core.fileMode is false on the Windows checkout this repository
    is developed on, so every file there reads as rwxr-xr-x.
    """
    try:
        proc = subprocess.run(["git", "ls-files", "-s", "--", "*.sh"],
                              cwd=REPO_ROOT, capture_output=True, text=True)
    except OSError as exc:
        raise CheckInput("cannot run git in %s: %s" % (REPO_ROOT, exc))
    if proc.returncode != 0:
        raise CheckInput(
            "git ls-files exited %d in %s: %s. The mode this case reads lives "
            "in the index, so it settles nothing outside a checkout."
            % (proc.returncode, REPO_ROOT, proc.stderr.strip()))
    modes = {}
    for line in proc.stdout.splitlines():
        head, _, path = line.partition("\t")
        fields = head.split()
        if not path or len(fields) < 3:
            raise CheckInput(
                "git ls-files -s wrote a line this case cannot read: %r"
                % line)
        modes[path.strip()] = fields[0]
    if not modes:
        raise CheckInput(
            "git ls-files tracks no .sh under %s. Twelve are committed, so an "
            "empty listing is the reader failing and not the tree changing."
            % REPO_ROOT)
    return modes


def _script_token(line):
    """-> the first word of `line` when it names a script path, else None.

    A command sits at the start of its line in every caller this reads: a
    shell statement, and the container command of the systemd unit
    tools/campaign_ctl.py writes, whose ExecStart continues across lines.

    Two exclusions keep prose out. A token carrying no `/` is excluded,
    because no file here reaches a script through PATH and a bare basename in
    a docstring reads as one otherwise. A token followed by a word that is
    neither an option nor a variable is excluded, because a sentence opening
    with a path is a citation: five lines across crash_parse.py, selftest.py
    and this file open that way and none of them runs anything.
    """
    body = line.strip()
    if not body or body.startswith("#"):
        return None
    if body.startswith("ExecStart="):
        body = body[len("ExecStart="):].strip()
    words = body.split()
    token = words[0].strip("\"'`(){}[],;")
    if not token.endswith(".sh") or "/" not in token:
        return None
    for word in words[1:]:
        if word in ("\\", "&&", "||", "|", ";", "&"):
            break
        if not word.startswith(("-", "$", "\"$", "'$")):
            return None
    return token


def bare_script_invocations(scripts):
    """-> [(caller, line number, token, script)] for each bare invocation.

    `scripts` is the tracked .sh set the token is resolved against. A token is
    matched by path suffix, so /harnesses/run_all.sh inside a container and
    harnesses/run_all.sh on the host resolve to the same tracked file.
    """
    found = []
    for rel in sorted(_tracked_callers()):
        path = os.path.join(REPO_ROOT, rel.replace("/", os.sep))
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                lines = handle.read().splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            token = _script_token(line)
            if token is None:
                continue
            norm = token.lstrip("/")
            for script in sorted(scripts):
                if script == norm or script.endswith("/" + norm):
                    found.append((rel, number, token, script))
    return found


def _tracked_callers():
    """-> every tracked file that can execute a command."""
    try:
        proc = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT,
                              capture_output=True, text=True)
    except OSError as exc:
        raise CheckInput("cannot run git in %s: %s" % (REPO_ROOT, exc))
    if proc.returncode != 0:
        raise CheckInput("git ls-files exited %d in %s: %s"
                         % (proc.returncode, REPO_ROOT, proc.stderr.strip()))
    return [p.strip() for p in proc.stdout.splitlines()
            if p.strip().endswith(SCRIPT_CALLER_SUFFIXES)]


def script_mode_offenders():
    """-> ([(caller, line, token, script, mode)], scripts, invocations).

    An offender is a tracked .sh invoked as a bare command by another tracked
    file while its index mode is not 100755. Zero invocations is a pass and is
    reported as one: every caller in the tree names an interpreter, which is
    the state this case exists to keep.
    """
    modes = tracked_script_modes()
    invocations = bare_script_invocations(set(modes))
    offenders = [(rel, number, token, script, modes[script])
                 for rel, number, token, script in invocations
                 if modes[script] != SCRIPT_MODE]
    return offenders, modes, invocations


def excluded_from(source):
    """-> the names the exclusions drop from one of the four sources."""
    unscoped = sorted(set(HARNESS_EXCLUSIONS) - set(HARNESS_EXCLUSION_SOURCES))
    if unscoped:
        raise CheckInput(
            "HARNESS_EXCLUSIONS declares %s and HARNESS_EXCLUSION_SOURCES "
            "gives no scope for it. An exclusion with no scope reads as "
            "covering all four sources, which compares the name against "
            "nothing." % ", ".join(unscoped))
    unknown = {key for sources, _r in HARNESS_EXCLUSION_SOURCES.values()
               for key in sources} - set(HARNESS_SOURCE_KEYS)
    if unknown:
        raise CheckInput(
            "HARNESS_EXCLUSION_SOURCES names %s, which is no source in "
            "HARNESS_SOURCES. An exclusion aimed at a source that does not "
            "exist drops nothing and reads as though it does."
            % ", ".join(sorted(unknown)))
    return {name for name, (sources, _reason)
            in HARNESS_EXCLUSION_SOURCES.items()
            if name in HARNESS_EXCLUSIONS and source in sources}


def check_harnesses():
    """The four Track U target lists still name the same harnesses, and a
    script invoked with no interpreter is executable in the index."""
    built, bare = harness_directories()
    carried = {
        "config": harness_config_targets(),
        "run": harness_run_targets(),
        "doc": harness_doc_targets(),
        "build": built,
    }
    labels = dict(HARNESS_SOURCES)
    # Read whole. An exclusion no longer removes a name from the comparison;
    # it says the name is not required in the sources its scope covers, so a
    # name absent from two sources by design is still compared against the two
    # that carry it.
    sets = {key: set(names) for key, names in carried.items()}
    skips = {key: excluded_from(key) for key, _label in HARNESS_SOURCES}
    for key, label in HARNESS_SOURCES:
        if not sets[key] - skips[key]:
            raise CheckInput(
                "%s carries no target name. A source that reads as empty "
                "makes every other source disagree with it, and the reader "
                "for it is the thing to fix." % label)

    # A name every source excludes names no target at all. `common` is one:
    # it holds no build.sh, so it reaches the stray listing below instead.
    everywhere = {name for name in HARNESS_EXCLUSIONS
                  if all(name in skips[key] for key, _l in HARNESS_SOURCES)}
    targets = sorted(set().union(*sets.values()) - everywhere)
    offenders = []
    for name in targets:
        absent = [labels[key] for key, _ in HARNESS_SOURCES
                  if name not in sets[key] and name not in skips[key]]
        if absent:
            present = [labels[key] for key, _ in HARNESS_SOURCES
                       if name in sets[key]]
            offenders.append((name, absent, present))
    stray = sorted(set(bare) - everywhere - skips["build"])
    mode_offenders, modes, invocations = script_mode_offenders()

    print("harnesses: %d target(s) across %d source(s), %d declared "
          "exclusion(s)" % (len(targets), len(HARNESS_SOURCES),
                            len(HARNESS_EXCLUSIONS)))
    print("harnesses: %d tracked script(s), %d executable in the index, %d "
          "invoked as a bare command"
          % (len(modes), sum(1 for m in modes.values() if m == SCRIPT_MODE),
             len(invocations)))
    print()
    print("  %-22s %-14s %-11s %-11s %s"
          % ("target", "campaign.yaml", "run_all.sh", "TARGETS.md",
             "build.sh"))
    print("  %-22s %-14s %-11s %-11s %s"
          % ("-" * 22, "-" * 14, "-" * 11, "-" * 11, "-" * 8))
    for name in targets:
        # n/a is a source this name is excluded from. It reads apart from NO
        # so the table states which absences are declared and which are the
        # disagreement the check reports.
        cells = tuple("n/a" if name in skips[key]
                      else ("yes" if name in sets[key] else "NO")
                      for key, _ in HARNESS_SOURCES)
        print("  %-22s %-14s %-11s %-11s %s" % ((name,) + cells))
    print()
    print("  %-22s %s" % ("excluded", "reason"))
    print("  %-22s %s" % ("-" * 22, "-" * 6))
    for name in sorted(HARNESS_EXCLUSIONS):
        sources, scope = HARNESS_EXCLUSION_SOURCES[name]
        print("  %-22s %s" % (name, HARNESS_EXCLUSIONS[name]))
        print("  %-22s dropped from %s"
              % ("", ", ".join(labels[key] for key, _l in HARNESS_SOURCES
                               if key in sources)))
        print("  %-22s %s" % ("", scope))
    print()

    if not offenders and not stray and not mode_offenders:
        print("harnesses: OK")
        return 0

    for rel, number, token, script, mode in mode_offenders:
        print("harnesses: %s:%d: %s runs %s with no interpreter, and %s is "
              "mode %s in the index" % (rel, number, token, script, script,
                                        mode))
        print("    a bare command exits 126 there. Either name the "
              "interpreter, or run: git update-index --chmod=+x %s" % script)
        print()

    for name, absent, present in offenders:
        for label in absent:
            print("harnesses: %s: %s does not carry it" % (name, label))
        print("    carried by  %s" % (", ".join(present) or "no source"))
        print()
    for name in stray:
        print("harnesses: %s: a directory under harnesses/ with no build.sh "
              "and no declared exclusion" % name)
        print("    a directory that builds no target belongs in "
              "HARNESS_EXCLUSIONS with the reason it holds none")
        print()
    print("The four lists drive four separate steps: the fuzz phase reads "
          "config/campaign.yaml, run_all.sh runs the binaries, TARGETS.md "
          "carries the entry point and the replay command, and build_all.sh "
          "compiles what the directories hold. A target named by fewer than "
          "all four is built and never run, or run and never built, and the "
          "campaign reports the skip hours in.")
    return 1


# ---------------------------------------------------------------------------
# agents: every command line in agents/*.md against the tool it names.
#
# The tool modules are imported inside check_agents() and not at the top of
# this file. Some of them reach pipeline_state, which needs fcntl, and the
# import block above states why this module stays runnable on a Windows
# workstation. Keeping the imports inside the check confines that to `agents`:
# the other seven still run there, and `agents` reports the absent module as a
# condition it cannot run under rather than as an offending entry.
# ---------------------------------------------------------------------------

# Tools a brief names whose command surface no argparse parser declares. A
# name here is resolved no further than its file existing, so the reason has
# to state what the check gives up. This is the whole of what the check
# accepts as unreadable; anything else that fails to yield a parser is
# reported.
AGENT_TOOL_EXCLUSIONS = {
    "tools/build_kernel.sh":
        "a bash script. It reads JOBS, LINUX_SRC, NVIDIA_SRC and RUNG from "
        "the environment and takes no argument for a parser to declare",
    "tools/crashlog_ctl.py":
        "reads sys.argv by hand. Its four subcommands and its two flags are "
        "literals inside main(), so no parser carries them and no import "
        "reaches them",
}

# A fenced block delimiter, either backticks or tildes, at any indent.
FENCE_RE = re.compile(r"^\s*(```+|~~~+)")

# A tool named as a path, which is the form every command line uses.
TOOL_PATH_RE = re.compile(r"\btools/([A-Za-z0-9_]+\.(?:py|sh))\b")

# A tool named anywhere in the prose, with the directory optional. The exit
# code sentences write `surface_verify.py check` without the directory, so the
# binding below needs the looser form. Every match is resolved against
# tools/ before it is used, so a stray word ending in .py binds nothing.
TOOL_MENTION_RE = re.compile(r"\b(?:tools/)?([A-Za-z0-9_]+\.(?:py|sh))\b")

# An inline code span. DOTALL, because a span in these briefs wraps across a
# line break and the command inside it is one command.
SPAN_RE = re.compile(r"`([^`]+)`", re.S)

# The list markers, block quote markers and table cell bars a command line
# sits behind in a numbered step.
LIST_MARKER_RE = re.compile(r"^\s*(?:(?:[-*+>]|\d+[.)]|\|)\s+)*")

# A heredoc and everything after it on the joined line.
HEREDOC_RE = re.compile(r"<<-?\s*['\"]?\w+['\"]?.*$", re.S)

# The words a simple command is separated from its neighbours by. A single
# bar is a separator only when it is spaced, because the briefs write
# alternatives as in_progress|done|blocked with no spaces.
SEPARATOR_RE = re.compile(r";|&&|\|\||\s\|\s|\s>>?\s")

# The shell keywords a simple command sits behind once the separators have
# split the line. `for f in ...; do CMD; done` puts one in front of CMD.
SHELL_KEYWORDS = ("do", "done", "then", "else", "fi", "elif")

# The words a simple command carries in front of the interpreter.
COMMAND_PREFIXES = ("sudo", "python3", "python", "bash", "sh", "time", "exec")

# The first word of a bare command line in prose. A prose sentence naming a
# tool starts with a capital or with the tool's own path, so the check reads a
# line as a command only when it opens with one of these.
COMMAND_STARTERS = ("python3", "python", "sudo", "bash", "sh", "for", "[")

# An argument whose value the brief withholds: an angle bracket placeholder,
# a shell variable, an ellipsis, or a quoted one. A placeholder is measured
# against neither the declared choices nor the declared type, because the
# operator substitutes it and the brief carries no value to measure.
PLACEHOLDER_RE = re.compile(r"^[\"']?(?:<[^<>]*>[^\s]*|\$[\w{].*|\.{3})[\"']?$")

# An exit code a brief states, in either the noun or the verb form: "exits 4",
# "Exit 3 means", "reaches exit 4".
EXIT_CODE_RE = re.compile(r"\bexits?\s+(\d+)\b", re.I)

# Every tool returns 0 by falling off the end of main(), so 0 is reachable
# whether or not a return statement names it.
IMPLICIT_EXIT = 0


def agent_briefs():
    """-> every phase brief under AGENTS_DIR, by path."""
    if not os.path.isdir(AGENTS_DIR):
        raise CheckInput(
            "%s is not a directory. The phase briefs are committed artefacts; "
            "a checkout missing them cannot run this check." % AGENTS_DIR)
    found = sorted(name for name in os.listdir(AGENTS_DIR)
                   if name.endswith(".md"))
    if not found:
        raise CheckInput(
            "no .md brief under %s. A brief set that reads as empty makes "
            "every command line resolve vacuously, and the reader for it is "
            "the thing to fix." % AGENTS_DIR)
    return [(name, os.path.join(AGENTS_DIR, name)) for name in found]


def _join_continuations(numbered):
    """-> [(line number, line)] with backslash continuations joined."""
    joined, held, start = [], None, None
    for number, line in numbered:
        body = line.rstrip()
        if held is None:
            held, start = body, number
        else:
            held = held + " " + body.strip()
        if held.endswith("\\"):
            held = held[:-1].rstrip()
            continue
        joined.append((start, held))
        held, start = None, None
    if held is not None:
        joined.append((start, held))
    return joined


def _flatten(line):
    """-> the line as one whitespace-normalised shell line.

    A lone backslash survives whitespace normalisation as its own word, which
    is what a continuation inside a wrapped code span collapses to. Dropping
    it here means one rule covers the continuation in all three sources.
    """
    return " ".join(word for word in line.split() if word != "\\")


def _split_fences(text):
    """-> (fenced lines, prose lines), both numbered, both the same length.

    A fenced line is blanked in the prose stream and a prose line is dropped
    from the fenced stream, so the span scan below cannot pair a fence
    delimiter's backticks with a backtick in the surrounding prose.
    """
    fenced, prose, fence = [], [], None
    for number, line in enumerate(text.splitlines(), 1):
        opened = FENCE_RE.match(line)
        if opened:
            if fence is None:
                fence = opened.group(1)
            elif line.strip().startswith(fence):
                fence = None
            prose.append((number, ""))
            continue
        if fence:
            fenced.append((number, line))
            prose.append((number, ""))
        else:
            prose.append((number, line))
    return fenced, prose


def agent_commands(text):
    """-> [(line number, command)] for every command line in one brief.

    Three sources, because the briefs write commands three ways: inside a
    fenced block, inside an inline code span, and as a bare indented line
    under a numbered step. A source the extractor does not read is a command
    line nothing checks. Each source yields shell lines, and every simple
    command inside one is returned on its own.
    """
    fenced, prose = _split_fences(text)
    lines = set()

    for number, line in _join_continuations(fenced):
        if TOOL_PATH_RE.search(line):
            lines.add((number, _flatten(line)))

    body = "\n".join(line for _number, line in prose)
    for match in SPAN_RE.finditer(body):
        if TOOL_PATH_RE.search(match.group(1)):
            number = body.count("\n", 0, match.start()) + 1
            lines.add((number, _flatten(match.group(1))))

    for number, line in _join_continuations(prose):
        if "`" in line or not TOOL_PATH_RE.search(line):
            continue
        bare = LIST_MARKER_RE.sub("", line).strip()
        if bare.split(" ")[0] in COMMAND_STARTERS:
            lines.add((number, _flatten(bare)))

    found = set()
    for number, line in lines:
        for command in simple_commands(line):
            found.add((number, command))
    return sorted(found)


def _strip_comment(line):
    """-> the line up to the first comment marker outside a quoted string."""
    for index, char in enumerate(line):
        if char != "#" or (index and line[index - 1] not in " \t"):
            continue
        if line.count('"', 0, index) % 2 or line.count("'", 0, index) % 2:
            continue
        return line[:index]
    return line


def simple_commands(line):
    """-> every simple command inside one shell line, tool-bearing ones only.

    A loop body, a command behind a `[ -e ... ] &&` test and a command on the
    receiving end of a pipe are each a command the operator runs, and each one
    is checked on its own.
    """
    line = HEREDOC_RE.sub("", line)
    line = _strip_comment(line)
    out = []
    for part in SEPARATOR_RE.split(line):
        part = part.strip()
        while part.split(" ")[0] in SHELL_KEYWORDS:
            part = part.split(" ", 1)[1].strip() if " " in part else ""
        if part and TOOL_PATH_RE.search(part):
            out.append(part)
    return out


def command_words(command):
    """-> (tool path, [argument]) for one simple command, or None.

    The interpreter, sudo, the loop keyword and any leading environment
    assignment are dropped, because none of them is part of the tool's own
    argument surface.
    """
    try:
        words = shlex.split(command, comments=False, posix=False)
    except ValueError:
        words = command.split()
    while words:
        head = words[0]
        if head in COMMAND_PREFIXES or re.match(r"^\w+=", head):
            words.pop(0)
            continue
        break
    if not words:
        return None
    match = TOOL_PATH_RE.search(words[0])
    if not match:
        return None
    return "tools/" + match.group(1), words[1:]


class _ParserCaptured(BaseException):
    """The parser a tool builds inside main(), caught before it parses."""

    def __init__(self, parser):
        BaseException.__init__(self)
        self.parser = parser


def tool_parser(tool):
    """-> the argparse parser tools/<tool> declares.

    Most tools expose build_parser(). The rest build the parser as the first
    statement of main() and parse immediately, so the parser is taken by
    replacing parse_args with one that hands it back. Nothing in either path
    runs the tool's work.
    """
    module = importlib.import_module(os.path.basename(tool)[:-3])
    builder = getattr(module, "build_parser", None)
    if builder is not None:
        return builder()
    if not hasattr(module, "main"):
        raise CheckInput("%s declares neither build_parser nor main" % tool)

    def capture(parser, *_args, **_kwargs):
        raise _ParserCaptured(parser)

    saved_parse = argparse.ArgumentParser.parse_args
    saved_known = argparse.ArgumentParser.parse_known_args
    saved_argv = sys.argv
    argparse.ArgumentParser.parse_args = capture
    argparse.ArgumentParser.parse_known_args = capture
    sys.argv = [tool]
    try:
        module.main()
    except _ParserCaptured as caught:
        return caught.parser
    finally:
        argparse.ArgumentParser.parse_args = saved_parse
        argparse.ArgumentParser.parse_known_args = saved_known
        sys.argv = saved_argv
    raise CheckInput("%s builds no argparse parser in main()" % tool)


def parser_surface(parser):
    """-> ({option string: action}, {subcommand: subparser})."""
    flags, subcommands = {}, {}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            subcommands.update(action.choices)
        for option in action.option_strings:
            flags[option] = action
    return flags, subcommands


def tool_exit_codes(tool):
    """-> every integer a return or a sys.exit in tools/<tool> can yield.

    Read from the source, because the value is often a named module constant:
    surface_verify.py returns DISAGREE and INSUFFICIENT and never 3 and 4 as
    literals. The walk covers every function and not main() alone, so the set
    over-approximates what the process can exit with. That is the safe
    direction: the check reports a documented code only when nothing anywhere
    in the tool produces it.
    """
    with open(os.path.join(REPO_ROOT, tool), encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=tool)
    named = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Constant):
            continue
        if not isinstance(node.value.value, int):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                named[target.id] = node.value.value

    def resolve(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return {node.value}
        if isinstance(node, ast.Name) and node.id in named:
            return {named[node.id]}
        if isinstance(node, ast.IfExp):
            return resolve(node.body) | resolve(node.orelse)
        return set()

    codes = {IMPLICIT_EXIT}
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and node.value is not None:
            codes |= resolve(node.value)
        elif isinstance(node, ast.Call) and _is_exit_call(node):
            for argument in node.args:
                codes |= resolve(argument)
    return codes


def _is_exit_call(node):
    """-> whether the call node is sys.exit or a bare exit."""
    if isinstance(node.func, ast.Attribute):
        return (node.func.attr == "exit"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in ("sys", "os"))
    return isinstance(node.func, ast.Name) and node.func.id == "exit"


def agent_exit_claims(text):
    """-> [(line number, tool path, exit code)] for one brief.

    An exit code binds to the tool named most recently at or before the line
    that states it. That is how the briefs read: the command block comes
    first, and the sentence after it says what each code means. A code stated
    before any tool is named binds to nothing and is dropped.
    """
    claims, current = [], None
    for number, line in enumerate(text.splitlines(), 1):
        for match in TOOL_MENTION_RE.finditer(line):
            candidate = "tools/" + match.group(1)
            if os.path.isfile(os.path.join(REPO_ROOT, candidate)):
                current = candidate
        if current is None:
            continue
        for match in EXIT_CODE_RE.finditer(line):
            claims.append((number, current, int(match.group(1))))
    return claims


def _resolve_command(tool, arguments, parsers, shapes=None):
    """-> [fault] for one command, each fault a line naming what disagreed.

    `shapes` is an optional list the caller owns. A command whose subcommand
    is a metavariable is appended to it and yields no fault: no subparser is
    named, so no flag after it can be resolved against one. Counting them
    keeps that visible, because a command silently checked against nothing is
    the class of hole this whole tool reports.
    """
    if not os.path.isfile(os.path.join(REPO_ROOT, tool)):
        return ["no such tool %s" % tool]
    if tool in AGENT_TOOL_EXCLUSIONS:
        return []
    if tool not in parsers:
        parsers[tool] = tool_parser(tool)
    flags, subcommands = parser_surface(parsers[tool])

    faults = []
    words = list(arguments)
    if subcommands and words and not words[0].startswith("-"):
        name = words.pop(0)
        if PLACEHOLDER_RE.match(name):
            if shapes is not None:
                shapes.append((tool, name))
            return []
        if name not in subcommands:
            return ["no such subcommand %s. %s declares %s"
                    % (name, tool, ", ".join(sorted(subcommands)))]
        # The subcommand's own flags, and not those merged with the main
        # parser's. argparse binds a main-parser flag before the subcommand
        # name and refuses it after, so merging accepts a command line that
        # cannot run: `syzlang_gen.py emit -v` parsed here and exits 2 when
        # run. A flag declared on both, which regression_check.py does for -v
        # through a parent parser, is carried by the subparser and still
        # resolves.
        flags, _ = parser_surface(subcommands[name])
        where = "%s %s" % (tool, name)
    elif subcommands and words and words[0].startswith("-"):
        where = tool
    else:
        where = tool

    index = 0
    while index < len(words):
        word = words[index]
        index += 1
        if not word.startswith("-") or word == "-" or word == "--":
            continue
        option, _, inline = word.partition("=")
        if option not in flags:
            faults.append("no such flag %s. %s declares %s"
                          % (option, where,
                             ", ".join(sorted(flags)) or "no flag"))
            continue
        action = flags[option]
        if action.nargs == 0:
            if inline:
                faults.append("%s on %s takes no value, and the brief gives "
                              "it %s" % (option, where, inline))
            continue
        if inline:
            value = inline
        elif index < len(words) and not words[index].startswith("--"):
            value = words[index]
            index += 1
        else:
            faults.append("%s on %s needs a value, and the brief gives it "
                          "none" % (option, where))
            continue
        faults.extend(_resolve_value(option, where, action, value))
    return faults


def _resolve_value(option, where, action, value):
    """-> [fault] for one argument value against the action that takes it."""
    faults = []
    for alternative in value.strip("\"'").split("|"):
        if not alternative or PLACEHOLDER_RE.match(alternative):
            continue
        if action.choices is not None and alternative not in action.choices:
            faults.append("%s on %s: %s is not among the declared choices %s"
                          % (option, where, alternative,
                             ", ".join(str(c) for c in action.choices)))
            continue
        if action.type is None:
            continue
        try:
            action.type(alternative)
        except (TypeError, ValueError, argparse.ArgumentTypeError):
            # ArgumentTypeError is what a tool's own validating type raises,
            # and argparse derives it from Exception and not from ValueError.
            # Leaving it out let it escape main() as an exit 2 traceback, so
            # a documented argument the tool refuses read as this check being
            # broken. knowledge_ctl._positive_int is one such type.
            faults.append("%s on %s: %s is not a valid %s"
                          % (option, where, alternative,
                             getattr(action.type, "__name__", action.type)))
    return faults


# A count of this tool's own checks, stated in prose. The number word or digit
# sits immediately before the noun, which is how all four statements in the
# tree today are written: "the twelve checks CI runs", "over all twelve
# checks". `artefact` and `regression` are admitted between the two because
# AGENTS.md writes the first form with the adjective.
CHECK_COUNT_RE = re.compile(r"\b(\w+)\s+(?:artefact\s+|regression\s+)?"
                            r"checks?\b")

# Number words a count is written as here. A count above this range would be
# written in digits, which the reader also takes.
CHECK_COUNT_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
                     "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
                     "eleven": 11, "twelve": 12, "thirteen": 13,
                     "fourteen": 14, "fifteen": 15, "sixteen": 16}

# How far back a count is bound to an invocation of this tool. A count is read
# as a count of these checks only where `regression_check.py` is named within
# this many characters before it, with line breaks folded to single spaces.
# Measured over AGENTS.md and the twelve briefs: at 200 the rule reads exactly
# the four statements that are about this tool and nothing else. At 300 it
# also reads "all three of its numbers" at AGENTS.md's seeds gate, and
# "All four checks are required" in agents/describe.md's validation section,
# neither of which counts a check in CHECKS.
CHECK_COUNT_WINDOW = 200

# How far apart two registered names sit and still read as one enumeration.
# The reader takes the first registered name after a count and extends while
# the next one starts within this many characters of the previous one ending,
# so a comma list and a Markdown table are both read whole and the constant
# does not encode either shape. Measured over the two enumerations in the
# tree: 248 characters at the widest in AGENTS.md, 199 in the table at
# agents/describe.md:219. A gap set too wide can only pull in a name from the
# prose after the list, which adds to the set the assertion needs to see and
# never removes one, so this errs wide.
CHECK_LIST_GAP = 300

# How many registered names have to appear before the run is read as an
# enumeration of the whole set. One name is a sentence naming one check; two
# or more is a list, and a list that is short is the defect this case exists
# to catch, because AGENTS.md said ten and listed nine.
CHECK_LIST_FLOOR = 2

# The backticked spans an enumeration is read out of.
CHECK_NAME_SPAN_RE = re.compile(r"`([a-z_]+)`")


def check_count_sources():
    """-> every file this case reads a stated check count out of.

    AGENTS.md and the phase briefs, which are what a coding agent follows to
    decide how many checks a run has to pass. The generated documentation is
    outside this: `pages` compares it against the artefacts it was rendered
    from, and a count restated there is the generator's to fix.
    """
    out = [os.path.join(REPO_ROOT, "AGENTS.md")]
    out.extend(path for _name, path in agent_briefs())
    return [path for path in out if os.path.isfile(path)]


def stated_check_counts():
    """-> [(path, line, stated, listed)] for every count of these checks.

    `stated` is the number the prose states. `listed` is the set of registered
    check names enumerated in the CHECK_LIST_WINDOW characters after it, empty
    where fewer than CHECK_LIST_FLOOR of them appear there.

    A prose figure this repository has now got wrong twice: AGENTS.md said ten
    and listed nine while CHECKS carried twelve, and an agent following it ran
    nine.
    """
    registered = set(CHECKS)
    found = []
    for path in check_count_sources():
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                raw = handle.read()
        except OSError as exc:
            raise CheckInput("cannot read %s (%s)" % (path, exc))
        rel = os.path.relpath(path, REPO_ROOT).replace(os.sep, "/")
        # Joined the way check_figures joins its own sources, so a count and
        # the invocation binding it are read across the 80-column wrap that
        # separates them at AGENTS.md:122. Code spans are kept, because the
        # enumeration beside a count is written as backticked names.
        flat, offsets = _join_wrapped(raw.splitlines())
        for hit in CHECK_COUNT_RE.finditer(flat):
            word = hit.group(1)
            stated = (int(word) if word.isdigit()
                      else CHECK_COUNT_WORDS.get(word.lower()))
            if stated is None:
                continue
            before = flat[max(0, hit.start() - CHECK_COUNT_WINDOW):hit.start()]
            if "regression_check.py" not in before:
                continue
            listed = _enumerated_checks(flat, hit.end(), registered)
            found.append((rel, _line_of(offsets, hit.start()), stated,
                          listed if len(listed) >= CHECK_LIST_FLOOR
                          else set()))
    return found


def _enumerated_checks(flat, start, registered):
    """-> the registered check names the run of names at `start` holds.

    The run begins at the first registered name at or after `start` and ends
    at the first gap wider than CHECK_LIST_GAP. An empty set means no
    registered name follows the count at all, which is a count stated without
    a list beside it.
    """
    listed, end = set(), None
    for match in CHECK_NAME_SPAN_RE.finditer(flat, start):
        if match.group(1) not in registered:
            continue
        if end is not None and match.start() - end > CHECK_LIST_GAP:
            break
        listed.add(match.group(1))
        end = match.end()
    return listed


def check_agents():
    """Every command line in agents/*.md resolves against the tool it names,
    and every count of these checks stated there matches the registry."""
    briefs = agent_briefs()
    parsers = {}
    offenders = []
    counted = {}
    tools = set()
    shapes = []
    commands = 0
    claims = 0

    for name, path in briefs:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        found, stated = 0, 0
        for number, command in agent_commands(text):
            parsed = command_words(command)
            if parsed is None:
                # The line names a tool and does not read as an invocation of
                # it. Reported rather than dropped: a shape the extractor
                # cannot read is a command line nothing checks, and a silent
                # skip is the blind spot this check exists to close.
                offenders.append((name, number, command,
                                  "names a tool and does not read as a "
                                  "command invoking it"))
                continue
            tool, arguments = parsed
            found += 1
            tools.add(tool)
            for fault in _resolve_command(tool, arguments, parsers, shapes):
                offenders.append((name, number, command, fault))
        for number, tool, code in agent_exit_claims(text):
            if tool in AGENT_TOOL_EXCLUSIONS:
                continue
            if not os.path.isfile(os.path.join(REPO_ROOT, tool)):
                offenders.append((name, number, "exit %d" % code,
                                  "no such tool %s" % tool))
                continue
            stated += 1
            if code not in tool_exit_codes(tool):
                offenders.append((name, number, "exit %d" % code,
                                  "%s cannot exit %d: no return and no "
                                  "sys.exit in it yields that value"
                                  % (tool, code)))
        counted[name] = (found, stated)
        commands += found
        claims += stated

    counts = stated_check_counts()
    registered = set(CHECKS)
    miscounted = [(rel, number, stated, sorted(registered - listed))
                  for rel, number, stated, listed in counts
                  if stated != len(CHECKS) or (listed and listed != registered)]
    if not counts:
        raise CheckInput(
            "no count of these checks is stated in AGENTS.md or in any brief "
            "under %s. AGENTS.md carries the sentence a coding agent reads to "
            "decide how many checks a run has to pass, so a reader finding "
            "none is the extractor failing and not the prose changing."
            % AGENTS_DIR)

    if not commands:
        raise CheckInput(
            "no command line in any brief under %s. A brief set carrying no "
            "command makes every tool agree with it vacuously, and the "
            "extractor is then the thing to fix." % AGENTS_DIR)

    print("agents: %d brief(s), %d command line(s) and %d stated exit code(s) "
          "over %d tool(s), %d declared exclusion(s)"
          % (len(briefs), commands, claims, len(tools),
             len(AGENT_TOOL_EXCLUSIONS)))
    print("agents: %d stated count(s) of these checks against %d registered, "
          "%d of them enumerating the set by name"
          % (len(counts), len(CHECKS),
             sum(1 for _r, _n, _s, listed in counts if listed)))
    print("agents: %d command line(s) naming a subcommand as a metavariable"
          % len(shapes))
    print()
    print("  %-16s %8s %11s" % ("brief", "commands", "exit codes"))
    print("  %-16s %8s %11s" % ("-" * 16, "-" * 8, "-" * 11))
    for name, _path in briefs:
        print("  %-16s %8d %11d" % ((name,) + counted[name]))
    print()
    print("  %-24s %s" % ("excluded", "reason"))
    print("  %-24s %s" % ("-" * 24, "-" * 6))
    for tool in sorted(AGENT_TOOL_EXCLUSIONS):
        print("  %-24s %s" % (tool, AGENT_TOOL_EXCLUSIONS[tool]))
    print()

    if not offenders and not miscounted:
        print("agents: OK")
        return 0

    for rel, number, stated, absent in miscounted:
        print("agents: %s:%d: states %d check(s) and the registry carries %d"
              % (rel, number, stated, len(CHECKS)))
        if absent:
            print("    the enumeration beside it omits %s"
                  % ", ".join(absent))
        print("    an agent following this prose runs the number it states. "
              "The registry is tools/regression_check.py CHECKS, and "
              "CHECK_ORDER carries the order to list them in.")
        print()

    for name, number, command, fault in offenders:
        print("agents: agents/%s:%d: %s" % (name, number, command))
        print("    %s" % fault)
        print()
    if not offenders:
        return 1
    print("Each line above is a command a phase brief tells a coding agent to "
          "run on a metered instance. A subcommand, a flag or a value the "
          "tool does not declare stalls the phase there and needs a human to "
          "diagnose it, and the brief and the tool are the two things to "
          "reconcile.")
    return 1


# --------------------------------------------------------------- figures ---

# The prose files a phase brief or a hand-written page can state a surface
# figure in. The reference tree under docs/src/content/docs/reference is
# generated and `pages` already compares it against the artefacts it was
# rendered from, so reading it here would report the same drift twice and name
# the rendered file where the generator is the thing to edit.
FIGURE_DOC_ROOTS = (
    os.path.join(REPO_ROOT, "docs", "src", "content", "docs", "architecture"),
    os.path.join(REPO_ROOT, "docs", "src", "content", "docs", "guides"),
    os.path.join(REPO_ROOT, "docs", "src", "content", "docs",
                 "getting-started"),
)
GENERATED_DOCS = os.path.join("docs", "src", "content", "docs", "reference")

FAMILY_WORD = r"(?:escape|uvm_tools|uvm|control|alloc|modeset|drm)"
FIGURE_ENUM = re.compile(r"(?:\d+\s+%s\s*,\s*){2,}"
                         r"(?:\d+\s+%s\b\s*(?:,\s*)?(?:and\s+)?)+"
                         % (FAMILY_WORD, FAMILY_WORD))
FIGURE_PAIR = re.compile(r"(\d+)\s+(%s)\b" % FAMILY_WORD)

EXCLUDED_TOTAL_PATTERNS = (
    re.compile(r"(\d+)\s+commands?\s+(?:sit|lie)\s+outside\s+the\s+"
               r"denominator"),
    re.compile(r"excludes?\s+the\s+(\d+)\s+commands?\s+outside\s+the\s+"
               r"denominator"),
)
GROUP_COUNT_PATTERNS = (
    re.compile(r"naming\s+the\s+(\w+)\s+excluded\s+groups"),
    re.compile(r"\b(\w+)\s+groups?\s+(?:sit\s+outside|are\s+counted)"),
)

# The per-group figure stated beside the excluded total, keyed by the family
# surface_cov counts that group under. The rule that read the 351 total and
# the word "six" never read these six numbers, so a group whose count moved
# left the prose stating the old one while the total still summed.
#
# Each pattern is anchored on the phrase its group is named by, because the
# family word alone is ambiguous: `(\d+) modeset commands?` also matches the
# 64 modelled modeset commands on two documentation pages, which is the
# family denominator and not the exclusion. Measured over the prose sources:
# these six read 11 figures and all 11 agree with the artefacts.
EXCLUDED_GROUP_PATTERNS = (
    ("control_gsp",
     re.compile(r"(\d+)\s+control\s+commands?\s+routed\s+to\s+GSP", re.I)),
    ("uvm_test",
     re.compile(r"(\d+)\s+uvm_test\s+commands?", re.I)),
    ("drm_undispatched",
     re.compile(r"(\d+)\s+DRM\s+commands?\s+declared", re.I)),
    ("escape_dead",
     re.compile(r"(\d+)\s+escapes?\s+declared\s+with\s+no\s+dispatch", re.I)),
    ("escape_mux",
     re.compile(r"(\d+)\s+multiplexer\s+escapes?", re.I)),
    ("modeset_undispatched",
     re.compile(r"(\d+)\s+modeset\s+commands?\s+"
                r"(?:declared\s+in|the\s+dispatch)", re.I)),
)

# A family figure standing on its own, outside any enumeration, whose own
# words bind it to that family's whole denominator. FIGURE_PAIR runs only
# inside a FIGURE_ENUM match, so a figure stated alone was read by no rule.
#
# The totalising word is required. A bare `N <family>` is not a claim about
# the denominator: measured over the prose sources, 28 pairs stand outside an
# enumeration and 13 of them state a subset, among them the 16 control
# commands carrying an in-handler capability check and the 2 drm commands
# carrying DRM_MASTER. Bound this way the rule reads 4 figures and all 4
# agree.
FIGURE_TOTAL_PATTERNS = (
    re.compile(r"all\s+(\d+)\s+(%s)\s+(?:targets?|commands?)\b"
               % FAMILY_WORD, re.I),
    re.compile(r"(\d+)\s+(%s)\s+targets?\b" % FAMILY_WORD, re.I),
)
NUMBER_WORDS = {"four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
                "nine": 9, "ten": 10}

# A page documenting the denominator's history has to be able to name the
# figures it retired. The rule reports a retired denominator stated as a
# current one, so prose that marks the figure as retired is outside it. The
# window is the text before the match, because every one of these words
# qualifies the number that follows.
RETIRED_CONTEXT = re.compile(
    r"(?:retired|superseded|former|previous(?:ly)?|no longer|used to be|"
    r"history|earlier)\b[^.]{0,64}$", re.I)


def retired_denominators(current):
    """-> the denominators this repository has retired, newest first.

    Read out of pipeline_state.DENOMINATOR_VERSIONS with ast rather than by
    importing the module. pipeline_state needs fcntl, and importing it here
    would stop this check running on a Windows workstation, which is the
    reason the module's other imports are already limited the same way.
    """
    path = os.path.join(REPO_ROOT, "tools", "pipeline_state.py")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
    except (OSError, SyntaxError) as exc:
        raise CheckInput(
            "cannot read DENOMINATOR_VERSIONS from %s (%s). The denominator's "
            "own history is what makes a retired figure recognisable, so this "
            "check cannot run without it."
            % (os.path.relpath(path, REPO_ROOT).replace(os.sep, "/"), exc))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "DENOMINATOR_VERSIONS" not in names:
            continue
        try:
            versions = ast.literal_eval(node.value)
        except ValueError as exc:
            raise CheckInput(
                "DENOMINATOR_VERSIONS in %s is not a literal this check can "
                "read (%s)" % (path, exc))
        return [n for _label, n in versions if n != current]
    raise CheckInput(
        "%s declares no DENOMINATOR_VERSIONS. The denominator's history is "
        "recorded there and nowhere else."
        % os.path.relpath(path, REPO_ROOT).replace(os.sep, "/"))


def figure_sources():
    """-> every file whose prose figures this check reads."""
    out = [os.path.join(REPO_ROOT, "AGENTS.md")]
    if os.path.isdir(AGENTS_DIR):
        out.extend(os.path.join(AGENTS_DIR, name)
                   for name in sorted(os.listdir(AGENTS_DIR))
                   if name.endswith(".md"))
    for root in FIGURE_DOC_ROOTS:
        for base, _dirs, names in os.walk(root):
            out.extend(os.path.join(base, name) for name in sorted(names)
                       if name.endswith(".md"))
    return [p for p in out
            if os.path.isfile(p) and GENERATED_DOCS not in p]


def _blank_code(text):
    """-> the lines with fenced blocks and inline spans blanked.

    A figure inside a code span reproduces what a tool prints, and
    register_check.py holds those immutable for the same reason. Blanking to
    the same width keeps every offset intact, so a match still maps to the
    line it started on.
    """
    out, fenced = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            out.append(" " * len(line))
            continue
        out.append(" " * len(line) if fenced
                   else re.sub(r"`[^`]*`",
                               lambda m: " " * len(m.group(0)), line))
    return out


def _join_wrapped(lines):
    """-> (one text with line breaks as spaces, the start offset of each line).

    Prose here wraps at 80 columns and a family enumeration routinely spans
    two lines. Reading line by line sums a partial list and reports a
    denominator mismatch that is an artefact of the wrap. register_check.py
    matches across a line break for the same reason.
    """
    starts, offset = [], 0
    for line in lines:
        starts.append(offset)
        offset += len(line) + 1
    return " ".join(lines), starts


def _line_of(starts, offset):
    """-> the 1-based line an offset falls on."""
    low, high = 0, len(starts) - 1
    while low < high:
        mid = (low + high + 1) // 2
        if starts[mid] <= offset:
            low = mid
        else:
            high = mid - 1
    return low + 1


def _excerpt(text, start, width=104):
    """-> the matched neighbourhood, for a report line."""
    return re.sub(r"\s+", " ", text[start:start + width]).strip()


def check_figures():
    """Every surface figure stated in prose matches the measured artefacts."""
    try:
        targets, excluded, _meta = surface_cov.load_targets()
    except (OSError, ValueError, KeyError,
            surface_cov.SurfaceError) as exc:
        # SurfaceError is the domain error load_targets raises for a missing
        # or unreadable inventory, which is the condition this clause exists
        # for. Left out, it escapes as a traceback and the check exits 2 with
        # no line naming the artefact.
        raise CheckInput("cannot load the surface inventories (%s)" % exc)

    denominator = len(targets)
    excluded_total = len(excluded)
    families = collections.Counter(r["family"] for r in targets.values())
    group_counts = collections.Counter(r["family"]
                                       for r in excluded.values())
    groups = len(group_counts)
    retired = retired_denominators(denominator)

    declared = {group for group, _p in EXCLUDED_GROUP_PATTERNS}
    unnamed = sorted(set(group_counts) - declared)
    if unnamed:
        raise CheckInput(
            "the inventories carry the excluded group(s) %s and "
            "EXCLUDED_GROUP_PATTERNS names no pattern for them, so a figure "
            "stated for that group is read by no rule. Add the phrase the "
            "prose names it by." % ", ".join(unnamed))

    sources = figure_sources()
    offences = []
    read_groups = read_totals = 0

    def note(path, starts, offset, rule, why, text):
        offences.append((os.path.relpath(path, REPO_ROOT).replace(os.sep, "/"),
                         _line_of(starts, offset), rule, why,
                         _excerpt(text, offset)))

    for path in sources:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                raw = handle.read()
        except OSError as exc:
            raise CheckInput("cannot read %s (%s)" % (path, exc))
        text, starts = _join_wrapped(_blank_code(raw))

        # superseded: a figure this repository has retired, stated as current.
        for number in retired:
            for hit in re.finditer(r"(?<![\d.])%d(?![\d.])" % number, text):
                if RETIRED_CONTEXT.search(text[:hit.start()]):
                    continue
                note(path, starts, hit.start(), "superseded",
                     "%d is a retired denominator and the current one is %d"
                     % (number, denominator), text)

        # enumeration: a family list, checked by its own sum. This is the rule
        # that catches a family added to the surface and left out of a brief,
        # because the sum moves even when every listed figure is right.
        for hit in FIGURE_ENUM.finditer(text):
            pairs = FIGURE_PAIR.findall(hit.group(0))
            total = sum(int(value) for value, _family in pairs)
            if total == denominator:
                continue
            missing = sorted(set(families) - {f for _v, f in pairs})
            note(path, starts, hit.start(), "enumeration",
                 "family enumeration sums to %d against a denominator of %d%s"
                 % (total, denominator,
                    (", omitting " + ", ".join(missing)) if missing else ""),
                 text)

        # bound: a figure the words around it bind to a quantity an artefact
        # settles.
        for pattern in EXCLUDED_TOTAL_PATTERNS:
            for hit in pattern.finditer(text):
                if int(hit.group(1)) != excluded_total:
                    note(path, starts, hit.start(), "bound",
                         "states %s commands outside the denominator against "
                         "%d counted" % (hit.group(1), excluded_total), text)
        for pattern in GROUP_COUNT_PATTERNS:
            for hit in pattern.finditer(text):
                stated = NUMBER_WORDS.get(hit.group(1).lower())
                if stated is not None and stated != groups:
                    note(path, starts, hit.start(), "bound",
                         "names %s exclusion groups against %d counted"
                         % (hit.group(1), groups), text)

        # group: one excluded group's own figure, beside the total the rule
        # above reads. A group whose count moves leaves the total right and
        # the six numbers under it wrong.
        for group, pattern in EXCLUDED_GROUP_PATTERNS:
            for hit in pattern.finditer(text):
                counted_group = group_counts.get(group, 0)
                read_groups += 1
                if int(hit.group(1)) != counted_group:
                    note(path, starts, hit.start(), "group",
                         "states %s in the %s group against %d counted"
                         % (hit.group(1), group, counted_group), text)

        # total: a family figure stated alone and bound by its own words to
        # that family's whole denominator.
        enumerated = [(m.start(), m.end())
                      for m in FIGURE_ENUM.finditer(text)]
        for pattern in FIGURE_TOTAL_PATTERNS:
            for hit in pattern.finditer(text):
                if any(a <= hit.start() < b for a, b in enumerated):
                    continue
                family = hit.group(2).lower()
                read_totals += 1
                if int(hit.group(1)) != families.get(family, 0):
                    note(path, starts, hit.start(), "total",
                         "states %s %s targets against %d counted"
                         % (hit.group(1), family, families.get(family, 0)),
                         text)

    print("figures: denominator %d over %d family/families, %d excluded over "
          "%d group(s)" % (denominator, len(families), excluded_total, groups))
    print("figures: retired denominator(s) %s"
          % (", ".join(str(n) for n in retired) or "none"))
    print("figures: %d prose file(s) read" % len(sources))
    print("figures: %d per-group figure(s) and %d standalone family total(s) "
          "compared" % (read_groups, read_totals))
    print()
    print("  %-24s %8s" % ("excluded group", "counted"))
    print("  %-24s %8s" % ("-" * 24, "-" * 8))
    for group in sorted(group_counts):
        print("  %-24s %8d" % (group, group_counts[group]))
    print()

    if not offences:
        print("figures: OK")
        return 0

    print("  %-34s %6s %-12s %s" % ("file", "line", "rule", "figure"))
    print("  %-34s %6s %-12s %s" % ("-" * 34, "-" * 6, "-" * 12, "-" * 6))
    for path, line, rule, why, _text in offences:
        print("  %-34s %6d %-12s %s" % (path, line, rule, why))
    print()
    for path, line, _rule, _why, text in offences:
        print("figures: %s:%d" % (path, line))
        print("    %s" % text)
    print()
    print("A brief is executed by a model that takes these numbers as fact, "
          "and nothing else reads them: `agents` checks the command lines and "
          "not the prose. Correct the figure, or state the command that "
          "produces it instead of the figure.")
    return 1


# --------------------------------------------------------------------------
# Documentation checks: citations and command lines
# --------------------------------------------------------------------------

DOC_ROOT = os.path.join(REPO_ROOT, "docs", "src", "content", "docs")

# The committed pages, held apart from DOC_ROOT so a caller pointing the check
# at its own directory is told apart from a run over the real tree. Only the
# real tree carries every page an exclusion is declared for.
COMMITTED_DOC_ROOT = DOC_ROOT
VENDOR_DIR = os.path.join(REPO_ROOT, "artifacts", "src")
VENDOR_EXT = (".c", ".h", ".go", ".py", ".sh", ".mk")

# A fenced block, so a citation or a command inside one is read as the
# reproduction it is and not as a claim this check can settle.
DOC_FENCE_RE = re.compile(r"^```.*?^```", re.S | re.M)

# `path/file.c:120` or `file.go:25-35`, inside an inline code span. The docs
# write every citation that way, and prose naming a file without a span is a
# mention rather than a citation.
DOC_CITE_RE = re.compile(
    r"`([A-Za-z0-9_./+-]+\.(?:c|h|go|py|sh|mk))(?::(\d+)(?:-(\d+))?)?`")

# A documented invocation. Only a line that opens with the command counts: a
# command quoted inside a verbatim error message is a reproduction, and the
# flags later in that sentence belong to a different subcommand.
DOC_INVOKE_RE = re.compile(
    r"^[ \t]*(?:\$[ \t]*)?(?:sudo[ \t]+(?:-\S+[ \t]+)*)?"
    r"python3?[ \t]+(?:-\S+[ \t]+)*"
    r"(tools/[a-z_0-9]+\.py)([^\n|;&]*)$", re.M)

# An inline code span, outside any fenced block. The prose runs commands in
# these as often as it shows them in a block: measured over the committed
# pages, the fenced blocks carry 129 invocations and another 39 appear only in
# a span, among them the tools/crash_ctl.py line this check's own CI comment
# cites. A span is matched against DOC_INVOKE_RE the same way a block line is,
# so the two sources share one definition of what an invocation is.
DOC_SPAN_RE = re.compile(r"`([^`\n]+)`")

# A cited path that resolves in no tree, with the reason it never will. Each
# one is a real reference and none of them is a defect, so leaving them
# unlisted would make this check report twenty offenders on a clean run and
# train a reader to ignore it.
#
# An entry excluding nothing is dead and is an offence, checked below over the
# committed pages. Three were removed when the count was first taken. Two of
# them, run_all.sh and build_all.sh, were declared as generated into
# harnesses/ by the harness phase, and the tree commits harnesses/run_all.sh
# and harnesses/build_all.sh, so all thirteen citations of them resolve and
# the exclusion was never consulted. The third, injected.c, is cited by no
# page. Removing an entry narrows the check: a citation of that basename that
# resolves nowhere is now reported.
CITATION_EXCLUSIONS = {
    "repro.c":
        "a reproducer the poc phase generates per crash under "
        "artifacts/pocs/, so no checkout carries it",
    "measure_sizes.sh":
        "a probe script ioctl_inventory.py generates beside its own output",
    "_nvoc.c":
        "the suffix NVOC gives every generated class file, written as a "
        "pattern and not as one file",
    "kernel/kcov.c":
        "Linux, which this repository does not vendor",
    "drivers/gpu/drm/drm_ioctl.c":
        "Linux, which this repository does not vendor",
    "drivers/gpu/drm/drm_auth.c":
        "Linux, which this repository does not vendor",
}


# A tool the docs invoke that declares no argparse parser, with the reason.
# Kept apart from AGENT_TOOL_EXCLUSIONS so the two checks state their own
# surface: a brief and a page do not invoke the same set of tools.
DOC_TOOL_EXCLUSIONS = {
    "tools/selftest.py":
        "a unittest module. It is run by `python3 tools/selftest.py` with no "
        "argument of its own, and unittest.main() takes the parsing",
    "tools/gspwn_config.py":
        "takes no argument. Run bare it prints the effective configuration, "
        "and it declares no parser for a surface to be checked against",
    "tools/register_check.py":
        "reads sys.argv by hand at main(). Its positional paths and its two "
        "help flags are literals there, so no parser carries them and no "
        "import reaches them",
}


def doc_files():
    """-> every documentation page, generated pages included.

    A generated page carries citations its generator wrote, and a stale one
    there is the same defect as a stale one in a hand-written page.
    """
    out = []
    for base, _dirs, names in os.walk(DOC_ROOT):
        out.extend(os.path.join(base, name) for name in sorted(names)
                   if name.endswith((".md", ".mdx")))
    return sorted(out)


def _blank_fences(text):
    """-> the text with fenced blocks blanked to the same line count."""
    return DOC_FENCE_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)


DOC_FROM_FENCE = "fence"
DOC_FROM_SPAN = "span"

# Info strings a fenced block carries that make its body a shell transcript.
# Measured over the committed pages: no block this check skips carries any
# other info string, so a wider filter here recovers nothing. The invocations
# it was missing were in inline spans, which is what doc_invocations reads.
DOC_SHELL_INFO = ("", "sh", "bash", "console", "shell")


def doc_invocations(text):
    """-> [(line, source, shown text, tool, argument text)] for one page.

    Both places a page runs a tool, read through one definition of what an
    invocation is. A fenced block contributes each line opening with the
    command, joined across a trailing backslash. An inline code span
    contributes its whole body where the body opens with the command, which
    is how the prose writes a one-line invocation mid-sentence.

    A span inside a fenced block is read once, as part of the block: the
    spans are taken from the text with every block blanked.
    """
    found = []
    for fence in DOC_FENCE_RE.finditer(text):
        body = fence.group(0)
        if body.splitlines()[0].strip("`").strip() not in DOC_SHELL_INFO:
            continue
        at = text[:fence.start()].count("\n") + 1
        joined = re.sub(r"\\\n[ \t]*", " ", body)
        for match in DOC_INVOKE_RE.finditer(joined):
            found.append((at + joined[:match.start()].count("\n"),
                          DOC_FROM_FENCE, match.group(0).strip(),
                          match.group(1), match.group(2)))

    outside = _blank_fences(text)
    for span in DOC_SPAN_RE.finditer(outside):
        match = DOC_INVOKE_RE.match(span.group(1))
        if match is None:
            continue
        found.append((outside[:span.start()].count("\n") + 1,
                      DOC_FROM_SPAN, span.group(0).strip(),
                      match.group(1), match.group(2)))
    return sorted(found)


def _vendored_trees():
    """-> every vendored source tree present, by path."""
    if not os.path.isdir(VENDOR_DIR):
        return []
    return [os.path.join(VENDOR_DIR, name)
            for name in sorted(os.listdir(VENDOR_DIR))
            if os.path.isdir(os.path.join(VENDOR_DIR, name))]


def _index_sources(trees):
    """-> ({tree-relative path: full path}, {basename: [full path]})."""
    by_path, by_base = {}, {}
    roots = list(trees) + [REPO_ROOT]
    skip = {".git", "node_modules", "__pycache__", ".claude", "artifacts",
            "dist", ".astro", "tmp", "thoughts", ".github"}
    for top in roots:
        for base, dirs, names in os.walk(top):
            dirs[:] = [d for d in dirs if d not in skip]
            for name in names:
                if not name.endswith(VENDOR_EXT):
                    continue
                full = os.path.join(base, name)
                rel = os.path.relpath(full, top).replace(os.sep, "/")
                by_path.setdefault(rel, full)
                by_base.setdefault(name, []).append(full)
    return by_path, by_base


def _resolve_citation(cited, by_path, by_base):
    """-> [full path] a cited path can mean, most specific first."""
    if cited in by_path:
        return [by_path[cited]]
    suffix = [v for k, v in by_path.items() if k.endswith("/" + cited)]
    if suffix:
        return suffix
    return list(by_base.get(os.path.basename(cited), []))


def _cited_line(path, number):
    """-> the cited line, or None when the file is shorter than that."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle, 1):
                if index == number:
                    return line.rstrip()
    except OSError:
        return None
    return None


def check_citations():
    """Every file and line the docs cite resolves in a vendored source tree."""
    trees = _vendored_trees()
    if not trees:
        print("citations: no vendored source tree under %s. artifacts/ is "
              "gitignored, so a clean checkout carries none and this check "
              "settles nothing. It runs on a provisioned machine, which is "
              "where a re-vendored tree moves the line numbers."
              % os.path.relpath(VENDOR_DIR, REPO_ROOT))
        return 0

    by_path, by_base = _index_sources(trees)
    pages = doc_files()
    offenders = []
    files_cited = lines_cited = excluded = 0
    per_exclusion = {name: 0 for name in CITATION_EXCLUSIONS}

    for path in pages:
        rel = os.path.relpath(path, REPO_ROOT).replace(os.sep, "/")
        with open(path, encoding="utf-8") as handle:
            text = _blank_fences(handle.read())
        for match in DOC_CITE_RE.finditer(text):
            cited, start, end = match.group(1), match.group(2), match.group(3)
            number = text[:match.start()].count("\n") + 1
            hits = _resolve_citation(cited, by_path, by_base)
            if not hits:
                # The exclusions are consulted only here, where the path
                # resolved in no tree. Every reason states why a path never
                # will: it is generated by a phase, fabricated by a fixture,
                # or belongs to Linux. Consulting them before resolution
                # matched on basename, so a vendored file named run_all.sh,
                # build_all.sh, measure_sizes.sh or repro.c was excluded in
                # any tree, which is wider than any of those reasons.
                key = (cited if cited in CITATION_EXCLUSIONS
                       else os.path.basename(cited))
                if key in CITATION_EXCLUSIONS:
                    excluded += 1
                    per_exclusion[key] += 1
                    continue
                offenders.append((rel, number, match.group(0),
                                  "resolves in no tree, and no exclusion "
                                  "declares why"))
                continue
            if start is None:
                files_cited += 1
                continue
            if len(hits) > 1:
                offenders.append((rel, number, match.group(0),
                                  "names %d files, so the line number is "
                                  "ambiguous. Qualify the path"
                                  % len(hits)))
                continue
            lines_cited += 1
            first, last = int(start), int(end) if end else int(start)
            if last < first:
                # A reversed range. The guard below reads the end of the
                # range, so a citation whose end precedes its start resolves
                # there and leaves the start line unread, and calling .strip()
                # on that None exits 2 with a traceback.
                offenders.append((rel, number, match.group(0),
                                  "the range ends at %d and starts at %d"
                                  % (last, first)))
                continue
            if _cited_line(hits[0], last) is None:
                offenders.append((rel, number, match.group(0),
                                  "the file has fewer than %d lines" % last))
                continue
            opening = _cited_line(hits[0], first)
            if opening is None or not opening.strip():
                offenders.append((rel, number, match.group(0),
                                  "line %s is blank, so the citation has "
                                  "drifted" % start))

    print("citations: %d page(s), %d file citation(s) and %d line "
          "citation(s) over %d vendored tree(s), %d declared exclusion(s)"
          % (len(pages), files_cited, lines_cited, len(trees),
             len(CITATION_EXCLUSIONS)))
    print("citations: %d citation instance(s) matched a declared exclusion"
          % excluded)
    print()
    print("  %-30s %9s  %s" % ("excluded", "instances", "reason"))
    print("  %-30s %9s  %s" % ("-" * 30, "-" * 9, "-" * 6))
    for name in sorted(CITATION_EXCLUSIONS):
        print("  %-30s %9d  %s"
              % (name, per_exclusion[name], CITATION_EXCLUSIONS[name]))
    print()

    # An exclusion matching nothing is dead, and it hides the reason it was
    # written: either the path now resolves, which makes the stated reason
    # false, or no page cites it any more. Both are reported here so the set
    # cannot drift into a list of paths nobody has read. The assertion runs
    # over the committed pages only, since a caller pointing DOC_ROOT at one
    # page necessarily leaves every exclusion unmatched.
    if _pinned_artefact(DOC_ROOT, COMMITTED_DOC_ROOT):
        for name in sorted(CITATION_EXCLUSIONS):
            if per_exclusion[name]:
                continue
            offenders.append(("tools/regression_check.py", 0,
                              "CITATION_EXCLUSIONS[%r]" % name,
                              "excludes nothing over the committed pages. "
                              "Either the path now resolves, or no page "
                              "cites it. Delete the entry"))

    if not offenders:
        print("citations: OK")
        return 0
    for rel, number, cite, fault in offenders:
        print("%s:%d: %s %s" % (rel, number, cite, fault), file=sys.stderr)
    print("citations: %d offending citation(s)" % len(offenders),
          file=sys.stderr)
    return 1


def check_commands():
    """Every tool invocation the docs show parses against the tool."""
    pages = doc_files()
    parsers = {}
    offenders = []
    counted = fenced = spanned = 0
    tools = set()
    shapes = []

    for path in pages:
        rel = os.path.relpath(path, REPO_ROOT).replace(os.sep, "/")
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for number, source, shown, tool, rest in doc_invocations(text):
            counted += 1
            if source == DOC_FROM_FENCE:
                fenced += 1
            else:
                spanned += 1
            tools.add(tool)
            try:
                words = shlex.split(rest, comments=False, posix=False)
            except ValueError:
                words = rest.split()
            if tool in DOC_TOOL_EXCLUSIONS:
                continue
            for fault in _resolve_command(tool, words, parsers, shapes):
                offenders.append((rel, number, shown, fault))

    if not counted:
        raise CheckInput(
            "no tool invocation in any page under %s. A documentation set "
            "showing no command makes every tool agree with it vacuously, "
            "and the extractor is then the thing to fix."
            % os.path.relpath(DOC_ROOT, REPO_ROOT))

    print("commands: %d page(s), %d invocation(s) over %d tool(s), "
          "%d declared exclusion(s)"
          % (len(pages), counted, len(tools), len(DOC_TOOL_EXCLUSIONS)))
    print("commands: %d in a fenced block, %d in an inline code span, %d "
          "naming its subcommand as a metavariable"
          % (fenced, spanned, len(shapes)))
    print()
    print("  %-24s %s" % ("excluded", "reason"))
    print("  %-24s %s" % ("-" * 24, "-" * 6))
    for name in sorted(DOC_TOOL_EXCLUSIONS):
        print("  %-24s %s" % (name, DOC_TOOL_EXCLUSIONS[name]))
    print()

    if not offenders:
        print("commands: OK")
        return 0
    for rel, number, command, fault in offenders:
        print("%s:%d: %s: %s" % (rel, number, command, fault),
              file=sys.stderr)
    print("commands: %d offending invocation(s)" % len(offenders),
          file=sys.stderr)
    return 1


CHECKS = {
    "names": check_names,
    "pins": check_pins,
    "coverage": check_coverage,
    "derived": check_derived,
    "families": check_families,
    "pages": check_pages,
    "stale": check_stale,
    "harnesses": check_harnesses,
    "agents": check_agents,
    "figures": check_figures,
    "citations": check_citations,
    "commands": check_commands,
}

# The order `all` runs them in, and the order the module docstring and the CI
# steps present them in. It follows the dependency between them, in three
# bands.
#
# The first six read the description set. names and pins read it alone,
# coverage, derived and families join it against the artefacts it was
# generated from, and pages renders those artefacts.
#
# stale and harnesses follow because neither reads the description set: stale
# reads the provenance record against the artefacts the first six compare, and
# harnesses reads the Track U seam, which the first seven never touch.
#
# agents, figures, citations and commands close the order because each reads
# prose against something the bands above have already settled. agents and
# commands resolve a command line against the tool's own argparse parser,
# figures compares a stated surface figure against the inventories coverage
# reads, and citations resolves a cited path and line in a vendored source
# tree. A prose failure reported before the artefact failure that caused it
# names the page where the generator is the thing to edit.
CHECK_ORDER = ("names", "pins", "coverage", "derived", "families", "pages",
               "stale", "harnesses", "agents", "figures",
               "citations", "commands")


def check_order():
    """-> every registered check, in CHECK_ORDER, unlisted ones last.

    A check added to CHECKS and not to CHECK_ORDER still runs. Dropping it
    would make the registry and this tuple disagree silently, which is the
    class of defect the whole tool exists to report.
    """
    return ([name for name in CHECK_ORDER if name in CHECKS]
            + sorted(set(CHECKS) - set(CHECK_ORDER)))


def build_parser():
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(__doc__.splitlines()[1:]))
    # -v is declared twice on purpose: once on the main parser and once on
    # every subcommand through this parent, so both `-v names` and `names -v`
    # work. argparse refuses the flag after the subcommand otherwise, and the
    # usage line gives no hint that the position matters.
    verbose = argparse.ArgumentParser(add_help=False)
    # SUPPRESS, so an absent flag on the subcommand leaves the namespace
    # alone. A store_true default of False here would overwrite the main
    # parser's True and silence `regression_check.py -v names`.
    verbose.add_argument("-v", "--verbose", action="store_true",
                         default=argparse.SUPPRESS,
                         help="log what each artefact read contributed")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="log what each artefact read contributed")
    sub = parser.add_subparsers(dest="check", required=True)
    for name in check_order():
        sub.add_parser(name, parents=[verbose],
                       help=(CHECKS[name].__doc__ or "").strip())
    sub.add_parser("all", parents=[verbose],
                   help="run every check and fail if any one fails")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s")

    order = check_order() if args.check == "all" else [args.check]
    worst = 0
    for index, name in enumerate(order):
        if index:
            print()
        if len(order) > 1:
            print("== %s ==" % name)
        try:
            worst = max(worst, CHECKS[name]())
        except CheckInput as exc:
            print("%s: cannot run: %s" % (name, exc), file=sys.stderr)
            worst = max(worst, 2)
        except Exception:  # noqa: BLE001  (the reason is below)
            # An artefact shaped in a way the check did not anticipate is the
            # same condition as an absent one: the check could not run, which
            # is exit 2. Letting it propagate exits 1, which CI reads as an
            # offending entry, and under `all` it abandons every check after
            # this one, so one broken artefact hides four working verdicts.
            # The traceback goes to stderr, because the shape that produced it
            # is the thing to fix and the line number names it.
            print("%s: cannot run: unexpected %s"
                  % (name, sys.exc_info()[1].__class__.__name__),
                  file=sys.stderr)
            traceback.print_exc()
            worst = max(worst, 2)
    return worst


if __name__ == "__main__":
    sys.exit(main())
