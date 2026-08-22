#!/usr/bin/env python3
"""Build seed syz-programs for the NVIDIA driver, from two sources.

A trace and the surface artefacts each carry half of what a seed needs, and
neither half works alone.

    convert   strace of a real CUDA workload -> one seed program. Supplies a
              real fd lifecycle and the real order of the escapes a workload
              issues.
    chains    surface/rm-chains.json and rm-control-rank.json -> one
              program per allocation chain, each prologue built once and
              followed by the control commands that chain reaches. Supplies the
              command identity a trace cannot.

Why the split. NV_ESC_RM_CONTROL and NV_ESC_RM_ALLOC dispatch on a field inside
the parameter struct: NVOS54_PARAMETERS.cmd selects one of 531 control commands
and NVOS64_PARAMETERS.hClass selects one of 155 allocation classes. strace does
not decode NVIDIA parameter structs, so neither field ever appears in the trace
text, and the request number is identical for every leaf behind it. `convert`
reads the request number and nothing else, so a traced control call cannot name
its command however the map is written. tools/ioctl_map.json records those two
escapes under `comment_multiplexers` rather than under a call name, and
`convert` writes a comment naming the escape and the selector field it could
not see.

fd tracking in `convert`:
             openat("/dev/nvidiaX") = N  ->  resource r<k>
             ioctl(N, 0x....)            ->  ioctl$NAME(r<k>, 0x...., ...)

The prescribed trace command is `strace -v -f` (agents/seeds.md), so both
of its output quirks are handled here: `[pid N]` prefixes are stripped and
fd state is tracked per process (fds are per-process namespaces), and the
symbolic `_IOC(dir, type, nr, size)` form strace -v prints for requests it
does not know is decoded back into the request number before lookup.
"""
import argparse
import json
import logging
import os
import re
import sys
import tempfile

logger = logging.getLogger("trace2seed")

PID_RE = re.compile(r"^\s*\[pid\s+(\d+)\]\s*")
OPEN_RE = re.compile(r'openat\([^,]+,\s*"((?:/dev/nvidia|/dev/dri)[^"]*)"[^)]*\)\s*=\s*(\d+)')
IOCTL_RE = re.compile(r"ioctl\((\d+),\s*(0x[0-9a-fA-F]+|_IOC\([^)]*\)|\w+)")
IOCTL_SYM_RE = re.compile(r"_IOC\(([^,]+),([^,]+),([^,]+),([^)]+)\)")
CLOSE_RE = re.compile(r"close\((\d+)")

DEV_TO_DESC = {
    "/dev/nvidiactl": "openat$nvidiactl",
    "/dev/nvidia-uvm": "openat$nvidia_uvm",
    "/dev/nvidia-uvm-tools": "openat$nvidia_uvm_tools",
}

# Devices the describe phase is forbidden to model (agents/describe.md):
# seeds referencing them fail the syzkaller-parse gate.
OUT_OF_SCOPE = {
    "/dev/nvidia-modeset": "nvidia-modeset out of scope",
}

# Linux ioctl encoding: request = dir<<30 | size<<16 | type<<8 | nr.
_IOC_DIR = {"_IOC_NONE": 0, "_IOC_WRITE": 1, "_IOC_READ": 2}

# openat's first argument. syzkaller prints AT_FDCWD (-100) as the unsigned
# 64-bit value, and a seed missing this argument does not parse at all.
AT_FDCWD = "0xffffffffffffff9c"

# The section of tools/ioctl_map.json holding the multiplexer request numbers,
# written by tools/ioctl_inventory.py. Its key starts with "comment" so the
# loaders that iterate request-number entries skip it; this module reads it by
# name.
MULTIPLEXER_KEY = "comment_multiplexers"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MAP = os.path.join(REPO_ROOT, "tools", "ioctl_map.json")
DEFAULT_DESC = os.path.join(REPO_ROOT, "descriptions" )
DEFAULT_CHAINS = os.path.join(REPO_ROOT, "surface", "rm-chains.json")
DEFAULT_RANK = os.path.join(REPO_ROOT, "surface", "rm-control-rank.json")
DEFAULT_OUT_DIR = os.path.join(REPO_ROOT, "artifacts", "seeds")

# syzkaller refuses a program above prog.MaxCalls, so a chain's commands are
# split across programs that each repeat the prologue. 40 is syzkaller's
# default, taken from memory: no syzkaller tree exists in this checkout to
# read prog.MaxCalls from, and no emitted program has been through
# prog.Deserialize. The flag and the environment variable exist because of
# that — the campaign owns the value, and a machine with a syzkaller tree
# should read it there and set GSPWN_SEED_MAX_CALLS rather than trust this.
DEFAULT_MAX_CALLS = 40
MAX_CALLS_VAR = "GSPWN_SEED_MAX_CALLS"

# The floor a chain-shaped program can be built at: one openat, one allocation
# and one control command. Below that buildable_paths drops every path and the
# run writes nothing while exiting 0, which reads to a phase gate as an empty
# bank successfully produced.
MIN_MAX_CALLS = 3


def _env_max_calls():
    """-> (value, error message or None) for MAX_CALLS_VAR.

    Read without raising, because this runs at import: a bad value used to
    end the process in a traceback before argparse had printed so much as a
    usage line, and every other bad input to this tool fails as a SeedError
    naming what was wrong. cmd_chains raises the message; `convert` does not
    read the variable and is not failed by it.
    """
    raw = os.getenv(MAX_CALLS_VAR)
    if raw is None:
        return DEFAULT_MAX_CALLS, None
    try:
        return int(raw), None
    except ValueError:
        return DEFAULT_MAX_CALLS, (
            "%s must be a whole number of calls per program, and was %r. "
            "Unset it to use the default of %d, or pass --max-calls."
            % (MAX_CALLS_VAR, raw, DEFAULT_MAX_CALLS))


MAX_CALLS, MAX_CALLS_ERROR = _env_max_calls()

# The device a chain-shaped program opens. Every allocation variant a chain
# step needs takes fd_nv and every control variant takes fd_nvidiactl, and
# fd_nvidiactl is declared a subtype of fd_nv, so one open covers both.
CHAIN_DEVICE = "/dev/nvidiactl"
CHAIN_DEVICE_CALL = "openat$nvidiactl"

ALLOC_PREFIX = "ioctl$NV_ESC_RM_ALLOC_"
CONTROL_PREFIX = "ioctl$NV_ESC_RM_CONTROL_"

CHAIN_FILE_PREFIX = "chain-"
CHAIN_FILE_SUFFIX = ".syz"

# write_atomic's temp file, named so a run interrupted between the write and
# the rename leaves something the next run can recognise and report.
TEMP_PREFIX = ".trace2seed-"
TEMP_SUFFIX = ".tmp"

# A declared syzlang call and the two arguments a seed has to reproduce: the fd
# resource it consumes and the pinned request number. Reading the request
# number out of the description set rather than hardcoding it means a driver
# bump that moves a struct size cannot leave this tool emitting the old number.
DECL_RE = re.compile(
    r"^(ioctl\$[A-Za-z0-9_]+)\(fd\s+(\w+),\s*cmd\s+const\[(0x[0-9a-fA-F]+)\]",
    re.M)


class SeedError(Exception):
    """An input this tool needs is absent, unreadable or inconsistent."""


def parse_request(raw):
    """Return the ioctl request number for a strace-printed request
    argument, or None when it cannot be interpreted (e.g. a symbolic
    name like TCGETS). Handles the plain hex/decimal form and the
    symbolic _IOC(dir, type, nr, size) form; fields may be hex or
    decimal, and dir may combine _IOC_READ|_IOC_WRITE or be numeric."""
    raw = raw.strip()
    if raw.startswith("_IOC("):
        m = IOCTL_SYM_RE.fullmatch(raw)
        if not m:
            return None
        dir_s, type_s, nr_s, size_s = m.groups()
        d = 0
        for part in dir_s.split("|"):
            part = part.strip()
            if part in _IOC_DIR:
                d |= _IOC_DIR[part]
            else:
                try:
                    d |= int(part, 0)
                except ValueError:
                    return None
        fields = []
        for s in (type_s, nr_s, size_s):
            try:
                fields.append(int(s.strip(), 0))
            except ValueError:
                return None
        typ, nr, size = fields
        return (d << 30) | (size << 16) | (typ << 8) | nr
    try:
        return int(raw, 0)
    except ValueError:
        return None


def dev_desc(path):
    if path in DEV_TO_DESC:
        return DEV_TO_DESC[path]
    if re.fullmatch(r"/dev/nvidia\d+", path):
        return "openat$nvidia"
    if path.startswith("/dev/dri/"):
        return "openat$dri"
    return None


def load_map(path):
    """-> (name map, multiplexer map) from tools/ioctl_map.json.

    Lookups use hex(value) (lowercase); normalise both sets of keys the same
    way so uppercase-hex keys don't silently yield 100% unmapped.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError) as exc:
        raise SeedError("cannot read the ioctl map %s: %s" % (path, exc))
    names = {k.lower(): v for k, v in raw.items()
             if not k.startswith("comment")}
    section = raw.get(MULTIPLEXER_KEY) or {}
    multiplexers = {k.lower(): v
                    for k, v in (section.get("requests") or {}).items()}
    overlap = sorted(set(names) & set(multiplexers))
    if overlap:
        raise SeedError(
            "%s gives %d request number(s) both a call name and a multiplexer "
            "record, so a traced call would be reported two ways: %s"
            % (path, len(overlap), ", ".join(overlap)))
    logger.info("ioctl map %s: %d call name(s), %d multiplexer request "
                "number(s)", path, len(names), len(multiplexers))
    return names, multiplexers


def multiplexer_note(record, request, var):
    """The line a traced multiplexer call becomes.

    Not a call: the identity the seed would need is the selector field inside
    the parameter struct, and it is not in the trace. Naming the escape here
    was the defect this replaces, because no description declares that name.
    """
    return ("# %s on %s, request %s: %s.%s selects the command and strace "
            "does not decode it, so no %s* call can be named from this trace "
            "(%d-byte parameter form)"
            % (record["escape"], var, request, record["param_struct"],
               record["selector_field"], record["variant_prefix"],
               request_size(request)))


def request_size(request):
    """-> the parameter size the ioctl request number encodes, or 0.

    Linux packs it as request = dir<<30 | size<<16 | type<<8 | nr. Two
    request numbers that differ only in this field are two calling forms of
    one escape over two parameter layouts, which is the distinction the
    multiplexer header below reports.
    """
    try:
        return (int(request, 0) >> 16) & 0x3fff
    except (TypeError, ValueError):
        return 0


def convert(trace_text, ioctl_map, multiplexers=None):
    """-> the seed program text for one strace file.

    `multiplexers` is the map's `comment_multiplexers` section keyed by request
    number. Omitted, every request number is looked up in `ioctl_map` alone,
    which is what a caller passing a hand-built map wants.
    """
    multiplexers = multiplexers or {}
    lines = []
    seen_multiplexers = {}
    fd_res = {}        # (pid, fd) -> resource var name; fds are per-process
    res_n = 0
    for raw in trace_text.splitlines():
        pid = ""
        pm = PID_RE.match(raw)
        if pm:
            pid = pm.group(1)
            raw = raw[pm.end():]
        m = OPEN_RE.search(raw)
        if m:
            path, fd = m.group(1), m.group(2)
            if path in OUT_OF_SCOPE:
                lines.append("# skipped: " + OUT_OF_SCOPE[path])
                continue
            desc = dev_desc(path)
            if desc is None:
                continue
            var = "r%d" % res_n
            res_n += 1
            fd_res[(pid, fd)] = var
            # openat takes four arguments, the first being the directory fd.
            # Emitting three produced seeds that syz-manager refuses to parse,
            # so the whole bank failed the seeds gate for a reason that looked
            # like a description problem. AT_FDCWD is -100, which syzkaller
            # writes as the unsigned 64-bit value below.
            lines.append('%s = %s(%s, &AUTO=\'%s\\x00\', 0x2, 0x0)'
                         % (var, desc, AT_FDCWD, path))
            continue
        m = IOCTL_RE.search(raw)
        if m and (pid, m.group(1)) in fd_res:
            fd = m.group(1)
            value = parse_request(m.group(2))
            num = hex(value) if value is not None else m.group(2).lower()
            var = fd_res[(pid, fd)]
            name = ioctl_map.get(num)
            if name:
                lines.append("%s(%s, %s, &AUTO)" % (name, var, num))
            elif num in multiplexers:
                record = multiplexers[num]
                # Keyed by request number and not by escape name: one escape
                # can appear under two request numbers that differ only in
                # the parameter size, and which form a workload issues is the
                # one thing about a multiplexer call a trace does record.
                seen_multiplexers[num] = seen_multiplexers.get(num, 0) + 1
                lines.append(multiplexer_note(record, num, var))
            else:
                lines.append("# unmapped ioctl %s on fd %s" % (num, fd))
            continue
        m = CLOSE_RE.search(raw)
        if m and (pid, m.group(1)) in fd_res:
            lines.append("close(%s)" % fd_res.pop((pid, m.group(1))))
    if seen_multiplexers:
        lines = multiplexer_header(seen_multiplexers, multiplexers) + lines
    return "\n".join(lines) + "\n"


def multiplexer_header(counts, multiplexers):
    """The block a seed carrying multiplexer calls opens with.

    `counts` is keyed by request number. Where one escape appears under more
    than one request number the block names each calling form the trace used,
    because the surface model does not carry every class behind every form:
    the describe phase emits one variant per allocation class over the wider
    parameter struct and the narrower one is modelled for whichever classes
    the inventory measured it for. A workload issuing the narrower form
    reaches an allocation route that may have no declared variant at all, and
    without this line nothing in the run says which form was seen.
    """
    total = sum(counts.values())
    by_escape = {}
    for request in counts:
        by_escape.setdefault(multiplexers[request]["escape"], []).append(
            request)
    summary = []
    for escape in sorted(by_escape):
        summary.append("%s x%d"
                       % (escape, sum(counts[r] for r in by_escape[escape])))
    head = [
        "# %d call(s) here reached a dispatching escape whose command is "
        "inside the parameter struct (%s)." % (total, ", ".join(summary)),
        "# A trace carries the object chain and the fd lifecycle and cannot "
        "carry those commands.",
        "# The command-targeted programs come from "
        "`tools/trace2seed.py chains`.",
    ]
    for escape in sorted(by_escape):
        requests = sorted(by_escape[escape])
        if len(requests) < 2:
            continue
        head.append(
            "# %s was traced under %d calling forms: %s. They are separate "
            "parameter layouts and the description set declares a variant "
            "per class for each form it carries, so a class reached only "
            "through one of them is modelled only there."
            % (escape, len(requests),
               ", ".join("%s (%s, %d bytes, x%d)"
                         % (r, multiplexers[r]["param_struct"],
                            request_size(r), counts[r])
                         for r in requests)))
    return head


def declared_calls(desc_dir):
    """-> {variant name: (fd resource, request number)} over the description set.

    A local parser rather than an import of tools/regression_check.py: that
    module pulls in surface_cov and the whole inventory-loading path to answer
    a question this one asks of two regexes, and this tool runs on a
    workstation with no artefacts beyond the description files.
    """
    if not os.path.isdir(desc_dir):
        raise SeedError(
            "no description set at %s. Run the describe phase, or pass "
            "--descriptions at the set you want the call names read from."
            % desc_dir)
    files = sorted(name for name in os.listdir(desc_dir)
                   if name.endswith(".txt"))
    if not files:
        raise SeedError("no .txt description files under %s" % desc_dir)
    calls = {}
    for name in files:
        with open(os.path.join(desc_dir, name), encoding="utf-8") as handle:
            for match in DECL_RE.finditer(handle.read()):
                calls[match.group(1)] = (match.group(2),
                                         match.group(3).lower())
    logger.info("description set %s: %d file(s), %d declared ioctl call(s)",
                desc_dir, len(files), len(calls))
    return calls


def load_json(path, what):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise SeedError("cannot read %s (%s): %s" % (what, path, exc))


def chain_paths(chains):
    """-> {chain path: [(internal class, [handlers])]} over the chain records.

    The path is the ordered tuple of external classes an unprivileged process
    allocates to reach the class, read straight off `chain`. Records with an
    `unallocatable_reason`, with no chain, or owning no command are left out
    and counted by the caller.
    """
    records = chains.get("chains")
    if not isinstance(records, list):
        raise SeedError(
            "the chains artefact holds no `chains` list. Expected schema "
            "gspwn.rm-chains/1 from `python3 tools/object_graph.py chains`, "
            "got top-level keys %s" % sorted(chains))
    paths = {}
    for record in records:
        handlers = [c["handler"] for c in record.get("commands") or []]
        if record.get("unallocatable_reason") or not record.get("chain"):
            continue
        if not handlers:
            continue
        path = tuple(step["external_class"] for step in record["chain"])
        paths.setdefault(path, []).append((record["internal_class"], handlers))
    return paths


def unreached(chains):
    """-> [(owning class, reason, command count)] the chain artefact records.

    Read from `unresolved_owning_classes` and not from the per-record
    `unallocatable_reason`: a class with no RS_ENTRY row owns commands the
    records carry under no internal class at all, so scanning the records alone
    accounts for two of the four and silently loses fifteen commands.
    """
    return [(row["owning_class"], row["reason"], row["command_count"])
            for row in chains.get("unresolved_owning_classes") or []]


def reachable(paths, path):
    """-> the handlers a program allocating `path` can call.

    Every chain is a walk from the file descriptor down one parent edge at a
    time, so a class whose own chain is a prefix of this one is allocated on
    the way and its commands are reachable without a second prologue. That is
    where the chain shape pays for itself: Subdevice's three allocations also
    build RmClientResource and Device.
    """
    out = []
    for other, entries in paths.items():
        if len(other) <= len(path) and path[:len(other)] == other:
            for _internal, handlers in entries:
                out.extend(handlers)
    return out


def group_chains(paths):
    """-> [(path, [handlers])], every chained command assigned to one prologue.

    Greedy on yield per allocation, the same rule the `cumulative_reach` block
    of rm-chains.json is computed with: take the prologue that reaches the most
    still-unassigned commands per allocation it costs, assign them, repeat.
    Ties break on the command count, then the shorter prologue, then the path,
    so the grouping does not depend on the order the records were read in.
    """
    pending = set()
    for entries in paths.values():
        for _internal, handlers in entries:
            pending.update(handlers)
    reach = {path: reachable(paths, path) for path in paths}
    groups = []
    while pending:
        best, best_key = None, None
        for path in sorted(paths):
            gain = [h for h in reach[path] if h in pending]
            if not gain:
                continue
            key = (-len(set(gain)) / float(len(path)), -len(set(gain)),
                   len(path), path)
            if best_key is None or key < best_key:
                best, best_key = path, key
        if best is None:
            break
        taken = [h for h in dict.fromkeys(reach[best]) if h in pending]
        pending.difference_update(taken)
        groups.append((best, taken))
    return groups


def order_by_rank(handlers, ranks):
    """Rank 1 first. A handler the ranking omits sorts after every ranked one,
    by name, so an incomplete ranking reorders and never drops."""
    return sorted(handlers,
                  key=lambda h: (0, ranks[h], h) if h in ranks
                  else (1, 0, h))


def chain_program(path, handlers, declared, first, total):
    """-> the text of one chain-shaped program."""
    alloc = [(ALLOC_PREFIX + cls, cls) for cls in path]
    head = [
        "# chain-shaped program: %d allocation(s) reaching %s"
        % (len(path), path[-1]),
        "# prologue: %s" % " -> ".join(path),
        "# commands %d-%d of %d, ordered by "
        "surface/rm-control-rank.json"
        % (first, first + len(handlers) - 1, total),
        "# every parameter struct is written &AUTO, so this text wires no "
        "handles. descriptions/nvidia_structs.txt types "
        "hObjectParent and hObjectNew as nv_handle resources, which is what "
        "syzkaller's resource machinery would need to carry a parent handle "
        "from one call to the next. Whether it does so for an argument "
        "written &AUTO has not been checked against syzkaller's prog text "
        "parser: no syzkaller tree exists in this repository. If it does "
        "not, the first execution allocates with a zero parent handle and "
        "the chain is a prologue in name only.",
    ]
    body = ["r0 = %s(%s, &AUTO='%s\\x00', 0x2, 0x0)"
            % (CHAIN_DEVICE_CALL, AT_FDCWD, CHAIN_DEVICE)]
    for name, _cls in alloc:
        body.append("%s(r0, %s, &AUTO)" % (name, declared[name][1]))
    for handler in handlers:
        name = CONTROL_PREFIX + handler
        body.append("%s(r0, %s, &AUTO)" % (name, declared[name][1]))
    return "\n".join(head + body) + "\n"


def all_commands(paths):
    """-> the set of control commands the chain paths carry, each once."""
    return {handler
            for entries in paths.values()
            for _internal, handlers in entries
            for handler in handlers}


def buildable_paths(paths, declared, max_calls):
    """-> (emittable paths, undeclared call counts, oversize paths, blocked).

    Run before the grouping, not after it. A chain whose deepest allocation has
    no description would otherwise be picked as the best prologue and then
    dropped, taking with it the commands of every shorter chain it covered,
    which a prologue that is buildable would have carried.

    The undeclared counts are per call name and answer "how many commands does
    this missing description block". They are not a total: a path whose
    prologue is missing two descriptions books its command count against each
    of them, and one command blocked by two names is still one command.
    `blocked` is the set of commands an undeclared name stood in front of,
    each once, which is what a total is drawn from.
    """
    kept, undeclared, oversize = {}, {}, []
    blocked = set()
    for path, entries in sorted(paths.items()):
        commands = [h for _internal, handlers in entries for h in handlers]
        missing = [ALLOC_PREFIX + cls for cls in path
                   if ALLOC_PREFIX + cls not in declared]
        if missing:
            for name in missing:
                undeclared[name] = undeclared.get(name, 0) + len(commands)
            blocked.update(commands)
            continue
        if max_calls - 1 - len(path) < 1:
            oversize.append((path, len(commands)))
            continue
        surviving = []
        for internal, handlers in entries:
            wanted = []
            for handler in handlers:
                name = CONTROL_PREFIX + handler
                if name in declared:
                    wanted.append(handler)
                else:
                    undeclared[name] = undeclared.get(name, 0) + 1
                    blocked.add(handler)
            if wanted:
                surviving.append((internal, wanted))
        if surviving:
            kept[path] = surviving
    return kept, undeclared, oversize, blocked


def build_chain_programs(chains, ranks, declared, max_calls=MAX_CALLS):
    """-> ([(filename, text)], report dict).

    One program per prologue, split into consecutive programs when the command
    list does not fit under syzkaller's per-program call limit. Each split
    repeats the prologue, because a syz program is executed on its own.
    """
    paths = chain_paths(chains)
    kept, undeclared, oversize, blocked = buildable_paths(
        paths, declared, max_calls)
    groups = group_chains(kept)
    programs, used = [], set()
    for path, handlers in groups:
        wanted = order_by_rank(handlers, ranks)
        room = max_calls - 1 - len(path)
        chunks = [wanted[i:i + room] for i in range(0, len(wanted), room)]
        for index, chunk in enumerate(chunks):
            name = chain_filename(path[-1], index, used)
            used.add(name)
            programs.append((name, chain_program(
                path, chunk, declared, index * room + 1, len(wanted))))
    # What the run dropped before emission, counted once per command however
    # many paths or missing descriptions it fell through. Every chained command
    # is either emitted or here, so `commands` + `dropped` + the unreached
    # total closes on the whole control surface at any --max-calls. The
    # per-cause detail stays in `undeclared` and `oversize`.
    lost = all_commands(paths) - all_commands(kept)
    report = {
        "paths": len(paths),
        "prologues": len(groups),
        "programs": len(programs),
        "commands": sum(len(h) for _p, h in groups),
        "undeclared": undeclared,
        # Commands no program carries because a name they need is declared by
        # no description, each counted once: a command an undeclared name
        # blocked on one path but that another prologue still reaches is not
        # lost, and summing the per-name counts would report both it and every
        # command blocked twice.
        "undeclared_commands": sorted(blocked & lost),
        "oversize": oversize,
        "dropped": sorted(lost),
        "unreached": unreached(chains),
    }
    return programs, report


def chain_filename(target, index, used):
    """A deterministic name, so re-running overwrites its own output rather
    than growing the bank by a copy of every program."""
    base = "%s%s-%02d" % (CHAIN_FILE_PREFIX, target.lower(), index)
    name = base + CHAIN_FILE_SUFFIX
    bump = 0
    while name in used:
        bump += 1
        name = "%s-%d%s" % (base, bump, CHAIN_FILE_SUFFIX)
    return name


def write_atomic(path, text):
    """Write through a temp file in the same directory and rename, so an
    interrupted run leaves the previous program intact rather than a half
    file the corpus importer refuses."""
    directory = os.path.dirname(os.path.abspath(path))
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=directory, delete=False,
        prefix=TEMP_PREFIX, suffix=TEMP_SUFFIX)
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def cmd_convert(args):
    names, multiplexers = load_map(args.map)
    try:
        with open(args.trace, errors="replace") as handle:
            text = handle.read()
    except OSError as exc:
        raise SeedError("cannot read the trace %s: %s" % (args.trace, exc))
    prog = convert(text, names, multiplexers)
    os.makedirs(args.out_dir, exist_ok=True)
    # Lowest unused index: a count-based name overwrites an existing seed
    # when the bank has gaps (seed-0000,0001,0003 -> count names 0003).
    existing = {x for x in os.listdir(args.out_dir) if x.endswith(".syz")}
    n = 0
    while "seed-%04d.syz" % n in existing:
        n += 1
    out = os.path.join(args.out_dir, "seed-%04d.syz" % n)
    write_atomic(out, prog)
    # Count emitted ioctl calls, not lines starting with a particular
    # description prefix: the map's values are whatever the describe phase
    # named its descriptions, and keying the count on "ioctl$" reported zero
    # mapped while happily emitting them. The seeds gate reads this ratio.
    mapped = sum(1 for ln in prog.splitlines()
                 if re.match(r"^[A-Za-z_][\w$]*\(r\d+,", ln))
    unmapped = prog.count("# unmapped ioctl")
    mux = sum(1 for ln in prog.splitlines()
              if re.match(r"^# \w+ on r\d+, request ", ln))
    print("wrote %s (%d mapped ioctls, %d unmapped, %d multiplexer calls "
          "carrying no decodable command)" % (out, mapped, unmapped, mux))
    if mux:
        print("the %d multiplexer call(s) are control or allocation commands "
              "this trace cannot identify. Run `chains` for those." % mux)
    return 0


def cmd_chains(args):
    if MAX_CALLS_ERROR:
        raise SeedError(MAX_CALLS_ERROR)
    if args.max_calls < MIN_MAX_CALLS:
        raise SeedError(
            "--max-calls %d cannot hold a program: the shortest chain-shaped "
            "program is one openat, one allocation and one control command, "
            "so %d is the floor. Below it every path is dropped and the run "
            "writes an empty bank."
            % (args.max_calls, MIN_MAX_CALLS))
    declared = declared_calls(args.descriptions)
    chains = load_json(args.chains, "the chain artefact")
    # A missing ranking is a warning and not the error a missing chain
    # artefact is: the ranking decides which commands --max-calls keeps and
    # never what any of them contains. A ranking named explicitly and absent
    # is an error, because the caller asked for that ordering.
    ranks = {}
    if args.no_rank and args.rank:
        raise SeedError("--rank and --no-rank contradict each other")
    rank_path = None if args.no_rank else (args.rank or DEFAULT_RANK)
    if rank_path and not os.path.isfile(rank_path) and not args.rank:
        logger.warning("no ranking at %s, so the commands inside each program "
                       "are ordered by handler name and --max-calls keeps an "
                       "arbitrary subset of a long chain. Build one with "
                       "`python3 tools/ctrl_rank.py rank`.", rank_path)
        rank_path = None
    if rank_path:
        rank_doc = load_json(rank_path, "the control ranking")
        ranks = {c["handler"]: c["rank"] for c in rank_doc.get("commands", [])}
        if not ranks:
            raise SeedError(
                "%s holds no `commands` with a `rank`. Regenerate it with "
                "`python3 tools/ctrl_rank.py rank`." % rank_path)
    programs, report = build_chain_programs(chains, ranks, declared,
                                            args.max_calls)
    os.makedirs(args.out_dir, exist_ok=True)
    for name, text in programs:
        write_atomic(os.path.join(args.out_dir, name), text)
    written = {n for n, _t in programs}
    listing = os.listdir(args.out_dir)
    stale = sorted(name for name in listing
                   if name.startswith(CHAIN_FILE_PREFIX)
                   and name.endswith(CHAIN_FILE_SUFFIX)
                   and name not in written)
    # write_atomic renames into place, so a run killed between the temp file
    # and the rename leaves the temp file behind. It is not a program and the
    # stale scan above cannot see it, so it accumulates in the bank unnamed.
    leftovers = sorted(name for name in listing
                       if name.startswith(TEMP_PREFIX)
                       and name.endswith(TEMP_SUFFIX))
    print("wrote %d chain-shaped program(s) to %s: %d prologue(s) over %d "
          "distinct chain(s), carrying %d control command(s)"
          % (report["programs"], args.out_dir, report["prologues"],
             report["paths"], report["commands"]))
    for path, count in report["oversize"]:
        print("skipped %s: its prologue is %d allocation(s) and --max-calls "
              "%d leaves no room for any of its %d command(s)"
              % (" -> ".join(path), len(path), args.max_calls, count))
    if report["undeclared"]:
        print("%d call name(s) the chains need are declared by no description, "
              "and %d command(s) reach no program because of it:"
              % (len(report["undeclared"]),
                 len(report["undeclared_commands"])))
        for name in sorted(report["undeclared"]):
            print("  %s (%d command(s))" % (name, report["undeclared"][name]))
    unreached_total = 0
    for owning, reason, count in report["unreached"]:
        unreached_total += count
        print("no chain for %s, so its %d command(s) reach no program: %s"
              % (owning, count, reason))
    dropped = len(report["dropped"])
    accounted = report["commands"] + dropped + unreached_total
    # Every term, or the line closes on a smaller surface than the run was
    # given and a budget that dropped commands reads as a complete account.
    print("%d control command(s) accounted for: %d emitted, %d dropped "
          "before emission, %d with no chain"
          % (accounted, report["commands"], dropped, unreached_total))
    if stale:
        print("%d chain program(s) in %s were not written by this run and are "
              "left in place: %s. Delete them if they came from an older "
              "driver." % (len(stale), args.out_dir, ", ".join(stale)))
    if leftovers:
        print("%d temp file(s) from an interrupted run are in %s: %s. They "
              "are not programs; delete them."
              % (len(leftovers), args.out_dir, ", ".join(leftovers)))
    if not report["programs"]:
        print("trace2seed: no chain-shaped program was written to %s, so the "
              "seed bank is empty. %d command(s) were dropped before emission "
              "and %d reach no chain; the lines above name each one."
              % (args.out_dir, dropped, unreached_total), file=sys.stderr)
        return 1
    return 0


def build_parser():
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(__doc__.splitlines()[1:]))
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log what each input contributed")
    # -v after the subcommand as well as before it. The default is SUPPRESS
    # so the subparser leaves the attribute alone when the flag was not given
    # there; a plain store_true default of False would overwrite the value a
    # top-level -v had already set, and `trace2seed.py -v chains` would log
    # nothing.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="store_true",
                        default=argparse.SUPPRESS,
                        help="log what each input contributed")
    sub = ap.add_subparsers(dest="command", required=True)

    conv = sub.add_parser("convert", parents=[common],
                          help="one strace file -> one seed program")
    conv.add_argument("--trace", required=True)
    conv.add_argument("--out-dir", required=True)
    conv.add_argument("--map", default=DEFAULT_MAP)
    conv.set_defaults(func=cmd_convert)

    ch = sub.add_parser("chains", parents=[common],
                        help="build chain-shaped programs")
    ch.add_argument("--chains", default=DEFAULT_CHAINS,
                    help="rm-chains.json, from `object_graph.py chains`")
    ch.add_argument("--rank", default=None,
                    help="rm-control-rank.json, from `ctrl_rank.py rank` "
                         "(default: %s when it exists)" % DEFAULT_RANK)
    ch.add_argument("--no-rank", dest="no_rank", action="store_true",
                    help="order the commands inside a program by handler name")
    ch.add_argument("--descriptions", default=DEFAULT_DESC)
    ch.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    ch.add_argument("--max-calls", type=int, default=MAX_CALLS,
                    help="calls per program, syzkaller's prog.MaxCalls "
                         "(default %(default)s)")
    ch.set_defaults(func=cmd_chains)
    return ap


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # The pre-subcommand invocation `--trace X --out-dir Y` is what
    # agents/seeds.md carried for three rounds. Accept it as `convert`.
    #
    # Not when a subcommand is already there: `-v convert --trace X` also
    # opens with a flag and also names --trace, and inserting a second
    # `convert` in front of it makes the first one an unrecognised argument.
    # A trace file named exactly `convert` or `chains` would suppress the
    # routing, and the result is an argparse usage error rather than a wrong
    # conversion.
    if (argv and argv[0].startswith("-") and "--trace" in argv
            and not {"convert", "chains"} & set(argv)):
        argv.insert(0, "convert")
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    try:
        return args.func(args)
    except SeedError as exc:
        print("trace2seed: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
