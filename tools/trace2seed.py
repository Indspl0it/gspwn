#!/usr/bin/env python3
"""Convert strace of a real CUDA workload into seed syz-programs.

Valid RM object allocation chains from real workloads are exactly what
random generation struggles to produce (spec Phase 2b). Seeds are text
prog files; syz-manager imports them via the corpus.

fd tracking: openat("/dev/nvidiaX") = N  ->  resource r<k>
             ioctl(N, 0x....)            ->  ioctl$NAME(r<k>, 0x...., ...)

The prescribed trace command is `strace -v -f` (agents/seeds.md), so both
of its output quirks are handled here: `[pid N]` prefixes are stripped and
fd state is tracked per process (fds are per-process namespaces), and the
symbolic `_IOC(dir, type, nr, size)` form strace -v prints for requests it
does not know is decoded back into the request number before lookup.
"""
import argparse
import json
import os
import re

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

# Devices the describe phase is forbidden to model (agents/describe.md,
# spec section 9): seeds referencing them fail the syzkaller-parse gate.
OUT_OF_SCOPE = {
    "/dev/nvidia-modeset": "nvidia-modeset out of scope",
}

# Linux ioctl encoding: request = dir<<30 | size<<16 | type<<8 | nr.
_IOC_DIR = {"_IOC_NONE": 0, "_IOC_WRITE": 1, "_IOC_READ": 2}


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


def convert(trace_text, ioctl_map):
    lines = []
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
            lines.append('%s = %s(&AUTO=\'%s\\x00\', 0x2, 0x0)'
                         % (var, desc, path))
            continue
        m = IOCTL_RE.search(raw)
        if m and (pid, m.group(1)) in fd_res:
            fd = m.group(1)
            value = parse_request(m.group(2))
            num = hex(value) if value is not None else m.group(2).lower()
            name = ioctl_map.get(num)
            if name:
                lines.append("%s(%s, %s, &AUTO)" % (name, fd_res[(pid, fd)],
                                                    num))
            else:
                lines.append("# unmapped ioctl %s on fd %s" % (num, fd))
            continue
        m = CLOSE_RE.search(raw)
        if m and (pid, m.group(1)) in fd_res:
            lines.append("close(%s)" % fd_res.pop((pid, m.group(1))))
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--map", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "ioctl_map.json"))
    a = ap.parse_args()
    with open(a.map) as f:
        # Lookups use hex(value) (lowercase); normalise map keys the same
        # way so uppercase-hex keys don't silently yield 100% unmapped.
        ioctl_map = {k.lower(): v for k, v in json.load(f).items()
                     if not k.startswith("comment")}
    with open(a.trace, errors="replace") as f:
        text = f.read()
    prog = convert(text, ioctl_map)
    os.makedirs(a.out_dir, exist_ok=True)
    # Lowest unused index: a count-based name overwrites an existing seed
    # when the bank has gaps (seed-0000,0001,0003 -> count names 0003).
    existing = {x for x in os.listdir(a.out_dir) if x.endswith(".syz")}
    n = 0
    while "seed-%04d.syz" % n in existing:
        n += 1
    out = os.path.join(a.out_dir, "seed-%04d.syz" % n)
    with open(out, "w") as f:
        f.write(prog)
    mapped = sum(1 for ln in prog.splitlines()
                 if ln.startswith("ioctl$"))
    unmapped = prog.count("# unmapped ioctl")
    print("wrote %s (%d mapped ioctls, %d unmapped)" % (out, mapped, unmapped))


if __name__ == "__main__":
    main()
