#!/usr/bin/env python3
"""Convert strace of a real CUDA workload into seed syz-programs.

Valid RM object allocation chains from real workloads are exactly what
random generation struggles to produce (spec Phase 2b). Seeds are text
prog files; syz-manager imports them via the corpus.

fd tracking: openat("/dev/nvidiaX") = N  ->  resource r<k>
             ioctl(N, 0x....)            ->  ioctl$NAME(r<k>, 0x...., ...)
"""
import argparse
import json
import os
import re
import sys

OPEN_RE = re.compile(r'openat\([^,]+,\s*"((?:/dev/nvidia|/dev/dri)[^"]*)"[^)]*\)\s*=\s*(\d+)')
IOCTL_RE = re.compile(r"ioctl\((\d+),\s*(0x[0-9a-fA-F]+|\w+)")
CLOSE_RE = re.compile(r"close\((\d+)")

DEV_TO_DESC = {
    "/dev/nvidiactl": "openat$nvidiactl",
    "/dev/nvidia-uvm": "openat$nvidia_uvm",
    "/dev/nvidia-uvm-tools": "openat$nvidia_uvm_tools",
    "/dev/nvidia-modeset": "openat$nvidia_modeset",
}


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
    fd_res = {}        # fd -> resource var name
    res_n = 0
    for raw in trace_text.splitlines():
        m = OPEN_RE.search(raw)
        if m:
            path, fd = m.group(1), m.group(2)
            desc = dev_desc(path)
            if desc is None:
                continue
            var = "r%d" % res_n
            res_n += 1
            fd_res[fd] = var
            lines.append('%s = %s(&AUTO=\'%s\\x00\', 0x2, 0x0)'
                         % (var, desc, path))
            continue
        m = IOCTL_RE.search(raw)
        if m and m.group(1) in fd_res:
            fd, num = m.group(1), m.group(2).lower()
            name = ioctl_map.get(num)
            if name:
                lines.append("%s(%s, %s, &AUTO)" % (name, fd_res[fd], num))
            else:
                lines.append("# unmapped ioctl %s on fd %s" % (num, fd))
            continue
        m = CLOSE_RE.search(raw)
        if m and m.group(1) in fd_res:
            lines.append("close(%s)" % fd_res.pop(m.group(1)))
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--map", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "ioctl_map.json"))
    a = ap.parse_args()
    with open(a.map) as f:
        ioctl_map = {k: v for k, v in json.load(f).items()
                     if not k.startswith("comment")}
    with open(a.trace, errors="replace") as f:
        text = f.read()
    prog = convert(text, ioctl_map)
    os.makedirs(a.out_dir, exist_ok=True)
    n = len([x for x in os.listdir(a.out_dir) if x.endswith(".syz")])
    out = os.path.join(a.out_dir, "seed-%04d.syz" % n)
    with open(out, "w") as f:
        f.write(prog)
    mapped = sum(1 for ln in prog.splitlines()
                 if ln.startswith("ioctl$"))
    unmapped = prog.count("# unmapped ioctl")
    print("wrote %s (%d mapped ioctls, %d unmapped)" % (out, mapped, unmapped))


if __name__ == "__main__":
    main()
