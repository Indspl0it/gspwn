#!/usr/bin/env python3
"""Seed corpus generator for the Track U harnesses.

An empty corpus spends the first hours of a campaign rediscovering a format's
syntax. Every seed here is either a value a real container image supplies or a
structure the parser under test accepts, so the fuzzer starts inside the
format and mutates outward.

Sources for the text seeds:

  options       The values NVIDIA_DRIVER_CAPABILITIES takes, and the option
                names declared in src/options.h. default_container_opts is
                reproduced exactly.
  require       NVIDIA_REQUIRE_CUDA and NVIDIA_REQUIRE_DRIVER as CUDA base
                images set them, against the four rule names src/cli/
                configure.c registers.
  imex          NVIDIA_IMEX_CHANNELS values, including the separator shapes
                str_count_tokens sizes its allocation from.
  paths         The paths src/nvc_mount.c and src/nvc_container.c construct
                inside a container rootfs, and the symlink shapes the fixture
                in fuzz_path_resolve.c provides.

The ld.so.cache seeds are built here rather than copied, because the format is
a binary one and the repository carries no sample. The layout follows glibc's
dl-cache.h as src/ldcache.c reads it: a 17-byte libc6 magic, a 3-byte version,
nlibs, table_size, five unused words, then nlibs 24-byte entries whose key and
value are byte offsets from the start of the header, then the string table.

Run from anywhere. Writes into each harness's seeds/ directory, overwriting a
seed of the same name and leaving anything else in place.
"""
import argparse
import logging
import os
import struct
import sys

logger = logging.getLogger(__name__)

HERE = os.path.dirname(os.path.abspath(__file__))

MAGIC_LIBC6 = b"glibc-ld.so.cache"      # 17 bytes, no terminator
MAGIC_LIBC5 = b"ld.so-1.7.0"            # 11 bytes, no terminator
MAGIC_VERSION = b"1.1"                  # 3 bytes, no terminator

HEADER_LIBC6_SIZE = 48                  # 17 + 3 + 4 + 4 + 20, padded to 8
ENTRY_LIBC6_SIZE = 24                   # int32 + 3 * uint32 + uint64

LD_ELF = 0x0001
LD_I386_LIB32 = 0x0000
LD_X8664_LIB64 = 0x0300

DRIVER = "560.35.03"

# NVIDIA_DRIVER_CAPABILITIES values and the option strings the runtime hook
# builds from them, space separated as options_parse expects.
OPTIONS_SEEDS = {
    "default": "standalone no-cgroups no-devbind utility",
    "compute-utility": "compute utility",
    "all": "compute utility graphics display video ngx compat32",
    "supervised": "supervised utility compute",
    "compat-ldconfig": "standalone utility compute cuda-compat-mode=ldconfig",
    "compat-mount": "standalone utility compute cuda-compat-mode=mount",
    "compat-disabled": "standalone utility compute cuda-compat-mode=disabled",
    "driver-opts": "no-glvnd no-uvm no-modeset no-mps no-persistenced "
                   "no-fabricmanager no-gsp-firmware",
    "library-opts": "load-kmods no-create-imex-channels",
    "empty": "",
    "spaces": "  compute   utility  ",
}

# NVIDIA_REQUIRE_* predicates. The multi-clause forms are what the CUDA base
# images ship; the single-clause forms isolate one comparator each.
REQUIRE_SEEDS = {
    "cuda-ge": "cuda>=12.6",
    "cuda-image": "cuda>=12.6 brand=unknown,driver>=470,driver<471 "
                  "brand=nvidia,driver>=470,driver<471 "
                  "brand=nvidiartx,driver>=470,driver<471 "
                  "brand=tesla,driver>=470,driver<471",
    "driver-range": "driver>=470,driver<471",
    "arch-list": "arch=5.0,5.2,6.0,6.1,7.0,7.5,8.0,8.6,8.9,9.0",
    "brand-eq": "brand=tesla",
    "brand-ne": "brand!=geforce",
    "cuda-eq": "cuda=12.6",
    "cuda-le": "cuda<=12.6",
    "leading-zeros": "driver>=470.00.01",
    "trailing-dots": "cuda>=12.6...",
}

# NVIDIA_IMEX_CHANNELS values.
IMEX_SEEDS = {
    "single": "0",
    "list": "0,1,2,3",
    "leading-comma": ",0,1",
    "trailing-comma": "0,1,",
    "double-comma": "0,,1",
    "only-commas": ",,,",
    "empty": "",
    "max-minor": "1048575",
    "over-max": "1048576",
    "wide": ",".join(str(n) for n in range(64)),
}

# Paths the library resolves inside a container rootfs, matched to the fixture
# fuzz_path_resolve.c builds.
PATH_SEEDS = {
    "libcuda-soname": "/usr/lib/x86_64-linux-gnu/libcuda.so.1",
    "libcuda-real": "/usr/lib/x86_64-linux-gnu/libcuda.so.560.35.03",
    "compat-dir": "/usr/local/cuda/compat",
    "compat-lib": "/usr/local/cuda/compat/libcuda.so.560.35.03",
    "relative-link": "/lib/x86_64-linux-gnu/libcuda.so.1",
    "absolute-link": "/lib64/x86_64-linux-gnu/libcuda.so.1",
    "via-compat-link": "/compat/libcuda.so.560.35.03",
    "dotdot": "/usr/lib/../lib/x86_64-linux-gnu",
    "dotdot-above-root": "/../../etc/ld.so.conf",
    "escape-link": "/escape/etc/passwd",
    "self-link": "/loop",
    "long-chain": "/chain0",
    "dot-components": "/./usr/./lib/./x86_64-linux-gnu",
    "double-slash": "//usr//lib//x86_64-linux-gnu",
    "trailing-slash": "/usr/lib/",
    "root": "/",
    "ldsoconf": "/etc/ld.so.conf",
    "devnode": "/dev/nvidiactl",
    "firmware": "/lib/firmware/nvidia/560.35.03/gsp_tu10x.bin",
}


def libc6_cache(entries, arch=LD_X8664_LIB64, nlibs_override=None):
    """One glibc 1.1 cache holding (key, value) string pairs.

    Offsets in key and value are byte offsets from the start of the header,
    which is how src/ldcache.c dereferences them.
    """
    count = len(entries)
    table_start = HEADER_LIBC6_SIZE + count * ENTRY_LIBC6_SIZE
    strings = bytearray()
    offsets = []
    for key, value in entries:
        key_off = table_start + len(strings)
        strings += key.encode() + b"\x00"
        value_off = table_start + len(strings)
        strings += value.encode() + b"\x00"
        offsets.append((key_off, value_off))

    header = bytearray()
    header += MAGIC_LIBC6
    header += MAGIC_VERSION
    header += struct.pack("<I", count if nlibs_override is None else nlibs_override)
    header += struct.pack("<I", len(strings))
    header += struct.pack("<5I", 0, 0, 0, 0, 0)
    assert len(header) == HEADER_LIBC6_SIZE, len(header)

    body = bytearray()
    for key_off, value_off in offsets:
        body += struct.pack("<iIIIQ", LD_ELF | arch, key_off, value_off, 0, 0)
    assert len(body) == count * ENTRY_LIBC6_SIZE

    return bytes(header + body + strings)


def libc5_prefixed_cache(entries):
    """A cache whose libc6 header sits behind a libc5 header.

    src/ldcache.c skips the libc5 entries and realigns on an 8-byte boundary
    before reading the libc6 header. That skip is arithmetic over an unchecked
    nlibs, so the shape is worth having in the corpus.
    """
    libc5_nlibs = 2
    libc5 = bytearray()
    libc5 += MAGIC_LIBC5
    libc5 += struct.pack("<I", libc5_nlibs)
    libc5 += b"\x00" * (12 * libc5_nlibs)   # entry_libc5 is 3 * 4 bytes
    padding = (-len(libc5)) % 8
    libc5 += b"\x00" * padding
    return bytes(libc5) + libc6_cache(entries)


LIBRARY_ENTRIES = [
    ("libcuda.so.1", "/usr/lib/x86_64-linux-gnu/libcuda.so." + DRIVER),
    ("libnvidia-ml.so.1", "/usr/lib/x86_64-linux-gnu/libnvidia-ml.so." + DRIVER),
    ("libnvidia-ptxjitcompiler.so.1",
     "/usr/lib/x86_64-linux-gnu/libnvidia-ptxjitcompiler.so." + DRIVER),
]


def ldcache_seeds():
    """Every ld.so.cache seed, as name -> bytes."""
    return {
        "valid-x86_64.cache": libc6_cache(LIBRARY_ENTRIES),
        "valid-i386.cache": libc6_cache(LIBRARY_ENTRIES, arch=LD_I386_LIB32),
        "one-entry.cache": libc6_cache(LIBRARY_ENTRIES[:1]),
        "no-entries.cache": libc6_cache([]),
        "libc5-prefixed.cache": libc5_prefixed_cache(LIBRARY_ENTRIES),
        # A relative value, which sends ldcache_resolve into path_resolve with
        # a path that does not start at the root.
        "relative-value.cache": libc6_cache([
            ("libcuda.so.1", "usr/lib/x86_64-linux-gnu/libcuda.so." + DRIVER),
        ]),
        # A value long enough to reach PATH_MAX inside path_append.
        "long-value.cache": libc6_cache([
            ("libcuda.so.1", "/" + "a" * 4000 + "/libcuda.so.1"),
        ]),
    }


def path_join_seeds():
    """Component pairs for fuzz_path_join, separated by the 0x01 byte."""
    seeds = {}
    for name, path in PATH_SEEDS.items():
        head, _, tail = path.rpartition("/")
        seeds[name] = (head or "/") + "\x01" + tail
    seeds["rootfs-and-lib"] = "/run/containerd/io.containerd.runtime.v2.task/" \
                              "k8s.io/abc/rootfs\x01usr/lib/x86_64-linux-gnu"
    seeds["many-components"] = "\x01".join(
        ["/var/lib/docker/overlay2/deadbeef/merged", "usr", "local", "cuda",
         "compat", "libcuda.so." + DRIVER])
    seeds["empty-second"] = "/usr/lib\x01"
    seeds["empty-first"] = "\x01usr/lib"
    return {k: v.encode() for k, v in seeds.items()}


DICTIONARIES = {
    "fuzz_options_parse": [
        "standalone", "no-cgroups", "no-devbind", "supervised", "utility",
        "compute", "video", "graphics", "display", "ngx", "compat32",
        "cuda-compat-mode=disabled", "cuda-compat-mode=mount",
        "cuda-compat-mode=ldconfig", "load-kmods", "no-create-imex-channels",
        "no-glvnd", "no-uvm", "no-modeset", "no-mps", "no-persistenced",
        "no-fabricmanager", "no-gsp-firmware",
    ],
    "fuzz_dsl_evaluate": [
        "cuda", "driver", "arch", "brand", ">=", "<=", "!=", "=", "<", ">",
        ",", " ", "tesla", "geforce", "unknown", "nvidia", "nvidiartx",
        "12.6", "470", "8.9", "0",
    ],
    "fuzz_imex_channels": [",", "0", "1", "1048575", "1048576", "all"],
    "fuzz_path_resolve": [
        "..", ".", "/", "//", "usr", "lib", "lib64", "compat", "loop",
        "escape", "chain0", "x86_64-linux-gnu", "libcuda.so.1",
        "/usr/local/cuda/compat", "/etc/ld.so.conf", "/dev/nvidiactl",
    ],
    "fuzz_path_join": ["/", "//", "..", ".", "usr", "lib", "rootfs"],
    "fuzz_ldcache": [
        "glibc-ld.so.cache", "ld.so-1.7.0", "1.1", "libcuda.so",
        "libnvidia-ml.so",
    ],
}


def write_seed(target, name, payload):
    """Write one seed under <harness>/seeds/, creating the directory."""
    seeds_dir = os.path.join(HERE, target, "seeds")
    os.makedirs(seeds_dir, exist_ok=True)
    path = os.path.join(seeds_dir, name)
    with open(path, "wb") as fh:
        fh.write(payload)
    return path


def write_dictionary(target, tokens):
    """Write the libFuzzer dictionary for one harness."""
    path = os.path.join(HERE, target, "%s.dict" % target)
    lines = []
    for token in tokens:
        escaped = token.replace("\\", "\\\\").replace('"', '\\"')
        lines.append('"%s"' % escaped)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# Format keywords for %s, from the library's own source.\n"
                 % target)
        fh.write("\n".join(lines) + "\n")
    return path


def generate():
    """Write every seed and dictionary. Returns the count written."""
    written = 0
    for name, value in OPTIONS_SEEDS.items():
        write_seed("fuzz_options_parse", name, value.encode())
        written += 1
    for name, value in REQUIRE_SEEDS.items():
        write_seed("fuzz_dsl_evaluate", name, value.encode())
        written += 1
    for name, value in IMEX_SEEDS.items():
        write_seed("fuzz_imex_channels", name, value.encode())
        written += 1
    for name, value in PATH_SEEDS.items():
        write_seed("fuzz_path_resolve", name, value.encode())
        written += 1
    for name, value in path_join_seeds().items():
        write_seed("fuzz_path_join", name, value)
        written += 1
    for name, value in ldcache_seeds().items():
        write_seed("fuzz_ldcache", name, value)
        written += 1
    for target, tokens in DICTIONARIES.items():
        write_dictionary(target, tokens)
    logger.info("wrote %d seeds and %d dictionaries under %s",
                written, len(DICTIONARIES), HERE)
    return written


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate the Track U harness seed corpora.")
    parser.add_argument("--verbose", action="store_true",
                        help="log every file written")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")
    try:
        count = generate()
    except OSError as exc:
        logger.error("cannot write seeds under %s: %s", HERE, exc)
        return 1
    print("%d seeds written" % count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
