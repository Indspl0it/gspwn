/*
 * Track U harness: path_resolve() and path_resolve_full() in src/utils.c,
 * which are both thin wrappers over do_path_resolve().
 *
 * Threat model: the attacker supplies the container image and its OCI
 * configuration. The code under test runs as root during container init,
 * before isolation is enforced.
 *
 * Reachability. do_path_resolve walks a path one component at a time inside a
 * root directory, following symlinks with readlinkat and refusing to leave the
 * root. It is the containment mechanism for every path the library touches
 * inside the container rootfs:
 *
 *   src/nvc_mount.c mount_in_root()   resolves each bind-mount destination
 *   src/nvc_mount.c mount_firmware()  resolves the firmware source
 *   src/nvc_container.c find_compat_library_paths()  resolves the CUDA compat
 *                                     directory, changed to this function by
 *                                     commit 5ae7360
 *   src/ldcache.c ldcache_resolve()   resolves each cache value string
 *
 * The container rootfs is the attacker's filesystem. Every symlink, every
 * directory and every ".." component the walk meets came out of the image.
 * Commits ad1f8c8, 5ae7360 and 77c1cbc all changed how this walk or its
 * callers treat a symlink.
 *
 * Fixture. The walk needs real directory entries, so the harness builds one
 * temporary root at startup holding the shapes the library meets in a real
 * image: a resolvable library chain, a relative and an absolute symlink, a
 * self-referential symlink, a chain longer than MAXSYMLINKS, and a symlink
 * pointing above the root. The fixture is built once and removed at exit. No
 * input creates or removes anything, so the campaign cannot exhaust the disk.
 *
 * Root privilege is not required: the fixture is a temporary directory owned
 * by the fuzzing user, and the walk only opens with O_PATH and reads links.
 */
#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/types.h>

#include <ftw.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "error_generic.h"
#include "utils.h"

#define MAX_INPUT 8192
#define LINK_CHAIN 48   /* longer than MAXSYMLINKS, which glibc sets to 20 */

static char fixture_root[PATH_MAX];

static void
must_mkdir(const char *rel)
{
        char p[PATH_MAX];

        snprintf(p, sizeof(p), "%s/%s", fixture_root, rel);
        if (mkdir(p, 0755) < 0 && access(p, F_OK) < 0) {
                fprintf(stderr, "harness fixture: mkdir %s failed\n", p);
                exit(1);
        }
}

static void
must_file(const char *rel)
{
        char p[PATH_MAX];
        FILE *fh;

        snprintf(p, sizeof(p), "%s/%s", fixture_root, rel);
        if ((fh = fopen(p, "w")) == NULL) {
                fprintf(stderr, "harness fixture: create %s failed\n", p);
                exit(1);
        }
        fputs("ELF placeholder\n", fh);
        fclose(fh);
}

static void
must_link(const char *target, const char *rel)
{
        char p[PATH_MAX];

        snprintf(p, sizeof(p), "%s/%s", fixture_root, rel);
        if (symlink(target, p) < 0 && access(p, F_OK) < 0) {
                fprintf(stderr, "harness fixture: symlink %s failed\n", p);
                exit(1);
        }
}

static int
unlink_entry(const char *path, const struct stat *st, int flag, struct FTW *ftw)
{
        (void)st;
        (void)flag;
        (void)ftw;
        remove(path);
        return (0);
}

static void
teardown_fixture(void)
{
        if (fixture_root[0] != '\0')
                nftw(fixture_root, unlink_entry, 16, FTW_DEPTH | FTW_PHYS);
}

static void
build_fixture(void)
{
        char chain[64];
        char target[64];
        int i;

        snprintf(fixture_root, sizeof(fixture_root), "%s/nvc-fuzz-XXXXXX",
                 getenv("TMPDIR") != NULL ? getenv("TMPDIR") : "/tmp");
        if (mkdtemp(fixture_root) == NULL) {
                fprintf(stderr, "harness fixture: mkdtemp failed\n");
                exit(1);
        }
        if (fixture_root[0] != '/') {
                fprintf(stderr, "harness fixture: root must be absolute\n");
                exit(1);
        }
        atexit(teardown_fixture);

        must_mkdir("usr");
        must_mkdir("usr/lib");
        must_mkdir("usr/lib/x86_64-linux-gnu");
        must_mkdir("usr/local");
        must_mkdir("usr/local/cuda");
        must_mkdir("usr/local/cuda/compat");
        must_mkdir("etc");
        must_mkdir("dev");

        must_file("usr/lib/x86_64-linux-gnu/libcuda.so.560.35.03");
        must_file("usr/local/cuda/compat/libcuda.so.560.35.03");
        must_file("etc/ld.so.conf");

        /* The shapes a real image presents to the walk. */
        must_link("libcuda.so.560.35.03", "usr/lib/x86_64-linux-gnu/libcuda.so.1");
        must_link("usr/lib", "lib");                 /* relative */
        must_link("/usr/lib", "lib64");              /* absolute, re-roots the walk */
        must_link("loop", "loop");                   /* self-referential */
        must_link("../../..", "escape");             /* points above the root */
        must_link("usr/local/cuda/compat", "compat");

        /* A chain longer than MAXSYMLINKS, which drives the ELOOP branch. */
        for (i = 0; i < LINK_CHAIN; ++i) {
                snprintf(chain, sizeof(chain), "chain%d", i);
                snprintf(target, sizeof(target), "chain%d", i + 1);
                must_link(target, chain);
        }
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
        (void)argc;
        (void)argv;
        build_fixture();
        return (0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        char buf[PATH_MAX];
        struct error err = {0};
        char *path;

        if (size == 0 || size > MAX_INPUT)
                return (0);
        if (fixture_root[0] == '\0')
                build_fixture();
        if ((path = malloc(size + 1)) == NULL)
                return (0);
        memcpy(path, data, size);
        path[size] = '\0';

        path_resolve(&err, buf, fixture_root, path);
        error_reset(&err);

        path_resolve_full(&err, buf, fixture_root, path);
        error_reset(&err);

        free(path);
        return (0);
}
