/*
 * Track U harness: ldcache_open() and ldcache_resolve() in src/ldcache.c.
 *
 * Threat model: the attacker supplies the container image and its OCI
 * configuration. The code under test runs as root during container init,
 * before isolation is enforced.
 *
 * Reachability, stated precisely because it is conditional. src/nvc.c line 339
 * sets ctx->cfg.ldcache from the --ldcache option and falls back to
 * LDCACHE_PATH. src/nvc_info.c lookup_paths() passes that path to
 * ldcache_init. Under the default configuration the file is the host's
 * /etc/ld.so.cache, which the Track U attacker does not write. The path is
 * reachable from the image only where an operator has pointed --ldcache at a
 * file the container supplies, and the poc phase has to establish that before
 * a finding here can carry a Track U severity. TARGETS.md records the same
 * caveat. The parser is harnessed anyway because it is the only binary format
 * parser in the library and because a finding in it is a real defect whatever
 * reaches it.
 *
 * What the parser does with the bytes. ldcache_open mmaps the file, checks the
 * libc5 and libc6 magic strings and one size bound, and stops. ldcache_resolve
 * then reads h->nlibs straight out of the mapping and iterates that many
 * entries, deriving key and value as unchecked byte offsets from the start of
 * the mapping and handing both to str_has_prefix and path_resolve as
 * NUL-terminated strings. Neither the count nor either offset is checked
 * against ctx->size.
 *
 * Fixtures. One temporary file receives each input, because file_map takes a
 * path. One temporary root directory receives the path_resolve calls
 * ldcache_resolve makes on each cache value. Both are created once and removed
 * at exit; no input creates or removes anything.
 */
#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/types.h>

#include <ftw.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "error_generic.h"
#include "ldcache.h"
#include "utils.h"

/* Well above a real /etc/ld.so.cache header plus a handful of entries. A
 * larger input only slows the campaign down. */
#define MAX_INPUT 65536

/* The SONAME prefixes nvc_info.c looks for, trimmed to the two that matter. */
static const char *const LIBS[] = {
        "libcuda.so",
        "libnvidia-ml.so",
};

static char cache_path[PATH_MAX];
static char fixture_root[PATH_MAX];

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
teardown(void)
{
        if (cache_path[0] != '\0')
                unlink(cache_path);
        if (fixture_root[0] != '\0')
                nftw(fixture_root, unlink_entry, 16, FTW_DEPTH | FTW_PHYS);
}

static void
build_fixture(void)
{
        const char *tmp = getenv("TMPDIR") != NULL ? getenv("TMPDIR") : "/tmp";
        char p[PATH_MAX];
        int fd;

        snprintf(fixture_root, sizeof(fixture_root), "%s/nvc-ldcache-XXXXXX", tmp);
        if (mkdtemp(fixture_root) == NULL) {
                fprintf(stderr, "harness fixture: mkdtemp failed\n");
                exit(1);
        }
        atexit(teardown);

        snprintf(p, sizeof(p), "%s/usr", fixture_root);
        mkdir(p, 0755);
        snprintf(p, sizeof(p), "%s/usr/lib", fixture_root);
        mkdir(p, 0755);

        snprintf(cache_path, sizeof(cache_path), "%s/ld.so.cache", fixture_root);
        if ((fd = open(cache_path, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0) {
                fprintf(stderr, "harness fixture: cannot create %s\n", cache_path);
                exit(1);
        }
        close(fd);
}

/* ldcache_resolve's selection callback. nvc_info.c's compares two candidate
 * paths and decides which wins; returning 1 unconditionally keeps every
 * candidate flowing through the allocation path, which is what the harness
 * wants to exercise. */
static int
select_always(struct error *err, void *ctx, const char *root,
    const char *orig, const char *path)
{
        (void)err;
        (void)ctx;
        (void)root;
        (void)orig;
        (void)path;
        return (1);
}

static void
drive(uint32_t arch)
{
        struct ldcache ld;
        struct error err = {0};
        char *paths[nitems(LIBS)];
        size_t i;

        ldcache_init(&ld, &err, cache_path);
        if (ldcache_open(&ld) < 0) {
                error_reset(&err);
                return;
        }

        if (ldcache_resolve(&ld, arch, fixture_root, LIBS, paths,
            nitems(LIBS), select_always, NULL) == 0) {
                for (i = 0; i < nitems(LIBS); ++i)
                        free(paths[i]);
        }
        error_reset(&err);

        ldcache_close(&ld);
        error_reset(&err);
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
        int fd;
        ssize_t written;

        if (size == 0 || size > MAX_INPUT)
                return (0);
        if (fixture_root[0] == '\0')
                build_fixture();

        /* One reusable file, truncated each time. Nothing accumulates on disk. */
        if ((fd = open(cache_path, O_WRONLY | O_TRUNC)) < 0)
                return (0);
        written = write(fd, data, size);
        close(fd);
        if (written < 0 || (size_t)written != size)
                return (0);

        drive(LD_X8664_LIB64);
        drive(LD_I386_LIB32);
        return (0);
}
