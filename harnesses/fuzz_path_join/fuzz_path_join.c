/*
 * Track U harness: path_new(), path_append() and path_join() in src/utils.c.
 *
 * Threat model: the attacker supplies the container image and its OCI
 * configuration. The code under test runs as root during container init,
 * before isolation is enforced.
 *
 * Reachability. Every path the library constructs passes through these three
 * functions. src/nvc_mount.c builds each bind-mount source and destination
 * with them, src/nvc_container.c builds the container rootfs paths, and
 * src/ldcache.c passes a cache value string into path_resolve, which appends
 * it. The container rootfs, the CUDA compat directory and the library
 * SONAMEs discovered inside the image all originate in the image.
 *
 * The functions write into a caller-supplied PATH_MAX buffer. path_append
 * computes its remaining capacity from strlen(buf) and reads buf[len - 1] to
 * decide whether a separator is needed, so the buffer state carried between
 * calls is part of the input. This harness reproduces that carried state by
 * appending every component of the input in sequence to one buffer.
 *
 * Deterministic, no global state between runs, no filesystem, no network.
 */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "error_generic.h"
#include "utils.h"

/* PATH_MAX is the contract: every caller in the library declares
 * char buf[PATH_MAX]. A shorter buffer here would report an overflow the
 * library cannot suffer. */
#define MAX_INPUT 8192

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        char buf[PATH_MAX];
        struct error err = {0};
        char *copy, *cursor, *component;
        const char *first = NULL, *second = NULL;

        if (size == 0 || size > MAX_INPUT)
                return (0);
        if ((copy = malloc(size + 1)) == NULL)
                return (0);
        memcpy(copy, data, size);
        copy[size] = '\0';

        /* A NUL byte in the input splits it into components. The library
         * appends components one at a time, so the fuzzer needs a way to
         * express more than one. */
        cursor = copy;
        if (path_new(&err, buf, "/") == 0) {
                while ((component = strsep(&cursor, "\x01")) != NULL) {
                        if (first == NULL)
                                first = component;
                        else if (second == NULL)
                                second = component;
                        if (path_append(&err, buf, component) < 0) {
                                error_reset(&err);
                                break;
                        }
                }
        }
        error_reset(&err);

        /* path_join is path_new followed by path_append and is the form most
         * call sites use. Drive it directly with the first two components. */
        if (first != NULL) {
                path_join(&err, buf, first, second != NULL ? second : "");
                error_reset(&err);
        }

        free(copy);
        return (0);
}
