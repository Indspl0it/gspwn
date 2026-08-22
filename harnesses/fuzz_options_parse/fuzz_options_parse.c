/*
 * Track U harness: options_parse() in src/options.c.
 *
 * Threat model: the attacker supplies the container image and its OCI
 * configuration. The code under test runs as root during container init,
 * before isolation is enforced.
 *
 * Reachability. NVIDIA_DRIVER_CAPABILITIES is an image environment variable.
 * nvidia-container-runtime-hook turns its comma-separated values into the
 * --compute --utility style flags of `nvidia-container-cli configure`, and
 * src/cli/configure.c joins those into one space-separated string that
 * nvc_container_new passes to options_parse against container_opts. The same
 * function parses the library option string in nvc_init and the driver option
 * string in nvc_driver_info_new.
 *
 * The parser copies the whole string into a fixed NVC_ARG_MAX buffer after one
 * length check and then walks it with strsep. Both the check and the walk are
 * what this harness exercises.
 *
 * Deterministic, no global state between runs, no filesystem, no network.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nvc_internal.h"

#include "error_generic.h"
#include "options.h"

/* Longer than any option string the hook can construct. Bounds the harness's
 * own allocation without bounding what the parser sees, since options_parse
 * rejects anything at or above NVC_ARG_MAX itself. */
#define MAX_INPUT 8192

static void
drive(const char *str, const struct option *opts, size_t nopts)
{
        struct error err = {0};

        options_parse(&err, str, opts, nopts);
        error_reset(&err);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        char *str;

        if (size > MAX_INPUT)
                return (0);
        if ((str = malloc(size + 1)) == NULL)
                return (0);
        memcpy(str, data, size);
        str[size] = '\0';

        drive(str, container_opts, nitems(container_opts));
        drive(str, driver_opts, nitems(driver_opts));
        drive(str, library_opts, nitems(library_opts));

        free(str);
        return (0);
}
