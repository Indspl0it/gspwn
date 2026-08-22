/*
 * Track U harness: dsl_evaluate() in src/cli/dsl.c, and the two comparators
 * it dispatches to, dsl_compare_version() and dsl_compare_string().
 *
 * Threat model: the attacker supplies the container image and its OCI
 * configuration. The code under test runs as root during container init,
 * before isolation is enforced.
 *
 * Reachability. Any environment variable named NVIDIA_REQUIRE_* in the image
 * becomes one --require=EXPR argument to `nvidia-container-cli configure`.
 * src/cli/configure.c collects up to 32 of them into ctx->reqs and calls
 * dsl_evaluate on each against four rules: cuda, driver, arch and brand. Every
 * byte of the predicate comes from the image, and a CUDA base image sets at
 * least NVIDIA_REQUIRE_CUDA.
 *
 * The parser splits the predicate on spaces and then on commas, locates the
 * operator with strcspn and strspn over "<>=!", writes a reformatted
 * expression into a fixed EXPR_MAX buffer, and walks two version strings in
 * parallel with strtoumax. This harness drives all of it.
 *
 * The rule callbacks below stand in for configure.c's four. Each one ends in
 * the same comparator the real callback ends in, with a fixed driver and
 * device value in place of the ones read from a live GPU. That keeps the
 * parsing surface identical and removes the need for a driver.
 *
 * Deterministic, no global state between runs, no filesystem, no network.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cli/dsl.h"

#include "error_generic.h"
#include "utils.h"

#define MAX_INPUT 4096

/* Values a real host would report. configure.c reads these from
 * nvc_driver_info and nvc_device; the parsing under test does not depend on
 * which values they hold. */
static const char *const FIXED_CUDA_VERSION = "12.6";
static const char *const FIXED_DRIVER_VERSION = "560.35.03";
static const char *const FIXED_DEVICE_ARCH = "8.9";
static const char *const FIXED_DEVICE_BRAND = "Tesla";

static int
check_cuda_version(const struct dsl_data *data, enum dsl_comparator cmp,
    const char *version)
{
        (void)data;
        return (dsl_compare_version(FIXED_CUDA_VERSION, cmp, version));
}

static int
check_driver_version(const struct dsl_data *data, enum dsl_comparator cmp,
    const char *version)
{
        (void)data;
        return (dsl_compare_version(FIXED_DRIVER_VERSION, cmp, version));
}

static int
check_device_arch(const struct dsl_data *data, enum dsl_comparator cmp,
    const char *arch)
{
        (void)data;
        return (dsl_compare_version(FIXED_DEVICE_ARCH, cmp, arch));
}

static int
check_device_brand(const struct dsl_data *data, enum dsl_comparator cmp,
    const char *brand)
{
        (void)data;
        return (dsl_compare_string(FIXED_DEVICE_BRAND, cmp, brand));
}

/* The same four names configure.c registers, in the same order. */
static const struct dsl_rule rules[] = {
        {"cuda", &check_cuda_version},
        {"driver", &check_driver_version},
        {"arch", &check_device_arch},
        {"brand", &check_device_brand},
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        struct error err = {0};
        struct dsl_data ctx = {0};
        char *predicate;

        if (size == 0 || size > MAX_INPUT)
                return (0);
        if ((predicate = malloc(size + 1)) == NULL)
                return (0);
        memcpy(predicate, data, size);
        predicate[size] = '\0';

        dsl_evaluate(&err, predicate, &ctx, rules, nitems(rules));
        error_reset(&err);

        free(predicate);
        return (0);
}
