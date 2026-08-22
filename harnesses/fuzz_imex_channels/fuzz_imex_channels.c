/*
 * Track U harness: parse_imex_info() in src/cli/common.c, and
 * str_count_tokens() in src/utils.c, which sizes its allocation.
 *
 * Threat model: the attacker supplies the container image and its OCI
 * configuration. The code under test runs as root during container init,
 * before isolation is enforced.
 *
 * Reachability. NVIDIA_IMEX_CHANNELS is an image environment variable. The
 * runtime hook passes it through as --imex-channel to `nvidia-container-cli`,
 * src/cli/main.c stores it in ctx->imex_channels, and parse_imex_info turns
 * the comma-separated list into the channel array that drives host-side mknod
 * of /dev/nvidia-caps-imex-channels/channelN. The architecture threat model
 * names this surface directly: host-side mknod driven by an image environment
 * variable, running as root.
 *
 * What the parser does. str_count_tokens sizes the allocation from the
 * separator count, deliberately skipping index 0, and the loop then writes one
 * entry per non-empty token. The allocation and the write count are two
 * independent walks of the same string, which is the shape a fuzzer settles
 * quickly. Each channel id is parsed with strtoumax and bounded below 1 << 20.
 *
 * Deterministic, no filesystem, no network. The harness frees the channel
 * array on the success path; see build.sh for the leak policy on the failure
 * path, where the library itself does not free it.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cli/cli.h"

#include "error_generic.h"
#include "utils.h"

/* A real NVIDIA_IMEX_CHANNELS value is a short list. Anything past this only
 * spends campaign time inside strtoumax. */
#define MAX_INPUT 4096

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        struct error err = {0};
        struct nvc_imex_info imex = {0};
        char *chans;

        if (size > MAX_INPUT)
                return (0);
        if ((chans = malloc(size + 1)) == NULL)
                return (0);
        memcpy(chans, data, size);
        chans[size] = '\0';

        if (parse_imex_info(&err, chans, &imex) == 0)
                free(imex.chans);
        error_reset(&err);

        free(chans);
        return (0);
}
