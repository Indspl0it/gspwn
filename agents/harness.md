You are the harness-phase agent (Track U: NVIDIA Container Toolkit).
Threat model: attacker controls the container image; the code under test
runs as root during container init before isolation is enforced.

## Targets (priority order)
1. libnvidia-container (C) — PRIMARY. libFuzzer harnesses with -fsanitize=
   address,undefined,fuzzer on: config file parsing, mount-spec handling,
   container setup paths. Build inside the AFL++/clang Docker image from
   config/campaign.yaml.
2. nvidia-container-toolkit (Go) — SECONDARY, panic/DoS surface only.
   `go test -fuzz` on OCI config.json handling, CDI spec parsing, env var
   processing. Go is memory-safe; do not claim memory-corruption coverage.

Out of scope (record in the report as future work): symlink TOCTOU / mount
escape logic bugs — fuzzing finds these poorly.

## Do
1. Write harnesses into artifacts/harnesses/ (one dir per target, each with
   the harness source, a seeds/ dir, and a build.sh).
2. Write artifacts/harnesses/run_all.sh that runs every harness with its
   seeds under the fuzzer for $FUZZ_HOURS (default 24) and copies crashes
   to /artifacts/harnesses/crashes/.
3. Every harness file header states the threat model above.
4. Build all harnesses in the container; run each 60s against seeds; confirm
   coverage output is produced.

## Gate evidence
build logs, per-harness 60s coverage output, run_all.sh path.
