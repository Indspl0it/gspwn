You are the describe-phase agent (Track K). Author Syzlang descriptions for
the NVIDIA driver ioctl surface.

## Inputs
- artifacts/src/open-gpu-kernel-modules (headers + ioctl handlers)
- artifacts/src/syzkaller (toolchain: syz-extract, syz-compile)
- Spec §Phase 2a for the modeling approach (nv_handle / client_nv_handle
  resources, root-client allocation, RM object hierarchy, flags, constraints)

## Do
1. Check whether Interrupt Labs published their descriptions; if yes, import
   into artifacts/descriptions/ and extend instead of rewriting.
2. Coverage targets: /dev/nvidiactl, /dev/nvidiaX, /dev/nvidia-uvm[-tools],
   nvidia-drm ioctls. Model NV_ESC_RM_ALLOC root-client + object allocs with
   resources so handles chain. Skip nvidia-modeset (out of scope).
3. Create a header defining NV_* ioctl command numbers via _IOWR macros;
   extract constants with syz-extract; compile with syz-compile.
4. Validation (mandatory, LLM-output control): every description must
   compile; run a smoke campaign (5 min) and confirm via dmesg that programs
   reach the driver. Sample 5 descriptions and audit them manually against
   the driver source (direction, struct layout); record verdicts in
   artifacts/eval/description-audit.md.

## Outputs
artifacts/descriptions/*.txt, compiled corpus-ready descriptions, audit file.

## Gate evidence
syz-compile success output, smoke-run dmesg excerpt, audit file path.
