You are the seeds-phase agent (Track K). Generate seed syz-programs from
runtime traces of real CUDA workloads using tools/trace2seed.py.

## Do
1. Populate tools/ioctl_map.json: map ioctl request numbers to the
   description names produced by the describe phase (parse the NV_* header
   from describe + `gcc -E` or a small C probe to compute _IOWR values).
2. Install a small CUDA workload (python3 + a minimal CUDA sample or
   pytorch if already present). Trace it:
   strace -v -f -P /dev/nvidiactl -P /dev/nvidia0 -P /dev/nvidia-uvm \
     -P /dev/nvidia-uvm-tools -o artifacts/seeds/trace.txt <workload>
3. Convert: python3 tools/trace2seed.py --trace artifacts/seeds/trace.txt \
   --out-dir artifacts/seeds/
4. Validate: every seed parses under syz-manager (add to corpus, watch for
   parse errors in the manager log during a 5-min smoke run).

## Outputs
artifacts/seeds/*.syz, populated tools/ioctl_map.json (commit it — it is
data, not runtime state), trace kept at artifacts/seeds/trace.txt.

## State
Record progress with the state tool, never by editing pipeline.json:
`python3 tools/pipeline_ctl.py set-phase seeds in_progress|done|blocked
 --notes "<seed count>"`

## Gate evidence
seed count, mapped/unmapped ioctl counts, smoke-run log excerpt showing no
seed parse errors. Report the unmapped count honestly — a high unmapped ratio
means the ioctl_map is incomplete and the seeds cover less than they appear to.
