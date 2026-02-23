# CASR Integration for Crash Deduplication

This document explains how CASR (Crash Analysis and Severity Reporting) is integrated into the fuzzing benchmark to deduplicate crashes.

## Problem

CASR binaries require GLIBC 2.25-2.34, but the ARVO containers use Ubuntu 16.04 with GLIBC 2.23. Running CASR directly fails with:
```
casr-libfuzzer: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.29' not found
```

Additionally, CASR requires the `personality` syscall (for controlling ASLR), which is blocked by default container security policies.

## Solution

### 1. Separate GLIBC Installation

We install GLIBC 2.35 from Ubuntu 22.04 to `/opt/glibc-new/`, completely separate from the system GLIBC. This avoids any conflicts with the container's existing libraries.

**Location:** `/opt/glibc-new/lib/x86_64-linux-gnu/`
- `ld-linux-x86-64.so.2` - Dynamic linker
- `libc.so.6` - C library
- `libm.so.6` - Math library
- Other required libraries

### 2. Binary Patching with patchelf

We use `patchelf` to modify the CASR binaries directly, setting their RPATH and interpreter to use the new GLIBC:

```bash
for tool in /usr/local/casr/casr-*; do
    # Set RPATH to find new glibc libraries
    patchelf --set-rpath /opt/glibc-new/lib/x86_64-linux-gnu "$tool"
    # Set interpreter to use new dynamic linker
    patchelf --set-interpreter /opt/glibc-new/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 "$tool"
done
```

This approach:
- **Bakes the dependency** into the binaries themselves
- **No wrapper scripts needed** - CASR binaries can be called directly
- **Cleaner than wrappers** - the binaries know where to find their libraries
- **Zero overhead** - no shell script interpretation

The CASR binaries now run with GLIBC 2.35 while the rest of the system continues using GLIBC 2.23.

### 3. Seccomp Profile Configuration

Container creation now includes `--security-opt seccomp=unconfined` to allow the `personality` syscall.

**File:** `benchmark/arvo_utils.py:128-136`

```python
RUN_CMD_ARGS = [
    "podman",
    "run",
    "--platform=linux/amd64",
    "--net=none",
    "--pull=never",
    "--security-opt", "seccomp=unconfined",  # Allow personality syscall for CASR
    "-d",
]
```

## Build Process

### 1. Build CASR from Source

Run the build script to compile CASR from the forked repository and download GLIBC:

```bash
cd build
./download_casr.sh
```

This builds and downloads:
- `casr-binaries.tar.gz` - CASR binaries built from https://github.com/thisiscam/casr (branch: claude/casr-cluster-investigation-SEpPg)
  - Includes the new `casr-cluster-map` tool for full crash-to-cluster mapping
- `libc6_2.35-0ubuntu3_amd64.deb` - GLIBC 2.35 package

**Build Process:**
- The script builds CASR in a container (using Podman or Docker) to ensure reproducibility
- Uses `Dockerfile.casr-builder` with Rust 1.93 base image
- Extracts compiled binaries from the container
- No local Rust toolchain required on the host system

### 2. Container Build

The Dockerfile templates (`dockerfile_fuzzing_template` and `dockerfile_fix_template`) now:

1. Extract GLIBC 2.35 to `/opt/glibc-new/`
2. Extract CASR to `/usr/local/casr/`
3. Patch CASR binaries with `patchelf`:
   - Set RPATH to `/opt/glibc-new/lib/x86_64-linux-gnu`
   - Set interpreter to `/opt/glibc-new/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`
4. Create symlinks in `/usr/bin/` for all CASR tools:
   - `casr-afl`
   - `casr-cluster`
   - `casr-cluster-map` - New tool for full crash-to-cluster mapping
   - `casr-libfuzzer`
   - `casr-san`
   - `casr-gdb`
5. Verify installation with `casr-san --version`

## Runtime Usage

### In Python Code

The `_run_casr_in_container()` method in `fuzzing_only_benchmark.py` handles crash deduplication:

```python
async def _run_casr_in_container(
    self,
    container: ArvoContainer,
    fuzzer_type: FuzzerType,
    crash_files: List[str],
    case_id: int,
    target: FuzzingTarget,
) -> Dict[str, str]:
    """Run CASR deduplication and return crash-to-cluster mapping."""
```

**Process:**
1. Determine crash directory based on fuzzer type (libFuzzer vs AFL++)
2. Find fuzzer binary path
3. Run `casr-libfuzzer -i <crashes_dir> -o <output_dir> -- <fuzzer_binary>`
4. Parse CASR output directory structure (cl1/, cl2/, ...) to map crashes to clusters
5. Return dict: `{"crash-abc123": "cl1", "crash-def456": "cl2", ...}`

### CASR Output

CASR creates:
- **Cluster directories:** `cl1/`, `cl2/`, ..., `clN/`
- **Crash reports:** `<cluster_dir>/<crash_file>.casrep` (JSON format with stack traces, severity, etc.)
- **Original crashes:** Copied into their respective cluster directories

Example output structure:
```
/tmp/casr_reports_ground_truth/
├── cl1/
│   ├── crash-abc123
│   └── crash-abc123.casrep
├── cl2/
│   ├── crash-def456
│   └── crash-def456.casrep
├── oom/
└── timeout/
```

## Verification

Test CASR in a container:

```bash
# Start a container
podman exec -it <container_id> bash

# Verify CASR installation
casr-san --version
# Should output: casr-san 2.13.0

# Check GLIBC
ls -la /opt/glibc-new/lib/x86_64-linux-gnu/

# Test deduplication
casr-libfuzzer -i /tmp/crashes -o /tmp/casr_test -- /out/*_fuzzer
ls /tmp/casr_test/
# Should show cl1/, cl2/, etc.
```

## Benefits

1. **No System Impact:** The new GLIBC installation doesn't interfere with existing system libraries
2. **Transparent Usage:** CASR tools work like normal commands via wrapper scripts
3. **Accurate Deduplication:** Groups crashes by stack trace similarity, reducing duplicate analysis
4. **Rich Reports:** CASR provides exploitability assessment and detailed crash information

## References

- CASR GitHub: https://github.com/ispras/casr
- CASR Paper: https://arxiv.org/abs/2112.13719
- Ubuntu GLIBC Packages: http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/
