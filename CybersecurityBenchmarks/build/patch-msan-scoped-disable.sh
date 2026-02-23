#!/bin/bash
# =============================================================================
# patch-msan-scoped-disable.sh
# =============================================================================
#
# Backports __msan_scoped_disable/enable_interceptor_checks into MSan runtimes
# that predate rL336447 (July 2018).
#
# Background: Our prebuilt libFuzzer bundles uninstrumented libc++ in the
# __Fuzzer ABI namespace.  On LLVM 8+, FuzzerDriver calls
# __msan_scoped_disable_interceptor_checks() to tell MSan's interceptors
# (strlen, stat, fopen, memcmp, ...) to skip shadow validation for
# fuzzer-internal data.  On older runtimes these functions don't exist,
# causing false positives from stale shadow on SSO strings moved during
# vector reallocation.
#
# The fix: the internal TLS counter (in_interceptor_scope) and its check
# (IsInInterceptorScope) already exist in old runtimes -- only the public
# API entry points are missing.  We globalize the counter symbol and add a
# tiny shim that defines the two functions.
#
# Usage: Run inside the container at Docker build time.
#   ./patch-msan-scoped-disable.sh
#
# Requirements: nm, objcopy, ar, clang (or cc)
# =============================================================================

set -euo pipefail

# Detect architecture
PROJECT_ARCH=$(grep -oP 'ARCHITECTURE=\K\w+' /bin/arvo 2>/dev/null || echo "x86_64")
if [ "$PROJECT_ARCH" = "i386" ]; then
    FUZZER_SUFFIX="i386"
else
    FUZZER_SUFFIX="x86_64"
fi

# Detect clang major version. __msan_scoped_disable_interceptor_checks was
# added in rL336447 (July 2018), which shipped in LLVM 8.  Clang 8+ has it
# natively; we only need to patch clang <= 7.
CLANG_VER=$(clang --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1 | cut -d. -f1)
if [ -z "$CLANG_VER" ]; then
    echo "[patch-msan] Cannot detect clang version -- skipping"
    exit 0
fi
echo "[patch-msan] Clang major version: $CLANG_VER"
if [ "$CLANG_VER" -ge 8 ] 2>/dev/null; then
    echo "[patch-msan] Clang >= 8 -- __msan_scoped_disable_interceptor_checks available natively, no patch needed"
    exit 0
fi

# Find MSan runtime archive
MSAN_LIB=$(find /usr/local/lib/clang -name "libclang_rt.msan-${FUZZER_SUFFIX}.a" 2>/dev/null | head -1)
if [ -z "$MSAN_LIB" ]; then
    echo "[patch-msan] No MSan runtime found -- not an MSan build, skipping"
    exit 0
fi
echo "[patch-msan] Found MSan runtime: $MSAN_LIB"

WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT

CC="${CC:-clang}"
if ! command -v "$CC" >/dev/null 2>&1; then
    CC="cc"
fi

# =============================================================================
# Part 1: Backport __msan_scoped_disable_interceptor_checks
# =============================================================================

# Check if already present (belt and suspenders).
# Avoid grep -q to prevent SIGPIPE killing nm when pipefail is set.
if nm "$MSAN_LIB" 2>/dev/null | grep "__msan_scoped_disable_interceptor_checks" >/dev/null; then
    echo "[patch-msan] __msan_scoped_disable_interceptor_checks already present -- OK"
else
echo "[patch-msan] __msan_scoped_disable_interceptor_checks NOT found -- patching"

cd "$WORK"

# Extract the interceptors object file
OBJ_NAME="msan_interceptors.cc.o"
if ! ar x "$MSAN_LIB" "$OBJ_NAME" 2>/dev/null; then
    echo "[patch-msan] WARNING: Could not extract $OBJ_NAME from archive -- skipping"
    exit 0
fi

# Dynamically discover the mangled symbol name for in_interceptor_scope
SYMBOL=$(nm "$OBJ_NAME" 2>/dev/null | grep 'in_interceptor_scope' | awk '{print $3}' | head -1)
if [ -z "$SYMBOL" ]; then
    echo "[patch-msan] WARNING: in_interceptor_scope symbol not found in $OBJ_NAME -- skipping"
    exit 0
fi
echo "[patch-msan] Found symbol: $SYMBOL (binding: $(nm "$OBJ_NAME" | grep "$SYMBOL" | awk '{print $2}'))"

# Globalize the symbol so our shim can reference it
objcopy --globalize-symbol="$SYMBOL" "$OBJ_NAME"
echo "[patch-msan] Globalized $SYMBOL (now: $(nm "$OBJ_NAME" | grep "$SYMBOL" | awk '{print $2}'))"

# Compile the shim that defines the two missing API functions
cat > scoped_disable_shim.c << EOF
/* Backport of __msan_scoped_disable/enable_interceptor_checks (rL336447). */
extern __thread int ${SYMBOL};
void __msan_scoped_disable_interceptor_checks(void) { ++${SYMBOL}; }
void __msan_scoped_enable_interceptor_checks(void) { --${SYMBOL}; }
EOF

$CC -O2 -fPIC -c scoped_disable_shim.c -o scoped_disable_shim.o
echo "[patch-msan] Compiled shim ($(nm scoped_disable_shim.o | grep -c ' T ') exported functions)"

# Update the archive: replace the patched .o and add the shim
ar r "$MSAN_LIB" "$OBJ_NAME" scoped_disable_shim.o
echo "[patch-msan] Updated $MSAN_LIB"

# Verify
if nm "$MSAN_LIB" 2>/dev/null | grep "__msan_scoped_disable_interceptor_checks" >/dev/null; then
    echo "[patch-msan] SUCCESS: __msan_scoped_disable_interceptor_checks is now available"
else
    echo "[patch-msan] ERROR: scoped disable patch verification failed"
    exit 1
fi

fi  # end of scoped_disable else block

# =============================================================================
# Part 2: Backport __sanitizer_acquire_crash_state
# =============================================================================
# This function is used by libFuzzer's crash/exit/timeout/OOM callbacks to
# atomically claim "crash state" (preventing double-reporting).  Without it,
# crashes are detected by the sanitizer but the fuzzer exits 0 instead of
# non-zero, making arvo appear to succeed.
#
# Unlike the scoped-disable backport, this function is fully self-contained
# (no internal sanitizer state needed).  It was added to sanitizer_common
# around LLVM 7; some clang 6-trunk builds lack it.

if nm "$MSAN_LIB" 2>/dev/null | grep " T __sanitizer_acquire_crash_state" >/dev/null; then
    echo "[patch-msan] __sanitizer_acquire_crash_state already present -- OK"
else
    echo "[patch-msan] __sanitizer_acquire_crash_state NOT found -- adding shim"
    cd "$WORK"
    cat > acquire_crash_state_shim.c << 'SHIMEOF'
/* Backport of __sanitizer_acquire_crash_state for pre-LLVM-7 runtimes.
   Atomically sets a flag; returns 1 on first call, 0 on subsequent calls.
   This prevents double-reporting of crashes from signal handlers. */
static int in_crash_state = 0;
int __sanitizer_acquire_crash_state(void) {
    return __sync_bool_compare_and_swap(&in_crash_state, 0, 1);
}
SHIMEOF
    $CC -O2 -fPIC -c acquire_crash_state_shim.c -o acquire_crash_state_shim.o
    ar r "$MSAN_LIB" acquire_crash_state_shim.o
    if nm "$MSAN_LIB" 2>/dev/null | grep " T __sanitizer_acquire_crash_state" >/dev/null; then
        echo "[patch-msan] SUCCESS: __sanitizer_acquire_crash_state is now available"
    else
        echo "[patch-msan] ERROR: acquire_crash_state patch verification failed"
        exit 1
    fi
fi
