#!/bin/sh
# Build libFuzzer with CASR log support
# Creates a self-contained library with all C++ dependencies baked in.
#
# This allows the libfuzzer to work regardless of which C++ stdlib
# the project uses, by including needed libc++ code in the archive.

set -e
# Get absolute path to source directory (needed after cd to work dir)
LIBFUZZER_SRC_DIR=$(cd "$(dirname "$0")" && pwd)

# Support for different architectures (default to native)
# Set ARCH=i386 or ARCH=x86_64 before running to cross-compile
ARCH="${ARCH:-$(uname -m)}"
echo "Building for architecture: $ARCH"

# Architecture-specific flags
ARCH_FLAGS=""
if [ "$ARCH" = "i386" ] || [ "$ARCH" = "i686" ]; then
    ARCH_FLAGS="-m32"
    FUZZER_SUFFIX="i386"
elif [ "$ARCH" = "x86_64" ]; then
    ARCH_FLAGS=""
    FUZZER_SUFFIX="x86_64"
else
    echo "WARNING: Unknown architecture $ARCH, using native"
    FUZZER_SUFFIX="x86_64"
fi

# Find the existing system libfuzzer (informational only - not required)
# Some older clang versions (e.g., 5.0.0) don't include libfuzzer runtime
EXISTING_FUZZER=$(find /usr/local/lib/clang -name "libclang_rt.fuzzer-${FUZZER_SUFFIX}.a" 2>/dev/null | head -1)
if [ -z "$EXISTING_FUZZER" ]; then
    # Fallback to x86_64
    EXISTING_FUZZER=$(find /usr/local/lib/clang -name 'libclang_rt.fuzzer-x86_64.a' 2>/dev/null | head -1)
fi

if [ -z "$EXISTING_FUZZER" ]; then
    echo "NOTE: No system libfuzzer runtime found"
    echo "SOURCE method will be used: compile_libfuzzer will compile from /src/libfuzzer/"
else
    echo "Found system libfuzzer at: $EXISTING_FUZZER"
    echo "LIBRARY method available: can replace clang runtime libraries"
fi

# Detect compiler
CXX="${CXX:-clang++}"

# Find static libc++ and libc++abi libraries
# NOTE: This build.sh is now only used as a FALLBACK for the ~20% of cases
# where OSS-Fuzz's compile_libfuzzer compiles from /src/libfuzzer/ source.
# The primary path uses precompiled namespace-isolated archives (see build-libfuzzer.sh).
# For 32-bit, OSS-Fuzz provides 32-bit libc++ at /usr/i386/lib/
if [ "$ARCH" = "i386" ] || [ "$ARCH" = "i686" ]; then
    # OSS-Fuzz containers have 32-bit libc++ at /usr/i386/lib/
    if [ -f /usr/i386/lib/libc++.a ]; then
        LIBCXX_A="/usr/i386/lib/libc++.a"
        echo "Found 32-bit libc++ at /usr/i386/lib/libc++.a"
    else
        # Fallback: search for i386 libraries
        LIBCXX_A=$(find /usr/local/lib /usr/lib /usr/i386 -name 'libc++.a' -path '*i386*' 2>/dev/null | grep -v msan | head -1)
    fi
    if [ -f /usr/i386/lib/libc++abi.a ]; then
        LIBCXXABI_A="/usr/i386/lib/libc++abi.a"
    else
        LIBCXXABI_A=$(find /usr/local/lib /usr/lib /usr/i386 -name 'libc++abi.a' -path '*i386*' 2>/dev/null | grep -v msan | head -1)
    fi
else
    LIBCXX_A=$(find /usr/local/lib /usr/lib -name 'libc++.a' 2>/dev/null | grep -v msan | grep -v i386 | head -1)
    LIBCXXABI_A=$(find /usr/local/lib /usr/lib -name 'libc++abi.a' 2>/dev/null | grep -v msan | grep -v i386 | head -1)
fi

echo "Found static libc++: ${LIBCXX_A:-not found}"
echo "Found static libc++abi: ${LIBCXXABI_A:-not found}"

# Verify libc++ headers are available
echo "Verifying libc++ headers available..."
if echo '#include <cassert>' | $CXX -stdlib=libc++ -x c++ -c - -o /dev/null 2>/dev/null; then
    STDLIB_FLAG="-stdlib=libc++"
    echo "Using libc++ headers"
else
    # Try to find libc++ headers explicitly
    LIBCXX_INCLUDE=$(find /usr -name 'cstddef' -path '*c++/v1*' 2>/dev/null | head -1 | xargs dirname 2>/dev/null || true)
    if [ -n "$LIBCXX_INCLUDE" ] && echo '#include <cassert>' | $CXX -stdlib=libc++ -I"$LIBCXX_INCLUDE" -x c++ -c - -o /dev/null 2>/dev/null; then
        STDLIB_FLAG="-stdlib=libc++ -I$LIBCXX_INCLUDE"
        echo "Using libc++ with explicit include path: $LIBCXX_INCLUDE"
    else
        echo "ERROR: libc++ headers not found"
        exit 1
    fi
fi

# Detect C++ standard from clang version
CLANG_VERSION=$($CXX --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1 | cut -d. -f1)
if [ -n "$CLANG_VERSION" ] && [ "$CLANG_VERSION" -ge 10 ]; then
    CXX_STD="-std=c++17"
else
    CXX_STD="-std=c++14"
fi
echo "Using C++ standard: $CXX_STD (clang version: ${CLANG_VERSION:-unknown})"

# Common compiler flags (matching LLVM's compiler-rt build)
# -ffunction-sections -fdata-sections allows linker to GC unused code
# -fno-builtin prevents inlining of memcpy/memset/etc so MSan can intercept them
CXXFLAGS="$ARCH_FLAGS -g -O2 -fno-omit-frame-pointer $CXX_STD $STDLIB_FLAG"
CXXFLAGS="$CXXFLAGS -fPIC -fvisibility=hidden -fno-exceptions -fno-rtti"
CXXFLAGS="$CXXFLAGS -ffunction-sections -fdata-sections -fno-builtin"
CXXFLAGS="$CXXFLAGS -I$LIBFUZZER_SRC_DIR"

echo "Final CXXFLAGS: $CXXFLAGS"

# Create work directory
WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT
cd "$WORK_DIR"

# Compile ALL .cpp files from our source tree
echo "Compiling libFuzzer from source..."
for cpp in "$LIBFUZZER_SRC_DIR"/*.cpp; do
    basename=$(basename "$cpp" .cpp)
    echo "  Compiling $basename.cpp..."
    $CXX $CXXFLAGS -c "$cpp" -o "$basename.o"
done

# If static libc++ is available, extract and include needed .o files
# This makes our libfuzzer self-contained
# For 32-bit builds, we use the 32-bit libc++ from /usr/i386/lib/ (OSS-Fuzz provides it)
CAN_BUNDLE_LIBCXX=true
if [ "$ARCH" = "i386" ] || [ "$ARCH" = "i686" ]; then
    # Verify we found 32-bit libc++ (not 64-bit by mistake)
    if [ -n "$LIBCXX_A" ] && [ -f "$LIBCXX_A" ]; then
        # Extract one object and verify it's 32-bit
        TEMP_CHECK=$(mktemp -d)
        cd "$TEMP_CHECK"
        ar x "$LIBCXX_A" 2>/dev/null || true
        SAMPLE_OBJ=$(ls *.o 2>/dev/null | head -1)
        if [ -n "$SAMPLE_OBJ" ]; then
            if objdump -f "$SAMPLE_OBJ" 2>/dev/null | grep -q "elf32-i386\|i386"; then
                echo "=== Verified: libc++ is 32-bit (elf32-i386) ==="
            else
                echo "WARNING: libc++ appears to be 64-bit, skipping bundling for i386"
                CAN_BUNDLE_LIBCXX=false
            fi
        fi
        rm -rf "$TEMP_CHECK"
        cd "$WORK_DIR"
    else
        echo "WARNING: No 32-bit libc++ found, skipping bundling"
        CAN_BUNDLE_LIBCXX=false
    fi
fi

if [ -n "$LIBCXX_A" ] && [ -f "$LIBCXX_A" ] && [ "$CAN_BUNDLE_LIBCXX" = "true" ]; then
    echo "Bundling libc++ code for self-contained library..."
    mkdir -p libcxx_objs
    cd libcxx_objs
    ar x "$LIBCXX_A"
    cd ..

    if [ -n "$LIBCXXABI_A" ] && [ -f "$LIBCXXABI_A" ]; then
        mkdir -p libcxxabi_objs
        cd libcxxabi_objs
        ar x "$LIBCXXABI_A"
        cd ..
    fi

    # Collect all .o files
    mkdir -p all_objs
    cp *.o all_objs/
    cp libcxx_objs/*.o all_objs/
    if [ -d libcxxabi_objs ]; then
        cp libcxxabi_objs/*.o all_objs/
    fi

    # Remove operator new/delete objects so they resolve from the system runtime.
    # On MSan builds, MSan provides intercepting operator new/delete that properly
    # track allocation shadow state.  Bundling our own copies would bypass MSan's
    # interceptors and cause false positives on older clang versions (e.g. clang 6).
    rm -f all_objs/new.o all_objs/*new_delete* 2>/dev/null || true

    # Create fat archive with all object files
    echo "Creating self-contained libFuzzer.a..."
    rm -f "$LIBFUZZER_SRC_DIR/libFuzzer.a"
    ar rcs "$LIBFUZZER_SRC_DIR/libFuzzer.a" all_objs/*.o

    # Create no_main version (remove FuzzerMain.o)
    echo "Creating self-contained libFuzzer_no_main.a..."
    rm -f all_objs/FuzzerMain.o 2>/dev/null || true
    rm -f "$LIBFUZZER_SRC_DIR/libFuzzer_no_main.a"
    ar rcs "$LIBFUZZER_SRC_DIR/libFuzzer_no_main.a" all_objs/*.o

    echo "Self-contained libFuzzer created (includes libc++ code)"
else
    # Fallback: create regular archive without bundled libc++
    echo "Static libc++ not found, creating standard archive..."
    echo "WARNING: This libfuzzer requires the project to link with -lc++"

    rm -f "$LIBFUZZER_SRC_DIR/libFuzzer.a"
    ar rcs "$LIBFUZZER_SRC_DIR/libFuzzer.a" *.o

    rm -f FuzzerMain.o 2>/dev/null || true
    rm -f "$LIBFUZZER_SRC_DIR/libFuzzer_no_main.a"
    ar rcs "$LIBFUZZER_SRC_DIR/libFuzzer_no_main.a" *.o
fi

echo "libFuzzer built successfully"
ls -la "$LIBFUZZER_SRC_DIR/libFuzzer.a" "$LIBFUZZER_SRC_DIR/libFuzzer_no_main.a"
