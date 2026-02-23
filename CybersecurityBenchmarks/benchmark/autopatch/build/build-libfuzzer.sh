#!/bin/bash
# =============================================================================
# build-libfuzzer.sh - Build namespace-isolated libFuzzer archives
# =============================================================================
#
# Builds libFuzzer with a private copy of libc++ in the __Fuzzer ABI namespace,
# matching LLVM's approach for compiler-rt. This ensures the fuzzer's internal
# C++ runtime is invisible to MSan-instrumented project code, eliminating
# false positives from uninstrumented libc++ symbol collisions.
#
# Produces (for each architecture):
#   libFuzzer-{arch}.a          - with main()
#   libFuzzer_no_main-{arch}.a  - without main()
#
# Supported architectures: x86_64, i386
#
# Usage:
#   ./build-libfuzzer.sh                    # Build both x86_64 and i386
#   ARCHS="x86_64" ./build-libfuzzer.sh    # Build x86_64 only
#   OUTPUT_DIR=/tmp/out ./build-libfuzzer.sh
#
# Requirements: clang, cmake, ninja-build, binutils, gcc-multilib (for i386)
# =============================================================================

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
LIBFUZZER_SRC="${SCRIPT_DIR}/libfuzzer-modern"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/libfuzzer-prebuilt}"
ARCHS="${ARCHS:-x86_64 i386}"
LLVM_VERSION="${LLVM_VERSION:-10}"

# LLVM source URL (only need libcxx, libcxxabi, and cmake modules)
LLVM_RELEASE_URL="https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}.0.0"

echo "==========================================="
echo "Build Namespace-Isolated libFuzzer"
echo "==========================================="
echo "Source:       ${LIBFUZZER_SRC}"
echo "Output:       ${OUTPUT_DIR}"
echo "Architectures: ${ARCHS}"
echo "LLVM Version: ${LLVM_VERSION}"
echo "==========================================="

# Verify libfuzzer source exists
if [ ! -d "${LIBFUZZER_SRC}" ] || [ ! -f "${LIBFUZZER_SRC}/FuzzerDriver.cpp" ]; then
    echo "ERROR: libfuzzer source not found at ${LIBFUZZER_SRC}"
    exit 1
fi

# Create temp working directory
WORK_DIR=$(mktemp -d)
trap "rm -rf ${WORK_DIR}" EXIT
echo "[*] Working directory: ${WORK_DIR}"

# =============================================================================
# Step 1: Download LLVM libc++ source
# =============================================================================

echo ""
echo "[*] Step 1: Downloading LLVM ${LLVM_VERSION} libc++ source..."

LLVM_SRC="${WORK_DIR}/llvm-src"
mkdir -p "${LLVM_SRC}"

# Download and extract only what we need
for component in libcxx libcxxabi; do
    TARBALL="${component}-${LLVM_VERSION}.0.0.src.tar.xz"
    echo "    Downloading ${TARBALL}..."
    curl -sSL "${LLVM_RELEASE_URL}/${TARBALL}" -o "${WORK_DIR}/${TARBALL}"
    mkdir -p "${LLVM_SRC}/${component}"
    tar -xf "${WORK_DIR}/${TARBALL}" -C "${LLVM_SRC}/${component}" --strip-components=1
    rm "${WORK_DIR}/${TARBALL}"
done

# We also need the llvm cmake modules for the standalone libc++ build
LLVM_TARBALL="llvm-${LLVM_VERSION}.0.0.src.tar.xz"
echo "    Downloading ${LLVM_TARBALL} (cmake modules only)..."
curl -sSL "${LLVM_RELEASE_URL}/${LLVM_TARBALL}" -o "${WORK_DIR}/${LLVM_TARBALL}"
mkdir -p "${LLVM_SRC}/llvm"
# Extract only the cmake/ directory
tar -xf "${WORK_DIR}/${LLVM_TARBALL}" -C "${LLVM_SRC}/llvm" --strip-components=1 \
    "llvm-${LLVM_VERSION}.0.0.src/cmake" "llvm-${LLVM_VERSION}.0.0.src/CMakeLists.txt" 2>/dev/null || \
    tar -xf "${WORK_DIR}/${LLVM_TARBALL}" -C "${LLVM_SRC}/llvm" --strip-components=1
rm "${WORK_DIR}/${LLVM_TARBALL}"

echo "    LLVM source ready"

# =============================================================================
# Build function for a single architecture
# =============================================================================

build_for_arch() {
    local ARCH="$1"
    local ARCH_FLAGS=""
    local FUZZER_SUFFIX=""

    if [ "$ARCH" = "i386" ] || [ "$ARCH" = "i686" ]; then
        ARCH_FLAGS="-m32"
        FUZZER_SUFFIX="i386"
        echo ""
        echo "[*] Building for i386 (32-bit)..."
    else
        ARCH_FLAGS=""
        FUZZER_SUFFIX="x86_64"
        echo ""
        echo "[*] Building for x86_64..."
    fi

    local BUILD_DIR="${WORK_DIR}/build-${FUZZER_SUFFIX}"
    mkdir -p "${BUILD_DIR}"

    # -----------------------------------------------------------------
    # Step 2: Build libc++ with __Fuzzer namespace (direct compilation, no cmake)
    # -----------------------------------------------------------------

    echo "    [2a] Building libc++ with __Fuzzer namespace..."
    local LIBCXX_BUILD="${BUILD_DIR}/libcxx-build"
    mkdir -p "${LIBCXX_BUILD}"

    local CXX="${CXX:-clang++}"
    local CC="${CC:-clang}"
    local LIBCXX_HEADERS="${LLVM_SRC}/libcxx/include"

    # Common flags for building libc++ with namespace isolation
    # -gdwarf-4: containers use llvm-symbolizer 6.x which only handles DWARF v2-v4.
    # Modern clang defaults to DWARF v5 which causes the symbolizer to hang on
    # large binaries (parsing loop on unrecognized format).
    local LIBCXX_FLAGS="${ARCH_FLAGS} -O2 -fPIC -gdwarf-4"
    LIBCXX_FLAGS="${LIBCXX_FLAGS} -fvisibility=hidden -fvisibility-inlines-hidden"
    LIBCXX_FLAGS="${LIBCXX_FLAGS} -fno-exceptions -fno-rtti"
    # -fno-builtin prevents the compiler from inlining memcpy/memmove/memset.
    # Without this, clang -O2 replaces calls like memcpy(dst, src, 8) with
    # inline load/store instructions. Since this code is NOT compiled with
    # MSan, those inlined writes don't update MSan's shadow memory. MSan then
    # thinks the written memory is still "uninitialized", causing false
    # positives when MSan-intercepted functions (strlen, fopen, etc.) later
    # read it. With -fno-builtin, memory operations remain as actual function
    # calls (call memcpy), which MSan intercepts and uses to correctly
    # propagate shadow state. This is critical on clang 6 where
    # __msan_scoped_disable_interceptor_checks may not be available.
    LIBCXX_FLAGS="${LIBCXX_FLAGS} -fno-builtin"
    LIBCXX_FLAGS="${LIBCXX_FLAGS} -nostdinc++"
    # ABI version MUST be 1 to match the container's system libc++. ABI v2 uses
    # alternate string layout ({data, size, cap}) while v1 uses ({cap, size, data}).
    # If we use v2 but the container has v1, string copy constructors read garbage
    # pointers causing huge allocation crashes in FuzzerDriver on startup.
    LIBCXX_FLAGS="${LIBCXX_FLAGS} -D_LIBCPP_ABI_VERSION=1"
    LIBCXX_FLAGS="${LIBCXX_FLAGS} -D_LIBCPP_ABI_NAMESPACE=__Fuzzer"
    LIBCXX_FLAGS="${LIBCXX_FLAGS} -D_LIBCPP_BUILDING_LIBRARY"
    LIBCXX_FLAGS="${LIBCXX_FLAGS} -D_LIBCPP_DISABLE_EXTERN_TEMPLATE"
    LIBCXX_FLAGS="${LIBCXX_FLAGS} -D_LIBCPP_HAS_NO_PRAGMA_SYSTEM_HEADER"
    LIBCXX_FLAGS="${LIBCXX_FLAGS} -I${LIBCXX_HEADERS}"
    LIBCXX_FLAGS="${LIBCXX_FLAGS} -I${LLVM_SRC}/libcxxabi/include"

    # Compile libc++abi sources
    echo "    Compiling libc++abi..."
    cd "${LIBCXX_BUILD}"
    for cpp in "${LLVM_SRC}/libcxxabi/src"/*.cpp; do
        local basename
        basename=$(basename "$cpp" .cpp)
        # Skip operator new/delete -- these must remain UNDEFINED so the linker
        # resolves them from the system at final link time.  On MSan builds the
        # runtime provides intercepting versions of operator new/delete that
        # properly track allocation shadow state.  If we bundle our own
        # (localized) copies, they call malloc directly; MSan marks the returned
        # memory as uninitialized but never sees the subsequent writes from our
        # uninstrumented code, causing false positives.
        case "$basename" in
            stdlib_new_delete) continue ;;
        esac
        $CXX $LIBCXX_FLAGS -std=c++14 -c "$cpp" -o "cxxabi_${basename}.o" 2>/dev/null &
    done
    wait

    # Compile libc++ sources (excluding unsupported files)
    echo "    Compiling libc++..."
    for cpp in "${LLVM_SRC}/libcxx/src"/*.cpp; do
        local basename
        basename=$(basename "$cpp" .cpp)
        # Skip files that are either not needed or conflict with libc++abi
        case "$basename" in
            filesystem|debug) continue ;;          # need OS support not available
            exception) continue ;;                  # conflicts with libc++abi stdlib_exception (exception hierarchy)
            new) continue ;;                        # duplicates libc++abi operator new/delete
        esac
        $CXX $LIBCXX_FLAGS -std=c++14 -c "$cpp" -o "cxx_${basename}.o" 2>/dev/null &
    done
    wait

    # Compile exception_ptr shim: provides the bare std::exception_ptr methods
    # that future.cpp needs.
    #
    # We can't include libc++'s full exception.cpp because it conflicts with
    # libc++abi's stdlib_exception.cpp on the exception class hierarchy.
    #
    # The fuzzer is built with -fno-exceptions, so exceptions are never actually
    # thrown. The exception_ptr fields in std::promise/future are always null.
    # This shim provides no-op implementations that handle null pointers without
    # pulling in any __cxa_* exception infrastructure, keeping the archive
    # self-contained for C projects (which don't link against libc++).
    # Compile exception_ptr shim: provides the bare std::exception_ptr methods
    # that future.cpp needs.
    #
    # We can't include libc++'s full exception.cpp because it conflicts with
    # libc++abi's stdlib_exception.cpp on the exception class hierarchy.
    #
    # The fuzzer is built with -fno-exceptions, so exceptions are never actually
    # thrown. The exception_ptr fields in std::promise/future are always null.
    # This shim provides no-op implementations that handle null pointers without
    # pulling in any __cxa_* exception infrastructure, keeping the archive
    # self-contained for C projects (which don't link against libc++).
    echo "    Compiling exception_ptr shim..."
    cat > exception_ptr_shim.cpp << 'SHIM_EOF'
#include <cstdlib>

namespace std {

class exception_ptr {
    void* __ptr_;
public:
    ~exception_ptr() noexcept;
    exception_ptr(const exception_ptr& other) noexcept;
    exception_ptr& operator=(const exception_ptr& other) noexcept;
};

exception_ptr::~exception_ptr() noexcept { __ptr_ = nullptr; }
exception_ptr::exception_ptr(const exception_ptr& other) noexcept : __ptr_(other.__ptr_) {}
exception_ptr& exception_ptr::operator=(const exception_ptr& other) noexcept {
    __ptr_ = other.__ptr_;
    return *this;
}

[[noreturn]] void rethrow_exception(exception_ptr) { abort(); }

} // namespace std
SHIM_EOF
    $CXX $LIBCXX_FLAGS -std=c++14 -c exception_ptr_shim.cpp -o cxx_exception_ptr_shim.o 2>&1

    # Archive into libc++.a
    ar rcs libc++.a cxxabi_*.o cxx_*.o
    local LIBCXX_A="${LIBCXX_BUILD}/libc++.a"
    echo "    libc++.a built: $(wc -c < "${LIBCXX_A}") bytes ($(ls cxxabi_*.o cxx_*.o | wc -l) objects)"
    echo "    Headers at: ${LIBCXX_HEADERS}"

    # -----------------------------------------------------------------
    # Step 3: Compile libfuzzer with namespace-matching flags
    # -----------------------------------------------------------------

    echo "    [2b] Compiling libfuzzer with __Fuzzer namespace..."
    local FUZZER_BUILD="${BUILD_DIR}/fuzzer-objs"
    mkdir -p "${FUZZER_BUILD}"

    # Detect C++ standard from clang version
    local CLANG_VERSION
    CLANG_VERSION=$($CXX --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1 | cut -d. -f1)
    local CXX_STD="-std=c++14"
    if [ -n "$CLANG_VERSION" ] && [ "$CLANG_VERSION" -ge 10 ]; then
        CXX_STD="-std=c++17"
    fi

    local CXXFLAGS="${ARCH_FLAGS} -g -gdwarf-4 -O2 -fno-omit-frame-pointer ${CXX_STD}"
    CXXFLAGS="${CXXFLAGS} -fPIC -fvisibility=hidden -fno-exceptions -fno-rtti"
    CXXFLAGS="${CXXFLAGS} -ffunction-sections -fdata-sections"
    # -fno-builtin: same rationale as for libc++ above -- ensure memcpy et al.
    # remain real function calls so MSan can intercept them.
    CXXFLAGS="${CXXFLAGS} -fno-builtin"
    CXXFLAGS="${CXXFLAGS} -nostdinc++ -D_LIBCPP_ABI_VERSION=Fuzzer"
    CXXFLAGS="${CXXFLAGS} -isystem ${LIBCXX_HEADERS}"
    CXXFLAGS="${CXXFLAGS} -I${LIBFUZZER_SRC}"

    cd "${FUZZER_BUILD}"
    for cpp in "${LIBFUZZER_SRC}"/*.cpp; do
        local basename
        basename=$(basename "$cpp" .cpp)
        $CXX $CXXFLAGS -c "$cpp" -o "${basename}.o" &
    done
    wait

    echo "    Compiled $(ls *.o | wc -l) object files"

    # Create raw fuzzer archive (before merging with libc++)
    ar rcs libFuzzer_raw.a *.o

    # -----------------------------------------------------------------
    # Step 4: Partial link + localize hidden symbols
    # -----------------------------------------------------------------

    echo "    [2c] Partial linking fuzzer + libc++..."

    # Create output subdir to avoid mixing merged objects with raw objects
    mkdir -p merged

    # Linker emulation flag for partial link (ld uses -m, not -m32)
    local LD_EMULATION=""
    if [ "$FUZZER_SUFFIX" = "i386" ]; then
        LD_EMULATION="-m elf_i386"
    fi

    # Full archive (with main)
    ld ${LD_EMULATION} -r \
        --whole-archive libFuzzer_raw.a \
        --no-whole-archive "${LIBCXX_A}" \
        -o merged/fuzzer_merged.o

    # Localize ALL non-fuzzer symbols to prevent conflicts with project's libc++
    # --localize-hidden catches most symbols, but libc++abi exception types
    # (std::logic_error, etc.) are in bare std:: and may not have hidden visibility.
    # We use --keep-global-symbol to whitelist only the symbols the fuzzer exports.
    objcopy --localize-hidden merged/fuzzer_merged.o
    # Additionally localize any remaining std:: or libc++abi symbols that leaked
    # through --localize-hidden (e.g., exception types in bare std:: namespace).
    # The --wildcard flag enables glob pattern matching.
    objcopy --wildcard \
        --localize-symbol='_ZNSt*' \
        --localize-symbol='_ZSt*' \
        --localize-symbol='_ZTISt*' \
        --localize-symbol='_ZTSSt*' \
        --localize-symbol='_ZTVSt*' \
        --localize-symbol='_ZNKSt*' \
        --localize-symbol='__cxa_*' \
        merged/fuzzer_merged.o 2>/dev/null || true
    ar qcs "libFuzzer-${FUZZER_SUFFIX}.a" merged/fuzzer_merged.o

    # No-main archive (exclude FuzzerMain.o from raw objects)
    ar rcs libFuzzer_raw_no_main.a $(ls Fuzzer*.o | grep -v FuzzerMain.o)
    ld ${LD_EMULATION} -r \
        --whole-archive libFuzzer_raw_no_main.a \
        --no-whole-archive "${LIBCXX_A}" \
        -o merged/fuzzer_no_main_merged.o

    objcopy --localize-hidden merged/fuzzer_no_main_merged.o
    objcopy --wildcard \
        --localize-symbol='_ZNSt*' \
        --localize-symbol='_ZSt*' \
        --localize-symbol='_ZTISt*' \
        --localize-symbol='_ZTSSt*' \
        --localize-symbol='_ZTVSt*' \
        --localize-symbol='_ZNKSt*' \
        --localize-symbol='__cxa_*' \
        merged/fuzzer_no_main_merged.o 2>/dev/null || true
    ar qcs "libFuzzer_no_main-${FUZZER_SUFFIX}.a" merged/fuzzer_no_main_merged.o

    # Copy to output
    cp "libFuzzer-${FUZZER_SUFFIX}.a" "${OUTPUT_DIR}/"
    cp "libFuzzer_no_main-${FUZZER_SUFFIX}.a" "${OUTPUT_DIR}/"

    echo "    Done: libFuzzer-${FUZZER_SUFFIX}.a ($(stat -c%s "${OUTPUT_DIR}/libFuzzer-${FUZZER_SUFFIX}.a" 2>/dev/null || stat -f%z "${OUTPUT_DIR}/libFuzzer-${FUZZER_SUFFIX}.a") bytes)"
    echo "    Done: libFuzzer_no_main-${FUZZER_SUFFIX}.a"
}

# =============================================================================
# Main: build for each architecture
# =============================================================================

mkdir -p "${OUTPUT_DIR}"

for arch in ${ARCHS}; do
    build_for_arch "${arch}"
done

# =============================================================================
# Package
# =============================================================================

echo ""
echo "[*] Packaging libfuzzer-prebuilt.tar.gz..."
tar -czf "${OUTPUT_DIR}/libfuzzer-prebuilt.tar.gz" -C "${OUTPUT_DIR}" \
    $(cd "${OUTPUT_DIR}" && ls libFuzzer-*.a libFuzzer_no_main-*.a 2>/dev/null)

echo ""
echo "==========================================="
echo "Build complete!"
echo "==========================================="
echo "Output directory: ${OUTPUT_DIR}"
ls -la "${OUTPUT_DIR}"/*.a 2>/dev/null
echo ""
echo "Archive: ${OUTPUT_DIR}/libfuzzer-prebuilt.tar.gz"
ls -la "${OUTPUT_DIR}/libfuzzer-prebuilt.tar.gz"
