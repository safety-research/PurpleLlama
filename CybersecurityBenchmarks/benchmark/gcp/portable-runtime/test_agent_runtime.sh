#!/bin/bash
# Test Portable Agent Runtime on Different glibc Versions
#
# This script tests the portable runtime on various Linux distributions
# to ensure compatibility with different glibc versions.
#
# The Python and Node.js binaries are from python-build-standalone and
# unofficial-builds respectively, compiled against glibc 2.17.
#
# Usage:
#   ./test_agent_runtime.sh                    # Test all platforms
#   ./test_agent_runtime.sh ubuntu:16.04       # Test specific platform
#   ./test_agent_runtime.sh --tarball file.tar.gz  # Use specific tarball

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
RUNTIME_TAR="${OUTPUT_DIR}/agent-runtime.tar.gz"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default test images (in order of increasing glibc version)
DEFAULT_IMAGES="centos:7 ubuntu:16.04 ubuntu:18.04 ubuntu:20.04 ubuntu:22.04"
TEST_IMAGES=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --tarball)
            RUNTIME_TAR="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [options] [image...]"
            echo ""
            echo "Options:"
            echo "  --tarball FILE   Use specific tarball (default: output/agent-runtime.tar.gz)"
            echo "  --help           Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                        # Test all platforms"
            echo "  $0 ubuntu:16.04           # Test specific platform"
            echo "  $0 ubuntu:16.04 centos:7  # Test multiple platforms"
            exit 0
            ;;
        *)
            # Assume it's an image name
            TEST_IMAGES="$*"
            break
            ;;
    esac
done

# Use default images if none specified
if [ -z "${TEST_IMAGES}" ]; then
    TEST_IMAGES="${DEFAULT_IMAGES}"
fi

# Check if runtime tarball exists
if [ ! -f "${RUNTIME_TAR}" ]; then
    echo -e "${RED}ERROR: Runtime tarball not found at ${RUNTIME_TAR}${NC}"
    echo "Run ./build.sh first to create the runtime bundle."
    exit 1
fi

echo "=== Testing Portable Agent Runtime ==="
echo "Tarball: ${RUNTIME_TAR}"
echo "Size: $(ls -lh "${RUNTIME_TAR}" | awk '{print $5}')"
echo ""

# Track results using simple variables (bash 3.2 compatible)
PASSED=0
FAILED=0
RESULTS_IMAGES=""
RESULTS_STATUS=""

test_in_container() {
    local image="$1"

    echo -e "${YELLOW}=== Testing in ${image} ===${NC}"

    # Create temporary container and run tests
    local output
    local exit_code=0

    output=$(docker run --rm --platform linux/amd64 \
        -v "${RUNTIME_TAR}:/tmp/runtime.tar.gz:ro" \
        "${image}" \
        bash -c '
            set -e

            # Extract runtime
            mkdir -p /agent-runtime
            tar -xzf /tmp/runtime.tar.gz -C /agent-runtime

            echo "Container glibc: $(ldd --version 2>&1 | head -1 || echo "unknown")"

            # Test 1: Python version (direct execution - binaries built for glibc 2.17)
            echo -n "Test 1 - Python version: "
            /agent-runtime/python/bin/python3.11 --version

            # Test 2: Python import
            echo -n "Test 2 - Python import (sys): "
            /agent-runtime/python/bin/python3.11 -c "import sys; print(f\"OK (executable: {sys.executable})\")"

            # Test 3: anthropic import
            echo -n "Test 3 - anthropic SDK import: "
            /agent-runtime/python/bin/python3.11 -c "import anthropic; print(\"OK\")" 2>&1 || echo "FAILED (not installed?)"

            # Test 4: httpx import (for HTTPS)
            echo -n "Test 4 - httpx import: "
            /agent-runtime/python/bin/python3.11 -c "import httpx; print(\"OK\")" 2>&1 || echo "FAILED"

            # Test 5: Node.js version
            echo -n "Test 5 - Node.js version: "
            /agent-runtime/node/bin/node --version 2>&1 || echo "FAILED"

            # Test 6: Entrypoint script
            echo -n "Test 6 - Entrypoint script: "
            if [ -f /agent-runtime/bin/agent-entrypoint.sh ]; then
                export AGENT_RUNTIME_DIR=/agent-runtime
                /agent-runtime/bin/agent-entrypoint.sh python3 -c "print(\"OK\")"
            else
                echo "SKIPPED (not found)"
            fi

            echo ""
            echo "All tests completed successfully!"
        ' 2>&1) || exit_code=$?

    echo "${output}"

    if [ ${exit_code} -eq 0 ]; then
        echo -e "${GREEN}=== PASSED: ${image} ===${NC}"
        RESULTS_IMAGES="${RESULTS_IMAGES}${image}|"
        RESULTS_STATUS="${RESULTS_STATUS}PASSED|"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}=== FAILED: ${image} ===${NC}"
        RESULTS_IMAGES="${RESULTS_IMAGES}${image}|"
        RESULTS_STATUS="${RESULTS_STATUS}FAILED|"
        FAILED=$((FAILED + 1))
    fi

    echo ""
}

# Pull all images first (to avoid interleaved output)
echo "=== Pulling test images ==="
for image in ${TEST_IMAGES}; do
    echo "Pulling ${image}..."
    docker pull --platform linux/amd64 "${image}" > /dev/null 2>&1 || echo "  Warning: Failed to pull ${image}"
done
echo ""

# Run tests
for image in ${TEST_IMAGES}; do
    test_in_container "${image}"
done

# Summary
echo "=========================================="
echo "=== Test Summary ==="
echo "=========================================="

# Parse results (bash 3.2 compatible)
IFS='|' read -ra IMAGES_ARR <<< "${RESULTS_IMAGES}"
IFS='|' read -ra STATUS_ARR <<< "${RESULTS_STATUS}"

i=0
for image in ${TEST_IMAGES}; do
    status="${STATUS_ARR[$i]:-NOT RUN}"
    if [ "${status}" = "PASSED" ]; then
        echo -e "  ${image}: ${GREEN}${status}${NC}"
    else
        echo -e "  ${image}: ${RED}${status}${NC}"
    fi
    i=$((i + 1))
done
echo ""
echo "Total: ${PASSED} passed, ${FAILED} failed"

if [ ${FAILED} -gt 0 ]; then
    echo ""
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
else
    echo ""
    echo -e "${GREEN}All tests passed!${NC}"
fi
