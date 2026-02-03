#!/bin/bash
# Build script for portable agent runtime
#
# This script:
# 1. Builds the Docker image that creates the runtime bundle
# 2. Extracts the runtime from the container
# 3. Adds the agent-entrypoint.sh and agent code
# 4. Creates agent-runtime.tar.gz
#
# Usage:
#   ./build.sh                    # Build and extract
#   ./build.sh --no-cache         # Force rebuild from scratch
#   ./build.sh --upload gs://...  # Upload to GCS after building

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
IMAGE_NAME="agent-runtime-builder"

# Parse arguments
NO_CACHE=""
GCS_BUCKET=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        --upload)
            GCS_BUCKET="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--no-cache] [--upload gs://bucket/path]"
            exit 1
            ;;
    esac
done

echo "=== Building Portable Agent Runtime ==="
echo "Script directory: ${SCRIPT_DIR}"
echo "Output directory: ${OUTPUT_DIR}"

# Clean previous output
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

# Step 1: Build Docker image
echo ""
echo "=== Step 1: Building Docker image ==="
docker build ${NO_CACHE} \
    -f "${SCRIPT_DIR}/Dockerfile.builder" \
    -t "${IMAGE_NAME}" \
    "${SCRIPT_DIR}"

# Step 2: Extract runtime from container
echo ""
echo "=== Step 2: Extracting runtime from container ==="
CONTAINER_ID=$(docker create "${IMAGE_NAME}")
docker cp "${CONTAINER_ID}:/runtime" "${OUTPUT_DIR}/agent-runtime"
docker rm "${CONTAINER_ID}"

# Step 3: Add agent-entrypoint.sh
echo ""
echo "=== Step 3: Adding agent-entrypoint.sh ==="
if [ -f "${SCRIPT_DIR}/agent-entrypoint.sh" ]; then
    cp "${SCRIPT_DIR}/agent-entrypoint.sh" "${OUTPUT_DIR}/agent-runtime/bin/"
    chmod +x "${OUTPUT_DIR}/agent-runtime/bin/agent-entrypoint.sh"
    echo "Copied agent-entrypoint.sh"
else
    echo "WARNING: agent-entrypoint.sh not found, skipping"
fi

# Step 4: Copy agent and evaluation code
echo ""
echo "=== Step 4: Copying agent and evaluation code ==="

# Create directories
mkdir -p "${OUTPUT_DIR}/agent-runtime/agent"
mkdir -p "${OUTPUT_DIR}/agent-runtime/evaluation"

# Copy agent module (for patching)
if [ -d "${SCRIPT_DIR}/agent" ]; then
    cp -r "${SCRIPT_DIR}/agent/"* "${OUTPUT_DIR}/agent-runtime/agent/"
    echo "Copied agent code"
else
    echo "WARNING: agent/ directory not found"
fi

# Copy evaluation module (for fuzzing)
if [ -d "${SCRIPT_DIR}/evaluation" ]; then
    cp -r "${SCRIPT_DIR}/evaluation/"* "${OUTPUT_DIR}/agent-runtime/evaluation/"
    echo "Copied evaluation code"
else
    echo "WARNING: evaluation/ directory not found"
fi

# Step 5: Create tarball
echo ""
echo "=== Step 5: Creating tarball ==="
cd "${OUTPUT_DIR}"

# #region agent log
DEBUG_LOG="/Users/camyang/Desktop/ant_fellow/PurpleLlama/CybersecurityBenchmarks/.cursor/debug.log"
XATTR_BEFORE=$(xattr -lr agent-runtime 2>/dev/null | wc -l | tr -d ' ')
echo "{\"location\":\"build.sh:step5\",\"message\":\"xattr count before strip\",\"data\":{\"count\":${XATTR_BEFORE}},\"timestamp\":$(date +%s)000,\"sessionId\":\"debug-session\",\"hypothesisId\":\"B\"}" >> "${DEBUG_LOG}"
# #endregion

# Strip macOS extended attributes (like com.apple.provenance) from all files
# These xattrs get embedded in PAX headers and cause "Ignoring unknown extended
# header keyword" warnings when extracted on Linux
if command -v xattr &> /dev/null; then
    echo "Stripping macOS extended attributes..."
    xattr -cr agent-runtime
fi

# #region agent log
XATTR_AFTER=$(xattr -lr agent-runtime 2>/dev/null | wc -l | tr -d ' ')
echo "{\"location\":\"build.sh:step5\",\"message\":\"xattr count after strip\",\"data\":{\"count\":${XATTR_AFTER}},\"timestamp\":$(date +%s)000,\"sessionId\":\"debug-session\",\"hypothesisId\":\"B\"}" >> "${DEBUG_LOG}"
# #endregion

# COPYFILE_DISABLE=1 prevents macOS from including AppleDouble (._*) files
COPYFILE_DISABLE=1 tar -czf agent-runtime.tar.gz -C agent-runtime .

# Step 5b: Compute and save source hash for change detection
echo ""
echo "=== Step 5b: Computing source hash ==="
# Source the shared hash computation script (single source of truth)
HASH_SCRIPT="${SCRIPT_DIR}/../scripts/compute_hashes.sh"
# shellcheck source=/dev/null
source "${HASH_SCRIPT}"
SOURCE_HASH=$(compute_runtime_hash "${SCRIPT_DIR}")
echo "${SOURCE_HASH}" > "${OUTPUT_DIR}/source-hash.txt"
echo "Source hash: ${SOURCE_HASH}"

# Calculate sizes
UNCOMPRESSED_SIZE=$(du -sh agent-runtime | cut -f1)
COMPRESSED_SIZE=$(ls -lh agent-runtime.tar.gz | awk '{print $5}')

echo ""
echo "=== Build Complete ==="
echo "  Uncompressed: ${UNCOMPRESSED_SIZE}"
echo "  Compressed:   ${COMPRESSED_SIZE}"
echo ""
echo "Output files:"
echo "  ${OUTPUT_DIR}/agent-runtime/      (extracted directory)"
echo "  ${OUTPUT_DIR}/agent-runtime.tar.gz (compressed tarball)"

# Step 6: Upload to GCS if requested
if [ -n "${GCS_BUCKET}" ]; then
    echo ""
    echo "=== Step 6: Uploading to GCS ==="
    gsutil cp "${OUTPUT_DIR}/agent-runtime.tar.gz" "${GCS_BUCKET}/agent-runtime.tar.gz"
    echo "Uploaded to: ${GCS_BUCKET}/agent-runtime.tar.gz"
fi

# Step 7: Quick verification
echo ""
echo "=== Verification ==="
echo "Testing Python in extracted runtime..."
if "${OUTPUT_DIR}/agent-runtime/lib/ld-linux-x86-64.so.2" \
    --library-path "${OUTPUT_DIR}/agent-runtime/lib" \
    "${OUTPUT_DIR}/agent-runtime/python/bin/python3.11" --version 2>/dev/null; then
    echo "Python: OK"
else
    echo "Python: FAILED (this is expected on macOS, test on Linux)"
fi

echo ""
echo "To test on different glibc versions, run:"
echo "  ./test_agent_runtime.sh"
