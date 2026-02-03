#!/bin/bash
# Fuzz Task Script for Cloud Batch
#
# Unified fuzzing script that handles both Ground Truth and LLM patches.
# Uses the -fix image which has CASR for crash deduplication.
#
# Environment variables (set by Cloud Batch):
#   BATCH_TASK_INDEX   - Task index (0-based)
#   BUCKET_NAME        - GCS bucket for results
#   ARTIFACT_REGISTRY  - Artifact Registry path
#   ARVO_CASES         - Comma-separated list of ARVO case IDs
#   FUZZING_DURATION   - Fuzzing duration in seconds (default: 300)
#   RUN_ID             - Unique run identifier
#   BUILD_VERSION      - Version hash for container images (default: "latest")
#   TARGET             - Fuzzing target: "ground_truth" or "llm_patch"
#   MODEL              - Model name (e.g., "claude-sonnet-4-20250514" or "ground_truth")

set -e

# =============================================================================
# Configuration
# =============================================================================

WORKDIR="/tmp/arvo-fuzz"
RUNTIME_DIR="/opt/agent-runtime"
OUTPUT_DIR="/tmp/output"
mkdir -p "${WORKDIR}" "${RUNTIME_DIR}" "${OUTPUT_DIR}"
cd "${WORKDIR}"

# Parse case list into array
IFS=',' read -ra CASES <<< "${ARVO_CASES}"
TOTAL_CASES=${#CASES[@]}

# Determine which case this task handles
if [ -z "${BATCH_TASK_INDEX}" ]; then
    echo "ERROR: BATCH_TASK_INDEX not set"
    exit 1
fi

if [ "${BATCH_TASK_INDEX}" -ge "${TOTAL_CASES}" ]; then
    echo "Task index ${BATCH_TASK_INDEX} >= total cases ${TOTAL_CASES}, skipping"
    exit 0
fi

CASE_ID="${CASES[${BATCH_TASK_INDEX}]}"

# Defaults
FUZZING_DURATION="${FUZZING_DURATION:-300}"
BUILD_VERSION="${BUILD_VERSION:-latest}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
TARGET="${TARGET:-ground_truth}"
MODEL="${MODEL:-ground_truth}"

# Patch cache location (for LLM patches)
PATCH_CACHE="gs://${BUCKET_NAME}/patches/case_${CASE_ID}/${MODEL}"

echo "==========================================="
echo "Fuzz Task (Unified Fuzzing)"
echo "==========================================="
echo "Task Index:        ${BATCH_TASK_INDEX}"
echo "Case ID:           ${CASE_ID}"
echo "Target:            ${TARGET}"
echo "Model:             ${MODEL}"
echo "Run ID:            ${RUN_ID}"
echo "Fuzzing Duration:  ${FUZZING_DURATION}s"
echo "Build Version:     ${BUILD_VERSION}"
echo "Bucket:            ${BUCKET_NAME}"
echo "Artifact Registry: ${ARTIFACT_REGISTRY}"
if [ "${TARGET}" = "llm_patch" ]; then
    echo "Patch Cache:       ${PATCH_CACHE}"
fi
echo "==========================================="

# =============================================================================
# Install Docker (if not present)
# =============================================================================

# Ensure Docker is in PATH (may not be set in Cloud Batch environment)
export PATH="/usr/bin:/usr/local/bin:$PATH"

if ! command -v docker &> /dev/null; then
    echo "[*] Installing Docker..."
    apt-get update
    apt-get install -y docker.io
    systemctl start docker
fi

# Ensure Docker daemon is running
if ! systemctl is-active --quiet docker; then
    echo "[*] Starting Docker daemon..."
    systemctl start docker
fi

# Configure Docker to authenticate with Artifact Registry
echo "[*] Configuring Docker authentication..."
REGISTRY_HOST="$(echo ${ARTIFACT_REGISTRY} | cut -d'/' -f1)"
gcloud auth configure-docker "${REGISTRY_HOST}" --quiet

# =============================================================================
# For LLM patches: Check that patch exists and was successful
# =============================================================================

BINARY_PATH=""
ORIGINAL_CRASH_TYPE=""

if [ "${TARGET}" = "llm_patch" ]; then
    echo ""
    echo "[*] Checking patch cache for LLM binary..."
    
    # Check if patch result exists (job dependency ensures patch job completed)
    CACHED_RESULT=$(gsutil cat "${PATCH_CACHE}/result.json" 2>/dev/null || echo "")
    
    if [ -z "${CACHED_RESULT}" ]; then
        echo "ERROR: No patch result found at ${PATCH_CACHE}/result.json"
        echo "Patch job may have failed to produce a result."
        exit 1
    fi
    
    # Check if patch fixed the crash
    CRASH_FIXED=$(echo "${CACHED_RESULT}" | grep -o '"crash_fixed": *[^,}]*' | grep -o 'true\|false' || echo "false")
    
    if [ "${CRASH_FIXED}" != "true" ]; then
        echo "[*] Patch did not fix crash (crash_fixed=${CRASH_FIXED}), skipping fuzzing"
        echo "==========================================="
        echo "Fuzz Task Skipped: Case ${CASE_ID}"
        echo "Reason: Patch did not fix the original crash"
        echo "==========================================="
        exit 0
    fi
    
    # Download rebuilt binary
    echo "[*] Downloading rebuilt binary from cache..."
    if ! gsutil cp "${PATCH_CACHE}/rebuilt_binary" "/tmp/rebuilt_binary" 2>/dev/null; then
        echo "ERROR: Could not download rebuilt binary from ${PATCH_CACHE}/rebuilt_binary"
        exit 1
    fi
    
    BINARY_PATH="/tmp/rebuilt_binary"
    echo "[*] Downloaded LLM binary to ${BINARY_PATH}"
    
    # Get original crash type for reproduction checking
    ORIGINAL_CRASH_TYPE=$(echo "${CACHED_RESULT}" | grep -o '"original_crash_type": *"[^"]*"' | sed 's/.*: *"\([^"]*\)"/\1/' || echo "")
    if [ -n "${ORIGINAL_CRASH_TYPE}" ]; then
        echo "[*] Original crash type: ${ORIGINAL_CRASH_TYPE}"
    fi
fi

# =============================================================================
# Pull container image from Artifact Registry (uses -fix image with CASR)
# =============================================================================

IMAGE="${ARTIFACT_REGISTRY}/arvo-${CASE_ID}-fix:${BUILD_VERSION}"
echo "[*] Pulling container image: ${IMAGE}"

docker pull "${IMAGE}" || {
    echo "ERROR: Failed to pull ${IMAGE}"
    exit 1
}

# =============================================================================
# Download agent runtime (for evaluation module)
# =============================================================================

echo "[*] Downloading agent runtime from GCS..."
gsutil cp "gs://${BUCKET_NAME}/agent-runtime/agent-runtime.tar.gz" "${WORKDIR}/"
tar -xzf "${WORKDIR}/agent-runtime.tar.gz" -C "${RUNTIME_DIR}" --strip-components=1

# Verify runtime
if [ ! -f "${RUNTIME_DIR}/bin/agent-entrypoint.sh" ]; then
    echo "ERROR: Agent runtime not properly extracted"
    ls -la "${RUNTIME_DIR}"
    exit 1
fi

# =============================================================================
# Run fuzzing using evaluation module
# =============================================================================

echo ""
echo "=== Running Fuzzing (${TARGET}) ==="
echo ""

# Start container in background
CONTAINER_ID=$(docker run -d \
    --platform linux/amd64 \
    -v "${RUNTIME_DIR}:/agent-runtime:ro" \
    -v "${OUTPUT_DIR}:/output" \
    "${IMAGE}" \
    sleep infinity)

echo "[*] Container started: ${CONTAINER_ID}"

# For LLM patches: copy the rebuilt binary into the container
if [ "${TARGET}" = "llm_patch" ] && [ -n "${BINARY_PATH}" ]; then
    echo "[*] Copying rebuilt binary into container..."
    docker cp "${BINARY_PATH}" "${CONTAINER_ID}:/tmp/rebuilt_binary"
    
    # Fix RPATH so the binary can find shared libraries in /out/
    docker exec "${CONTAINER_ID}" patchelf --set-rpath '/out:$ORIGIN' /tmp/rebuilt_binary 2>/dev/null || true
fi

# Build the evaluation command
EVAL_CMD="python3 -m evaluation.main \
    --case-id ${CASE_ID} \
    --model ${MODEL} \
    --target ${TARGET} \
    --duration ${FUZZING_DURATION} \
    --output-dir /output \
    --verbose"

# Add binary path for LLM patches
if [ "${TARGET}" = "llm_patch" ]; then
    EVAL_CMD="${EVAL_CMD} --binary-path /tmp/rebuilt_binary"
fi

# Add original crash type if available
if [ -n "${ORIGINAL_CRASH_TYPE}" ]; then
    EVAL_CMD="${EVAL_CMD} --original-crash-type ${ORIGINAL_CRASH_TYPE}"
fi

# Run fuzzing
echo "[*] Running: ${EVAL_CMD}"
docker exec "${CONTAINER_ID}" /agent-runtime/bin/agent-entrypoint.sh ${EVAL_CMD} 2>&1 | tee "${OUTPUT_DIR}/fuzz_${TARGET}.log"

# Stop container
echo "[*] Stopping container..."
docker stop "${CONTAINER_ID}" > /dev/null
docker rm "${CONTAINER_ID}" > /dev/null

# =============================================================================
# Extract results from evaluation output
# =============================================================================

echo "[*] Processing results..."

# Determine result file path based on target
if [ "${TARGET}" = "ground_truth" ]; then
    RESULT_FILE="${OUTPUT_DIR}/case_${CASE_ID}/ground_truth/fuzzing_result_ground_truth.json"
else
    RESULT_FILE="${OUTPUT_DIR}/case_${CASE_ID}/${MODEL}/fuzzing_result_llm_patch.json"
fi

if [ -f "${RESULT_FILE}" ]; then
    CRASH_COUNT=$(grep -o '"total_crashes": *[0-9]*' "${RESULT_FILE}" | grep -o '[0-9]*' || echo "0")
    UNIQUE_CRASHES=$(grep -o '"unique_crashes": *[0-9]*' "${RESULT_FILE}" | grep -o '[0-9]*' || echo "0")
else
    echo "[!] Warning: Result file not found at ${RESULT_FILE}"
    CRASH_COUNT=0
    UNIQUE_CRASHES=0
fi

# =============================================================================
# Upload results to GCS
# =============================================================================

echo "[*] Uploading results to GCS..."

# The evaluation module creates output at ${OUTPUT_DIR}/case_${CASE_ID}/${MODEL}/
# We upload from the case directory to avoid duplicating case_id in the path
LOCAL_RESULT_DIR="${OUTPUT_DIR}/case_${CASE_ID}"

if [ "${TARGET}" = "ground_truth" ]; then
    RESULT_PATH="gs://${BUCKET_NAME}/results/case_${CASE_ID}/gt/${RUN_ID}/"
else
    RESULT_PATH="gs://${BUCKET_NAME}/results/case_${CASE_ID}/${MODEL}/${RUN_ID}/fuzz/"
fi

# Upload the case results (without the case_id directory wrapper)
gsutil -m cp -r "${LOCAL_RESULT_DIR}/*" "${RESULT_PATH}" || {
    echo "WARNING: Failed to upload some results"
}

# Also upload the top-level fuzz log
gsutil cp "${OUTPUT_DIR}/fuzz_${TARGET}.log" "${RESULT_PATH}" || true

# =============================================================================
# Cleanup
# =============================================================================

echo "[*] Cleaning up..."
docker rmi "${IMAGE}" || true

echo ""
echo "==========================================="
echo "Fuzz Task Complete: Case ${CASE_ID}"
echo "Target:         ${TARGET}"
echo "Model:          ${MODEL}"
echo "Total crashes:  ${CRASH_COUNT}"
echo "Unique crashes: ${UNIQUE_CRASHES}"
echo "Results:        ${RESULT_PATH}"
echo "==========================================="
