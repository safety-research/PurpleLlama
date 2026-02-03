#!/bin/bash
# Fuzz Task Script for Cloud Batch
#
# Unified fuzzing script that handles both Ground Truth and LLM patches.
# Uses the -fix image which has CASR for crash deduplication.
#
# Storage structure:
#   Results (persistent experiment data):
#     gs://{bucket}/results/{experiment_id}/{case_id}/{model}/
#       - crashes.json, metadata.json (for both LLM and GT)
#   Run logs (debugging):
#     gs://{bucket}/runs/{run_id}/logs/{case_id}/{model}/
#       - fuzz.log, casr/ directory
#
# Environment variables (set by Cloud Batch):
#   BATCH_TASK_INDEX   - Task index (0-based)
#   BUCKET_NAME        - GCS bucket for results
#   ARTIFACT_REGISTRY  - Artifact Registry path
#   ARVO_CASES         - Comma-separated list of ARVO case IDs
#   FUZZING_DURATION   - Fuzzing duration in seconds (default: 300)
#   RUN_ID             - Unique run identifier
#   EXPERIMENT_ID      - Experiment ID for grouping results
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
EXPERIMENT_ID="${EXPERIMENT_ID:-default}"

# GCS paths
if [ "${TARGET}" = "ground_truth" ]; then
    RESULTS_PATH="gs://${BUCKET_NAME}/results/${EXPERIMENT_ID}/${CASE_ID}/gt"
    RUN_LOGS_PATH="gs://${BUCKET_NAME}/runs/${RUN_ID}/logs/${CASE_ID}/gt"
else
    RESULTS_PATH="gs://${BUCKET_NAME}/results/${EXPERIMENT_ID}/${CASE_ID}/${MODEL}"
    RUN_LOGS_PATH="gs://${BUCKET_NAME}/runs/${RUN_ID}/logs/${CASE_ID}/${MODEL}"
fi

echo "==========================================="
echo "Fuzz Task (Unified Fuzzing)"
echo "==========================================="
echo "Task Index:        ${BATCH_TASK_INDEX}"
echo "Case ID:           ${CASE_ID}"
echo "Target:            ${TARGET}"
echo "Model:             ${MODEL}"
echo "Run ID:            ${RUN_ID}"
echo "Experiment ID:     ${EXPERIMENT_ID}"
echo "Fuzzing Duration:  ${FUZZING_DURATION}s"
echo "Build Version:     ${BUILD_VERSION}"
echo "Results Path:      ${RESULTS_PATH}"
echo "Run Logs Path:     ${RUN_LOGS_PATH}"
echo "Bucket:            ${BUCKET_NAME}"
echo "Artifact Registry: ${ARTIFACT_REGISTRY}"
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
    echo "[*] Checking experiment results for LLM binary..."
    
    # Check if patch result exists in experiment
    PATCH_RESULT=$(gsutil cat "${RESULTS_PATH}/result.json" 2>/dev/null || echo "")
    
    if [ -z "${PATCH_RESULT}" ]; then
        echo "ERROR: No patch result found at ${RESULTS_PATH}/result.json"
        echo "Patch job may have failed to produce a result."
        exit 1
    fi
    
    # Check if patch fixed the crash
    CRASH_FIXED=$(echo "${PATCH_RESULT}" | grep -o '"crash_fixed": *[^,}]*' | grep -o 'true\|false' || echo "false")
    
    if [ "${CRASH_FIXED}" != "true" ]; then
        echo "[*] Patch did not fix crash (crash_fixed=${CRASH_FIXED}), skipping fuzzing"
        echo "==========================================="
        echo "Fuzz Task Skipped: Case ${CASE_ID}"
        echo "Reason: Patch did not fix the original crash"
        echo "==========================================="
        exit 0
    fi
    
    # Download rebuilt binary from experiment results
    echo "[*] Downloading rebuilt binary from experiment results..."
    if ! gsutil cp "${RESULTS_PATH}/rebuilt_binary" "/tmp/rebuilt_binary" 2>/dev/null; then
        echo "ERROR: Could not download rebuilt binary from ${RESULTS_PATH}/rebuilt_binary"
        exit 1
    fi
    
    BINARY_PATH="/tmp/rebuilt_binary"
    echo "[*] Downloaded LLM binary to ${BINARY_PATH}"
    
    # Get original crash type for reproduction checking
    ORIGINAL_CRASH_TYPE=$(echo "${PATCH_RESULT}" | grep -o '"original_crash_type": *"[^"]*"' | sed 's/.*: *"\([^"]*\)"/\1/' || echo "")
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
    --security-opt seccomp=unconfined \
    --init \
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
docker exec "${CONTAINER_ID}" /agent-runtime/bin/agent-entrypoint.sh ${EVAL_CMD} 2>&1 | tee "${OUTPUT_DIR}/fuzz.log"

# Stop container
echo "[*] Stopping container..."
docker stop "${CONTAINER_ID}" > /dev/null
docker rm "${CONTAINER_ID}" > /dev/null

# =============================================================================
# Extract results from evaluation output
# =============================================================================

echo "[*] Processing results..."

# Find the result file (handle both old nested and new flat structure)
RESULT_FILE=""
CRASHES_FILE=""
EVAL_OUTPUT_DIR=""

if [ "${TARGET}" = "ground_truth" ]; then
    # Try flat structure first
    if [ -f "${OUTPUT_DIR}/fuzzing_result_ground_truth.json" ]; then
        RESULT_FILE="${OUTPUT_DIR}/fuzzing_result_ground_truth.json"
        CRASHES_FILE="${OUTPUT_DIR}/crashes.json"
        EVAL_OUTPUT_DIR="${OUTPUT_DIR}"
    elif [ -f "${OUTPUT_DIR}/case_${CASE_ID}/ground_truth/fuzzing_result_ground_truth.json" ]; then
        RESULT_FILE="${OUTPUT_DIR}/case_${CASE_ID}/ground_truth/fuzzing_result_ground_truth.json"
        CRASHES_FILE="${OUTPUT_DIR}/case_${CASE_ID}/ground_truth/crashes.json"
        EVAL_OUTPUT_DIR="${OUTPUT_DIR}/case_${CASE_ID}/ground_truth"
    fi
else
    # LLM patch - try flat structure first
    if [ -f "${OUTPUT_DIR}/fuzzing_result_llm_patch.json" ]; then
        RESULT_FILE="${OUTPUT_DIR}/fuzzing_result_llm_patch.json"
        CRASHES_FILE="${OUTPUT_DIR}/crashes.json"
        EVAL_OUTPUT_DIR="${OUTPUT_DIR}"
    elif [ -f "${OUTPUT_DIR}/case_${CASE_ID}/${MODEL}/fuzzing_result_llm_patch.json" ]; then
        RESULT_FILE="${OUTPUT_DIR}/case_${CASE_ID}/${MODEL}/fuzzing_result_llm_patch.json"
        CRASHES_FILE="${OUTPUT_DIR}/case_${CASE_ID}/${MODEL}/crashes.json"
        EVAL_OUTPUT_DIR="${OUTPUT_DIR}/case_${CASE_ID}/${MODEL}"
    fi
fi

CRASH_COUNT=0
UNIQUE_CRASHES=0

if [ -n "${RESULT_FILE}" ] && [ -f "${RESULT_FILE}" ]; then
    CRASH_COUNT=$(grep -o '"total_crashes": *[0-9]*' "${RESULT_FILE}" | grep -o '[0-9]*' || echo "0")
    UNIQUE_CRASHES=$(grep -o '"unique_crashes": *[0-9]*' "${RESULT_FILE}" | grep -o '[0-9]*' || echo "0")
else
    echo "[!] Warning: Result file not found"
fi

# =============================================================================
# Upload RESULTS (persistent experiment data)
# =============================================================================

echo "[*] Uploading results to experiment..."

# Upload crashes.json if it exists
if [ -n "${CRASHES_FILE}" ] && [ -f "${CRASHES_FILE}" ]; then
    gsutil cp "${CRASHES_FILE}" "${RESULTS_PATH}/"
fi

# Create and upload fuzz metadata.json
cat > /tmp/fuzz_metadata.json << EOF
{
    "run_id": "${RUN_ID}",
    "experiment_id": "${EXPERIMENT_ID}",
    "case_id": ${CASE_ID},
    "model": "${MODEL}",
    "target": "${TARGET}",
    "fuzzing_duration": ${FUZZING_DURATION},
    "total_crashes": ${CRASH_COUNT},
    "unique_crashes": ${UNIQUE_CRASHES},
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# For GT, this is the main metadata. For LLM, append fuzz info.
if [ "${TARGET}" = "ground_truth" ]; then
    gsutil cp "/tmp/fuzz_metadata.json" "${RESULTS_PATH}/metadata.json"
else
    # For LLM patches, we already have patch metadata, so save as fuzz_metadata.json
    gsutil cp "/tmp/fuzz_metadata.json" "${RESULTS_PATH}/fuzz_metadata.json"
fi

# =============================================================================
# Upload RUN LOGS (debugging/ephemeral)
# =============================================================================

echo "[*] Uploading run logs..."

# Upload fuzz log
if [ -f "${OUTPUT_DIR}/fuzz.log" ]; then
    gsutil cp "${OUTPUT_DIR}/fuzz.log" "${RUN_LOGS_PATH}/"
fi

# Upload fuzzing result JSON (detailed, for debugging)
if [ -n "${RESULT_FILE}" ] && [ -f "${RESULT_FILE}" ]; then
    gsutil cp "${RESULT_FILE}" "${RUN_LOGS_PATH}/"
fi

# Upload CASR files if they exist
if [ -n "${EVAL_OUTPUT_DIR}" ] && [ -d "${EVAL_OUTPUT_DIR}/casr" ]; then
    gsutil -m cp -r "${EVAL_OUTPUT_DIR}/casr" "${RUN_LOGS_PATH}/" || true
fi

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
echo "Results:        ${RESULTS_PATH}"
echo "Run Logs:       ${RUN_LOGS_PATH}"
echo "==========================================="
