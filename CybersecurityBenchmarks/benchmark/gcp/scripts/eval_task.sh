#!/bin/bash
# Eval Task Script for Cloud Batch
#
# This script runs as a single task in the EVAL Cloud Batch job.
# It runs the Agent SDK inside an ARVO container to generate and verify patches.
#
# Environment variables (set by Cloud Batch):
#   BATCH_TASK_INDEX  - Task index (0-based)
#   BUCKET_NAME       - GCS bucket for assets and results
#   ARTIFACT_REGISTRY - Artifact Registry path
#   ARVO_CASES        - Comma-separated list of ARVO case IDs
#   MODEL             - Anthropic model to use
#   RUN_ID            - Unique run identifier
#   FUZZING_DURATION  - Fuzzing duration in seconds
#   ANTHROPIC_API_KEY - API key (from Secret Manager)
#   FORCE_REPATCH     - If "true", ignore cached patches and re-run agent
#   FUZZ_ONLY         - If "true", require cached patches (fail if not found)
#   BUILD_VERSION     - Version hash for container images (default: "latest")

set -e

# =============================================================================
# Configuration
# =============================================================================

WORKDIR="/tmp/arvo-eval"
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

# Cache settings
FORCE_REPATCH="${FORCE_REPATCH:-false}"
FUZZ_ONLY="${FUZZ_ONLY:-false}"
BUILD_VERSION="${BUILD_VERSION:-latest}"
PATCH_CACHE="gs://${BUCKET_NAME}/patches/case_${CASE_ID}/${MODEL}"

echo "==========================================="
echo "Eval Task"
echo "==========================================="
echo "Task Index:        ${BATCH_TASK_INDEX}"
echo "Case ID:           ${CASE_ID}"
echo "Model:             ${MODEL}"
echo "Run ID:            ${RUN_ID}"
echo "Fuzzing Duration:  ${FUZZING_DURATION}s"
echo "Force Repatch:     ${FORCE_REPATCH}"
echo "Fuzz Only:         ${FUZZ_ONLY}"
echo "Build Version:     ${BUILD_VERSION}"
echo "Patch Cache:       ${PATCH_CACHE}"
echo "Bucket:            ${BUCKET_NAME}"
echo "Artifact Registry: ${ARTIFACT_REGISTRY}"
echo "==========================================="

# =============================================================================
# Install Docker
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
# Download agent runtime
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

echo "[*] Agent runtime ready at ${RUNTIME_DIR}"

# =============================================================================
# Pull and run container
# =============================================================================

IMAGE="${ARTIFACT_REGISTRY}/arvo-${CASE_ID}-vul:${BUILD_VERSION}"
echo "[*] Pulling container image: ${IMAGE}"

docker pull "${IMAGE}" || {
    echo "ERROR: Failed to pull ${IMAGE}"
    exit 1
}

echo "[*] Starting container..."

# Start container in background (we'll run multiple commands)
CONTAINER_ID=$(docker run -d \
    -v "${RUNTIME_DIR}:/agent-runtime:ro" \
    -v "${OUTPUT_DIR}:/output" \
    -e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}" \
    -e "CASE_ID=${CASE_ID}" \
    -e "MODEL=${MODEL}" \
    -e "FUZZING_DURATION=${FUZZING_DURATION}" \
    "${IMAGE}" \
    sleep infinity)

echo "[*] Container started: ${CONTAINER_ID}"

# Helper function to run commands in container
run_in_container() {
    docker exec "${CONTAINER_ID}" /agent-runtime/bin/agent-entrypoint.sh "$@"
}

# =============================================================================
# Step 1: Check Patch Cache
# =============================================================================

echo ""
echo "[*] Step 1: Checking patch cache..."

SKIP_AGENT="false"
CRASH_FIXED="false"
PATCH_RESULT="/output/case_${CASE_ID}/autopatchbench/${MODEL}/result.json"

# Try to fetch cached result
CACHED_RESULT=$(gsutil cat "${PATCH_CACHE}/result.json" 2>/dev/null || echo "")

if [ -n "${CACHED_RESULT}" ]; then
    CACHED_CRASH_FIXED=$(echo "${CACHED_RESULT}" | grep -o '"crash_fixed": *[^,}]*' | grep -o 'true\|false' || echo "false")
    echo "[*] Found cached patch: crash_fixed=${CACHED_CRASH_FIXED}"

    if [ "${FORCE_REPATCH}" = "true" ]; then
        echo "[*] FORCE_REPATCH=true, ignoring cache and re-running agent"
    elif [ "${CACHED_CRASH_FIXED}" = "true" ]; then
        echo "[*] Using cached patch (crash_fixed=true)"
        SKIP_AGENT="true"
        CRASH_FIXED="true"

        # Download cached artifacts into container
        mkdir -p "${OUTPUT_DIR}/case_${CASE_ID}/autopatchbench/${MODEL}"
        gsutil cp "${PATCH_CACHE}/result.json" "${OUTPUT_DIR}/case_${CASE_ID}/autopatchbench/${MODEL}/"
        gsutil cp "${PATCH_CACHE}/patch.txt" "${OUTPUT_DIR}/case_${CASE_ID}/autopatchbench/${MODEL}/" 2>/dev/null || true

        # Download rebuilt binary and copy into container
        if gsutil cp "${PATCH_CACHE}/rebuilt_binary" "/tmp/rebuilt_binary" 2>/dev/null; then
            docker cp "/tmp/rebuilt_binary" "${CONTAINER_ID}:/out/fuzzer"
            echo "[*] Restored cached rebuilt binary to /out/fuzzer"
        else
            echo "[!] Warning: Could not download cached rebuilt binary"
            SKIP_AGENT="false"
            CRASH_FIXED="false"
        fi
    else
        echo "[*] Cached patch did not fix crash, re-running agent"
    fi
else
    echo "[*] No cached patch found"

    if [ "${FUZZ_ONLY}" = "true" ]; then
        echo "ERROR: FUZZ_ONLY=true but no cached patch found for case ${CASE_ID}"
        docker stop "${CONTAINER_ID}" > /dev/null 2>&1 || true
        docker rm "${CONTAINER_ID}" > /dev/null 2>&1 || true
        exit 1
    fi
fi

# =============================================================================
# Step 2: Run Agent (Patching) - if not using cache
# =============================================================================

if [ "${SKIP_AGENT}" = "false" ]; then
    echo ""
    echo "[*] Step 2: Running agent (patching)..."
    run_in_container python3 -m agent.main \
        --case-id "${CASE_ID}" \
        --agent autopatchbench \
        --model "${MODEL}" \
        --output-dir /output \
        --verbose

    # Check if patching succeeded
    if docker exec "${CONTAINER_ID}" test -f "${PATCH_RESULT}"; then
        CRASH_FIXED=$(docker exec "${CONTAINER_ID}" cat "${PATCH_RESULT}" | grep -o '"crash_fixed": *[^,}]*' | grep -o 'true\|false')
        echo "[*] Patch result: crash_fixed=${CRASH_FIXED}"

        # Upload patch artifacts to cache
        echo "[*] Uploading patch artifacts to cache..."
        docker cp "${CONTAINER_ID}:${PATCH_RESULT}" "/tmp/result.json"
        gsutil cp "/tmp/result.json" "${PATCH_CACHE}/"

        # Upload patch file if it exists
        PATCH_FILE="/output/case_${CASE_ID}/autopatchbench/${MODEL}/patch.txt"
        if docker exec "${CONTAINER_ID}" test -f "${PATCH_FILE}"; then
            docker cp "${CONTAINER_ID}:${PATCH_FILE}" "/tmp/patch.txt"
            gsutil cp "/tmp/patch.txt" "${PATCH_CACHE}/"
        fi

        # Upload rebuilt binary if crash was fixed
        if [ "${CRASH_FIXED}" = "true" ]; then
            if docker exec "${CONTAINER_ID}" test -f "/out/fuzzer"; then
                docker cp "${CONTAINER_ID}:/out/fuzzer" "/tmp/rebuilt_binary"
                gsutil cp "/tmp/rebuilt_binary" "${PATCH_CACHE}/"
                echo "[*] Cached rebuilt binary for future runs"
            fi
        fi
    else
        echo "[!] Warning: Patch result file not found"
        CRASH_FIXED="false"
    fi
else
    echo ""
    echo "[*] Step 2: Skipped (using cached patch)"
fi

# =============================================================================
# Step 3: Run Evaluation (Fuzzing) - only if patch fixes the crash
# =============================================================================

if [ "${CRASH_FIXED}" = "true" ]; then
    echo ""
    echo "[*] Step 3: Running evaluation (fuzzing) for ${FUZZING_DURATION}s..."

    # Get original crash type for reproduction checking
    ORIGINAL_CRASH_TYPE=$(docker exec "${CONTAINER_ID}" cat "${PATCH_RESULT}" | grep -o '"original_crash_type": *"[^"]*"' | sed 's/.*: *"\([^"]*\)"/\1/' || echo "")

    run_in_container python3 -m evaluation.main \
        --case-id "${CASE_ID}" \
        --model "${MODEL}" \
        --target llm_patch \
        --duration "${FUZZING_DURATION}" \
        --output-dir /output \
        ${ORIGINAL_CRASH_TYPE:+--original-crash-type "${ORIGINAL_CRASH_TYPE}"} \
        --verbose
else
    echo ""
    echo "[*] Skipping fuzzing - patch did not fix the original crash"
fi

# =============================================================================
# Stop container
# =============================================================================

echo ""
echo "[*] Stopping container..."
docker stop "${CONTAINER_ID}" > /dev/null
docker rm "${CONTAINER_ID}" > /dev/null

# =============================================================================
# Upload results
# =============================================================================

echo "[*] Uploading results to GCS..."
RESULT_PATH="gs://${BUCKET_NAME}/results/case_${CASE_ID}/${MODEL}/${RUN_ID}/"
gsutil -m cp -r "${OUTPUT_DIR}/*" "${RESULT_PATH}" || {
    echo "WARNING: Failed to upload some results"
}

# Cleanup
docker rmi "${IMAGE}" || true

echo ""
echo "==========================================="
echo "Eval Task Complete: Case ${CASE_ID}"
echo "Results: ${RESULT_PATH}"
echo "==========================================="
