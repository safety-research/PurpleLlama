#!/bin/bash
# Patch Task Script for Cloud Batch
#
# This script runs as a single task in the PATCH Cloud Batch job.
# It runs the LLM Agent to generate and verify patches, then uploads
# the rebuilt binary to GCS for later fuzzing.
#
# NOTE: This script only does patching - fuzzing is handled by fuzz_task.sh
#
# Storage structure:
#   Results (persistent experiment data):
#     gs://{bucket}/results/{experiment_id}/{case_id}/{model}/
#       - patch.txt, result.json, metadata.json, rebuilt_binary
#   Run logs (debugging):
#     gs://{bucket}/runs/{run_id}/logs/{case_id}/{model}/
#       - chat.md, crash_output.txt, build_output.txt
#
# Environment variables (set by Cloud Batch):
#   BATCH_TASK_INDEX  - Task index (0-based)
#   BUCKET_NAME       - GCS bucket for assets and results
#   ARTIFACT_REGISTRY - Artifact Registry path
#   ARVO_CASES        - Comma-separated list of ARVO case IDs
#   MODEL             - Anthropic model to use
#   RUN_ID            - Unique run identifier
#   EXPERIMENT_ID     - Experiment ID for grouping results
#   ANTHROPIC_API_KEY - API key (from Secret Manager)
#   FORCE_REPATCH     - If "true", ignore cached patches and re-run agent
#   BUILD_VERSION     - Version hash for container images (default: "latest")

set -e

# =============================================================================
# Configuration
# =============================================================================

WORKDIR="/tmp/arvo-patch"
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

# Settings
FORCE_REPATCH="${FORCE_REPATCH:-false}"
BUILD_VERSION="${BUILD_VERSION:-latest}"
EXPERIMENT_ID="${EXPERIMENT_ID:-default}"

# GCS paths
RESULTS_PATH="gs://${BUCKET_NAME}/results/${EXPERIMENT_ID}/${CASE_ID}/${MODEL}"
RUN_LOGS_PATH="gs://${BUCKET_NAME}/runs/${RUN_ID}/logs/${CASE_ID}/${MODEL}"

echo "==========================================="
echo "Patch Task (LLM Patching Only)"
echo "==========================================="
echo "Task Index:        ${BATCH_TASK_INDEX}"
echo "Case ID:           ${CASE_ID}"
echo "Model:             ${MODEL}"
echo "Run ID:            ${RUN_ID}"
echo "Experiment ID:     ${EXPERIMENT_ID}"
echo "Force Repatch:     ${FORCE_REPATCH}"
echo "Build Version:     ${BUILD_VERSION}"
echo "Results Path:      ${RESULTS_PATH}"
echo "Run Logs Path:     ${RUN_LOGS_PATH}"
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
# Pull and run container (uses -vul image for patching)
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
    --security-opt seccomp=unconfined \
    --init \
    -v "${RUNTIME_DIR}:/agent-runtime:ro" \
    -v "${OUTPUT_DIR}:/output" \
    -e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}" \
    -e "CASE_ID=${CASE_ID}" \
    -e "MODEL=${MODEL}" \
    "${IMAGE}" \
    sleep infinity)

echo "[*] Container started: ${CONTAINER_ID}"

# Helper function to run commands in container
run_in_container() {
    docker exec "${CONTAINER_ID}" /agent-runtime/bin/agent-entrypoint.sh "$@"
}

# =============================================================================
# Step 1: Check for existing results in experiment
# =============================================================================

echo ""
echo "[*] Step 1: Checking for existing results in experiment..."

SKIP_AGENT="false"
CRASH_FIXED="false"

# Check if result already exists in the experiment
EXISTING_RESULT=$(gsutil cat "${RESULTS_PATH}/result.json" 2>/dev/null || echo "")

if [ -n "${EXISTING_RESULT}" ]; then
    EXISTING_CRASH_FIXED=$(echo "${EXISTING_RESULT}" | grep -o '"crash_fixed": *[^,}]*' | grep -o 'true\|false' || echo "false")
    echo "[*] Found existing result: crash_fixed=${EXISTING_CRASH_FIXED}"

    if [ "${FORCE_REPATCH}" = "true" ]; then
        echo "[*] FORCE_REPATCH=true, ignoring existing result and re-running agent"
    else
        echo "[*] Using existing result - skipping agent run"
        SKIP_AGENT="true"
        CRASH_FIXED="${EXISTING_CRASH_FIXED}"
    fi
else
    echo "[*] No existing result found in experiment"
fi

# =============================================================================
# Step 2: Run Agent (Patching) - if not using existing result
# =============================================================================

# Agent output path (flat structure)
AGENT_OUTPUT="/output"

if [ "${SKIP_AGENT}" = "false" ]; then
    echo ""
    echo "[*] Step 2: Running agent (patching)..."
    
    # Capture agent exit code - non-zero means patch didn't fix crash, not a script failure
    AGENT_EXIT_CODE=0
    run_in_container python3 -m agent.main \
        --case-id "${CASE_ID}" \
        --agent autopatchbench \
        --model "${MODEL}" \
        --output-dir /output \
        --verbose || AGENT_EXIT_CODE=$?
    
    if [ "${AGENT_EXIT_CODE}" -ne 0 ]; then
        echo "[!] Warning: Agent exited with code ${AGENT_EXIT_CODE} (patch may not have fixed the crash)"
    fi

    # Find result file (handle both old nested and new flat structure)
    RESULT_FILE=""
    if docker exec "${CONTAINER_ID}" test -f "/output/result.json"; then
        RESULT_FILE="/output/result.json"
    elif docker exec "${CONTAINER_ID}" test -f "/output/case_${CASE_ID}/autopatchbench/${MODEL}/result.json"; then
        RESULT_FILE="/output/case_${CASE_ID}/autopatchbench/${MODEL}/result.json"
        AGENT_OUTPUT="/output/case_${CASE_ID}/autopatchbench/${MODEL}"
    fi

    if [ -n "${RESULT_FILE}" ]; then
        CRASH_FIXED=$(docker exec "${CONTAINER_ID}" cat "${RESULT_FILE}" | grep -o '"crash_fixed": *[^,}]*' | grep -o 'true\|false' || echo "false")
        echo "[*] Patch result: crash_fixed=${CRASH_FIXED}"

        # =============================================================================
        # Upload RESULTS (persistent experiment data)
        # =============================================================================
        echo "[*] Uploading results to experiment..."
        
        # Copy result.json
        docker cp "${CONTAINER_ID}:${RESULT_FILE}" "/tmp/result.json"
        gsutil cp "/tmp/result.json" "${RESULTS_PATH}/"

        # Copy patch.txt if it exists
        PATCH_FILE="${AGENT_OUTPUT}/patch.txt"
        if docker exec "${CONTAINER_ID}" test -f "${PATCH_FILE}"; then
            docker cp "${CONTAINER_ID}:${PATCH_FILE}" "/tmp/patch.txt"
            gsutil cp "/tmp/patch.txt" "${RESULTS_PATH}/"
        fi

        # Create and upload metadata.json
        cat > /tmp/metadata.json << EOF
{
    "run_id": "${RUN_ID}",
    "experiment_id": "${EXPERIMENT_ID}",
    "case_id": ${CASE_ID},
    "model": "${MODEL}",
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "crash_fixed": ${CRASH_FIXED}
}
EOF
        gsutil cp "/tmp/metadata.json" "${RESULTS_PATH}/"

        # Upload rebuilt binary if crash was fixed (Python agent saves this automatically)
        REBUILT_BINARY="${AGENT_OUTPUT}/rebuilt_binary"
        if docker exec "${CONTAINER_ID}" test -f "${REBUILT_BINARY}"; then
            docker cp "${CONTAINER_ID}:${REBUILT_BINARY}" "/tmp/rebuilt_binary"
            gsutil cp "/tmp/rebuilt_binary" "${RESULTS_PATH}/"
            echo "[*] Uploaded rebuilt binary to results"
        elif [ "${CRASH_FIXED}" = "true" ]; then
            echo "[!] Warning: crash_fixed=true but rebuilt_binary not found at ${REBUILT_BINARY}"
        fi

        # =============================================================================
        # Upload RUN LOGS (debugging/ephemeral)
        # =============================================================================
        echo "[*] Uploading run logs..."
        
        # Copy chat.md if it exists
        CHAT_FILE="${AGENT_OUTPUT}/chat.md"
        if docker exec "${CONTAINER_ID}" test -f "${CHAT_FILE}"; then
            docker cp "${CONTAINER_ID}:${CHAT_FILE}" "/tmp/chat.md"
            gsutil cp "/tmp/chat.md" "${RUN_LOGS_PATH}/"
        fi

        # Copy crash_output.txt if it exists
        CRASH_OUTPUT="${AGENT_OUTPUT}/crash_output.txt"
        if docker exec "${CONTAINER_ID}" test -f "${CRASH_OUTPUT}"; then
            docker cp "${CONTAINER_ID}:${CRASH_OUTPUT}" "/tmp/crash_output.txt"
            gsutil cp "/tmp/crash_output.txt" "${RUN_LOGS_PATH}/"
        fi

    else
        echo "[!] Warning: Patch result file not found"
        CRASH_FIXED="false"
    fi
else
    echo ""
    echo "[*] Step 2: Skipped (using existing result)"
fi

# =============================================================================
# Stop container
# =============================================================================

echo ""
echo "[*] Stopping container..."
docker stop "${CONTAINER_ID}" > /dev/null
docker rm "${CONTAINER_ID}" > /dev/null

# Cleanup
docker rmi "${IMAGE}" || true

echo ""
echo "==========================================="
echo "Patch Task Complete: Case ${CASE_ID}"
echo "Crash Fixed:   ${CRASH_FIXED}"
echo "Results:       ${RESULTS_PATH}"
echo "Run Logs:      ${RUN_LOGS_PATH}"
echo "==========================================="

# Exit with success even if patch didn't fix crash
# The fuzz job will check the results and skip if no valid binary
exit 0
