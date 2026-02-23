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

echo "==========================================="
echo "Eval Task"
echo "==========================================="
echo "Task Index:        ${BATCH_TASK_INDEX}"
echo "Case ID:           ${CASE_ID}"
echo "Model:             ${MODEL}"
echo "Run ID:            ${RUN_ID}"
echo "Fuzzing Duration:  ${FUZZING_DURATION}s"
echo "Bucket:            ${BUCKET_NAME}"
echo "Artifact Registry: ${ARTIFACT_REGISTRY}"
echo "==========================================="

# =============================================================================
# Install Docker
# =============================================================================

if ! command -v docker &> /dev/null; then
    echo "[*] Installing Docker..."
    apt-get update
    apt-get install -y docker.io
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

IMAGE="${ARTIFACT_REGISTRY}/arvo-${CASE_ID}-vul:latest"
echo "[*] Pulling container image: ${IMAGE}"

docker pull "${IMAGE}" || {
    echo "ERROR: Failed to pull ${IMAGE}"
    exit 1
}

echo "[*] Running agent inside container..."

# Run the container with:
# - Agent runtime mounted read-only
# - Output directory mounted for results
# - API key passed as environment variable
docker run --rm \
    -v "${RUNTIME_DIR}:/agent-runtime:ro" \
    -v "${OUTPUT_DIR}:/output" \
    -e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}" \
    -e "CASE_ID=${CASE_ID}" \
    -e "MODEL=${MODEL}" \
    -e "FUZZING_DURATION=${FUZZING_DURATION}" \
    "${IMAGE}" \
    /agent-runtime/bin/agent-entrypoint.sh \
    python3 /agent-runtime/agent/agent.py \
        --case-id "${CASE_ID}" \
        --model "${MODEL}" \
        --output-dir /output \
        --fuzzing-duration "${FUZZING_DURATION}" \
        --verbose

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
