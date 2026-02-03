#!/bin/bash
# Ground Truth Task Script for Cloud Batch
#
# This script runs as a single task in the GT Cloud Batch job.
# It fuzzes the -fix (ground truth patched) version of ARVO cases
# to establish baseline crash rates.
#
# Environment variables (set by Cloud Batch):
#   BATCH_TASK_INDEX   - Task index (0-based)
#   BUCKET_NAME        - GCS bucket for results
#   ARTIFACT_REGISTRY  - Artifact Registry path
#   ARVO_CASES         - Comma-separated list of ARVO case IDs
#   FUZZING_DURATION   - Fuzzing duration in seconds (default: 300)
#   RUN_ID             - Unique run identifier
#   BUILD_VERSION      - Version hash for container images (default: "latest")

set -e

# =============================================================================
# Configuration
# =============================================================================

WORKDIR="/tmp/arvo-gt"
RESULTS_DIR="${WORKDIR}/results"
mkdir -p "${WORKDIR}" "${RESULTS_DIR}"
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
FUZZING_DURATION="${FUZZING_DURATION:-300}"
BUILD_VERSION="${BUILD_VERSION:-latest}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"

echo "==========================================="
echo "Ground Truth Task"
echo "==========================================="
echo "Task Index:        ${BATCH_TASK_INDEX}"
echo "Case ID:           ${CASE_ID}"
echo "Run ID:            ${RUN_ID}"
echo "Fuzzing Duration:  ${FUZZING_DURATION}s"
echo "Build Version:     ${BUILD_VERSION}"
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
# Pull container image from Artifact Registry
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

RUNTIME_DIR="/opt/agent-runtime"
mkdir -p "${RUNTIME_DIR}"

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
echo "=== Running Ground Truth Fuzzing ==="
echo ""

OUTPUT_DIR="${RESULTS_DIR}/case_${CASE_ID}/gt/${RUN_ID}"
mkdir -p "${OUTPUT_DIR}"

# Run container with evaluation module
docker run --rm \
    --platform linux/amd64 \
    -v "${RUNTIME_DIR}:/agent-runtime:ro" \
    -v "${OUTPUT_DIR}:/output" \
    "${IMAGE}" \
    /agent-runtime/bin/agent-entrypoint.sh \
    python3 -m evaluation.main \
        --case-id "${CASE_ID}" \
        --model "ground_truth" \
        --target "ground_truth" \
        --duration "${FUZZING_DURATION}" \
        --output-dir /output \
        --verbose 2>&1 | tee "${OUTPUT_DIR}/gt.log"

# =============================================================================
# Extract results from evaluation output
# =============================================================================

echo "[*] Processing results..."

# Read crash count from evaluation result
RESULT_FILE="${OUTPUT_DIR}/case_${CASE_ID}/ground_truth/fuzzing_result_ground_truth.json"
if [ -f "${RESULT_FILE}" ]; then
    CRASH_COUNT=$(grep -o '"total_crashes": *[0-9]*' "${RESULT_FILE}" | grep -o '[0-9]*' || echo "0")
    UNIQUE_CRASHES=$(grep -o '"unique_crashes": *[0-9]*' "${RESULT_FILE}" | grep -o '[0-9]*' || echo "0")
else
    CRASH_COUNT=0
    UNIQUE_CRASHES=0
fi

# =============================================================================
# Upload results to GCS
# =============================================================================

echo "[*] Uploading results to GCS..."
gsutil -m cp -r "${OUTPUT_DIR}/*" "gs://${BUCKET_NAME}/results/case_${CASE_ID}/gt/${RUN_ID}/"

# =============================================================================
# Cleanup (optional - VM is ephemeral anyway)
# =============================================================================

echo "[*] Cleaning up..."
docker rmi "${IMAGE}" || true

echo ""
echo "==========================================="
echo "Ground Truth Task Complete: Case ${CASE_ID}"
echo "Total crashes:  ${CRASH_COUNT}"
echo "Unique crashes: ${UNIQUE_CRASHES}"
echo "Results: gs://${BUCKET_NAME}/results/case_${CASE_ID}/gt/${RUN_ID}/"
echo "==========================================="
