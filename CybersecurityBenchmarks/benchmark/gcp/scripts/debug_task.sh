#!/bin/bash
# Debug Task Script for Cloud Batch
#
# This script sets up the same environment as fuzz/patch tasks but waits
# indefinitely, allowing you to SSH into the VM for interactive debugging.
#
# Environment variables (set by Cloud Batch):
#   BATCH_TASK_INDEX   - Task index (0-based)
#   BUCKET_NAME        - GCS bucket for assets
#   ARTIFACT_REGISTRY  - Artifact Registry path
#   ARVO_CASES         - Comma-separated list of ARVO case IDs
#   BUILD_VERSION      - Version hash for container images (default: "latest")
#   TARGET             - Fuzzing target: "ground_truth" or "llm_patch"
#   MODEL              - Model name (e.g., "claude-sonnet-4-20250514" or "ground_truth")
#   JOB_TYPE           - Job type to debug: "fuzz", "patch", or "build"
#
# Usage:
#   After submitting a debug job, find the VM and SSH in:
#     gcloud compute instances list --filter="name~batch"
#     gcloud compute ssh <vm-name> --zone=<zone>
#
#   Then you can:
#     - Run /tmp/fuzz_task.sh manually
#     - docker exec -it <container> bash
#     - Inspect the environment

set -e

# =============================================================================
# Configuration
# =============================================================================

WORKDIR="/tmp/arvo-debug"
RUNTIME_DIR="/opt/agent-runtime"
OUTPUT_DIR="/tmp/output"
mkdir -p "${WORKDIR}" "${RUNTIME_DIR}" "${OUTPUT_DIR}"
cd "${WORKDIR}"

# Parse case list into array
IFS=',' read -ra CASES <<< "${ARVO_CASES}"
TOTAL_CASES=${#CASES[@]}

# Determine which case this task handles
BATCH_TASK_INDEX="${BATCH_TASK_INDEX:-0}"

if [ "${BATCH_TASK_INDEX}" -ge "${TOTAL_CASES}" ]; then
    echo "Task index ${BATCH_TASK_INDEX} >= total cases ${TOTAL_CASES}, using first case"
    BATCH_TASK_INDEX=0
fi

CASE_ID="${CASES[${BATCH_TASK_INDEX}]}"

# Defaults
BUILD_VERSION="${BUILD_VERSION:-latest}"
RUN_ID="${RUN_ID:-debug-$(date +%Y%m%d_%H%M%S)}"
TARGET="${TARGET:-ground_truth}"
MODEL="${MODEL:-ground_truth}"
JOB_TYPE="${JOB_TYPE:-fuzz}"

echo "==========================================="
echo "Debug Task"
echo "==========================================="
echo "Task Index:        ${BATCH_TASK_INDEX}"
echo "Case ID:           ${CASE_ID}"
echo "Job Type:          ${JOB_TYPE}"
echo "Target:            ${TARGET}"
echo "Model:             ${MODEL}"
echo "Run ID:            ${RUN_ID}"
echo "Build Version:     ${BUILD_VERSION}"
echo "Bucket:            ${BUCKET_NAME}"
echo "Artifact Registry: ${ARTIFACT_REGISTRY}"
echo "==========================================="

# =============================================================================
# Install Docker (if not present)
# =============================================================================

export PATH="/usr/bin:/usr/local/bin:$PATH"

if ! command -v docker &> /dev/null; then
    echo "[*] Installing Docker..."
    apt-get update
    apt-get install -y docker.io
    systemctl start docker
fi

if ! systemctl is-active --quiet docker; then
    echo "[*] Starting Docker daemon..."
    systemctl start docker
fi

# Configure Docker authentication
echo "[*] Configuring Docker authentication..."
REGISTRY_HOST="$(echo ${ARTIFACT_REGISTRY} | cut -d'/' -f1)"
gcloud auth configure-docker "${REGISTRY_HOST}" --quiet

# =============================================================================
# Download agent runtime
# =============================================================================

echo "[*] Downloading agent runtime from GCS..."
gsutil cp "gs://${BUCKET_NAME}/agent-runtime/agent-runtime.tar.gz" "${WORKDIR}/"
tar -xzf "${WORKDIR}/agent-runtime.tar.gz" -C "${RUNTIME_DIR}" --strip-components=1

if [ ! -f "${RUNTIME_DIR}/bin/agent-entrypoint.sh" ]; then
    echo "WARNING: Agent runtime not properly extracted"
    ls -la "${RUNTIME_DIR}"
fi

echo "[*] Agent runtime ready at ${RUNTIME_DIR}"

# =============================================================================
# Download task scripts for manual execution
# =============================================================================

echo "[*] Downloading task scripts..."
gsutil cp "gs://${BUCKET_NAME}/scripts/fuzz_task.sh" /tmp/fuzz_task.sh 2>/dev/null || true
gsutil cp "gs://${BUCKET_NAME}/scripts/patch_task.sh" /tmp/patch_task.sh 2>/dev/null || true
gsutil cp "gs://${BUCKET_NAME}/scripts/build_task.sh" /tmp/build_task.sh 2>/dev/null || true
chmod +x /tmp/*_task.sh 2>/dev/null || true

# =============================================================================
# Pull container image
# =============================================================================

# Choose image based on job type
if [ "${JOB_TYPE}" = "patch" ] || [ "${JOB_TYPE}" = "build" ]; then
    IMAGE="${ARTIFACT_REGISTRY}/arvo-${CASE_ID}-vul:${BUILD_VERSION}"
else
    IMAGE="${ARTIFACT_REGISTRY}/arvo-${CASE_ID}-fix:${BUILD_VERSION}"
fi

echo "[*] Pulling container image: ${IMAGE}"
docker pull "${IMAGE}" || {
    echo "WARNING: Failed to pull ${IMAGE}"
    echo "You may need to pull it manually or check that the build job completed."
}

# =============================================================================
# Start container in debug mode
# =============================================================================

echo "[*] Starting container in debug mode..."

CONTAINER_NAME="arvo-debug-${CASE_ID}"

# Remove existing container if any
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

# Start container with all mounts
CONTAINER_ID=$(docker run -d \
    --name "${CONTAINER_NAME}" \
    --platform linux/amd64 \
    -v "${RUNTIME_DIR}:/agent-runtime:ro" \
    -v "${OUTPUT_DIR}:/output" \
    -e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}" \
    -e "CASE_ID=${CASE_ID}" \
    -e "MODEL=${MODEL}" \
    -e "TARGET=${TARGET}" \
    "${IMAGE}" \
    sleep infinity)

echo "[*] Container started: ${CONTAINER_ID}"

# =============================================================================
# Create helper scripts
# =============================================================================

# Create environment file
cat > /tmp/debug_env.sh << ENVEOF
# Debug environment variables
export BUCKET_NAME="${BUCKET_NAME}"
export ARTIFACT_REGISTRY="${ARTIFACT_REGISTRY}"
export ARVO_CASES="${ARVO_CASES}"
export CASE_ID="${CASE_ID}"
export MODEL="${MODEL}"
export TARGET="${TARGET}"
export RUN_ID="${RUN_ID}"
export FUZZING_DURATION="${FUZZING_DURATION:-300}"
export BUILD_VERSION="${BUILD_VERSION}"
export BATCH_TASK_INDEX="${BATCH_TASK_INDEX}"
export CONTAINER_ID="${CONTAINER_ID}"
export CONTAINER_NAME="${CONTAINER_NAME}"
export IMAGE="${IMAGE}"
export RUNTIME_DIR="${RUNTIME_DIR}"
export OUTPUT_DIR="${OUTPUT_DIR}"
ENVEOF

# Create container exec helper
cat > /tmp/container_exec.sh << 'EXECEOF'
#!/bin/bash
# Helper to exec into the debug container
source /tmp/debug_env.sh
docker exec -it "${CONTAINER_NAME}" /agent-runtime/bin/agent-entrypoint.sh "$@"
EXECEOF
chmod +x /tmp/container_exec.sh

# Create container shell helper
cat > /tmp/container_shell.sh << 'SHELLEOF'
#!/bin/bash
# Open a shell in the debug container
source /tmp/debug_env.sh
docker exec -it "${CONTAINER_NAME}" bash
SHELLEOF
chmod +x /tmp/container_shell.sh

# =============================================================================
# Print debug instructions
# =============================================================================

echo ""
echo "==========================================="
echo "DEBUG VM READY"
echo "==========================================="
echo ""
echo "Container: ${CONTAINER_NAME} (${CONTAINER_ID:0:12})"
echo "Image:     ${IMAGE}"
echo "Case ID:   ${CASE_ID}"
echo ""
echo "To SSH into this VM from your local machine:"
echo "  1. Find the VM:  gcloud compute instances list --filter='name~batch'"
echo "  2. SSH into it:  gcloud compute ssh <vm-name> --zone=<zone>"
echo ""
echo "Once connected, useful commands:"
echo ""
echo "  # Source environment variables"
echo "  source /tmp/debug_env.sh"
echo ""
echo "  # Open shell in container"
echo "  /tmp/container_shell.sh"
echo ""
echo "  # Run command in container"
echo "  /tmp/container_exec.sh python3 -m evaluation.main --help"
echo ""
echo "  # Run fuzzing manually"
echo "  /tmp/container_exec.sh python3 -m evaluation.main \\"
echo "      --case-id ${CASE_ID} --model ${MODEL} --target ${TARGET} \\"
echo "      --duration 60 --output-dir /output --verbose"
echo ""
echo "  # Run patching agent manually"
echo "  /tmp/container_exec.sh python3 -m agent.main \\"
echo "      --case-id ${CASE_ID} --agent autopatchbench --model ${MODEL} \\"
echo "      --output-dir /output --verbose"
echo ""
echo "  # Run the full task script"
echo "  /tmp/${JOB_TYPE}_task.sh"
echo ""
echo "  # Check container logs"
echo "  docker logs ${CONTAINER_NAME}"
echo ""
echo "==========================================="
echo ""

# =============================================================================
# Wait indefinitely
# =============================================================================

echo "[*] Waiting for debug session (Ctrl+C to stop)..."
echo "[*] The container will stay running until this script is terminated."
echo ""

# Keep the script running so Cloud Batch doesn't terminate the VM
while true; do
    sleep 60
    # Check if container is still running
    if ! docker ps -q -f "name=${CONTAINER_NAME}" | grep -q .; then
        echo "[!] Container stopped unexpectedly"
        echo "[*] Restarting container..."
        docker start "${CONTAINER_NAME}" || true
    fi
done
