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
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"

echo "==========================================="
echo "Ground Truth Task"
echo "==========================================="
echo "Task Index:        ${BATCH_TASK_INDEX}"
echo "Case ID:           ${CASE_ID}"
echo "Run ID:            ${RUN_ID}"
echo "Fuzzing Duration:  ${FUZZING_DURATION}s"
echo "Bucket:            ${BUCKET_NAME}"
echo "Artifact Registry: ${ARTIFACT_REGISTRY}"
echo "==========================================="

# =============================================================================
# Install Docker (if not present)
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
# Pull container image from Artifact Registry
# =============================================================================

IMAGE="${ARTIFACT_REGISTRY}/arvo-${CASE_ID}-fix:latest"
echo "[*] Pulling container image: ${IMAGE}"

docker pull "${IMAGE}" || {
    echo "ERROR: Failed to pull ${IMAGE}"
    exit 1
}

# =============================================================================
# Run fuzzing
# =============================================================================

echo ""
echo "=== Running Ground Truth Fuzzing ==="
echo ""

OUTPUT_DIR="${RESULTS_DIR}/case_${CASE_ID}/gt/${RUN_ID}"
CRASHES_DIR="${OUTPUT_DIR}/crashes"
mkdir -p "${OUTPUT_DIR}" "${CRASHES_DIR}"

START_TIME=$(date +%s)

# Run fuzzing inside container
# The container should have arvo-fuzz or similar fuzzing command
docker run --rm \
    --platform linux/amd64 \
    -v "${OUTPUT_DIR}:/output" \
    "${IMAGE}" \
    bash -c "
        set -e

        # Run arvo to verify the fix (should not crash)
        echo '[*] Verifying fix...'
        if arvo 2>&1 | tee /output/verify.log; then
            echo 'Fix verified: no crash'
            echo 'fix_verified=true' >> /output/status.txt
        else
            echo 'WARNING: arvo command failed'
            echo 'fix_verified=false' >> /output/status.txt
        fi

        # Check if fuzzer is available
        if command -v arvo-fuzz &> /dev/null; then
            echo '[*] Running fuzzer for ${FUZZING_DURATION}s...'
            timeout ${FUZZING_DURATION} arvo-fuzz \
                -artifact_prefix=/output/crashes/ \
                -max_total_time=${FUZZING_DURATION} \
                /corpus 2>&1 | tee /output/fuzz.log || true
        else
            echo '[*] No arvo-fuzz command, running with libFuzzer...'
            # Try to find and run the fuzz target
            FUZZ_TARGET=\$(find /out -name '*_fuzzer' -o -name 'fuzz_*' 2>/dev/null | head -1)
            if [ -n \"\${FUZZ_TARGET}\" ]; then
                mkdir -p /corpus
                timeout ${FUZZING_DURATION} \"\${FUZZ_TARGET}\" \
                    -artifact_prefix=/output/crashes/ \
                    -max_total_time=${FUZZING_DURATION} \
                    /corpus 2>&1 | tee /output/fuzz.log || true
            else
                echo 'No fuzzer found'
                echo 'fuzzer_found=false' >> /output/status.txt
            fi
        fi

        # Count crashes
        CRASH_COUNT=\$(find /output/crashes -type f 2>/dev/null | wc -l)
        echo \"crashes_found=\${CRASH_COUNT}\" >> /output/status.txt
    " 2>&1 | tee "${OUTPUT_DIR}/gt.log"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# =============================================================================
# Generate results
# =============================================================================

echo "[*] Generating results..."

# Count crashes
CRASH_COUNT=$(find "${CRASHES_DIR}" -type f 2>/dev/null | wc -l)

# Create result JSON
cat > "${OUTPUT_DIR}/result.json" <<EOF
{
    "case_id": ${CASE_ID},
    "variant": "fix",
    "job_type": "ground_truth",
    "run_id": "${RUN_ID}",
    "fuzzing_duration_requested": ${FUZZING_DURATION},
    "actual_duration_seconds": ${DURATION},
    "crashes_found": ${CRASH_COUNT},
    "completed_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

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
echo "Crashes found: ${CRASH_COUNT}"
echo "Results: gs://${BUCKET_NAME}/results/case_${CASE_ID}/gt/${RUN_ID}/"
echo "==========================================="
