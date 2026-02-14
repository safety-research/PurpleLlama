#!/bin/bash
# Build Task Script for Cloud Batch
#
# This script runs as a single task in the BUILD Cloud Batch job.
# It builds ARVO container images and pushes them to Artifact Registry.
#
# Environment variables (set by Cloud Batch):
#   BATCH_TASK_INDEX  - Task index (0-based)
#   BUCKET_NAME       - GCS bucket for build assets
#   ARTIFACT_REGISTRY - Artifact Registry path (e.g., us-central1-docker.pkg.dev/project/arvo)
#   ARVO_CASES        - Comma-separated list of ARVO case IDs
#
# The task index determines which case this task handles.

set -e

# =============================================================================
# Configuration
# =============================================================================

WORKDIR="/tmp/arvo-build"
mkdir -p "${WORKDIR}"
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
echo "Build Task"
echo "==========================================="
echo "Task Index:        ${BATCH_TASK_INDEX}"
echo "Case ID:           ${CASE_ID}"
echo "Bucket:            ${BUCKET_NAME}"
echo "Artifact Registry: ${ARTIFACT_REGISTRY}"
echo "==========================================="

# =============================================================================
# Install Docker and configure auth
# =============================================================================

if ! command -v docker &> /dev/null; then
    echo "[*] Installing Docker..."
    apt-get update
    apt-get install -y docker.io
    systemctl start docker
fi

# Configure Docker to authenticate with Artifact Registry
echo "[*] Configuring Docker authentication..."
gcloud auth configure-docker "$(echo ${ARTIFACT_REGISTRY} | cut -d'/' -f1)" --quiet

# =============================================================================
# Download Dockerfile template and build assets
# =============================================================================

echo "[*] Downloading build assets from GCS..."
gsutil cp "gs://${BUCKET_NAME}/build-assets/dockerfile_fuzzing_template" "${WORKDIR}/" || true
gsutil cp -r "gs://${BUCKET_NAME}/build-assets/libfuzzer-modern/" "${WORKDIR}/" || true
gsutil cp "gs://${BUCKET_NAME}/build-assets/casr-binaries.tar.gz" "${WORKDIR}/" || true

# =============================================================================
# Build and push image
# =============================================================================

build_and_push_image() {
    local case_id="$1"
    local variant="$2"  # "vul" or "fix"
    local base_image="n132/arvo:${case_id}-${variant}"
    local target_image="${ARTIFACT_REGISTRY}/arvo-${case_id}-${variant}:latest"

    echo ""
    echo "=== Building ${target_image} ==="
    echo "Base image: ${base_image}"

    # Check if image already exists in registry
    if gcloud artifacts docker images describe "${target_image}" &>/dev/null; then
        echo "Image already exists in Artifact Registry, skipping"
        return 0
    fi

    # Pull base image
    echo "[*] Pulling base image..."
    docker pull "${base_image}" || {
        echo "ERROR: Failed to pull ${base_image}"
        return 1
    }

    # Check if we have a Dockerfile template
    if [ -f "${WORKDIR}/dockerfile_fuzzing_template" ]; then
        # Create Dockerfile from template
        local dockerfile="${WORKDIR}/Dockerfile.${case_id}-${variant}"
        sed "s|\${ARVO_ID}|${case_id}|g; s|\${VARIANT}|${variant}|g" \
            "${WORKDIR}/dockerfile_fuzzing_template" > "${dockerfile}"

        echo "[*] Building image with custom Dockerfile..."
        docker build -t "${target_image}" -f "${dockerfile}" "${WORKDIR}" || {
            echo "ERROR: Failed to build image"
            return 1
        }
    else
        # Just tag the base image
        echo "[*] Tagging base image..."
        docker tag "${base_image}" "${target_image}"
    fi

    # Push to Artifact Registry
    echo "[*] Pushing to Artifact Registry..."
    docker push "${target_image}" || {
        echo "ERROR: Failed to push ${target_image}"
        return 1
    }

    # Cleanup
    docker rmi "${target_image}" "${base_image}" || true

    echo "[*] Done: ${target_image}"
}

# =============================================================================
# Build both variants
# =============================================================================

# Build vulnerable version (for LLM patching)
build_and_push_image "${CASE_ID}" "vul"

# Build fixed version (for ground truth comparison)
build_and_push_image "${CASE_ID}" "fix"

# =============================================================================
# Record metadata
# =============================================================================

METADATA_FILE="${WORKDIR}/metadata-${CASE_ID}.json"
cat > "${METADATA_FILE}" <<EOF
{
    "case_id": ${CASE_ID},
    "built_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "task_index": ${BATCH_TASK_INDEX},
    "vul_image": "${ARTIFACT_REGISTRY}/arvo-${CASE_ID}-vul:latest",
    "fix_image": "${ARTIFACT_REGISTRY}/arvo-${CASE_ID}-fix:latest"
}
EOF

gsutil cp "${METADATA_FILE}" "gs://${BUCKET_NAME}/images/metadata-${CASE_ID}.json"

echo ""
echo "==========================================="
echo "Build Task Complete: Case ${CASE_ID}"
echo "==========================================="
