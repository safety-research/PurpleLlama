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
#   BUILD_VERSION     - Version hash from build assets (e.g., "abc12345")
#   FORCE_REBUILD     - Set to "true" to rebuild even if versioned image exists
#
# The task index determines which case this task handles.
#
# Image tagging:
#   Images are tagged with both the version hash and "latest":
#   - arvo-{case_id}-{variant}:{BUILD_VERSION} (version-specific)
#   - arvo-{case_id}-{variant}:latest (convenience alias)
#
#   Build is skipped if the versioned tag already exists (unless FORCE_REBUILD=true).

set -e

# =============================================================================
# Configuration
# =============================================================================

WORKDIR="/tmp/arvo-build"
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

# Build version (defaults to "latest" if not set)
BUILD_VERSION="${BUILD_VERSION:-latest}"
FORCE_REBUILD="${FORCE_REBUILD:-false}"

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
echo "Build Version:     ${BUILD_VERSION}"
echo "Force Rebuild:     ${FORCE_REBUILD}"
echo "==========================================="

# =============================================================================
# Install Docker and configure auth
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
# Download Dockerfile template and build assets
# =============================================================================

echo "[*] Downloading build assets from GCS..."
# Download all Dockerfile templates
gsutil cp "gs://${BUCKET_NAME}/build-assets/dockerfile_vul_template" "${WORKDIR}/" || true
gsutil cp "gs://${BUCKET_NAME}/build-assets/dockerfile_fix_template" "${WORKDIR}/" || true
gsutil cp "gs://${BUCKET_NAME}/build-assets/dockerfile_fuzzing_template" "${WORKDIR}/" || true

# Download build dependencies
gsutil cp -r "gs://${BUCKET_NAME}/build-assets/libfuzzer-modern/" "${WORKDIR}/" || true
gsutil cp "gs://${BUCKET_NAME}/build-assets/casr-binaries.tar.gz" "${WORKDIR}/" || true
gsutil cp "gs://${BUCKET_NAME}/build-assets/libc6_2.35-0ubuntu3_amd64.deb" "${WORKDIR}/" || true
gsutil cp "gs://${BUCKET_NAME}/build-assets/differential-debugging-deps-16.04.deb" "${WORKDIR}/" || true
gsutil cp "gs://${BUCKET_NAME}/build-assets/differential-debugging-deps-20.04.deb" "${WORKDIR}/" || true
gsutil cp -r "gs://${BUCKET_NAME}/build-assets/microsnapshots/" "${WORKDIR}/" || true
gsutil cp "gs://${BUCKET_NAME}/build-assets/casr_cluster.py" "${WORKDIR}/" || true

# =============================================================================
# Build and push image
# =============================================================================

build_and_push_image() {
    local case_id="$1"
    local variant="$2"  # "vul" or "fix"
    local base_image="n132/arvo:${case_id}-${variant}"
    local versioned_image="${ARTIFACT_REGISTRY}/arvo-${case_id}-${variant}:${BUILD_VERSION}"
    local latest_image="${ARTIFACT_REGISTRY}/arvo-${case_id}-${variant}:latest"

    echo ""
    echo "=== Building arvo-${case_id}-${variant} ==="
    echo "Base image:       ${base_image}"
    echo "Versioned image:  ${versioned_image}"
    echo "Latest image:     ${latest_image}"

    # Check if versioned image already exists in registry (skip if FORCE_REBUILD is not true)
    if [ "${FORCE_REBUILD}" != "true" ]; then
        if gcloud artifacts docker images describe "${versioned_image}" &>/dev/null; then
            echo "[*] Versioned image already exists, skipping build"
            return 0
        fi
    else
        echo "[*] FORCE_REBUILD=true, rebuilding even if image exists"
    fi

    # Pull base image
    echo "[*] Pulling base image..."
    docker pull "${base_image}" || {
        echo "ERROR: Failed to pull ${base_image}"
        return 1
    }

    # Select the appropriate Dockerfile template for each variant
    # - vul: dockerfile_vul_template (minimal, just libfuzzer)
    # - fix: dockerfile_fuzzing_template (with CASR, debugging deps, but no 10-min QA)
    local template_file=""
    if [ "${variant}" = "vul" ]; then
        template_file="${WORKDIR}/dockerfile_vul_template"
    else
        template_file="${WORKDIR}/dockerfile_fuzzing_template"
    fi

    # Check if we have the Dockerfile template
    if [ -f "${template_file}" ]; then
        # Create Dockerfile from template
        # Note: Templates use {ARVO_ID} not ${ARVO_ID}
        local dockerfile="${WORKDIR}/Dockerfile.${case_id}-${variant}"
        sed "s|{ARVO_ID}|${case_id}|g" "${template_file}" > "${dockerfile}"

        echo "[*] Building image with ${template_file##*/}..."
        docker build -t "${versioned_image}" -f "${dockerfile}" "${WORKDIR}" || {
            echo "ERROR: Failed to build image"
            return 1
        }
    else
        # Just tag the base image
        echo "[*] No template found (${template_file##*/}), tagging base image..."
        docker tag "${base_image}" "${versioned_image}"
    fi

    # Also tag as latest
    docker tag "${versioned_image}" "${latest_image}"

    # Push both tags to Artifact Registry
    echo "[*] Pushing versioned image to Artifact Registry..."
    docker push "${versioned_image}" || {
        echo "ERROR: Failed to push ${versioned_image}"
        return 1
    }

    echo "[*] Pushing latest tag to Artifact Registry..."
    docker push "${latest_image}" || {
        echo "ERROR: Failed to push ${latest_image}"
        return 1
    }

    # Cleanup
    docker rmi "${versioned_image}" "${latest_image}" "${base_image}" || true

    echo "[*] Done: ${versioned_image}"
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
    "build_version": "${BUILD_VERSION}",
    "built_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "task_index": ${BATCH_TASK_INDEX},
    "vul_image": "${ARTIFACT_REGISTRY}/arvo-${CASE_ID}-vul:${BUILD_VERSION}",
    "fix_image": "${ARTIFACT_REGISTRY}/arvo-${CASE_ID}-fix:${BUILD_VERSION}"
}
EOF

gsutil cp "${METADATA_FILE}" "gs://${BUCKET_NAME}/images/metadata-${CASE_ID}.json"

echo ""
echo "==========================================="
echo "Build Task Complete: Case ${CASE_ID}"
echo "==========================================="
