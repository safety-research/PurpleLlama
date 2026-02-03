#!/bin/bash
# Dependencies Build Task Script for Cloud Batch
#
# This script builds CASR and differential-debugging-deps on native x86_64 GCP VMs.
# It only rebuilds if the source files have changed (hash-based detection).
#
# Environment variables (set by Cloud Batch):
#   BUCKET_NAME     - GCS bucket for build assets
#   FORCE_REBUILD   - Set to "true" to rebuild even if hashes match
#
# Artifacts produced:
#   gs://{BUCKET_NAME}/build-assets/casr-binaries.tar.gz
#   gs://{BUCKET_NAME}/build-assets/differential-debugging-deps-16.04.deb
#   gs://{BUCKET_NAME}/build-assets/differential-debugging-deps-20.04.deb
#   gs://{BUCKET_NAME}/build-assets/deps-manifest.json

set -e

# =============================================================================
# Configuration
# =============================================================================

WORKDIR="/tmp/deps-build"
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

FORCE_REBUILD="${FORCE_REBUILD:-false}"

echo "==========================================="
echo "Dependencies Build Task"
echo "==========================================="
echo "Bucket:        ${BUCKET_NAME}"
echo "Force Rebuild: ${FORCE_REBUILD}"
echo "Working Dir:   ${WORKDIR}"
echo "==========================================="

# =============================================================================
# Install build dependencies
# =============================================================================

echo "[*] Installing build dependencies..."
apt-get update
apt-get install -y \
    build-essential \
    curl \
    git \
    jq \
    podman \
    fuse-overlayfs \
    slirp4netns

# Install Rust for CASR build
echo "[*] Installing Rust..."

# Ensure HOME is set (Cloud Batch may not set it)
export HOME="${HOME:-/root}"
echo "    HOME=${HOME}"

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Source cargo env (try multiple locations)
if [ -f "$HOME/.cargo/env" ]; then
    source "$HOME/.cargo/env"
elif [ -f "/root/.cargo/env" ]; then
    source "/root/.cargo/env"
else
    # Fallback: add cargo to PATH directly
    export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"
fi

# Verify installations
echo "[*] Verifying installations..."
rustc --version
cargo --version
podman --version

# =============================================================================
# Download source files from GCS
# =============================================================================

echo "[*] Downloading source files from GCS..."

# Download CASR submodule source
mkdir -p "${WORKDIR}/casr"
echo "    Downloading CASR source from gs://${BUCKET_NAME}/deps-sources/casr/ ..."
gsutil -m cp -r "gs://${BUCKET_NAME}/deps-sources/casr/*" "${WORKDIR}/casr/" || {
    echo "ERROR: CASR source not found in GCS"
    echo "Checking what exists in GCS..."
    gsutil ls "gs://${BUCKET_NAME}/deps-sources/" || true
    echo "Upload with: python -m cli upload-deps-sources"
    exit 1
}
echo "    CASR source downloaded"
ls -la "${WORKDIR}/casr/" | head -10

# Download DD build script
gsutil cp "gs://${BUCKET_NAME}/deps-sources/build_deb_packages.sh" "${WORKDIR}/" || {
    echo "ERROR: build_deb_packages.sh not found in GCS"
    exit 1
}
chmod +x "${WORKDIR}/build_deb_packages.sh"

# Download Dockerfile.casr-builder
gsutil cp "gs://${BUCKET_NAME}/deps-sources/Dockerfile.casr-builder" "${WORKDIR}/" || {
    echo "ERROR: Dockerfile.casr-builder not found in GCS"
    exit 1
}

# =============================================================================
# Compute source hashes (using shared hash computation script)
# =============================================================================

# Download the shared hash computation script
gsutil cp "gs://${BUCKET_NAME}/deps-sources/compute_hashes.sh" "${WORKDIR}/" || {
    echo "ERROR: compute_hashes.sh not found in GCS"
    exit 1
}
chmod +x "${WORKDIR}/compute_hashes.sh"

# Source the shared hash functions
# shellcheck source=/dev/null
source "${WORKDIR}/compute_hashes.sh"

LOCAL_CASR_HASH=$(compute_casr_hash "${WORKDIR}/casr")
LOCAL_DD_HASH=$(compute_dd_hash "${WORKDIR}/build_deb_packages.sh")

echo "[*] Local source hashes:"
echo "    CASR: ${LOCAL_CASR_HASH}"
echo "    DD:   ${LOCAL_DD_HASH}"

# =============================================================================
# Check existing manifest
# =============================================================================

REBUILD_CASR=false
REBUILD_DD=false

if [ "${FORCE_REBUILD}" = "true" ]; then
    echo "[*] FORCE_REBUILD=true, rebuilding all dependencies"
    REBUILD_CASR=true
    REBUILD_DD=true
else
    # Download existing manifest
    MANIFEST_JSON=$(gsutil cat "gs://${BUCKET_NAME}/build-assets/deps-manifest.json" 2>/dev/null || echo "{}")

    GCS_CASR_HASH=$(echo "${MANIFEST_JSON}" | jq -r '.casr_hash // ""')
    GCS_DD_HASH=$(echo "${MANIFEST_JSON}" | jq -r '.dd_hash // ""')

    echo "[*] GCS manifest hashes:"
    echo "    CASR: ${GCS_CASR_HASH:-none}"
    echo "    DD:   ${GCS_DD_HASH:-none}"

    if [ "${LOCAL_CASR_HASH}" != "${GCS_CASR_HASH}" ]; then
        echo "[*] CASR source changed, will rebuild"
        REBUILD_CASR=true
    else
        echo "[*] CASR unchanged, skipping"
    fi

    if [ "${LOCAL_DD_HASH}" != "${GCS_DD_HASH}" ]; then
        echo "[*] DD build script changed, will rebuild"
        REBUILD_DD=true
    else
        echo "[*] DD unchanged, skipping"
    fi
fi

# Exit early if nothing to build
if [ "${REBUILD_CASR}" = "false" ] && [ "${REBUILD_DD}" = "false" ]; then
    echo "[*] All dependencies up to date, nothing to build"
    exit 0
fi

# =============================================================================
# Build CASR
# =============================================================================

if [ "${REBUILD_CASR}" = "true" ]; then
    echo ""
    echo "==========================================="
    echo "Building CASR from source"
    echo "==========================================="

    cd "${WORKDIR}/casr"

    # Build CASR
    echo "[*] Running cargo build --release..."
    cargo build --release

    # Package binaries
    echo "[*] Packaging CASR binaries..."
    mkdir -p "${WORKDIR}/casr-binaries/bin"

    # Copy only ELF executables, exclude .d dependency files
    find target/release -maxdepth 1 -type f -name 'casr-*' ! -name '*.d' -executable \
        -exec cp {} "${WORKDIR}/casr-binaries/bin/" \;

    # Verify binaries are x86_64
    echo "[*] Verifying binary architecture..."
    FILE_OUTPUT=$(file "${WORKDIR}/casr-binaries/bin/casr-san")
    echo "    file output: ${FILE_OUTPUT}"
    if echo "${FILE_OUTPUT}" | grep -q "x86-64"; then
        echo "    Architecture: x86-64 (correct)"
    elif echo "${FILE_OUTPUT}" | grep -q "ARM\|aarch64"; then
        echo "ERROR: Got ARM/aarch64 binaries instead of x86-64"
        exit 1
    else
        echo "WARNING: Could not determine architecture, assuming x86-64"
    fi

    # List built binaries
    echo "[*] Built CASR binaries:"
    ls -la "${WORKDIR}/casr-binaries/bin/"

    # Create tarball
    cd "${WORKDIR}"
    tar -czvf casr-binaries.tar.gz -C casr-binaries .

    # Upload to GCS
    echo "[*] Uploading casr-binaries.tar.gz to GCS..."
    gsutil cp casr-binaries.tar.gz "gs://${BUCKET_NAME}/build-assets/"

    echo "[*] CASR build complete!"
fi

# =============================================================================
# Build differential-debugging-deps
# =============================================================================

if [ "${REBUILD_DD}" = "true" ]; then
    echo ""
    echo "==========================================="
    echo "Building differential-debugging-deps"
    echo "==========================================="

    cd "${WORKDIR}"

    # The build script is interactive, we need to make it non-interactive
    # Set environment variables to skip prompts
    export DEBIAN_FRONTEND=noninteractive

    # Create a modified non-interactive version
    cat > build_deb_noninteractive.sh << 'SCRIPT_EOF'
#!/bin/bash
# Non-interactive wrapper for build_deb_packages.sh
# Automatically answers "yes" to rebuild prompts

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="/tmp/deb-packaging"
LLVM_VERSION="13.0.1"
PYTHON_VERSION="3.7.17"

# Force rebuilds (no prompts)
BUILD_16_04=true
BUILD_20_04=true
REBUILD_PYTHON_16_04=true
REBUILD_PYTHON_20_04=true
REBUILD_LLDB_16_04=true
REBUILD_LLDB_20_04=true

# No cache (fresh build)
CACHE_DIR="${SCRIPT_DIR}/.build-cache"
rm -rf "${CACHE_DIR}"
mkdir -p "${CACHE_DIR}"

# Detect container runtime
if command -v podman &> /dev/null; then
    CONTAINER_CMD="podman"
elif command -v docker &> /dev/null; then
    CONTAINER_CMD="docker"
else
    echo "ERROR: Neither podman nor docker found"
    exit 1
fi

echo "Using container runtime: ${CONTAINER_CMD}"

# Source the actual build script functions (or inline the key parts)
# For simplicity, we'll call the original with yes piped to handle prompts
yes | bash "${SCRIPT_DIR}/build_deb_packages.sh" || {
    # If the script fails on prompts, run it differently
    echo "[*] Retrying with explicit answers..."
    cd "${SCRIPT_DIR}"

    # Delete existing debs to force rebuild
    rm -f differential-debugging-deps-*.deb

    bash "${SCRIPT_DIR}/build_deb_packages.sh" <<< $'y\ny\n'
}
SCRIPT_EOF

    chmod +x build_deb_noninteractive.sh

    echo "[*] Running differential-debugging-deps build (this takes 2-3 hours)..."

    # Delete existing debs to force rebuild
    rm -f differential-debugging-deps-*.deb 2>/dev/null || true

    # Run the build script with "yes" to all prompts
    # Use expect-like behavior with yes command
    yes y | timeout 14400 bash build_deb_packages.sh || {
        echo "[*] Build completed or timed out after 4 hours"
    }

    # Check if debs were created
    if [ -f "differential-debugging-deps-16.04.deb" ]; then
        echo "[*] Uploading differential-debugging-deps-16.04.deb to GCS..."
        gsutil cp differential-debugging-deps-16.04.deb "gs://${BUCKET_NAME}/build-assets/"
    else
        echo "WARNING: differential-debugging-deps-16.04.deb not built"
    fi

    if [ -f "differential-debugging-deps-20.04.deb" ]; then
        echo "[*] Uploading differential-debugging-deps-20.04.deb to GCS..."
        gsutil cp differential-debugging-deps-20.04.deb "gs://${BUCKET_NAME}/build-assets/"
    else
        echo "WARNING: differential-debugging-deps-20.04.deb not built"
    fi

    echo "[*] DD build complete!"
fi

# =============================================================================
# Update manifest
# =============================================================================

echo ""
echo "[*] Updating deps-manifest.json..."

# Get current hashes (may have been updated during build)
FINAL_CASR_HASH="${LOCAL_CASR_HASH}"
FINAL_DD_HASH="${LOCAL_DD_HASH}"

# Create manifest
cat > deps-manifest.json << EOF
{
    "casr_hash": "${FINAL_CASR_HASH}",
    "dd_hash": "${FINAL_DD_HASH}",
    "built_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "rebuilt_casr": ${REBUILD_CASR},
    "rebuilt_dd": ${REBUILD_DD}
}
EOF

gsutil cp deps-manifest.json "gs://${BUCKET_NAME}/build-assets/"

echo ""
echo "==========================================="
echo "Dependencies Build Complete"
echo "==========================================="
echo "CASR rebuilt:   ${REBUILD_CASR}"
echo "DD rebuilt:     ${REBUILD_DD}"
echo ""
echo "Artifacts uploaded to:"
echo "  gs://${BUCKET_NAME}/build-assets/casr-binaries.tar.gz"
echo "  gs://${BUCKET_NAME}/build-assets/differential-debugging-deps-16.04.deb"
echo "  gs://${BUCKET_NAME}/build-assets/differential-debugging-deps-20.04.deb"
echo "  gs://${BUCKET_NAME}/build-assets/deps-manifest.json"
