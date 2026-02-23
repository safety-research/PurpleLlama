#!/bin/bash
# Build CASR (Crash Analysis and Severity Reporting) from local submodule
# Uses custom casr-cluster-map tool that preserves full crash-to-cluster mapping
#
# Also downloads glibc 2.35 which is required for CASR to work in Ubuntu 16.04 containers
#
# Run this script once on the host to build CASR before building containers.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Configuration for CASR (using local submodule)
CASR_SUBMODULE="casr"
CASR_BIN_TAR="casr-binaries.tar.gz"
CASR_DOCKERFILE="Dockerfile.casr-builder"

# Detect container runtime (prefer podman, fallback to docker)
if command -v podman &> /dev/null; then
    CONTAINER_CMD="podman"
elif command -v docker &> /dev/null; then
    CONTAINER_CMD="docker"
else
    echo "Error: Neither podman nor docker found. Please install one of them:"
    echo "  - Podman: https://podman.io/getting-started/installation"
    echo "  - Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

echo "Using container runtime: $CONTAINER_CMD"

# Ensure the submodule is initialized and updated
if [ ! -d "$CASR_SUBMODULE/.git" ] && [ ! -f "$CASR_SUBMODULE/.git" ]; then
    echo "Initializing CASR submodule..."
    git submodule update --init --recursive "$CASR_SUBMODULE"
fi

# Build CASR from source in container
if [ -f "$CASR_BIN_TAR" ]; then
    echo "CASR binaries already built: $CASR_BIN_TAR"
    echo "To rebuild, delete the file and run again."
else
    echo "Building CASR in container from local submodule ($CASR_SUBMODULE)..."

    # Build the container image with CASR binaries (only builder stage)
    # Use --platform linux/amd64 to ensure x86_64 binaries even on ARM hosts
    $CONTAINER_CMD build \
        --platform linux/amd64 \
        --target builder \
        -f "$CASR_DOCKERFILE" \
        -t casr-builder:latest \
        .

    # Create a temporary container to extract binaries
    echo "Extracting binaries from container..."
    TEMP_CONTAINER=$($CONTAINER_CMD create --platform linux/amd64 casr-builder:latest /bin/true)

    # Create temporary directory for extraction
    mkdir -p casr-binaries/bin

    # Copy binaries from container using podman cp
    $CONTAINER_CMD cp "$TEMP_CONTAINER:/output/bin/." casr-binaries/bin/

    # Clean up temporary container
    $CONTAINER_CMD rm "$TEMP_CONTAINER"

    # Verify binaries are x86_64 (not ARM)
    echo "Verifying binary architecture..."
    BINARY_ARCH=$(file casr-binaries/bin/casr-san | grep -o 'x86-64\|ARM aarch64' || echo "unknown")
    if [ "$BINARY_ARCH" != "x86-64" ]; then
        echo "ERROR: Expected x86-64 binaries but got: $BINARY_ARCH"
        echo "Make sure Docker/Podman supports --platform linux/amd64 emulation"
        rm -rf casr-binaries
        exit 1
    fi
    echo "Binary architecture: $BINARY_ARCH (correct)"

    # Package the binaries
    echo "Packaging CASR binaries..."
    tar czf "$CASR_BIN_TAR" -C casr-binaries .

    # Clean up
    rm -rf casr-binaries

    echo "Built and packaged: $CASR_BIN_TAR ($(ls -lh "$CASR_BIN_TAR" | awk '{print $5}'))"
fi

# Verify the tarball
echo "Verifying CASR binaries tarball contents..."
tar -tzf "$CASR_BIN_TAR" | head -10
echo "..."

# Download glibc 2.35 (required for CASR, containers have glibc 2.23)
GLIBC_DEB="libc6_2.35-0ubuntu3_amd64.deb"
GLIBC_URL="http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/${GLIBC_DEB}"

if [ -f "$GLIBC_DEB" ]; then
    echo "glibc 2.35 already downloaded: $GLIBC_DEB"
    echo "To re-download, delete the file and run again."
else
    echo "Downloading glibc 2.35 from $GLIBC_URL ..."
    curl -L -o "$GLIBC_DEB" "$GLIBC_URL"
    echo "Downloaded: $GLIBC_DEB ($(ls -lh "$GLIBC_DEB" | awk '{print $5}'))"
fi

# Verify the .deb package
echo "Verifying glibc package..."
file "$GLIBC_DEB"

echo ""
echo "=== Build Summary ==="
echo "CASR binaries: $CASR_BIN_TAR"
echo "glibc: $GLIBC_DEB"
echo ""
echo "Binaries available:"
tar -tzf "$CASR_BIN_TAR" | grep "bin/casr-" | sed 's/^/  /'
echo ""
echo "Both packages ready for container build!"
