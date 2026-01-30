#!/bin/bash
# Download CASR (Crash Analysis and Severity Reporting) for crash deduplication
# CASR provides casr-afl, casr-cluster, casr-libfuzzer for crash triage
#
# Run this script once on the host to download CASR before building containers.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CASR_TAR="casr-x86_64-unknown-linux-gnu.tar.xz"
CASR_URL="https://github.com/ispras/casr/releases/latest/download/${CASR_TAR}"

if [ -f "$CASR_TAR" ]; then
    echo "CASR already downloaded: $CASR_TAR"
    echo "To re-download, delete the file and run again."
else
    echo "Downloading CASR from $CASR_URL ..."
    curl -L -o "$CASR_TAR" "$CASR_URL"
    echo "Downloaded: $CASR_TAR ($(ls -lh "$CASR_TAR" | awk '{print $5}'))"
fi

# Verify the tarball
echo "Verifying tarball contents..."
tar -tf "$CASR_TAR" | head -10
echo "..."
echo "CASR download complete!"
