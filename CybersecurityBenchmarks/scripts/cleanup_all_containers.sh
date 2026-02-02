#!/bin/bash
set -e

# Ensure this script is NOT run with sudo (rootless podman)
if [ "$EUID" -eq 0 ] || [ -n "$SUDO_USER" ]; then
    echo "Error: Do not run this script with sudo!"
    echo "This is for rootless podman - run as regular user."
    exit 1
fi

CONTAINERS_DIR="/data/containers"
TRASH_DIR="/data/containers_trash_$(date +%s)"

# 1. Kill container processes (user's own processes, no sudo needed)
echo "Killing container processes..."
pkill -9 conmon 2>/dev/null || true
pkill -9 crun 2>/dev/null || true

# 2. Move storage dir (instant) - only if it exists
if [ -d "$CONTAINERS_DIR" ]; then
    echo "Moving $CONTAINERS_DIR to $TRASH_DIR"
    mv "$CONTAINERS_DIR" "$TRASH_DIR"
    HAS_OLD_DATA=true
else
    echo "$CONTAINERS_DIR does not exist, skipping move"
    HAS_OLD_DATA=false
fi

# 3. Recreate fresh storage dir (as current user - let podman handle the rest)
echo "Creating fresh storage directory"
mkdir -p "$CONTAINERS_DIR"

# 4. Parallel delete in background (only if we moved data)
if [ "$HAS_OLD_DATA" = true ]; then
    echo "Deleting old data in background (parallel)..."
    # Clean up old log file if it exists
    rm -f /tmp/containers_cleanup.log
    nohup bash -c "find '$TRASH_DIR' -mindepth 1 -maxdepth 1 -print0 | xargs -0 -P \$(nproc) -I {} rm -rf {}" > /tmp/containers_cleanup.log 2>&1 &
    echo "Cleanup PID: $!"
fi

# 5. Migrate to new storage (let podman initialize it properly)
echo "Migrating to new storage..."
podman system migrate

echo "Done! Auth preserved at \${XDG_RUNTIME_DIR}/containers/auth.json"