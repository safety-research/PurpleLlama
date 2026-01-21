#!/bin/bash
# Setup script for GCP data volume for AutoPatch benchmark
# This script formats, mounts, and configures Podman storage on /dev/nvme1n1

set -e

DEVICE="/dev/nvme1n1"
MOUNT_POINT="/data"
PODMAN_STORAGE="/data/containers"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo_error "This script must be run as root (use sudo)"
   exit 1
fi

# Check if device exists
if [[ ! -b "$DEVICE" ]]; then
    echo_error "Device $DEVICE not found!"
    echo "Available block devices:"
    lsblk
    exit 1
fi

# ============================================
# Step 1: Check if disk needs formatting
# ============================================
echo_info "Checking if $DEVICE is formatted..."

# Check if device has a filesystem
if blkid "$DEVICE" &>/dev/null; then
    FS_TYPE=$(blkid -s TYPE -o value "$DEVICE")
    echo_info "Device already has filesystem: $FS_TYPE"
else
    echo_warn "Device $DEVICE is not formatted!"
    echo ""
    echo -e "${RED}WARNING: Formatting will ERASE ALL DATA on $DEVICE${NC}"
    echo ""
    
    # Show disk info
    echo "Disk info:"
    lsblk "$DEVICE"
    echo ""
    
    read -p "Are you sure you want to format $DEVICE? Type 'YES' to confirm: " confirm
    if [[ "$confirm" != "YES" ]]; then
        echo_info "Aborted. Disk was not formatted."
        exit 0
    fi
    
    echo_info "Formatting $DEVICE with ext4..."
    mkfs.ext4 -m 0 -E lazy_itable_init=0,lazy_journal_init=0,discard "$DEVICE"
    echo_info "Formatting complete!"
fi

# ============================================
# Step 2: Mount the disk
# ============================================
echo_info "Checking mount status..."

# Create mount point if it doesn't exist
if [[ ! -d "$MOUNT_POINT" ]]; then
    echo_info "Creating mount point $MOUNT_POINT"
    mkdir -p "$MOUNT_POINT"
fi

# Check if already mounted
if mountpoint -q "$MOUNT_POINT"; then
    echo_info "$MOUNT_POINT is already mounted"
else
    echo_info "Mounting $DEVICE to $MOUNT_POINT..."
    mount -o discard,defaults "$DEVICE" "$MOUNT_POINT"
    echo_info "Mounted successfully!"
fi

# Add/update fstab entry
UUID=$(blkid -s UUID -o value "$DEVICE")
FS_TYPE=$(blkid -s TYPE -o value "$DEVICE")

if grep -q "$MOUNT_POINT" /etc/fstab; then
    # Check if the UUID matches
    if grep -q "UUID=$UUID" /etc/fstab; then
        echo_info "fstab entry already exists with correct UUID"
    else
        echo_warn "fstab entry exists but UUID doesn't match - updating..."
        # Remove old entry and add new one
        sed -i "\|$MOUNT_POINT|d" /etc/fstab
        echo "UUID=$UUID $MOUNT_POINT $FS_TYPE discard,defaults,nofail 0 2" >> /etc/fstab
        echo_info "Updated fstab with correct UUID: $UUID"
    fi
else
    echo_info "Adding entry to /etc/fstab for persistence..."
    echo "UUID=$UUID $MOUNT_POINT $FS_TYPE discard,defaults,nofail 0 2" >> /etc/fstab
    echo_info "Added to /etc/fstab"
fi

# Set ownership to the user who invoked sudo
REAL_USER=${SUDO_USER:-$USER}
REAL_USER_ID=$(id -u "$REAL_USER")
REAL_GROUP_ID=$(id -g "$REAL_USER")

# Only set ownership on the mount point directory itself (not recursive).
# This is fast and allows the user to access the directory.
# Subdirectories (like Podman storage) will be handled separately.
# If disk was already set up with the same UID (e.g., remounting on another GCP instance
# with the same username), this will be a no-op or quick update.
CURRENT_OWNER=$(stat -c '%u' "$MOUNT_POINT")
if [[ "$CURRENT_OWNER" != "$REAL_USER_ID" ]]; then
    echo_info "Setting ownership of $MOUNT_POINT to $REAL_USER (not recursive)..."
    chown "$REAL_USER:$REAL_USER" "$MOUNT_POINT"
else
    echo_info "Mount point $MOUNT_POINT already owned by UID $REAL_USER_ID"
fi

# ============================================
# Step 3: Setup Podman storage (rootful)
# ============================================
echo_info "Checking rootful Podman storage configuration..."

PODMAN_LINK="/var/lib/containers"

# Check if podman storage is already configured
if [[ -L "$PODMAN_LINK" ]] && [[ "$(readlink -f "$PODMAN_LINK")" == "$PODMAN_STORAGE" ]]; then
    echo_info "Rootful Podman storage already configured at $PODMAN_STORAGE"
else
    echo_info "Setting up rootful Podman storage at $PODMAN_STORAGE..."
    
    # Stop podman if running
    systemctl stop podman 2>/dev/null || true
    systemctl stop podman.socket 2>/dev/null || true
    
    # Create the storage directory
    mkdir -p "$PODMAN_STORAGE"
    
    # If /var/lib/containers exists and is not a symlink, move its contents
    if [[ -d "$PODMAN_LINK" ]] && [[ ! -L "$PODMAN_LINK" ]]; then
        if [[ "$(ls -A $PODMAN_LINK 2>/dev/null)" ]]; then
            echo_info "Moving existing container data to $PODMAN_STORAGE..."
            rsync -a "$PODMAN_LINK/" "$PODMAN_STORAGE/"
        fi
        rm -rf "$PODMAN_LINK"
    fi
    
    # Create symlink
    if [[ ! -e "$PODMAN_LINK" ]]; then
        ln -s "$PODMAN_STORAGE" "$PODMAN_LINK"
        echo_info "Created symlink: $PODMAN_LINK -> $PODMAN_STORAGE"
    fi
    
    # Set ownership only if needed (check if directory is new or has wrong owner)
    STORAGE_OWNER=$(stat -c '%u' "$PODMAN_STORAGE" 2>/dev/null || echo "0")
    if [[ "$STORAGE_OWNER" != "$REAL_USER_ID" ]]; then
        echo_info "Setting ownership of $PODMAN_STORAGE..."
        chown -R "$REAL_USER:$REAL_USER" "$PODMAN_STORAGE"
    else
        echo_info "Podman storage $PODMAN_STORAGE already has correct ownership"
    fi
    
    echo_info "Rootful Podman storage configured!"
fi

# ============================================
# Step 4: Setup Podman storage (rootless)
# ============================================
echo_info "Checking rootless Podman storage configuration..."

# Get the real user's home directory
REAL_USER_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
ROOTLESS_CONFIG_DIR="$REAL_USER_HOME/.config/containers"
ROOTLESS_STORAGE_CONF="$ROOTLESS_CONFIG_DIR/storage.conf"
ROOTLESS_STORAGE_PATH="$PODMAN_STORAGE/storage"
ROOTLESS_RUN_PATH="$PODMAN_STORAGE/run"

# Check if rootless storage is already configured correctly
if [[ -f "$ROOTLESS_STORAGE_CONF" ]] && grep -q "graphroot = \"$ROOTLESS_STORAGE_PATH\"" "$ROOTLESS_STORAGE_CONF" 2>/dev/null; then
    echo_info "Rootless Podman storage already configured at $ROOTLESS_STORAGE_PATH"
else
    echo_info "Setting up rootless Podman storage at $ROOTLESS_STORAGE_PATH..."
    
    # Clean up any existing rootless podman data that might conflict
    ROOTLESS_LOCAL_STORAGE="$REAL_USER_HOME/.local/share/containers"
    if [[ -d "$ROOTLESS_LOCAL_STORAGE" ]]; then
        echo_info "Cleaning up old rootless storage at $ROOTLESS_LOCAL_STORAGE..."
        rm -rf "$ROOTLESS_LOCAL_STORAGE"
    fi
    
    # Clean up any stale lock files in tmpfs
    rm -rf /run/libpod 2>/dev/null || true
    rm -rf /run/containers 2>/dev/null || true
    rm -rf "/run/user/$REAL_USER_ID/libpod" 2>/dev/null || true
    rm -rf "/run/user/$REAL_USER_ID/containers" 2>/dev/null || true
    
    # Create storage directories
    mkdir -p "$ROOTLESS_STORAGE_PATH"
    mkdir -p "$ROOTLESS_RUN_PATH"
    
    # Create config directory
    mkdir -p "$ROOTLESS_CONFIG_DIR"
    
    # Create rootless storage.conf with fuse-overlayfs (required for rootless overlay on ext4)
    # Note: runroot is on /data (persistent) instead of tmpfs to avoid permission issues
    cat > "$ROOTLESS_STORAGE_CONF" << EOF
[storage]
driver = "overlay"
graphroot = "$ROOTLESS_STORAGE_PATH"
runroot = "$ROOTLESS_RUN_PATH"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
EOF
    
    # Set ownership of config directory to the real user
    chown -R "$REAL_USER:$REAL_USER" "$ROOTLESS_CONFIG_DIR"
    
    # Set ownership of storage directories
    chown -R "$REAL_USER:$REAL_USER" "$ROOTLESS_STORAGE_PATH"
    chown -R "$REAL_USER:$REAL_USER" "$ROOTLESS_RUN_PATH"
    
    echo_info "Rootless Podman storage configured!"
    echo_info "Config file: $ROOTLESS_STORAGE_CONF"
fi

# ============================================
# Step 5: Enable lingering and configure cgroups
# ============================================
echo_info "Enabling lingering for rootless podman..."

# Enable lingering so rootless podman works without active login session
if ! loginctl show-user "$REAL_USER" 2>/dev/null | grep -q "Linger=yes"; then
    loginctl enable-linger "$REAL_USER"
    echo_info "Enabled lingering for user $REAL_USER"
else
    echo_info "Lingering already enabled for user $REAL_USER"
fi

# Configure podman to use cgroupfs (more reliable for rootless without full systemd session)
CONTAINERS_CONF="$ROOTLESS_CONFIG_DIR/containers.conf"
if [[ ! -f "$CONTAINERS_CONF" ]] || ! grep -q "cgroup_manager" "$CONTAINERS_CONF" 2>/dev/null; then
    cat >> "$CONTAINERS_CONF" << 'EOF'
[engine]
cgroup_manager = "cgroupfs"
EOF
    chown "$REAL_USER:$REAL_USER" "$CONTAINERS_CONF"
    echo_info "Configured cgroupfs as cgroup manager"
else
    echo_info "Cgroup manager already configured"
fi

# ============================================
# Step 6: Verify podman works
# ============================================
echo_info "Verifying podman configuration..."

# Test podman as the real user
if sudo -u "$REAL_USER" podman info &>/dev/null; then
    echo_info "Podman is working correctly!"
else
    echo_warn "Podman verification failed. Attempting to reset storage..."
    # Clear and recreate storage if verification fails
    rm -rf "$ROOTLESS_STORAGE_PATH"/* "$ROOTLESS_RUN_PATH"/* 2>/dev/null || true
    mkdir -p "$ROOTLESS_STORAGE_PATH" "$ROOTLESS_RUN_PATH"
    chown -R "$REAL_USER:$REAL_USER" "$ROOTLESS_STORAGE_PATH" "$ROOTLESS_RUN_PATH"
    
    if sudo -u "$REAL_USER" podman info &>/dev/null; then
        echo_info "Podman is now working after storage reset!"
    else
        echo_error "Podman still not working. Check: sudo -u $REAL_USER podman info"
    fi
fi

# ============================================
# Summary
# ============================================
echo ""
echo "=========================================="
echo -e "${GREEN}Setup Complete!${NC}"
echo "=========================================="
echo ""
echo "Disk status:"
df -h "$MOUNT_POINT"
echo ""
echo "Mount verification:"
mount | grep "$DEVICE" || echo_warn "Device not shown in mount output!"
echo ""
echo "Rootful Podman storage (sudo podman):"
ls -la "$PODMAN_LINK"
echo ""
echo "Rootless Podman storage (podman as $REAL_USER):"
echo "  Config: $ROOTLESS_STORAGE_CONF"
echo "  Storage: $ROOTLESS_STORAGE_PATH"
echo "  Runroot: $ROOTLESS_RUN_PATH"
cat "$ROOTLESS_STORAGE_CONF"
echo ""
echo "Podman graphRoot:"
sudo -u "$REAL_USER" podman info 2>/dev/null | grep graphRoot || echo_warn "Could not get podman info"
echo ""
echo "You can now run the AutoPatch benchmark!"
