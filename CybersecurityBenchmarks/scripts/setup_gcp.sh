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

# Add to fstab if not already there
if grep -q "$MOUNT_POINT" /etc/fstab; then
    echo_info "fstab entry already exists"
else
    echo_info "Adding entry to /etc/fstab for persistence..."
    UUID=$(blkid -s UUID -o value "$DEVICE")
    echo "UUID=$UUID $MOUNT_POINT ext4 discard,defaults,nofail 0 2" >> /etc/fstab
    echo_info "Added to /etc/fstab"
fi

# Set ownership to the user who invoked sudo
REAL_USER=${SUDO_USER:-$USER}
chown -R "$REAL_USER:$REAL_USER" "$MOUNT_POINT"

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
    
    # Set ownership
    chown -R "$REAL_USER:$REAL_USER" "$PODMAN_STORAGE"
    
    echo_info "Rootful Podman storage configured!"
fi

# ============================================
# Step 4: Setup Podman storage (rootless)
# ============================================
echo_info "Checking rootless Podman storage configuration..."

# Get the real user's home directory
REAL_USER_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
REAL_USER_ID=$(id -u "$REAL_USER")
ROOTLESS_CONFIG_DIR="$REAL_USER_HOME/.config/containers"
ROOTLESS_STORAGE_CONF="$ROOTLESS_CONFIG_DIR/storage.conf"
ROOTLESS_STORAGE_PATH="$PODMAN_STORAGE/storage"

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
    
    # Clean up any stale lock files
    rm -rf /run/libpod 2>/dev/null || true
    rm -rf /run/containers 2>/dev/null || true
    rm -rf "/run/user/$REAL_USER_ID/libpod" 2>/dev/null || true
    
    # Create storage directories
    mkdir -p "$ROOTLESS_STORAGE_PATH"
    mkdir -p "/run/user/$REAL_USER_ID/containers"
    
    # Create config directory
    mkdir -p "$ROOTLESS_CONFIG_DIR"
    
    # Create rootless storage.conf
    cat > "$ROOTLESS_STORAGE_CONF" << EOF
[storage]
driver = "overlay"
graphroot = "$ROOTLESS_STORAGE_PATH"
runroot = "/run/user/$REAL_USER_ID/containers"
EOF
    
    # Set ownership of config directory to the real user
    chown -R "$REAL_USER:$REAL_USER" "$ROOTLESS_CONFIG_DIR"
    chown -R "$REAL_USER:$REAL_USER" "$ROOTLESS_STORAGE_PATH"
    
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
echo "Rootful Podman storage (sudo podman):"
ls -la "$PODMAN_LINK"
echo ""
echo "Rootless Podman storage (podman as $REAL_USER):"
echo "  Config: $ROOTLESS_STORAGE_CONF"
echo "  Storage: $ROOTLESS_STORAGE_PATH"
cat "$ROOTLESS_STORAGE_CONF"
echo ""
echo "Verify with: podman info | grep graphRoot"
echo ""
echo "You can now run the AutoPatch benchmark!"
