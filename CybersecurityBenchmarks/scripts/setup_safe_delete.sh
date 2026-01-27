#!/bin/bash
# Setup script for safe-delete functionality
# Registers a directory for safe-delete protection:
#   - Single file rm: moved to trash instead of deleted
#   - Bulk rm (10+ files): requires confirmation
#   - Trash auto-cleanup after 30 days
#
# Usage: sudo ./setup_safe_delete.sh <directory>
# Example: sudo ./setup_safe_delete.sh /data

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Show usage
usage() {
    echo "Usage: sudo $0 <directory>"
    echo ""
    echo "Registers a directory for safe-delete protection:"
    echo "  - Single file rm: moved to trash instead of deleted"
    echo "  - Bulk rm (10+ files): requires confirmation"
    echo "  - Trash auto-cleanup after 30 days"
    echo ""
    echo "Example: sudo $0 /data"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo_error "This script must be run as root (use sudo)"
    exit 1
fi

# Check arguments
if [[ $# -lt 1 ]]; then
    usage
fi

TARGET_DIR="$1"

# Validate directory
if [[ ! -d "$TARGET_DIR" ]]; then
    echo_error "Directory '$TARGET_DIR' does not exist!"
    exit 1
fi

# Resolve to absolute path
TARGET_DIR=$(realpath "$TARGET_DIR")

# Get the real user who invoked sudo
REAL_USER=${SUDO_USER:-$USER}
REAL_USER_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

echo_info "Setting up safe-delete for directory: $TARGET_DIR"

# ============================================
# Configuration
# ============================================
TRASH_DIR="$TARGET_DIR/.trash"
SAFE_RM_SCRIPT="/usr/local/bin/safe-rm"
SAFE_RM_CONFIG="/etc/safe-rm.conf"
TRASH_CLEANUP_CRON="/etc/cron.daily/cleanup-safe-delete-trash"

# ============================================
# Step 1: Create trash directory
# ============================================
echo_info "Setting up trash directory..."

if [[ ! -d "$TRASH_DIR" ]]; then
    mkdir -p "$TRASH_DIR"
    chown "$REAL_USER:$REAL_USER" "$TRASH_DIR"
    echo_info "Created trash directory at $TRASH_DIR"
else
    echo_info "Trash directory already exists at $TRASH_DIR"
fi

# ============================================
# Step 2: Register directory in config
# ============================================
echo_info "Registering directory for safe-delete..."

# Create config file if it doesn't exist
if [[ ! -f "$SAFE_RM_CONFIG" ]]; then
    cat > "$SAFE_RM_CONFIG" << 'EOF'
# Safe-delete configuration
# Each line contains a protected directory and its trash location
# Format: PROTECTED_DIR:TRASH_DIR
# Lines starting with # are comments
EOF
    echo_info "Created config file at $SAFE_RM_CONFIG"
fi

# Check if directory is already registered
if grep -q "^${TARGET_DIR}:" "$SAFE_RM_CONFIG" 2>/dev/null; then
    echo_info "Directory already registered in $SAFE_RM_CONFIG"
else
    echo "${TARGET_DIR}:${TRASH_DIR}" >> "$SAFE_RM_CONFIG"
    echo_info "Added $TARGET_DIR to safe-delete config"
fi

# ============================================
# Step 3: Create/update safe-rm wrapper script
# ============================================
echo_info "Installing safe-rm wrapper script..."

cat > "$SAFE_RM_SCRIPT" << 'SAFE_RM_EOF'
#!/bin/bash
# Safe rm wrapper script
# - Single files in protected directories: moved to trash instead of deleted
# - Bulk deletions (10+ files): requires confirmation
# - Reads protected directories from /etc/safe-rm.conf

SAFE_RM_CONFIG="/etc/safe-rm.conf"
BULK_THRESHOLD=10

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# Get trash directory for a given file path
get_trash_dir() {
    local file_path="$1"
    local abs_path=$(realpath -m "$file_path" 2>/dev/null || echo "$file_path")
    
    if [[ ! -f "$SAFE_RM_CONFIG" ]]; then
        return 1
    fi
    
    while IFS=: read -r protected_dir trash_dir; do
        # Skip comments and empty lines
        [[ "$protected_dir" =~ ^#.*$ || -z "$protected_dir" ]] && continue
        
        # Check if file is under this protected directory
        if [[ "$abs_path" == "$protected_dir"/* || "$abs_path" == "$protected_dir" ]]; then
            echo "$trash_dir"
            return 0
        fi
    done < "$SAFE_RM_CONFIG"
    
    return 1
}

# Check if any file is in a protected directory
any_file_protected() {
    for f in "${FILES[@]}"; do
        if get_trash_dir "$f" >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

# Parse arguments to separate flags from files
FLAGS=()
FILES=()
FORCE=false
RECURSIVE=false
INTERACTIVE=false

for arg in "$@"; do
    case "$arg" in
        -f|--force)
            FLAGS+=("$arg")
            FORCE=true
            ;;
        -r|-R|--recursive)
            FLAGS+=("$arg")
            RECURSIVE=true
            ;;
        -i|--interactive)
            FLAGS+=("$arg")
            INTERACTIVE=true
            ;;
        -rf|-fr|-Rf|-fR)
            FLAGS+=("$arg")
            FORCE=true
            RECURSIVE=true
            ;;
        -*)
            FLAGS+=("$arg")
            ;;
        *)
            FILES+=("$arg")
            ;;
    esac
done

# If no files specified, just pass through to real rm
if [[ ${#FILES[@]} -eq 0 ]]; then
    /bin/rm "${FLAGS[@]}"
    exit $?
fi

# If no files are in protected directories, use real rm directly
if ! any_file_protected; then
    /bin/rm "${FLAGS[@]}" "${FILES[@]}"
    exit $?
fi

# Count total items that would be affected
count_items() {
    local count=0
    for f in "${FILES[@]}"; do
        if [[ -e "$f" ]]; then
            if [[ -d "$f" ]] && $RECURSIVE; then
                # Count all items in directory
                count=$((count + $(find "$f" -type f 2>/dev/null | wc -l)))
            elif [[ -f "$f" ]]; then
                count=$((count + 1))
            fi
        fi
    done
    echo $count
}

# Move file to trash with timestamp to avoid collisions
move_to_trash() {
    local file="$1"
    local trash_dir="$2"
    local basename=$(basename "$file")
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local trash_name="${timestamp}_${basename}"
    
    # Ensure trash directory exists
    mkdir -p "$trash_dir" 2>/dev/null
    
    # Create metadata file for potential restoration
    local meta_file="$trash_dir/.${trash_name}.meta"
    echo "original_path=$(realpath "$file")" > "$meta_file"
    echo "deleted_at=$(date -Iseconds)" >> "$meta_file"
    
    mv "$file" "$trash_dir/$trash_name"
    return $?
}

# Get total item count
TOTAL_COUNT=$(count_items)

# Check if this is a bulk operation requiring confirmation
if [[ $TOTAL_COUNT -ge $BULK_THRESHOLD ]] && ! $FORCE; then
    echo -e "${YELLOW}[SAFE-RM]${NC} This will delete ${RED}$TOTAL_COUNT${NC} files/items."
    echo -e "Files/directories to be deleted:"
    for f in "${FILES[@]}"; do
        if [[ -e "$f" ]]; then
            if [[ -d "$f" ]]; then
                echo "  📁 $f (directory)"
            else
                echo "  📄 $f"
            fi
        fi
    done
    echo ""
    read -p "Are you sure you want to proceed? Type 'yes' to confirm: " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo -e "${GREEN}[SAFE-RM]${NC} Aborted."
        exit 0
    fi
    # If confirmed, use real rm for bulk operations
    /bin/rm "${FLAGS[@]}" "${FILES[@]}"
    exit $?
fi

# Handle single file deletions - move to trash if in protected directory
if [[ ${#FILES[@]} -eq 1 ]] && [[ -f "${FILES[0]}" ]] && ! $RECURSIVE && ! $FORCE; then
    TRASH_DIR=$(get_trash_dir "${FILES[0]}")
    if [[ -n "$TRASH_DIR" ]]; then
        if move_to_trash "${FILES[0]}" "$TRASH_DIR"; then
            echo -e "${GREEN}[SAFE-RM]${NC} Moved '${FILES[0]}' to trash"
            exit 0
        else
            echo -e "${RED}[SAFE-RM]${NC} Failed to move to trash, file not deleted"
            exit 1
        fi
    fi
fi

# For all other cases (directories, multiple files under threshold, or forced), use real rm
/bin/rm "${FLAGS[@]}" "${FILES[@]}"
SAFE_RM_EOF

chmod +x "$SAFE_RM_SCRIPT"
echo_info "Installed safe-rm script at $SAFE_RM_SCRIPT"

# ============================================
# Step 4: Create/update cron job for trash cleanup
# ============================================
echo_info "Setting up trash cleanup cron job..."

cat > "$TRASH_CLEANUP_CRON" << 'CRON_EOF'
#!/bin/bash
# Clean up trash files older than 30 days for all safe-delete protected directories

SAFE_RM_CONFIG="/etc/safe-rm.conf"
RETENTION_DAYS=30

if [[ ! -f "$SAFE_RM_CONFIG" ]]; then
    exit 0
fi

while IFS=: read -r protected_dir trash_dir; do
    # Skip comments and empty lines
    [[ "$protected_dir" =~ ^#.*$ || -z "$protected_dir" ]] && continue
    
    if [[ -d "$trash_dir" ]]; then
        # Delete files older than retention period
        find "$trash_dir" -type f -mtime +${RETENTION_DAYS} -delete 2>/dev/null
        # Delete empty directories
        find "$trash_dir" -mindepth 1 -type d -empty -delete 2>/dev/null
        # Clean up orphaned metadata files
        find "$trash_dir" -name "*.meta" -mtime +${RETENTION_DAYS} -delete 2>/dev/null
    fi
done < "$SAFE_RM_CONFIG"
CRON_EOF

chmod +x "$TRASH_CLEANUP_CRON"
echo_info "Installed trash cleanup cron job at $TRASH_CLEANUP_CRON"

# ============================================
# Step 5: Add shell aliases to user's bashrc
# ============================================
echo_info "Configuring shell aliases..."

BASHRC="$REAL_USER_HOME/.bashrc"

# Define the shell configuration block
SHELL_CONFIG='
# Safe-delete configuration (added by setup_safe_delete.sh)
alias rm='\''safe-rm'\''
alias trash='\''safe-rm-trash'\''

# List trash contents for all protected directories
safe-rm-trash() {
    local config="/etc/safe-rm.conf"
    if [[ ! -f "$config" ]]; then
        echo "No safe-delete directories configured"
        return 1
    fi
    
    while IFS=: read -r protected_dir trash_dir; do
        [[ "$protected_dir" =~ ^#.*$ || -z "$protected_dir" ]] && continue
        if [[ -d "$trash_dir" ]]; then
            echo -e "\n\033[1;32mTrash for $protected_dir:\033[0m ($trash_dir)"
            ls -la "$trash_dir" 2>/dev/null | grep -v "^total" | grep -v "^\." | head -20
            local count=$(ls -1 "$trash_dir" 2>/dev/null | grep -v "^\." | wc -l)
            if [[ $count -gt 20 ]]; then
                echo "  ... and $((count - 20)) more files"
            fi
        fi
    done < "$config"
}

# Restore file from trash
trash-restore() {
    if [[ -z "$1" ]]; then
        echo "Usage: trash-restore <filename_in_trash> [trash_directory]"
        echo ""
        echo "Run '\''trash'\'' to see available files"
        return 1
    fi
    
    local file_to_restore="$1"
    local trash_dir="$2"
    
    # If no trash dir specified, search all configured trash directories
    if [[ -z "$trash_dir" ]]; then
        local config="/etc/safe-rm.conf"
        while IFS=: read -r protected_dir td; do
            [[ "$protected_dir" =~ ^#.*$ || -z "$protected_dir" ]] && continue
            if [[ -f "$td/$file_to_restore" ]]; then
                trash_dir="$td"
                break
            fi
        done < "$config"
    fi
    
    if [[ -z "$trash_dir" || ! -f "$trash_dir/$file_to_restore" ]]; then
        echo "File not found in any trash directory: $file_to_restore"
        return 1
    fi
    
    local meta_file="$trash_dir/.$file_to_restore.meta"
    if [[ -f "$meta_file" ]]; then
        local orig_path=$(grep "^original_path=" "$meta_file" | cut -d= -f2-)
        echo "Restoring to: $orig_path"
        mv "$trash_dir/$file_to_restore" "$orig_path" && /bin/rm -f "$meta_file"
    else
        echo "No metadata found. Where would you like to restore?"
        read -p "Destination path: " dest
        mv "$trash_dir/$file_to_restore" "$dest"
    fi
}

# Empty trash for all or specific directory
trash-empty() {
    local target_dir="$1"
    local config="/etc/safe-rm.conf"
    
    if [[ ! -f "$config" ]]; then
        echo "No safe-delete directories configured"
        return 1
    fi
    
    while IFS=: read -r protected_dir trash_dir; do
        [[ "$protected_dir" =~ ^#.*$ || -z "$protected_dir" ]] && continue
        
        # If target specified, only empty that one
        if [[ -n "$target_dir" && "$protected_dir" != "$target_dir" ]]; then
            continue
        fi
        
        if [[ -d "$trash_dir" ]]; then
            local count=$(ls -1 "$trash_dir" 2>/dev/null | grep -v "^\." | wc -l)
            if [[ $count -gt 0 ]]; then
                echo "Emptying trash for $protected_dir ($count files)..."
                /bin/rm -rf "$trash_dir"/* "$trash_dir"/.[!.]* 2>/dev/null
                echo "Done."
            else
                echo "Trash for $protected_dir is already empty"
            fi
        fi
    done < "$config"
}'

# Check if safe-delete is already configured
if ! grep -q "# Safe-delete configuration" "$BASHRC" 2>/dev/null; then
    echo "$SHELL_CONFIG" >> "$BASHRC"
    chown "$REAL_USER:$REAL_USER" "$BASHRC"
    echo_info "Added safe-delete aliases to $BASHRC"
else
    echo_info "Safe-delete aliases already configured in $BASHRC"
fi

# ============================================
# Summary
# ============================================
echo ""
echo "=========================================="
echo -e "${GREEN}Safe-Delete Setup Complete!${NC}"
echo "=========================================="
echo ""
echo "Protected directory: $TARGET_DIR"
echo "Trash location: $TRASH_DIR"
echo ""
echo "Configuration file: $SAFE_RM_CONFIG"
cat "$SAFE_RM_CONFIG" | grep -v "^#" | grep -v "^$" | while IFS=: read -r dir trash; do
    echo "  - $dir -> $trash"
done
echo ""
echo -e "${GREEN}Available commands:${NC}"
echo "  rm <file>          - Moves single files to trash (in protected dirs)"
echo "  rm <files...>      - Requires confirmation if 10+ files"
echo "  rm -f <file>       - Force delete (bypasses trash)"
echo "  trash              - List all trash contents"
echo "  trash-restore <f>  - Restore file from trash"
echo "  trash-empty [dir]  - Empty trash (optionally for specific directory)"
echo ""
echo -e "${YELLOW}NOTE:${NC} Run 'source ~/.bashrc' or start a new shell to activate"
