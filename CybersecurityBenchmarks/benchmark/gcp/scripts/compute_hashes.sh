#!/bin/bash
# =============================================================================
# compute_hashes.sh - Single source of truth for hash computation
# =============================================================================
#
# This script provides consistent hash computation for use by both:
# - Bash task scripts (via sourcing)
# - Python CLI (via subprocess call)
#
# Usage:
#   Source in bash:   source compute_hashes.sh
#   CLI invocation:   ./compute_hashes.sh <hash_type> <path> [options]
#
# Hash types:
#   file <path>              - SHA256 of a single file (64 chars)
#   casr <casr_dir>          - CASR source hash (16 chars)
#   dd <script_path>         - DD build script hash (16 chars)
#   runtime <runtime_dir>    - Runtime source hash (16 chars)
#
# All multi-file hashes use the same algorithm:
#   For each file (sorted): hash(relative_path + file_content_sha256)
#   Then truncate to 16 characters
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Core hash functions
# -----------------------------------------------------------------------------

# Compute SHA256 hash of a single file (full 64 char hex)
compute_file_hash() {
    local filepath="$1"
    sha256sum "$filepath" | cut -d' ' -f1
}

# Compute hash of CASR source directory
# Matches Python: compute_deps_source_hash() for CASR
compute_casr_hash() {
    local casr_dir="$1"
    local combined=""
    
    # First: .rs files (sorted)
    while IFS= read -r -d $'\0' filepath; do
        local relative_path="${filepath#${casr_dir}/}"
        local file_hash
        file_hash=$(sha256sum "$filepath" | cut -d' ' -f1)
        combined+="${relative_path}${file_hash}"
    done < <(find "$casr_dir" -name "*.rs" -print0 2>/dev/null | sort -z)
    
    # Second: Cargo.toml files (sorted)
    while IFS= read -r -d $'\0' filepath; do
        local relative_path="${filepath#${casr_dir}/}"
        local file_hash
        file_hash=$(sha256sum "$filepath" | cut -d' ' -f1)
        combined+="${relative_path}${file_hash}"
    done < <(find "$casr_dir" -name "Cargo.toml" -print0 2>/dev/null | sort -z)
    
    # Final hash, truncated to 16 chars
    echo -n "$combined" | sha256sum | cut -c1-16
}

# Compute hash of DD build script
# Matches Python: compute_file_hash()[:16]
compute_dd_hash() {
    local script_path="$1"
    sha256sum "$script_path" | cut -c1-16
}

# Compute hash of runtime source (agent/ + evaluation/ + entrypoint)
# Matches Python: compute_runtime_source_hash()
compute_runtime_hash() {
    local runtime_dir="$1"
    local combined=""
    
    # Hash all .py files in agent/ and evaluation/ (sorted by relative path)
    for subdir in "agent" "evaluation"; do
        local source_dir="${runtime_dir}/${subdir}"
        if [ -d "$source_dir" ]; then
            while IFS= read -r -d $'\0' filepath; do
                # Relative path from runtime_dir (e.g., "agent/main.py")
                local relative_path="${filepath#${runtime_dir}/}"
                local file_hash
                file_hash=$(sha256sum "$filepath" | cut -d' ' -f1)
                combined+="${relative_path}${file_hash}"
            done < <(find "$source_dir" -name "*.py" -type f -print0 2>/dev/null | sort -z)
        fi
    done
    
    # Also hash the entrypoint script
    local entrypoint="${runtime_dir}/agent-entrypoint.sh"
    if [ -f "$entrypoint" ]; then
        local file_hash
        file_hash=$(sha256sum "$entrypoint" | cut -d' ' -f1)
        combined+="agent-entrypoint.sh${file_hash}"
    fi
    
    # Final hash, truncated to 16 chars
    echo -n "$combined" | sha256sum | cut -c1-16
}

# -----------------------------------------------------------------------------
# CLI interface (when script is executed directly, not sourced)
# -----------------------------------------------------------------------------

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script is being executed directly
    
    show_usage() {
        echo "Usage: $0 <hash_type> <path>"
        echo ""
        echo "Hash types:"
        echo "  file <filepath>        - SHA256 of a single file (64 chars)"
        echo "  casr <casr_dir>        - CASR source hash (16 chars)"
        echo "  dd <script_path>       - DD build script hash (16 chars)"
        echo "  runtime <runtime_dir>  - Runtime source hash (16 chars)"
        echo ""
        echo "Examples:"
        echo "  $0 file /path/to/file.txt"
        echo "  $0 casr /path/to/casr"
        echo "  $0 runtime /path/to/portable-runtime"
        exit 1
    }
    
    if [ $# -lt 2 ]; then
        show_usage
    fi
    
    HASH_TYPE="$1"
    TARGET_PATH="$2"
    
    case "$HASH_TYPE" in
        file)
            if [ ! -f "$TARGET_PATH" ]; then
                echo "Error: File not found: $TARGET_PATH" >&2
                exit 1
            fi
            compute_file_hash "$TARGET_PATH"
            ;;
        casr)
            if [ ! -d "$TARGET_PATH" ]; then
                echo "Error: Directory not found: $TARGET_PATH" >&2
                exit 1
            fi
            compute_casr_hash "$TARGET_PATH"
            ;;
        dd)
            if [ ! -f "$TARGET_PATH" ]; then
                echo "Error: File not found: $TARGET_PATH" >&2
                exit 1
            fi
            compute_dd_hash "$TARGET_PATH"
            ;;
        runtime)
            if [ ! -d "$TARGET_PATH" ]; then
                echo "Error: Directory not found: $TARGET_PATH" >&2
                exit 1
            fi
            compute_runtime_hash "$TARGET_PATH"
            ;;
        *)
            echo "Error: Unknown hash type: $HASH_TYPE" >&2
            show_usage
            ;;
    esac
fi
