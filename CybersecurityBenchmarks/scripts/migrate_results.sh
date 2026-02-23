#!/bin/bash
# Migration script for result storage restructure
#
# This script migrates existing patches from the old structure to the new
# experiment-based structure under the "default" experiment.
#
# Old structure:
#   gs://{bucket}/results/case_{id}/{model}/{run_id}/patch/.../patch.txt
#   gs://{bucket}/results/case_{id}/{model}/{run_id}/patch/.../result.json
#
# New structure:
#   gs://{bucket}/results/default/{case_id}/{model}/patch.txt
#   gs://{bucket}/results/default/{case_id}/{model}/result.json
#   gs://{bucket}/results/default/{case_id}/{model}/metadata.json
#
# Usage:
#   ./migrate_results.sh [--dry-run] [--delete-old]
#
# Options:
#   --dry-run     Show what would be done without making changes
#   --delete-old  Delete old results after migration

set -e

# Configuration
BUCKET="${BUCKET_NAME:-fellows-safety-research-camyang-arvo-benchmark}"
EXPERIMENT_ID="default"
DRY_RUN=false
DELETE_OLD=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --delete-old)
            DELETE_OLD=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "==========================================="
echo "Result Storage Migration"
echo "==========================================="
echo "Bucket:         ${BUCKET}"
echo "Experiment ID:  ${EXPERIMENT_ID}"
echo "Dry Run:        ${DRY_RUN}"
echo "Delete Old:     ${DELETE_OLD}"
echo "==========================================="
echo ""

# Find all case directories
echo "[*] Finding existing results..."
CASES=$(gsutil ls "gs://${BUCKET}/results/" 2>/dev/null | grep -oE 'case_[0-9]+' | sort -u || echo "")

if [ -z "${CASES}" ]; then
    echo "[!] No existing results found"
    exit 0
fi

echo "[*] Found cases: $(echo ${CASES} | wc -w | tr -d ' ')"
echo ""

MIGRATED=0
SKIPPED=0
ERRORS=0

for CASE_DIR in ${CASES}; do
    CASE_ID=$(echo "${CASE_DIR}" | sed 's/case_//')
    
    # Find all model directories for this case
    MODELS=$(gsutil ls "gs://${BUCKET}/results/${CASE_DIR}/" 2>/dev/null | grep -vE '(gt|default)/$' | xargs -I{} basename {} || echo "")
    
    for MODEL in ${MODELS}; do
        # Skip if not a model directory (e.g., gt)
        if [ "${MODEL}" = "gt" ]; then
            continue
        fi
        
        echo "[*] Processing case ${CASE_ID}, model ${MODEL}..."
        
        # Find the most recent run with a result.json
        RUNS=$(gsutil ls "gs://${BUCKET}/results/${CASE_DIR}/${MODEL}/" 2>/dev/null | xargs -I{} basename {} | sort -r || echo "")
        
        FOUND_RESULT=false
        for RUN_ID in ${RUNS}; do
            # Look for result.json in the old nested structure
            OLD_RESULT_PATH="gs://${BUCKET}/results/${CASE_DIR}/${MODEL}/${RUN_ID}/patch/${CASE_DIR}/autopatchbench/${MODEL}/result.json"
            OLD_PATCH_PATH="gs://${BUCKET}/results/${CASE_DIR}/${MODEL}/${RUN_ID}/patch/${CASE_DIR}/autopatchbench/${MODEL}/patch.txt"
            
            # Check if result exists
            if gsutil -q stat "${OLD_RESULT_PATH}" 2>/dev/null; then
                FOUND_RESULT=true
                
                # New paths
                NEW_RESULT_PATH="gs://${BUCKET}/results/${EXPERIMENT_ID}/${CASE_ID}/${MODEL}/result.json"
                NEW_PATCH_PATH="gs://${BUCKET}/results/${EXPERIMENT_ID}/${CASE_ID}/${MODEL}/patch.txt"
                NEW_METADATA_PATH="gs://${BUCKET}/results/${EXPERIMENT_ID}/${CASE_ID}/${MODEL}/metadata.json"
                
                # Check if already migrated
                if gsutil -q stat "${NEW_RESULT_PATH}" 2>/dev/null; then
                    echo "  [skip] Already exists at ${NEW_RESULT_PATH}"
                    SKIPPED=$((SKIPPED + 1))
                    break
                fi
                
                echo "  [migrate] Found result from run ${RUN_ID}"
                
                if [ "${DRY_RUN}" = "true" ]; then
                    echo "  [dry-run] Would copy:"
                    echo "    ${OLD_RESULT_PATH} -> ${NEW_RESULT_PATH}"
                    if gsutil -q stat "${OLD_PATCH_PATH}" 2>/dev/null; then
                        echo "    ${OLD_PATCH_PATH} -> ${NEW_PATCH_PATH}"
                    fi
                    echo "    Create ${NEW_METADATA_PATH}"
                else
                    # Copy result.json
                    if gsutil cp "${OLD_RESULT_PATH}" "${NEW_RESULT_PATH}" 2>/dev/null; then
                        echo "  [ok] Copied result.json"
                    else
                        echo "  [error] Failed to copy result.json"
                        ERRORS=$((ERRORS + 1))
                        continue
                    fi
                    
                    # Copy patch.txt if it exists
                    if gsutil -q stat "${OLD_PATCH_PATH}" 2>/dev/null; then
                        if gsutil cp "${OLD_PATCH_PATH}" "${NEW_PATCH_PATH}" 2>/dev/null; then
                            echo "  [ok] Copied patch.txt"
                        else
                            echo "  [warn] Failed to copy patch.txt"
                        fi
                    fi
                    
                    # Also try to copy rebuilt_binary if it exists (from old patch cache)
                    OLD_BINARY_PATH="gs://${BUCKET}/patches/${CASE_DIR}/${MODEL}/rebuilt_binary"
                    NEW_BINARY_PATH="gs://${BUCKET}/results/${EXPERIMENT_ID}/${CASE_ID}/${MODEL}/rebuilt_binary"
                    if gsutil -q stat "${OLD_BINARY_PATH}" 2>/dev/null; then
                        if gsutil cp "${OLD_BINARY_PATH}" "${NEW_BINARY_PATH}" 2>/dev/null; then
                            echo "  [ok] Copied rebuilt_binary from patch cache"
                        fi
                    fi
                    
                    # Create metadata.json
                    METADATA=$(cat << EOF
{
    "migrated_from_run_id": "${RUN_ID}",
    "experiment_id": "${EXPERIMENT_ID}",
    "case_id": ${CASE_ID},
    "model": "${MODEL}",
    "migrated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "original_path": "${OLD_RESULT_PATH}"
}
EOF
)
                    echo "${METADATA}" | gsutil cp - "${NEW_METADATA_PATH}" 2>/dev/null
                    echo "  [ok] Created metadata.json"
                fi
                
                MIGRATED=$((MIGRATED + 1))
                break  # Only migrate from the first (most recent) run with results
            fi
        done
        
        if [ "${FOUND_RESULT}" = "false" ]; then
            echo "  [skip] No result.json found"
            SKIPPED=$((SKIPPED + 1))
        fi
    done
done

echo ""
echo "==========================================="
echo "Migration Summary"
echo "==========================================="
echo "Migrated: ${MIGRATED}"
echo "Skipped:  ${SKIPPED}"
echo "Errors:   ${ERRORS}"
echo "==========================================="

# Delete old results if requested
if [ "${DELETE_OLD}" = "true" ] && [ "${DRY_RUN}" = "false" ] && [ "${MIGRATED}" -gt 0 ]; then
    echo ""
    echo "[!] Deleting old results structure..."
    
    # Delete old results (but keep the new experiment directory)
    for CASE_DIR in ${CASES}; do
        CASE_ID=$(echo "${CASE_DIR}" | sed 's/case_//')
        
        # Delete model directories (not gt or the new structure)
        MODELS=$(gsutil ls "gs://${BUCKET}/results/${CASE_DIR}/" 2>/dev/null | grep -vE "(gt|${EXPERIMENT_ID})/$" || echo "")
        
        for MODEL_PATH in ${MODELS}; do
            echo "  Deleting ${MODEL_PATH}..."
            gsutil -m rm -r "${MODEL_PATH}" 2>/dev/null || true
        done
    done
    
    # Also clean up old patches cache
    echo "[!] Cleaning up old patches cache..."
    gsutil -m rm -r "gs://${BUCKET}/patches/" 2>/dev/null || true
    
    echo "[ok] Old structure deleted"
fi

echo ""
echo "Migration complete!"
