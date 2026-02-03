#!/bin/bash
# Agent Runtime Entrypoint Script
#
# This script sets up the environment for running the portable agent runtime
# inside ARVO containers (or any glibc 2.17+ system).
#
# The Python and Node.js binaries are from python-build-standalone and
# unofficial-builds respectively, which are compiled against old glibc (2.17).
# They should work natively on old systems without bundled glibc.
#
# Usage:
#   /agent-runtime/bin/agent-entrypoint.sh python3 script.py
#   /agent-runtime/bin/agent-entrypoint.sh node script.js
#   /agent-runtime/bin/agent-entrypoint.sh  # Runs default agent
#
# Environment variables:
#   ANTHROPIC_API_KEY  - Required for LLM calls
#   AGENT_RUNTIME_DEBUG=1 - Enable debug output
#   AGENT_RUNTIME_DIR  - Override runtime directory (default: auto-detect)

set -e

# =============================================================================
# Determine runtime directory
# =============================================================================

if [ -n "${AGENT_RUNTIME_DIR}" ]; then
    RUNTIME_DIR="${AGENT_RUNTIME_DIR}"
elif [ -d "/agent-runtime" ]; then
    RUNTIME_DIR="/agent-runtime"
else
    # Auto-detect from script location
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    RUNTIME_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
fi

# Verify runtime directory
if [ ! -f "${RUNTIME_DIR}/python/bin/python3.11" ]; then
    echo "ERROR: Could not find agent runtime at ${RUNTIME_DIR}"
    echo "Expected to find: ${RUNTIME_DIR}/python/bin/python3.11"
    exit 1
fi

# =============================================================================
# Environment Configuration
# =============================================================================

# 1. PATH - prepend runtime binaries
export PATH="${RUNTIME_DIR}/bin:${RUNTIME_DIR}/python/bin:${RUNTIME_DIR}/node/bin:${PATH}"

# 2. Python environment
export PYTHONHOME="${RUNTIME_DIR}/python"
# Include both agent/ and evaluation/ modules, plus the parent directory for imports
export PYTHONPATH="${RUNTIME_DIR}/python/lib/python3.11:${RUNTIME_DIR}/python/lib/python3.11/site-packages:${RUNTIME_DIR}"

# 3. Node.js environment
export NODE_PATH="${RUNTIME_DIR}/node/lib/node_modules"

# 4. SSL certificates - use system certs if available
# This is important for HTTPS connections to Anthropic API
if [ -z "${SSL_CERT_FILE}" ]; then
    if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
        export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
    elif [ -f /etc/pki/tls/certs/ca-bundle.crt ]; then
        export SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt
    elif [ -f /etc/ssl/ca-bundle.pem ]; then
        export SSL_CERT_FILE=/etc/ssl/ca-bundle.pem
    fi
fi

# Also set REQUESTS_CA_BUNDLE for Python requests library
if [ -n "${SSL_CERT_FILE}" ]; then
    export REQUESTS_CA_BUNDLE="${SSL_CERT_FILE}"
fi

# =============================================================================
# Debug Output
# =============================================================================

if [ "${AGENT_RUNTIME_DEBUG:-0}" = "1" ]; then
    echo "[agent-runtime] ======================================"
    echo "[agent-runtime] Runtime directory: ${RUNTIME_DIR}"
    echo "[agent-runtime] PATH: ${PATH}"
    echo "[agent-runtime] PYTHONHOME: ${PYTHONHOME}"
    echo "[agent-runtime] SSL_CERT_FILE: ${SSL_CERT_FILE:-not set}"
    echo "[agent-runtime] Container glibc: $(ldd --version 2>&1 | head -1 || echo 'unknown')"

    # Test Python
    echo -n "[agent-runtime] Python: "
    "${RUNTIME_DIR}/python/bin/python3.11" --version 2>&1 || echo "FAILED"

    # Test Node.js
    echo -n "[agent-runtime] Node.js: "
    "${RUNTIME_DIR}/node/bin/node" --version 2>&1 || echo "FAILED"

    echo "[agent-runtime] ======================================"
fi

# =============================================================================
# Execute Command
# =============================================================================

if [ $# -eq 0 ]; then
    # No command specified - show usage
    echo "Agent Runtime Entrypoint"
    echo ""
    echo "Usage: $0 <command> [args...]"
    echo ""
    echo "Examples:"
    echo "  # Run patching agent"
    echo "  $0 python3 -m agent.main --case-id 42 --agent autopatchbench --model claude-sonnet-4-20250514"
    echo ""
    echo "  # Run fuzzing evaluation"
    echo "  $0 python3 -m evaluation.main --case-id 42 --duration 300"
    echo ""
    echo "  # Run Python script"
    echo "  $0 python3 script.py"
    echo ""
    echo "Available modules:"
    echo "  agent      - Patching agents (autopatchbench)"
    echo "  evaluation - Fuzzing and crash analysis"
    exit 1
else
    # Determine what to run based on first argument
    CMD="$1"
    shift

    case "${CMD}" in
        python|python3|python3.11)
            exec "${RUNTIME_DIR}/python/bin/python3.11" "$@"
            ;;
        node|nodejs)
            exec "${RUNTIME_DIR}/node/bin/node" "$@"
            ;;
        npm)
            exec "${RUNTIME_DIR}/node/bin/npm" "$@"
            ;;
        *)
            # Try to run as-is (might be a script in PATH)
            exec "$CMD" "$@"
            ;;
    esac
fi
