# Multi-stage Dockerfile for building portable agent runtime
#
# This creates a self-contained Python + Node.js runtime that works on
# glibc 2.17+ systems (Ubuntu 14.04+, CentOS 7+).
#
# Key insight: Both python-build-standalone and unofficial-builds Node.js
# are specifically compiled against old glibc, so they should work without
# needing bundled glibc libraries.
#
# Usage:
#   docker build -f Dockerfile.builder -t agent-runtime-builder .
#   docker run --rm -v $(pwd)/output:/output agent-runtime-builder
#
# Output: /output/agent-runtime.tar.gz (~60-70MB compressed)

# =============================================================================
# Stage 1: Download all components
# =============================================================================
# Force x86_64 platform since python-build-standalone and unofficial-builds
# Node.js are x86_64 binaries targeting glibc 2.17
FROM --platform=linux/amd64 debian:bookworm AS downloader

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /downloads

# Versions
ARG PYTHON_VERSION=3.11.9
ARG PYTHON_BUILD_DATE=20240726
ARG NODE_VERSION=18.20.4

# Download Python from python-build-standalone
# These builds target glibc 2.17 (CentOS 7 era)
RUN curl -L -o python.tar.gz \
    "https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_BUILD_DATE}/cpython-${PYTHON_VERSION}+${PYTHON_BUILD_DATE}-x86_64-unknown-linux-gnu-install_only.tar.gz" \
    && mkdir -p /runtime/python \
    && tar -xzf python.tar.gz -C /runtime/python --strip-components=1 \
    && rm python.tar.gz

# Download Node.js from unofficial-builds (glibc-217 variant)
# This is a special build that targets glibc 2.17
RUN curl -L -o node.tar.gz \
    "https://unofficial-builds.nodejs.org/download/release/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64-glibc-217.tar.gz" \
    && mkdir -p /runtime/node \
    && tar -xzf node.tar.gz -C /runtime/node --strip-components=1 \
    && rm node.tar.gz

# =============================================================================
# Stage 2: Install Python packages
# =============================================================================
FROM downloader AS python-deps

# Install pip packages
WORKDIR /runtime

# Upgrade pip and install packages
RUN /runtime/python/bin/python3.11 -m pip install --upgrade pip && \
    /runtime/python/bin/python3.11 -m pip install \
    anthropic \
    httpx \
    pydantic \
    tree-sitter \
    tree-sitter-cpp \
    && echo "Python packages installed"

# Verify imports work
RUN /runtime/python/bin/python3.11 -c "import anthropic; print('anthropic OK')" && \
    /runtime/python/bin/python3.11 -c "import tree_sitter; import tree_sitter_cpp; print('tree-sitter OK')"

# =============================================================================
# Stage 3: Create bin directory with entry points
# =============================================================================
FROM python-deps AS final

# Create bin directory
RUN mkdir -p /runtime/bin

# Create symlinks in bin/
RUN ln -sf ../python/bin/python3.11 /runtime/bin/python3.11 && \
    ln -sf python3.11 /runtime/bin/python3 && \
    ln -sf python3 /runtime/bin/python && \
    ln -sf ../node/bin/node /runtime/bin/node && \
    ln -sf ../node/bin/npm /runtime/bin/npm

# Create VERSION file
RUN echo "agent-runtime v1.0.0" > /runtime/VERSION && \
    /runtime/python/bin/python3.11 --version >> /runtime/VERSION && \
    /runtime/node/bin/node --version >> /runtime/VERSION && \
    echo "Built: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> /runtime/VERSION

# Strip unnecessary files to reduce size
RUN rm -rf /runtime/python/include && \
    rm -rf /runtime/python/share && \
    rm -rf /runtime/node/include && \
    rm -rf /runtime/node/share && \
    find /runtime -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true && \
    find /runtime -type d -name "test" -exec rm -rf {} + 2>/dev/null || true && \
    find /runtime -type d -name "tests" -exec rm -rf {} + 2>/dev/null || true && \
    find /runtime -name "*.pyc" -delete 2>/dev/null || true

# Create agent directory for user code
RUN mkdir -p /runtime/agent

# Default command: show contents and sizes
CMD echo "=== Agent Runtime Contents ===" && \
    ls -la /runtime && \
    echo "" && \
    echo "=== Size ===" && \
    du -sh /runtime/* && \
    echo "" && \
    echo "=== Total ===" && \
    du -sh /runtime
