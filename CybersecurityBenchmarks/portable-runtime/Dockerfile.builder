# Multi-stage Dockerfile for building portable agent runtime
#
# This creates a self-contained Python runtime with the Claude Code single
# binary that works on glibc 2.17+ systems (Ubuntu 14.04+, CentOS 7+).
#
# Key insight: python-build-standalone is compiled against old glibc, and
# the Claude Code single binary (Bun-compiled) is self-contained with zero
# external dependencies. No Node.js needed.
#
# Usage:
#   docker build -f Dockerfile.builder -t agent-runtime-builder .
#   docker run --rm -v $(pwd)/output:/output agent-runtime-builder
#
# Output: /output/agent-runtime.tar.gz

# Force x86_64 platform since all ARVO containers are amd64
ARG TARGETPLATFORM=linux/amd64

# =============================================================================
# Stage 0: Get ALL musl runtime libraries from Alpine
# =============================================================================
# The Claude Code musl binary needs: musl libc, musl linker, libstdc++, libgcc_s.
# ALL must come from the same musl ecosystem to avoid ABI mismatches.
# Alpine uses musl natively, so we extract everything from a single Alpine image.
FROM --platform=$TARGETPLATFORM alpine:3.21 AS alpine-libs
RUN apk add --no-cache libstdc++ libgcc musl

# =============================================================================
# Stage 1: Download all components
# =============================================================================
FROM --platform=$TARGETPLATFORM debian:bookworm AS downloader

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    xz-utils \
    patchelf \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /downloads

# Versions
ARG PYTHON_VERSION=3.11.9
ARG PYTHON_BUILD_DATE=20240726

# Download Python from python-build-standalone
# These builds target glibc 2.17 (CentOS 7 era)
RUN curl -L -o python.tar.gz \
    "https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_BUILD_DATE}/cpython-${PYTHON_VERSION}+${PYTHON_BUILD_DATE}-x86_64-unknown-linux-gnu-install_only.tar.gz" \
    && mkdir -p /runtime/python \
    && tar -xzf python.tar.gz -C /runtime/python --strip-components=1 \
    && rm python.tar.gz

# Download Claude Code single binary (musl / statically-linked variant).
# ARVO containers use Ubuntu 16.04 (glibc 2.23), so we need the musl build
# which is fully static and works on any glibc version.
# Distribution: https://claude.ai/install.sh -> GCS bucket with versioned releases.
ARG CLAUDE_CODE_VERSION=2.1.44
RUN mkdir -p /runtime/bin && \
    GCS_BUCKET="https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases" && \
    if [ "${CLAUDE_CODE_VERSION}" = "latest" ]; then \
    CC_VERSION=$(curl -fsSL "$GCS_BUCKET/latest"); \
    else \
    CC_VERSION="${CLAUDE_CODE_VERSION}"; \
    fi && \
    echo "Downloading Claude Code CLI v${CC_VERSION} (linux-x64-musl)..." && \
    curl -fsSL -o /runtime/bin/claude "$GCS_BUCKET/$CC_VERSION/linux-x64-musl/claude" && \
    chmod +x /runtime/bin/claude && \
    ls -lh /runtime/bin/claude && \
    echo "Claude Code CLI v${CC_VERSION} installed"

# Bundle ALL musl libraries from Alpine (single ecosystem, no ABI mismatches)
COPY --from=alpine-libs /lib/ld-musl-x86_64.so.1 /runtime/lib/
COPY --from=alpine-libs /lib/ld-musl-x86_64.so.1 /runtime/lib/libc.musl-x86_64.so.1
COPY --from=alpine-libs /usr/lib/libstdc++.so.6 /runtime/lib/
COPY --from=alpine-libs /usr/lib/libgcc_s.so.1 /runtime/lib/
RUN patchelf --set-interpreter /agent-runtime/lib/ld-musl-x86_64.so.1 \
    --set-rpath /agent-runtime/lib \
    /runtime/bin/claude && \
    echo "Patched claude binary (interpreter + rpath)" && \
    echo "Bundled libs:" && ls -lh /runtime/lib/

# =============================================================================
# Stage 2: Install Python packages
# =============================================================================
FROM downloader AS python-deps

WORKDIR /runtime

# Upgrade pip and install packages (including claude-agent-sdk for CC agent)
RUN /runtime/python/bin/python3.11 -m pip install --upgrade pip && \
    /runtime/python/bin/python3.11 -m pip install \
    anthropic \
    httpx \
    pydantic \
    tree-sitter \
    tree-sitter-cpp \
    claude-agent-sdk \
    anyio \
    && echo "Python packages installed"

# Verify imports work
RUN /runtime/python/bin/python3.11 -c "import anthropic; print('anthropic OK')" && \
    /runtime/python/bin/python3.11 -c "import tree_sitter; import tree_sitter_cpp; print('tree-sitter OK')"

# =============================================================================
# Stage 3: Create bin directory with entry points
# =============================================================================
FROM python-deps AS final

# Create symlinks in bin/ (claude binary already present from stage 1)
RUN ln -sf ../python/bin/python3.11 /runtime/bin/python3.11 && \
    ln -sf python3.11 /runtime/bin/python3 && \
    ln -sf python3 /runtime/bin/python

# Create VERSION file
RUN echo "agent-runtime v2.0.0" > /runtime/VERSION && \
    /runtime/python/bin/python3.11 --version >> /runtime/VERSION && \
    echo "Claude Code CLI: single-binary (Bun-compiled)" >> /runtime/VERSION && \
    echo "Built: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> /runtime/VERSION

# Strip unnecessary files to reduce size
RUN rm -rf /runtime/python/include && \
    rm -rf /runtime/python/share && \
    find /runtime -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true && \
    find /runtime -type d -name "test" -exec rm -rf {} + 2>/dev/null || true && \
    find /runtime -type d -name "tests" -exec rm -rf {} + 2>/dev/null || true && \
    find /runtime -name "*.pyc" -delete 2>/dev/null || true

# Create agent directory for user code
RUN mkdir -p /runtime/agent

# Default command: show contents and sizes
CMD ["sh", "-c", "echo '=== Agent Runtime Contents ===' && ls -la /runtime && echo '' && echo '=== Size ===' && du -sh /runtime/* && echo '' && echo '=== Total ===' && du -sh /runtime"]
