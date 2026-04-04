# =============================================================================
# Gaia — Multi-stage Dockerfile
# Stage 1 (builder-webui)  : Build the React/TypeScript front-end with pnpm
# Stage 2 (builder-rust)   : Compile the Rust user-space daemon + eBPF probes
# Stage 3 (runtime)        : Minimal runtime image with just the binary + assets
# =============================================================================
#
# Requirements for the host running the final image:
#   - Linux kernel 5.10+ with CONFIG_DEBUG_INFO_BTF=y and CONFIG_BPF_SYSCALL=y
#   - CAP_BPF / CAP_SYS_ADMIN  (or run as root in the container)
#
# Build:
#   docker build -t gaia:latest .
#
# Run:
#   docker run --rm --privileged \
#     -v /sys/kernel/btf:/sys/kernel/btf:ro \
#     -v /sys/fs/bpf:/sys/fs/bpf \
#     -v $(pwd)/gaia.toml:/etc/gaia/gaia.toml:ro \
#     -p 17890:17890 \
#     gaia:latest
# =============================================================================

# ── Stage 1: Front-end build ─────────────────────────────────────────────────
FROM public.ecr.aws/docker/library/node:22-slim AS builder-webui

# Install pnpm via corepack (ships with Node 16+)
RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /src/gaia-webui

# Copy lockfile + manifest first for layer caching
COPY gaia-webui/package.json gaia-webui/pnpm-lock.yaml ./

RUN pnpm config set registry https://registry.npmmirror.com && \
    pnpm install --frozen-lockfile

# Copy the rest of the front-end sources
COPY gaia-webui/ .

RUN pnpm run build


# ── Stage 2: Rust + eBPF build ───────────────────────────────────────────────
FROM public.ecr.aws/docker/library/rust:slim AS builder-rust

# ── System dependencies ────────────────────────────────────────────────────
# llvm/clang are required by bpf-linker; linux-headers for BTF object generation.
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libclang-dev \
    lld \
    linux-headers-generic \
    pkg-config \
    libssl-dev \
    ca-certificates \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Rust nightly toolchain ────────────────────────────────────────────────
# The channel is pinned via rust-toolchain.toml which cargo/rustup respects
# automatically; we still install the nightly base here so `rustup` does not
# need a network call at container start.
COPY rust-toolchain.toml /workspace/rust-toolchain.toml
WORKDIR /workspace

RUN rustup toolchain install nightly \
    && rustup component add rust-src --toolchain nightly \
    && rustup target add bpfel-unknown-none --toolchain nightly \
    && rustup target add x86_64-unknown-linux-gnu --toolchain nightly

# ── bpf-linker (eBPF LLVM back-end) ──────────────────────────────────────
RUN cargo install bpf-linker --locked

# ── Copy workspace sources ───────────────────────────────────────────────
COPY Cargo.toml Cargo.lock rustfmt.toml /workspace/
COPY .cargo /workspace/.cargo/

COPY gaia-xdp         /workspace/gaia-xdp/
COPY gaia-xdp-common  /workspace/gaia-xdp-common/
COPY gaia-xdp-ebpf    /workspace/gaia-xdp-ebpf/

# ── Build release binary ─────────────────────────────────────────────────
# CARGO_TARGET_DIR is explicitly set to keep the build cache inside the
# container layer and avoid polluting the host mount.
ENV CARGO_TARGET_DIR=/workspace/target \
    RUST_LOG=info

RUN cargo build --release -p gaia-xdp


# ── Stage 3: Minimal runtime image ───────────────────────────────────────────
FROM public.ecr.aws/docker/library/debian:bookworm-slim AS runtime

# Runtime libs needed by the binary (openssl, libgcc, …)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a dedicated directory layout
RUN mkdir -p /opt/gaia/webui /etc/gaia

# ── Copy compiled artefacts ───────────────────────────────────────────────
COPY --from=builder-rust /workspace/target/release/gaia-xdp /usr/local/bin/gaia-xdp
COPY --from=builder-webui /src/gaia-webui/dist /opt/gaia/webui/

# ── Default config (can be overridden by bind-mount) ─────────────────────
COPY gaia.toml /etc/gaia/gaia.toml

WORKDIR /opt/gaia

# Expose the HTTP API / WebUI port
EXPOSE 17890

# The daemon needs elevated capabilities to load eBPF programs.
# Pass --privileged (or at minimum --cap-add=BPF --cap-add=SYS_ADMIN) at
# `docker run` time.  We do NOT set USER to root here — let the operator
# decide the privilege level.

ENTRYPOINT ["/usr/local/bin/gaia-xdp"]
CMD ["--config", "/etc/gaia/gaia.toml", "--web-listen", "0.0.0.0:17890"]
