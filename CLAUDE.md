# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GAIA is an active defense security monitoring platform for OpenEuler servers. It uses eBPF to monitor critical systemd services at kernel level, detect anomalies, block malicious activity, and hot-patch vulnerable functions at runtime without service restarts. The entire stack is written in Rust with a React/TypeScript frontend embedded in the binary.

## Build Commands

```bash
# Build (requires pnpm installed globally for WebUI)
cargo build
cargo build --release

# Run (requires root or CAP_BPF + CAP_SYS_ADMIN, Linux 5.10+ with CONFIG_DEBUG_INFO_BTF=y)
sudo RUST_LOG=info ./target/debug/gaia-xdp --config gaia.toml

# Lint
cargo clippy
cd gaia-webui && pnpm lint

# Format
cargo fmt
cd gaia-webui && pnpm format   # if configured
```

The build script (`gaia-xdp/build.rs`) automatically runs `pnpm install && pnpm build` in `gaia-webui/` and compiles the eBPF probes with nightly Rust. The compiled WebUI assets and eBPF bytecode are embedded into the final binary.

## Workspace Structure

This is a Cargo workspace with three Rust crates plus a frontend:

- **`gaia-xdp-common/`** — `no_std` shared types between kernel and user space: `KernelEvent`, event kind/action constants, rate limit structures, hotpatch rule entries. This crate compiles in both kernel (eBPF) and user-space contexts.
- **`gaia-xdp-ebpf/`** — Kernel-space eBPF probes (compiled with `no_std` via Aya). Contains five probe groups: file I/O (`openat`), process/privilege (`execve`, `setuid/gid`), network (`connect`, `bind`), hot-patching (kprobe `tcp_connect` + uprobes), and port blocking (cgroup sock addr hooks). BPF maps are the only IPC channel to user space.
- **`gaia-xdp/`** — User-space daemon. Loads/attaches eBPF probes, reads the ring buffer, runs anomaly detection, manages hot-patching, and serves the HTTP API + embedded WebUI on port 17890.
- **`gaia-webui/`** — React 19 + TypeScript + Vite frontend. Built by `build.rs` and embedded via `rust-embed`.

## Architecture

### Data Flow

```
Kernel eBPF probes → BPF ring buffer (256 KB) → User-space event loop
  → Anomaly detection (baselines + whitelists) → Alert records
  → HTTP API / WebUI / AI analysis (OpenAI/Ollama/custom LLM)
```

Policy changes flow in reverse: HTTP API updates `RuntimeState` → BPF maps are synced to kernel.

### Key Abstractions in `gaia-xdp/src/main.rs`

- **`MonitorPolicy`** — Deserialized from `gaia.toml`. Contains sensitive path prefixes, monitored services, exec whitelists, blocked ports, baseline thresholds, and hotpatch targets.
- **`RuntimeState`** — In-memory state wrapped in `Arc<RwLock<>>`. Holds event/alert history, per-service PID mappings, baseline counters (reset every 30s), and AI chat history.
- **`EventRecord` / `AlertRecord`** — User-friendly wrappers around `KernelEvent` with severity levels and human-readable reasons.

### Hot-patching System (`main.rs`)

1. Parse ELF symbol tables + DWARF debug info to find function offsets.
2. Resolve runtime addresses via `/proc/pid/maps` (handles ASLR).
3. Attach uprobes/uretprobes for `Monitor` mode.
4. For `OverrideReturn`/`SkipCall`: inject machine code via ptrace `PEEKTEXT`/`POKETEXT`.
5. For `ReplaceFunction`: inject a replacement `.so` by ptrace-injecting a `__libc_dlopen_mode` call.

### Systemd Integration

The daemon queries systemd cgroup PIDs every 5 seconds via `systemctl show --property=ControlGroup` and parses `/sys/fs/cgroup/.../cgroup.procs`. This PID→service mapping is used to attribute kernel events to specific services.

### AI Analysis (`gaia-xdp/src/ai.rs`)

High/critical alerts are streamed to a configurable LLM (OpenAI-compatible API or Ollama). The AI receives recent events and baseline metrics as context. The `/api/v1/ai/chat` endpoint supports interactive investigation; `/api/v1/ai/events` is an SSE stream of AI responses.

## Configuration

`gaia.toml` is the policy file. Key sections:

```toml
[[sensitive_prefixes]]       # File paths that trigger alerts when accessed
[[monitored_services]]       # systemd services to watch (e.g. "ssh.service")
[[exec_whitelist_prefixes]]  # Allowed binary paths for process events
[[blocked_ports]]            # Ports blocked at kernel level via cgroup hooks
rate_limit_rules = []        # CIDR-based connection rate limits

[baseline_thresholds]        # Max syscalls per 30s window before alerting
file_io = 200
network = 160
privilege = 20
process = 80

[[hotpatch.targets]]         # Runtime function patching targets
binary = "/path/to/binary"
symbol = "function_name"
pid = 12345
patch_action = "monitor"     # monitor | override_return | skip_call | replace_function
```

## eBPF Development Notes

- eBPF code in `gaia-xdp-ebpf/` must remain `no_std` and cannot use heap allocation.
- BPF maps are defined in `gaia-xdp-ebpf/src/main.rs` and accessed from user space via Aya's typed map handles.
- The `gaia-xdp-common` crate uses `#![cfg_attr(not(feature = "user"), no_std)]` to compile in both contexts.
- eBPF probes are compiled with the nightly toolchain (see `rust-toolchain.toml`); the stable toolchain is used for `gaia-xdp`.
- Requires BTF-enabled kernel (`CONFIG_DEBUG_INFO_BTF=y`) for CO-RE (Compile Once, Run Everywhere).
