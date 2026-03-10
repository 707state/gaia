# Agent Guidelines for gaia-xdp

This document provides guidelines for AI agents working on the gaia-xdp eBPF/XDP project.

## Project Overview

gaia-xdp is a Rust workspace with three crates:
- `gaia-xdp-common`: Shared types and definitions (no_std)
- `gaia-xdp-ebpf`: eBPF program compiled for kernel space
- `gaia-xdp`: User-space loader and control program

The project uses the [Aya](https://github.com/aya-rs/aya) eBPF library and targets Linux XDP.

**Note**: There are no Cursor rules (`.cursor/rules/`) or Copilot rules (`.github/copilot-instructions.md`) in this repository.

## Toolchain

- **Rust toolchain**: `nightly` (specified in `rust-toolchain.toml`)
- **Components**: `rust-src`, `clippy`, `rust-analyzer`, `rustfmt`
- **Targets**: `aarch64-unknown-linux-gnu`
- **Formatting**: `rustfmt` with custom configuration (see `rustfmt.toml`)

## Build Commands

### Standard Builds
```bash
cargo build          # Build all workspace members
cargo build --release
cargo check          # Check code without building
cargo run --release  # Run user-space program (requires sudo via cargo runner)
```

### eBPF-Specific Builds
The eBPF program is automatically built via `build.rs` in the `gaia-xdp` crate. No separate build command needed.

### Cross-Compilation (macOS to Linux)
```bash
ARCH=aarch64  # or x86_64
CC=${ARCH}-linux-musl-gcc cargo build --package gaia-xdp --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
Binary at `target/${ARCH}-unknown-linux-musl/release/gaia-xdp`.

# AGENTS.md

This repository contains the gaia-xdp project.

gaia-xdp is a monitoring and configuration system built using Rust and the Aya eBPF framework.

Agents modifying this repository must follow the rules described in this document.

---

# Project Overview

gaia-xdp uses Linux eBPF to implement system observability and monitoring.

The platform provides:

- system monitoring
- traffic inspection
- system call statistics
- hot data detection
- Web-based configuration and visualization

The project targets Linux ARM64 systems and aims to leverage ARMv8-A architecture features where possible.

---

# Project Structure

The repository is expected to contain the following components:
gaia-xdp/
-- gaia-xdp-ebpf/
-- gaia-xdp-common/
-- gaia-xdp/
-- webui/


Rules:

- `gaia-xdp-ebpf/` contains kernel-space eBPF programs.
- `gaia-xdp/` contains Rust userspace control logic.
- `webui/` contains the frontend UI.
- Kernel-space and user-space code must remain separated.

---

# eBPF Programming Rules

Code inside the `gaia-xdp-ebpf/` directory must follow Linux eBPF verifier restrictions.

Allowed:

- `core`
- `aya-ebpf`
- `aya-log-ebpf`

Forbidden:

- `std`
- heap allocation
- recursion
- dynamic memory
- unbounded loops

Loops must have a fixed upper bound.

Example:
```rust
for i in 0..8 {
}
```


---

# Map Usage

Maps must be declared using Aya macros.

Example:

```rust
#[map]
static mut EVENTS: RingBuf =
RingBuf::with_max_entries(1024, 0);
```

Guidelines:

- map keys should typically use `u32`
- avoid large map sizes
- prefer ring buffers or perf buffers for event streaming

---

# Program Types

The project may include multiple eBPF program types.

Examples include:

- XDP programs for packet processing
- LSM programs for security hooks
- tracepoints or kprobes for system call tracing

Each program must be implemented using the correct Aya macro.

Example XDP program:

```rust
#[xdp]
pub fn packet_filter(ctx: XdpContext) -> u32

```
Example LSM program:
```rust
#[lsm(name = "task_alloc")]
pub fn task_alloc(ctx: LsmContext) -> i32
```


---

# Safety Rules

All kernel pointer dereferences must occur inside `unsafe` blocks.

Example:

```rust
unsafe {
(*task).pid
}
```


Never assume kernel memory is safe.

---

# Logging

Use Aya logging macros for debugging.

Example:

```rust
info!(&ctx, "event triggered");
```


Do not use `println!` inside eBPF code.

---

# Target Platform

The target platform for gaia-xdp is:

- Linux ARM64 (AArch64)

Agents should ensure that code remains compatible with modern Linux kernels and ARM64 systems.

---

# Performance Goals

The system aims to provide low-overhead monitoring.

Agents should avoid:

- large stack allocations
- complex branching logic
- unnecessary map accesses

---

# Testing and Debugging

eBPF programs must pass the kernel verifier.

Agents should ensure:

- stack usage remains small
- loops are bounded
- helper functions are valid for the program type

Tools that may be used:

- bpftool
- kernel logs
- Aya userspace loader

---

# Contribution Guidelines

Agents modifying this repository must:

- keep kernel and userspace code separated
- avoid introducing verifier-incompatible constructs
- maintain compatibility with Aya APIs


## Linting and Formatting

### Code Formatting
```bash
cargo fmt            # Format all code
cargo fmt --check    # Check formatting
```
**rustfmt configuration** (`rustfmt.toml`):
- `group_imports = "StdExternalCrate"`: Group imports by std, external, crate
- `imports_granularity = "Crate"`: Merge imports from same crate
- `reorder_imports = true`: Alphabetical ordering

### Linting with Clippy
```bash
cargo clippy                    # All workspace members
cargo clippy -p gaia-xdp        # Specific crate
cargo clippy -p gaia-xdp-ebpf
cargo clippy -p gaia-xdp-common
```
**Note**: eBPF code contains `#[allow(clippy::all)]` due to false positives from kernel bindings.

## Testing

Currently no tests defined. When adding tests:
```bash
cargo test --workspace          # Run all tests
cargo test -p gaia-xdp          # Specific crate
cargo test --package gaia-xdp test_function_name  # Single test
```
eBPF code cannot be tested with standard Rust tests; consider integration tests with `aya` test framework when available.

## Code Style Guidelines

### Imports
- **Grouping**: Follow `rustfmt`'s `StdExternalCrate` grouping: std → external → internal
- **Granularity**: Merge imports from same crate (`imports_granularity = "Crate"`)
- **Ordering**: Alphabetical within each group (`reorder_imports = true`)
- **`rustfmt::skip`**: Use `#[rustfmt::skip]` on imports only when necessary

Example:
```rust
use std::net::Ipv4Addr;
use anyhow::Context as _;
use aya::{maps::HashMap, programs::{Xdp, XdpFlags}};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
```

### Naming Conventions
- **Types**: `CamelCase` (structs, enums, traits, type aliases)
- **Functions/methods**: `snake_case`
- **Variables**: `snake_case`
- **Constants**: `SCREAMING_SNAKE_CASE` (including static variables)
- **Modules**: `snake_case`
- **Lifetimes**: Short, lowercase (e.g., `'a`, `'ctx`)

### Error Handling
- **User-space**: Use `anyhow::Result<T>` with `anyhow::Context` for adding context.
- **eBPF space**: Use `Result<T, ()>` for simple error propagation, or `Result<T, i32>` for LSM hooks.
- **Error conversion**: Use `?` operator where possible; match explicitly when needed.
- **Unwrap/expect**: Avoid `unwrap()`/`expect()` in production code; in eBPF code `unwrap()` acceptable for map operations known to succeed.

Example user-space:
```rust
program.attach(&iface, XdpFlags::default())
    .context("failed to attach XDP program")?;
```

Example eBPF:
```rust
match try_gaia_xdp(ctx) {
    Ok(ret) => ret,
    Err(_) => xdp_action::XDP_ABORTED,
}
```

### Unsafe Code
- **Minimize unsafe**: Keep unsafe blocks small.
- **`unsafe_op_in_unsafe_fn`**: Use `#[allow(unsafe_op_in_unsafe_fn)]` when defining unsafe functions with unsafe operations.
- **Pointer safety**: Use helper functions like `ptr_at` to validate bounds before dereferencing.

Example:
```rust
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}
```

### eBPF-Specific Guidelines
- **`#![no_std]` and `#![no_main]`**: Required for eBPF programs.
- **`#[xdp]` and `#[lsm]`**: Use Aya macros to define eBPF programs.
- **`#[map]`**: Define maps with descriptive names in `SCREAMING_SNAKE_CASE`.
- **`#[inline(always)]`**: Use for small helper functions in hot paths.
- **`#[panic_handler]`**: Define with `#[cfg(not(test))]` to avoid conflicts with test harness.
- **License section**: Keep `#[unsafe(link_section = "license")]` unchanged.

Example map:
```rust
#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);
```

Example program:
```rust
#[xdp]
pub fn gaia_xdp(ctx: XdpContext) -> u32 {
    match try_gaia_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}
```

### Logging
- **User-space**: Use `log` crate with `env_logger`.
- **eBPF space**: Use `aya_log_ebpf::info!` and other macros.
- **Conditional logging**: Consider rate-limiting to avoid flooding.

Example eBPF logging:
```rust
info!(&ctx, "SRC IP: {:i}, SRC PORT: {}, ACTION: {}", source_addr, source_port, action);
```

### WebUI

You should use pnpm as package manager for JavaScript. I want you to use react to build this WebUI.

## Cargo Runner Configuration

`.cargo/config.toml` sets `runner = "sudo -E"` for running the XDP program (requires elevated privileges).

---
*This file is intended for AI agents working on the gaia-xdp project. Update it as the project evolves.*
