# openEuler Key Service Monitor (基于Rust的openEuler关键服务监控工具)

[English](#english) | [中文](#chinese)

---

<h2 id="english">English</h2>

### 📖 Introduction
This project is a lightweight, high-security, and low-overhead monitoring and active defense tool tailored for key services on the **openEuler** operating system. Built with **Rust** and **eBPF** (via the [Aya](https://aya-rs.dev/) framework), it provides deep observability and runtime protection without requiring kernel modifications or service restarts.

### ✨ Core Features

#### 1. Fine-grained Security Monitoring
- **File System Access**: Tracks read, write, execution, and attribute modifications of sensitive files (e.g., `/etc/shadow`, SSL certificates).
- **Process Lifecycle**: Monitors process creation (`execve`), exits, and privilege escalation (`setuid`/`setgid`) to detect malicious injections.
- **Network Activities**: Captures TCP/UDP connections and listening port changes to identify reverse shells or C2 communications.
- **Syscall Anomaly Detection**: Analyzes syscall sequences to detect deviations from normal behavior baselines.

#### 2. Runtime Hot-patching (Active Defense)
- **Kernel-space Mitigation**: Intercepts vulnerable kernel functions using eBPF to validate parameters or modify return values (e.g., `bpf_override_return`).
- **User-space Mitigation**: Utilizes `uprobe` to filter parameters or block malicious behaviors in key services (like Nginx or OpenSSH) without modifying binaries.

#### 3. openEuler Deep Adaptation
- **BPF CO-RE**: "Compile Once, Run Everywhere" support for various openEuler kernel versions (5.10+).
- **Systemd Integration**: Discovers and tracks service PIDs dynamically via systemd DBus interfaces.
- **ARM64 Optimization**: Fully compatible and optimized for ARM64 architectures (e.g., Kunpeng processors).

### 🛠️ Architecture
- **Kernel Space**: Pure Rust eBPF probes compiled into BTF-aware objects.
- **User Space**: A Rust-based asynchronous controller (powered by Tokio) for event collection, rule-based anomaly detection, and alerting.
- **Deployment**: Single statically linked binary with zero external dependencies.

---

<h2 id="chinese">中文</h2>

### 📖 项目简介
本项目是一个专为 **openEuler** 操作系统量身定制的轻量级、高安全、低开销的关键服务监控与主动防御工具。项目采用 **Rust** 语言与 **eBPF** 技术（基于 [Aya](https://aya-rs.dev/) 框架）深度结合的开发范式，无需修改内核或重启服务即可提供深度的系统可观测性与运行时保护。

### ✨ 核心功能

#### 1. 关键服务细粒度安全监控
- **文件系统访问**：捕获对敏感文件（如 `/etc/shadow`、SSL证书）的读写、执行及属性修改操作。
- **进程生命周期**：监控进程创建（`execve`）、退出及特权提升（`setuid`/`setgid`），检测非法注入与提权。
- **网络活动**：监控TCP/UDP连接建立与监听端口变更，识别反向Shell或恶意C2外连。
- **系统调用异常检测**：统计分析系统调用序列，识别偏离正常基线的异常行为模式。

#### 2. 高危函数运行时热补丁（主动防御）
- **内核态热补丁**：针对内核高危函数，通过eBPF在出入口进行参数校验或执行流劫持（如 `bpf_override_return`）。
- **用户态热补丁**：利用 `uprobe` 技术，在不修改二进制文件的前提下，对关键服务（如Nginx、OpenSSH）的高危函数进行行为阻断或返回值篡改。

#### 3. openEuler 平台深度适配
- **BPF CO-RE 支持**：实现“一次编译，到处运行”，完美适配 openEuler 5.10 及以上内核。
- **Systemd 深度集成**：通过 DBus 接口动态感知服务状态，自动完成监控目标的发现与进程关联。
- **ARM64 架构优化**：在基于鲲鹏等 ARM64 架构的 openEuler 环境中经过深度优化与验证。

### 🛠️ 系统架构
- **内核态**：纯 Rust 编写的 eBPF 探针程序，利用 CO-RE 技术实现跨版本兼容。
- **用户态**：基于 Tokio 异步运行时构建的事件收集、解析、聚合与告警引擎。
- **极简部署**：编译为单一静态链接的二进制文件，实现“零依赖”极简部署。
