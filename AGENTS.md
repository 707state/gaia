# Monitoring Agents Architecture (监控代理架构说明)

[English](#english) | [中文](#chinese)

---

<h2 id="english">English</h2>

### 🤖 Agents Overview
In this project, "Agents" refer to the distributed eBPF probes running in the Linux kernel and the centralized user-space daemon that manages them. Together, they form a closed-loop system for data collection, analysis, and active mitigation.

### 🔬 Kernel-Space Agents (eBPF Probes)
These agents operate in the kernel space with near-zero performance overhead, utilizing BPF Ring Buffers and Per-CPU Maps for data sharing.

1. **File I/O Agent**
   - **Hooks**: `tracepoint/syscalls/sys_enter_openat`, `sys_exit_openat`.
   - **Role**: Performs lightweight prefix matching on file paths. Forwards access events of sensitive targets to user space.
2. **Process & Privilege Agent**
   - **Hooks**: `tracepoint/syscalls/sys_enter_execve`, `setuid`, `setgid`.
   - **Role**: Tracks process trees and detects unauthorized privilege escalations.
3. **Network Telemetry Agent**
   - **Hooks**: `tracepoint/syscalls/sys_enter_connect`, `bind`.
   - **Role**: Monitors outbound connections and port binding events of tracked systemd services.
4. **Hot-patching Agent (Active Defense)**
   - **Hooks**: `kprobe`, `kretprobe`, `uprobe`, `uretprobe`.
   - **Role**: Deployed dynamically to vulnerable functions. Validates arguments or forces error returns (via `bpf_override_return`) to neutralize exploits at runtime.

### 🧠 User-Space Agent (Controller)
The user-space agent is a high-performance Rust daemon that acts as the brain of the system.

- **Event Collector**: Uses `Tokio` async runtime to read high-throughput event streams from BPF Ring Buffers without blocking.
- **Systemd Tracker**: Listens to systemd DBus events to maintain a dynamic mapping of `Service Name -> PID List`, automatically attaching eBPF probes to new worker processes.
- **Anomaly Detection Engine**: 
  - *Whitelist Rules*: Verifies behaviors against predefined YAML/TOML profiles.
  - *Statistical Baselines*: Detects abnormal spikes in syscall frequencies.
- **Symbol Resolver**: Dynamically parses ELF/DWARF formats (`.symtab`/`.dynsym`) and `/proc/[pid]/maps` to calculate absolute memory addresses for `uprobe` attachments, bypassing ASLR limitations.

---

<h2 id="chinese">中文</h2>

### 🤖 代理（探针）架构总览
在本项目中，“Agent（代理）”指的是运行在 Linux 内核态的分布式 eBPF 探针，以及管理这些探针的用户态守护进程。它们共同组成了一个具备数据采集、分析和主动防御能力的闭环系统。

### 🔬 内核态代理 (eBPF 探针)
这些代理在内核态运行，性能损耗极低，主要通过 BPF 环形缓冲区（Ring Buffer）和 Per-CPU 映射表（Map）与用户态进行数据交互。

1. **文件 I/O 监控代理**
   - **挂载点**：`tracepoint/syscalls/sys_enter_openat` 及 `sys_exit_openat`。
   - **职责**：在内核态进行轻量级的路径前缀匹配，仅将对敏感目标的访问事件上报至用户态，过滤无效噪音。
2. **进程与权限监控代理**
   - **挂载点**：`tracepoint/syscalls/sys_enter_execve`、`setuid`、`setgid`。
   - **职责**：追踪进程树的生命周期，检测未经授权的特权提升行为。
3. **网络遥测代理**
   - **挂载点**：`tracepoint/syscalls/sys_enter_connect`、`bind`。
   - **职责**：监控被托管关键服务的外连请求与端口监听变更事件。
4. **热补丁代理 (主动防御)**
   - **挂载点**：`kprobe`、`kretprobe`、`uprobe`、`uretprobe`。
   - **职责**：针对高危漏洞函数动态下发。在函数入口校验参数，或通过 `bpf_override_return` 强制返回错误码，从而在运行时阻断漏洞利用。

### 🧠 用户态代理 (控制中心)
用户态代理是一个基于 Rust 构建的高性能守护进程，作为整个系统的“大脑”。

- **异步事件收集器**：利用 `Tokio` 异步运行时，从 BPF 环形缓冲区中非阻塞、零拷贝地批量读取高吞吐事件流。
- **Systemd 追踪器**：监听 systemd 的 DBus 事件，动态维护“服务名 -> PID 列表”的映射表，实现监控探针的自适应挂载。
- **异常检测引擎**：
  - *白名单规则*：基于 YAML/TOML 配置文件，对进程行为进行合规性校验。
  - *统计基线*：对系统调用频率等数值型指标建立动态基线，检测异常峰值。
- **动态符号解析器**：实时解析目标二进制文件的 ELF 符号表（`.symtab`/`.dynsym`）和 `/proc/[pid]/maps`，计算出函数在运行时的绝对内存地址，从而克服 ASLR（地址空间布局随机化）限制，精准挂载 `uprobe`。
