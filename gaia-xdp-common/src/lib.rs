#![no_std]

pub const DETAIL_LEN: usize = 128;
pub const COMM_LEN: usize = 16;
pub const ADDR_LEN: usize = 16;

// ── Event kinds ──

pub const EVENT_KIND_FILE_IO: u8 = 1;
pub const EVENT_KIND_PROCESS: u8 = 2;
pub const EVENT_KIND_PRIVILEGE: u8 = 3;
pub const EVENT_KIND_NETWORK: u8 = 4;
pub const EVENT_KIND_HOTPATCH: u8 = 5;

// ── Event actions ──

pub const EVENT_ACTION_ENTER: u8 = 1;
pub const EVENT_ACTION_EXIT: u8 = 2;
pub const EVENT_ACTION_ALERT: u8 = 3;
pub const EVENT_ACTION_BLOCKED: u8 = 4;
pub const EVENT_ACTION_RATE_LIMITED: u8 = 5;
/// Bind syscall — process started listening on a port
pub const EVENT_ACTION_BIND: u8 = 6;
/// Process exited / killed by the user-space controller
pub const EVENT_ACTION_KILL: u8 = 7;
/// eBPF probe detected a hotpatch target in BLOCK mode and requests user-space to kill the PID.
/// bpf_override_return is NOT used because tcp_connect lacks ALLOW_ERROR_INJECTION; instead the
/// kprobe emits this action and the user-space controller sends SIGKILL.
pub const EVENT_ACTION_KILL_REQUEST: u8 = 8;
/// Kept for ABI compatibility — previously used for bpf_override_return, now superseded by
/// KILL_REQUEST. User-space will never see this value from the kernel probe.
pub const EVENT_ACTION_OVERRIDE: u8 = 8;

// ── Network protocols ──

pub const PROTOCOL_UNKNOWN: u8 = 0;
pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;

// ── Rate limit actions ──

pub const RATE_ACTION_LOG: u8 = 0;
pub const RATE_ACTION_BLOCK: u8 = 1;
pub const RATE_ACTION_THROTTLE: u8 = 2;

// ── Map capacity limits ──

pub const MAX_RATE_LIMIT_RULES: u32 = 64;
pub const MAX_RATE_LIMIT_COUNTERS: u32 = 65536;
pub const MAX_HOTPATCH_PIDS: u32 = 256;
/// Maximum entries in the process parent map (PID → PPID)
pub const MAX_PROCESS_TREE: u32 = 4096;

// ── Traffic monitoring ──

/// Maximum tracked service PIDs (synced from user-space)
pub const MAX_SERVICE_PIDS: u32 = 1024;
/// Maximum per-PID traffic stats entries
pub const MAX_TRAFFIC_STATS: u32 = 65536;

// ── Hotpatch guard modes ──

/// kprobe guard: only log / alert, do not override return
pub const HOTPATCH_MODE_MONITOR: u8 = 0;
/// kprobe guard: override return value with EPERM (-1) via bpf_override_return
pub const HOTPATCH_MODE_BLOCK: u8 = 1;

/// A CIDR-based rate limit rule stored in BPF HashMap.
/// Key: rule index (u32). Value: this struct.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RateLimitEntry {
    /// Network address in network byte order (IPv4 in first 4 bytes)
    pub network: [u8; 16],
    /// CIDR prefix length (e.g. 24 for /24)
    pub prefix_len: u8,
    /// Action: RATE_ACTION_LOG / RATE_ACTION_BLOCK / RATE_ACTION_THROTTLE
    pub action: u8,
    /// Whether this rule is enabled
    pub enabled: u8,
    pub _pad: u8,
    /// Max connections per second
    pub max_conn_per_sec: u32,
}

/// Per-IP connection counter for rate limiting.
/// Key: IPv4 addr as u32. Value: this struct.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RateLimitCounter {
    pub count: u32,
    pub last_reset_ns: u64,
    /// Which rule index matched (for reporting)
    pub rule_idx: u32,
}

/// Hotpatch PID filter entry.
/// Key: PID (u32). Value: this struct.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HotpatchPidEntry {
    /// 1 = active, 0 = inactive
    pub active: u8,
    /// Guard mode: HOTPATCH_MODE_MONITOR or HOTPATCH_MODE_BLOCK
    pub mode: u8,
    pub _pad: [u8; 2],
}

/// Process parent entry for process-tree tracking.
/// Key: child PID (u32). Value: this struct.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessTreeEntry {
    /// Parent PID
    pub ppid: u32,
    /// Creator UID at the time of execve
    pub uid: u32,
    /// Timestamp of the execve event (ns)
    pub timestamp_ns: u64,
    /// Executable name (first COMM_LEN bytes)
    pub comm: [u8; COMM_LEN],
}

/// Service PID marker — stored in SERVICE_PIDS BPF map.
/// Key: PID (u32). Value: this struct.
/// User-space syncs monitored service PIDs into this map so that
/// eBPF traffic probes can filter only relevant processes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServicePidEntry {
    /// 1 = active, 0 = inactive
    pub active: u8,
    pub _pad: [u8; 3],
    /// Service index (maps back to user-space service list for aggregation)
    pub service_idx: u32,
}

/// Per-PID traffic statistics accumulated by eBPF kprobes on tcp_sendmsg / tcp_recvmsg.
/// Key: PID (u32). Value: this struct.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrafficStats {
    /// Total bytes sent (outbound)
    pub bytes_sent: u64,
    /// Total bytes received (inbound)
    pub bytes_recv: u64,
    /// Total packets/calls sent
    pub packets_sent: u64,
    /// Total packets/calls received
    pub packets_recv: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub kind: u8,
    pub action: u8,
    pub protocol: u8,
    pub reserved: u8,
    pub port: u16,
    pub reserved2: u16,
    pub addr: [u8; ADDR_LEN],
    pub comm: [u8; COMM_LEN],
    pub detail: [u8; DETAIL_LEN],
}

impl KernelEvent {
    pub const fn empty() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            tgid: 0,
            uid: 0,
            gid: 0,
            kind: 0,
            action: 0,
            protocol: 0,
            reserved: 0,
            port: 0,
            reserved2: 0,
            addr: [0; ADDR_LEN],
            comm: [0; COMM_LEN],
            detail: [0; DETAIL_LEN],
        }
    }
}

#[cfg(feature = "user")]
mod pod_impls {
    use super::*;
    unsafe impl aya::Pod for RateLimitEntry {}
    unsafe impl aya::Pod for RateLimitCounter {}
    unsafe impl aya::Pod for HotpatchPidEntry {}
    unsafe impl aya::Pod for KernelEvent {}
    unsafe impl aya::Pod for ProcessTreeEntry {}
    unsafe impl aya::Pod for ServicePidEntry {}
    unsafe impl aya::Pod for TrafficStats {}
}
