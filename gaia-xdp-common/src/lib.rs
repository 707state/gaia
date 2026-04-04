#![no_std]

pub const DETAIL_LEN: usize = 128;
pub const COMM_LEN: usize = 16;
pub const ADDR_LEN: usize = 16;

pub const EVENT_KIND_FILE_IO: u8 = 1;
pub const EVENT_KIND_PROCESS: u8 = 2;
pub const EVENT_KIND_PRIVILEGE: u8 = 3;
pub const EVENT_KIND_NETWORK: u8 = 4;
pub const EVENT_KIND_HOTPATCH: u8 = 5;

pub const EVENT_ACTION_ENTER: u8 = 1;
pub const EVENT_ACTION_EXIT: u8 = 2;
pub const EVENT_ACTION_ALERT: u8 = 3;
pub const EVENT_ACTION_BLOCKED: u8 = 4;
pub const EVENT_ACTION_RATE_LIMITED: u8 = 5;

pub const PROTOCOL_UNKNOWN: u8 = 0;
pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;

pub const RATE_ACTION_LOG: u8 = 0;
pub const RATE_ACTION_BLOCK: u8 = 1;
pub const RATE_ACTION_THROTTLE: u8 = 2;

pub const MAX_RATE_LIMIT_RULES: u32 = 64;
pub const MAX_RATE_LIMIT_COUNTERS: u32 = 65536;
pub const MAX_HOTPATCH_PIDS: u32 = 256;
pub const MAX_HOTPATCH_RULES: u32 = 64;

/// Hotpatch actions: what the uprobe should do when the target function is entered.
pub const HOTPATCH_ACTION_MONITOR: u8 = 0;
pub const HOTPATCH_ACTION_OVERRIDE_RETURN: u8 = 1;
pub const HOTPATCH_ACTION_SKIP_CALL: u8 = 2;
pub const HOTPATCH_ACTION_REPLACE_FUNCTION: u8 = 3;

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
    pub _pad: [u8; 3],
}

/// Hotpatch rule entry stored in HOTPATCH_RULES BPF HashMap.
/// Key: rule index (u32). Value: this struct.
///
/// Each rule corresponds to one HotpatchTarget and tells the eBPF uprobe
/// what action to take when the target function is entered.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HotpatchRuleEntry {
    /// HOTPATCH_ACTION_MONITOR / HOTPATCH_ACTION_OVERRIDE_RETURN / HOTPATCH_ACTION_SKIP_CALL
    pub action: u8,
    /// Whether this rule is enabled (1 = yes, 0 = no)
    pub enabled: u8,
    pub _pad: [u8; 2],
    /// The return value to force when action == OVERRIDE_RETURN or SKIP_CALL.
    /// Interpreted as a signed i64 (e.g. -1 for EPERM, -22 for EINVAL).
    pub override_return_value: i64,
    /// Target PID filter: 0 means match all PIDs.
    pub target_pid: u32,
    pub _pad2: [u8; 4],
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
    unsafe impl aya::Pod for HotpatchRuleEntry {}
    unsafe impl aya::Pod for KernelEvent {}
}
