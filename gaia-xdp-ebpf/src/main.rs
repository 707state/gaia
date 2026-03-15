#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, kretprobe, map, tracepoint, uprobe, uretprobe},
    maps::{Array, HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use gaia_xdp_common::{
    HotpatchPidEntry, KernelEvent, ProcessTreeEntry, RateLimitCounter, RateLimitEntry,
    ServicePidEntry, TrafficStats, EVENT_ACTION_ALERT, EVENT_ACTION_BIND, EVENT_ACTION_BLOCKED,
    EVENT_ACTION_ENTER, EVENT_ACTION_EXIT, EVENT_ACTION_KILL_REQUEST, EVENT_ACTION_RATE_LIMITED,
    EVENT_KIND_FILE_IO, EVENT_KIND_HOTPATCH, EVENT_KIND_NETWORK, EVENT_KIND_PRIVILEGE,
    EVENT_KIND_PROCESS, HOTPATCH_MODE_BLOCK, MAX_HOTPATCH_PIDS, MAX_PROCESS_TREE,
    MAX_RATE_LIMIT_COUNTERS, MAX_RATE_LIMIT_RULES, MAX_SERVICE_PIDS, MAX_TRAFFIC_STATS,
    PROTOCOL_TCP, RATE_ACTION_BLOCK,
};

// ── Tracepoint field offsets (ARM64 / x86_64 compatible via common ABI) ──
const OPENAT_FILENAME_OFFSET: usize = 24;
const EXIT_RET_OFFSET: usize = 16;
const EXECVE_FILENAME_OFFSET: usize = 16;
const SETID_VAL_OFFSET: usize = 16;
const SOCKADDR_PTR_OFFSET: usize = 24;
/// Offset of `pid` field in `sys_enter_execve` tracepoint args
const EXECVE_PID_OFFSET: usize = 8;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const ONE_SEC_NS: u64 = 1_000_000_000;

const SENSITIVE_PATHS: [&[u8]; 5] = [
    b"/etc/shadow",
    b"/etc/ssl",
    b"/root/.ssh",
    b"/var/lib/gaia",
    b"/etc/passwd",
];

// ── Kernel sockaddr structs ──

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct In6Addr {
    s6_addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: In6Addr,
    sin6_scope_id: u32,
}

// ── BPF Maps ──

/// Main event ring buffer for sending events to user space.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Blocked TCP/UDP ports. Key = port number (host byte order). Value = 1.
#[map]
static BLOCKED_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(128, 0);

/// Per-CPU scratch space for building events without stack overflow.
#[map]
static SCRATCH: Array<KernelEvent> = Array::with_max_entries(1, 0);

/// Rate limit rules: key = rule index (u32), value = RateLimitEntry.
#[map]
static RATE_LIMIT_RULES: HashMap<u32, RateLimitEntry> =
    HashMap::with_max_entries(MAX_RATE_LIMIT_RULES, 0);

/// Number of active rate limit rules (stored at index 0).
#[map]
static RATE_LIMIT_RULE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

/// Per-IP connection counters: key = IPv4 addr as u32.
#[map]
static RATE_LIMIT_COUNTERS: HashMap<u32, RateLimitCounter> =
    HashMap::with_max_entries(MAX_RATE_LIMIT_COUNTERS, 0);

/// Hotpatch PID filter: key = PID (u32), value = HotpatchPidEntry.
#[map]
static HOTPATCH_PIDS: HashMap<u32, HotpatchPidEntry> =
    HashMap::with_max_entries(MAX_HOTPATCH_PIDS, 0);

/// Process parent tracking: key = child PID (u32), value = ProcessTreeEntry.
#[map]
static PROCESS_TREE: HashMap<u32, ProcessTreeEntry> =
    HashMap::with_max_entries(MAX_PROCESS_TREE, 0);

/// Service PID filter: key = PID (u32), value = ServicePidEntry.
/// User-space syncs monitored service PIDs into this map so traffic probes
/// only count bytes for relevant processes.
#[map]
static SERVICE_PIDS: HashMap<u32, ServicePidEntry> = HashMap::with_max_entries(MAX_SERVICE_PIDS, 0);

/// Per-PID traffic statistics: key = PID (u32), value = TrafficStats.
/// Updated by kprobes on tcp_sendmsg / tcp_recvmsg.
#[map]
static TRAFFIC_STATS: HashMap<u32, TrafficStats> = HashMap::with_max_entries(MAX_TRAFFIC_STATS, 0);

// ── Helper functions ──

#[inline(always)]
fn get_scratch() -> Option<*mut KernelEvent> {
    SCRATCH.get_ptr_mut(0)
}

#[inline(always)]
fn fill_base(event: &mut KernelEvent, kind: u8, action: u8) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.pid = pid_tgid as u32;
    event.tgid = (pid_tgid >> 32) as u32;
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;
    event.kind = kind;
    event.action = action;
    event.protocol = 0;
    event.reserved = 0;
    event.port = 0;
    event.reserved2 = 0;
    event.addr = [0u8; 16];
    event.detail = [0u8; 128];
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    } else {
        event.comm = [0u8; 16];
    }
}

#[inline(always)]
fn emit(event: &KernelEvent) {
    let _ = EVENTS.output::<KernelEvent>(*event, 0);
}

fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    let mut i = 0;
    while i < dst.len() && i < src.len() {
        dst[i] = src[i];
        i += 1;
    }
}

fn is_sensitive_path(path: &[u8]) -> bool {
    let mut i = 0;
    while i < SENSITIVE_PATHS.len() {
        if starts_with(path, SENSITIVE_PATHS[i]) {
            return true;
        }
        i += 1;
    }
    false
}

fn starts_with(input: &[u8], prefix: &[u8]) -> bool {
    if prefix.len() > input.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        if input[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Check if an IPv4 address (as u32 in network byte order) matches a CIDR rule.
#[inline(always)]
fn ipv4_matches_cidr(addr: u32, network: &[u8; 16], prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 32 {
        return false;
    }
    // Build network u32 from first 4 bytes (network byte order)
    let net = u32::from_be_bytes([network[0], network[1], network[2], network[3]]);
    let addr_host = u32::from_be(addr);
    let net_host = u32::from_be(net);
    let mask = if prefix_len == 32 {
        0xFFFF_FFFFu32
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    (addr_host & mask) == (net_host & mask)
}

/// Check rate limit rules against an IPv4 address. Returns the action if rate exceeded.
#[inline(always)]
fn check_rate_limit_ipv4(addr: u32, now_ns: u64) -> Option<u8> {
    let count_ptr = RATE_LIMIT_RULE_COUNT.get_ptr(0)?;
    let rule_count = unsafe { *count_ptr };
    if rule_count == 0 {
        return None;
    }

    // Iterate rules (bounded to avoid verifier issues)
    let max = if rule_count > 16 { 16 } else { rule_count };
    let mut idx: u32 = 0;
    while idx < max {
        if let Some(rule) = unsafe { RATE_LIMIT_RULES.get(&idx) } {
            if rule.enabled != 0 && ipv4_matches_cidr(addr, &rule.network, rule.prefix_len) {
                // Check / update per-IP counter
                if let Some(counter) = unsafe { RATE_LIMIT_COUNTERS.get(&addr) } {
                    let elapsed = now_ns.saturating_sub(counter.last_reset_ns);
                    if elapsed >= ONE_SEC_NS {
                        // Window expired, reset
                        let new_counter = RateLimitCounter {
                            count: 1,
                            last_reset_ns: now_ns,
                            rule_idx: idx,
                        };
                        let _ = RATE_LIMIT_COUNTERS.insert(&addr, &new_counter, 0);
                    } else {
                        let new_count = counter.count + 1;
                        if new_count > rule.max_conn_per_sec {
                            return Some(rule.action);
                        }
                        let new_counter = RateLimitCounter {
                            count: new_count,
                            last_reset_ns: counter.last_reset_ns,
                            rule_idx: idx,
                        };
                        let _ = RATE_LIMIT_COUNTERS.insert(&addr, &new_counter, 0);
                    }
                } else {
                    // First connection from this IP
                    let new_counter = RateLimitCounter {
                        count: 1,
                        last_reset_ns: now_ns,
                        rule_idx: idx,
                    };
                    let _ = RATE_LIMIT_COUNTERS.insert(&addr, &new_counter, 0);
                }
                // Rule matched, stop checking further rules
                return None;
            }
        }
        idx += 1;
    }
    None
}

// ── File I/O Agent ──
//
// Hooks: sys_enter_openat, sys_exit_openat
// Role: Lightweight prefix matching on file paths; forward sensitive-path events to user space.

#[tracepoint]
pub fn tp_sys_enter_openat(ctx: TracePointContext) -> u32 {
    match handle_openat_enter(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn handle_openat_enter(ctx: TracePointContext) -> Result<(), i32> {
    let ptr = get_scratch().ok_or(1)?;
    let event = unsafe { &mut *ptr };
    fill_base(event, EVENT_KIND_FILE_IO, EVENT_ACTION_ENTER);

    let filename_ptr: u64 = unsafe { ctx.read_at(OPENAT_FILENAME_OFFSET) }.map_err(|_| 1)?;
    let bytes =
        unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.detail) }?;

    if is_sensitive_path(bytes) {
        event.action = EVENT_ACTION_ALERT;
    }

    emit(event);
    Ok(())
}

#[tracepoint]
pub fn tp_sys_exit_openat(ctx: TracePointContext) -> u32 {
    let Some(ptr) = get_scratch() else { return 0 };
    let event = unsafe { &mut *ptr };
    fill_base(event, EVENT_KIND_FILE_IO, EVENT_ACTION_EXIT);
    let ret: i64 = unsafe { ctx.read_at(EXIT_RET_OFFSET) }.unwrap_or_default();
    write_i64_detail(&mut event.detail, ret);
    emit(event);
    0
}

// ── Process & Privilege Agent ──
//
// Hooks: sys_enter_execve, sys_enter_setuid, sys_enter_setgid
// Role: Track process trees and detect unauthorized privilege escalations.

#[tracepoint]
pub fn tp_sys_enter_execve(ctx: TracePointContext) -> u32 {
    match handle_execve_enter(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn handle_execve_enter(ctx: TracePointContext) -> Result<(), i32> {
    let ptr = get_scratch().ok_or(1)?;
    let event = unsafe { &mut *ptr };
    fill_base(event, EVENT_KIND_PROCESS, EVENT_ACTION_ENTER);

    let filename_ptr: u64 = unsafe { ctx.read_at(EXECVE_FILENAME_OFFSET) }.map_err(|_| 1)?;
    let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.detail) }?;

    // Record process tree entry: map child PID -> (parent PID, uid, timestamp, comm)
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let pid = pid_tgid as u32;
    let ppid = (pid_tgid >> 32) as u32; // tgid used as ppid approximation in eBPF context
    let uid = uid_gid as u32;
    let tree_entry = ProcessTreeEntry {
        ppid,
        uid,
        timestamp_ns: event.timestamp_ns,
        comm: event.comm,
    };
    let _ = PROCESS_TREE.insert(&pid, &tree_entry, 0);

    emit(event);
    Ok(())
}

#[tracepoint]
pub fn tp_sys_enter_setuid(ctx: TracePointContext) -> u32 {
    handle_privilege_change(ctx, true)
}

#[tracepoint]
pub fn tp_sys_enter_setgid(ctx: TracePointContext) -> u32 {
    handle_privilege_change(ctx, false)
}

fn handle_privilege_change(ctx: TracePointContext, is_uid: bool) -> u32 {
    let Some(ptr) = get_scratch() else { return 0 };
    let event = unsafe { &mut *ptr };
    fill_base(event, EVENT_KIND_PRIVILEGE, EVENT_ACTION_ALERT);

    let val: u32 = unsafe { ctx.read_at(SETID_VAL_OFFSET) }.unwrap_or_default();

    if is_uid {
        copy_bytes(&mut event.detail, b"setuid:");
    } else {
        copy_bytes(&mut event.detail, b"setgid:");
    }
    let prefix_len = 7;
    let mut buf = [0u8; 10];
    let n = u32_to_ascii(val, &mut buf);
    let mut j = 0;
    while j < n && (prefix_len + j) < event.detail.len() {
        event.detail[prefix_len + j] = buf[j];
        j += 1;
    }

    // Alert if privilege escalation to root (uid/gid = 0)
    if val == 0 {
        let uid_gid = bpf_get_current_uid_gid();
        let current_uid = uid_gid as u32;
        if current_uid != 0 {
            // Non-root process attempting to set uid/gid to 0 — escalation attempt
            let marker = b"->ROOT";
            let start = prefix_len + n;
            let mut k = 0;
            while k < marker.len() && (start + k) < event.detail.len() {
                event.detail[start + k] = marker[k];
                k += 1;
            }
        }
    }

    emit(event);
    0
}

// ── Network Telemetry Agent (with rate limiting and port blocking) ──
//
// Hooks: sys_enter_connect, sys_enter_bind
// Role: Monitor outbound connections and port binding events.

#[tracepoint]
pub fn tp_sys_enter_connect(ctx: TracePointContext) -> u32 {
    match handle_connect_event(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn tp_sys_enter_bind(ctx: TracePointContext) -> u32 {
    match handle_bind_event(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn handle_connect_event(ctx: TracePointContext) -> Result<(), i32> {
    let sockaddr_ptr: u64 = unsafe { ctx.read_at(SOCKADDR_PTR_OFFSET) }.map_err(|_| 1)?;
    let family: u16 = unsafe { bpf_probe_read_user(sockaddr_ptr as *const u16) }.map_err(|_| 1)?;

    let ptr = get_scratch().ok_or(1)?;
    let event = unsafe { &mut *ptr };
    fill_base(event, EVENT_KIND_NETWORK, EVENT_ACTION_ENTER);
    event.protocol = PROTOCOL_TCP;

    if family == AF_INET {
        let sockaddr: SockAddrIn =
            unsafe { bpf_probe_read_user(sockaddr_ptr as *const SockAddrIn) }.map_err(|_| 1)?;
        event.port = u16::from_be(sockaddr.sin_port);
        let addr_bytes = sockaddr.sin_addr.to_ne_bytes();
        event.addr[0] = addr_bytes[0];
        event.addr[1] = addr_bytes[1];
        event.addr[2] = addr_bytes[2];
        event.addr[3] = addr_bytes[3];

        // Check rate limit for this IPv4 address
        let now_ns = unsafe { bpf_ktime_get_ns() };
        if let Some(action) = check_rate_limit_ipv4(sockaddr.sin_addr, now_ns) {
            if action == RATE_ACTION_BLOCK {
                event.action = EVENT_ACTION_BLOCKED;
                copy_bytes(&mut event.detail, b"rate-limit:blocked");
            } else {
                event.action = EVENT_ACTION_RATE_LIMITED;
                copy_bytes(&mut event.detail, b"rate-limit:exceeded");
            }
            emit(event);
            return Ok(());
        }
    } else if family == AF_INET6 {
        let sockaddr: SockAddrIn6 =
            unsafe { bpf_probe_read_user(sockaddr_ptr as *const SockAddrIn6) }.map_err(|_| 1)?;
        event.port = u16::from_be(sockaddr.sin6_port);
        event.addr = sockaddr.sin6_addr.s6_addr;
    } else {
        return Ok(());
    }

    // Check blocked ports
    if unsafe { BLOCKED_PORTS.get(&event.port).is_some() } {
        event.action = EVENT_ACTION_BLOCKED;
        copy_bytes(&mut event.detail, b"blocked-port");
    }

    emit(event);
    Ok(())
}

fn handle_bind_event(ctx: TracePointContext) -> Result<(), i32> {
    let sockaddr_ptr: u64 = unsafe { ctx.read_at(SOCKADDR_PTR_OFFSET) }.map_err(|_| 1)?;
    let family: u16 = unsafe { bpf_probe_read_user(sockaddr_ptr as *const u16) }.map_err(|_| 1)?;

    let ptr = get_scratch().ok_or(1)?;
    let event = unsafe { &mut *ptr };
    // Use distinct BIND action to differentiate from outbound connections
    fill_base(event, EVENT_KIND_NETWORK, EVENT_ACTION_BIND);
    event.protocol = PROTOCOL_TCP;

    if family == AF_INET {
        let sockaddr: SockAddrIn =
            unsafe { bpf_probe_read_user(sockaddr_ptr as *const SockAddrIn) }.map_err(|_| 1)?;
        event.port = u16::from_be(sockaddr.sin_port);
        let addr_bytes = sockaddr.sin_addr.to_ne_bytes();
        event.addr[0] = addr_bytes[0];
        event.addr[1] = addr_bytes[1];
        event.addr[2] = addr_bytes[2];
        event.addr[3] = addr_bytes[3];
    } else if family == AF_INET6 {
        let sockaddr: SockAddrIn6 =
            unsafe { bpf_probe_read_user(sockaddr_ptr as *const SockAddrIn6) }.map_err(|_| 1)?;
        event.port = u16::from_be(sockaddr.sin6_port);
        event.addr = sockaddr.sin6_addr.s6_addr;
    } else {
        return Ok(());
    }

    // Alert if binding to a known blocked port (unusual — service may be compromised)
    if unsafe { BLOCKED_PORTS.get(&event.port).is_some() } {
        event.action = EVENT_ACTION_ALERT;
        copy_bytes(&mut event.detail, b"bind:suspicious-port");
    } else {
        copy_bytes(&mut event.detail, b"bind");
    }

    emit(event);
    Ok(())
}

// ── Hot-patching Agent (Active Defense) ──
//
// Hooks: kprobe / kretprobe on kernel functions, uprobe / uretprobe on user binaries.
// Role: Validate arguments and force error returns via bpf_override_return to neutralize exploits.

/// kprobe guard on tcp_connect — monitors kernel-level TCP connection attempts.
///
/// When HOTPATCH_MODE_BLOCK is set for the calling PID the probe emits a
/// KILL_REQUEST event so that the user-space controller can send SIGKILL.
///
/// NOTE: `bpf_override_return` cannot be used here because `tcp_connect` is not
/// annotated with `ALLOW_ERROR_INJECTION` in the kernel, and the BPF verifier
/// rejects programs that call that helper on non-injectable functions:
///   "program of this type cannot use helper bpf_override_return"
/// The user-space SIGKILL path achieves equivalent protection.
#[kprobe]
pub fn kprobe_hotpatch_guard(_ctx: ProbeContext) -> u32 {
    let Some(ptr) = get_scratch() else { return 0 };
    let event = unsafe { &mut *ptr };
    fill_base(event, EVENT_KIND_HOTPATCH, EVENT_ACTION_ALERT);
    copy_bytes(&mut event.detail, b"kprobe:tcp_connect");

    // Check if this PID is in the hotpatch filter in BLOCK mode
    let pid = event.pid;
    if let Some(entry) = unsafe { HOTPATCH_PIDS.get(&pid) } {
        if entry.active != 0 && entry.mode == HOTPATCH_MODE_BLOCK {
            // Cannot call bpf_override_return: tcp_connect has no ALLOW_ERROR_INJECTION
            // annotation, so the BPF verifier rejects it at load time.
            // Instead emit KILL_REQUEST so user-space can send SIGKILL to the process.
            event.action = EVENT_ACTION_KILL_REQUEST;
            copy_bytes(&mut event.detail, b"kprobe:tcp_connect:KILL_REQUEST");
        }
    }

    emit(event);
    0
}

/// kretprobe on tcp_connect — captures the return value for post-analysis.
#[kretprobe]
pub fn kretprobe_hotpatch_guard(ctx: RetProbeContext) -> u32 {
    let Some(ptr) = get_scratch() else { return 0 };
    let event = unsafe { &mut *ptr };
    fill_base(event, EVENT_KIND_HOTPATCH, EVENT_ACTION_EXIT);

    // Read the (possibly overridden) return value
    let retval: i64 = ctx.ret();
    write_i64_detail(&mut event.detail, retval);

    // Prefix detail with "kretprobe:tcp_connect:ret="
    let prefix = b"kretprobe:tcp_connect:ret=";
    let mut tmp = [0u8; 128];
    copy_bytes(&mut tmp, prefix);
    let prefix_len = prefix.len();
    let mut i = 0;
    while i < event.detail.len() && (prefix_len + i) < tmp.len() {
        tmp[prefix_len + i] = event.detail[i];
        if event.detail[i] == 0 {
            break;
        }
        i += 1;
    }
    event.detail = tmp;

    emit(event);
    0
}

/// uprobe entry point — fires when the target user-space function is entered.
/// Filters by PID and logs / blocks as configured.
#[uprobe]
pub fn uprobe_hotpatch_entry(_ctx: ProbeContext) -> u32 {
    let Some(ptr) = get_scratch() else { return 0 };
    let event = unsafe { &mut *ptr };
    fill_base(event, EVENT_KIND_HOTPATCH, EVENT_ACTION_ENTER);

    // Check if this PID is in the hotpatch filter
    let pid = event.pid;
    if let Some(entry) = unsafe { HOTPATCH_PIDS.get(&pid) } {
        if entry.active != 0 {
            copy_bytes(&mut event.detail, b"uprobe-entry:pid-filtered");
            event.action = EVENT_ACTION_BLOCKED;
            emit(event);
            return 0;
        }
    }

    copy_bytes(&mut event.detail, b"uprobe-entry");
    emit(event);
    0
}

/// uretprobe exit point — fires when the target user-space function returns.
#[uretprobe]
pub fn uretprobe_hotpatch_exit(ctx: RetProbeContext) -> u32 {
    let Some(ptr) = get_scratch() else { return 0 };
    let event = unsafe { &mut *ptr };
    fill_base(event, EVENT_KIND_HOTPATCH, EVENT_ACTION_EXIT);

    let pid = event.pid;
    if let Some(entry) = unsafe { HOTPATCH_PIDS.get(&pid) } {
        if entry.active != 0 {
            // Capture the return value for analysis
            let retval: i64 = ctx.ret();
            copy_bytes(&mut event.detail, b"uretprobe-exit:ret=");
            let mut tmp_buf = [0u8; 21];
            let n = u64_to_ascii(retval.unsigned_abs(), &mut tmp_buf);
            let prefix_len = 19; // len("uretprobe-exit:ret=")
            let mut k = 0;
            while k < n && (prefix_len + k) < event.detail.len() {
                event.detail[prefix_len + k] = tmp_buf[k];
                k += 1;
            }
            emit(event);
            return 0;
        }
    }

    copy_bytes(&mut event.detail, b"uretprobe-exit");
    emit(event);
    0
}

// ── Traffic Monitoring Agent ──
//
// Hooks: kprobe on tcp_sendmsg, kretprobe on tcp_recvmsg
// Role: Count bytes sent/received per TGID for ALL processes system-wide.
// User-space aggregates by service using the service_map.

/// kprobe on tcp_sendmsg — counts outbound bytes for ALL processes.
///
/// Prototype: int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
/// The `size` argument (3rd parameter) gives us the byte count.
#[kprobe]
pub fn kprobe_tcp_sendmsg(ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    // 3rd argument = size (bytes to send). Read as usize to match kernel size_t.
    let size: u64 = match ctx.arg::<usize>(2) {
        Some(s) => s as u64,
        None => return 0,
    };
    // Sanity check: single sendmsg should not exceed 64MB
    if size > 64 * 1024 * 1024 {
        return 0;
    }

    if let Some(stats) = unsafe { TRAFFIC_STATS.get(&tgid) } {
        let updated = TrafficStats {
            bytes_sent: stats.bytes_sent + size,
            bytes_recv: stats.bytes_recv,
            packets_sent: stats.packets_sent + 1,
            packets_recv: stats.packets_recv,
        };
        let _ = TRAFFIC_STATS.insert(&tgid, &updated, 0);
    } else {
        let new_stats = TrafficStats {
            bytes_sent: size,
            bytes_recv: 0,
            packets_sent: 1,
            packets_recv: 0,
        };
        let _ = TRAFFIC_STATS.insert(&tgid, &new_stats, 0);
    }
    0
}

/// kprobe on tcp_recvmsg — no-op, actual counting done in kretprobe.
#[kprobe]
pub fn kprobe_tcp_recvmsg(_ctx: ProbeContext) -> u32 {
    0
}

/// kretprobe on tcp_recvmsg — captures actual bytes received from return value.
/// Return value > 0 = number of bytes actually received.
#[kretprobe]
pub fn kretprobe_tcp_recvmsg(ctx: RetProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    let ret: i64 = ctx.ret();
    // tcp_recvmsg returns int (32-bit); mask to 32 bits to avoid aarch64 sign-extension issues
    let ret32 = ret as i32;
    if ret32 <= 0 {
        return 0;
    }
    let bytes = ret32 as u64;

    if let Some(stats) = unsafe { TRAFFIC_STATS.get(&tgid) } {
        let updated = TrafficStats {
            bytes_sent: stats.bytes_sent,
            bytes_recv: stats.bytes_recv + bytes,
            packets_sent: stats.packets_sent,
            packets_recv: stats.packets_recv + 1,
        };
        let _ = TRAFFIC_STATS.insert(&tgid, &updated, 0);
    } else {
        let new_stats = TrafficStats {
            bytes_sent: 0,
            bytes_recv: bytes,
            packets_sent: 0,
            packets_recv: 1,
        };
        let _ = TRAFFIC_STATS.insert(&tgid, &new_stats, 0);
    }
    0
}

// ── Numeric formatting helpers ──

fn u32_to_ascii(mut val: u32, out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    if val == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut rev = [0u8; 10];
    let mut len = 0;
    while val > 0 && len < rev.len() {
        rev[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }
    let mut i = 0;
    while i < len && i < out.len() {
        out[i] = rev[len - 1 - i];
        i += 1;
    }
    i
}

fn write_i64_detail(dst: &mut [u8], val: i64) {
    if dst.is_empty() {
        return;
    }
    let mut buf = [0u8; 21];
    let start;
    let abs_val;
    if val < 0 {
        buf[0] = b'-';
        abs_val = val.unsigned_abs();
        start = 1;
    } else {
        abs_val = val as u64;
        start = 0;
    }
    let n = u64_to_ascii(abs_val, &mut buf[start..]);
    copy_bytes(dst, &buf[..start + n]);
}

fn u64_to_ascii(mut val: u64, out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    if val == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut rev = [0u8; 20];
    let mut len = 0;
    while val > 0 && len < rev.len() {
        rev[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }
    let mut i = 0;
    while i < len && i < out.len() {
        out[i] = rev[len - 1 - i];
        i += 1;
    }
    i
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
