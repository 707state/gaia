#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, map, tracepoint, uprobe, uretprobe},
    maps::{Array, HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use gaia_xdp_common::{
    KernelEvent, EVENT_ACTION_ALERT, EVENT_ACTION_BLOCKED, EVENT_ACTION_ENTER, EVENT_ACTION_EXIT,
    EVENT_KIND_FILE_IO, EVENT_KIND_HOTPATCH, EVENT_KIND_NETWORK, EVENT_KIND_PRIVILEGE,
    EVENT_KIND_PROCESS, PROTOCOL_TCP,
};

// ── Tracepoint field offsets (from /sys/kernel/debug/tracing/events/...) ──
// openat: dfd@16, filename@24, flags@32, mode@40
const OPENAT_FILENAME_OFFSET: usize = 24;
// exit_openat: ret@16
const EXIT_RET_OFFSET: usize = 16;
// execve: filename@16
const EXECVE_FILENAME_OFFSET: usize = 16;
// setuid: uid@16 ; setgid: gid@16
const SETID_VAL_OFFSET: usize = 16;
// connect: fd@16, uservaddr@24, addrlen@32
// bind:    fd@16, umyaddr@24,   addrlen@32
const SOCKADDR_PTR_OFFSET: usize = 24;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const SENSITIVE_PATHS: [&[u8]; 4] = [b"/etc/shadow", b"/etc/ssl", b"/root/.ssh", b"/var/lib/gaia"];

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

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static BLOCKED_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(128, 0);

/// Scratch space for building KernelEvent without blowing the 512-byte BPF stack.
#[map]
static SCRATCH: Array<KernelEvent> = Array::with_max_entries(1, 0);

// ── helpers ──

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
        let prefix = SENSITIVE_PATHS[i];
        if starts_with(path, prefix) {
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

// ── File I/O Agent ──

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
    let prefix_len = 7; // "setuid:" or "setgid:"
    let mut buf = [0u8; 10];
    let n = u32_to_ascii(val, &mut buf);
    let mut j = 0;
    while j < n && (prefix_len + j) < event.detail.len() {
        event.detail[prefix_len + j] = buf[j];
        j += 1;
    }

    emit(event);
    0
}

// ── Network Telemetry Agent ──

#[tracepoint]
pub fn tp_sys_enter_connect(ctx: TracePointContext) -> u32 {
    match handle_network_event(ctx, EVENT_ACTION_ENTER) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn tp_sys_enter_bind(ctx: TracePointContext) -> u32 {
    match handle_network_event(ctx, EVENT_ACTION_EXIT) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn handle_network_event(ctx: TracePointContext, default_action: u8) -> Result<(), i32> {
    let sockaddr_ptr: u64 = unsafe { ctx.read_at(SOCKADDR_PTR_OFFSET) }.map_err(|_| 1)?;
    let family: u16 = unsafe { bpf_probe_read_user(sockaddr_ptr as *const u16) }.map_err(|_| 1)?;

    let ptr = get_scratch().ok_or(1)?;
    let event = unsafe { &mut *ptr };
    fill_base(event, EVENT_KIND_NETWORK, default_action);
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

    if unsafe { BLOCKED_PORTS.get(&event.port).is_some() } {
        event.action = EVENT_ACTION_BLOCKED;
    }

    emit(event);
    Ok(())
}

// ── Hot-patching Agent ──

#[kprobe]
pub fn kprobe_hotpatch_guard(ctx: ProbeContext) -> u32 {
    let Some(ptr) = get_scratch() else { return 0 };
    let event = unsafe { &mut *ptr };
    fill_base(event, EVENT_KIND_HOTPATCH, EVENT_ACTION_ALERT);
    copy_bytes(&mut event.detail, b"kprobe:tcp_connect");
    emit(event);
    let _ = ctx;
    0
}

#[uprobe]
pub fn uprobe_hotpatch_entry(_ctx: ProbeContext) -> u32 {
    let Some(ptr) = get_scratch() else { return 0 };
    let event = unsafe { &mut *ptr };
    fill_base(event, EVENT_KIND_HOTPATCH, EVENT_ACTION_ENTER);
    copy_bytes(&mut event.detail, b"uprobe-entry");
    emit(event);
    0
}

#[uretprobe]
pub fn uretprobe_hotpatch_exit(_ctx: RetProbeContext) -> u32 {
    let Some(ptr) = get_scratch() else { return 0 };
    let event = unsafe { &mut *ptr };
    fill_base(event, EVENT_KIND_HOTPATCH, EVENT_ACTION_EXIT);
    copy_bytes(&mut event.detail, b"uretprobe-exit");
    emit(event);
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
