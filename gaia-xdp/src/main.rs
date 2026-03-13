use std::{
    collections::{HashMap, VecDeque},
    fs,
    mem::size_of,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, Method, header},
    routing::get,
};
use aya::{
    Ebpf,
    maps::{Array as BpfArray, HashMap as BpfHashMap, MapData, ring_buf::RingBuf},
    programs::{KProbe, TracePoint, UProbe},
};
use clap::Parser;
use gaia_xdp_common::{
    EVENT_ACTION_ALERT, EVENT_ACTION_BLOCKED, EVENT_ACTION_RATE_LIMITED,
    EVENT_KIND_FILE_IO, EVENT_KIND_HOTPATCH, EVENT_KIND_NETWORK, EVENT_KIND_PRIVILEGE,
    EVENT_KIND_PROCESS, HotpatchPidEntry, KernelEvent, RateLimitEntry,
};
use log::{info, warn};
use object::{Object, ObjectSymbol};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{Interest, unix::AsyncFd},
    net::TcpListener,
    process::Command,
    signal,
    sync::RwLock,
};
use tower_http::cors::CorsLayer;

const DEFAULT_CONFIG: &str = "gaia.toml";
const MAX_EVENT_HISTORY: usize = 512;
const MAX_ALERT_HISTORY: usize = 256;
const BASELINE_WINDOW_SECS: u64 = 30;

// ── CLI ──

#[derive(Debug, Parser)]
struct Opt {
    #[arg(long, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    #[arg(long, default_value = "0.0.0.0:17890")]
    web_listen: String,
}

// ── Policy config (YAML / TOML) ──

#[derive(Debug, Clone, Deserialize, Serialize)]
struct MonitorPolicy {
    #[serde(default)]
    sensitive_prefixes: Vec<String>,
    #[serde(default)]
    monitored_services: Vec<String>,
    #[serde(default)]
    exec_whitelist_prefixes: Vec<String>,
    #[serde(default)]
    blocked_ports: Vec<u16>,
    #[serde(default)]
    baseline_thresholds: HashMap<String, u32>,
    #[serde(default)]
    hotpatch: HotpatchPolicy,
    #[serde(default)]
    rate_limit_rules: Vec<RateLimitRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct HotpatchPolicy {
    #[serde(default)]
    targets: Vec<HotpatchTarget>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct HotpatchTarget {
    binary: String,
    symbol: String,
    #[serde(default)]
    pid: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RateLimitRule {
    cidr: String,
    max_conn_per_sec: u32,
    #[serde(default)]
    action: RateLimitAction,
    #[serde(default)]
    enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
enum RateLimitAction {
    #[default]
    Log,
    Block,
    Throttle,
}

impl Default for MonitorPolicy {
    fn default() -> Self {
        Self {
            sensitive_prefixes: vec!["/etc/shadow".into(), "/etc/ssl".into(), "/root/.ssh".into()],
            monitored_services: vec!["sshd.service".into(), "nginx.service".into()],
            exec_whitelist_prefixes: vec!["/usr/bin".into(), "/usr/sbin".into()],
            blocked_ports: vec![4444, 31337],
            baseline_thresholds: HashMap::from([
                ("file_io".to_string(), 200),
                ("process".to_string(), 80),
                ("privilege".to_string(), 20),
                ("network".to_string(), 160),
                ("hotpatch".to_string(), 50),
            ]),
            hotpatch: HotpatchPolicy::default(),
            rate_limit_rules: Vec::new(),
        }
    }
}

// ── Data types ──

#[derive(Debug, Clone, Serialize)]
struct EventRecord {
    timestamp_ns: u64,
    kind: String,
    action: String,
    pid: u32,
    tgid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    detail: String,
    network: Option<NetworkView>,
}

#[derive(Debug, Clone, Serialize)]
struct NetworkView {
    port: u16,
    address: String,
}

#[derive(Debug, Clone, Serialize)]
struct AlertRecord {
    level: String,
    reason: String,
    event: EventRecord,
}

#[derive(Debug, Clone, Serialize)]
struct Snapshot {
    features: FeatureStatus,
    counters: HashMap<String, u64>,
    services: HashMap<String, Vec<u32>>,
    events: Vec<EventRecord>,
    alerts: Vec<AlertRecord>,
}

#[derive(Debug, Clone, Serialize)]
struct FeatureStatus {
    file_io_agent: bool,
    process_agent: bool,
    network_agent: bool,
    hotpatch_agent: bool,
    anomaly_engine: bool,
    symbol_resolver: bool,
}

// ── Runtime state ──

#[derive(Debug)]
struct BaselineState {
    window_started: Instant,
    counters: HashMap<String, u32>,
}

#[derive(Debug)]
struct RuntimeState {
    counters: HashMap<String, u64>,
    service_map: HashMap<String, Vec<u32>>,
    events: VecDeque<EventRecord>,
    alerts: VecDeque<AlertRecord>,
    baseline: BaselineState,
}

impl RuntimeState {
    fn new() -> Self {
        Self {
            counters: HashMap::new(),
            service_map: HashMap::new(),
            events: VecDeque::new(),
            alerts: VecDeque::new(),
            baseline: BaselineState {
                window_started: Instant::now(),
                counters: HashMap::new(),
            },
        }
    }
}

#[derive(Clone)]
struct Shared {
    policy: Arc<RwLock<MonitorPolicy>>,
    config_path: PathBuf,
    runtime: Arc<RwLock<RuntimeState>>,
    bpf: Arc<Mutex<Ebpf>>,
    hotpatch_active: Arc<Mutex<bool>>,
    symbol_resolver_ok: Arc<Mutex<bool>>,
}

// ── main ──

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::parse();
    let policy = load_policy(&opt.config).context("load policy")?;
    info!("policy loaded from {}", opt.config.display());

    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/gaia-xdp"
    )))
    .context("load eBPF object")?;
    info!("eBPF object loaded");

    attach_agents(&mut bpf).context("attach eBPF agents")?;
    apply_blocked_ports(&mut bpf, &policy.blocked_ports).context("configure blocked ports")?;
    apply_rate_limit_rules(&mut bpf, &policy.rate_limit_rules).context("configure rate limits")?;

    let shared = Shared {
        policy: Arc::new(RwLock::new(policy.clone())),
        config_path: opt.config.clone(),
        runtime: Arc::new(RwLock::new(RuntimeState::new())),
        bpf: Arc::new(Mutex::new(bpf)),
        hotpatch_active: Arc::new(Mutex::new(false)),
        symbol_resolver_ok: Arc::new(Mutex::new(true)),
    };

    // Hotpatch targets are best-effort: failure to attach should not crash.
    {
        let mut bpf_guard = shared.bpf.lock().unwrap();
        match attach_hotpatch_targets(&mut bpf_guard, &policy.hotpatch.targets, &shared) {
            Ok(()) => {
                if !policy.hotpatch.targets.is_empty() {
                    if let Ok(mut h) = shared.hotpatch_active.lock() {
                        *h = true;
                    }
                    info!(
                        "hot-patch agent attached {} target(s)",
                        policy.hotpatch.targets.len()
                    );
                }
            }
            Err(err) => warn!("hot-patch attach skipped: {err:#}"),
        }

        let events = bpf_guard.take_map("EVENTS").context("missing EVENTS map")?;
        let events = RingBuf::<MapData>::try_from(events).context("open EVENTS ring buffer")?;
        spawn_event_collector(events, shared.clone());
    }

    spawn_service_tracker(shared.clone());

    let web_state = shared.clone();
    let web_listen = opt.web_listen.clone();
    tokio::spawn(async move {
        if let Err(err) = run_http_server(web_state, web_listen).await {
            warn!("web api stopped: {err:#}");
        }
    });

    info!("gaia controller started — press Ctrl-C to stop");
    signal::ctrl_c().await.context("waiting for ctrl-c")?;
    info!("gaia controller exiting");
    Ok(())
}

// ── eBPF attach ──

fn attach_agents(bpf: &mut Ebpf) -> Result<()> {
    // File I/O Agent
    attach_tracepoint(bpf, "tp_sys_enter_openat", "syscalls", "sys_enter_openat")?;
    attach_tracepoint(bpf, "tp_sys_exit_openat", "syscalls", "sys_exit_openat")?;
    info!("file I/O agent attached");

    // Process & Privilege Agent
    attach_tracepoint(bpf, "tp_sys_enter_execve", "syscalls", "sys_enter_execve")?;
    attach_tracepoint(bpf, "tp_sys_enter_setuid", "syscalls", "sys_enter_setuid")?;
    attach_tracepoint(bpf, "tp_sys_enter_setgid", "syscalls", "sys_enter_setgid")?;
    info!("process & privilege agent attached");

    // Network Telemetry Agent
    attach_tracepoint(bpf, "tp_sys_enter_connect", "syscalls", "sys_enter_connect")?;
    attach_tracepoint(bpf, "tp_sys_enter_bind", "syscalls", "sys_enter_bind")?;
    info!("network telemetry agent attached");

    // Hot-patching Agent (kprobe guard)
    let prog: &mut KProbe = bpf
        .program_mut("kprobe_hotpatch_guard")
        .context("missing kprobe_hotpatch_guard")?
        .try_into()
        .context("kprobe cast")?;
    prog.load().context("load kprobe_hotpatch_guard")?;
    prog.attach("tcp_connect", 0)
        .context("attach kprobe tcp_connect")?;
    info!("hot-patch kprobe guard attached on tcp_connect");

    Ok(())
}

fn attach_tracepoint(bpf: &mut Ebpf, prog_name: &str, category: &str, name: &str) -> Result<()> {
    let prog: &mut TracePoint = bpf
        .program_mut(prog_name)
        .with_context(|| format!("missing {prog_name}"))?
        .try_into()
        .with_context(|| format!("tracepoint cast {prog_name}"))?;
    prog.load()
        .with_context(|| format!("load tracepoint {prog_name}"))?;
    prog.attach(category, name)
        .with_context(|| format!("attach tracepoint {category}/{name}"))?;
    Ok(())
}

fn apply_blocked_ports(bpf: &mut Ebpf, blocked_ports: &[u16]) -> Result<()> {
    let map = bpf
        .map_mut("BLOCKED_PORTS")
        .context("missing BLOCKED_PORTS map")?;
    let mut ports = BpfHashMap::<_, u16, u8>::try_from(map).context("blocked ports map cast")?;
    // Clear existing entries
    let existing: Vec<u16> = ports.keys().filter_map(|k| k.ok()).collect();
    for k in existing {
        let _ = ports.remove(&k);
    }
    for port in blocked_ports {
        ports
            .insert(*port, 1, 0)
            .with_context(|| format!("insert blocked port {port}"))?;
    }
    info!("blocked ports configured: {blocked_ports:?}");
    Ok(())
}

fn apply_rate_limit_rules(bpf: &mut Ebpf, rules: &[RateLimitRule]) -> Result<()> {
    // Update rule count
    {
        let map = bpf
            .map_mut("RATE_LIMIT_RULE_COUNT")
            .context("missing RATE_LIMIT_RULE_COUNT map")?;
        let mut arr = BpfArray::<_, u32>::try_from(map).context("rule count array cast")?;
        arr.set(0, rules.len() as u32, 0)
            .context("set rule count")?;
    }

    // Update rules map
    {
        let map = bpf
            .map_mut("RATE_LIMIT_RULES")
            .context("missing RATE_LIMIT_RULES map")?;
        let mut rule_map =
            BpfHashMap::<_, u32, RateLimitEntry>::try_from(map).context("rules map cast")?;
        // Clear existing
        let existing: Vec<u32> = rule_map.keys().filter_map(|k| k.ok()).collect();
        for k in existing {
            let _ = rule_map.remove(&k);
        }
        // Insert new rules
        for (idx, rule) in rules.iter().enumerate() {
            if let Some(entry) = parse_rate_limit_to_entry(rule) {
                rule_map
                    .insert(idx as u32, entry, 0)
                    .with_context(|| format!("insert rate limit rule {idx}"))?;
            }
        }
    }

    info!("rate limit rules configured: {} rule(s)", rules.len());
    Ok(())
}

fn parse_rate_limit_to_entry(rule: &RateLimitRule) -> Option<RateLimitEntry> {
    let (addr, prefix_len) = parse_cidr(&rule.cidr)?;
    let mut network = [0u8; 16];
    let octets = addr.octets();
    network[0] = octets[0];
    network[1] = octets[1];
    network[2] = octets[2];
    network[3] = octets[3];

    let action = match rule.action {
        RateLimitAction::Log => gaia_xdp_common::RATE_ACTION_LOG,
        RateLimitAction::Block => gaia_xdp_common::RATE_ACTION_BLOCK,
        RateLimitAction::Throttle => gaia_xdp_common::RATE_ACTION_THROTTLE,
    };

    Some(RateLimitEntry {
        network,
        prefix_len,
        action,
        enabled: if rule.enabled { 1 } else { 0 },
        _pad: 0,
        max_conn_per_sec: rule.max_conn_per_sec,
    })
}

fn parse_cidr(cidr: &str) -> Option<(Ipv4Addr, u8)> {
    if let Some((addr_str, prefix_str)) = cidr.split_once('/') {
        let addr: Ipv4Addr = addr_str.parse().ok()?;
        let prefix: u8 = prefix_str.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        Some((addr, prefix))
    } else {
        // Treat as /32
        let addr: Ipv4Addr = cidr.parse().ok()?;
        Some((addr, 32))
    }
}

fn sync_bpf_blocked_ports(shared: &Shared, blocked_ports: &[u16]) {
    if let Ok(mut bpf) = shared.bpf.lock() {
        if let Err(err) = apply_blocked_ports(&mut bpf, blocked_ports) {
            warn!("failed to sync blocked ports to BPF: {err:#}");
        }
    }
}

fn sync_bpf_rate_limits(shared: &Shared, rules: &[RateLimitRule]) {
    if let Ok(mut bpf) = shared.bpf.lock() {
        if let Err(err) = apply_rate_limit_rules(&mut bpf, rules) {
            warn!("failed to sync rate limit rules to BPF: {err:#}");
        }
    }
}

fn sync_bpf_hotpatch_pids(shared: &Shared, targets: &[HotpatchTarget]) {
    if let Ok(mut bpf) = shared.bpf.lock() {
        let map = match bpf.map_mut("HOTPATCH_PIDS") {
            Some(map) => map,
            None => {
                warn!("missing HOTPATCH_PIDS map");
                return;
            }
        };
        let mut pid_map = match BpfHashMap::<_, u32, HotpatchPidEntry>::try_from(map) {
            Ok(m) => m,
            Err(err) => {
                warn!("hotpatch pids map cast failed: {err:#}");
                return;
            }
        };
        // Clear existing
        let existing: Vec<u32> = pid_map.keys().filter_map(|k| k.ok()).collect();
        for k in existing {
            let _ = pid_map.remove(&k);
        }
        // Insert PIDs from targets
        for target in targets {
            if let Some(pid) = target.pid {
                let entry = HotpatchPidEntry {
                    active: 1,
                    _pad: [0; 3],
                };
                let _ = pid_map.insert(pid, entry, 0);
            }
        }
        info!("hotpatch PID filter updated: {} target(s)", targets.len());
    }
}

fn attach_hotpatch_targets(
    bpf: &mut Ebpf,
    targets: &[HotpatchTarget],
    shared: &Shared,
) -> Result<()> {
    if targets.is_empty() {
        return Ok(());
    }

    // Load uprobe programs once
    {
        let entry: &mut UProbe = bpf
            .program_mut("uprobe_hotpatch_entry")
            .context("missing uprobe_hotpatch_entry")?
            .try_into()
            .context("cast uprobe_hotpatch_entry")?;
        entry.load().context("load uprobe_hotpatch_entry")?;
    }
    {
        let exit: &mut UProbe = bpf
            .program_mut("uretprobe_hotpatch_exit")
            .context("missing uretprobe_hotpatch_exit")?
            .try_into()
            .context("cast uretprobe_hotpatch_exit")?;
        exit.load().context("load uretprobe_hotpatch_exit")?;
    }

    for target in targets {
        let binary_path = Path::new(&target.binary);
        if !binary_path.exists() {
            warn!(
                "hotpatch target binary not found: {} — skipping",
                target.binary
            );
            continue;
        }

        // Attach uprobe entry
        if let Err(err) = (|| -> Result<()> {
            let entry: &mut UProbe = bpf
                .program_mut("uprobe_hotpatch_entry")
                .context("missing")?
                .try_into()
                .context("cast")?;
            entry
                .attach(target.symbol.as_str(), &target.binary, target.pid)
                .context("attach")?;
            Ok(())
        })() {
            warn!(
                "uprobe attach failed {}:{} — {err:#}",
                target.binary, target.symbol
            );
            continue;
        }

        // Attach uretprobe exit
        if let Err(err) = (|| -> Result<()> {
            let exit: &mut UProbe = bpf
                .program_mut("uretprobe_hotpatch_exit")
                .context("missing")?
                .try_into()
                .context("cast")?;
            exit.attach(target.symbol.as_str(), &target.binary, target.pid)
                .context("attach")?;
            Ok(())
        })() {
            warn!(
                "uretprobe attach failed {}:{} — {err:#}",
                target.binary, target.symbol
            );
            continue;
        }

        info!(
            "hotpatch uprobe/uretprobe attached: {}:{}",
            target.binary, target.symbol
        );

        // Symbol resolver: resolve runtime address (informational)
        if let Some(pid) = target.pid {
            match resolve_runtime_symbol(pid, binary_path, &target.symbol) {
                Ok(addr) => info!(
                    "symbol resolved {}:{} pid={} => 0x{addr:x}",
                    target.binary, target.symbol, pid
                ),
                Err(err) => {
                    if let Ok(mut guard) = shared.symbol_resolver_ok.lock() {
                        *guard = false;
                    }
                    warn!(
                        "symbol resolver failed {}:{} pid={}: {err:#}",
                        target.binary, target.symbol, pid
                    );
                }
            }
        }
    }

    Ok(())
}

// ── Event collector (async ring buffer reader) ──

fn spawn_event_collector(events: RingBuf<MapData>, shared: Shared) {
    tokio::spawn(async move {
        let mut async_fd = match AsyncFd::with_interest(events, Interest::READABLE) {
            Ok(fd) => fd,
            Err(err) => {
                warn!("create AsyncFd for ring buffer failed: {err:#}");
                return;
            }
        };

        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(guard) => guard,
                Err(err) => {
                    warn!("ring buffer read wait failed: {err:#}");
                    return;
                }
            };

            let ring = guard.get_inner_mut();
            while let Some(item) = ring.next() {
                if item.len() != size_of::<KernelEvent>() {
                    continue;
                }
                let event =
                    unsafe { core::ptr::read_unaligned(item.as_ptr().cast::<KernelEvent>()) };
                process_event(event, &shared).await;
            }
            guard.clear_ready();
        }
    });
}

// ── Systemd service tracker ──

fn spawn_service_tracker(shared: Shared) {
    tokio::spawn(async move {
        loop {
            let services = shared.policy.read().await.monitored_services.clone();
            if services.is_empty() {
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
            let mut mapping = HashMap::<String, Vec<u32>>::new();
            for service in &services {
                if let Some(pid) = query_service_pid(service).await {
                    mapping.insert(service.clone(), vec![pid]);
                }
            }
            let mut state = shared.runtime.write().await;
            state.service_map = mapping;
            drop(state);
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
}

async fn query_service_pid(service: &str) -> Option<u32> {
    let output = Command::new("systemctl")
        .arg("show")
        .arg(service)
        .arg("--property")
        .arg("MainPID")
        .arg("--value")
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let pid = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .ok()?;
    (pid > 0).then_some(pid)
}

// ── Anomaly detection engine ──

async fn process_event(event: KernelEvent, shared: &Shared) {
    let record = to_event_record(event);
    let mut state = shared.runtime.write().await;
    let policy = shared.policy.read().await;

    let key = record.kind.clone();
    *state.counters.entry(key.clone()).or_insert(0) += 1;

    // Statistical baseline: reset window periodically
    if state.baseline.window_started.elapsed() > Duration::from_secs(BASELINE_WINDOW_SECS) {
        state.baseline.window_started = Instant::now();
        state.baseline.counters.clear();
    }
    let baseline_count = state.baseline.counters.entry(key.clone()).or_insert(0);
    *baseline_count += 1;
    let baseline_now = *baseline_count;

    // Baseline spike detection
    if let Some(threshold) = policy.baseline_thresholds.get(&key)
        && baseline_now > *threshold
    {
        push_alert(
            &mut state,
            "medium",
            format!("syscall baseline exceeded for {key}: {baseline_now} > {threshold}"),
            &record,
        );
    }

    // Whitelist rule: sensitive file access
    if event.kind == EVENT_KIND_FILE_IO
        && event.action == EVENT_ACTION_ALERT
        && file_path_sensitive(&record.detail, &policy)
    {
        push_alert(
            &mut state,
            "high",
            "sensitive file accessed".into(),
            &record,
        );
    }

    // Whitelist rule: execve path check
    if event.kind == EVENT_KIND_PROCESS && !exec_path_whitelisted(&record.detail, &policy) {
        push_alert(
            &mut state,
            "high",
            "execve target not in whitelist prefixes".into(),
            &record,
        );
    }

    // Privilege escalation alert
    if event.kind == EVENT_KIND_PRIVILEGE {
        push_alert(
            &mut state,
            "high",
            "privilege change detected".into(),
            &record,
        );
    }

    // Active defense: blocked port
    if event.kind == EVENT_KIND_NETWORK && event.action == EVENT_ACTION_BLOCKED {
        push_alert(
            &mut state,
            "critical",
            "blocked port hit — active defense policy triggered".into(),
            &record,
        );
    }

    // Rate limit exceeded
    if event.kind == EVENT_KIND_NETWORK && event.action == EVENT_ACTION_RATE_LIMITED {
        push_alert(
            &mut state,
            "high",
            format!("IP rate limit exceeded — {}", record.detail),
            &record,
        );
    }

    state.events.push_front(record);
    while state.events.len() > MAX_EVENT_HISTORY {
        state.events.pop_back();
    }
}

fn exec_path_whitelisted(path: &str, policy: &MonitorPolicy) -> bool {
    if policy.exec_whitelist_prefixes.is_empty() {
        return true;
    }
    policy
        .exec_whitelist_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn file_path_sensitive(path: &str, policy: &MonitorPolicy) -> bool {
    if policy.sensitive_prefixes.is_empty() {
        return true;
    }
    policy
        .sensitive_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn push_alert(state: &mut RuntimeState, level: &str, reason: String, event: &EventRecord) {
    state.alerts.push_front(AlertRecord {
        level: level.to_string(),
        reason,
        event: event.clone(),
    });
    while state.alerts.len() > MAX_ALERT_HISTORY {
        state.alerts.pop_back();
    }
}

// ── Event conversion ──

fn to_event_record(event: KernelEvent) -> EventRecord {
    let comm = fixed_to_string(&event.comm);
    let detail = fixed_to_string(&event.detail);
    let network = if event.kind == EVENT_KIND_NETWORK {
        Some(NetworkView {
            port: event.port,
            address: format_address(&event.addr),
        })
    } else {
        None
    };

    EventRecord {
        timestamp_ns: event.timestamp_ns,
        kind: kind_name(event.kind).to_string(),
        action: action_name(event.action).to_string(),
        pid: event.pid,
        tgid: event.tgid,
        uid: event.uid,
        gid: event.gid,
        comm,
        detail,
        network,
    }
}

fn kind_name(kind: u8) -> &'static str {
    match kind {
        EVENT_KIND_FILE_IO => "file_io",
        EVENT_KIND_PROCESS => "process",
        EVENT_KIND_PRIVILEGE => "privilege",
        EVENT_KIND_NETWORK => "network",
        EVENT_KIND_HOTPATCH => "hotpatch",
        _ => "unknown",
    }
}

fn action_name(action: u8) -> &'static str {
    match action {
        1 => "enter",
        2 => "exit",
        3 => "alert",
        4 => "blocked",
        5 => "rate_limited",
        _ => "unknown",
    }
}

fn fixed_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn format_address(raw: &[u8; 16]) -> String {
    if raw[4..].iter().all(|x| *x == 0) {
        return format!("{}.{}.{}.{}", raw[0], raw[1], raw[2], raw[3]);
    }
    std::net::Ipv6Addr::from(*raw).to_string()
}

// ── Policy loader (TOML / YAML) ──

fn load_policy(path: &Path) -> Result<MonitorPolicy> {
    if !path.exists() {
        info!("config file not found, using defaults");
        return Ok(MonitorPolicy::default());
    }
    let raw =
        fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    match path.extension().and_then(|x| x.to_str()) {
        Some("yaml") | Some("yml") => {
            serde_yaml::from_str::<MonitorPolicy>(&raw).context("parse yaml policy")
        }
        Some("toml") | None => toml::from_str::<MonitorPolicy>(&raw).context("parse toml policy"),
        Some(other) => Err(anyhow!("unsupported config extension: {other}")),
    }
}

// ── Symbol resolver (ELF + /proc/[pid]/maps) ──

fn resolve_runtime_symbol(pid: u32, binary: &Path, symbol: &str) -> Result<u64> {
    let offset = resolve_symbol_offset(binary, symbol)?;
    let base = resolve_process_mapping_base(pid, binary)?;
    Ok(base + offset)
}

fn resolve_symbol_offset(binary: &Path, symbol: &str) -> Result<u64> {
    let data = fs::read(binary).with_context(|| format!("read binary {}", binary.display()))?;
    let obj = object::File::parse(data.as_slice()).context("parse ELF")?;

    for sym in obj.symbols() {
        if let Ok(name) = sym.name()
            && name == symbol
            && sym.address() > 0
        {
            return Ok(sym.address());
        }
    }
    // Also check dynamic symbols (.dynsym)
    for sym in obj.dynamic_symbols() {
        if let Ok(name) = sym.name()
            && name == symbol
            && sym.address() > 0
        {
            return Ok(sym.address());
        }
    }
    Err(anyhow!("symbol {symbol} not found in {}", binary.display()))
}

fn resolve_process_mapping_base(pid: u32, binary: &Path) -> Result<u64> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).context("read /proc maps")?;
    let target = binary
        .canonicalize()
        .unwrap_or_else(|_| binary.to_path_buf());
    let target_str = target.to_string_lossy();

    for line in maps.lines() {
        if !line.contains(target_str.as_ref()) {
            continue;
        }
        let mut fields = line.split_whitespace();
        let range = fields.next().ok_or_else(|| anyhow!("bad maps range"))?;
        let _perms = fields.next();
        let offset = fields.next().ok_or_else(|| anyhow!("bad maps offset"))?;

        let (start, _) = range
            .split_once('-')
            .ok_or_else(|| anyhow!("bad maps address range"))?;
        let start = u64::from_str_radix(start, 16).context("parse maps start")?;
        let offset = u64::from_str_radix(offset, 16).context("parse maps offset")?;
        return Ok(start.saturating_sub(offset));
    }

    Err(anyhow!("binary mapping not found for pid {pid}"))
}

// ── HTTP API ──

async fn run_http_server(shared: Shared, addr: String) -> Result<()> {
    let cors = CorsLayer::new()
        .allow_origin("*".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(vec![header::CONTENT_TYPE, header::ACCEPT]);

    let app = Router::new()
        .route("/api/v1/state", get(api_state))
        .route("/api/v1/config", get(api_get_config).post(api_update_config))
        .route(
            "/api/v1/config/rate-limit",
            get(api_get_rate_limits)
                .post(api_add_rate_limit)
                .put(api_update_rate_limit),
        )
        .route(
            "/api/v1/config/rate-limit/{index}",
            axum::routing::delete(api_delete_rate_limit),
        )
        .route(
            "/api/v1/config/hotpatch",
            get(api_get_hotpatch)
                .post(api_add_hotpatch)
                .put(api_update_hotpatch),
        )
        .route(
            "/api/v1/config/hotpatch/{index}",
            axum::routing::delete(api_delete_hotpatch),
        )
        .with_state(shared)
        .layer(cors);

    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind http listener {addr}"))?;
    info!("web api listening on http://{addr}");
    axum::serve(listener, app).await.context("serve axum")?;
    Ok(())
}

async fn api_state(State(shared): State<Shared>) -> Json<Snapshot> {
    let state = shared.runtime.read().await;
    let hotpatch_active = shared.hotpatch_active.lock().map(|v| *v).unwrap_or(false);
    let symbol_resolver = shared
        .symbol_resolver_ok
        .lock()
        .map(|v| *v)
        .unwrap_or(false);

    let snapshot = Snapshot {
        features: FeatureStatus {
            file_io_agent: true,
            process_agent: true,
            network_agent: true,
            hotpatch_agent: hotpatch_active,
            anomaly_engine: true,
            symbol_resolver,
        },
        counters: state.counters.clone(),
        services: state.service_map.clone(),
        events: state.events.iter().cloned().collect(),
        alerts: state.alerts.iter().cloned().collect(),
    };
    Json(snapshot)
}

// ── Config API: full policy ──

async fn api_get_config(State(shared): State<Shared>) -> Json<MonitorPolicy> {
    let policy = shared.policy.read().await;
    Json(policy.clone())
}

#[derive(Debug, Deserialize)]
struct ConfigUpdate {
    #[serde(default)]
    sensitive_prefixes: Option<Vec<String>>,
    #[serde(default)]
    monitored_services: Option<Vec<String>>,
    #[serde(default)]
    exec_whitelist_prefixes: Option<Vec<String>>,
    #[serde(default)]
    blocked_ports: Option<Vec<u16>>,
    #[serde(default)]
    baseline_thresholds: Option<HashMap<String, u32>>,
}

async fn api_update_config(
    State(shared): State<Shared>,
    Json(update): Json<ConfigUpdate>,
) -> Json<MonitorPolicy> {
    let mut policy = shared.policy.write().await;
    if let Some(v) = update.sensitive_prefixes {
        policy.sensitive_prefixes = v;
    }
    if let Some(v) = update.monitored_services {
        policy.monitored_services = v;
    }
    if let Some(v) = update.exec_whitelist_prefixes {
        policy.exec_whitelist_prefixes = v;
    }
    if let Some(ref v) = update.blocked_ports {
        policy.blocked_ports = v.clone();
    }
    if let Some(v) = update.baseline_thresholds {
        policy.baseline_thresholds = v;
    }
    let snapshot = policy.clone();
    drop(policy);
    // Sync blocked ports to BPF if changed
    if update.blocked_ports.is_some() {
        sync_bpf_blocked_ports(&shared, &snapshot.blocked_ports);
    }
    persist_policy(&shared).await;
    Json(snapshot)
}

// ── Config API: rate limit rules ──

async fn api_get_rate_limits(State(shared): State<Shared>) -> Json<Vec<RateLimitRule>> {
    let policy = shared.policy.read().await;
    Json(policy.rate_limit_rules.clone())
}

async fn api_add_rate_limit(
    State(shared): State<Shared>,
    Json(rule): Json<RateLimitRule>,
) -> Json<Vec<RateLimitRule>> {
    let mut policy = shared.policy.write().await;
    policy.rate_limit_rules.push(rule);
    let rules = policy.rate_limit_rules.clone();
    drop(policy);
    sync_bpf_rate_limits(&shared, &rules);
    persist_policy(&shared).await;
    Json(rules)
}

#[derive(Debug, Deserialize)]
struct IndexedUpdate<T> {
    index: usize,
    #[serde(flatten)]
    data: T,
}

async fn api_update_rate_limit(
    State(shared): State<Shared>,
    Json(update): Json<IndexedUpdate<RateLimitRule>>,
) -> Json<Vec<RateLimitRule>> {
    let mut policy = shared.policy.write().await;
    if update.index < policy.rate_limit_rules.len() {
        policy.rate_limit_rules[update.index] = update.data;
    }
    let rules = policy.rate_limit_rules.clone();
    drop(policy);
    sync_bpf_rate_limits(&shared, &rules);
    persist_policy(&shared).await;
    Json(rules)
}

async fn api_delete_rate_limit(
    State(shared): State<Shared>,
    axum::extract::Path(index): axum::extract::Path<usize>,
) -> Json<Vec<RateLimitRule>> {
    let mut policy = shared.policy.write().await;
    if index < policy.rate_limit_rules.len() {
        policy.rate_limit_rules.remove(index);
    }
    let rules = policy.rate_limit_rules.clone();
    drop(policy);
    sync_bpf_rate_limits(&shared, &rules);
    persist_policy(&shared).await;
    Json(rules)
}

// ── Config API: hotpatch targets ──

async fn api_get_hotpatch(State(shared): State<Shared>) -> Json<Vec<HotpatchTarget>> {
    let policy = shared.policy.read().await;
    Json(policy.hotpatch.targets.clone())
}

async fn api_add_hotpatch(
    State(shared): State<Shared>,
    Json(target): Json<HotpatchTarget>,
) -> Json<Vec<HotpatchTarget>> {
    let mut policy = shared.policy.write().await;
    policy.hotpatch.targets.push(target);
    let targets = policy.hotpatch.targets.clone();
    drop(policy);
    sync_bpf_hotpatch_pids(&shared, &targets);
    persist_policy(&shared).await;
    Json(targets)
}

async fn api_update_hotpatch(
    State(shared): State<Shared>,
    Json(update): Json<IndexedUpdate<HotpatchTarget>>,
) -> Json<Vec<HotpatchTarget>> {
    let mut policy = shared.policy.write().await;
    if update.index < policy.hotpatch.targets.len() {
        policy.hotpatch.targets[update.index] = update.data;
    }
    let targets = policy.hotpatch.targets.clone();
    drop(policy);
    sync_bpf_hotpatch_pids(&shared, &targets);
    persist_policy(&shared).await;
    Json(targets)
}

async fn api_delete_hotpatch(
    State(shared): State<Shared>,
    axum::extract::Path(index): axum::extract::Path<usize>,
) -> Json<Vec<HotpatchTarget>> {
    let mut policy = shared.policy.write().await;
    if index < policy.hotpatch.targets.len() {
        policy.hotpatch.targets.remove(index);
    }
    let targets = policy.hotpatch.targets.clone();
    drop(policy);
    sync_bpf_hotpatch_pids(&shared, &targets);
    persist_policy(&shared).await;
    Json(targets)
}

// ── Persist policy to config file ──

async fn persist_policy(shared: &Shared) {
    let policy = shared.policy.read().await;
    let path = &shared.config_path;
    match toml::to_string_pretty(&*policy) {
        Ok(content) => {
            if let Err(err) = fs::write(path, content) {
                warn!("failed to persist config to {}: {err:#}", path.display());
            } else {
                info!("config persisted to {}", path.display());
            }
        }
        Err(err) => warn!("failed to serialize config: {err:#}"),
    }
}
