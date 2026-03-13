use std::{
    collections::{HashMap, VecDeque},
    fs,
    mem::size_of,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, Method},
    routing::get,
};
use aya::{
    Ebpf,
    maps::{HashMap as BpfHashMap, MapData, ring_buf::RingBuf},
    programs::{KProbe, TracePoint, UProbe},
};
use clap::Parser;
use gaia_xdp_common::{
    EVENT_ACTION_ALERT, EVENT_ACTION_BLOCKED, EVENT_KIND_FILE_IO, EVENT_KIND_HOTPATCH,
    EVENT_KIND_NETWORK, EVENT_KIND_PRIVILEGE, EVENT_KIND_PROCESS, KernelEvent,
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

#[derive(Debug, Clone, Deserialize)]
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
}

#[derive(Debug, Clone, Deserialize, Default)]
struct HotpatchPolicy {
    #[serde(default)]
    targets: Vec<HotpatchTarget>,
}

#[derive(Debug, Clone, Deserialize)]
struct HotpatchTarget {
    binary: String,
    symbol: String,
    #[serde(default)]
    pid: Option<u32>,
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
    policy: MonitorPolicy,
    runtime: Arc<RwLock<RuntimeState>>,
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

    let shared = Shared {
        policy: policy.clone(),
        runtime: Arc::new(RwLock::new(RuntimeState::new())),
        hotpatch_active: Arc::new(Mutex::new(false)),
        symbol_resolver_ok: Arc::new(Mutex::new(true)),
    };

    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/gaia-xdp"
    )))
    .context("load eBPF object")?;
    info!("eBPF object loaded");

    attach_agents(&mut bpf).context("attach eBPF agents")?;
    apply_blocked_ports(&mut bpf, &policy.blocked_ports).context("configure blocked ports")?;

    // Hotpatch targets are best-effort: failure to attach should not crash.
    match attach_hotpatch_targets(&mut bpf, &policy.hotpatch.targets, &shared) {
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

    let events = bpf.take_map("EVENTS").context("missing EVENTS map")?;
    let events = RingBuf::<MapData>::try_from(events).context("open EVENTS ring buffer")?;
    spawn_event_collector(events, shared.clone());
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
    for port in blocked_ports {
        ports
            .insert(*port, 1, 0)
            .with_context(|| format!("insert blocked port {port}"))?;
    }
    info!("blocked ports configured: {blocked_ports:?}");
    Ok(())
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
    let services = shared.policy.monitored_services.clone();
    tokio::spawn(async move {
        if services.is_empty() {
            return;
        }
        loop {
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
    if let Some(threshold) = shared.policy.baseline_thresholds.get(&key)
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
        && file_path_sensitive(&record.detail, &shared.policy)
    {
        push_alert(
            &mut state,
            "high",
            "sensitive file accessed".into(),
            &record,
        );
    }

    // Whitelist rule: execve path check
    if event.kind == EVENT_KIND_PROCESS && !exec_path_whitelisted(&record.detail, &shared.policy) {
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
        .allow_methods([Method::GET]);

    let app = Router::new()
        .route("/api/v1/state", get(api_state))
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
