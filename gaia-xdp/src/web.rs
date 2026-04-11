use super::*;

#[derive(Debug, Deserialize)]
struct ConfigUpdate {
    #[serde(default)]
    sensitive_prefixes: Option<Vec<ToggleItem>>,
    #[serde(default)]
    monitored_services: Option<Vec<ToggleItem>>,
    #[serde(default)]
    exec_whitelist_prefixes: Option<Vec<ToggleItem>>,
    #[serde(default)]
    blocked_ports: Option<Vec<TogglePort>>,
    #[serde(default)]
    baseline_thresholds: Option<HashMap<String, u32>>,
}

#[derive(Debug, Deserialize)]
struct IndexedUpdate<T> {
    index: usize,
    #[serde(flatten)]
    data: T,
}

#[derive(Debug, Deserialize)]
struct ToggleRequest {
    section: String,
    index: usize,
    enabled: bool,
}

#[derive(Serialize)]
struct ReloadResult {
    success: bool,
    message: String,
    targets_count: usize,
}

pub(crate) async fn run_http_server(shared: Shared, addr: String) -> Result<()> {
    let cors = CorsLayer::new()
        .allow_origin("*".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(vec![header::CONTENT_TYPE, header::ACCEPT]);

    let app = Router::new()
        .route("/api/v1/state", get(api_state))
        .route("/api/v1/config", get(api_get_config).post(api_update_config))
        .route("/api/v1/config/rate-limit", get(api_get_rate_limits).post(api_add_rate_limit).put(api_update_rate_limit))
        .route("/api/v1/config/rate-limit/{index}", axum::routing::delete(api_delete_rate_limit))
        .route("/api/v1/config/hotpatch", get(api_get_hotpatch).post(api_add_hotpatch).put(api_update_hotpatch))
        .route("/api/v1/config/hotpatch/{index}", axum::routing::delete(api_delete_hotpatch))
        .route("/api/v1/config/toggle", post(api_toggle_item))
        .route("/api/v1/process/{pid}", get(crate::process::api_process_detail))
        .route("/api/v1/upload-lib", post(api_upload_lib))
        .route("/api/v1/reload-hotpatch", post(api_reload_hotpatch))
        .route("/api/v1/ai/config", get(crate::ai::api_ai_get_config).post(crate::ai::api_ai_update_config))
        .route("/api/v1/ai/chat", post(crate::ai::api_ai_chat))
        .route("/api/v1/ai/events", get(crate::ai::api_ai_events))
        .with_state(shared)
        .layer(cors)
        .fallback(embedded_webui_handler);

    info!("serving embedded WebUI ({} files)", WebAssets::iter().count());

    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind http listener {addr}"))?;
    info!("web api listening on http://{addr}");
    axum::serve(listener, app).await.context("serve axum")?;
    Ok(())
}

async fn embedded_webui_handler(uri: Uri) -> Response {
    if uri.path().starts_with("/api/") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    let path = uri.path().trim_start_matches('/');
    let file_path = if path.is_empty() { "index.html" } else { path };

    match WebAssets::get(file_path) {
        Some(content) => {
            let mime = guess_mime(file_path);
            ([(header::CONTENT_TYPE, mime)], content.data.to_vec()).into_response()
        }
        None => match WebAssets::get("index.html") {
            Some(index) => ([(header::CONTENT_TYPE, "text/html; charset=utf-8".to_string())], index.data.to_vec()).into_response(),
            None => (StatusCode::NOT_FOUND, "WebUI not embedded").into_response(),
        },
    }
}

fn guess_mime(path: &str) -> String {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("ico") => "image/x-icon",
        Some("json") => "application/json",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        _ => "application/octet-stream",
    }
    .to_string()
}

async fn api_state(State(shared): State<Shared>) -> Json<Snapshot> {
    let state = shared.runtime.read().await;
    let hotpatch_active = shared.hotpatch_active.lock().map(|v| *v).unwrap_or(false);
    let symbol_resolver = shared.symbol_resolver_ok.lock().map(|v| *v).unwrap_or(false);

    Json(Snapshot {
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
        traffic: state.traffic.clone(),
    })
}

async fn api_get_config(State(shared): State<Shared>) -> Json<MonitorPolicy> {
    let policy = shared.policy.read().await;
    Json(policy.clone())
}

async fn api_update_config(State(shared): State<Shared>, Json(update): Json<ConfigUpdate>) -> Json<MonitorPolicy> {
    let mut policy = shared.policy.write().await;
    if let Some(v) = update.sensitive_prefixes { policy.sensitive_prefixes = v; }
    if let Some(v) = update.monitored_services { policy.monitored_services = v; }
    if let Some(v) = update.exec_whitelist_prefixes { policy.exec_whitelist_prefixes = v; }
    if let Some(ref v) = update.blocked_ports { policy.blocked_ports = v.clone(); }
    if let Some(v) = update.baseline_thresholds { policy.baseline_thresholds = v; }
    let snapshot = policy.clone();
    drop(policy);
    if update.blocked_ports.is_some() {
        sync_bpf_blocked_ports(&shared, &snapshot.blocked_ports);
    }
    persist_policy(&shared).await;
    Json(snapshot)
}

async fn api_get_rate_limits(State(shared): State<Shared>) -> Json<Vec<RateLimitRule>> {
    let policy = shared.policy.read().await;
    Json(policy.rate_limit_rules.clone())
}

async fn api_add_rate_limit(State(shared): State<Shared>, Json(rule): Json<RateLimitRule>) -> Json<Vec<RateLimitRule>> {
    let mut policy = shared.policy.write().await;
    policy.rate_limit_rules.push(rule);
    let rules = policy.rate_limit_rules.clone();
    drop(policy);
    sync_bpf_rate_limits(&shared, &rules);
    persist_policy(&shared).await;
    Json(rules)
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

async fn api_get_hotpatch(State(shared): State<Shared>) -> Json<Vec<HotpatchTarget>> {
    let policy = shared.policy.read().await;
    Json(policy.hotpatch.targets.clone())
}

async fn api_add_hotpatch(State(shared): State<Shared>, Json(target): Json<HotpatchTarget>) -> Json<Vec<HotpatchTarget>> {
    let mut policy = shared.policy.write().await;
    policy.hotpatch.targets.push(target);
    let targets = policy.hotpatch.targets.clone();
    drop(policy);
    sync_bpf_hotpatch_pids(&shared, &targets);
    sync_bpf_hotpatch_rules(&shared, &targets);
    {
        let mut bpf_guard = shared.bpf.lock().unwrap();
        if let Err(err) = attach_hotpatch_targets(&mut bpf_guard, &targets, &shared) {
            warn!("hotpatch uprobe auto-attach after add: {err:#}");
        }
    }
    {
        let mut patches = shared.code_patches.lock().unwrap();
        restore_hotpatch_code_patches(&mut patches);
        apply_hotpatch_code_patches(&targets, &mut patches);
    }
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
    sync_bpf_hotpatch_rules(&shared, &targets);
    {
        let mut bpf_guard = shared.bpf.lock().unwrap();
        if let Err(err) = attach_hotpatch_targets(&mut bpf_guard, &targets, &shared) {
            warn!("hotpatch uprobe auto-attach after update: {err:#}");
        }
    }
    {
        let mut patches = shared.code_patches.lock().unwrap();
        restore_hotpatch_code_patches(&mut patches);
        apply_hotpatch_code_patches(&targets, &mut patches);
    }
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
    sync_bpf_hotpatch_rules(&shared, &targets);
    {
        let mut patches = shared.code_patches.lock().unwrap();
        restore_hotpatch_code_patches(&mut patches);
        apply_hotpatch_code_patches(&targets, &mut patches);
    }
    persist_policy(&shared).await;
    Json(targets)
}

async fn api_upload_lib(mut multipart: Multipart) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut file_data: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name().unwrap_or("") == "file" {
            file_name = field.file_name().map(|s| s.to_string());
            match field.bytes().await {
                Ok(bytes) => file_data = Some(bytes.to_vec()),
                Err(e) => return Err((StatusCode::BAD_REQUEST, format!("read field: {e}"))),
            }
        }
    }

    let data = file_data.ok_or_else(|| (StatusCode::BAD_REQUEST, "missing 'file' field".to_string()))?;
    let original_name = file_name.unwrap_or_else(|| "uploaded.so".to_string());

    let obj = match object::File::parse(data.as_slice()) {
        Ok(o) => o,
        Err(e) => return Err((StatusCode::BAD_REQUEST, format!("invalid ELF: {e}"))),
    };

    let host_arch = std::env::consts::ARCH;
    let elf_arch = match obj.architecture() {
        object::Architecture::Aarch64 => "aarch64",
        object::Architecture::X86_64 => "x86_64",
        other => return Err((StatusCode::BAD_REQUEST, format!("unsupported ELF architecture: {other:?}"))),
    };
    if elf_arch != host_arch {
        return Err((StatusCode::BAD_REQUEST, format!("architecture mismatch: uploaded .so is {elf_arch} but host is {host_arch}")));
    }
    if obj.kind() != object::ObjectKind::Dynamic {
        return Err((StatusCode::BAD_REQUEST, format!("uploaded file is not a shared library (got {:?}, expected ET_DYN)", obj.kind())));
    }

    let lib_dir = PathBuf::from("/tmp/gaia-libs");
    if let Err(e) = fs::create_dir_all(&lib_dir) {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("create lib dir: {e}")));
    }
    let safe_name = original_name
        .rsplit('/')
        .next()
        .unwrap_or("uploaded.so")
        .replace(|c: char| !c.is_alphanumeric() && c != '.' && c != '_' && c != '-', "_");
    let dest = lib_dir.join(&safe_name);
    if let Err(e) = fs::write(&dest, &data) {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("write file: {e}")));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(0o755));
    }

    let path_str = dest.to_string_lossy().to_string();
    info!("uploaded library saved: {} ({} bytes, arch={})", path_str, data.len(), elf_arch);

    Ok(Json(serde_json::json!({
        "path": path_str,
        "size": data.len(),
        "arch": elf_arch,
        "name": safe_name,
    })))
}

async fn api_toggle_item(
    State(shared): State<Shared>,
    Json(req): Json<ToggleRequest>,
) -> Result<Json<MonitorPolicy>, StatusCode> {
    let mut policy = shared.policy.write().await;
    match req.section.as_str() {
        "sensitive_prefixes" => {
            if req.index < policy.sensitive_prefixes.len() {
                policy.sensitive_prefixes[req.index].enabled = req.enabled;
            }
        }
        "monitored_services" => {
            if req.index < policy.monitored_services.len() {
                policy.monitored_services[req.index].enabled = req.enabled;
            }
        }
        "exec_whitelist_prefixes" => {
            if req.index < policy.exec_whitelist_prefixes.len() {
                policy.exec_whitelist_prefixes[req.index].enabled = req.enabled;
            }
        }
        "blocked_ports" => {
            if req.index < policy.blocked_ports.len() {
                policy.blocked_ports[req.index].enabled = req.enabled;
            }
            let ports = policy.blocked_ports.clone();
            let snapshot = policy.clone();
            drop(policy);
            sync_bpf_blocked_ports(&shared, &ports);
            persist_policy(&shared).await;
            return Ok(Json(snapshot));
        }
        "rate_limit_rules" => {
            if req.index < policy.rate_limit_rules.len() {
                policy.rate_limit_rules[req.index].enabled = req.enabled;
            }
            let rules = policy.rate_limit_rules.clone();
            let snapshot = policy.clone();
            drop(policy);
            sync_bpf_rate_limits(&shared, &rules);
            persist_policy(&shared).await;
            return Ok(Json(snapshot));
        }
        "hotpatch_targets" => {
            if req.index < policy.hotpatch.targets.len() {
                policy.hotpatch.targets[req.index].enabled = req.enabled;
            }
            let targets = policy.hotpatch.targets.clone();
            let snapshot = policy.clone();
            drop(policy);
            sync_bpf_hotpatch_pids(&shared, &targets);
            sync_bpf_hotpatch_rules(&shared, &targets);
            persist_policy(&shared).await;
            return Ok(Json(snapshot));
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    }
    let snapshot = policy.clone();
    drop(policy);
    persist_policy(&shared).await;
    Ok(Json(snapshot))
}

async fn api_reload_hotpatch(State(shared): State<Shared>) -> Json<ReloadResult> {
    let policy = shared.policy.read().await;
    let targets = policy.hotpatch.targets.clone();
    drop(policy);

    info!("reload-hotpatch requested: {} target(s)", targets.len());

    let result = {
        let mut bpf_guard = shared.bpf.lock().unwrap();
        attach_hotpatch_targets(&mut bpf_guard, &targets, &shared)
    };

    sync_bpf_hotpatch_pids(&shared, &targets);
    sync_bpf_hotpatch_rules(&shared, &targets);

    {
        let mut patches = shared.code_patches.lock().unwrap();
        restore_hotpatch_code_patches(&mut patches);
        apply_hotpatch_code_patches(&targets, &mut patches);
    }

    match result {
        Ok(()) => Json(ReloadResult {
            success: true,
            message: format!("Hotpatch reloaded: {} target(s) processed", targets.len()),
            targets_count: targets.len(),
        }),
        Err(err) => {
            let msg = format!("Hotpatch reload error: {err:#}");
            warn!("{msg}");
            Json(ReloadResult {
                success: false,
                message: msg,
                targets_count: targets.len(),
            })
        }
    }
}

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
