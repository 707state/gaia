use super::*;

pub(crate) fn load_ai_config(config_path: &Path) -> AiConfig {
    let path = ai_config_path(config_path);
    if !path.exists() {
        return AiConfig::default();
    }
    match fs::read_to_string(&path) {
        Ok(raw) => toml::from_str::<AiConfig>(&raw).unwrap_or_default(),
        Err(_) => AiConfig::default(),
    }
}

fn ai_config_path(config_path: &Path) -> PathBuf {
    let stem = config_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("gaia");
    let ext = config_path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("toml");
    let parent = config_path.parent().unwrap_or(Path::new("."));
    parent.join(format!("{stem}-ai.{ext}"))
}

async fn persist_ai_config(shared: &Shared) {
    let cfg = shared.ai_config.read().await;
    let path = ai_config_path(&shared.config_path);
    match toml::to_string_pretty(&*cfg) {
        Ok(content) => {
            if let Err(err) = fs::write(&path, content) {
                warn!("failed to persist AI config to {}: {err:#}", path.display());
            } else {
                info!("AI config persisted to {}", path.display());
            }
        }
        Err(err) => warn!("failed to serialize AI config: {err:#}"),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct AiConfigUpdate {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    provider: Option<AiProvider>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    api_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AiChatRequest {
    messages: Vec<ChatMessage>,
    #[serde(default = "default_true")]
    include_context: bool,
}

pub(crate) async fn api_ai_get_config(State(shared): State<Shared>) -> Json<AiConfig> {
    let cfg = shared.ai_config.read().await;
    let mut safe = cfg.clone();
    if !safe.api_key.is_empty() {
        safe.api_key = "••••••••".to_string();
    }
    Json(safe)
}

pub(crate) async fn api_ai_update_config(
    State(shared): State<Shared>,
    Json(update): Json<AiConfigUpdate>,
) -> Json<AiConfig> {
    let mut cfg = shared.ai_config.write().await;
    if let Some(v) = update.enabled { cfg.enabled = v; }
    if let Some(v) = update.provider { cfg.provider = v; }
    if let Some(v) = update.base_url { cfg.base_url = v; }
    if let Some(v) = update.model { cfg.model = v; }
    if let Some(v) = update.api_key {
        if v != "••••••••" {
            cfg.api_key = v;
        }
    }
    let mut safe = cfg.clone();
    drop(cfg);
    persist_ai_config(&shared).await;
    if !safe.api_key.is_empty() {
        safe.api_key = "••••••••".to_string();
    }
    Json(safe)
}

async fn build_system_prompt(shared: &Shared, include_context: bool) -> String {
    let base = "You are GAIA, an AI security analyst embedded in the GAIA eBPF-based security \
monitoring platform. You help operators understand security events, analyze anomalies, \
investigate alerts, and suggest remediation steps. Be concise, technical, and actionable. \
When referencing events, cite specific PIDs, process names, and timestamps where available.";

    if !include_context {
        return base.to_string();
    }

    let state = shared.runtime.read().await;
    let recent_events: Vec<String> = state
        .events
        .iter()
        .take(AI_CONTEXT_EVENTS)
        .map(|e| {
            format!(
                "[{}] kind={} action={} pid={} comm={} detail={}{}",
                e.timestamp_ns / 1_000_000,
                e.kind,
                e.action,
                e.pid,
                e.comm,
                e.detail,
                e.service
                    .as_ref()
                    .map(|s| format!(" service={s}"))
                    .unwrap_or_default(),
            )
        })
        .collect();

    let recent_alerts: Vec<String> = state
        .alerts
        .iter()
        .take(10)
        .map(|a| format!("[{}] {}: {}", a.level.to_uppercase(), a.event.comm, a.reason))
        .collect();

    let counters: Vec<String> = state
        .counters
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();

    drop(state);

    format!(
        "{base}\n\n\
        ## Current System State\n\
        Event counters (cumulative): {}\n\n\
        ## Recent Alerts (newest first)\n{}\n\n\
        ## Recent Events (newest first)\n{}",
        counters.join(", "),
        if recent_alerts.is_empty() { "None".to_string() } else { recent_alerts.join("\n") },
        if recent_events.is_empty() { "None".to_string() } else { recent_events.join("\n") },
    )
}

fn resolve_base_url(cfg: &AiConfig) -> String {
    if !cfg.base_url.is_empty() {
        return cfg.base_url.trim_end_matches('/').to_string();
    }
    match cfg.provider {
        AiProvider::Ollama => "http://localhost:11434".to_string(),
        AiProvider::OpenAi | AiProvider::Custom => "https://api.openai.com".to_string(),
    }
}

pub(crate) async fn api_ai_chat(
    State(shared): State<Shared>,
    Json(req): Json<AiChatRequest>,
) -> Response {
    let cfg = {
        let guard = shared.ai_config.read().await;
        guard.clone()
    };

    if !cfg.enabled {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "AI analysis is disabled. Enable it in Settings → AI Analysis.",
        )
            .into_response();
    }

    let system_prompt = build_system_prompt(&shared, req.include_context).await;
    let mut messages: Vec<serde_json::Value> = vec![serde_json::json!({
        "role": "system",
        "content": system_prompt,
    })];
    for msg in &req.messages {
        messages.push(serde_json::json!({
            "role": msg.role,
            "content": msg.content,
        }));
    }

    let base_url = resolve_base_url(&cfg);
    let endpoint = match cfg.provider {
        AiProvider::Ollama => format!("{base_url}/api/chat"),
        _ => format!("{base_url}/v1/chat/completions"),
    };
    let body = serde_json::json!({
        "model": cfg.model,
        "messages": messages,
        "stream": true,
    });

    let client = reqwest::Client::new();
    let mut req_builder = client
        .post(&endpoint)
        .header("Content-Type", "application/json")
        .json(&body);

    if !cfg.api_key.is_empty() {
        req_builder = req_builder.header("Authorization", format!("Bearer {}", cfg.api_key));
    }

    let http_resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("LLM API request failed: {e}")).into_response(),
    };

    if !http_resp.status().is_success() {
        let status = http_resp.status();
        let body_text = http_resp.text().await.unwrap_or_default();
        return (StatusCode::BAD_GATEWAY, format!("LLM API error {status}: {body_text}")).into_response();
    }

    let is_ollama = cfg.provider == AiProvider::Ollama;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(64);

    tokio::spawn(async move {
        let mut byte_stream = http_resp.bytes_stream();
        let mut buffer = String::new();

        while let Some(chunk) = futures_util::StreamExt::next(&mut byte_stream).await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Ok(Event::default().data(
                        serde_json::json!({"error": e.to_string()}).to_string(),
                    ))).await;
                    return;
                }
            };

            buffer.push_str(&String::from_utf8_lossy(&chunk));

            while let Some(newline_pos) = buffer.find('\n') {
                let line = buffer[..newline_pos].trim().to_string();
                buffer = buffer[newline_pos + 1..].to_string();

                if line.is_empty() || line == "data: [DONE]" {
                    continue;
                }

                let json_str = if line.starts_with("data: ") { &line[6..] } else { &line };
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
                    let (delta, done) = if is_ollama {
                        let content = val["message"]["content"].as_str().unwrap_or("").to_string();
                        let done = val["done"].as_bool().unwrap_or(false);
                        (content, done)
                    } else {
                        let content = val["choices"][0]["delta"]["content"].as_str().unwrap_or("").to_string();
                        let done = val["choices"][0]["finish_reason"]
                            .as_str()
                            .map(|r| r == "stop")
                            .unwrap_or(false);
                        (content, done)
                    };

                    if !delta.is_empty() || done {
                        let payload = serde_json::json!({ "delta": delta, "done": done });
                        if tx.send(Ok(Event::default().data(payload.to_string()))).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }

        let _ = tx.send(Ok(Event::default().data(
            serde_json::json!({"delta": "", "done": true}).to_string(),
        ))).await;
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

pub(crate) async fn api_ai_events(State(shared): State<Shared>) -> Response {
    let rx = shared.ai_alert_tx.subscribe();
    let stream = TokioStreamExt::filter_map(BroadcastStream::new(rx), |result| match result {
        Ok(notification) => {
            let data = serde_json::to_string(&notification).unwrap_or_default();
            Some(Ok::<Event, Infallible>(Event::default().event("alert").data(data)))
        }
        Err(_) => None,
    });

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}
