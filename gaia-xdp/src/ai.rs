use futures_util::StreamExt as FuturesStreamExt;
use qrcode::{QrCode, render::svg};
use rig::{
    agent::MultiTurnStreamItem,
    client::{CompletionClient, Nothing},
    completion::message::Message,
    providers::{ollama, openai},
    streaming::{StreamedAssistantContent, StreamingChat},
};
use tokio::{io::AsyncWriteExt, net::UnixStream};

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

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub(crate) struct WechatBotStatus {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    logged_in: bool,
    #[serde(default)]
    needs_qr_scan: bool,
    #[serde(default)]
    qr_url: Option<String>,
    #[serde(default)]
    last_error: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
}

fn notify_status_path(config_path: &Path) -> PathBuf {
    let stem = config_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("gaia");
    let parent = config_path.parent().unwrap_or(Path::new("."));
    parent.join(format!("{stem}-notify-state.json"))
}

pub(crate) fn load_wechat_bot_status(config_path: &Path) -> WechatBotStatus {
    let path = notify_status_path(config_path);
    match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str::<WechatBotStatus>(&raw).unwrap_or_default(),
        Err(_) => WechatBotStatus::default(),
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
    #[serde(default)]
    analysis_interval_hours: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TriggerAnalysisRequest {
    #[serde(default)]
    source: Option<String>,
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

pub(crate) async fn api_ai_get_wechat_status(
    State(shared): State<Shared>,
) -> Json<WechatBotStatus> {
    Json(load_wechat_bot_status(&shared.config_path))
}

pub(crate) async fn api_ai_get_wechat_qr(State(shared): State<Shared>) -> Response {
    let status = load_wechat_bot_status(&shared.config_path);
    let Some(qr_url) = status.qr_url.as_deref() else {
        return (StatusCode::NOT_FOUND, "wechat qr url not available").into_response();
    };

    let code = match QrCode::new(qr_url.as_bytes()) {
        Ok(code) => code,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to generate qr code: {err}"),
            )
                .into_response();
        }
    };

    let image = code
        .render::<svg::Color<'_>>()
        .min_dimensions(256, 256)
        .quiet_zone(true)
        .build();

    ([(header::CONTENT_TYPE, "image/svg+xml")], image).into_response()
}

pub(crate) async fn api_ai_update_config(
    State(shared): State<Shared>,
    Json(update): Json<AiConfigUpdate>,
) -> Json<AiConfig> {
    let mut cfg = shared.ai_config.write().await;
    if let Some(v) = update.enabled {
        cfg.enabled = v;
    }
    if let Some(v) = update.provider {
        cfg.provider = v;
    }
    if let Some(v) = update.base_url {
        cfg.base_url = v;
    }
    if let Some(v) = update.model {
        cfg.model = v;
    }
    if let Some(v) = update.api_key {
        if v != "••••••••" {
            cfg.api_key = v;
        }
    }
    if let Some(v) = update.analysis_interval_hours {
        cfg.analysis_interval_hours = v;
    }
    let mut safe = cfg.clone();
    drop(cfg);
    persist_ai_config(&shared).await;
    if !safe.api_key.is_empty() {
        safe.api_key = "••••••••".to_string();
    }
    Json(safe)
}

pub(crate) async fn api_ai_trigger_analysis(
    State(shared): State<Shared>,
    Json(req): Json<TriggerAnalysisRequest>,
) -> Response {
    let source = req.source.unwrap_or_else(|| "webui_manual".to_string());
    let payload = serde_json::json!({
        "action": "analyze_now",
        "source": source,
    })
    .to_string();

    let mut stream = match UnixStream::connect(&shared.notify_control_socket).await {
        Ok(stream) => stream,
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!(
                    "gaia-notify control socket unavailable ({}): {err}",
                    shared.notify_control_socket.display()
                ),
            )
                .into_response();
        }
    };

    if let Err(err) = stream.write_all(format!("{payload}\n").as_bytes()).await {
        return (
            StatusCode::BAD_GATEWAY,
            format!("failed to send analysis command to gaia-notify: {err}"),
        )
            .into_response();
    }

    Json(serde_json::json!({
        "ok": true,
        "message": "analysis command sent",
        "source": source,
    }))
    .into_response()
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
        .map(|a| {
            format!(
                "[{}] {}: {}",
                a.level.to_uppercase(),
                a.event.comm,
                a.reason
            )
        })
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
        if recent_alerts.is_empty() {
            "None".to_string()
        } else {
            recent_alerts.join("\n")
        },
        if recent_events.is_empty() {
            "None".to_string()
        } else {
            recent_events.join("\n")
        },
    )
}

fn resolve_base_url_for_rig(cfg: &AiConfig) -> String {
    let raw = if !cfg.base_url.is_empty() {
        cfg.base_url.trim_end_matches('/').to_string()
    } else {
        match cfg.provider {
            AiProvider::Ollama => "http://localhost:11434".to_string(),
            AiProvider::OpenAi | AiProvider::Custom => "https://api.openai.com".to_string(),
        }
    };
    // rig's OpenAI client appends /v1 automatically; strip it if already present.
    raw.trim_end_matches("/v1").to_string()
}

/// Convert a `ChatMessage` role/content pair into a rig `Message`.
/// Returns `None` for "system" messages (handled via preamble).
fn chat_msg_to_rig(msg: &ChatMessage) -> Option<Message> {
    match msg.role.as_str() {
        "user" => Some(Message::user(msg.content.clone())),
        "assistant" => Some(Message::assistant(msg.content.clone())),
        _ => None,
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

    // Find the last user message to use as the prompt; everything before it is history.
    let last_user_idx = req.messages.iter().rposition(|m| m.role == "user");
    let Some(user_idx) = last_user_idx else {
        return (StatusCode::BAD_REQUEST, "no user message in request").into_response();
    };

    let prompt_text = req.messages[user_idx].content.clone();
    let history: Vec<Message> = req.messages[..user_idx]
        .iter()
        .filter_map(chat_msg_to_rig)
        .collect();

    let system_prompt = build_system_prompt(&shared, req.include_context).await;
    let base_url = resolve_base_url_for_rig(&cfg);

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(64);

    // Build the rig stream in a spawned task so we can return the SSE response immediately.
    tokio::spawn(async move {
        let send = |tx: &tokio::sync::mpsc::Sender<Result<Event, Infallible>>,
                    delta: String,
                    done: bool| {
            let payload = serde_json::json!({ "delta": delta, "done": done });
            let _ = tx.try_send(Ok(Event::default().data(payload.to_string())));
        };

        macro_rules! drain_stream {
            ($stream:expr) => {{
                let mut s = $stream;
                while let Some(item) = FuturesStreamExt::next(&mut s).await {
                    match item {
                        Ok(MultiTurnStreamItem::StreamAssistantItem(
                            StreamedAssistantContent::Text(t),
                        )) => {
                            send(&tx, t.text, false);
                        }
                        Ok(MultiTurnStreamItem::FinalResponse(_)) => {
                            send(&tx, String::new(), true);
                            return;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            send(&tx, format!("[stream error: {e}]"), true);
                            return;
                        }
                    }
                }
                send(&tx, String::new(), true);
            }};
        }

        match cfg.provider {
            AiProvider::Ollama => {
                let mut builder = ollama::Client::builder().api_key(Nothing);
                if !base_url.is_empty() {
                    builder = builder.base_url(&base_url);
                }
                let client = match builder.build() {
                    Ok(c) => c,
                    Err(e) => {
                        send(&tx, format!("[rig build error: {e}]"), true);
                        return;
                    }
                };
                let agent = client
                    .agent(cfg.model.as_str())
                    .preamble(&system_prompt)
                    .build();
                let stream = agent.stream_chat(&prompt_text, history).await;
                drain_stream!(stream);
            }
            AiProvider::OpenAi => {
                let client = match openai::Client::builder()
                    .api_key(cfg.api_key.trim())
                    .base_url(&base_url)
                    .build()
                {
                    Ok(c) => c,
                    Err(e) => {
                        send(&tx, format!("[rig build error: {e}]"), true);
                        return;
                    }
                };
                let agent = client
                    .agent(cfg.model.as_str())
                    .preamble(&system_prompt)
                    .build();
                let stream = agent.stream_chat(&prompt_text, history).await;
                drain_stream!(stream);
            }
            AiProvider::Custom => {
                let client = match openai::Client::builder()
                    .api_key(cfg.api_key.trim())
                    .base_url(&base_url)
                    .build()
                {
                    Ok(c) => c,
                    Err(e) => {
                        send(&tx, format!("[rig build error: {e}]"), true);
                        return;
                    }
                };
                let agent = client
                    .completions_api()
                    .agent(cfg.model.as_str())
                    .preamble(&system_prompt)
                    .build();
                let stream = agent.stream_chat(&prompt_text, history).await;
                drain_stream!(stream);
            }
        }
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
            Some(Ok::<Event, Infallible>(
                Event::default().event("alert").data(data),
            ))
        }
        Err(_) => None,
    });

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}
