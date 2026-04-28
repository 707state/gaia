use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::Parser;
use futures_util::StreamExt as FuturesStreamExt;
use log::{error, info, warn};
use rig::{
    agent::{MultiTurnStreamItem, StreamingResult},
    client::{CompletionClient, Nothing},
    completion::message::Message,
    providers::{ollama, openai},
    streaming::{StreamedAssistantContent, StreamingChat},
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{RwLock, mpsc},
};
use tokio_rusqlite::{Connection as SqliteConn, params};
use wechatbot::{BotOptions, Credentials, IncomingMessage, WeChatBot, protocol};

const DEFAULT_CONFIG: &str = "gaia.toml";
const DEFAULT_SOCKET: &str = "/tmp/gaia-ai-notify.sock";
const DEFAULT_CONTROL_SOCKET: &str = "/tmp/gaia-ai-notify-control.sock";
const RECENT_ALERT_CONTEXT: usize = 10;
const ANALYSIS_HISTORY_WINDOW_MS: i64 = 24 * 3600 * 1000;
const ANALYSIS_HISTORY_SUMMARY_LEN: usize = 500;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

struct AnalysisDb {
    conn: SqliteConn,
}

#[derive(Debug, Clone)]
struct StoredAnalysis {
    ts_ms: i64,
    source: String,
    alert_count: i64,
    content: String,
}

impl AnalysisDb {
    async fn open(path: &str) -> Result<Self> {
        let conn = SqliteConn::open(path)
            .await
            .with_context(|| format!("open analysis db at {path}"))?;
        conn.call(|c| {
            c.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 CREATE TABLE IF NOT EXISTS analysis_history (
                   id          INTEGER PRIMARY KEY AUTOINCREMENT,
                   ts_ms       INTEGER NOT NULL,
                   source      TEXT NOT NULL,
                   alert_count INTEGER NOT NULL,
                   content     TEXT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS idx_analysis_ts ON analysis_history(ts_ms);",
            )?;
            Ok(())
        })
        .await
        .context("create analysis_history table")?;
        Ok(Self { conn })
    }

    async fn insert_analysis(
        &self,
        ts_ms: i64,
        source: &str,
        alert_count: usize,
        content: &str,
    ) -> Result<()> {
        let source = source.to_string();
        let content = content.to_string();
        let alert_count = alert_count as i64;
        self.conn
            .call(move |c| {
                c.execute(
                    "INSERT INTO analysis_history (ts_ms, source, alert_count, content) VALUES (?1,?2,?3,?4)",
                    params![ts_ms, source, alert_count, content],
                )?;
                Ok(())
            })
            .await
            .context("insert analysis")?;
        Ok(())
    }

    async fn query_recent(&self, since_ms: i64) -> Result<Vec<StoredAnalysis>> {
        self.conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT ts_ms, source, alert_count, content
                     FROM analysis_history
                     WHERE ts_ms >= ?1
                     ORDER BY ts_ms ASC",
                )?;
                let rows = stmt
                    .query_map(params![since_ms], |row| {
                        Ok(StoredAnalysis {
                            ts_ms: row.get(0)?,
                            source: row.get(1)?,
                            alert_count: row.get(2)?,
                            content: row.get(3)?,
                        })
                    })?
                    .filter_map(|r| r.ok())
                    .collect();
                Ok(rows)
            })
            .await
            .context("query recent analyses")
    }
}

#[derive(Debug, Parser)]
struct Opt {
    #[arg(long, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket_path: PathBuf,
    #[arg(long, default_value = DEFAULT_CONTROL_SOCKET)]
    control_socket_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
enum AiProvider {
    #[default]
    OpenAi,
    Ollama,
    Custom,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AiRuntimeConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    provider: AiProvider,
    #[serde(default)]
    base_url: String,
    #[serde(default = "default_ai_model")]
    model: String,
    #[serde(default)]
    api_key: String,
    #[serde(default)]
    analysis_interval_hours: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct NotifyConfig {
    #[serde(default)]
    analysis_prompt: String,
    #[serde(default)]
    wechat: WechatConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct WechatConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    cred_path: String,
    #[serde(default = "default_subscribers_path")]
    subscribers_path: String,
    #[serde(default = "default_bot_name")]
    bot_name: String,
    #[serde(default = "default_status_path")]
    status_path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AiAlertNotification {
    timestamp: String,
    level: String,
    reason: String,
    event_kind: String,
    event_action: String,
    pid: u32,
    comm: String,
    detail: String,
}

#[derive(Debug)]
enum BotCommand {
    SeenUser { user_id: String, text: String },
    TriggerAnalysis { source: String },
}

#[derive(Debug, Deserialize)]
struct NotifyControlCommand {
    action: String,
    #[serde(default)]
    source: String,
}

fn default_true() -> bool {
    true
}

fn default_ai_model() -> String {
    "gpt-4o-mini".to_string()
}

fn default_bot_name() -> String {
    "ClawBot".to_string()
}

fn default_subscribers_path() -> String {
    "gaia-notify-subscribers.json".to_string()
}

fn default_status_path() -> String {
    "gaia-notify-state.json".to_string()
}

fn default_contexts_path() -> String {
    "gaia-notify-contexts.json".to_string()
}

impl Default for AiRuntimeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: AiProvider::OpenAi,
            base_url: String::new(),
            model: default_ai_model(),
            api_key: String::new(),
            analysis_interval_hours: 0,
        }
    }
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            analysis_prompt: String::new(),
            wechat: WechatConfig::default(),
        }
    }
}

impl Default for WechatConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_url: String::new(),
            cred_path: String::new(),
            subscribers_path: default_subscribers_path(),
            bot_name: default_bot_name(),
            status_path: default_status_path(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct WechatContextEntry {
    #[serde(default)]
    context_token: String,
    #[serde(default)]
    updated_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct WechatBotStatus {
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

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::parse();
    let notify_cfg = load_notify_config(&opt.config);
    let subscribers_path = resolve_sidecar_path(&opt.config, &notify_cfg.wechat.subscribers_path);
    let status_path = resolve_sidecar_path(&opt.config, &notify_cfg.wechat.status_path);
    let contexts_path = contexts_path(&opt.config);
    let initial_subscribers = load_subscribers(&subscribers_path);
    let initial_contexts = load_contexts(&contexts_path);
    info!(
        "loaded wechat subscribers: path={} count={} entries={:?}",
        subscribers_path.display(),
        initial_subscribers.len(),
        initial_subscribers,
    );
    info!(
        "loaded wechat contexts: path={} count={} users={:?}",
        contexts_path.display(),
        initial_contexts.len(),
        initial_contexts.keys().collect::<Vec<_>>(),
    );
    let subscribers = Arc::new(RwLock::new(initial_subscribers));
    let contexts = Arc::new(RwLock::new(initial_contexts));
    let recent_alerts = Arc::new(RwLock::new(VecDeque::<AiAlertNotification>::new()));

    let db_path = analysis_db_path(&opt.config);
    let analysis_db =
        Arc::new(AnalysisDb::open(db_path.to_str().unwrap_or("gaia-analysis.db")).await?);
    info!("opened analysis history db: {}", db_path.display());

    let (bot_tx, bot_rx) = mpsc::unbounded_channel::<BotCommand>();

    spawn_control_socket_server(opt.control_socket_path.clone(), bot_tx.clone());
    spawn_analysis_scheduler(opt.config.clone(), bot_tx.clone());

    if notify_cfg.wechat.enabled {
        start_bot_runtime(
            opt.config.clone(),
            notify_cfg.clone(),
            subscribers.clone(),
            contexts.clone(),
            subscribers_path.clone(),
            contexts_path.clone(),
            status_path.clone(),
            recent_alerts.clone(),
            analysis_db.clone(),
            bot_tx.clone(),
            bot_rx,
        )
        .await?;
    } else {
        info!("wechat notification runtime disabled by config");
        let no_wechat_alerts = recent_alerts.clone();
        let no_wechat_db = analysis_db.clone();
        let no_wechat_config = opt.config.clone();
        tokio::spawn(async move {
            run_bot_actor_no_wechat(no_wechat_config, no_wechat_alerts, no_wechat_db, bot_rx).await;
        });
    }

    consume_alert_socket(opt.socket_path, recent_alerts).await
}

fn load_ai_runtime_config(config_path: &Path) -> AiRuntimeConfig {
    let sidecar = ai_config_path(config_path);
    match fs::read_to_string(&sidecar) {
        Ok(raw) => toml::from_str::<AiRuntimeConfig>(&raw).unwrap_or_default(),
        Err(_) => AiRuntimeConfig::default(),
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

fn analysis_db_path(config_path: &Path) -> PathBuf {
    let stem = config_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("gaia");
    let parent = config_path.parent().unwrap_or(Path::new("."));
    parent.join(format!("{stem}-analysis.db"))
}

fn load_notify_config(config_path: &Path) -> NotifyConfig {
    let sidecar = notify_config_path(config_path);
    match fs::read_to_string(&sidecar) {
        Ok(raw) => toml::from_str::<NotifyConfig>(&raw).unwrap_or_default(),
        Err(_) => NotifyConfig::default(),
    }
}

fn notify_config_path(config_path: &Path) -> PathBuf {
    let stem = config_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("gaia");
    let parent = config_path.parent().unwrap_or(Path::new("."));
    parent.join(format!("{stem}-notify.toml"))
}

fn resolve_sidecar_path(config_path: &Path, sidecar: &str) -> PathBuf {
    let path = PathBuf::from(sidecar);
    if path.is_absolute() {
        path
    } else {
        config_path.parent().unwrap_or(Path::new(".")).join(path)
    }
}

fn load_subscribers(path: &Path) -> BTreeSet<String> {
    match fs::read_to_string(path) {
        Ok(raw) => {
            let subscribers = serde_json::from_str::<BTreeSet<String>>(&raw).unwrap_or_default();
            info!(
                "loaded subscriber file: path={} count={} entries={:?}",
                path.display(),
                subscribers.len(),
                subscribers,
            );
            subscribers
        }
        Err(err) => {
            warn!(
                "failed to read subscriber file {}, defaulting to empty set: {err:#}",
                path.display()
            );
            BTreeSet::new()
        }
    }
}

fn contexts_path(config_path: &Path) -> PathBuf {
    resolve_sidecar_path(config_path, &default_contexts_path())
}

fn load_contexts(path: &Path) -> BTreeMap<String, WechatContextEntry> {
    match fs::read_to_string(path) {
        Ok(raw) => {
            let contexts = serde_json::from_str::<BTreeMap<String, WechatContextEntry>>(&raw)
                .unwrap_or_default();
            info!(
                "loaded wechat context file: path={} count={} users={:?}",
                path.display(),
                contexts.len(),
                contexts.keys().collect::<Vec<_>>(),
            );
            contexts
        }
        Err(err) => {
            warn!(
                "failed to read wechat context file {}, defaulting to empty map: {err:#}",
                path.display()
            );
            BTreeMap::new()
        }
    }
}

fn persist_contexts(path: &Path, contexts: &BTreeMap<String, WechatContextEntry>) {
    if let Some(parent) = path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            warn!(
                "failed to create wechat context directory {}: {err:#}",
                parent.display()
            );
            return;
        }
    }
    match serde_json::to_string_pretty(contexts) {
        Ok(body) => {
            if let Err(err) = fs::write(path, body) {
                warn!(
                    "failed to persist wechat contexts {}: {err:#}",
                    path.display()
                );
            } else {
                info!(
                    "persisted wechat context file: path={} count={} users={:?}",
                    path.display(),
                    contexts.len(),
                    contexts.keys().collect::<Vec<_>>(),
                );
            }
        }
        Err(err) => warn!("failed to serialize wechat contexts: {err:#}"),
    }
}

fn persist_subscribers(path: &Path, subscribers: &BTreeSet<String>) {
    if let Some(parent) = path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            warn!(
                "failed to create subscriber directory {}: {err:#}",
                parent.display()
            );
            return;
        }
    }
    match serde_json::to_string_pretty(subscribers) {
        Ok(body) => {
            if let Err(err) = fs::write(path, body) {
                warn!("failed to persist subscribers {}: {err:#}", path.display());
            } else {
                info!(
                    "persisted subscriber file: path={} count={} entries={:?}",
                    path.display(),
                    subscribers.len(),
                    subscribers,
                );
            }
        }
        Err(err) => warn!("failed to serialize subscribers: {err:#}"),
    }
}

fn persist_wechat_status(path: &Path, status: &WechatBotStatus) {
    if let Some(parent) = path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            warn!(
                "failed to create wechat status directory {}: {err:#}",
                parent.display()
            );
            return;
        }
    }
    match serde_json::to_string_pretty(status) {
        Ok(body) => {
            if let Err(err) = fs::write(path, body) {
                warn!(
                    "failed to persist wechat status {}: {err:#}",
                    path.display()
                );
            }
        }
        Err(err) => warn!("failed to serialize wechat status: {err:#}"),
    }
}

fn current_timestamp_string() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => format!("{}.{:03}Z", d.as_secs(), d.subsec_millis()),
        Err(_) => "0.000Z".to_string(),
    }
}

fn spawn_control_socket_server(
    control_socket_path: PathBuf,
    tx: mpsc::UnboundedSender<BotCommand>,
) {
    tokio::spawn(async move {
        if let Some(parent) = control_socket_path.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                warn!(
                    "failed to create control socket directory {}: {err:#}",
                    parent.display()
                );
                return;
            }
        }
        if let Err(err) = fs::remove_file(&control_socket_path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    "failed to remove stale control socket {}: {err:#}",
                    control_socket_path.display()
                );
                return;
            }
        }

        let listener = match UnixListener::bind(&control_socket_path) {
            Ok(listener) => listener,
            Err(err) => {
                warn!(
                    "failed to bind control socket {}: {err:#}",
                    control_socket_path.display()
                );
                return;
            }
        };
        info!(
            "gaia-notify control socket listening on {}",
            control_socket_path.display()
        );

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    warn!("control socket accept failed: {err:#}");
                    continue;
                }
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stream).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let cmd = match serde_json::from_str::<NotifyControlCommand>(&line) {
                        Ok(cmd) => cmd,
                        Err(err) => {
                            warn!("invalid control command: {err:#}");
                            continue;
                        }
                    };
                    if cmd.action == "analyze_now" {
                        let source = if cmd.source.trim().is_empty() {
                            "control_socket".to_string()
                        } else {
                            cmd.source
                        };
                        let _ = tx.send(BotCommand::TriggerAnalysis { source });
                    }
                }
            });
        }
    });
}

fn spawn_analysis_scheduler(config_path: PathBuf, tx: mpsc::UnboundedSender<BotCommand>) {
    tokio::spawn(async move {
        let mut last_run: Option<Instant> = None;
        loop {
            let cfg = load_ai_runtime_config(&config_path);
            let interval_hours = cfg.analysis_interval_hours;
            if cfg.enabled && interval_hours > 0 {
                let interval = Duration::from_secs(interval_hours as u64 * 3600);
                if last_run.is_none() {
                    last_run = Some(Instant::now());
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    continue;
                }
                let should_run = last_run.map(|t| t.elapsed() >= interval).unwrap_or(false);
                if should_run {
                    last_run = Some(Instant::now());
                    let _ = tx.send(BotCommand::TriggerAnalysis {
                        source: format!("scheduler_{}h", interval_hours),
                    });
                }
            } else {
                last_run = None;
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

async fn start_bot_runtime(
    config_path: PathBuf,
    notify_cfg: NotifyConfig,
    subscribers: Arc<RwLock<BTreeSet<String>>>,
    contexts: Arc<RwLock<BTreeMap<String, WechatContextEntry>>>,
    subscribers_path: PathBuf,
    contexts_path: PathBuf,
    status_path: PathBuf,
    recent_alerts: Arc<RwLock<VecDeque<AiAlertNotification>>>,
    analysis_db: Arc<AnalysisDb>,
    tx: mpsc::UnboundedSender<BotCommand>,
    rx: mpsc::UnboundedReceiver<BotCommand>,
) -> Result<()> {
    persist_wechat_status(
        &status_path,
        &WechatBotStatus {
            enabled: true,
            logged_in: false,
            needs_qr_scan: false,
            qr_url: None,
            last_error: None,
            account_id: None,
            user_id: None,
            updated_at: Some(current_timestamp_string()),
        },
    );

    let qr_status_path = status_path.clone();
    let error_status_path = status_path.clone();
    let options = BotOptions {
        base_url: if notify_cfg.wechat.base_url.trim().is_empty() {
            None
        } else {
            Some(notify_cfg.wechat.base_url.clone())
        },
        cred_path: if notify_cfg.wechat.cred_path.trim().is_empty() {
            None
        } else {
            Some(
                resolve_sidecar_path(&config_path, &notify_cfg.wechat.cred_path)
                    .to_string_lossy()
                    .into_owned(),
            )
        },
        on_qr_url: Some(Box::new(move |url| {
            persist_wechat_status(
                &qr_status_path,
                &WechatBotStatus {
                    enabled: true,
                    logged_in: false,
                    needs_qr_scan: true,
                    qr_url: Some(url.to_string()),
                    last_error: None,
                    account_id: None,
                    user_id: None,
                    updated_at: Some(current_timestamp_string()),
                },
            );
            info!("scan this QR URL with WeChat ClawBot: {url}");
        })),
        on_error: Some(Box::new(move |err| {
            persist_wechat_status(
                &error_status_path,
                &WechatBotStatus {
                    enabled: true,
                    logged_in: false,
                    needs_qr_scan: true,
                    qr_url: None,
                    last_error: Some(err.to_string()),
                    account_id: None,
                    user_id: None,
                    updated_at: Some(current_timestamp_string()),
                },
            );
            warn!("wechatbot runtime error: {err:#}");
        })),
    };

    let bot = Arc::new(WeChatBot::new(options));
    let creds = bot.login(false).await.context("wechatbot login failed")?;
    persist_wechat_status(
        &status_path,
        &WechatBotStatus {
            enabled: true,
            logged_in: true,
            needs_qr_scan: false,
            qr_url: None,
            last_error: None,
            account_id: Some(creds.account_id.clone()),
            user_id: Some(creds.user_id.clone()),
            updated_at: Some(current_timestamp_string()),
        },
    );
    info!(
        "wechatbot logged in: account_id={} user_id={}",
        creds.account_id, creds.user_id
    );

    let message_tx = tx.clone();
    let message_contexts = contexts.clone();
    let message_contexts_path = contexts_path.clone();
    bot.on_message(Box::new(move |msg| {
        info!(
            "wechat on_message callback fired: user_id={} text={:?}",
            msg.user_id, msg.text,
        );
        persist_incoming_context(&message_contexts, &message_contexts_path, msg);
        let _ = message_tx.send(BotCommand::SeenUser {
            user_id: msg.user_id.clone(),
            text: msg.text.clone(),
        });
    }))
    .await;

    let actor_bot = bot.clone();
    tokio::spawn(async move {
        run_bot_actor(
            actor_bot,
            creds,
            config_path,
            subscribers,
            contexts,
            subscribers_path,
            contexts_path,
            recent_alerts,
            analysis_db,
            rx,
        )
        .await;
    });

    tokio::spawn(async move {
        if let Err(err) = bot.run().await {
            error!("wechatbot run loop exited: {err:#}");
        }
    });

    Ok(())
}

async fn run_bot_actor(
    bot: Arc<WeChatBot>,
    creds: Credentials,
    config_path: PathBuf,
    subscribers: Arc<RwLock<BTreeSet<String>>>,
    contexts: Arc<RwLock<BTreeMap<String, WechatContextEntry>>>,
    subscribers_path: PathBuf,
    _contexts_path: PathBuf,
    recent_alerts: Arc<RwLock<VecDeque<AiAlertNotification>>>,
    analysis_db: Arc<AnalysisDb>,
    mut rx: mpsc::UnboundedReceiver<BotCommand>,
) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            BotCommand::SeenUser { user_id, text } => {
                info!(
                    "received wechat user message: user_id={} raw_text={:?}",
                    user_id, text,
                );
                let lowered = text.trim().to_ascii_lowercase();
                if matches!(
                    lowered.as_str(),
                    "/analyze" | "analyze" | "分析" | "立即分析"
                ) {
                    info!(
                        "processing manual analysis command from user_id={}",
                        user_id
                    );
                    let mut guard = subscribers.write().await;
                    let inserted = guard.insert(user_id.clone());
                    info!(
                        "updated subscriber set from analysis command: inserted={} count={} entries={:?}",
                        inserted,
                        guard.len(),
                        *guard,
                    );
                    if inserted {
                        persist_subscribers(&subscribers_path, &guard);
                    }
                    drop(guard);

                    match bot
                        .send(
                            user_id.as_str(),
                            "已收到分析请求，正在结合历史记录分析，结果会通过微信推送。",
                        )
                        .await
                    {
                        Ok(_) => info!("sent analysis ack to user_id={}", user_id),
                        Err(err) => {
                            warn!("failed to send analysis ack to {user_id}: {err:#}");
                        }
                    }
                    let ai_cfg = load_ai_runtime_config(&config_path);
                    let notify_cfg = load_notify_config(&config_path);
                    let since_ms = now_ms() - ANALYSIS_HISTORY_WINDOW_MS;
                    let history = analysis_db
                        .query_recent(since_ms)
                        .await
                        .unwrap_or_else(|err| {
                            warn!("failed to query analysis history: {err:#}");
                            Vec::new()
                        });
                    info!(
                        "loaded analysis history for wechat query: user_id={} history_count={} since_ms={}",
                        user_id,
                        history.len(),
                        since_ms,
                    );
                    let analysis = match analyze_with_history(
                        &ai_cfg,
                        &notify_cfg.analysis_prompt,
                        &recent_alerts,
                        &history,
                        "wechat_command",
                    )
                    .await
                    {
                        Ok(text) => text,
                        Err(err) => {
                            warn!(
                                "AI analysis with history failed, falling back to summary: {err:#}"
                            );
                            fallback_summary_from_recent(&recent_alerts).await
                        }
                    };
                    info!(
                        "manual analysis ready for broadcast: user_id={} analysis_len={}",
                        user_id,
                        analysis.len(),
                    );
                    broadcast_to_subscribers(
                        &creds,
                        &subscribers,
                        &contexts,
                        "wechat_command",
                        &analysis,
                    )
                    .await;
                    continue;
                }
                let reply = if matches!(lowered.as_str(), "/unsubscribe" | "unsubscribe" | "stop") {
                    info!("processing unsubscribe command from user_id={}", user_id);
                    let mut guard = subscribers.write().await;
                    let removed = guard.remove(&user_id);
                    info!(
                        "updated subscriber set from unsubscribe command: removed={} count={} entries={:?}",
                        removed,
                        guard.len(),
                        *guard,
                    );
                    if removed {
                        persist_subscribers(&subscribers_path, &guard);
                        "已取消订阅高危告警推送。".to_string()
                    } else {
                        "当前未处于订阅状态。".to_string()
                    }
                } else {
                    info!(
                        "processing normal/status command from user_id={} lowered={}",
                        user_id, lowered
                    );
                    let mut guard = subscribers.write().await;
                    let inserted = guard.insert(user_id.clone());
                    info!(
                        "updated subscriber set from normal/status command: inserted={} count={} entries={:?}",
                        inserted,
                        guard.len(),
                        *guard,
                    );
                    if inserted {
                        persist_subscribers(&subscribers_path, &guard);
                    }
                    if matches!(lowered.as_str(), "/status" | "status") {
                        format!(
                            "当前已订阅。订阅用户数：{}，已记录会话上下文数：{}",
                            guard.len(),
                            contexts.read().await.len()
                        )
                    } else {
                        "已接入 GAIA 高危告警推送。后续 WebUI 手动分析与定时分析会主动推送到微信。发送 /unsubscribe 可取消订阅，发送 /status 查看状态。".to_string()
                    }
                };

                match bot.send(user_id.as_str(), reply.as_str()).await {
                    Ok(_) => info!(
                        "sent control reply to user_id={} reply_len={}",
                        user_id,
                        reply.len(),
                    ),
                    Err(err) => warn!("failed to send control reply to {user_id}: {err:#}"),
                }
            }
            BotCommand::TriggerAnalysis { source } => {
                info!(
                    "processing trigger analysis command (save-only): source={}",
                    source
                );
                let ai_cfg = load_ai_runtime_config(&config_path);
                let notify_cfg = load_notify_config(&config_path);
                let alert_count = recent_alerts.read().await.len();
                let analysis = match analyze_recent_alerts(
                    &ai_cfg,
                    &notify_cfg.analysis_prompt,
                    &recent_alerts,
                    &source,
                )
                .await
                {
                    Ok(text) => text,
                    Err(err) => {
                        warn!("AI analysis failed, falling back to summary: {err:#}");
                        fallback_summary_from_recent(&recent_alerts).await
                    }
                };
                let ts = now_ms();
                if let Err(err) = analysis_db
                    .insert_analysis(ts, &source, alert_count, &analysis)
                    .await
                {
                    warn!(
                        "failed to save analysis to db: source={} err={:#}",
                        source, err
                    );
                } else {
                    info!(
                        "saved analysis to db: source={} alert_count={} analysis_len={}",
                        source,
                        alert_count,
                        analysis.len(),
                    );
                }
            }
        }
    }
}

async fn consume_alert_socket(
    socket_path: PathBuf,
    recent_alerts: Arc<RwLock<VecDeque<AiAlertNotification>>>,
) -> Result<()> {
    loop {
        match UnixStream::connect(&socket_path).await {
            Ok(stream) => {
                info!("connected to GAIA notify socket {}", socket_path.display());
                let mut lines = BufReader::new(stream).lines();
                while let Some(line) = lines.next_line().await.context("read notify socket")? {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let alert = match serde_json::from_str::<AiAlertNotification>(&line) {
                        Ok(alert) => alert,
                        Err(err) => {
                            warn!("invalid alert payload: {err:#}");
                            continue;
                        }
                    };

                    {
                        let mut guard = recent_alerts.write().await;
                        guard.push_front(alert.clone());
                        while guard.len() > RECENT_ALERT_CONTEXT {
                            guard.pop_back();
                        }
                    }
                }
                warn!("notify socket closed, retrying");
            }
            Err(err) => warn!(
                "connect notify socket {} failed: {err:#}",
                socket_path.display()
            ),
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn analyze_recent_alerts(
    cfg: &AiRuntimeConfig,
    analysis_prompt: &str,
    recent_alerts: &Arc<RwLock<VecDeque<AiAlertNotification>>>,
    source: &str,
) -> Result<String> {
    info!(
        "starting AI alert analysis: source={source} provider={:?} model={} enabled={} base_url={} interval_hours={}",
        cfg.provider,
        cfg.model,
        cfg.enabled,
        redact_url_for_log(&cfg.base_url),
        cfg.analysis_interval_hours,
    );
    if !cfg.enabled {
        return Ok(fallback_summary_from_recent(recent_alerts).await);
    }

    let recent_snapshot = {
        let guard = recent_alerts.read().await;
        guard
            .iter()
            .take(RECENT_ALERT_CONTEXT)
            .cloned()
            .collect::<Vec<_>>()
    };
    info!(
        "AI alert analysis context prepared: source={source} alert_count={} system_prompt_len={} custom_prompt_len={}",
        recent_snapshot.len(),
        0,
        analysis_prompt.trim().len(),
    );
    let recent_lines = recent_snapshot
        .iter()
        .map(|item| {
            format!(
                "[{}] level={} kind={} action={} pid={} comm={} reason={} detail={}",
                item.timestamp,
                item.level,
                item.event_kind,
                item.event_action,
                item.pid,
                item.comm,
                item.reason,
                item.detail,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let mut system_prompt = String::from(
        "You are GAIA's incident triage assistant. Analyze the recent high-risk alerts as a batch. \
Give a compact operator-facing response in Simplified Chinese with exactly three sections: \
`风险判断`, `依据`, `处置建议`. Be specific and avoid generic filler.",
    );
    if !analysis_prompt.trim().is_empty() {
        system_prompt.push_str("\n\n");
        system_prompt.push_str(analysis_prompt.trim());
    }

    let user_prompt = format!(
        "分析触发来源: {}\n\
最近高危告警总数: {}\n\n\
最近相关高危告警:\n{}",
        source,
        recent_snapshot.len(),
        if recent_lines.is_empty() {
            "None".to_string()
        } else {
            recent_lines
        }
    );
    info!(
        "AI alert analysis prompts built: source={source} system_prompt_len={} user_prompt_len={}",
        system_prompt.len(),
        user_prompt.len(),
    );

    let content = run_llm_analysis_with_rig(cfg, &system_prompt, &user_prompt).await?;

    if content.is_empty() {
        anyhow::bail!("empty LLM response");
    }

    Ok(format!(
        "GAIA 高危告警批量分析\n\n触发来源: {}\n告警数量: {}\n\n{}",
        source,
        recent_snapshot.len(),
        content
    ))
}

async fn analyze_with_history(
    cfg: &AiRuntimeConfig,
    analysis_prompt: &str,
    recent_alerts: &Arc<RwLock<VecDeque<AiAlertNotification>>>,
    history: &[StoredAnalysis],
    source: &str,
) -> Result<String> {
    if !cfg.enabled {
        return Ok(fallback_summary_from_recent(recent_alerts).await);
    }

    let recent_snapshot = {
        let guard = recent_alerts.read().await;
        guard
            .iter()
            .take(RECENT_ALERT_CONTEXT)
            .cloned()
            .collect::<Vec<_>>()
    };

    let recent_lines = recent_snapshot
        .iter()
        .map(|item| {
            format!(
                "[{}] level={} kind={} action={} pid={} comm={} reason={} detail={}",
                item.timestamp,
                item.level,
                item.event_kind,
                item.event_action,
                item.pid,
                item.comm,
                item.reason,
                item.detail,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let mut system_prompt = String::from(
        "You are GAIA's incident triage assistant. Analyze the recent high-risk alerts as a batch, \
taking into account the historical analysis records from the past 24 hours. \
Give a compact operator-facing response in Simplified Chinese with exactly three sections: \
`风险判断`, `依据`, `处置建议`. Be specific and avoid generic filler.",
    );
    if !analysis_prompt.trim().is_empty() {
        system_prompt.push_str("\n\n");
        system_prompt.push_str(analysis_prompt.trim());
    }

    let history_section = if history.is_empty() {
        "过去 24 小时内无历史分析记录。".to_string()
    } else {
        let entries = history
            .iter()
            .map(|h| {
                let ts_secs = h.ts_ms / 1000;
                let summary = if h.content.len() > ANALYSIS_HISTORY_SUMMARY_LEN {
                    format!("{}…", &h.content[..ANALYSIS_HISTORY_SUMMARY_LEN])
                } else {
                    h.content.clone()
                };
                format!(
                    "[ts={}] 来源={} 告警数={}\n{}",
                    ts_secs, h.source, h.alert_count, summary
                )
            })
            .collect::<Vec<_>>()
            .join("\n---\n");
        format!(
            "过去 24 小时内共 {} 次分析记录：\n{}",
            history.len(),
            entries
        )
    };

    let user_prompt = format!(
        "查询来源: {}\n\
最近高危告警总数: {}\n\n\
最近相关高危告警:\n{}\n\n\
历史分析参考:\n{}",
        source,
        recent_snapshot.len(),
        if recent_lines.is_empty() {
            "None".to_string()
        } else {
            recent_lines
        },
        history_section,
    );

    info!(
        "AI analysis with history: source={source} alert_count={} history_count={} user_prompt_len={}",
        recent_snapshot.len(),
        history.len(),
        user_prompt.len(),
    );

    let content = run_llm_analysis_with_rig(cfg, &system_prompt, &user_prompt).await?;

    if content.is_empty() {
        anyhow::bail!("empty LLM response");
    }

    Ok(format!(
        "GAIA 综合分析（含 24h 历史）\n\n查询来源: {}\n当前告警数: {}\n历史分析条数: {}\n\n{}",
        source,
        recent_snapshot.len(),
        history.len(),
        content
    ))
}

async fn run_llm_analysis_with_rig(
    cfg: &AiRuntimeConfig,
    system_prompt: &str,
    user_prompt: &str,
) -> Result<String> {
    let resolved_base_url = resolve_base_url(cfg);
    match cfg.provider {
        AiProvider::Ollama => {
            info!(
                "building rig ollama client: model={} base_url={} system_prompt_len={} user_prompt_len={}",
                cfg.model,
                resolved_base_url,
                system_prompt.len(),
                user_prompt.len(),
            );
            let mut builder = ollama::Client::builder().api_key(Nothing);
            if !cfg.base_url.trim().is_empty() {
                builder = builder.base_url(&resolved_base_url);
            }
            let client = builder.build().context("build rig ollama client failed")?;
            let agent = client
                .agent(cfg.model.as_str())
                .preamble(system_prompt)
                .build();
            info!("dispatching rig ollama stream_chat request");
            let stream = agent.stream_chat(user_prompt, Vec::<Message>::new()).await;
            collect_streamed_response(stream, "rig ollama chat failed").await
        }
        AiProvider::OpenAi => {
            info!(
                "building rig openai responses client: model={} base_url={} request_path=/v1/responses system_prompt_len={} user_prompt_len={}",
                cfg.model,
                resolved_base_url,
                system_prompt.len(),
                user_prompt.len(),
            );
            let client = openai::Client::builder()
                .api_key(cfg.api_key.trim())
                .base_url(&resolved_base_url)
                .build()
                .context("build rig openai responses client failed")?;
            let agent = client
                .agent(cfg.model.as_str())
                .preamble(system_prompt)
                .build();
            info!("dispatching rig openai responses stream_chat request");
            let stream = agent.stream_chat(user_prompt, Vec::<Message>::new()).await;
            collect_streamed_response(stream, "rig openai responses chat failed").await
        }
        AiProvider::Custom => {
            info!(
                "building rig openai-compatible completions client: model={} base_url={} request_path=/v1/chat/completions system_prompt_len={} user_prompt_len={}",
                cfg.model,
                resolved_base_url,
                system_prompt.len(),
                user_prompt.len(),
            );
            let client = openai::Client::builder()
                .api_key(cfg.api_key.trim())
                .base_url(&resolved_base_url)
                .build()
                .context("build rig openai-compatible client failed")?
                .completions_api();
            let agent = client
                .agent(cfg.model.as_str())
                .preamble(system_prompt)
                .build();
            info!("dispatching rig openai-compatible completions stream_chat request");
            let stream = agent.stream_chat(user_prompt, Vec::<Message>::new()).await;
            collect_streamed_response(stream, "rig openai-compatible chat failed").await
        }
    }
}

async fn collect_streamed_response<R>(
    mut stream: StreamingResult<R>,
    err_ctx: &'static str,
) -> Result<String>
where
    R: Clone + Unpin + rig::completion::GetTokenUsage,
{
    let mut text = String::new();
    let mut chunk_count = 0usize;
    while let Some(item) = FuturesStreamExt::next(&mut stream).await {
        match item.context(err_ctx)? {
            MultiTurnStreamItem::StreamAssistantItem(StreamedAssistantContent::Text(t)) => {
                chunk_count += 1;
                info!(
                    "LLM text chunk received: err_ctx={} chunk_index={} chunk_len={}",
                    err_ctx,
                    chunk_count,
                    t.text.len(),
                );
                text.push_str(&t.text);
            }
            MultiTurnStreamItem::StreamAssistantItem(StreamedAssistantContent::Reasoning(r)) => {
                info!(
                    "LLM reasoning chunk received: err_ctx={} content_blocks={}",
                    err_ctx,
                    r.content.len(),
                );
            }
            MultiTurnStreamItem::StreamAssistantItem(
                StreamedAssistantContent::ReasoningDelta { reasoning, .. },
            ) => {
                info!(
                    "LLM reasoning delta received: err_ctx={} chunk_len={}",
                    err_ctx,
                    reasoning.len(),
                );
            }
            MultiTurnStreamItem::StreamAssistantItem(StreamedAssistantContent::ToolCall {
                tool_call,
                ..
            }) => {
                warn!(
                    "LLM unexpectedly emitted tool call during notify analysis: err_ctx={} tool_name={}",
                    err_ctx, tool_call.function.name,
                );
            }
            MultiTurnStreamItem::StreamAssistantItem(StreamedAssistantContent::ToolCallDelta {
                id,
                ..
            }) => {
                warn!(
                    "LLM unexpectedly emitted tool call delta during notify analysis: err_ctx={} tool_call_id={}",
                    err_ctx, id,
                );
            }
            MultiTurnStreamItem::StreamAssistantItem(StreamedAssistantContent::Final(_)) => {
                info!(
                    "LLM stream final usage marker received: err_ctx={}",
                    err_ctx
                );
            }
            MultiTurnStreamItem::StreamUserItem(_) => {
                warn!(
                    "LLM stream produced unexpected user item during notify analysis: err_ctx={}",
                    err_ctx,
                );
            }
            MultiTurnStreamItem::FinalResponse(final_response) => {
                if text.is_empty() {
                    text.push_str(final_response.response());
                }
                info!(
                    "LLM final response received: err_ctx={} aggregated_text_len={} usage={:?}",
                    err_ctx,
                    text.len(),
                    final_response.usage(),
                );
                break;
            }
            _ => {
                warn!(
                    "LLM stream produced unhandled item variant during notify analysis: err_ctx={}",
                    err_ctx,
                );
            }
        }
    }
    info!(
        "LLM stream finished: err_ctx={} total_text_len={} total_text_chunks={}",
        err_ctx,
        text.len(),
        chunk_count,
    );
    Ok(text)
}

fn redact_url_for_log(raw: &str) -> String {
    if raw.trim().is_empty() {
        return "<default>".to_string();
    }
    raw.trim().to_string()
}

fn persist_incoming_context(
    contexts: &Arc<RwLock<BTreeMap<String, WechatContextEntry>>>,
    contexts_path: &Path,
    msg: &IncomingMessage,
) {
    if msg.context_token().is_empty() {
        warn!(
            "incoming wechat message missing context token: user_id={} text={:?}",
            msg.user_id, msg.text,
        );
        return;
    }

    let user_id = msg.user_id.clone();
    let context_token = msg.context_token().to_string();
    let updated_at = Some(current_timestamp_string());
    let contexts = Arc::clone(contexts);
    let path = contexts_path.to_path_buf();
    tokio::spawn(async move {
        let snapshot = {
            let mut guard = contexts.write().await;
            guard.insert(
                user_id.clone(),
                WechatContextEntry {
                    context_token,
                    updated_at,
                },
            );
            info!(
                "updated wechat context cache: user_id={} count={} users={:?}",
                user_id,
                guard.len(),
                guard.keys().collect::<Vec<_>>(),
            );
            guard.clone()
        };
        persist_contexts(&path, &snapshot);
    });
}

async fn send_wechat_text_via_context(
    creds: &Credentials,
    user_id: &str,
    context_token: &str,
    text: &str,
) -> Result<()> {
    let client = wechatbot::protocol::ILinkClient::new();
    for chunk in split_wechat_text(text, 4000) {
        let msg = protocol::build_text_message(user_id, context_token, &chunk);
        client
            .send_message(&creds.base_url, &creds.token, &msg)
            .await
            .with_context(|| format!("send wechat message failed for {user_id}"))?;
    }
    Ok(())
}

async fn send_wechat_text_direct(creds: &Credentials, user_id: &str, text: &str) -> Result<()> {
    let client = wechatbot::protocol::ILinkClient::new();
    for chunk in split_wechat_text(text, 4000) {
        let msg = protocol::build_text_message(user_id, "", &chunk);
        client
            .send_message(&creds.base_url, &creds.token, &msg)
            .await
            .with_context(|| format!("send direct wechat message failed for {user_id}"))?;
    }
    Ok(())
}

fn split_wechat_text(text: &str, limit: usize) -> Vec<String> {
    if text.len() <= limit {
        return vec![text.to_string()];
    }
    let mut chunks = Vec::new();
    let mut remaining = text;
    while !remaining.is_empty() {
        if remaining.len() <= limit {
            chunks.push(remaining.to_string());
            break;
        }
        let window = &remaining[..limit];
        let cut = window
            .rfind("\n\n")
            .filter(|&i| i > limit * 3 / 10)
            .map(|i| i + 2)
            .or_else(|| {
                window
                    .rfind('\n')
                    .filter(|&i| i > limit * 3 / 10)
                    .map(|i| i + 1)
            })
            .or_else(|| {
                window
                    .rfind(' ')
                    .filter(|&i| i > limit * 3 / 10)
                    .map(|i| i + 1)
            })
            .unwrap_or(limit);
        chunks.push(remaining[..cut].to_string());
        remaining = &remaining[cut..];
    }
    chunks
}

fn resolve_base_url(cfg: &AiRuntimeConfig) -> String {
    let raw = if !cfg.base_url.trim().is_empty() {
        cfg.base_url.trim_end_matches('/').to_string()
    } else {
        match cfg.provider {
            AiProvider::Ollama => "http://localhost:11434".to_string(),
            AiProvider::OpenAi | AiProvider::Custom => "https://api.openai.com".to_string(),
        }
    };
    // rig appends /v1 automatically; strip it if already present in base_url.
    raw.trim_end_matches("/v1").to_string()
}

async fn fallback_summary_from_recent(
    recent_alerts: &Arc<RwLock<VecDeque<AiAlertNotification>>>,
) -> String {
    let snapshot = {
        let guard = recent_alerts.read().await;
        guard
            .iter()
            .take(RECENT_ALERT_CONTEXT)
            .cloned()
            .collect::<Vec<_>>()
    };
    if snapshot.is_empty() {
        return "GAIA 定时/手动分析\n\n风险判断\n当前没有可供分析的高危告警。\n\n依据\n最近缓存的高危告警为空。\n\n处置建议\n继续观察，如需主动巡检可等待新告警或检查采集链路。".to_string();
    }

    let top = &snapshot[0];
    format!(
        "GAIA 高危告警汇总\n\n风险判断\n最近存在 {} 条高危告警，最新一条为 {} 级别，建议人工复核。\n\n依据\n最新告警时间: {}\n类型: {} / {}\n进程: {} (pid={})\n原因: {}\n详情: {}\n\n处置建议\n1. 优先核查最新高危告警对应进程及父进程链。\n2. 结合最近 {} 条高危告警确认是否为同一攻击链。\n3. 如确认为攻击行为，先隔离主机或进程，再补充取证。",
        snapshot.len(),
        top.level.to_uppercase(),
        top.timestamp,
        top.event_kind,
        top.event_action,
        top.comm,
        top.pid,
        top.reason,
        top.detail,
        snapshot.len()
    )
}

async fn broadcast_to_subscribers(
    creds: &Credentials,
    subscribers: &Arc<RwLock<BTreeSet<String>>>,
    contexts: &Arc<RwLock<BTreeMap<String, WechatContextEntry>>>,
    source: &str,
    text: &str,
) {
    let mut targets: Vec<String> = {
        let guard = subscribers.read().await;
        guard.iter().cloned().collect()
    };
    let context_snapshot = {
        let guard = contexts.read().await;
        guard.clone()
    };
    if targets.is_empty() {
        info!(
            "wechat broadcast has no subscribers, falling back to logged-in wechat user: source={} fallback_user={}",
            source, creds.user_id,
        );
        if !creds.user_id.trim().is_empty() {
            targets.push(creds.user_id.clone());
        }
    }
    info!(
        "starting wechat broadcast: source={} target_count={} targets={:?} context_count={} text_len={}",
        source,
        targets.len(),
        targets,
        context_snapshot.len(),
        text.len(),
    );
    if targets.is_empty() {
        warn!(
            "wechat broadcast skipped because there is no subscriber and no logged-in fallback user: source={}",
            source,
        );
        return;
    }
    for user_id in targets {
        if let Some(entry) = context_snapshot.get(&user_id) {
            info!(
                "sending wechat broadcast message via persisted context: source={} target={} text_len={} context_updated_at={:?}",
                source,
                user_id,
                text.len(),
                entry.updated_at,
            );
            match send_wechat_text_via_context(creds, &user_id, &entry.context_token, text).await {
                Ok(_) => {
                    info!(
                        "wechat broadcast send succeeded via persisted context: source={} target={}",
                        source, user_id
                    );
                    continue;
                }
                Err(err) => warn!(
                    "send via persisted context failed, trying direct push: source={} target={} err={:#}",
                    source, user_id, err
                ),
            }
        } else {
            warn!(
                "no persisted context for target, trying direct push: source={} target={}",
                source, user_id,
            );
        }

        match send_wechat_text_direct(creds, &user_id, text).await {
            Ok(_) => info!(
                "wechat broadcast direct send succeeded: source={} target={}",
                source, user_id
            ),
            Err(err) => warn!("failed to send alert to {user_id}: {err:#}"),
        }
    }
}

// Handles TriggerAnalysis commands when WeChat is disabled — saves analysis to DB only.
async fn run_bot_actor_no_wechat(
    config_path: PathBuf,
    recent_alerts: Arc<RwLock<VecDeque<AiAlertNotification>>>,
    analysis_db: Arc<AnalysisDb>,
    mut rx: mpsc::UnboundedReceiver<BotCommand>,
) {
    while let Some(cmd) = rx.recv().await {
        if let BotCommand::TriggerAnalysis { source } = cmd {
            info!(
                "processing trigger analysis command (no-wechat save-only): source={}",
                source
            );
            let ai_cfg = load_ai_runtime_config(&config_path);
            let notify_cfg = load_notify_config(&config_path);
            let alert_count = recent_alerts.read().await.len();
            let analysis = match analyze_recent_alerts(
                &ai_cfg,
                &notify_cfg.analysis_prompt,
                &recent_alerts,
                &source,
            )
            .await
            {
                Ok(text) => text,
                Err(err) => {
                    warn!("AI analysis failed (no-wechat), falling back to summary: {err:#}");
                    fallback_summary_from_recent(&recent_alerts).await
                }
            };
            let ts = now_ms();
            if let Err(err) = analysis_db
                .insert_analysis(ts, &source, alert_count, &analysis)
                .await
            {
                warn!(
                    "failed to save analysis to db (no-wechat): source={} err={:#}",
                    source, err
                );
            } else {
                info!(
                    "saved analysis to db (no-wechat): source={} alert_count={} analysis_len={}",
                    source,
                    alert_count,
                    analysis.len(),
                );
            }
        }
    }
}
