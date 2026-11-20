pub mod approval;
pub mod config;
pub mod crypto;
pub mod drive;
pub mod mcp;
pub mod media;
pub mod oauth;
pub mod policy;
pub mod runner;
pub mod ssrf;
pub mod store;
pub mod tailscale;

use crate::approval::approval_router;
use crate::config::{load_or_init, save_config};
use crate::crypto::{hash_pin, random_pin};
use crate::drive::{spawn_drive_watcher, DriveManager, DriveSyncStatus};
use crate::mcp::{mcp_delete, mcp_get, mcp_post, HttpState};
use crate::oauth::{esc_html, oauth_router, origin_of};
use crate::policy::Policy;
use crate::store::{AccessRequest, AuditEvent, Grant, GrantKind, GrantMode, Store};
use crate::tailscale::TailscaleStatus;
use axum::{
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware,
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, State as TauriState, WindowEvent,
};
use tokio::sync::RwLock;
use tower_http::limit::RequestBodyLimitLayer;

pub struct AppCtx {
    pub store: Arc<RwLock<Store>>,
    pub drive: Arc<DriveManager>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardSnapshot {
    pub running: bool,
    pub paused: bool,
    pub host: String,
    pub port: u16,
    pub workspace: String,
    pub programs: Vec<String>,
    pub pairing_open: bool,
    pub pairing_remaining_secs: i64,
    pub ephem_display_pin: Option<String>,
    pub client_count: usize,
    pub clients: Vec<ClientSummary>,
    pub pending_requests: Vec<AccessRequest>,
    pub active_grants: Vec<Grant>,
    pub recent_audit: Vec<AuditEvent>,
    pub tailscale: TailscaleStatus,
    pub drive: DriveSyncStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSummary {
    pub client_id: String,
    pub client_name: String,
    pub created_at: String,
}

async fn security_headers(
    req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Response {
    let is_https = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("https"))
        .unwrap_or(false);
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    if is_https {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=86400"),
        );
    }
    res
}

async fn root_page(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Html<String> {
    let st = state.store.read().await;
    let origin = origin_of(&headers, &st);
    let badge_color = if st.paused { "#f87171" } else { "#4ade80" };
    let badge_text = if st.paused { "PAUSED" } else { "RUNNING" };
    crate::oauth::oauth_page(
        "Gemini Local Bridge",
        &format!(
            r#"<h1>Local Bridge Status</h1>
<p>All code, files, and execution remain strictly on this Windows PC.</p>
<div class="card">
  <div class="kv"><div class="k">Engine</div><div class="mono" style="color:{badge_color};font-weight:700">● {badge_text}</div></div>
  <div class="kv"><div class="k">MCP Endpoint</div><div class="mono">{}/mcp</div></div>
  <div class="kv"><div class="k">Remote Approvals</div><div class="mono"><a href="/approve" style="color:#38bdf8">{}/approve</a></div></div>
</div>"#,
            esc_html(&origin),
            esc_html(&origin)
        ),
    )
}

async fn healthz(State(state): State<HttpState>) -> Json<serde_json::Value> {
    let st = state.store.read().await;
    let pol = Policy::from_config(&st.cfg);
    Json(serde_json::json!({
        "ok": !st.paused,
        "paused": st.paused,
        "name": "gemini-local-bridge",
        "version": "2.0.0",
        "workspace": st.cfg.workspace,
        "programs": pol.program_names().len(),
        "pending": st.pending_requests().len(),
        "pairingOpen": st.is_pairing_open()
    }))
}

/// Safe temporary file share endpoint:
/// - Strict `Content-Security-Policy: default-src 'none'; sandbox` prevents XSS on bridge origin.
/// - Only verified raster images are served inline; everything else (HTML, SVG, JS, etc.) is forced attachment!
async fn share_get(
    State(state): State<HttpState>,
    AxumPath(token): AxumPath<String>,
) -> Response {
    let item = {
        let mut st = state.store.write().await;
        st.get_share(&token)
    };
    let Some(item) = item else {
        return (
            StatusCode::NOT_FOUND,
            "Link expired or unknown. Ask the bridge for a new one.",
        )
            .into_response();
    };
    let path = Path::new(&item.file);
    let Ok(bytes) = std::fs::read(path) else {
        return (StatusCode::NOT_FOUND, "File no longer exists.").into_response();
    };

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let (mime, inline) = match ext.as_str() {
        "png" => ("image/png", true),
        "jpg" | "jpeg" => ("image/jpeg", true),
        "gif" => ("image/gif", true),
        "webp" => ("image/webp", true),
        "bmp" => ("image/bmp", true),
        "avif" => ("image/avif", true),
        _ => ("application/octet-stream", false),
    };

    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("download")
        .replace('"', "");
    let disp = if inline {
        format!(r#"inline; filename="{fname}""#)
    } else {
        format!(r#"attachment; filename="{fname}""#)
    };

    state.store.write().await.audit(
        "share_fetched",
        serde_json::json!({ "file": item.file }),
    );

    (
        [
            (header::CONTENT_TYPE, mime.to_string()),
            (header::CONTENT_DISPOSITION, disp),
            (header::CACHE_CONTROL, "no-store".to_string()),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; sandbox".to_string(),
            ),
            (
                header::HeaderName::from_static("x-robots-tag"),
                "noindex, nofollow".to_string(),
            ),
        ],
        bytes,
    )
        .into_response()
}

pub fn build_http_router(store: Arc<RwLock<Store>>, drive: Arc<DriveManager>) -> Router {
    let http_state = HttpState {
        store: store.clone(),
        drive,
    };
    let core = Router::new()
        .route("/", get(root_page))
        .route("/healthz", get(healthz))
        .route("/share/{token}", get(share_get))
        .route(
            "/mcp",
            axum::routing::post(mcp_post)
                .get(mcp_get)
                .delete(mcp_delete),
        )
        .with_state(http_state);

    Router::new()
        .merge(core)
        .merge(oauth_router(store.clone()))
        .merge(approval_router(store))
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024))
        .layer(middleware::from_fn(security_headers))
}

// ---------------------------------------------------------------------------
// Tauri Desktop IPC Commands
// ---------------------------------------------------------------------------

#[tauri::command]
async fn get_dashboard(ctx: TauriState<'_, AppCtx>) -> Result<DashboardSnapshot, String> {
    let (
        paused,
        host,
        port,
        workspace,
        programs,
        pairing_open,
        pairing_remaining_secs,
        ephem_display_pin,
        clients,
        pending_requests,
        active_grants,
        recent_audit,
        cfg_clone,
    ) = {
        let st = ctx.store.read().await;
        let pol = Policy::from_config(&st.cfg);
        let mut clients: Vec<ClientSummary> = st
            .clients
            .values()
            .map(|c| ClientSummary {
                client_id: c.client_id.clone(),
                client_name: c.client_name.clone(),
                created_at: c.created_at.clone(),
            })
            .collect();
        clients.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        let audit: Vec<AuditEvent> = st.audit_ring.iter().rev().take(60).cloned().collect();
        (
            st.paused,
            st.cfg.host.clone(),
            st.cfg.port,
            st.cfg.workspace.clone(),
            pol.program_names(),
            st.is_pairing_open(),
            st.pairing_remaining_secs(),
            st.ephem_display_pin.clone(),
            clients,
            st.pending_requests(),
            st.active_grants(),
            audit,
            st.cfg.clone(),
        )
    };

    let ts = tokio::task::spawn_blocking(move || tailscale::get_status(port))
        .await
        .map_err(|e| e.to_string())?;
    let drive_st = ctx.drive.status(&cfg_clone).await;

    Ok(DashboardSnapshot {
        running: true,
        paused,
        host,
        port,
        workspace,
        programs,
        pairing_open,
        pairing_remaining_secs,
        ephem_display_pin,
        client_count: clients.len(),
        clients,
        pending_requests,
        active_grants,
        recent_audit,
        tailscale: ts,
        drive: drive_st,
    })
}

#[tauri::command]
async fn set_paused(ctx: TauriState<'_, AppCtx>, paused: bool) -> Result<(), String> {
    let mut st = ctx.store.write().await;
    st.paused = paused;
    st.audit(
        if paused { "bridge_paused" } else { "bridge_resumed" },
        serde_json::json!({}),
    );
    Ok(())
}

#[tauri::command]
async fn set_pairing(ctx: TauriState<'_, AppCtx>, open: bool, minutes: Option<i64>) -> Result<(), String> {
    let mut st = ctx.store.write().await;
    if open {
        st.enable_pairing(minutes.unwrap_or(5));
    } else {
        st.disable_pairing();
    }
    Ok(())
}

#[tauri::command]
async fn rotate_pin(ctx: TauriState<'_, AppCtx>, custom_pin: Option<String>) -> Result<String, String> {
    let new_pin = match custom_pin {
        Some(p) => {
            let trimmed = p.trim().to_string();
            if trimmed.len() < 6 || trimmed.len() > 16 || !trimmed.chars().all(|c| c.is_ascii_digit()) {
                return Err("PIN must be 6-16 digits.".into());
            }
            trimmed
        }
        None => random_pin(),
    };
    let hashed = hash_pin(&new_pin)?;
    let mut st = ctx.store.write().await;
    st.cfg.pin_hash = hashed;
    save_config(&st.cfg)?;
    st.ephem_display_pin = Some(new_pin.clone());
    st.audit("pin_rotated", serde_json::json!({}));
    Ok(new_pin)
}

#[tauri::command]
async fn dismiss_display_pin(ctx: TauriState<'_, AppCtx>) -> Result<(), String> {
    ctx.store.write().await.ephem_display_pin = None;
    Ok(())
}

#[tauri::command]
async fn decide_access_request(
    ctx: TauriState<'_, AppCtx>,
    id: String,
    decision: String,
) -> Result<(), String> {
    let mut st = ctx.store.write().await;
    st.decide_request(&id, &decision);
    Ok(())
}

#[tauri::command]
async fn add_manual_grant(
    ctx: TauriState<'_, AppCtx>,
    kind: String,
    target: String,
    mode: String,
) -> Result<(), String> {
    let mut st = ctx.store.write().await;
    let gk = if kind == "program" {
        GrantKind::Program
    } else {
        GrantKind::Path
    };
    let gm = if mode == "once" {
        GrantMode::Once
    } else {
        GrantMode::Session
    };
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err("Target cannot be empty.".into());
    }
    let final_target = if gk == GrantKind::Path {
        let pol = Policy::from_config(&st.cfg);
        let res = pol.resolve(trimmed);
        if res.forbidden {
            return Err("Bridge configuration/secrets folder cannot be granted.".into());
        }
        if !res.abs.exists() {
            return Err(format!("Path does not exist: {}", res.abs.display()));
        }
        res.real.to_string_lossy().to_string()
    } else {
        trimmed.to_lowercase().trim_end_matches(".exe").to_string()
    };
    let g = st.add_grant(gk.clone(), final_target.clone(), gm.clone(), "desktop".into());
    st.audit(
        "grant_created_desktop",
        serde_json::json!({ "id": g.id, "kind": gk, "target": final_target, "mode": gm }),
    );
    Ok(())
}

#[tauri::command]
async fn revoke_grant(ctx: TauriState<'_, AppCtx>, id: String) -> Result<(), String> {
    ctx.store.write().await.revoke_grant(&id);
    Ok(())
}

#[tauri::command]
async fn revoke_client(ctx: TauriState<'_, AppCtx>, client_id: String) -> Result<(), String> {
    ctx.store.write().await.remove_client(&client_id);
    Ok(())
}

#[tauri::command]
async fn toggle_tailscale_funnel(ctx: TauriState<'_, AppCtx>, enable: bool) -> Result<String, String> {
    let port = ctx.store.read().await.cfg.port;
    let msg = tokio::task::spawn_blocking(move || {
        if enable {
            tailscale::enable_funnel(port)
        } else {
            tailscale::disable_funnel()
        }
    })
    .await
    .map_err(|e| e.to_string())??;
    ctx.store.write().await.audit(
        if enable { "tailscale_funnel_enabled" } else { "tailscale_funnel_disabled" },
        serde_json::json!({ "message": msg }),
    );
    Ok(msg)
}

#[tauri::command]
async fn connect_google_drive(
    ctx: TauriState<'_, AppCtx>,
    folder_name: String,
    folder_id: Option<String>,
    mode: String,
) -> Result<String, String> {
    ctx.drive
        .connect_google_drive(ctx.store.clone(), folder_name, folder_id, mode)
        .await
}

#[tauri::command]
async fn disconnect_google_drive(ctx: TauriState<'_, AppCtx>) -> Result<(), String> {
    ctx.drive.disconnect(ctx.store.clone()).await
}

#[tauri::command]
async fn sync_google_drive_now(ctx: TauriState<'_, AppCtx>) -> Result<String, String> {
    let cfg = ctx.store.read().await.cfg.clone();
    ctx.drive.sync_now(ctx.store.clone(), &cfg).await
}

#[tauri::command]
async fn open_folder(path: String) -> Result<(), String> {
    #[cfg(windows)]
    {
        std::process::Command::new("explorer.exe")
            .arg(&path)
            .spawn()
            .map_err(|e| format!("open folder: {e}"))?;
    }
    Ok(())
}

pub fn run() {
    let (cfg, secrets, initial_pin) = load_or_init().expect("Failed to initialize bridge config");
    let bind_addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port)
        .parse()
        .expect("Valid bind host:port");

    let store = Arc::new(RwLock::new(Store::new(cfg.clone(), secrets, initial_pin)));
    let drive = Arc::new(DriveManager::new());

    // Start background HTTP/MCP/OAuth server + Drive watcher inside Tauri's async runtime.
    let srv_store = store.clone();
    let srv_drive = drive.clone();

    tauri::Builder::default()
        .manage(AppCtx {
            store: store.clone(),
            drive: drive.clone(),
        })
        .invoke_handler(tauri::generate_handler![
            get_dashboard,
            set_paused,
            set_pairing,
            rotate_pin,
            dismiss_display_pin,
            decide_access_request,
            add_manual_grant,
            revoke_grant,
            revoke_client,
            toggle_tailscale_funnel,
            connect_google_drive,
            disconnect_google_drive,
            sync_google_drive_now,
            open_folder,
        ])
        .setup(move |app| {
            // Spawn Axum HTTP server + Drive watcher on Tokio runtime.
            tauri::async_runtime::spawn(async move {
                {
                    let mut st = srv_store.write().await;
                    let ws = st.cfg.workspace.clone();
                    st.audit(
                        "bridge_started",
                        serde_json::json!({
                            "version": "2.0.0",
                            "bind": bind_addr.to_string(),
                            "workspace": ws
                        }),
                    );
                }

                spawn_drive_watcher(srv_store.clone(), srv_drive.clone());

                let router = build_http_router(srv_store, srv_drive);
                match tokio::net::TcpListener::bind(bind_addr).await {
                    Ok(listener) => {
                        let _ = axum::serve(
                            listener,
                            router.into_make_service_with_connect_info::<SocketAddr>(),
                        )
                        .await;
                    }
                    Err(e) => {
                        eprintln!("[bridge] failed to bind {bind_addr}: {e}");
                    }
                }
            });

            // System tray with quick controls
            let open_i = MenuItem::with_id(app, "open", "Open Dashboard", true, None::<&str>)?;
            let pair_i = MenuItem::with_id(app, "pair", "Enable Pairing (5 min)", true, None::<&str>)?;
            let sync_i = MenuItem::with_id(app, "sync", "Sync Google Drive Now", true, None::<&str>)?;
            let pause_i = MenuItem::with_id(app, "pause", "Toggle Pause (Kill Switch)", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit Gemini Local Bridge", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open_i, &pair_i, &sync_i, &pause_i, &quit_i])?;

            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("Gemini Local Bridge v2")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "pair" => {
                        let ctx = app.state::<AppCtx>();
                        let s = ctx.store.clone();
                        tauri::async_runtime::spawn(async move {
                            s.write().await.enable_pairing(5);
                        });
                    }
                    "sync" => {
                        let ctx = app.state::<AppCtx>();
                        let s = ctx.store.clone();
                        let d = ctx.drive.clone();
                        tauri::async_runtime::spawn(async move {
                            let cfg = s.read().await.cfg.clone();
                            let _ = d.sync_now(s, &cfg).await;
                        });
                    }
                    "pause" => {
                        let ctx = app.state::<AppCtx>();
                        let s = ctx.store.clone();
                        tauri::async_runtime::spawn(async move {
                            let mut st = s.write().await;
                            st.paused = !st.paused;
                        });
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                })
                .build(app)?;

            // Minimize to system tray instead of exiting when clicking X
            if let Some(w) = app.get_webview_window("main") {
                let w_clone = w.clone();
                w.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = w_clone.hide();
                    }
                });
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Gemini Local Bridge");
}
