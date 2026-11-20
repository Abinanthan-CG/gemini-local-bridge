use crate::drive::DriveManager;
use crate::media::{analyze_image, encode_base64_preview};
use crate::oauth::{origin_of, peer_ip, require_bearer};
use crate::policy::{PathAccess, Policy, ProgramAccess};
use crate::runner::run_allowlisted;
use crate::ssrf::download_public_url;
use crate::store::{GrantKind, Store};
use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use globset::Glob;
use serde_json::{json, Value};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use walkdir::WalkDir;

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "dist",
    "build",
    "out",
    "__pycache__",
    ".next",
    ".cache",
    "target",
];

#[derive(Clone)]
pub struct HttpState {
    pub store: Arc<RwLock<Store>>,
    pub drive: Arc<DriveManager>,
}

fn image_mime(ext: &str) -> Option<&'static str> {
    match ext {
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "bmp" => Some("image/bmp"),
        "ico" => Some("image/x-icon"),
        "avif" => Some("image/avif"),
        _ => None,
    }
}

fn human_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    }
}

fn is_probably_binary(buf: &[u8]) -> bool {
    let n = buf.len().min(8192);
    buf[..n].contains(&0)
}

fn ok_text(t: String) -> Value {
    json!({ "content": [{ "type": "text", "text": t }] })
}

fn err_text(t: String) -> Value {
    json!({ "isError": true, "content": [{ "type": "text", "text": t }] })
}

fn denied_msg(code: &str, message: &str, approval_url: &str) -> Value {
    let thing = if code == "PROGRAM_NOT_ALLOWED" {
        "program"
    } else {
        "folder or file"
    };
    err_text(format!(
        "{code}: {message}\nNothing was read or changed.\n\nTell the user: open {approval_url} on your phone (or use the Gemini Local Bridge desktop app) to grant this {thing}, then ask me to retry.\nOnly the human can grant it. Do not try to work around this policy."
    ))
}

fn rpc_ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_err(id: Value, code: i64, msg: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } })
}

fn tool_definitions(programs_csv: &str, default_timeout: u64) -> Value {
    json!([
        {
            "name": "workspace_info",
            "title": "Workspace info",
            "description": "Describe the sandbox: workspace root, allowed programs, Google Drive sync folder status, limits, active permission grants, and approval URL.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "list_directory",
            "title": "List directory",
            "description": "List files and folders. Paths are relative to the workspace unless absolute. Outside the workspace requires an approved path grant.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Directory path, relative to workspace or absolute. Default '.'" },
                    "include_hidden": { "type": "boolean", "description": "Include dotfiles. Default false." }
                }
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "read_file",
            "title": "Read file",
            "description": "Read a UTF-8 text file (paginated by line) or image metadata. Note: Gemini App strips binary MCP image blocks; use image_preview_base64 to view an image directly or preview_image for exact pixel metrics.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "File path, relative to workspace or absolute." },
                    "offset": { "type": "integer", "minimum": 1, "description": "First line (1-based). Default 1." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Max lines. Default 400." }
                },
                "required": ["path"]
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "write_file",
            "title": "Write file",
            "description": "Create or overwrite a UTF-8 text file. Refuses to overwrite unless overwrite=true.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "content": { "type": "string" },
                    "overwrite": { "type": "boolean" },
                    "create_dirs": { "type": "boolean" }
                },
                "required": ["path", "content"]
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false }
        },
        {
            "name": "replace_in_file",
            "title": "Replace in file",
            "description": "Replace an exact string in a UTF-8 text file. Fails if missing or ambiguous unless replace_all=true.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "old_string": { "type": "string", "minLength": 1 },
                    "new_string": { "type": "string" },
                    "replace_all": { "type": "boolean" }
                },
                "required": ["path", "old_string", "new_string"]
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false }
        },
        {
            "name": "search_text",
            "title": "Search text",
            "description": "Case-insensitive text search under a folder. Skips node_modules, .git, target, build outputs and binaries.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "minLength": 2 },
                    "path": { "type": "string" },
                    "glob": { "type": "string" },
                    "max_results": { "type": "integer", "minimum": 1, "maximum": 500 }
                },
                "required": ["query"]
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "copy_file",
            "title": "Copy file",
            "description": "Copy any file byte-for-byte (images, zips, PDFs) inside the workspace or from an approved folder.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source": { "type": "string" },
                    "destination": { "type": "string" },
                    "overwrite": { "type": "boolean" },
                    "create_dirs": { "type": "boolean" }
                },
                "required": ["source", "destination"]
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false }
        },
        {
            "name": "download_url",
            "title": "Download public URL",
            "description": "Download a public http(s) file directly into the workspace with DNS-pinned SSRF protection.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string" },
                    "path": { "type": "string" },
                    "overwrite": { "type": "boolean" }
                },
                "required": ["url", "path"]
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true }
        },
        {
            "name": "preview_image",
            "title": "Inspect image pixels as text",
            "description": "Fast native pixel analyzer: canvas size, silhouette coverage, bounding box, semi-transparent fringe % (alpha halo indicator), dominant hex colours, 64x32 ASCII silhouette, and multi-frame alignment drift table.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "paths": { "type": "array", "items": { "type": "string" }, "maxItems": 8 },
                    "ascii": { "type": "boolean" }
                }
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "image_preview_base64",
            "title": "Encode compact JPEG base64 preview",
            "description": "Resize and JPEG-compress a local image (native Rust, <150 KB) and return its base64 text so Gemini can decode and visually inspect it even when MCP binary image blocks are stripped.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Image file path." },
                    "max_edge": { "type": "integer", "minimum": 256, "maximum": 1600, "description": "Max width/height in pixels. Default 1024." },
                    "max_kb": { "type": "integer", "minimum": 16, "maximum": 180, "description": "Max JPEG size in KB. Default 32 (fast & clean for Gemini decoding)." }
                },
                "required": ["path"]
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "share_file",
            "title": "Create temporary file link",
            "description": "Mint an unguessable temporary HTTPS link to one file (default 60 min). Served with strict sandbox CSP.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "ttl_minutes": { "type": "integer", "minimum": 5, "maximum": 240 }
                },
                "required": ["path"]
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": true }
        },
        {
            "name": "run_command",
            "title": "Run allowlisted command",
            "description": format!("Run one allowlisted program without a shell (isolated in a Windows Job Object). Allowed: {programs_csv}. Default timeout {default_timeout}s."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "program": { "type": "string" },
                    "args": { "type": "array", "items": { "type": "string" }, "maxItems": 100 },
                    "cwd": { "type": "string" },
                    "timeout_sec": { "type": "integer", "minimum": 1, "maximum": 300 }
                },
                "required": ["program"]
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": false }
        },
        {
            "name": "drive_sync_status",
            "title": "Google Drive sync status",
            "description": "Show the single-folder Google Drive sync configuration, local folder path (inside workspace), remote Drive folder name, and last sync result.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "drive_sync_now",
            "title": "Sync Google Drive folder now",
            "description": "Immediately sync the dedicated workspace drive-sync folder with Google Drive so freshly rendered full-res images are available via @Google Drive (or new Drive files are pulled down).",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true }
        },
        {
            "name": "request_access",
            "title": "Request user permission",
            "description": "Create a pending approval request for an outside path or non-allowlisted program. Note: Gemini App may block this call; if so, tell the user to grant manually on the approval page or desktop app.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "kind": { "type": "string", "enum": ["path", "program"] },
                    "target": { "type": "string" },
                    "reason": { "type": "string" }
                },
                "required": ["kind", "target", "reason"]
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false }
        },
        {
            "name": "check_access",
            "title": "Check permission request",
            "description": "Check whether a request_access request was approved, denied, or is still pending.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request_id": { "type": "string" }
                },
                "required": ["request_id"]
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        }
    ])
}

pub async fn mcp_post(
    State(state): State<HttpState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    let ip = peer_ip(&addr, &headers);
    {
        let mut st = state.store.write().await;
        if st.paused {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "bridge_paused", "message": "Bridge is paused by the owner." })),
            )
                .into_response();
        }
        if !st.check_mcp_rate(&ip) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "rate_limited" })),
            )
                .into_response();
        }
    }

    let auth = match require_bearer(&state.store, &headers).await {
        Ok(rec) => rec,
        Err(resp) => return resp,
    };

    let origin = {
        let st = state.store.read().await;
        origin_of(&headers, &st)
    };

    if let Some(arr) = payload.as_array() {
        let mut responses = Vec::new();
        for item in arr {
            if let Some(r) = handle_single_rpc(&state, &origin, &auth.client_id, item).await {
                responses.push(r);
            }
        }
        if responses.is_empty() {
            return StatusCode::ACCEPTED.into_response();
        }
        return Json(Value::Array(responses)).into_response();
    }

    match handle_single_rpc(&state, &origin, &auth.client_id, &payload).await {
        Some(resp) => Json(resp).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

pub async fn mcp_get() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "POST, DELETE")],
        Json(json!({
            "error": "method_not_allowed",
            "hint": "Use POST for MCP Streamable HTTP. This server is stateless."
        })),
    )
        .into_response()
}

pub async fn mcp_delete() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn handle_single_rpc(
    state: &HttpState,
    origin: &str,
    client_id: &str,
    req: &Value,
) -> Option<Value> {
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let id = req.get("id").cloned();

    // JSON-RPC notifications have no id -> return 202 Accepted (None).
    if id.is_none() || method.starts_with("notifications/") {
        return None;
    }
    let id = id.unwrap();

    match method {
        "initialize" => {
            let client_ver = req
                .pointer("/params/protocolVersion")
                .and_then(|v| v.as_str())
                .unwrap_or("2025-06-18");
            let ver = match client_ver {
                "2025-06-18" | "2025-03-26" | "2024-11-05" => client_ver,
                _ => "2025-06-18",
            };
            let (ws, progs, drive_sub, drive_name) = {
                let st = state.store.read().await;
                let pol = Policy::from_config(&st.cfg);
                (
                    st.cfg.workspace.clone(),
                    pol.program_names().join(", "),
                    st.cfg.drive_sync.subfolder.clone(),
                    st.cfg.drive_sync.remote_folder_name.clone(),
                )
            };
            let instructions = format!(
                "You are connected to a local Windows PC through Gemini Local Bridge v2 (Rust).\n\
Workspace root: {ws}\n\
Allowlisted programs (no shell, Job Object isolated): {progs}.\n\
Images: Gemini App strips binary MCP image blocks. To visually inspect a local image immediately, call image_preview_base64 (returns compact JPEG base64 you can decode & view). For exact rig/alpha/alignment measurements, call preview_image. For full-resolution multi-MB renders, write into '{drive_sub}' and call drive_sync_now (synced to Google Drive folder '{drive_name}').\n\
Permissions: If a tool returns OUTSIDE_WORKSPACE or PROGRAM_NOT_ALLOWED, give the user the approval URL from the error so they can grant it in the web UI or desktop app, then retry once."
            );
            Some(rpc_ok(
                id,
                json!({
                    "protocolVersion": ver,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "gemini-local-bridge", "version": "2.0.0" },
                    "instructions": instructions
                }),
            ))
        }
        "ping" => Some(rpc_ok(id, json!({}))),
        "tools/list" => {
            let (progs, timeout) = {
                let st = state.store.read().await;
                let pol = Policy::from_config(&st.cfg);
                (
                    pol.program_names().join(", "),
                    st.cfg.default_command_timeout_seconds,
                )
            };
            Some(rpc_ok(id, json!({ "tools": tool_definitions(&progs, timeout) })))
        }
        "tools/call" => {
            let name = req
                .pointer("/params/name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args = req
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let res = dispatch_tool(state, origin, client_id, name, &args).await;
            Some(rpc_ok(id, res))
        }
        _ => Some(rpc_err(id, -32601, &format!("Method not found: {method}"))),
    }
}

async fn resolve_checked(
    store: &Arc<RwLock<Store>>,
    origin: &str,
    requested: &str,
    must_exist: bool,
    want_dir: bool,
) -> Result<(std::path::PathBuf, Option<String>), Value> {
    let st = store.read().await;
    let pol = Policy::from_config(&st.cfg);
    let (resolved, access) = pol.path_access(&st, requested);
    let grant_id = match access {
        PathAccess::Allowed { grant } => grant.map(|g| g.id),
        PathAccess::Denied {
            code,
            message,
            ..
        } => return Err(denied_msg(code, &message, &format!("{origin}/approve"))),
    };

    if !resolved.exists {
        if must_exist {
            return Err(err_text(format!(
                "NOT_FOUND: {} does not exist.",
                resolved.abs.display()
            )));
        }
        return Ok((resolved.abs, grant_id));
    }

    let meta = fs::metadata(&resolved.abs)
        .map_err(|e| err_text(format!("STAT_FAILED: {e}")))?;
    if want_dir && !meta.is_dir() {
        return Err(err_text(format!(
            "NOT_A_DIRECTORY: {} is a file.",
            resolved.abs.display()
        )));
    }
    Ok((resolved.abs, grant_id))
}

async fn consume_if_granted(store: &Arc<RwLock<Store>>, grant_id: Option<String>) {
    if let Some(id) = grant_id {
        let mut st = store.write().await;
        st.consume_grant_if_once(&id);
    }
}

async fn dispatch_tool(
    state: &HttpState,
    origin: &str,
    client_id: &str,
    name: &str,
    args: &Value,
) -> Value {
    match name {
        "workspace_info" => {
            let (cfg, progs, grants) = {
                let st = state.store.read().await;
                let pol = Policy::from_config(&st.cfg);
                (st.cfg.clone(), pol.program_names(), st.active_grants())
            };
            let drive_st = state.drive.status(&cfg).await;
            let mut lines = vec![
                format!("workspace: {}", cfg.workspace),
                format!("platform: {} ({})", std::env::consts::OS, std::env::consts::ARCH),
                format!("time: {}", chrono::Utc::now().to_rfc3339()),
                format!("allowed_programs: {}", progs.join(", ")),
                format!("approval_url: {origin}/approve"),
                format!(
                    "drive_sync: {} (local: {}, remote: '{}', mode: {})",
                    if drive_st.enabled && drive_st.configured { "enabled" } else { "not configured" },
                    drive_st.local_dir,
                    drive_st.remote_folder_name,
                    drive_st.mode
                ),
                format!("active_grants: {}", grants.len()),
            ];
            for g in grants {
                lines.push(format!("  - {:?} {} ({:?})", g.kind, g.target, g.mode));
            }
            lines.push(format!(
                "limits: read {}, write {}, image {}, copy {}, download {}, share {}, command output {}, timeout {}-{}s",
                human_size(cfg.max_read_bytes as u64),
                human_size(cfg.max_write_bytes as u64),
                human_size(cfg.max_image_bytes as u64),
                human_size(cfg.max_copy_bytes),
                human_size(cfg.max_download_bytes as u64),
                human_size(cfg.max_share_bytes),
                human_size(cfg.max_command_output_bytes as u64),
                cfg.default_command_timeout_seconds,
                cfg.max_command_timeout_seconds
            ));
            ok_text(lines.join("\n"))
        }

        "list_directory" => {
            let req_path = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
            let include_hidden = args
                .get("include_hidden")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let (dir, grant) = match resolve_checked(&state.store, origin, req_path, true, true).await {
                Ok(v) => v,
                Err(e) => return e,
            };
            let max_entries = state.store.read().await.cfg.max_list_entries;
            let read_dir = match fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(e) => return err_text(format!("READ_FAILED: {e}")),
            };
            let mut items: Vec<(bool, String, String)> = Vec::new();
            for entry in read_dir.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !include_hidden && name.starts_with('.') {
                    continue;
                }
                let meta = entry.metadata().ok();
                let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size = if is_dir {
                    String::new()
                } else {
                    meta.map(|m| human_size(m.len())).unwrap_or_default()
                };
                items.push((is_dir, name, size));
            }
            items.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.to_lowercase().cmp(&b.1.to_lowercase())));
            let total = items.len();
            let rows: Vec<String> = items
                .into_iter()
                .take(max_entries)
                .map(|(is_dir, name, size)| {
                    format!("{}\t{}\t{}", if is_dir { "DIR " } else { "FILE" }, size, name)
                })
                .collect();
            consume_if_granted(&state.store, grant).await;
            let more = if total > max_entries {
                format!("\n... {} more entries", total - max_entries)
            } else {
                String::new()
            };
            ok_text(format!(
                "{}\n{}{}",
                dir.display(),
                if rows.is_empty() { "(empty)".into() } else { rows.join("\n") },
                more
            ))
        }

        "read_file" => {
            let req_path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(1).max(1) as usize;
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(400).clamp(1, 5000) as usize;
            let (file, grant) = match resolve_checked(&state.store, origin, req_path, true, false).await {
                Ok(v) => v,
                Err(e) => return e,
            };
            let meta = match fs::metadata(&file) {
                Ok(m) if m.is_file() => m,
                Ok(_) => return err_text(format!("NOT_A_FILE: {}", file.display())),
                Err(e) => return err_text(format!("READ_FAILED: {e}")),
            };
            let (max_img, max_read) = {
                let st = state.store.read().await;
                (st.cfg.max_image_bytes as u64, st.cfg.max_read_bytes as u64)
            };
            let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
            if let Some(mime) = image_mime(&ext) {
                if meta.len() > max_img {
                    return err_text(format!(
                        "IMAGE_TOO_LARGE: {} exceeds {}.",
                        human_size(meta.len()),
                        human_size(max_img)
                    ));
                }
                let bytes = match fs::read(&file) {
                    Ok(b) => b,
                    Err(e) => return err_text(format!("READ_FAILED: {e}")),
                };
                consume_if_granted(&state.store, grant).await;
                return json!({
                    "content": [
                        {
                            "type": "text",
                            "text": format!(
                                "image: {} ({}, {mime})\nNote: If your client stripped the image pixels, call image_preview_base64 on this path to decode and see it visually, or preview_image for exact pixel metrics.",
                                file.display(),
                                human_size(meta.len())
                            )
                        },
                        {
                            "type": "image",
                            "data": STANDARD.encode(&bytes),
                            "mimeType": mime
                        }
                    ]
                });
            }

            if meta.len() > max_read * 8 {
                return err_text(format!("FILE_TOO_LARGE: {}.", human_size(meta.len())));
            }
            let bytes = match fs::read(&file) {
                Ok(b) => b,
                Err(e) => return err_text(format!("READ_FAILED: {e}")),
            };
            if is_probably_binary(&bytes) {
                return err_text(format!("BINARY_FILE: {} is not UTF-8 text.", file.display()));
            }
            let text_content = String::from_utf8_lossy(&bytes);
            let lines: Vec<&str> = text_content.lines().collect();
            let start = (offset - 1).min(lines.len());
            let end = (start + limit).min(lines.len());
            let numbered: Vec<String> = lines[start..end]
                .iter()
                .enumerate()
                .map(|(i, l)| format!("{}: {}", start + i + 1, l))
                .collect();
            consume_if_granted(&state.store, grant).await;
            let trunc = if end < lines.len() {
                format!("\n[showing lines {}-{}]", start + 1, end)
            } else {
                String::new()
            };
            ok_text(format!(
                "{} ({} lines, {}){}\n{}",
                file.display(),
                lines.len(),
                human_size(meta.len()),
                trunc,
                numbered.join("\n")
            ))
        }

        "write_file" => {
            let req_path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let content = args.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let overwrite = args.get("overwrite").and_then(|v| v.as_bool()).unwrap_or(false);
            let create_dirs = args.get("create_dirs").and_then(|v| v.as_bool()).unwrap_or(true);
            let max_write = state.store.read().await.cfg.max_write_bytes;
            if content.len() > max_write {
                return err_text(format!(
                    "TOO_LARGE: {} exceeds {}.",
                    human_size(content.len() as u64),
                    human_size(max_write as u64)
                ));
            }
            let (file, grant) = match resolve_checked(&state.store, origin, req_path, false, false).await {
                Ok(v) => v,
                Err(e) => return e,
            };
            if file.exists() {
                if file.is_dir() {
                    return err_text(format!("IS_DIRECTORY: {}", file.display()));
                }
                if !overwrite {
                    return err_text(format!(
                        "EXISTS: {}. Pass overwrite=true to replace it.",
                        file.display()
                    ));
                }
            }
            if create_dirs {
                if let Some(parent) = file.parent() {
                    if let Err(e) = fs::create_dir_all(parent) {
                        return err_text(format!("WRITE_FAILED: {e}"));
                    }
                }
            }
            if let Err(e) = fs::write(&file, content.as_bytes()) {
                return err_text(format!("WRITE_FAILED: {e}"));
            }
            consume_if_granted(&state.store, grant).await;
            state.store.write().await.audit(
                "file_written",
                json!({ "path": file.to_string_lossy(), "bytes": content.len() }),
            );
            ok_text(format!("wrote {} bytes to {}", content.len(), file.display()))
        }

        "replace_in_file" => {
            let req_path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let old_str = args.get("old_string").and_then(|v| v.as_str()).unwrap_or("");
            let new_str = args.get("new_string").and_then(|v| v.as_str()).unwrap_or("");
            let replace_all = args.get("replace_all").and_then(|v| v.as_bool()).unwrap_or(false);
            if old_str.is_empty() {
                return err_text("INVALID_ARG: old_string must not be empty.".into());
            }
            let (file, grant) = match resolve_checked(&state.store, origin, req_path, true, false).await {
                Ok(v) => v,
                Err(e) => return e,
            };
            let bytes = match fs::read(&file) {
                Ok(b) => b,
                Err(e) => return err_text(format!("READ_FAILED: {e}")),
            };
            if is_probably_binary(&bytes) {
                return err_text("BINARY_FILE: refusing to patch a binary file.".into());
            }
            let original = String::from_utf8_lossy(&bytes).to_string();
            let count = original.matches(old_str).count();
            if count == 0 {
                return err_text(format!("NOT_FOUND: old_string does not occur in {}.", file.display()));
            }
            if count > 1 && !replace_all {
                return err_text(format!(
                    "AMBIGUOUS: old_string occurs {count} times. Add more context or set replace_all=true."
                ));
            }
            let updated = if replace_all {
                original.replace(old_str, new_str)
            } else {
                original.replacen(old_str, new_str, 1)
            };
            if let Err(e) = fs::write(&file, updated.as_bytes()) {
                return err_text(format!("WRITE_FAILED: {e}"));
            }
            consume_if_granted(&state.store, grant).await;
            let reps = if replace_all { count } else { 1 };
            state.store.write().await.audit(
                "file_patched",
                json!({ "path": file.to_string_lossy(), "replacements": reps }),
            );
            ok_text(format!("replaced {reps} occurrence(s) in {}", file.display()))
        }

        "search_text" => {
            let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
            if query.len() < 2 {
                return err_text("INVALID_ARG: query must be at least 2 characters.".into());
            }
            let req_path = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
            let glob_str = args.get("glob").and_then(|v| v.as_str()).unwrap_or("*");
            let max_cfg = state.store.read().await.cfg.max_search_results;
            let max = args
                .get("max_results")
                .and_then(|v| v.as_u64())
                .map(|n| n as usize)
                .unwrap_or(100)
                .min(max_cfg);

            let (dir, grant) = match resolve_checked(&state.store, origin, req_path, true, true).await {
                Ok(v) => v,
                Err(e) => return e,
            };
            let matcher = Glob::new(glob_str)
                .unwrap_or_else(|_| Glob::new("*").unwrap())
                .compile_matcher();
            let needle = query.to_lowercase();
            let mut hits = Vec::new();
            let mut scanned = 0usize;

            let walker = WalkDir::new(&dir).max_depth(24).into_iter().filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                let name = e.file_name().to_string_lossy();
                if e.file_type().is_dir() {
                    if SKIP_DIRS.contains(&name.as_ref()) || name.starts_with('.') {
                        return false;
                    }
                }
                true
            });

            for entry in walker.flatten() {
                if hits.len() >= max || scanned > 5000 {
                    break;
                }
                if !entry.file_type().is_file() {
                    continue;
                }
                let fname = entry.file_name().to_string_lossy();
                if !matcher.is_match(fname.as_ref()) {
                    continue;
                }
                scanned += 1;
                let Ok(meta) = entry.metadata() else { continue };
                if meta.len() > 1024 * 1024 {
                    continue;
                }
                let Ok(buf) = fs::read(entry.path()) else { continue };
                if is_probably_binary(&buf) {
                    continue;
                }
                let txt = String::from_utf8_lossy(&buf);
                for (idx, line) in txt.lines().enumerate() {
                    if line.to_lowercase().contains(&needle) {
                        let snippet: String = line.trim().chars().take(300).collect();
                        hits.push(format!("{}:{}: {}", entry.path().display(), idx + 1, snippet));
                        if hits.len() >= max {
                            break;
                        }
                    }
                }
            }
            consume_if_granted(&state.store, grant).await;
            if hits.is_empty() {
                ok_text(format!("No matches for \"{query}\" under {}.", dir.display()))
            } else {
                ok_text(format!("{} match(es):\n{}", hits.len(), hits.join("\n")))
            }
        }

        "copy_file" => {
            let src_req = args.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let dst_req = args.get("destination").and_then(|v| v.as_str()).unwrap_or("");
            let overwrite = args.get("overwrite").and_then(|v| v.as_bool()).unwrap_or(false);
            let create_dirs = args.get("create_dirs").and_then(|v| v.as_bool()).unwrap_or(true);
            let max_copy = state.store.read().await.cfg.max_copy_bytes;

            let (src, src_grant) = match resolve_checked(&state.store, origin, src_req, true, false).await {
                Ok(v) => v,
                Err(e) => return e,
            };
            let meta = match fs::metadata(&src) {
                Ok(m) if m.is_file() => m,
                Ok(_) => return err_text(format!("NOT_A_FILE: {}", src.display())),
                Err(e) => return err_text(format!("STAT_FAILED: {e}")),
            };
            if meta.len() > max_copy {
                return err_text(format!(
                    "TOO_LARGE: {} exceeds {}.",
                    human_size(meta.len()),
                    human_size(max_copy)
                ));
            }
            let (dst, dst_grant) = match resolve_checked(&state.store, origin, dst_req, false, false).await {
                Ok(v) => v,
                Err(e) => return e,
            };
            if dst.exists() {
                if dst.is_dir() {
                    return err_text(format!("IS_DIRECTORY: {}", dst.display()));
                }
                if !overwrite {
                    return err_text(format!("EXISTS: {}. Pass overwrite=true to replace it.", dst.display()));
                }
            }
            if create_dirs {
                if let Some(p) = dst.parent() {
                    let _ = fs::create_dir_all(p);
                }
            }
            if let Err(e) = fs::copy(&src, &dst) {
                return err_text(format!("COPY_FAILED: {e}"));
            }
            consume_if_granted(&state.store, src_grant).await;
            consume_if_granted(&state.store, dst_grant).await;
            state.store.write().await.audit(
                "file_copied",
                json!({ "from": src.to_string_lossy(), "to": dst.to_string_lossy(), "bytes": meta.len() }),
            );
            ok_text(format!(
                "copied {} from {} to {}",
                human_size(meta.len()),
                src.display(),
                dst.display()
            ))
        }

        "download_url" => {
            let url = args.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let dst_req = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let overwrite = args.get("overwrite").and_then(|v| v.as_bool()).unwrap_or(false);
            let max_dl = state.store.read().await.cfg.max_download_bytes;

            let (dst, dst_grant) = match resolve_checked(&state.store, origin, dst_req, false, false).await {
                Ok(v) => v,
                Err(e) => return e,
            };
            if dst.exists() {
                if dst.is_dir() {
                    return err_text(format!("IS_DIRECTORY: {}", dst.display()));
                }
                if !overwrite {
                    return err_text(format!("EXISTS: {}. Pass overwrite=true to replace it.", dst.display()));
                }
            }

            let dl = match download_public_url(url, max_dl).await {
                Ok(r) => r,
                Err(e) => return err_text(e),
            };
            if let Some(p) = dst.parent() {
                let _ = fs::create_dir_all(p);
            }
            if let Err(e) = fs::write(&dst, &dl.bytes) {
                return err_text(format!("WRITE_FAILED: {e}"));
            }
            consume_if_granted(&state.store, dst_grant).await;
            state.store.write().await.audit(
                "url_downloaded",
                json!({ "url": dl.final_url, "to": dst.to_string_lossy(), "bytes": dl.bytes.len(), "contentType": dl.content_type }),
            );
            ok_text(format!(
                "downloaded {} ({}) to {}",
                human_size(dl.bytes.len() as u64),
                dl.content_type,
                dst.display()
            ))
        }

        "preview_image" => {
            let mut requested: Vec<String> = Vec::new();
            if let Some(arr) = args.get("paths").and_then(|v| v.as_array()) {
                for v in arr.iter().take(8) {
                    if let Some(s) = v.as_str() {
                        requested.push(s.to_string());
                    }
                }
            } else if let Some(s) = args.get("path").and_then(|v| v.as_str()) {
                requested.push(s.to_string());
            }
            if requested.is_empty() {
                return err_text("NO_INPUT: pass path or paths.".into());
            }

            let max_img = state.store.read().await.cfg.max_image_bytes as u64;
            let mut files = Vec::new();
            let mut grants = Vec::new();
            for item in &requested {
                let (p, g) = match resolve_checked(&state.store, origin, item, true, false).await {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                let Ok(meta) = fs::metadata(&p) else {
                    return err_text(format!("NOT_FOUND: {}", p.display()));
                };
                if !meta.is_file() {
                    return err_text(format!("NOT_A_FILE: {}", p.display()));
                }
                if meta.len() > max_img {
                    return err_text(format!("IMAGE_TOO_LARGE: {}", human_size(meta.len())));
                }
                files.push(p);
                if let Some(gid) = g {
                    grants.push(gid);
                }
            }

            let show_ascii = args
                .get("ascii")
                .and_then(|v| v.as_bool())
                .unwrap_or(files.len() == 1);

            let metrics = tokio::task::spawn_blocking(move || {
                files
                    .into_iter()
                    .map(|p| (p.clone(), analyze_image(&p)))
                    .collect::<Vec<_>>()
            })
            .await
            .unwrap_or_default();

            for gid in grants {
                consume_if_granted(&state.store, Some(gid)).await;
            }

            let mut out_blocks = Vec::new();
            let mut ok_list = Vec::new();
            for (p, res) in metrics {
                match res {
                    Err(e) => out_blocks.push(format!("file: {}\nERROR: {e}", p.display())),
                    Ok(m) => {
                        let bbox_line = match m.bbox {
                            Some(b) => format!(
                                "bbox: [{}, {}, {}, {}]  size {}x{}",
                                b[0],
                                b[1],
                                b[2],
                                b[3],
                                b[2] - b[0] + 1,
                                b[3] - b[1] + 1
                            ),
                            None => "bbox: empty image".into(),
                        };
                        let colors = if m.top_colors.is_empty() {
                            "none".into()
                        } else {
                            m.top_colors
                                .iter()
                                .map(|(h, pct)| format!("{h} {pct:.1}%"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        };
                        let mut block = format!(
                            "file: {}\nsize: {}x{}  mode: {}  has_alpha: {}  silhouette: {}\ncoverage: {:.1}% of canvas\n{}\nsemi-transparent: {:.1}% of silhouette\ntop colours: {}",
                            m.path,
                            m.width,
                            m.height,
                            m.mode,
                            if m.has_alpha { "yes" } else { "no" },
                            m.mask_source,
                            m.coverage_pct,
                            bbox_line,
                            m.semi_transparent_pct,
                            colors
                        );
                        if show_ascii && !m.ascii.is_empty() {
                            block.push_str(&format!("\nascii 64x32:\n{}", m.ascii));
                        }
                        out_blocks.push(block);
                        ok_list.push(m);
                    }
                }
            }

            if ok_list.len() > 1 && ok_list.iter().all(|m| m.bbox.is_some()) {
                let base = &ok_list[0];
                let bb = base.bbox.unwrap();
                let base_cx = (bb[0] + bb[2]) as f64 / 2.0;
                let base_cy = (bb[1] + bb[3]) as f64 / 2.0;
                let base_h = (bb[3] - bb[1] + 1).max(1) as f64;
                let mut rows = Vec::new();
                for m in &ok_list {
                    let b = m.bbox.unwrap();
                    let cx = (b[0] + b[2]) as f64 / 2.0;
                    let cy = (b[1] + b[3]) as f64 / 2.0;
                    let h = (b[3] - b[1] + 1) as f64;
                    let fname = Path::new(&m.path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(&m.path);
                    rows.push(format!(
                        "{:<24} d_center {:+},{:+}  d_bottom {:+}  scale {:.3}  canvas {}x{}",
                        fname,
                        (cx - base_cx).round() as i64,
                        (cy - base_cy).round() as i64,
                        b[3] as i64 - bb[3] as i64,
                        h / base_h,
                        m.width,
                        m.height
                    ));
                }
                out_blocks.push(format!("alignment vs first frame (pixels):\n{}", rows.join("\n")));
            }
            ok_text(out_blocks.join("\n\n"))
        }

        "image_preview_base64" => {
            let req_path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let max_edge = args.get("max_edge").and_then(|v| v.as_u64()).unwrap_or(1024) as u32;
            let max_kb = args.get("max_kb").and_then(|v| v.as_u64()).unwrap_or(32) as usize;
            let (file, grant) = match resolve_checked(&state.store, origin, req_path, true, false).await {
                Ok(v) => v,
                Err(e) => return e,
            };
            let file_clone = file.clone();
            let res = tokio::task::spawn_blocking(move || {
                encode_base64_preview(&file_clone, max_edge, max_kb)
            })
            .await
            .map_err(|e| format!("worker error: {e}"))
            .and_then(|r| r);

            consume_if_granted(&state.store, grant).await;
            match res {
                Ok(prev) => ok_text(format!(
                    "file: {}\noriginal: {}x{}  encoded: {}x{} JPEG q={} ({})\n--- base64_jpeg ---\n{}",
                    file.display(),
                    prev.orig_width,
                    prev.orig_height,
                    prev.out_width,
                    prev.out_height,
                    prev.quality,
                    human_size(prev.bytes_len as u64),
                    prev.base64_jpeg
                )),
                Err(e) => err_text(format!("ENCODE_FAILED: {e}")),
            }
        }

        "share_file" => {
            let req_path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let ttl = args.get("ttl_minutes").and_then(|v| v.as_i64()).unwrap_or(60);
            let (file, grant) = match resolve_checked(&state.store, origin, req_path, true, false).await {
                Ok(v) => v,
                Err(e) => return e,
            };
            let meta = match fs::metadata(&file) {
                Ok(m) if m.is_file() => m,
                _ => return err_text(format!("NOT_A_FILE: {}", file.display())),
            };
            let max_share = state.store.read().await.cfg.max_share_bytes;
            if meta.len() > max_share {
                return err_text(format!("TOO_LARGE: exceeds {}.", human_size(max_share)));
            }
            let item = {
                let mut st = state.store.write().await;
                let it = st.add_share(&file, ttl);
                st.audit(
                    "share_created",
                    json!({ "file": file.to_string_lossy(), "ttlMinutes": ttl }),
                );
                it
            };
            consume_if_granted(&state.store, grant).await;
            ok_text(format!(
                "url: {origin}/share/{}\nfile: {} ({})\nexpires_ms: {}",
                item.token,
                file.display(),
                human_size(meta.len()),
                item.expires_at
            ))
        }

        "run_command" => {
            let program = args.get("program").and_then(|v| v.as_str()).unwrap_or("");
            let argv: Vec<String> = args
                .get("args")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .take(100)
                        .map(|x| x.as_str().map(String::from).unwrap_or_else(|| x.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            if argv.iter().any(|a| a.len() > 4000) {
                return err_text("ARG_TOO_LONG: each argument must be under 4000 characters.".into());
            }

            let (entry, prog_grant, timeout_sec, max_out) = {
                let st = state.store.read().await;
                let pol = Policy::from_config(&st.cfg);
                let acc = pol.program_access(&st, program);
                match acc {
                    ProgramAccess::Allowed { entry, grant } => {
                        let t = args
                            .get("timeout_sec")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(st.cfg.default_command_timeout_seconds)
                            .clamp(1, st.cfg.max_command_timeout_seconds);
                        (entry, grant.map(|g| g.id), t, st.cfg.max_command_output_bytes)
                    }
                    ProgramAccess::Denied { code, message, .. } => {
                        return denied_msg(code, &message, &format!("{origin}/approve"));
                    }
                }
            };

            let cwd_req = args.get("cwd").and_then(|v| v.as_str()).unwrap_or(".");
            let (cwd, cwd_grant) = match resolve_checked(&state.store, origin, cwd_req, true, true).await {
                Ok(v) => v,
                Err(e) => return e,
            };

            let out = run_allowlisted(&entry, &argv, &cwd, timeout_sec, max_out).await;
            consume_if_granted(&state.store, prog_grant).await;
            consume_if_granted(&state.store, cwd_grant).await;

            state.store.write().await.audit(
                "command",
                json!({
                    "program": program,
                    "cwd": cwd.to_string_lossy(),
                    "args": argv.iter().take(20).collect::<Vec<_>>(),
                    "code": out.exit_code,
                    "timedOut": out.timed_out,
                    "durationMs": out.duration_ms
                }),
            );

            let mut footer = vec![
                format!("exit_code: {}", out.exit_code),
                format!("duration_ms: {}", out.duration_ms),
                format!("cwd: {}", cwd.display()),
            ];
            if out.timed_out {
                footer.push(format!("TIMEOUT: killed process tree after {timeout_sec}s"));
            }
            if out.truncated {
                footer.push(format!("OUTPUT_TRUNCATED at {}", human_size(max_out as u64)));
            }

            let body = format!(
                "{}\n\n--- stdout ---\n{}\n\n--- stderr ---\n{}",
                footer.join("\n"),
                if out.stdout.is_empty() { "(empty)" } else { &out.stdout },
                if out.stderr.is_empty() { "(empty)" } else { &out.stderr }
            );
            json!({
                "isError": out.exit_code != 0,
                "content": [{ "type": "text", "text": body }]
            })
        }

        "drive_sync_status" => {
            let cfg = state.store.read().await.cfg.clone();
            let ds = state.drive.status(&cfg).await;
            ok_text(format!(
                "enabled: {}\nconfigured: {}\nsyncing: {}\nlocal_dir: {}\nremote_folder: {} ({})\nmode: {}\nlocal_files: {}\nlast_sync: {}\nlast_result: {}",
                ds.enabled,
                ds.configured,
                ds.syncing,
                ds.local_dir,
                ds.remote_folder_name,
                ds.remote_folder_id,
                ds.mode,
                ds.local_file_count,
                ds.last_sync_at.as_deref().unwrap_or("never"),
                ds.last_result
            ))
        }

        "drive_sync_now" => {
            let cfg = state.store.read().await.cfg.clone();
            match state.drive.sync_now(state.store.clone(), &cfg).await {
                Ok(msg) => ok_text(format!(
                    "status: ok\nmessage: {msg}\nremote_folder: {}\nlocal_dir: {}",
                    cfg.drive_sync.remote_folder_name,
                    DriveManager::local_sync_dir(&cfg).display()
                )),
                Err(e) => err_text(format!("DRIVE_SYNC_ERROR: {e}")),
            }
        }

        "request_access" => {
            let kind_s = args.get("kind").and_then(|v| v.as_str()).unwrap_or("path");
            let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let reason = args.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            let kind = if kind_s == "program" {
                GrantKind::Program
            } else {
                GrantKind::Path
            };
            let mut st = state.store.write().await;
            if st.pending_requests().len() >= 8 {
                return err_text("TOO_MANY_PENDING: wait for user to decide existing requests.".into());
            }
            let normalized_target = if kind == GrantKind::Path {
                let pol = Policy::from_config(&st.cfg);
                let r = pol.resolve(target);
                if r.forbidden {
                    return err_text("FORBIDDEN_BRIDGE_DATA: cannot request access to bridge data.".into());
                }
                r.real.to_string_lossy().to_string()
            } else {
                target.to_lowercase().trim_end_matches(".exe").to_string()
            };
            let req = st.add_request(
                kind.clone(),
                normalized_target.clone(),
                reason.chars().take(500).collect(),
                client_id.to_string(),
            );
            st.audit(
                "access_requested",
                json!({ "id": req.id, "kind": kind, "target": normalized_target, "reason": reason }),
            );
            ok_text(format!(
                "status: pending\nrequest_id: {}\nkind: {kind_s}\ntarget: {normalized_target}\napproval_url: {origin}/approve\n\nAsk the user to approve in the desktop app or at {origin}/approve, then retry.",
                req.id
            ))
        }

        "check_access" => {
            let id = args
                .get("request_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_uppercase();
            let st = state.store.read().await;
            let Some(req) = st.requests.get(&id) else {
                return err_text(format!("NOT_FOUND: no request {id}."));
            };
            ok_text(format!(
                "request_id: {}\nstatus: {}\nkind: {:?}\ntarget: {}",
                req.id, req.status, req.kind, req.target
            ))
        }

        _ => err_text(format!("UNKNOWN_TOOL: {name}")),
    }
}
