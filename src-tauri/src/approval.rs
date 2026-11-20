use crate::crypto::{hmac_sign_b64url, hmac_verify_b64url, verify_pin};
use crate::oauth::{esc_html, peer_ip, BRAND_SVG};
use crate::policy::Policy;
use crate::store::{now_ms, GrantKind, GrantMode, Store};
use axum::{
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

fn page(title: &str, body: &str, refresh: bool) -> Html<String> {
    let meta_refresh = if refresh {
        r#"<meta http-equiv="refresh" content="8">"#
    } else {
        ""
    };
    Html(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{meta_refresh}
<title>{}</title>
<style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}
body{{margin:0;min-height:100vh;font:14.5px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;color:#e6edf5;background:radial-gradient(700px 260px at 50% -10%,rgba(56,189,248,.08),transparent 70%),#080b10;padding:1.5rem 1rem 2.5rem}}
.wrap{{max-width:34rem;margin:0 auto}}
.brand{{display:flex;align-items:center;gap:.7rem;margin-bottom:1.25rem}}
.brand-name{{font-weight:650;font-size:.95rem}}.brand-sub{{font-size:.75rem;color:#6f7f96}}
h1{{font-size:1.25rem;font-weight:650;letter-spacing:-.02em;margin:0 0 .25rem}}
h2{{font-size:.9rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:#8b9bb0;margin:1.4rem 0 .55rem}}
p{{color:#94a3b8;margin:.35rem 0;font-size:.9rem}}small{{color:#6f7f96;font-size:.8rem}}
a{{color:#38bdf8}}
.card{{background:#0e131b;border:1px solid rgba(255,255,255,.09);border-radius:10px;padding:1rem 1.1rem;margin:.65rem 0}}
.mono{{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;word-break:break-all;font-size:.82rem;color:#e6edf5}}
.kind{{display:inline-block;font-size:.68rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;padding:.15rem .45rem;border-radius:4px;background:rgba(56,189,248,.14);color:#38bdf8;margin-right:.35rem}}
.kind.program{{background:rgba(245,158,11,.15);color:#fbbf24}}
input,select{{width:100%;padding:.72rem .8rem;border:1px solid rgba(255,255,255,.15);border-radius:7px;background:#080b10;color:#e6edf5;font-size:.98rem;margin:.35rem 0 .6rem}}
input:focus,select:focus{{outline:none;border-color:#38bdf8}}
label{{display:block;margin-top:.35rem;font-size:.82rem;color:#a8b5c8}}
button{{padding:.68rem 1rem;border:1px solid #38bdf8;border-radius:7px;font-size:.9rem;font-weight:600;background:#0284c7;color:#fff;cursor:pointer;margin:.2rem .3rem .2rem 0}}
button.deny{{background:rgba(239,68,68,.14);border-color:rgba(239,68,68,.38);color:#fca5a5}}
button.secondary{{background:#141b26;border-color:rgba(255,255,255,.16);color:#e6edf5}}
button.link{{background:none;border:0;color:#6f7f96;padding:.25rem 0;font-weight:500;margin-top:1rem}}
.row{{display:flex;gap:.45rem;flex-wrap:wrap}}
</style></head><body><div class="wrap"><div class="brand">{BRAND_SVG}<div><div class="brand-name">Gemini Local Bridge</div><div class="brand-sub">Remote Access Gate</div></div></div>{body}</div></body></html>"#,
        esc_html(title)
    ))
}

fn make_cookie(secret: &str) -> String {
    let ts = now_ms();
    let sig = hmac_sign_b64url(secret, &format!("approve:{ts}"));
    format!("{ts}.{sig}")
}

fn valid_cookie(secret: &str, cookie_val: &str) -> Option<String> {
    let (ts_s, sig) = cookie_val.split_once('.')?;
    let ts = ts_s.parse::<i64>().ok()?;
    let age = now_ms() - ts;
    if !(0..=30 * 60_000).contains(&age) {
        return None;
    }
    if hmac_verify_b64url(secret, &format!("approve:{ts}"), sig) {
        Some(cookie_val.to_string())
    } else {
        None
    }
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn session_csrf(csrf_secret: &str, cookie_val: &str) -> String {
    hmac_sign_b64url(csrf_secret, &format!("approve-csrf:{cookie_val}"))
}

fn verify_session_csrf(csrf_secret: &str, cookie_val: &str, token: &str) -> bool {
    hmac_verify_b64url(csrf_secret, &format!("approve-csrf:{cookie_val}"), token)
}

pub fn approval_router(store: Arc<RwLock<Store>>) -> Router {
    Router::new()
        .route("/approve", get(approve_get))
        .route("/approve/login", post(approve_login))
        .route("/approve/decision", post(approve_decision))
        .route("/approve/grant", post(approve_grant))
        .route("/approve/revoke", post(approve_revoke))
        .route("/approve/logout", post(approve_logout))
        .with_state(store)
}

async fn approve_get(
    State(store): State<Arc<RwLock<Store>>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Html<String> {
    let st = store.read().await;
    let err_html = query
        .get("error")
        .filter(|s| !s.is_empty())
        .map(|e| format!(r#"<p style="color:#ef4444"><strong>{}</strong></p>"#, esc_html(e)))
        .unwrap_or_default();

    let cookie_opt = extract_cookie(&headers, "bridge_approve")
        .and_then(|v| valid_cookie(&st.secrets.session_secret, &v));

    let Some(cookie_val) = cookie_opt else {
        return page(
            "Approve access",
            &format!(
                r#"<h1>Gemini Local Bridge</h1>
<p>Access approvals for <span class="mono">{}</span>.</p>
{err_html}
<div class="card">
  <form method="post" action="/approve/login">
    <label for="pin"><strong>Access PIN</strong></label>
    <input id="pin" name="pin" type="password" inputmode="numeric" autocomplete="one-time-code" placeholder="6-digit PIN" required autofocus>
    <button type="submit">Unlock</button>
  </form>
</div>
<p><small>Check your Gemini Local Bridge desktop app for the PIN, or approve directly from the desktop window.</small></p>"#,
                esc_html(&st.cfg.workspace)
            ),
            false,
        );
    };

    let csrf = session_csrf(&st.secrets.csrf_secret, &cookie_val);
    let csrf_input = format!(r#"<input type="hidden" name="csrf" value="{}">"#, esc_html(&csrf));

    let pending = st.pending_requests();
    let active = st.active_grants();

    let pending_html = if pending.is_empty() {
        "<p>No pending requests.</p>".to_string()
    } else {
        pending
            .iter()
            .map(|r| {
                let kind_str = if r.kind == GrantKind::Program { "program" } else { "path" };
                let mins = ((r.expires_at - now_ms()) / 60_000).max(1);
                format!(
                    r#"<div class="card">
  <div><span class="kind {kind_str}">{kind_str}</span></div>
  <div class="mono" style="margin:.5rem 0">{}</div>
  <div><strong>Reason:</strong> {}</div>
  <div><small>Request {} · {mins} min left</small></div>
  <div class="row" style="margin-top:.75rem">
    <form method="post" action="/approve/decision">{csrf_input}<input type="hidden" name="id" value="{}"><input type="hidden" name="decision" value="allow_once"><button type="submit">Allow once ({} min)</button></form>
    <form method="post" action="/approve/decision">{csrf_input}<input type="hidden" name="id" value="{}"><input type="hidden" name="decision" value="allow_session"><button type="submit" class="secondary">Allow until restart</button></form>
    <form method="post" action="/approve/decision">{csrf_input}<input type="hidden" name="id" value="{}"><input type="hidden" name="decision" value="deny"><button type="submit" class="deny">Deny</button></form>
  </div>
</div>"#,
                    esc_html(&r.target),
                    esc_html(&r.reason),
                    esc_html(&r.id),
                    esc_html(&r.id),
                    st.cfg.approval_ttl_minutes,
                    esc_html(&r.id),
                    esc_html(&r.id)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let active_html = if active.is_empty() {
        "<p>No active grants.</p>".to_string()
    } else {
        active
            .iter()
            .map(|g| {
                let kind_str = if g.kind == GrantKind::Program { "program" } else { "path" };
                let mode_str = if g.mode == GrantMode::Session {
                    "until restart"
                } else {
                    "once"
                };
                format!(
                    r#"<div class="card">
  <div><span class="kind {kind_str}">{kind_str}</span> <span class="mono">{}</span></div>
  <div><small>{mode_str}</small></div>
  <form method="post" action="/approve/revoke">{csrf_input}<input type="hidden" name="id" value="{}"><button type="submit" class="deny" style="margin-top:.5rem">Revoke</button></form>
</div>"#,
                    esc_html(&g.target),
                    esc_html(&g.id)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    page(
        "Approve access",
        &format!(
            r#"<h1>Approvals</h1>
<p>Workspace: <span class="mono">{}</span></p>
{err_html}
<h2>Pending ({})</h2>
{pending_html}
<h2>Grant access manually</h2>
<div class="card">
  <form method="post" action="/approve/grant">
    {csrf_input}
    <label for="kind"><strong>Type</strong></label>
    <select id="kind" name="kind">
      <option value="path">Folder or file path</option>
      <option value="program">Program</option>
    </select>
    <label for="target"><strong>Target</strong></label>
    <input id="target" name="target" type="text" placeholder="C:\Users\YourName\Downloads  or  magick" required>
    <label for="mode"><strong>Duration</strong></label>
    <select id="mode" name="mode">
      <option value="session">Until the bridge restarts (best for browsing a folder)</option>
      <option value="once">Once ({} min, single tool call)</option>
    </select>
    <button type="submit">Grant</button>
  </form>
  <p><small>Folder grants cover files inside that folder. Bridge config/secrets folders can never be granted.</small></p>
</div>
<h2>Active grants ({})</h2>
{active_html}
<form method="post" action="/approve/logout">{csrf_input}<button type="submit" class="link">Lock this page</button></form>"#,
            esc_html(&st.cfg.workspace),
            pending.len(),
            st.cfg.approval_ttl_minutes,
            active.len()
        ),
        !pending.is_empty(),
    )
}

async fn approve_login(
    State(store): State<Arc<RwLock<Store>>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let ip = peer_ip(&addr, &headers);
    let mut st = store.write().await;

    let lock = st.pin_lock_seconds(&ip);
    if lock > 0 {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            page(
                "Locked",
                &format!("<h1>Too many attempts</h1><p>Try again in {lock} seconds.</p>"),
                false,
            ),
        )
            .into_response();
    }

    let pin = form.get("pin").map(String::as_str).unwrap_or("");
    if !verify_pin(pin, &st.cfg.pin_hash) {
        st.pin_failed(&ip);
        st.audit("approval_pin_failed", serde_json::json!({ "ip": ip }));
        return Redirect::to("/approve?error=Incorrect%20PIN").into_response();
    }

    st.pin_succeeded(&ip);
    let cookie = make_cookie(&st.secrets.session_secret);
    let is_https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("https"))
        .unwrap_or(false);
    let secure_attr = if is_https { "; Secure" } else { "" };
    let hdr = format!(
        "bridge_approve={cookie}; HttpOnly; SameSite=Lax; Path=/; Max-Age=1800{secure_attr}"
    );
    ([(header::SET_COOKIE, hdr)], Redirect::to("/approve")).into_response()
}

fn check_session_and_csrf(
    st: &Store,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> Result<(), Response> {
    let cookie_val = extract_cookie(headers, "bridge_approve")
        .and_then(|v| valid_cookie(&st.secrets.session_secret, &v))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                page("Locked", r#"<h1>Session expired</h1><p><a href="/approve">Unlock again</a></p>"#, false),
            )
                .into_response()
        })?;
    let csrf = form.get("csrf").map(String::as_str).unwrap_or("");
    if !verify_session_csrf(&st.secrets.csrf_secret, &cookie_val, csrf) {
        return Err((
            StatusCode::FORBIDDEN,
            page("Invalid request", r#"<h1>Invalid CSRF token</h1><p><a href="/approve">Reload page</a></p>"#, false),
        )
            .into_response());
    }
    Ok(())
}

async fn approve_decision(
    State(store): State<Arc<RwLock<Store>>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut st = store.write().await;
    if let Err(resp) = check_session_and_csrf(&st, &headers, &form) {
        return resp;
    }
    let id = form.get("id").map(String::as_str).unwrap_or("");
    let decision = form.get("decision").map(String::as_str).unwrap_or("");
    if matches!(decision, "deny" | "allow_once" | "allow_session") {
        let _ = st.decide_request(id, decision);
    }
    Redirect::to("/approve").into_response()
}

async fn approve_grant(
    State(store): State<Arc<RwLock<Store>>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut st = store.write().await;
    if let Err(resp) = check_session_and_csrf(&st, &headers, &form) {
        return resp;
    }
    let kind = if form.get("kind").map(String::as_str) == Some("program") {
        GrantKind::Program
    } else {
        GrantKind::Path
    };
    let mode = if form.get("mode").map(String::as_str) == Some("once") {
        GrantMode::Once
    } else {
        GrantMode::Session
    };
    let raw_target = form.get("target").map(String::as_str).unwrap_or("").trim();
    if raw_target.is_empty() {
        return Redirect::to("/approve").into_response();
    }

    let final_target = if kind == GrantKind::Path {
        let policy = Policy::from_config(&st.cfg);
        let resolved = policy.resolve(raw_target);
        if resolved.forbidden {
            return Redirect::to("/approve?error=Bridge%20secrets%20folder%20cannot%20be%20granted")
                .into_response();
        }
        if !Path::new(&resolved.abs).exists() {
            return Redirect::to("/approve?error=Path%20does%20not%20exist").into_response();
        }
        resolved.real.to_string_lossy().to_string()
    } else {
        raw_target
            .to_lowercase()
            .trim_end_matches(".exe")
            .to_string()
    };

    let grant = st.add_grant(kind.clone(), final_target.clone(), mode.clone(), "manual".into());
    st.audit(
        "grant_created_manually",
        serde_json::json!({ "id": grant.id, "kind": kind, "target": final_target, "mode": mode }),
    );
    Redirect::to("/approve").into_response()
}

async fn approve_revoke(
    State(store): State<Arc<RwLock<Store>>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut st = store.write().await;
    if let Err(resp) = check_session_and_csrf(&st, &headers, &form) {
        return resp;
    }
    if let Some(id) = form.get("id") {
        let _ = st.revoke_grant(id);
    }
    Redirect::to("/approve").into_response()
}

async fn approve_logout(
    State(store): State<Arc<RwLock<Store>>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let st = store.read().await;
    if let Err(resp) = check_session_and_csrf(&st, &headers, &form) {
        return resp;
    }
    (
        [(
            header::SET_COOKIE,
            "bridge_approve=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
        )],
        Redirect::to("/approve"),
    )
        .into_response()
}
