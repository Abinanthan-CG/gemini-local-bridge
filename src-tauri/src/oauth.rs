use crate::crypto::{
    ct_eq, hmac_sign_b64url, hmac_verify_b64url, random_b64url, random_hex, sha256_b64url,
    verify_pin,
};
use crate::store::{AuthCode, OAuthClient, Store, TokenRecord};
use axum::{
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;
use url::Url;

pub fn valid_redirect(uri: &str) -> bool {
    if uri.len() > 2000 {
        return false;
    }
    static GOOGLE_RE: OnceLock<Regex> = OnceLock::new();
    static LOCAL_RE: OnceLock<Regex> = OnceLock::new();
    let g = GOOGLE_RE.get_or_init(|| {
        Regex::new(r"^https://oauth-redirect(?:-sandbox|-test)?\.googleusercontent\.com/[ar]/[A-Za-z0-9._~\-/]+$").unwrap()
    });
    let l = LOCAL_RE.get_or_init(|| {
        Regex::new(r"^http://(?:127\.0\.0\.1|localhost|\[::1\]):\d{1,5}/[A-Za-z0-9._~\-/]*$")
            .unwrap()
    });
    g.is_match(uri) || l.is_match(uri)
}

pub fn esc_html(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn origin_of(headers: &HeaderMap, store: &Store) -> String {
    if let Some(ref explicit) = store.cfg.public_origin {
        if !explicit.trim().is_empty() {
            return explicit.trim_end_matches('/').to_string();
        }
    }
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .filter(|s| *s == "https" || *s == "http")
        .unwrap_or("http");
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("127.0.0.1:8787");
    format!("{proto}://{host}")
}

/// Returns peer IP without blindly trusting spoofable CDN headers.
pub fn peer_ip(addr: &SocketAddr, headers: &HeaderMap) -> String {
    // Only consider x-forwarded-for if request arrived from loopback (local Tailscale / reverse proxy).
    if addr.ip().is_loopback() {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next().map(str::trim).filter(|s| !s.is_empty()) {
                return first.to_string();
            }
        }
    }
    addr.ip().to_string()
}

pub const BRAND_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="32" height="32" fill="none" style="flex-shrink:0;border-radius:7px"><rect x="24" y="24" width="464" height="464" rx="112" fill="#0d1118" stroke="#38bdf8" stroke-opacity=".45" stroke-width="10"/><path d="M144 374 H368" stroke="#334155" stroke-width="12" stroke-linecap="round"/><path d="M126 374 V316 C126 258 184 234 256 234 C328 234 386 258 386 316 V374" stroke="#38bdf8" stroke-width="28" stroke-linecap="round"/><circle cx="126" cy="374" r="20" fill="#0d1118" stroke="#e0f2fe" stroke-width="12"/><circle cx="386" cy="374" r="20" fill="#0d1118" stroke="#38bdf8" stroke-width="12"/><path d="M256 80 C261 119 275 133 314 138 C275 143 261 157 256 196 C251 157 237 143 198 138 C237 133 251 119 256 80 Z" fill="#7dd3fc"/><circle cx="256" cy="138" r="7" fill="#fff"/></svg>"##;

pub fn oauth_page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{}</title>
<style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}
body{{margin:0;min-height:100vh;font:14.5px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;color:#e6edf5;background:radial-gradient(700px 260px at 50% -10%,rgba(56,189,248,.09),transparent 70%),#080b10;padding:2rem 1rem}}
.wrap{{max-width:30rem;margin:0 auto}}
.brand{{display:flex;align-items:center;gap:.7rem;margin-bottom:1.25rem}}
.brand-name{{font-weight:650;font-size:.95rem;letter-spacing:-.01em}}.brand-sub{{font-size:.75rem;color:#6f7f96}}
.card{{background:#0e131b;border:1px solid rgba(255,255,255,.09);border-radius:12px;padding:1.25rem;margin:.9rem 0}}
h1{{font-size:1.25rem;font-weight:650;letter-spacing:-.02em;margin:0 0 .35rem}}
p{{margin:.4rem 0;color:#94a3b8;font-size:.9rem}}
.kv{{padding:.55rem 0;border-bottom:1px solid rgba(255,255,255,.07)}}.kv:last-child{{border-bottom:0;padding-bottom:0}}
.k{{font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;color:#6f7f96}}
.mono{{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;word-break:break-all;font-size:.82rem;color:#e6edf5;margin-top:.15rem}}
input{{width:100%;padding:.75rem .85rem;border:1px solid rgba(255,255,255,.16);border-radius:8px;background:#080b10;color:#e6edf5;font-size:1.1rem;letter-spacing:3px;margin:.5rem 0}}
input:focus{{outline:none;border-color:#38bdf8}}
button{{width:100%;padding:.8rem;border:1px solid #38bdf8;border-radius:8px;font-size:.95rem;font-weight:600;background:#0284c7;color:#fff;margin-top:.45rem;cursor:pointer}}
button:hover{{background:#0369a1}}
.err{{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);color:#fca5a5;padding:.6rem .8rem;border-radius:8px;font-size:.85rem;margin:.6rem 0}}
</style></head><body><div class="wrap"><div class="brand">{BRAND_SVG}<div><div class="brand-name">Gemini Local Bridge</div><div class="brand-sub">OAuth 2.1 · PKCE S256</div></div></div>{body}</div></body></html>"#,
        esc_html(title)
    ))
}

#[derive(Deserialize)]
struct RegisterReq {
    client_name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    token_endpoint_auth_method: Option<String>,
}

#[derive(Serialize)]
struct ErrorJson {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

fn err_json(status: StatusCode, code: &str, desc: Option<&str>) -> Response {
    (
        status,
        Json(ErrorJson {
            error: code.into(),
            error_description: desc.map(String::from),
        }),
    )
        .into_response()
}

pub fn oauth_router(store: Arc<RwLock<Store>>) -> Router {
    Router::new()
        .route("/.well-known/oauth-authorization-server", get(as_metadata))
        .route("/.well-known/openid-configuration", get(as_metadata))
        .route("/.well-known/oauth-protected-resource", get(prm_metadata))
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(prm_metadata),
        )
        .route("/register", post(register_client))
        .route("/authorize", get(authorize_get).post(authorize_post))
        .route("/token", post(token_post))
        .route("/revoke", post(revoke_post))
        .with_state(store)
}

async fn as_metadata(
    State(store): State<Arc<RwLock<Store>>>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let st = store.read().await;
    let origin = origin_of(&headers, &st);
    Json(serde_json::json!({
        "issuer": origin,
        "authorization_endpoint": format!("{origin}/authorize"),
        "token_endpoint": format!("{origin}/token"),
        "registration_endpoint": format!("{origin}/register"),
        "revocation_endpoint": format!("{origin}/revoke"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
        "scopes_supported": ["mcp"],
        "service_documentation": format!("{origin}/"),
        "ui_locales_supported": ["en"]
    }))
}

async fn prm_metadata(
    State(store): State<Arc<RwLock<Store>>>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let st = store.read().await;
    let origin = origin_of(&headers, &st);
    Json(serde_json::json!({
        "resource": format!("{origin}/mcp"),
        "authorization_servers": [origin],
        "scopes_supported": ["mcp"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Gemini Local Bridge",
        "resource_documentation": format!("{origin}/")
    }))
}

async fn register_client(
    State(store): State<Arc<RwLock<Store>>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RegisterReq>,
) -> Response {
    let ip = peer_ip(&addr, &headers);
    let mut st = store.write().await;

    if !st.is_pairing_open() {
        st.audit("register_blocked_pairing_closed", serde_json::json!({ "ip": ip }));
        return err_json(
            StatusCode::FORBIDDEN,
            "pairing_closed",
            Some("Pairing Mode is off. Click 'Enable Pairing' in the Gemini Local Bridge desktop app first."),
        );
    }

    if !st.check_register_rate(&ip) {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "rate_limited", None);
    }

    let uris = body.redirect_uris.unwrap_or_default();
    if uris.is_empty() || !uris.iter().all(|u| valid_redirect(u)) {
        return err_json(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            Some("redirect_uris must contain Google or localhost callbacks."),
        );
    }

    let auth_method = match body.token_endpoint_auth_method.as_deref() {
        Some("none") => "none",
        _ => "client_secret_post",
    };

    let client = OAuthClient {
        client_id: format!("gcb_{}", random_hex(12)),
        client_secret: random_b64url(24),
        client_name: body
            .client_name
            .unwrap_or_else(|| "Gemini Apps".into())
            .chars()
            .take(120)
            .collect(),
        redirect_uris: uris,
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        response_types: vec!["code".into()],
        token_endpoint_auth_method: auth_method.into(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let _ = st.add_client(client.clone());
    st.audit(
        "client_registered",
        serde_json::json!({ "clientId": client.client_id, "name": client.client_name, "ip": ip }),
    );

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "client_id_issued_at": chrono::Utc::now().timestamp(),
            "client_secret_expires_at": 0,
            "client_name": client.client_name,
            "redirect_uris": client.redirect_uris,
            "grant_types": client.grant_types,
            "response_types": client.response_types,
            "token_endpoint_auth_method": client.token_endpoint_auth_method
        })),
    )
        .into_response()
}

fn validate_authorize(
    st: &Store,
    params: &HashMap<String, String>,
) -> Result<OAuthClient, (&'static str, &'static str)> {
    let cid = params.get("client_id").map(String::as_str).unwrap_or("");
    let client = st
        .clients
        .get(cid)
        .cloned()
        .ok_or(("invalid_client", "Unknown client_id."))?;
    let ruri = params.get("redirect_uri").map(String::as_str).unwrap_or("");
    if !client.redirect_uris.iter().any(|u| u == ruri) {
        return Err(("invalid_redirect_uri", "redirect_uri is not registered."));
    }
    if params.get("response_type").map(String::as_str) != Some("code") {
        return Err(("unsupported_response_type", "Only response_type=code is supported."));
    }
    let cc = params
        .get("code_challenge")
        .map(String::as_str)
        .unwrap_or("");
    static CC_RE: OnceLock<Regex> = OnceLock::new();
    let re = CC_RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9\-._~]{43,128}$").unwrap());
    if !re.is_match(cc) {
        return Err(("invalid_request", "PKCE code_challenge is required."));
    }
    let ccm = params
        .get("code_challenge_method")
        .map(String::as_str)
        .unwrap_or("plain");
    if !ccm.eq_ignore_ascii_case("S256") {
        return Err(("invalid_request", "Only S256 PKCE is supported."));
    }
    Ok(client)
}

fn make_csrf(secret: &str, client_id: &str, code_challenge: &str) -> String {
    let ts = chrono::Utc::now().timestamp();
    let msg = format!("oauth:{ts}:{client_id}:{code_challenge}");
    let sig = hmac_sign_b64url(secret, &msg);
    format!("{ts}.{sig}")
}

fn verify_csrf(secret: &str, token: &str, client_id: &str, code_challenge: &str) -> bool {
    let Some((ts_s, sig)) = token.split_once('.') else {
        return false;
    };
    let Ok(ts) = ts_s.parse::<i64>() else {
        return false;
    };
    let age = chrono::Utc::now().timestamp() - ts;
    if !(0..=600).contains(&age) {
        return false;
    }
    let msg = format!("oauth:{ts}:{client_id}:{code_challenge}");
    hmac_verify_b64url(secret, &msg, sig)
}

fn consent_html(
    params: &HashMap<String, String>,
    client: &OAuthClient,
    csrf_secret: &str,
    error: &str,
) -> Html<String> {
    let cc = params
        .get("code_challenge")
        .map(String::as_str)
        .unwrap_or("");
    let csrf = make_csrf(csrf_secret, &client.client_id, cc);
    let mut hidden = String::new();
    for (k, v) in params {
        if k == "pin" || k == "csrf" {
            continue;
        }
        hidden.push_str(&format!(
            r#"<input type="hidden" name="{}" value="{}">"#,
            esc_html(k),
            esc_html(v)
        ));
    }
    hidden.push_str(&format!(
        r#"<input type="hidden" name="csrf" value="{}">"#,
        esc_html(&csrf)
    ));

    let err_block = if error.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="err">{}</div>"#, esc_html(error))
    };
    let ruri = params.get("redirect_uri").map(String::as_str).unwrap_or("");

    oauth_page(
        "Authorize Gemini Local Bridge",
        &format!(
            r#"<h1>Authorize connection</h1>
<p><strong>{}</strong> wants to connect to local workspace and CLI tools on this Windows PC.</p>
<div class="card">
  <div class="kv"><div class="k">Client</div><div class="mono">{}</div></div>
  <div class="kv"><div class="k">Scope</div><div class="mono">mcp</div></div>
  <div class="kv"><div class="k">Callback</div><div class="mono">{}</div></div>
</div>
<div class="card">
  <p style="margin-top:0">Enter the 6-digit Access PIN shown in your Gemini Local Bridge desktop app.</p>
  {err_block}
  <form method="post" action="/authorize">
    {hidden}
    <input name="pin" type="password" inputmode="numeric" autocomplete="one-time-code" placeholder="6-digit PIN" autofocus required>
    <button type="submit">Approve &amp; Connect</button>
  </form>
</div>
<p style="font-size:.8rem">If you did not initiate this pairing, close this tab. No access is granted without the PIN.</p>"#,
            esc_html(&client.client_name),
            esc_html(&client.client_id),
            esc_html(ruri)
        ),
    )
}

async fn authorize_get(
    State(store): State<Arc<RwLock<Store>>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let st = store.read().await;
    if !st.is_pairing_open() {
        return (
            StatusCode::FORBIDDEN,
            oauth_page(
                "Pairing closed",
                "<h1>Pairing Mode is off</h1><p>Open the Gemini Local Bridge desktop app and click <strong>Enable Pairing</strong> to connect a new client.</p>",
            ),
        )
            .into_response();
    }
    match validate_authorize(&st, &params) {
        Ok(client) => consent_html(&params, &client, &st.secrets.csrf_secret, "").into_response(),
        Err((_, desc)) => (
            StatusCode::BAD_REQUEST,
            oauth_page("Invalid request", &format!("<h1>Invalid request</h1><p>{}</p>", esc_html(desc))),
        )
            .into_response(),
    }
}

async fn authorize_post(
    State(store): State<Arc<RwLock<Store>>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(params): Form<HashMap<String, String>>,
) -> Response {
    let ip = peer_ip(&addr, &headers);
    let mut st = store.write().await;

    if !st.is_pairing_open() {
        return (
            StatusCode::FORBIDDEN,
            oauth_page(
                "Pairing closed",
                "<h1>Pairing Mode is off</h1><p>Enable Pairing Mode in the desktop app and retry.</p>",
            ),
        )
            .into_response();
    }

    let client = match validate_authorize(&st, &params) {
        Ok(c) => c,
        Err((_, desc)) => {
            return (
                StatusCode::BAD_REQUEST,
                oauth_page("Invalid request", &format!("<h1>Invalid request</h1><p>{}</p>", esc_html(desc))),
            )
                .into_response()
        }
    };

    let cc = params
        .get("code_challenge")
        .map(String::as_str)
        .unwrap_or("");
    let csrf = params.get("csrf").map(String::as_str).unwrap_or("");
    if !verify_csrf(&st.secrets.csrf_secret, csrf, &client.client_id, cc) {
        return (
            StatusCode::BAD_REQUEST,
            consent_html(
                &params,
                &client,
                &st.secrets.csrf_secret,
                "Session expired. Please submit the PIN again.",
            ),
        )
            .into_response();
    }

    let lock = st.pin_lock_seconds(&ip);
    if lock > 0 {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            oauth_page(
                "Locked",
                &format!("<h1>Too many attempts</h1><p>Try again in {lock} seconds.</p>"),
            ),
        )
            .into_response();
    }

    let pin = params.get("pin").map(String::as_str).unwrap_or("");
    if !verify_pin(pin, &st.cfg.pin_hash) {
        st.pin_failed(&ip);
        st.audit("oauth_pin_failed", serde_json::json!({ "ip": ip }));
        return (
            StatusCode::UNAUTHORIZED,
            consent_html(&params, &client, &st.secrets.csrf_secret, "Incorrect PIN."),
        )
            .into_response();
    }

    st.pin_succeeded(&ip);
    let code = random_b64url(24);
    let ruri = params
        .get("redirect_uri")
        .cloned()
        .unwrap_or_default();
    st.add_code(AuthCode {
        value: code.clone(),
        client_id: client.client_id.clone(),
        redirect_uri: ruri.clone(),
        code_challenge: cc.to_string(),
        scope: "mcp".into(),
        expires_at: crate::store::now_ms() + 60_000,
    });
    st.audit(
        "oauth_code_issued",
        serde_json::json!({ "clientId": client.client_id, "ip": ip }),
    );

    let Ok(mut url) = Url::parse(&ruri) else {
        return err_json(StatusCode::BAD_REQUEST, "invalid_redirect_uri", None);
    };
    url.query_pairs_mut().append_pair("code", &code);
    if let Some(state) = params.get("state").filter(|s| !s.is_empty()) {
        url.query_pairs_mut().append_pair("state", state);
    }
    Redirect::to(url.as_str()).into_response()
}

fn extract_client_auth(headers: &HeaderMap, form: &HashMap<String, String>) -> (String, String) {
    if let Some(cid) = form.get("client_id").filter(|s| !s.is_empty()) {
        return (
            cid.clone(),
            form.get("client_secret").cloned().unwrap_or_default(),
        );
    }
    if let Some(auth) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(rest) = auth.strip_prefix("Basic ").or_else(|| auth.strip_prefix("basic ")) {
            if let Ok(decoded) = STANDARD.decode(rest.trim()) {
                let s = String::from_utf8_lossy(&decoded);
                if let Some((id, sec)) = s.split_once(':') {
                    return (id.to_string(), sec.to_string());
                }
            }
        }
    }
    (String::new(), String::new())
}

async fn token_post(
    State(store): State<Arc<RwLock<Store>>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let (id, secret) = extract_client_auth(&headers, &form);
    let mut st = store.write().await;

    let Some(client) = st.clients.get(&id).cloned() else {
        return err_json(StatusCode::UNAUTHORIZED, "invalid_client", None);
    };
    if client.token_endpoint_auth_method != "none" && !ct_eq(&secret, &client.client_secret) {
        return err_json(StatusCode::UNAUTHORIZED, "invalid_client", None);
    }

    let grant_type = form.get("grant_type").map(String::as_str).unwrap_or("");
    if grant_type == "authorization_code" {
        let code_val = form.get("code").map(String::as_str).unwrap_or("");
        let Some(entry) = st.take_code(code_val) else {
            return err_json(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                Some("Code missing, expired or already used."),
            );
        };
        if entry.client_id != client.client_id {
            return err_json(StatusCode::BAD_REQUEST, "invalid_grant", None);
        }
        let ruri = form.get("redirect_uri").map(String::as_str).unwrap_or("");
        if entry.redirect_uri != ruri {
            return err_json(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                Some("redirect_uri mismatch."),
            );
        }
        let verifier = form.get("code_verifier").map(String::as_str).unwrap_or("");
        if verifier.len() < 43 || verifier.len() > 128 {
            return err_json(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                Some("Bad code_verifier."),
            );
        }
        let computed = sha256_b64url(verifier);
        if !ct_eq(&computed, &entry.code_challenge) {
            return err_json(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                Some("PKCE verification failed."),
            );
        }

        let tokens = st.issue_tokens(&client.client_id, &entry.scope);
        st.audit(
            "oauth_token_issued",
            serde_json::json!({ "clientId": client.client_id }),
        );
        return (
            [(header::CACHE_CONTROL, "no-store")],
            Json(tokens),
        )
            .into_response();
    }

    if grant_type == "refresh_token" {
        let rt = form.get("refresh_token").map(String::as_str).unwrap_or("");
        if let Some(tokens) = st.refresh_access(rt, &client.client_id) {
            st.audit(
                "oauth_token_refreshed",
                serde_json::json!({ "clientId": client.client_id }),
            );
            return (
                [(header::CACHE_CONTROL, "no-store")],
                Json(tokens),
            )
                .into_response();
        }
        return err_json(StatusCode::BAD_REQUEST, "invalid_grant", None);
    }

    err_json(StatusCode::BAD_REQUEST, "unsupported_grant_type", None)
}

async fn revoke_post(
    State(store): State<Arc<RwLock<Store>>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let ip = peer_ip(&addr, &headers);
    let raw = form.get("token").map(String::as_str).unwrap_or("");
    if !raw.is_empty() {
        let mut st = store.write().await;
        if st.revoke_token(raw) {
            st.audit("oauth_token_revoked", serde_json::json!({ "ip": ip }));
        }
    }
    Json(serde_json::json!({}))
}

pub async fn require_bearer(
    store: &Arc<RwLock<Store>>,
    headers: &HeaderMap,
) -> Result<TokenRecord, Response> {
    let mut st = store.write().await;
    let origin = origin_of(headers, &st);
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let Some(token) = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        let hdr = format!(
            r#"Bearer resource_metadata="{origin}/.well-known/oauth-protected-resource""#
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, hdr)],
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response());
    };

    if let Some(rec) = st.lookup_access_token(token) {
        Ok(rec)
    } else {
        let hdr = format!(
            r#"Bearer error="invalid_token", resource_metadata="{origin}/.well-known/oauth-protected-resource""#
        );
        Err((
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, hdr)],
            Json(serde_json::json!({ "error": "invalid_token" })),
        )
            .into_response())
    }
}
