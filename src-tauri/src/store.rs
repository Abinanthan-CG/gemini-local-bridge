use crate::config::{data_dir, logs_dir, write_atomic, BridgeConfig, BridgeSecrets};
use crate::crypto::{dpapi_protect, dpapi_unprotect, random_b64url, random_hex, sha256_hex};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

pub fn normalize_path_key(p: &str) -> String {
    let mut s = p.replace('/', "\\");
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        s = stripped.to_string();
    }
    while s.len() > 3 && s.ends_with('\\') {
        s.pop();
    }
    s.to_lowercase()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub client_id: String,
    pub scope: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenBook {
    pub access: HashMap<String, TokenRecord>,
    pub refresh: HashMap<String, TokenRecord>,
}

#[derive(Debug, Clone)]
pub struct AuthCode {
    pub value: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scope: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GrantKind {
    Path,
    Program,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GrantMode {
    Once,
    Session,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub id: String,
    pub kind: GrantKind,
    pub target: String,
    pub normalized: String,
    pub mode: GrantMode,
    pub request_id: String,
    pub boot_id: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessRequest {
    pub id: String,
    pub kind: GrantKind,
    pub target: String,
    pub reason: String,
    pub client_id: String,
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub decided_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareItem {
    pub token: String,
    pub file: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub ts: String,
    pub event: String,
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct PinAttemptState {
    pub fails: u32,
    pub first_ms: i64,
    pub locked_until_ms: i64,
}

#[derive(Debug, Clone)]
struct RateBucket {
    count: u32,
    window_start_ms: i64,
}

pub struct Store {
    pub cfg: BridgeConfig,
    pub secrets: BridgeSecrets,
    pub boot_id: String,
    pub paused: bool,
    /// Pairing Mode: `/register` and `/authorize` only work while `now < pairing_until_ms`.
    pub pairing_until_ms: i64,
    /// Shown once in the desktop UI right after initial setup or PIN rotation.
    pub ephem_display_pin: Option<String>,
    pub clients: HashMap<String, OAuthClient>,
    pub tokens: TokenBook,
    pub grants: Vec<Grant>,
    pub codes: HashMap<String, AuthCode>,
    pub requests: HashMap<String, AccessRequest>,
    pub shares: HashMap<String, ShareItem>,
    pub audit_ring: VecDeque<AuditEvent>,
    /// Global PIN lockout (cannot be bypassed by spoofing headers!)
    global_pin_state: PinAttemptState,
    per_ip_pin_state: HashMap<String, PinAttemptState>,
    mcp_rate: HashMap<String, RateBucket>,
    register_rate: HashMap<String, RateBucket>,
}

fn read_dpapi_json<T: for<'de> Deserialize<'de> + Default>(filename: &str) -> T {
    let path = data_dir().join(filename);
    let Ok(bytes) = fs::read(&path) else {
        return T::default();
    };
    let Ok(plain) = dpapi_unprotect(&bytes) else {
        return T::default();
    };
    serde_json::from_slice(&plain).unwrap_or_default()
}

fn write_dpapi_json<T: Serialize>(filename: &str, value: &T) {
    let path = data_dir().join(filename);
    if let Ok(plain) = serde_json::to_vec(value) {
        if let Ok(enc) = dpapi_protect(&plain) {
            let _ = write_atomic(&path, &enc);
        }
    }
}

impl Store {
    pub fn new(cfg: BridgeConfig, secrets: BridgeSecrets, initial_pin: Option<String>) -> Self {
        let boot_id = random_hex(8);
        let clients: HashMap<String, OAuthClient> = read_dpapi_json("clients.dpapi");
        let tokens: TokenBook = read_dpapi_json("tokens.dpapi");

        // Auto-open Pairing Mode for 15 minutes on first launch (when 0 clients are registered yet).
        let pairing_until_ms = if clients.is_empty() {
            now_ms() + 15 * 60_000
        } else {
            0
        };

        let mut s = Self {
            cfg,
            secrets,
            boot_id,
            paused: false,
            pairing_until_ms,
            ephem_display_pin: initial_pin,
            clients,
            tokens,
            grants: Vec::new(),
            codes: HashMap::new(),
            requests: HashMap::new(),
            shares: HashMap::new(),
            audit_ring: VecDeque::with_capacity(200),
            global_pin_state: PinAttemptState {
                fails: 0,
                first_ms: 0,
                locked_until_ms: 0,
            },
            per_ip_pin_state: HashMap::new(),
            mcp_rate: HashMap::new(),
            register_rate: HashMap::new(),
        };
        s.load_recent_audit();
        s.prune();
        s
    }

    fn load_recent_audit(&mut self) {
        let path = logs_dir().join("audit.jsonl");
        let Ok(content) = fs::read_to_string(&path) else {
            return;
        };
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(120);
        for line in &lines[start..] {
            if let Ok(ev) = serde_json::from_str::<AuditEvent>(line) {
                if self.audit_ring.len() >= 200 {
                    self.audit_ring.pop_front();
                }
                self.audit_ring.push_back(ev);
            }
        }
    }

    pub fn audit(&mut self, event: &str, detail: serde_json::Value) {
        let ev = AuditEvent {
            ts: Utc::now().to_rfc3339(),
            event: event.to_string(),
            detail,
        };
        if self.audit_ring.len() >= 200 {
            self.audit_ring.pop_front();
        }
        self.audit_ring.push_back(ev.clone());

        let path = logs_dir().join("audit.jsonl");
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            if let Ok(line) = serde_json::to_string(&ev) {
                let _ = writeln!(f, "{line}");
            }
        }
    }

    pub fn prune(&mut self) {
        let t = now_ms();
        self.tokens.access.retain(|_, v| v.expires_at > t);
        self.tokens.refresh.retain(|_, v| v.expires_at > t);
        self.grants
            .retain(|g| !g.used && g.expires_at.map(|e| e > t).unwrap_or(true));
        self.codes.retain(|_, c| c.expires_at > t);
        self.requests
            .retain(|_, r| r.status != "pending" || r.expires_at > t);
        self.shares.retain(|_, s| s.expires_at > t);
        if self.mcp_rate.len() > 512 {
            self.mcp_rate.retain(|_, b| t - b.window_start_ms < 60_000);
        }
        if self.register_rate.len() > 256 {
            self.register_rate
                .retain(|_, b| t - b.window_start_ms < 300_000);
        }
        if self.per_ip_pin_state.len() > 256 {
            self.per_ip_pin_state
                .retain(|_, st| st.locked_until_ms > t || t - st.first_ms < 900_000);
        }
        self.persist_tokens();
    }

    pub fn persist_clients(&self) {
        write_dpapi_json("clients.dpapi", &self.clients);
    }

    pub fn persist_tokens(&self) {
        write_dpapi_json("tokens.dpapi", &self.tokens);
    }

    pub fn is_pairing_open(&self) -> bool {
        now_ms() < self.pairing_until_ms
    }

    pub fn pairing_remaining_secs(&self) -> i64 {
        ((self.pairing_until_ms - now_ms()) / 1000).max(0)
    }

    pub fn enable_pairing(&mut self, minutes: i64) {
        self.pairing_until_ms = now_ms() + minutes.clamp(1, 60) * 60_000;
        self.audit(
            "pairing_enabled",
            serde_json::json!({ "minutes": minutes }),
        );
    }

    pub fn disable_pairing(&mut self) {
        self.pairing_until_ms = 0;
        self.audit("pairing_disabled", serde_json::json!({}));
    }

    pub fn add_client(&mut self, client: OAuthClient) -> Result<(), String> {
        // Bound total registered clients to prevent unbounded state growth.
        if self.clients.len() >= 16 {
            // Remove oldest client if full.
            if let Some(oldest_id) = self
                .clients
                .values()
                .min_by_key(|c| c.created_at.clone())
                .map(|c| c.client_id.clone())
            {
                self.clients.remove(&oldest_id);
            }
        }
        self.clients.insert(client.client_id.clone(), client);
        self.persist_clients();
        Ok(())
    }

    pub fn remove_client(&mut self, client_id: &str) {
        self.clients.remove(client_id);
        self.tokens.access.retain(|_, v| v.client_id != client_id);
        self.tokens.refresh.retain(|_, v| v.client_id != client_id);
        self.persist_clients();
        self.persist_tokens();
        self.audit(
            "client_revoked",
            serde_json::json!({ "clientId": client_id }),
        );
    }

    pub fn issue_tokens(&mut self, client_id: &str, scope: &str) -> serde_json::Value {
        let access = random_b64url(32);
        let refresh = random_b64url(48);
        let t = now_ms();
        self.tokens.access.insert(
            sha256_hex(&access),
            TokenRecord {
                client_id: client_id.to_string(),
                scope: scope.to_string(),
                created_at: t,
                expires_at: t + self.cfg.token_ttl_seconds * 1000,
            },
        );
        self.tokens.refresh.insert(
            sha256_hex(&refresh),
            TokenRecord {
                client_id: client_id.to_string(),
                scope: scope.to_string(),
                created_at: t,
                expires_at: t + self.cfg.refresh_ttl_seconds * 1000,
            },
        );
        self.persist_tokens();
        // Auto-close Pairing Mode once a client successfully completes token exchange!
        if self.pairing_until_ms > 0 {
            self.pairing_until_ms = 0;
            self.audit(
                "pairing_auto_closed",
                serde_json::json!({ "clientId": client_id }),
            );
        }
        serde_json::json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.cfg.token_ttl_seconds,
            "refresh_token": refresh,
            "scope": scope
        })
    }

    pub fn refresh_access(
        &mut self,
        refresh_token: &str,
        client_id: &str,
    ) -> Option<serde_json::Value> {
        let hash = sha256_hex(refresh_token);
        let t = now_ms();
        let entry = self.tokens.refresh.get_mut(&hash)?;
        if entry.expires_at <= t || entry.client_id != client_id {
            return None;
        }
        let scope = entry.scope.clone();
        // Persistent non-rotating refresh token extended on each refresh (required for Gemini stability).
        entry.expires_at = t + self.cfg.refresh_ttl_seconds * 1000;

        let access = random_b64url(32);
        self.tokens.access.insert(
            sha256_hex(&access),
            TokenRecord {
                client_id: client_id.to_string(),
                scope: scope.clone(),
                created_at: t,
                expires_at: t + self.cfg.token_ttl_seconds * 1000,
            },
        );
        self.persist_tokens();
        Some(serde_json::json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.cfg.token_ttl_seconds,
            "refresh_token": refresh_token,
            "scope": scope
        }))
    }

    pub fn lookup_access_token(&mut self, raw: &str) -> Option<TokenRecord> {
        let hash = sha256_hex(raw);
        let t = now_ms();
        if let Some(rec) = self.tokens.access.get(&hash) {
            if rec.expires_at > t {
                return Some(rec.clone());
            }
        }
        if self.tokens.access.remove(&hash).is_some() {
            self.persist_tokens();
        }
        None
    }

    pub fn revoke_token(&mut self, raw: &str) -> bool {
        let hash = sha256_hex(raw);
        let a = self.tokens.access.remove(&hash).is_some();
        let r = self.tokens.refresh.remove(&hash).is_some();
        if a || r {
            self.persist_tokens();
            true
        } else {
            false
        }
    }

    pub fn add_code(&mut self, code: AuthCode) {
        self.codes.retain(|_, c| c.expires_at > now_ms());
        self.codes.insert(code.value.clone(), code);
    }

    pub fn take_code(&mut self, value: &str) -> Option<AuthCode> {
        let c = self.codes.remove(value)?;
        if c.expires_at <= now_ms() {
            return None;
        }
        Some(c)
    }

    pub fn add_grant(
        &mut self,
        kind: GrantKind,
        target: String,
        mode: GrantMode,
        request_id: String,
    ) -> Grant {
        let normalized = match kind {
            GrantKind::Path => normalize_path_key(&target),
            GrantKind::Program => target.to_lowercase().trim_end_matches(".exe").to_string(),
        };
        let t = now_ms();
        let grant = Grant {
            id: random_hex(6),
            kind,
            target,
            normalized,
            mode: mode.clone(),
            request_id,
            boot_id: self.boot_id.clone(),
            created_at: t,
            expires_at: if mode == GrantMode::Once {
                Some(t + self.cfg.approval_ttl_minutes * 60_000)
            } else {
                None
            },
            used: false,
        };
        self.grants.push(grant.clone());
        grant
    }

    pub fn find_grant(&self, kind: &GrantKind, value: &str) -> Option<Grant> {
        let candidate = match kind {
            GrantKind::Path => normalize_path_key(value),
            GrantKind::Program => value.to_lowercase().trim_end_matches(".exe").to_string(),
        };
        let t = now_ms();
        self.grants
            .iter()
            .find(|g| {
                if &g.kind != kind || g.used {
                    return false;
                }
                if let Some(exp) = g.expires_at {
                    if exp <= t {
                        return false;
                    }
                }
                match kind {
                    GrantKind::Program => g.normalized == candidate,
                    GrantKind::Path => {
                        candidate == g.normalized
                            || candidate.starts_with(&format!("{}\\", g.normalized))
                    }
                }
            })
            .cloned()
    }

    /// BUG FIX vs Node prototype: ONLY consume `Once` grants! `Session` grants persist until revoked or restart.
    pub fn consume_grant_if_once(&mut self, grant_id: &str) {
        if let Some(pos) = self.grants.iter().position(|g| g.id == grant_id) {
            if self.grants[pos].mode == GrantMode::Once {
                self.grants.remove(pos);
            }
        }
    }

    pub fn revoke_grant(&mut self, grant_id: &str) -> Option<Grant> {
        let pos = self.grants.iter().position(|g| g.id == grant_id)?;
        let g = self.grants.remove(pos);
        self.audit(
            "grant_revoked",
            serde_json::json!({ "id": g.id, "kind": g.kind, "target": g.target }),
        );
        Some(g)
    }

    pub fn active_grants(&self) -> Vec<Grant> {
        let t = now_ms();
        self.grants
            .iter()
            .filter(|g| !g.used && g.expires_at.map(|e| e > t).unwrap_or(true))
            .cloned()
            .collect()
    }

    pub fn add_request(
        &mut self,
        kind: GrantKind,
        target: String,
        reason: String,
        client_id: String,
    ) -> AccessRequest {
        let id = random_hex(3).to_uppercase();
        let t = now_ms();
        let req = AccessRequest {
            id: id.clone(),
            kind,
            target,
            reason,
            client_id,
            status: "pending".into(),
            created_at: t,
            expires_at: t + self.cfg.pending_request_ttl_minutes * 60_000,
            decided_at: None,
        };
        self.requests.insert(id, req.clone());
        req
    }

    pub fn pending_requests(&self) -> Vec<AccessRequest> {
        let t = now_ms();
        self.requests
            .values()
            .filter(|r| r.status == "pending" && r.expires_at > t)
            .cloned()
            .collect()
    }

    pub fn decide_request(&mut self, id: &str, decision: &str) -> Option<AccessRequest> {
        let key = id.to_uppercase();
        let t = now_ms();
        let req = self.requests.get_mut(&key)?;
        if req.status != "pending" || req.expires_at <= t {
            return None;
        }
        req.status = if decision == "deny" {
            "denied".into()
        } else {
            "approved".into()
        };
        req.decided_at = Some(t);
        let cloned = req.clone();
        if decision == "allow_once" || decision == "allow_session" {
            let mode = if decision == "allow_session" {
                GrantMode::Session
            } else {
                GrantMode::Once
            };
            self.add_grant(cloned.kind.clone(), cloned.target.clone(), mode, key);
            self.audit(
                "access_approved",
                serde_json::json!({ "id": cloned.id, "mode": decision, "kind": cloned.kind, "target": cloned.target }),
            );
        } else {
            self.audit(
                "access_denied",
                serde_json::json!({ "id": cloned.id, "kind": cloned.kind, "target": cloned.target }),
            );
        }
        Some(cloned)
    }

    pub fn add_share(&mut self, file: &Path, ttl_minutes: i64) -> ShareItem {
        let t = now_ms();
        self.shares.retain(|_, s| s.expires_at > t);
        let token = random_b64url(24);
        let item = ShareItem {
            token: token.clone(),
            file: file.to_string_lossy().to_string(),
            created_at: t,
            expires_at: t + ttl_minutes.clamp(5, 240) * 60_000,
        };
        self.shares.insert(token, item.clone());
        item
    }

    pub fn get_share(&mut self, token: &str) -> Option<ShareItem> {
        let t = now_ms();
        if let Some(item) = self.shares.get(token) {
            if item.expires_at > t {
                return Some(item.clone());
            }
        }
        self.shares.remove(token);
        None
    }

    /// Global + per-IP PIN lock check (returns remaining lockout seconds, or 0 if unlocked).
    pub fn pin_lock_seconds(&self, ip: &str) -> i64 {
        let t = now_ms();
        let mut max_rem = 0i64;
        if self.global_pin_state.locked_until_ms > t {
            max_rem = max_rem.max((self.global_pin_state.locked_until_ms - t + 999) / 1000);
        }
        if let Some(rec) = self.per_ip_pin_state.get(ip) {
            if rec.locked_until_ms > t {
                max_rem = max_rem.max((rec.locked_until_ms - t + 999) / 1000);
            }
        }
        max_rem
    }

    pub fn pin_failed(&mut self, ip: &str) {
        let t = now_ms();
        // Global counter: 5 failures in 10 min -> 15 min global lockout!
        if t - self.global_pin_state.first_ms > 10 * 60_000 {
            self.global_pin_state.fails = 0;
            self.global_pin_state.first_ms = t;
        }
        self.global_pin_state.fails += 1;
        if self.global_pin_state.fails >= 5 {
            self.global_pin_state.locked_until_ms = t + 15 * 60_000;
            self.global_pin_state.fails = 0;
            self.global_pin_state.first_ms = t;
            self.audit(
                "pin_global_lockout",
                serde_json::json!({ "ip": ip, "durationSecs": 900 }),
            );
        }

        let rec = self
            .per_ip_pin_state
            .entry(ip.to_string())
            .or_insert(PinAttemptState {
                fails: 0,
                first_ms: t,
                locked_until_ms: 0,
            });
        if t - rec.first_ms > 10 * 60_000 {
            rec.fails = 0;
            rec.first_ms = t;
        }
        rec.fails += 1;
        if rec.fails >= 5 {
            rec.locked_until_ms = t + 15 * 60_000;
            rec.fails = 0;
            rec.first_ms = t;
        }
    }

    pub fn pin_succeeded(&mut self, ip: &str) {
        self.global_pin_state.fails = 0;
        self.global_pin_state.locked_until_ms = 0;
        self.per_ip_pin_state.remove(ip);
    }

    pub fn check_mcp_rate(&mut self, ip: &str) -> bool {
        Self::bump_bucket(&mut self.mcp_rate, ip, 60_000, 300)
    }

    pub fn check_register_rate(&mut self, ip: &str) -> bool {
        Self::bump_bucket(&mut self.register_rate, ip, 300_000, 10)
    }

    fn bump_bucket(
        map: &mut HashMap<String, RateBucket>,
        ip: &str,
        window_ms: i64,
        limit: u32,
    ) -> bool {
        let t = now_ms();
        let entry = map.entry(ip.to_string()).or_insert(RateBucket {
            count: 0,
            window_start_ms: t,
        });
        if t - entry.window_start_ms > window_ms {
            entry.count = 0;
            entry.window_start_ms = t;
        }
        entry.count += 1;
        entry.count <= limit
    }
}
