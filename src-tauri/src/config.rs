use crate::crypto::{dpapi_protect, dpapi_unprotect, hash_pin, random_b64url, random_pin};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveSyncConfig {
    pub enabled: bool,
    /// Relative folder inside workspace (default "drive-sync")
    pub subfolder: String,
    /// Single Google Drive folder ID (strictly scoped via rclone root_folder_id)
    pub remote_folder_id: String,
    /// Human-friendly display name of the Drive folder
    pub remote_folder_name: String,
    /// "two_way" or "outbound_only"
    pub mode: String,
    /// Periodic pull interval in seconds (two-way mode)
    pub poll_interval_secs: u64,
    /// Whether initial bisync --resync has completed
    pub bisync_initialized: bool,
}

impl Default for DriveSyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            subfolder: "drive-sync".into(),
            remote_folder_id: String::new(),
            remote_folder_name: String::new(),
            mode: "two_way".into(),
            poll_interval_secs: 30,
            bisync_initialized: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeConfig {
    pub host: String,
    pub port: u16,
    pub workspace: String,
    /// Argon2id PHC hash of the access PIN. Plaintext PIN is NEVER stored on disk.
    pub pin_hash: String,
    pub token_ttl_seconds: i64,
    pub refresh_ttl_seconds: i64,
    pub approval_ttl_minutes: i64,
    pub pending_request_ttl_minutes: i64,
    pub max_read_bytes: usize,
    pub max_image_bytes: usize,
    pub max_write_bytes: usize,
    pub max_copy_bytes: u64,
    pub max_download_bytes: usize,
    pub max_share_bytes: u64,
    pub max_command_output_bytes: usize,
    pub default_command_timeout_seconds: u64,
    pub max_command_timeout_seconds: u64,
    pub max_list_entries: usize,
    pub max_search_results: usize,
    pub program_allowlist: Vec<String>,
    pub drive_sync: DriveSyncConfig,
    /// Optional explicit public origin override (otherwise inferred from Tailscale/Host)
    pub public_origin: Option<String>,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from(r"C:\Users\Public"));
        let workspace = home.join("GeminiWorkspace").to_string_lossy().to_string();
        Self {
            host: "127.0.0.1".into(),
            port: 8787,
            workspace,
            pin_hash: String::new(),
            token_ttl_seconds: 3600,
            refresh_ttl_seconds: 7_776_000, // 90 days
            approval_ttl_minutes: 15,
            pending_request_ttl_minutes: 30,
            max_read_bytes: 204_800,
            max_image_bytes: 8_388_608, // 8 MB
            max_write_bytes: 1_048_576,
            max_copy_bytes: 67_108_864,
            max_download_bytes: 20_971_520,
            max_share_bytes: 33_554_432,
            max_command_output_bytes: 262_144,
            default_command_timeout_seconds: 60,
            max_command_timeout_seconds: 300,
            max_list_entries: 500,
            max_search_results: 100,
            program_allowlist: vec![
                "git".into(),
                "node".into(),
                "npm".into(),
                "npx".into(),
                "python".into(),
                "pip".into(),
                "pytest".into(),
                "uv".into(),
                "uvx".into(),
            ],
            drive_sync: DriveSyncConfig::default(),
            public_origin: None,
        }
    }
}

/// DPAPI-encrypted runtime secrets stored separately from config.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSecrets {
    pub session_secret: String,
    pub csrf_secret: String,
}

pub fn data_dir() -> PathBuf {
    let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("GeminiBridge")
}

pub fn logs_dir() -> PathBuf {
    data_dir().join("logs")
}

pub fn rclone_config_path() -> PathBuf {
    data_dir().join("rclone.conf")
}

pub fn ensure_data_dirs() -> Result<(), String> {
    fs::create_dir_all(data_dir()).map_err(|e| format!("create data dir: {e}"))?;
    fs::create_dir_all(logs_dir()).map_err(|e| format!("create logs dir: {e}"))?;
    Ok(())
}

pub fn restrict_file_acl(path: &Path) {
    #[cfg(windows)]
    {
        if let Ok(user) = std::env::var("USERNAME") {
            let _ = std::process::Command::new("icacls")
                .args([
                    &path.to_string_lossy().to_string(),
                    "/inheritance:r",
                    "/grant:r",
                    &format!("{user}:F"),
                ])
                .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
                .output();
        }
    }
}

#[cfg(windows)]
use std::os::windows::process::CommandExt;

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))?;
    restrict_file_acl(path);
    Ok(())
}

/// Loads config and secrets; returns `(config, secrets, optional_initial_plaintext_pin)`.
/// `optional_initial_plaintext_pin` is ONLY `Some(pin)` on first creation so the UI can display it once.
pub fn load_or_init() -> Result<(BridgeConfig, BridgeSecrets, Option<String>), String> {
    ensure_data_dirs()?;
    let cfg_path = data_dir().join("config.json");
    let secrets_path = data_dir().join("secrets.dpapi");

    let mut cfg: BridgeConfig = if cfg_path.exists() {
        let raw = fs::read_to_string(&cfg_path).unwrap_or_default();
        serde_json::from_str(&raw).unwrap_or_default()
    } else {
        BridgeConfig::default()
    };

    let mut initial_pin: Option<String> = None;
    let mut dirty = !cfg_path.exists();

    if cfg.pin_hash.is_empty() {
        let pin = random_pin();
        cfg.pin_hash = hash_pin(&pin)?;
        initial_pin = Some(pin);
        dirty = true;
    }

    // Ensure workspace and drive-sync folder exist
    let ws = PathBuf::from(&cfg.workspace);
    fs::create_dir_all(&ws).map_err(|e| format!("create workspace {}: {e}", ws.display()))?;
    let sync_dir = ws.join(&cfg.drive_sync.subfolder);
    let _ = fs::create_dir_all(&sync_dir);

    if dirty {
        save_config(&cfg)?;
    }

    let secrets: BridgeSecrets = if secrets_path.exists() {
        let enc = fs::read(&secrets_path).map_err(|e| format!("read secrets: {e}"))?;
        let plain = dpapi_unprotect(&enc)?;
        serde_json::from_slice(&plain).map_err(|e| format!("parse secrets: {e}"))?
    } else {
        let s = BridgeSecrets {
            session_secret: random_b64url(32),
            csrf_secret: random_b64url(32),
        };
        let bytes = serde_json::to_vec(&s).map_err(|e| e.to_string())?;
        let enc = dpapi_protect(&bytes)?;
        write_atomic(&secrets_path, &enc)?;
        s
    };

    Ok((cfg, secrets, initial_pin))
}

pub fn save_config(cfg: &BridgeConfig) -> Result<(), String> {
    ensure_data_dirs()?;
    let cfg_path = data_dir().join("config.json");
    let bytes = serde_json::to_vec_pretty(cfg).map_err(|e| e.to_string())?;
    write_atomic(&cfg_path, &bytes)
}
