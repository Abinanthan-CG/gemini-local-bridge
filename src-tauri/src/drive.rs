use crate::config::{rclone_config_path, restrict_file_acl, save_config, BridgeConfig};
use crate::store::Store;
use chrono::Utc;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::{Mutex, RwLock};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveSyncStatus {
    pub rclone_installed: bool,
    pub rclone_path: Option<String>,
    pub enabled: bool,
    pub configured: bool,
    pub syncing: bool,
    pub local_dir: String,
    pub remote_folder_id: String,
    pub remote_folder_name: String,
    pub mode: String,
    pub last_sync_at: Option<String>,
    pub last_result: String,
    pub local_file_count: usize,
}

pub struct DriveManager {
    pub lock: Mutex<()>,
    pub syncing: RwLock<bool>,
    pub last_sync_at: RwLock<Option<String>>,
    pub last_result: RwLock<String>,
}

impl DriveManager {
    pub fn new() -> Self {
        Self {
            lock: Mutex::new(()),
            syncing: RwLock::new(false),
            last_sync_at: RwLock::new(None),
            last_result: RwLock::new("Not synced yet.".into()),
        }
    }

    pub fn find_rclone() -> Option<PathBuf> {
        if let Some(p) = crate::policy::which("rclone") {
            return Some(p);
        }
        if let Some(local) = dirs::data_local_dir() {
            let link = local.join("Microsoft").join("WinGet").join("Links").join("rclone.exe");
            if link.exists() {
                return Some(link);
            }
        }
        None
    }

    pub fn local_sync_dir(cfg: &BridgeConfig) -> PathBuf {
        PathBuf::from(&cfg.workspace).join(&cfg.drive_sync.subfolder)
    }

    pub async fn status(&self, cfg: &BridgeConfig) -> DriveSyncStatus {
        let rc = Self::find_rclone();
        let local_dir = Self::local_sync_dir(cfg);
        let _ = fs::create_dir_all(&local_dir);
        let local_file_count = walkdir::WalkDir::new(&local_dir)
            .max_depth(6)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .count();

        let conf_exists = rclone_config_path().exists();
        let configured = conf_exists && !cfg.drive_sync.remote_folder_id.trim().is_empty();

        DriveSyncStatus {
            rclone_installed: rc.is_some(),
            rclone_path: rc.map(|p| p.to_string_lossy().to_string()),
            enabled: cfg.drive_sync.enabled,
            configured,
            syncing: *self.syncing.read().await,
            local_dir: local_dir.to_string_lossy().to_string(),
            remote_folder_id: cfg.drive_sync.remote_folder_id.clone(),
            remote_folder_name: cfg.drive_sync.remote_folder_name.clone(),
            mode: cfg.drive_sync.mode.clone(),
            last_sync_at: self.last_sync_at.read().await.clone(),
            last_result: self.last_result.read().await.clone(),
            local_file_count,
        }
    }

    async fn run_rclone(args: &[String]) -> Result<(bool, String, String), String> {
        let bin = Self::find_rclone().ok_or_else(|| "rclone is not installed.".to_string())?;
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(windows)]
        cmd.creation_flags(0x0800_0000);
        let out = tokio::time::timeout(std::time::Duration::from_secs(180), cmd.output())
            .await
            .map_err(|_| "rclone command timed out after 180s".to_string())?
            .map_err(|e| format!("rclone exec: {e}"))?;
        Ok((
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        ))
    }

    /// Runs interactive browser OAuth (`rclone authorize "drive"`), resolves or creates the single Drive
    /// folder to obtain its exact `root_folder_id`, writes the isolated `rclone.conf`, and enables sync.
    pub async fn connect_google_drive(
        &self,
        store: Arc<RwLock<Store>>,
        folder_name: String,
        folder_id_override: Option<String>,
        mode: String,
    ) -> Result<String, String> {
        let _guard = self.lock.lock().await;
        let scope = if mode == "outbound_only" {
            "drive.file"
        } else {
            "drive"
        };

        // 1. Run `rclone authorize "drive"` — opens the user's browser for Google OAuth consent.
        let auth_args = vec![
            "authorize".into(),
            "drive".into(),
            "--drive-scope".into(),
            scope.into(),
        ];
        let (ok, stdout, stderr) = Self::run_rclone(&auth_args).await?;
        if !ok {
            return Err(format!("Google Drive OAuth failed: {}", stderr.trim()));
        }

        // Extract JSON token between `--->` and `<---` markers from rclone output.
        let token_json = extract_rclone_token(&stdout)
            .ok_or_else(|| format!("Could not parse rclone OAuth token from output."))?;

        let conf_path = rclone_config_path();
        // Write temporary unscoped config ONLY to look up / create the target single folder ID.
        let temp_conf = format!(
            "[gdrive_bridge]\ntype = drive\nscope = {scope}\ntoken = {token_json}\n"
        );
        fs::write(&conf_path, &temp_conf).map_err(|e| format!("write rclone.conf: {e}"))?;
        restrict_file_acl(&conf_path);

        let clean_name = if folder_name.trim().is_empty() {
            "GeminiBridgeSync".to_string()
        } else {
            folder_name.trim().to_string()
        };

        let folder_id = if let Some(id) = folder_id_override.filter(|s| !s.trim().is_empty()) {
            id.trim().to_string()
        } else {
            // Ensure folder exists on Drive, then fetch its exact ID.
            let _ = Self::run_rclone(&[
                "--config".into(),
                conf_path.to_string_lossy().to_string(),
                "mkdir".into(),
                format!("gdrive_bridge:{clean_name}"),
            ])
            .await?;

            let (ls_ok, ls_out, ls_err) = Self::run_rclone(&[
                "--config".into(),
                conf_path.to_string_lossy().to_string(),
                "lsjson".into(),
                "--dirs-only".into(),
                "gdrive_bridge:".into(),
            ])
            .await?;
            if !ls_ok {
                return Err(format!("Failed to resolve Drive folder ID: {}", ls_err.trim()));
            }
            let items: Vec<serde_json::Value> =
                serde_json::from_str(&ls_out).map_err(|e| format!("parse lsjson: {e}"))?;
            items
                .iter()
                .find(|v| {
                    v["Name"]
                        .as_str()
                        .map(|n| n.eq_ignore_ascii_case(&clean_name))
                        .unwrap_or(false)
                })
                .and_then(|v| v["ID"].as_str())
                .map(String::from)
                .ok_or_else(|| {
                    format!("Could not find folder '{clean_name}' in Google Drive after creating it.")
                })?
        };

        // 2. Overwrite rclone.conf strictly scoped to `root_folder_id`!
        let scoped_conf = format!(
            "[gdrive_bridge]\ntype = drive\nscope = {scope}\nroot_folder_id = {folder_id}\ntoken = {token_json}\n"
        );
        fs::write(&conf_path, &scoped_conf).map_err(|e| format!("write scoped rclone.conf: {e}"))?;
        restrict_file_acl(&conf_path);

        // 3. Persist config & ensure local drive-sync folder exists.
        let cfg_clone = {
            let mut st = store.write().await;
            st.cfg.drive_sync.enabled = true;
            st.cfg.drive_sync.remote_folder_id = folder_id.clone();
            st.cfg.drive_sync.remote_folder_name = clean_name.clone();
            st.cfg.drive_sync.mode = if mode == "outbound_only" {
                "outbound_only".into()
            } else {
                "two_way".into()
            };
            st.cfg.drive_sync.bisync_initialized = false;
            let _ = save_config(&st.cfg);
            let local_dir = Self::local_sync_dir(&st.cfg);
            let _ = fs::create_dir_all(&local_dir);
            let mode_val = st.cfg.drive_sync.mode.clone();
            st.audit(
                "drive_connected",
                serde_json::json!({
                    "folderName": clean_name,
                    "folderId": folder_id,
                    "mode": mode_val
                }),
            );
            st.cfg.clone()
        };

        drop(_guard);
        // 4. Kick off initial sync immediately.
        let sync_msg = self.sync_now(store, &cfg_clone).await?;
        Ok(format!(
            "Connected to Google Drive folder '{clean_name}' (ID: {folder_id}). {sync_msg}"
        ))
    }

    pub async fn disconnect(&self, store: Arc<RwLock<Store>>) -> Result<(), String> {
        let _guard = self.lock.lock().await;
        let _ = fs::remove_file(rclone_config_path());
        let mut st = store.write().await;
        st.cfg.drive_sync.enabled = false;
        st.cfg.drive_sync.remote_folder_id.clear();
        st.cfg.drive_sync.remote_folder_name.clear();
        st.cfg.drive_sync.bisync_initialized = false;
        save_config(&st.cfg)?;
        st.audit("drive_disconnected", serde_json::json!({}));
        *self.last_result.write().await = "Disconnected.".into();
        Ok(())
    }

    pub async fn sync_now(
        &self,
        store: Arc<RwLock<Store>>,
        cfg: &BridgeConfig,
    ) -> Result<String, String> {
        self.sync_internal(store, cfg, true).await
    }

    pub async fn sync_background(
        &self,
        store: Arc<RwLock<Store>>,
        cfg: &BridgeConfig,
    ) -> Result<String, String> {
        self.sync_internal(store, cfg, false).await
    }

    async fn sync_internal(
        &self,
        store: Arc<RwLock<Store>>,
        cfg: &BridgeConfig,
        log_success: bool,
    ) -> Result<String, String> {
        let _guard = self.lock.lock().await;
        let conf_path = rclone_config_path();
        if !conf_path.exists() || cfg.drive_sync.remote_folder_id.trim().is_empty() {
            return Err("Google Drive sync is not connected yet.".into());
        }

        let local_dir = Self::local_sync_dir(cfg);
        fs::create_dir_all(&local_dir).map_err(|e| format!("mkdir sync dir: {e}"))?;

        // Keep an anchor file in two-way mode so rclone bisync never aborts on an empty directory.
        if cfg.drive_sync.mode == "two_way" {
            let anchor = local_dir.join(".gemini-bridge-sync.txt");
            if !anchor.exists() {
                let _ = fs::write(
                    &anchor,
                    "Gemini Local Bridge single-folder sync anchor. Keep this file so two-way sync stays active when the folder has no other files.\n",
                );
            }
        }

        *self.syncing.write().await = true;

        let res = if cfg.drive_sync.mode == "outbound_only" {
            let args = vec![
                "--config".into(),
                conf_path.to_string_lossy().to_string(),
                "copy".into(),
                local_dir.to_string_lossy().to_string(),
                "gdrive_bridge:".into(),
                "--fast-list".into(),
                "--stats-one-line".into(),
            ];
            Self::run_rclone(&args).await
        } else {
            let base_args = |force_resync: bool| -> Vec<String> {
                let mut a = vec![
                    "--config".into(),
                    conf_path.to_string_lossy().to_string(),
                    "bisync".into(),
                    local_dir.to_string_lossy().to_string(),
                    "gdrive_bridge:".into(),
                    "--create-empty-src-dirs".into(),
                    "--conflict-resolve".into(),
                    "newer".into(),
                    "--conflict-loser".into(),
                    "num".into(),
                    "--resilient".into(),
                    "--recover".into(),
                ];
                if force_resync {
                    a.push("--resync".into());
                }
                a
            };

            let first = Self::run_rclone(&base_args(!cfg.drive_sync.bisync_initialized)).await;
            match first {
                Ok((false, _, ref err))
                    if err.contains("Empty prior Path") || err.contains("cannot find prior Path") =>
                {
                    Self::run_rclone(&base_args(true)).await
                }
                other => other,
            }
        };

        *self.syncing.write().await = false;

        match res {
            Ok((true, _out, _err)) => {
                let ts = Utc::now().to_rfc3339();
                *self.last_sync_at.write().await = Some(ts.clone());
                let summary = if cfg.drive_sync.mode == "outbound_only" {
                    "Outbound upload completed."
                } else {
                    "Two-way sync completed."
                };
                *self.last_result.write().await = summary.into();

                let mut st = store.write().await;
                if !st.cfg.drive_sync.bisync_initialized && st.cfg.drive_sync.mode == "two_way" {
                    st.cfg.drive_sync.bisync_initialized = true;
                    let _ = save_config(&st.cfg);
                }
                if log_success {
                    st.audit(
                        "drive_synced",
                        serde_json::json!({ "mode": cfg.drive_sync.mode }),
                    );
                }
                Ok(summary.into())
            }
            Ok((false, _out, err)) => {
                let tail = err
                    .lines()
                    .rev()
                    .take(4)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join(" | ");
                let msg = format!("Sync failed: {tail}");
                *self.last_result.write().await = msg.clone();
                let mut st = store.write().await;
                st.audit("drive_sync_failed", serde_json::json!({ "error": tail }));
                Err(msg)
            }
            Err(e) => {
                *self.last_result.write().await = e.clone();
                Err(e)
            }
        }
    }
}

fn extract_rclone_token(output: &str) -> Option<String> {
    if let (Some(start), Some(end)) = (output.find("--->"), output.find("<---")) {
        let slice = output[start + 4..end].trim();
        if slice.starts_with('{') && slice.ends_with('}') {
            return Some(slice.to_string());
        }
    }
    // Fallback: look for any line that is a JSON object containing access_token
    for line in output.lines() {
        let t = line.trim();
        if t.starts_with('{') && t.ends_with('}') && t.contains("access_token") {
            return Some(t.to_string());
        }
    }
    None
}

/// Spawns the background single-folder file watcher (debounced 2s) + periodic pull loop.
pub fn spawn_drive_watcher(store: Arc<RwLock<Store>>, drive: Arc<DriveManager>) {
    tokio::spawn(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);

        let watch_dir = {
            let st = store.read().await;
            DriveManager::local_sync_dir(&st.cfg)
        };
        let _ = fs::create_dir_all(&watch_dir);

        // Keep notify watcher alive inside this task.
        let tx_clone = tx.clone();
        let _watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(ev) = res {
                use notify::EventKind;
                match ev.kind {
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                        let _ = tx_clone.try_send(());
                    }
                    _ => {}
                }
            }
        })
        .and_then(|mut w| {
            use notify::{RecursiveMode, Watcher};
            w.watch(Path::new(&watch_dir), RecursiveMode::Recursive)?;
            Ok(w)
        });

        let mut poll = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tokio::select! {
                Some(()) = rx.recv() => {
                    // Debounce rapid writes (e.g. Python writing 6 pose PNGs in a loop).
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    while rx.try_recv().is_ok() {}
                    let cfg = { store.read().await.cfg.clone() };
                    if cfg.drive_sync.enabled && !cfg.drive_sync.remote_folder_id.is_empty() {
                        let _ = drive.sync_now(store.clone(), &cfg).await;
                    }
                }
                _ = poll.tick() => {
                    let cfg = { store.read().await.cfg.clone() };
                    if cfg.drive_sync.enabled
                        && cfg.drive_sync.mode == "two_way"
                        && !cfg.drive_sync.remote_folder_id.is_empty()
                    {
                        let _ = drive.sync_background(store.clone(), &cfg).await;
                    }
                }
            }
        }
    });
}
