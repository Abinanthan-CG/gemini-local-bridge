use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleStatus {
    pub installed: bool,
    pub backend_state: String,
    pub logged_in: bool,
    pub login_url: Option<String>,
    pub dns_name: Option<String>,
    pub funnel_active: bool,
    pub funnel_url: Option<String>,
    pub raw_error: Option<String>,
}

pub fn find_tailscale() -> Option<PathBuf> {
    let std_path = PathBuf::from(r"C:\Program Files\Tailscale\tailscale.exe");
    if std_path.exists() {
        return Some(std_path);
    }
    crate::policy::which("tailscale")
}

fn run_ts(bin: &PathBuf, args: &[&str]) -> Result<(bool, String, String), String> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    let out = cmd.output().map_err(|e| format!("tailscale exec: {e}"))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

pub fn get_status(port: u16) -> TailscaleStatus {
    let Some(bin) = find_tailscale() else {
        return TailscaleStatus {
            installed: false,
            backend_state: "NotInstalled".into(),
            logged_in: false,
            login_url: None,
            dns_name: None,
            funnel_active: false,
            funnel_url: None,
            raw_error: Some("Tailscale is not installed.".into()),
        };
    };

    let (ok, stdout, stderr) = match run_ts(&bin, &["status", "--json"]) {
        Ok(r) => r,
        Err(e) => {
            return TailscaleStatus {
                installed: true,
                backend_state: "Error".into(),
                logged_in: false,
                login_url: None,
                dns_name: None,
                funnel_active: false,
                funnel_url: None,
                raw_error: Some(e),
            }
        }
    };

    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or(serde_json::Value::Null);
    let backend_state = parsed["BackendState"]
        .as_str()
        .unwrap_or(if ok { "Unknown" } else { "Error" })
        .to_string();
    let logged_in = backend_state == "Running";
    let login_url = parsed["AuthURL"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from);

    let dns_name = parsed["Self"]["DNSName"]
        .as_str()
        .map(|s| s.trim_end_matches('.').to_string())
        .filter(|s| !s.is_empty());

    let mut funnel_active = false;
    let mut funnel_url = None;

    if logged_in {
        if let Ok((f_ok, f_out, _)) = run_ts(&bin, &["funnel", "status", "--json"]) {
            if f_ok {
                if let Ok(fj) = serde_json::from_str::<serde_json::Value>(&f_out) {
                    let allow = fj["AllowFunnel"].as_object();
                    let has_funnel = allow
                        .map(|m| m.values().any(|v| v.as_bool() == Some(true)))
                        .unwrap_or(false);
                    let targets_port = f_out.contains(&format!(":{port}"));
                    if has_funnel && targets_port {
                        funnel_active = true;
                        if let Some(ref dns) = dns_name {
                            funnel_url = Some(format!("https://{dns}"));
                        }
                    }
                }
            }
        }
    }

    TailscaleStatus {
        installed: true,
        backend_state,
        logged_in,
        login_url,
        dns_name,
        funnel_active,
        funnel_url,
        raw_error: if !ok && stderr.trim().len() > 0 {
            Some(stderr.trim().to_string())
        } else {
            None
        },
    }
}

pub fn enable_funnel(port: u16) -> Result<String, String> {
    let bin = find_tailscale().ok_or_else(|| "Tailscale is not installed.".to_string())?;
    let target = format!("http://127.0.0.1:{port}");
    let (ok, stdout, stderr) = run_ts(&bin, &["funnel", "--bg", &target])?;
    let combined = format!("{}\n{}", stdout.trim(), stderr.trim()).trim().to_string();
    if ok {
        Ok(if combined.is_empty() {
            format!("Tailscale Funnel enabled for {target}")
        } else {
            combined
        })
    } else {
        Err(combined)
    }
}

pub fn disable_funnel() -> Result<String, String> {
    let bin = find_tailscale().ok_or_else(|| "Tailscale is not installed.".to_string())?;
    let (ok, stdout, stderr) = run_ts(&bin, &["funnel", "reset"])?;
    let combined = format!("{}\n{}", stdout.trim(), stderr.trim()).trim().to_string();
    if ok {
        Ok("Tailscale Funnel reset.".into())
    } else {
        Err(combined)
    }
}
