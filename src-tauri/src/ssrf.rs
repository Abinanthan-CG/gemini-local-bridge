use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::Policy;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::lookup_host;
use url::Url;

/// Returns true for any address an outbound download tool must NEVER connect to.
pub fn is_private_or_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    let [a, b, _, _] = v4.octets();
    // 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8
    if a == 0 || a == 10 || a == 127 {
        return true;
    }
    // 100.64.0.0/10 (CGNAT / Tailscale)
    if a == 100 && (64..=127).contains(&b) {
        return true;
    }
    // 169.254.0.0/16 (link-local / cloud metadata)
    if a == 169 && b == 254 {
        return true;
    }
    // 172.16.0.0/12
    if a == 172 && (16..=31).contains(&b) {
        return true;
    }
    // 192.168.0.0/16, 192.0.0.0/24
    if a == 192 && (b == 168 || b == 0) {
        return true;
    }
    // 198.18.0.0/15 (benchmarking)
    if a == 198 && (b == 18 || b == 19) {
        return true;
    }
    // 224.0.0.0/4 multicast & 240.0.0.0/4 reserved
    a >= 224
}

fn is_private_v6(v6: Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_private_v4(v4);
    }
    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
        return true;
    }
    let segs = v6.segments();
    // fc00::/7 Unique local
    if (segs[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // fe80::/10 Link-local
    if (segs[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    false
}

/// Custom DNS resolver pinned directly into reqwest so there is ZERO DNS-rebinding TOCTOU.
struct PublicOnlyResolver;

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();
            if addrs.is_empty() {
                let err: Box<dyn std::error::Error + Send + Sync> = Box::new(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("DNS_FAILED: no addresses for {host}"),
                ));
                return Err(err);
            }
            for addr in &addrs {
                if is_private_or_reserved(addr.ip()) {
                    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "BLOCKED_ADDRESS: {host} resolves to private/loopback/link-local {}",
                            addr.ip()
                        ),
                    ));
                    return Err(err);
                }
            }
            let iter: Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

pub struct DownloadResult {
    pub bytes: Vec<u8>,
    pub final_url: String,
    pub content_type: String,
}

/// Downloads a public HTTP(S) URL with DNS-pinned SSRF protection, manual redirect checks, and size cap.
pub async fn download_public_url(raw_url: &str, max_bytes: usize) -> Result<DownloadResult, String> {
    let client = reqwest::Client::builder()
        .dns_resolver(Arc::new(PublicOnlyResolver))
        .redirect(Policy::none())
        .timeout(Duration::from_secs(30))
        .user_agent("gemini-local-bridge/2.0")
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let mut current = raw_url.to_string();
    let mut final_resp = None;

    for _hop in 0..4 {
        let parsed = Url::parse(&current).map_err(|_| "INVALID_URL: could not parse URL.")?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err("INVALID_URL: only http and https are allowed.".into());
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err("INVALID_URL: URLs with embedded credentials are not allowed.".into());
        }
        if let Some(host) = parsed.host_str() {
            let trimmed = host.trim_start_matches('[').trim_end_matches(']');
            if let Ok(ip) = trimmed.parse::<IpAddr>() {
                if is_private_or_reserved(ip) {
                    return Err(format!(
                        "BLOCKED_ADDRESS: literal private/loopback/link-local IP ({ip})."
                    ));
                }
            }
        } else {
            return Err("INVALID_URL: missing hostname.".into());
        }

        let resp = client.get(parsed.clone()).send().await.map_err(|e| {
            let msg = format!("{e:?}");
            if msg.contains("BLOCKED_ADDRESS") {
                "BLOCKED_ADDRESS: host resolved to a private, loopback or link-local IP.".into()
            } else {
                format!("DOWNLOAD_FAILED: {e}")
            }
        })?;

        let status = resp.status();
        if status.is_redirection() {
            let loc = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| format!("DOWNLOAD_FAILED: HTTP {status} missing Location header"))?;
            current = parsed
                .join(loc)
                .map_err(|_| "INVALID_URL: bad redirect URL")?
                .to_string();
            continue;
        }
        final_resp = Some(resp);
        break;
    }

    let mut resp = final_resp.ok_or_else(|| "TOO_MANY_REDIRECTS: stopped after 4 hops.")?;
    if !resp.status().is_success() {
        return Err(format!("HTTP_{}: request failed", resp.status().as_u16()));
    }

    if let Some(len) = resp.content_length() {
        if len as usize > max_bytes {
            return Err(format!(
                "TOO_LARGE: server reports {} bytes, cap is {} bytes.",
                len, max_bytes
            ));
        }
    }

    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("DOWNLOAD_FAILED: {e}"))?
    {
        if out.len() + chunk.len() > max_bytes {
            return Err(format!("TOO_LARGE: stopped at {max_bytes} bytes."));
        }
        out.extend_from_slice(&chunk);
    }

    Ok(DownloadResult {
        bytes: out,
        final_url: current,
        content_type,
    })
}
