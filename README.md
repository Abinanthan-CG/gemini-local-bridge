<p align="center">
  <img src="src-tauri/icons/icon.svg" width="88" height="88" alt="Gemini Local Bridge icon" />
</p>

<h1 align="center">Gemini Local Bridge</h1>

<p align="center">
  A local-first, security-hardened <strong>Rust + Tauri v2</strong> desktop &amp; system-tray MCP server that connects the <strong>Google Gemini App</strong> directly to your Windows PC over <strong>Tailscale Funnel</strong> — with optional single-folder Google Drive sync for lossless visual workflows.
</p>

<p align="center">
  <strong>All code, files, and execution stay strictly on your machine.</strong>
</p>

---

## Quickest Setup: Let Your AI Agent Do It

Point **Claude Code, OpenCode, Codex, Cursor, Windsurf, or Gemini CLI** at this repository with:

```text
Clone https://github.com/Abinanthan-CG/gemini-local-bridge and follow AGENTS.md to install prerequisites, build the app, set up Tailscale Funnel, and walk me through connecting it to the Google Gemini App.
```

[`AGENTS.md`](./AGENTS.md) contains the complete step-by-step playbook — environment audit, UAC confirmation, Tailscale Funnel setup, release build, 31-check live verification suite, Gemini OAuth pairing, and single-folder Google Drive sync.

---

## Architecture

```text
Google Gemini App (Web & Mobile)
        │  HTTPS + OAuth 2.1 (PKCE S256) + Bearer Token
        ▼
Tailscale Funnel (https://<machine>.<tailnet>.ts.net)
        │  Loopback forward only (127.0.0.1:8787) — no open firewall ports
        ▼
Gemini Local Bridge (Single Native Rust + Tauri v2 App)
  ├── Desktop Tray Dashboard + Mobile /approve Web Gate
  ├── OAuth 2.1 + DCR (Auto-locked via Pairing Mode)
  ├── Workspace Sandbox (%USERPROFILE%\GeminiWorkspace)
  ├── Allowlisted CLI Runner (No shell · Windows Job Objects)
  ├── Native Rust Image Engine (preview_image + image_preview_base64)
  └── Optional Single-Folder Drive Sync (isolated rclone.conf · root_folder_id)
```

---

## Security Model

| Layer | Implementation |
|---|---|
| **Network** | Binds `127.0.0.1:8787` only. No Windows Firewall rules, no router port forwarding. Public TLS terminates on Tailscale Funnel. |
| **OAuth 2.1 + Pairing Mode** | PKCE (`S256`) + Dynamic Client Registration (`/register`). Registration and `/authorize` **auto-lock (`403`)** the moment Gemini pairs — re-open for 5 min anytime from the desktop app or tray. |
| **PIN & Brute-Force Defense** | Plaintext PIN is **never** stored on disk — only an **Argon2id** PHC hash. Five failed attempts trigger a 15-minute **global** lockout (cannot be bypassed by spoofing `X-Forwarded-For` / `CF-Connecting-IP`). |
| **Secrets at Rest** | Session keys, CSRF secrets, paired clients, and hashed tokens are encrypted with **Windows DPAPI** in `%LOCALAPPDATA%\GeminiBridge\`. Bridge config/secrets folders are strictly forbidden from all MCP tools and manual grants. |
| **Command Isolation** | Allowlisted binaries only (`git, node, npm, npx, python, pip, pytest, uv, uvx`), spawned with **no shell**, stripped environment, output cap, hard timeout, and **Windows Job Objects** (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, max 32 processes) so child trees die cleanly with zero orphans. |
| **SSRF & XSS Defense** | `download_url` uses a **DNS-pinned `reqwest` resolver** blocking loopback, RFC1918, CGNAT, link-local, and multicast across every redirect (zero DNS-rebinding TOCTOU). `/share/:token` enforces `Content-Security-Policy: default-src 'none'; sandbox` and forces `attachment` on HTML/SVG. |
| **Least-Privilege Escalation** | Everything inside `GeminiWorkspace` is allowed; anything outside requires your explicit approval in the desktop **Approvals** tab or PIN-protected `/approve` mobile web page (*Once* or *Until restart*, revocable in 1 click). |

---

## Built-In MCP Tools (16)

| Category | Tools |
|---|---|
| **Workspace & Files** | `workspace_info`, `list_directory`, `read_file`, `write_file`, `replace_in_file`, `search_text`, `copy_file` |
| **Web & Sharing** | `download_url` *(DNS-pinned SSRF-safe)*, `share_file` *(temporary sandboxed link)* |
| **Visual & Image** | `preview_image` *(native Rust pixel metrics, alpha halo %, bbox, multi-frame alignment table, ASCII silhouette)*, `image_preview_base64` *(fast resized JPEG base64 relay so Gemini can visually see local images even though the Gemini App strips binary MCP image blocks)* |
| **CLI Execution** | `run_command` *(allowlisted, no shell, Job Object isolated)* |
| **Google Drive Sync** | `drive_sync_status`, `drive_sync_now` *(syncs only `GeminiWorkspace\drive-sync\` ↔ your single Drive folder)* |
| **Access Requests** | `request_access`, `check_access` |

---

## Why Single-Folder Google Drive Sync?

The Google Gemini App currently strips binary MCP image blocks (passing only text metadata to the model). This bridge provides **two visual workflows**:

1. **Instant quick check (`image_preview_base64`)**: Native Rust resizes & compresses any local image to a compact JPEG (default `32 KB`) and returns base64 text that Gemini decodes and views directly — zero extra setup.
2. **Lossless full-res two-way sync (`drive-sync` ↔ one Google Drive folder)**:
   - Uses `rclone` with an **isolated** `%LOCALAPPDATA%\GeminiBridge\rclone.conf` locked strictly to a single `root_folder_id`.
   - **PC → Gemini:** Local scripts write full-res multi-MB PNGs into `GeminiWorkspace\drive-sync\` → auto-uploaded within ~2 seconds → inspect losslessly via **@Google Drive** in Gemini.
   - **Gemini → PC:** Save/export Gemini-generated images into that Drive folder → pulled into `GeminiWorkspace\drive-sync\` automatically.
   - Prefer strict upload-only security? Choose **Outbound-only (`drive.file` scope)** in the **Drive Sync** tab so Google's servers physically prevent reading any other Drive file.

---

## Manual Build & Run (Windows 10/11 x64)

### Prerequisites
- [Rust](https://rustup.rs/) + Visual Studio 2022 Build Tools (C++ workload)
- Microsoft Edge WebView2 (pre-installed on Windows 11)
- [Tailscale](https://tailscale.com/) (`winget install -e --id Tailscale.Tailscale`)
- Optional for Drive Sync: [Rclone](https://rclone.org/) (`winget install -e --id Rclone.Rclone`)

### Build
```powershell
git clone https://github.com/Abinanthan-CG/gemini-local-bridge.git
cd gemini-local-bridge\src-tauri
cargo build --release
Start-Process .\target\release\gemini-local-bridge.exe
```

### Enable Permanent HTTPS via Tailscale Funnel
```powershell
tailscale funnel --bg http://127.0.0.1:8787
tailscale funnel status
```

Then open `https://gemini.google.com/customize/connectors` → **Custom → Create custom app** → paste `https://<your-machine>.<your-tailnet>.ts.net/mcp` and enter the 6-digit PIN displayed in the **Gemini Local Bridge** window.

---

## Automated Verification Suite

With Pairing Mode open and your PIN set in `BRIDGE_PIN`:

```powershell
$env:BRIDGE_URL = "https://<your-machine>.<your-tailnet>.ts.net"
$env:BRIDGE_PIN = "<6-digit-pin>"
node scripts\test-bridge.mjs
```

Runs **31 end-to-end checks** covering OAuth 2.1 + PKCE, Pairing Mode auto-lock, Argon2id PIN verification, MCP Streamable HTTP, file tools, forbidden secrets dir, Job Object command runner, native Rust `preview_image` & `image_preview_base64`, `/share` CSP sandbox XSS protection, DNS-pinned SSRF blocking, session grant persistence & revocation, and non-rotating refresh tokens.

---

## Rollback / Uninstall

1. Right-click the **Gemini Local Bridge** tray icon → **Quit**.
2. Disable Tailscale Funnel: `tailscale funnel reset`.
3. Remove the custom app in Gemini: **Settings → Connected Apps → Custom apps**.
4. Delete `%LOCALAPPDATA%\GeminiBridge` and your local repo folder.

## License

[MIT](./LICENSE)
