# Agent Setup Playbook — Gemini Local Bridge

If a user pointed you at this repository and asked you to set up **Gemini Local Bridge** on their Windows PC and walk them through connecting it to the Google Gemini App, follow this playbook step by step.

## Core Principles (Do Not Violate)

1. **Everything stays local.** All code, files, and command execution stay strictly on the user's PC. Tailscale Funnel (or another HTTPS tunnel) only forwards HTTPS to `127.0.0.1:8787`.
2. **Ask before global system changes.** Confirm with the user before installing Tailscale (triggers Windows UAC + installs a system service/virtual NIC), installing Rclone, modifying DNS, or opening public ports.
3. **Never weaken security defaults.** Keep `host = "127.0.0.1"`, Argon2id PIN hashing, Windows DPAPI secret encryption, Pairing Mode auto-lock, and the dedicated workspace sandbox (`%USERPROFILE%\GeminiWorkspace`). Never place `%LOCALAPPDATA%\GeminiBridge` inside the workspace.
4. **Verify end-to-end with real checks**, not guesses.

---

## Step 1 — Audit the User's Environment

Run a read-only check for:
- OS: Windows 10/11 x64
- Toolchains: `rustc`, `cargo`, Visual Studio Build Tools (`vswhere.exe` + MSVC C++ tools), Microsoft Edge WebView2 (`%ProgramFiles(x86)%\Microsoft\EdgeWebView\Application`)
- Tunneling & Sync: `tailscale`, `rclone`, `winget`
- Port `8787` availability (`netstat -ano | Select-String ":8787"`)
- Optional CLI tools for the allowlist: `git`, `node`, `python`, `uv`

Also verify the user meets **Google Gemini App Custom Apps** prerequisites before spending time building:
- Personal Google account (18+, supported region / US, **Keep Activity ON**, English)
- They can see **Settings → Connected Apps → Custom apps → Create custom app** at `https://gemini.google.com/customize/connectors`.

---

## Step 2 — Confirm Choices & Install Missing Prerequisites

Ask the user to confirm:
1. **Tailscale install** (if missing): `winget install -e --id Tailscale.Tailscale --accept-package-agreements --accept-source-agreements` *(triggers one UAC prompt)*.
2. **Single-folder Google Drive sync** (optional, recommended for lossless multi-MB images): `winget install -e --id Rclone.Rclone --accept-package-agreements --accept-source-agreements`.
3. **Rust / MSVC Build Tools** (only if missing):
   - Rust: `winget install -e --id Rustlang.Rustup`
   - MSVC Build Tools: `winget install -e --id Microsoft.VisualStudio.2022.BuildTools` (with C++ desktop workload)

---

## Step 3 — Set Up Tailscale Funnel (Permanent HTTPS URL)

1. Check `tailscale status`. If logged out, give the user the login URL printed by Tailscale (recommend signing in with their personal Gmail or GitHub).
2. Remind them to ensure **MagicDNS** and **HTTPS Certificates** are enabled at `https://login.tailscale.com/admin/dns`.
3. Run:
   ```powershell
   tailscale funnel --bg http://127.0.0.1:8787
   ```
   - If Funnel is not enabled on their tailnet yet, Tailscale prints a one-click enable link (`https://login.tailscale.com/f/funnel?node=...`) and waits. Give the user that link and wait for them to click **Enable Funnel**.
4. Confirm with `tailscale funnel status` and note their permanent hostname:
   `https://<machine>.<tailnet>.ts.net` → MCP URL is `https://<machine>.<tailnet>.ts.net/mcp`.

---

## Step 4 — Build & Verify the Tauri v2 + Rust App

1. Build the optimized single-binary native app:
   ```powershell
   cd src-tauri
   cargo build --release
   ```
   Output: `src-tauri\target\release\gemini-local-bridge.exe` (~17 MB).

2. **(Optional but recommended) Run the automated 31-check verification suite** against their live Tailscale URL using a temporary test config in `%LOCALAPPDATA%\GeminiBridge\config.json` (seed a temporary Argon2id hash with Node 24's `crypto.argon2Sync`, run `scripts\test-bridge.mjs`, then **wipe `%LOCALAPPDATA%\GeminiBridge`** so no test tokens/clients/PIN remain!).

3. Create a Desktop shortcut (`Gemini Local Bridge.lnk`) pointing to `gemini-local-bridge.exe` with `src-tauri\icons\icon.ico`, then launch `gemini-local-bridge.exe`.
   - On first clean launch, the app automatically:
     - Creates `%USERPROFILE%\GeminiWorkspace` and `%USERPROFILE%\GeminiWorkspace\drive-sync`
     - Generates a random 6-digit PIN, stores **only** its Argon2id hash in `%LOCALAPPDATA%\GeminiBridge\config.json`, and displays the PIN **once** in the top banner of the desktop window
     - Encrypts `secrets.dpapi` and `tokens.dpapi` with Windows DPAPI
     - Opens **Pairing Mode** for 15 minutes so the user can pair Gemini immediately

4. Verify `https://<machine>.<tailnet>.ts.net/healthz` returns `{"ok":true,"version":"2.0.0",...}`.

---

## Step 5 — Walk the User Through Connecting Google Gemini

Give the user these exact steps:
1. Open `https://gemini.google.com/customize/connectors` → **Custom → Create custom app**.
2. Paste their permanent MCP URL ending in `/mcp`:
   `https://<machine>.<tailnet>.ts.net/mcp`
3. Click **Next**. Gemini uses Dynamic Client Registration (`/register`) and opens the OAuth consent page (`/authorize`).
4. Enter the 6-digit **Access PIN** displayed in the **Gemini Local Bridge** desktop window → **Approve & Connect**.
5. **Important Pairing Mode behavior:** As soon as Gemini receives its OAuth token, **Pairing Mode auto-locks** (blocking `/register` and `/authorize` from the public internet). If the user accidentally cancels Gemini's dialog after approving, tell them to click **Enable Pairing (5m)** in the desktop app (or tray menu) before retrying.

---

## Step 6 — Walk Through Optional Single-Folder Google Drive Sync

Explain why Drive Sync is useful:
- **Gemini App currently strips binary MCP image blocks** (passing only text metadata to the model).
- This bridge solves that in **two complementary ways**:
  1. **Fast inline visual check (no Drive needed):** Native Rust `image_preview_base64` compresses any local image to a compact JPEG (default `max_kb: 32`) and returns base64 text that Gemini decodes and views directly.
  2. **Lossless full-res images in both directions:** Single-folder Google Drive sync (`GeminiWorkspace\drive-sync` ↔ one Drive folder locked by `root_folder_id` in an isolated `%LOCALAPPDATA%\GeminiBridge\rclone.conf`).

To connect Drive Sync:
1. Open the **Drive Sync** tab in **Gemini Local Bridge**.
2. Enter a dedicated folder name (default `GeminiBridgeSync`) and pick **Two-way sync** (or **Outbound-only (`drive.file`)** for strict Google-enforced upload-only scope).
3. Click **Connect Google Drive** and complete Google sign-in in the browser.
4. The app automatically maintains a `.gemini-bridge-sync.txt` anchor file so `rclone bisync` never aborts on an empty directory, watches `drive-sync\` with a 2-second debounce, and polls every 30 seconds in two-way mode.

---

## Step 7 — Run the Real End-to-End Gemini Verification

Ask the user to test these four prompts in a Gemini chat (typing `@` to explicitly select their custom app):

1. **Read & Write:**
   > @Local Bridge Create `notes/test.md` with today's UTC time from `workspace_info` and read it back.
2. **Command Runner (Job Object isolated):**
   > @Local Bridge Run `node --version` and `git --version` and show the exit codes.
3. **Permission Boundary:**
   > @Local Bridge List my Downloads folder.
   *(Verify it returns `OUTSIDE_WORKSPACE`. Show the user how to grant/revoke it from the desktop **Approvals** tab or `https://<machine>.<tailnet>.ts.net/approve` on mobile.)*
4. **Visual Image Relay (Base64 + optional Drive Sync):**
   > @Local Bridge Call `image_preview_base64` on a workspace image, decode the JPEG, and describe what you see.

---

## Rollback / Complete Removal

If the user ever wants to undo everything cleanly:
1. Right-click the **Gemini Local Bridge** tray icon → **Quit**.
2. Run `tailscale funnel reset` (and optionally uninstall Tailscale / Rclone from Windows Settings).
3. Remove the custom app in Gemini: `gemini.google.com` → **Settings → Connected Apps → Custom apps**.
4. Delete `%LOCALAPPDATA%\GeminiBridge` and the cloned repository folder.
