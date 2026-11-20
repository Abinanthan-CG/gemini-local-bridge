import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const BASE = process.env.BRIDGE_URL || 'http://127.0.0.1:8787';
const PIN = process.env.BRIDGE_PIN || '';
const REDIRECT = 'http://127.0.0.1:9999/callback';
const WORKSPACE = process.env.BRIDGE_WORKSPACE || path.join(os.homedir(), 'GeminiWorkspace');
const OUTSIDE_DIR = path.join(os.homedir(), 'Downloads');

if (!PIN) {
  console.error('Set BRIDGE_PIN=<current 6-digit PIN> before running.');
  process.exit(1);
}

// Ensure a tiny valid PNG exists in the workspace for native image tool checks.
function ensureTestPng() {
  const pngPath = path.join(WORKSPACE, 'assets', 'bridge-test.png');
  if (fs.existsSync(pngPath)) return false;
  fs.mkdirSync(path.dirname(pngPath), { recursive: true });
  // Minimal valid 1x1 cyan PNG
  const tinyPng = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
    'base64'
  );
  fs.writeFileSync(pngPath, tinyPng);
  return true;
}

let pass = 0;
let fail = 0;
const check = (name, cond, detail = '') => {
  if (cond) {
    pass += 1;
    console.log(`  PASS  ${name}`);
  } else {
    fail += 1;
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
  }
};
const b64url = (b) => b.toString('base64url');

async function main() {
  const createdSamplePng = ensureTestPng();
  console.log(`\nGemini Local Bridge v2 (Rust) test suite -> ${BASE}\n`);

  const health = await fetch(`${BASE}/healthz`).then((r) => r.json());
  check('healthz ok & v2.0.0', health.ok === true && health.version === '2.0.0', JSON.stringify(health));

  const meta = await fetch(`${BASE}/.well-known/oauth-authorization-server`).then((r) => r.json());
  check('OAuth AS metadata', meta.response_types_supported?.includes('code') && meta.code_challenge_methods_supported?.includes('S256'));

  const prm = await fetch(`${BASE}/.well-known/oauth-protected-resource`).then((r) => r.json());
  check('Protected resource metadata', prm.resource === `${BASE}/mcp`, JSON.stringify(prm));

  const regRes = await fetch(`${BASE}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'Bridge Verification',
      redirect_uris: [REDIRECT],
      token_endpoint_auth_method: 'client_secret_post',
    }),
  });
  const reg = await regRes.json();
  check('DCR registers client while Pairing Open', regRes.status === 201 && Boolean(reg.client_id && reg.client_secret), `${regRes.status} ${JSON.stringify(reg)}`);

  const verifier = b64url(crypto.randomBytes(48));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const authParams = new URLSearchParams({
    client_id: reg.client_id,
    redirect_uri: REDIRECT,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope: 'mcp',
    state: 'rustv2',
  });

  const consentHtml = await fetch(`${BASE}/authorize?${authParams}`).then((r) => r.text());
  const csrf = consentHtml.match(/name="csrf"\s+value="([^"]+)"/)?.[1] || '';
  check('consent page renders with CSRF token', consentHtml.includes('Access PIN') && csrf.includes('.'), csrf);

  const badPin = await fetch(`${BASE}/authorize`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ ...Object.fromEntries(authParams), csrf, pin: '000000' }),
    redirect: 'manual',
  });
  check('wrong PIN rejected (Argon2id)', badPin.status === 401, String(badPin.status));

  const goodPin = await fetch(`${BASE}/authorize`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ ...Object.fromEntries(authParams), csrf, pin: PIN }),
    redirect: 'manual',
  });
  const loc = goodPin.headers.get('location') || '';
  const code = loc ? new URL(loc).searchParams.get('code') : null;
  check('valid PIN issues auth code', (goodPin.status === 302 || goodPin.status === 303) && Boolean(code), `${goodPin.status} ${loc}`);

  const tokens = await fetch(`${BASE}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
      client_id: reg.client_id,
      client_secret: reg.client_secret,
    }),
  }).then((r) => r.json());
  check('PKCE token exchange succeeds', Boolean(tokens.access_token && tokens.refresh_token), JSON.stringify(tokens));

  const closedReg = await fetch(`${BASE}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'Intruder', redirect_uris: [REDIRECT] }),
  });
  check('Pairing Mode auto-closes after pairing (DCR returns 403)', closedReg.status === 403, String(closedReg.status));

  const headers = {
    authorization: `Bearer ${tokens.access_token}`,
    'content-type': 'application/json',
    accept: 'application/json',
  };
  const rpc = (body) => fetch(`${BASE}/mcp`, { method: 'POST', headers, body: JSON.stringify(body) }).then((r) => r.json());
  const call = (name, args = {}) => rpc({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });

  const unauth = await fetch(`${BASE}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  check('MCP requires bearer + WWW-Authenticate', unauth.status === 401 && (unauth.headers.get('www-authenticate') || '').includes('resource_metadata'));

  const init = await rpc({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '2' } } });
  check('MCP initialize v2.0.0', init.result?.serverInfo?.version === '2.0.0', JSON.stringify(init).slice(0, 200));

  const notif = await fetch(`${BASE}/mcp`, { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) });
  check('MCP notification returns 202 Accepted', notif.status === 202, String(notif.status));

  const list = await rpc({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  const names = (list.result?.tools || []).map((t) => t.name);
  check('tools/list includes native media & drive tools', names.includes('image_preview_base64') && names.includes('drive_sync_now') && names.length >= 15, names.join(', '));

  const runId = Date.now().toString(36);
  const f = `v2test/file-${runId}.txt`;
  const wr = await call('write_file', { path: f, content: 'hello rust v2\nsecond line\n' });
  check('write_file', Boolean(wr.result) && !wr.result.isError, JSON.stringify(wr));

  const rd = await call('read_file', { path: f });
  check('read_file', rd.result?.content?.[0]?.text?.includes('hello rust v2'));

  const rp = await call('replace_in_file', { path: f, old_string: 'second line', new_string: 'patched line' });
  check('replace_in_file', Boolean(rp.result) && !rp.result.isError);

  const st = await call('search_text', { query: 'patched line', path: 'v2test' });
  check('search_text', st.result?.content?.[0]?.text?.includes(path.basename(f)));

  const bridgeSecret = path.join(process.env.LOCALAPPDATA || '', 'GeminiBridge', 'config.json');
  const forbid = await call('read_file', { path: bridgeSecret });
  check('bridge secrets dir strictly forbidden', forbid.result?.isError && JSON.stringify(forbid.result).includes('FORBIDDEN_BRIDGE_DATA'));

  const outside = await call('read_file', { path: 'C:\\Windows\\win.ini' });
  check('outside path denied', outside.result?.isError && JSON.stringify(outside.result).includes('OUTSIDE_WORKSPACE'));

  const cmdNode = await call('run_command', { program: 'node', args: ['--version'] });
  check('run_command node', !cmdNode.result?.isError && Boolean(cmdNode.result?.content?.[0]?.text?.includes('exit_code: 0')));

  const cmdBad = await call('run_command', { program: 'powershell', args: ['-Command', 'echo hi'] });
  check('non-allowlisted program denied', cmdBad.result?.isError && JSON.stringify(cmdBad.result).includes('PROGRAM_NOT_ALLOWED'));

  const prev = await call('preview_image', { path: 'assets/bridge-test.png' });
  check('native Rust preview_image works', !prev.result?.isError && Boolean(prev.result?.content?.[0]?.text?.includes('size:')), JSON.stringify(prev.result).slice(0, 200));

  const b64 = await call('image_preview_base64', { path: 'assets/bridge-test.png', max_edge: 640, max_kb: 32 });
  const b64Text = b64.result?.content?.[0]?.text || '';
  const payload = b64Text.split('--- base64_jpeg ---\n')[1]?.trim() || '';
  const decoded = payload ? Buffer.from(payload, 'base64') : Buffer.alloc(0);
  check('native Rust image_preview_base64 emits valid JPEG', !b64.result?.isError && decoded[0] === 0xff && decoded[1] === 0xd8, `${decoded.length} bytes`);

  const htmlFile = `v2test/xss-${runId}.html`;
  await call('write_file', { path: htmlFile, content: '<script>alert(1)</script>' });
  const sh = await call('share_file', { path: htmlFile });
  const shUrl = (sh.result?.content?.[0]?.text || '').match(/url:\s+(\S+)/)?.[1];
  const shResp = shUrl ? await fetch(shUrl) : null;
  check(
    '/share forces attachment + CSP sandbox on HTML',
    shResp?.status === 200 &&
      (shResp.headers.get('content-security-policy') || '').includes('sandbox') &&
      (shResp.headers.get('content-disposition') || '').includes('attachment'),
    `${shResp?.status} csp=${shResp?.headers.get('content-security-policy')} disp=${shResp?.headers.get('content-disposition')}`
  );

  const ssrfLoop = await call('download_url', { url: 'http://127.0.0.1:8787/healthz', path: 'v2test/loop.txt' });
  check('download_url blocks loopback', ssrfLoop.result?.isError && JSON.stringify(ssrfLoop.result).includes('BLOCKED_ADDRESS'));

  const ssrfLan = await call('download_url', { url: 'http://192.168.1.1/', path: 'v2test/lan.txt' });
  check('download_url blocks LAN', ssrfLan.result?.isError && JSON.stringify(ssrfLan.result).includes('BLOCKED_ADDRESS'));

  const loginRes = await fetch(`${BASE}/approve/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ pin: PIN }),
    redirect: 'manual',
  });
  const cookie = (loginRes.headers.getSetCookie?.() || [loginRes.headers.get('set-cookie')]).filter(Boolean).map((c) => c.split(';')[0]).join('; ');
  const appPage = await fetch(`${BASE}/approve`, { headers: { cookie } }).then((r) => r.text());
  const appCsrf = appPage.match(/name="csrf"\s+value="([^"]+)"/)?.[1] || '';
  check('approval UI login + CSRF present', Boolean(cookie && appCsrf));

  if (fs.existsSync(OUTSIDE_DIR)) {
    await fetch(`${BASE}/approve/grant`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: new URLSearchParams({ csrf: appCsrf, kind: 'path', target: OUTSIDE_DIR, mode: 'session' }),
      redirect: 'manual',
    });
    const dl1 = await call('list_directory', { path: OUTSIDE_DIR });
    const dl2 = await call('list_directory', { path: OUTSIDE_DIR });
    check('session grant persists across multiple calls', !dl1.result?.isError && !dl2.result?.isError);

    const appPage2 = await fetch(`${BASE}/approve`, { headers: { cookie } }).then((r) => r.text());
    const grantId = appPage2.match(/action="\/approve\/revoke"[\s\S]*?name="id"\s+value="([a-f0-9]{12})"/)?.[1];
    if (grantId) {
      await fetch(`${BASE}/approve/revoke`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
        body: new URLSearchParams({ csrf: appCsrf, id: grantId }),
        redirect: 'manual',
      });
    }
    const dl3 = await call('list_directory', { path: OUTSIDE_DIR });
    check('revoked session grant blocks again', dl3.result?.isError && JSON.stringify(dl3.result).includes('OUTSIDE_WORKSPACE'));
  }

  const ref = await fetch(`${BASE}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
      client_id: reg.client_id,
      client_secret: reg.client_secret,
    }),
  }).then((r) => r.json());
  check('refresh token works while Pairing Mode is closed (non-rotating)', ref.refresh_token === tokens.refresh_token && Boolean(ref.access_token));

  const ds = await call('drive_sync_status');
  check('drive_sync_status responds cleanly', !ds.result?.isError && ds.result?.content?.[0]?.text?.includes('local_dir:'));

  fs.rmSync(path.join(WORKSPACE, 'v2test'), { recursive: true, force: true });
  if (createdSamplePng) {
    fs.rmSync(path.join(WORKSPACE, 'assets', 'bridge-test.png'), { force: true });
  }

  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
