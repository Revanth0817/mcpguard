import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { VERSION, expandEnv } from './util.js';

/** Keep the useful tail of a server's stderr, without package-manager chatter. */
function tidy(stderr) {
  const lines = stderr.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !/^npm (notice|warn)/i.test(l));
  const text = lines.slice(-3).join(' | ');
  return text ? ` — ${text.slice(-240)}` : '';
}

// cmd.exe metacharacters, escaped with ^ (same approach as cross-spawn).
const CMD_META = /([()\][%!^"`<>&|;, *?])/g;

/** Find the file Windows would run for `command` (PATH + PATHEXT), or null. */
function resolveWindowsCommand(command, env, cwd) {
  const get = (name) => env[Object.keys(env).find((k) => k.toUpperCase() === name) ?? name];
  const exts = (get('PATHEXT') || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean);
  const dirs = /[\\/]/.test(command) ? [''] : ['', ...(get('PATH') || '').split(';').filter(Boolean)];
  const names = path.extname(command) ? [command, ...exts.map((e) => command + e)] : exts.map((e) => command + e);
  for (const dir of dirs) {
    for (const name of names) {
      const file = path.resolve(cwd || process.cwd(), dir, name);
      try { if (fs.statSync(file).isFile()) return file; } catch { /* keep looking */ }
    }
  }
  return null;
}

/** Quote an argument for the target's argv parser, then escape it for cmd.exe. */
function escapeCmdArg(arg, doubleEscape) {
  let out = String(arg)
    .replace(/(\\*)"/g, '$1$1\\"')
    .replace(/(\\*)$/, '$1$1');
  out = `"${out}"`.replace(CMD_META, '^$1');
  return doubleEscape ? out.replace(CMD_META, '^$1') : out;
}

/**
 * Work out how to spawn a stdio server. On Windows, .exe files are run directly (Node quotes
 * the arguments); .cmd/.bat shims such as npx need cmd.exe, so the command line is escaped by hand
 * instead of relying on `shell: true`, which splits paths containing spaces.
 */
function spawnSpec(command, args, env, cwd) {
  if (process.platform !== 'win32') return { file: command, args, options: {} };
  const resolved = resolveWindowsCommand(command, env, cwd);
  if (resolved && /\.(exe|com)$/i.test(resolved)) return { file: resolved, args, options: {} };
  // Batch shims inside node_modules/.bin re-parse their arguments, so they need a second escape.
  const doubleEscape = !!resolved && /node_modules[\\/]\.bin[\\/][^\\/]+\.cmd$/i.test(resolved);
  const line = [path.normalize(resolved || command).replace(CMD_META, '^$1'), ...args.map((a) => escapeCmdArg(a, doubleEscape))].join(' ');
  return {
    file: env.ComSpec || env.COMSPEC || 'cmd.exe',
    args: ['/d', '/s', '/c', `"${line}"`],
    options: { windowsVerbatimArguments: true },
  };
}

const PROTOCOL_VERSION = '2025-06-18';
const INIT_PARAMS = {
  protocolVersion: PROTOCOL_VERSION,
  capabilities: {},
  clientInfo: { name: 'mcpguard', version: VERSION },
};

/**
 * Connect to an MCP server, list its tools (and prompts), then disconnect.
 * Only read-only discovery methods are called; no tool is ever invoked.
 */
export async function inspectServer(server, { timeoutMs = 20000 } = {}) {
  if (server.transport === 'stdio') return inspectStdio(server, timeoutMs);
  if (server.transport === 'http') return inspectHttp(server, timeoutMs);
  return { ok: false, error: `Live inspection of "${server.transport}" transport is not supported yet (static checks still apply).` };
}

async function listAll(request, method, key) {
  const items = [];
  let cursor;
  for (let page = 0; page < 20; page++) {
    const res = await request(method, cursor ? { cursor } : {});
    items.push(...(res?.[key] || []));
    cursor = res?.nextCursor;
    if (!cursor) break;
  }
  return items;
}

async function discoverWith(request, notify) {
  const init = await request('initialize', INIT_PARAMS);
  await notify('notifications/initialized');
  const caps = init?.capabilities || {};
  const tools = caps.tools ? await listAll(request, 'tools/list', 'tools') : [];
  let prompts = [];
  if (caps.prompts) { try { prompts = await listAll(request, 'prompts/list', 'prompts'); } catch { /* optional */ } }
  return {
    ok: true,
    serverInfo: init?.serverInfo || {},
    protocolVersion: init?.protocolVersion,
    instructions: init?.instructions,
    tools,
    prompts,
  };
}

function inspectStdio(server, timeoutMs) {
  return new Promise((resolve) => {
    const env = { ...process.env };
    for (const [k, v] of Object.entries(server.env || {})) env[k] = expandEnv(String(v));
    let child;
    try {
      const spec = spawnSpec(expandEnv(server.command), server.args.map((a) => expandEnv(a)), env, server.cwd);
      child = spawn(spec.file, spec.args, {
        env, cwd: server.cwd, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, ...spec.options,
      });
    } catch (e) {
      resolve({ ok: false, error: `Failed to start: ${e.message}` });
      return;
    }
    let nextId = 1;
    const pending = new Map();
    let buffer = '';
    let stderr = '';
    let finished = false;

    const finish = (result) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      for (const p of pending.values()) p.reject(new Error('closed'));
      try { child.stdin.end(); } catch { /* ignore */ }
      try { child.kill('SIGTERM'); } catch { /* ignore */ }
      setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* ignore */ } }, 1000).unref();
      resolve(result);
    };
    const timer = setTimeout(() => finish({ ok: false, error: `Timed out after ${timeoutMs / 1000}s${tidy(stderr)}` }), timeoutMs);

    const write = (msg) => { try { child.stdin.write(JSON.stringify(msg) + '\n'); } catch { /* ignore */ } };
    const request = (method, params) => new Promise((res, rej) => {
      const id = nextId++;
      pending.set(id, { resolve: res, reject: rej });
      write({ jsonrpc: '2.0', id, method, params });
    });
    const notify = async (method, params) => write({ jsonrpc: '2.0', method, ...(params ? { params } : {}) });

    child.on('error', (e) => finish({ ok: false, error: `Failed to start: ${e.message}` }));
    // A server that closes stdin early must not crash the scanner (EPIPE on write).
    child.stdin.on('error', () => {});
    child.on('exit', (code) => finish({ ok: false, error: `Server exited (code ${code}) before inspection finished${tidy(stderr)}` }));
    child.stderr.on('data', (d) => { stderr += d.toString(); if (stderr.length > 10000) stderr = stderr.slice(-5000); });
    child.stdout.on('data', (d) => {
      buffer += d.toString();
      let nl;
      while ((nl = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); } catch { continue; } // servers sometimes log to stdout
        if (msg.id !== undefined && pending.has(msg.id) && (msg.result !== undefined || msg.error)) {
          const p = pending.get(msg.id);
          pending.delete(msg.id);
          if (msg.error) p.reject(new Error(msg.error.message || 'JSON-RPC error'));
          else p.resolve(msg.result);
        } else if (msg.method && msg.id !== undefined) {
          // Server -> client requests: answer harmlessly, never grant anything.
          if (msg.method === 'ping') write({ jsonrpc: '2.0', id: msg.id, result: {} });
          else if (msg.method === 'roots/list') write({ jsonrpc: '2.0', id: msg.id, result: { roots: [] } });
          else write({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'Not supported by mcpguard' } });
        }
      }
    });

    discoverWith(request, notify).then(finish, (e) => finish({ ok: false, error: e.message }));
  });
}

async function inspectHttp(server, timeoutMs) {
  const url = expandEnv(server.url);
  const baseHeaders = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
  for (const [k, v] of Object.entries(server.headers || {})) baseHeaders[k.toLowerCase()] = expandEnv(String(v));
  let sessionId;
  let negotiated;
  let nextId = 1;
  const deadline = Date.now() + timeoutMs;

  const post = async (body) => {
    const headers = { ...baseHeaders };
    if (sessionId) headers['mcp-session-id'] = sessionId;
    if (negotiated) headers['mcp-protocol-version'] = negotiated;
    const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(Math.max(1000, deadline - Date.now())) });
    const sid = res.headers.get('mcp-session-id');
    if (sid) sessionId = sid;
    return res;
  };
  const request = async (method, params) => {
    const id = nextId++;
    const res = await post({ jsonrpc: '2.0', id, method, params });
    if (res.status === 401 || res.status === 403) throw new Error(`HTTP ${res.status}: server requires authentication (set headers or env vars)`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const type = res.headers.get('content-type') || '';
    const text = await res.text();
    let msgs = [];
    if (type.includes('text/event-stream')) {
      for (const block of text.split(/\r?\n\r?\n/)) {
        const data = block.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trim()).join('\n');
        if (data) { try { msgs.push(JSON.parse(data)); } catch { /* skip */ } }
      }
    } else {
      const parsed = JSON.parse(text);
      msgs = Array.isArray(parsed) ? parsed : [parsed];
    }
    const msg = msgs.find((m) => m.id === id);
    if (!msg) throw new Error('No response to request');
    if (msg.error) throw new Error(msg.error.message || 'JSON-RPC error');
    if (method === 'initialize') negotiated = msg.result?.protocolVersion;
    return msg.result;
  };
  const notify = async (method) => { await post({ jsonrpc: '2.0', method }).then((r) => r.body?.cancel?.()).catch(() => {}); };

  try {
    const result = await discoverWith(request, notify);
    if (sessionId) {
      const headers = { 'mcp-session-id': sessionId };
      fetch(url, { method: 'DELETE', headers, signal: AbortSignal.timeout(2000) }).catch(() => {});
    }
    return result;
  } catch (e) {
    return { ok: false, error: e.cause?.code ? `${e.message} (${e.cause.code})` : e.message };
  }
}
