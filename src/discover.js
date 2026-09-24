import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseJsonc } from './util.js';

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', '.next', 'vendor', '.venv', 'venv', '__pycache__', 'target', 'coverage']);

/** File names inside a project that can hold MCP server definitions. */
const PROJECT_FILES = [
  { match: (rel) => rel.endsWith('.mcp.json') && path.basename(rel) === '.mcp.json', client: 'Claude Code (project)' },
  { match: (rel) => /(^|\/)\.cursor\/mcp\.json$/.test(rel), client: 'Cursor (project)' },
  { match: (rel) => /(^|\/)\.vscode\/mcp\.json$/.test(rel), client: 'VS Code (workspace)' },
  { match: (rel) => /(^|\/)\.gemini\/settings\.json$/.test(rel), client: 'Gemini CLI (project)' },
  { match: (rel) => /(^|\/)\.roo\/mcp\.json$/.test(rel), client: 'Roo Code (project)' },
  { match: (rel) => path.basename(rel) === 'mcp.json' && !/\.(cursor|vscode|roo)\//.test(rel), client: 'Generic mcp.json' },
  { match: (rel) => path.basename(rel) === 'claude_desktop_config.json', client: 'Claude Desktop (copy)' },
  { match: (rel) => path.basename(rel) === 'mcp_config.json', client: 'Generic mcp_config.json' },
];

/** Well-known user-level config locations per client. */
export function globalConfigPaths(home, platform = process.platform, env = process.env) {
  // %APPDATA% belongs to the real user; when a home directory is passed in, stay inside it.
  const appData = (!home && env.APPDATA) || path.join(home || os.homedir(), 'AppData', 'Roaming');
  home = home || os.homedir();
  const claudeDesktop = platform === 'darwin'
    ? path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
    : platform === 'win32'
      ? path.join(appData, 'Claude', 'claude_desktop_config.json')
      : path.join(home, '.config', 'Claude', 'claude_desktop_config.json');
  const vscodeUser = platform === 'darwin'
    ? path.join(home, 'Library', 'Application Support', 'Code', 'User', 'mcp.json')
    : platform === 'win32'
      ? path.join(appData, 'Code', 'User', 'mcp.json')
      : path.join(home, '.config', 'Code', 'User', 'mcp.json');
  return [
    { file: claudeDesktop, client: 'Claude Desktop' },
    { file: path.join(home, '.claude.json'), client: 'Claude Code (user)' },
    { file: path.join(home, '.cursor', 'mcp.json'), client: 'Cursor (user)' },
    { file: vscodeUser, client: 'VS Code (user)' },
    { file: path.join(home, '.codeium', 'windsurf', 'mcp_config.json'), client: 'Windsurf' },
    { file: path.join(home, '.gemini', 'settings.json'), client: 'Gemini CLI (user)' },
  ];
}

function walk(dir, root, depth, out) {
  if (depth > 6) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walk(full, root, depth + 1, out);
    } else if (e.isFile() && e.name.endsWith('.json')) {
      const rel = path.relative(root, full).split(path.sep).join('/');
      const hit = PROJECT_FILES.find((p) => p.match(rel));
      if (hit) out.push({ file: full, client: hit.client });
    }
  }
}

export function findProjectConfigs(root) {
  const out = [];
  walk(root, root, 0, out);
  return out;
}

/** Find the 1-based line where a server's key appears, for SARIF/PR annotations. */
function lineOf(text, name, fromIndex = 0) {
  const idx = text.indexOf(JSON.stringify(name), fromIndex);
  if (idx === -1) return 1;
  return text.slice(0, idx).split('\n').length;
}

function normalizeServer(name, def, source, text, scope) {
  const d = def || {};
  const transportRaw = (d.type || d.transport || '').toLowerCase();
  const url = d.url || d.serverUrl || d.httpUrl;
  let transport = 'stdio';
  if (url) transport = transportRaw === 'sse' ? 'sse' : 'http';
  return {
    name,
    scope,
    client: source.client,
    file: source.file,
    line: lineOf(text, name),
    transport,
    command: d.command,
    args: Array.isArray(d.args) ? d.args.map(String) : [],
    env: d.env && typeof d.env === 'object' ? d.env : {},
    url,
    headers: d.headers && typeof d.headers === 'object' ? d.headers : {},
    disabled: d.disabled === true || d.enabled === false,
  };
}

/** Extract servers from any of the config shapes different clients use. */
export function parseConfigFile(source) {
  let text;
  try { text = fs.readFileSync(source.file, 'utf8'); } catch { return { servers: [], error: null, exists: false }; }
  // Editors create blank config files (e.g. VS Code's user mcp.json); that just means no servers.
  if (!text.replace(/^﻿/, '').trim()) return { servers: [], error: null, exists: true };
  let json;
  try { json = parseJsonc(text); } catch (e) {
    return { servers: [], error: `Could not parse JSON: ${e.message}`, exists: true };
  }
  const servers = [];
  const add = (obj, scope) => {
    if (!obj || typeof obj !== 'object') return;
    for (const [name, def] of Object.entries(obj)) {
      if (def && typeof def === 'object' && (def.command || def.url || def.serverUrl || def.httpUrl)) {
        servers.push(normalizeServer(name, def, source, text, scope));
      }
    }
  };
  add(json.mcpServers, 'default');
  add(json.servers, 'default');
  add(json.mcp?.servers, 'default');
  // Claude Code keeps per-project servers in ~/.claude.json under projects[path].mcpServers
  if (json.projects && typeof json.projects === 'object') {
    for (const [proj, cfg] of Object.entries(json.projects)) add(cfg?.mcpServers, `project:${proj}`);
  }
  return { servers, error: null, exists: true };
}

/**
 * Discover all MCP servers.
 * @param {{dir?: string, includeProject?: boolean, includeGlobal?: boolean, home?: string}} opts
 */
export function discover({ dir = process.cwd(), includeProject = true, includeGlobal = true, home } = {}) {
  const sources = [];
  if (includeProject) sources.push(...findProjectConfigs(dir).map((s) => ({ ...s, origin: 'project' })));
  if (includeGlobal) sources.push(...globalConfigPaths(home).map((s) => ({ ...s, origin: 'global' })));
  const seen = new Set();
  const configs = [];
  const servers = [];
  const errors = [];
  for (const src of sources) {
    const real = path.resolve(src.file);
    if (seen.has(real)) continue;
    seen.add(real);
    const res = parseConfigFile(src);
    if (!res.exists) continue;
    configs.push({ file: src.file, client: src.client, origin: src.origin, servers: res.servers.length });
    if (res.error) errors.push({ file: src.file, error: res.error });
    for (const s of res.servers) servers.push({ ...s, origin: src.origin });
  }
  return { configs, servers, errors };
}
