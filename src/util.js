import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';

export const VERSION = '0.1.0';

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];

export function sevRank(sev) {
  const i = SEVERITIES.indexOf(sev);
  return i === -1 ? -1 : i;
}

export function sha256(value) {
  const text = typeof value === 'string' ? value : stableStringify(value);
  return createHash('sha256').update(text).digest('hex');
}

/** JSON.stringify with sorted keys so hashes are stable across runs. */
export function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
}

/** Parse JSON that may contain // or /* comments and trailing commas (VS Code style). */
export function parseJsonc(text) {
  let out = '';
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const next = text[i + 1];
    if (inString) {
      out += c;
      if (c === '\\') { out += next ?? ''; i++; }
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') { inString = true; out += c; continue; }
    if (c === '/' && next === '/') { while (i < text.length && text[i] !== '\n') i++; out += '\n'; continue; }
    if (c === '/' && next === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++; i++; continue; }
    out += c;
  }
  out = out.replace(/,(\s*[}\]])/g, '$1');
  return JSON.parse(out);
}

export function displayPath(p, baseDir) {
  const home = os.homedir();
  if (baseDir) {
    const rel = path.relative(baseDir, p);
    if (!rel.startsWith('..') && !path.isAbsolute(rel)) return rel.split(path.sep).join('/');
  }
  if (p.startsWith(home + path.sep)) return '~/' + path.relative(home, p).split(path.sep).join('/');
  return p;
}

export function mask(secret) {
  if (!secret) return '';
  const s = String(secret);
  if (s.length <= 8) return '****';
  return s.slice(0, 4) + '…' + s.slice(-2) + ` (${s.length} chars)`;
}

/** Compare dotted numeric versions. Returns -1, 0, 1. Pre-release tags are ignored. */
export function compareVersions(a, b) {
  const pa = String(a).replace(/^v/, '').split(/[.+-]/).map((x) => parseInt(x, 10));
  const pb = String(b).replace(/^v/, '').split(/[.+-]/).map((x) => parseInt(x, 10));
  for (let i = 0; i < 3; i++) {
    const x = Number.isNaN(pa[i]) || pa[i] === undefined ? 0 : pa[i];
    const y = Number.isNaN(pb[i]) || pb[i] === undefined ? 0 : pb[i];
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const wrap = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
export const c = {
  bold: wrap('1'), dim: wrap('2'), red: wrap('31'), green: wrap('32'), yellow: wrap('33'),
  blue: wrap('34'), magenta: wrap('35'), cyan: wrap('36'), gray: wrap('90'), bgRed: wrap('41;97'),
};

/** Replace ${VAR} / ${env:VAR} placeholders from the environment. */
export function expandEnv(value, env = process.env) {
  if (typeof value !== 'string') return value;
  return value.replace(/\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, k) => env[k] ?? '');
}
