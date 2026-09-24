import os from 'node:os';
import { resolveLaunch } from './package.js';
import { matchAdvisories } from './advisories.js';
import { mask } from './util.js';

export const CONFIG_RULES = {
  MCPG001: { name: 'hardcoded-secret', title: 'Hardcoded secret in MCP config' },
  MCPG002: { name: 'unpinned-package', title: 'Server package is not pinned to a version' },
  MCPG003: { name: 'shell-execution', title: 'Server launched through a shell' },
  MCPG004: { name: 'insecure-transport', title: 'Remote server uses unencrypted HTTP' },
  MCPG005: { name: 'broad-filesystem-access', title: 'Server granted access to root or home directory' },
  MCPG006: { name: 'known-vulnerable-package', title: 'Known vulnerable MCP package version' },
  MCPG007: { name: 'unsafe-container', title: 'Container runs with dangerous privileges' },
  MCPG008: { name: 'unreviewed-source', title: 'Server installed directly from a git URL' },
  MCPG009: { name: 'unpublished-package', title: 'Server package does not exist in the registry' },
};

const SECRET_PATTERNS = [
  { re: /gh[pousr]_[A-Za-z0-9]{36,}/, label: 'GitHub token' },
  { re: /github_pat_[A-Za-z0-9_]{22,}/, label: 'GitHub fine-grained token' },
  { re: /sk-ant-[A-Za-z0-9_-]{20,}/, label: 'Anthropic API key' },
  { re: /sk-(?:proj-)?[A-Za-z0-9_-]{32,}/, label: 'OpenAI API key' },
  { re: /xox[abprs]-[A-Za-z0-9-]{10,}/, label: 'Slack token' },
  { re: /AKIA[0-9A-Z]{16}/, label: 'AWS access key' },
  { re: /AIza[0-9A-Za-z_-]{35}/, label: 'Google API key' },
  { re: /glpat-[A-Za-z0-9_-]{20,}/, label: 'GitLab token' },
  { re: /(?:sk|rk)_live_[A-Za-z0-9]{20,}/, label: 'Stripe live key' },
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, label: 'Private key' },
  { re: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s/]+:[^@\s]{3,}@/, label: 'Database URL with password' },
];
const SECRET_KEY_NAME = /(token|secret|passw(or)?d|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth|credential)/i;
const PLACEHOLDER = /^\s*$|\$\{|\$env:|^<.*>$|your[_-]|xxx|changeme|placeholder|example|dummy|redacted|\*\*\*/i;

/** Replace anything that looks like a secret with a masked version, for safe display. */
export function redact(value) {
  if (typeof value !== 'string') return value;
  let out = value;
  for (const p of SECRET_PATTERNS) {
    out = out.replace(new RegExp(p.re.source, 'g'), (m) => {
      const db = /^([a-z+]+:\/\/[^:\s/]+:)[^@\s]+@$/i.exec(m);
      return db ? `${db[1]}****@` : mask(m);
    });
  }
  return out.replace(/^(bearer\s+)(\S{16,})$/i, (_, b, t) => (PLACEHOLDER.test(t) ? b + t : b + mask(t)));
}

function finding(ruleId, severity, server, detail, fix, extra = {}) {
  return { ruleId, rule: CONFIG_RULES[ruleId].name, title: CONFIG_RULES[ruleId].title, severity, server: server.name, file: server.file, line: server.line, detail, fix, ...extra };
}

function checkSecrets(server) {
  const out = [];
  const candidates = [];
  for (const [k, v] of Object.entries(server.env)) candidates.push({ where: `env.${k}`, key: k, value: String(v) });
  for (const [k, v] of Object.entries(server.headers)) candidates.push({ where: `headers.${k}`, key: k, value: String(v) });
  server.args.forEach((a, i) => candidates.push({ where: `args[${i}]`, key: '', value: a }));
  if (server.url) candidates.push({ where: 'url', key: '', value: server.url });

  for (const cnd of candidates) {
    const hit = SECRET_PATTERNS.find((p) => p.re.test(cnd.value));
    if (hit) {
      const m = cnd.value.match(hit.re)[0];
      out.push(finding('MCPG001', 'high', server, `${hit.label} stored in plain text at ${cnd.where}: ${mask(m)}`,
        'Move the secret to an environment variable or secret manager and reference it as ${VAR}. Rotate the exposed key.'));
      continue;
    }
    const bearer = /^bearer\s+(\S{16,})$/i.exec(cnd.value);
    if (bearer && !PLACEHOLDER.test(bearer[1])) {
      out.push(finding('MCPG001', 'high', server, `Bearer token stored in plain text at ${cnd.where}: ${mask(bearer[1])}`,
        'Reference the token from an environment variable (e.g. "Bearer ${API_TOKEN}") and rotate it.'));
      continue;
    }
    if (cnd.key && SECRET_KEY_NAME.test(cnd.key) && cnd.value.length >= 12 && !PLACEHOLDER.test(cnd.value) && !/^(true|false|\d+)$/i.test(cnd.value)) {
      out.push(finding('MCPG001', 'medium', server, `Value of ${cnd.where} looks like a literal credential: ${mask(cnd.value)}`,
        'Use an environment variable reference instead of committing the value.'));
    }
  }
  return out;
}

function checkLaunch(server, launch) {
  const out = [];
  if (launch.kind === 'npm' || launch.kind === 'pypi' || launch.kind === 'docker') {
    if (launch.source === 'git') {
      out.push(finding('MCPG008', launch.pinned ? 'low' : 'medium', server,
        `Installs "${launch.name}" straight from a git source${launch.pinned ? ' (pinned to a commit)' : ' without a pinned commit'}; code is not reviewed by a registry and can change at any time.`,
        'Prefer a published, versioned package, or pin to a full commit SHA and review the code.'));
    } else if (launch.name && !launch.pinned && launch.source !== 'local') {
      const how = launch.kind === 'docker' ? `${launch.name}@sha256:<digest> or a fixed tag` : launch.kind === 'pypi' ? `${launch.name}==<version>` : `${launch.name}@<version>`;
      out.push(finding('MCPG002', 'medium', server,
        `"${launch.name}${launch.version ? (launch.kind === 'docker' ? ':' : '@') + launch.version : ''}" resolves to whatever is newest at launch time. A compromised or malicious update (rug pull) would run automatically.`,
        `Pin an exact version: ${how}. Then record it with "mcpguard lock".`, { package: launch.name }));
    }
    if (launch.kind === 'npm' || launch.kind === 'pypi') {
      for (const adv of matchAdvisories(launch.kind, launch.name, launch.version)) {
        out.push(finding('MCPG006', adv.severity, server, `${launch.name}@${launch.version} is affected by ${adv.id}: ${adv.summary}`,
          `Upgrade to ${adv.ranges.map((r) => r.fixed).join(' / ')} or later.`, { advisory: adv.id, package: launch.name }));
      }
    }
  }
  return out;
}

function checkShell(server) {
  const out = [];
  const cmd = String(server.command || '').toLowerCase().split(/[\\/]/).pop().replace(/\.exe$/, '');
  const joined = [server.command, ...server.args].join(' ');
  if (/(curl|wget|iwr|invoke-webrequest)[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|iex)\b/i.test(joined)) {
    out.push(finding('MCPG003', 'high', server, `Downloads and pipes remote code into an interpreter: "${joined.slice(0, 160)}"`,
      'Never pipe remote scripts into a shell. Install a pinned package instead.'));
  } else if (['sh', 'bash', 'zsh', 'fish', 'powershell', 'pwsh'].includes(cmd) && server.args.some((a) => /^-(c|command)$/i.test(a))) {
    out.push(finding('MCPG003', 'medium', server, `Server is started via "${cmd} -c", which hides what actually runs and allows command chaining.`,
      'Call the server binary/package directly with explicit arguments.'));
  }
  return out;
}

function checkTransport(server) {
  if (!server.url) return [];
  let u;
  try { u = new URL(server.url.replace(/\$\{[^}]+\}/g, 'x')); } catch { return []; }
  const local = ['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0'].includes(u.hostname);
  if (u.protocol === 'http:' && !local) {
    return [finding('MCPG004', 'high', server, `Remote server ${u.host} is reached over plain HTTP; tool calls, results and tokens can be read or modified in transit.`,
      'Use an https:// endpoint.')];
  }
  return [];
}

function checkFilesystem(server) {
  const home = os.homedir();
  const broad = new Set(['/', '~', '~/', '$HOME', '${HOME}', '%USERPROFILE%', 'C:\\', 'C:/', home, home + '/']);
  const hits = server.args.filter((a) => broad.has(a.trim()));
  if (!hits.length) return [];
  return [finding('MCPG005', 'medium', server,
    `Server is given access to ${hits.map((h) => `"${h}"`).join(', ')}. That includes SSH keys, cloud credentials and other MCP configs, which prompt-injected agents are known to exfiltrate.`,
    'Restrict access to the specific project directories the agent needs.')];
}

function checkDocker(server, launch) {
  if (launch.kind !== 'docker') return [];
  const out = [];
  const a = server.args;
  const reasons = [];
  if (a.includes('--privileged')) reasons.push('--privileged');
  if (a.some((x) => /docker\.sock/.test(x))) reasons.push('mounts the Docker socket (full host control)');
  if (a.some((x, i) => (x === '--network' || x === '--net') && a[i + 1] === 'host') || a.includes('--network=host')) reasons.push('uses host networking');
  if (a.some((x, i) => (x === '-v' || x === '--volume') && /^(\/|~|\$HOME|\$\{HOME\}):/.test(a[i + 1] || ''))) reasons.push('mounts the host root or home directory');
  if (reasons.length) out.push(finding('MCPG007', 'high', server, `Container ${reasons.join(', ')}.`, 'Drop the flag / mount only what the server needs.'));
  return out;
}

/** MCPG009: the configured package name is not published, so anyone can claim it. */
export function unpublishedPackageFinding(server, launch, how) {
  const registry = launch.kind === 'pypi' ? 'PyPI' : 'npm';
  return finding('MCPG009', 'high', server,
    `"${launch.name}" was not found on ${registry} (${how}). Anyone can register that name, and this config would then download and run their code${server.env && Object.keys(server.env).length ? ' with the env vars (including any tokens) set here' : ''}.`,
    'Remove the server, or fix the package name and pin an exact version. If it is a private package, make sure the registry and credentials are configured.',
    { package: launch.name });
}

export function checkServerConfig(server) {
  const launch = resolveLaunch(server);
  return {
    launch,
    findings: [
      ...checkSecrets(server),
      ...checkLaunch(server, launch),
      ...checkShell(server),
      ...checkTransport(server),
      ...checkFilesystem(server),
      ...checkDocker(server, launch),
    ],
  };
}
