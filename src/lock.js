import fs from 'node:fs';
import path from 'node:path';
import { VERSION, sha256, displayPath } from './util.js';

export const LOCK_FILE = 'mcp.lock.json';

export const DRIFT_RULES = {
  MCPD001: { name: 'unapproved-server', title: 'MCP server not in lockfile' },
  MCPD002: { name: 'server-config-changed', title: 'Server launch config changed since approval' },
  MCPD003: { name: 'tool-definition-changed', title: 'Tool definition changed since approval (possible rug pull)' },
  MCPD004: { name: 'tool-added', title: 'New tool appeared since approval' },
  MCPD005: { name: 'tool-removed', title: 'Tool removed since approval' },
  MCPD006: { name: 'server-removed', title: 'Approved server no longer configured' },
  MCPD007: { name: 'server-version-changed', title: 'Server reports a different version' },
};

export function serverKey(server, baseDir) {
  const scope = server.scope && server.scope !== 'default' ? `@${server.scope}` : '';
  return `${displayPath(server.file, baseDir)}#${server.name}${scope}`;
}

/** Fingerprint of how a server is launched. Env/header values are excluded so secrets never land in the lockfile. */
export function configFingerprint(server) {
  return {
    transport: server.transport,
    command: server.command ?? null,
    args: server.args,
    url: server.url ? server.url.split('?')[0] : null,
    envKeys: Object.keys(server.env || {}).sort(),
    headerKeys: Object.keys(server.headers || {}).map((h) => h.toLowerCase()).sort(),
  };
}

export function toolFingerprint(tool) {
  return {
    description: tool.description ?? '',
    title: tool.title ?? null,
    inputSchema: sha256(tool.inputSchema ?? {}),
    annotations: tool.annotations ? sha256(tool.annotations) : null,
  };
}

export function buildLock({ servers, inspections, baseDir }) {
  const entries = {};
  for (const s of servers) {
    const key = serverKey(s, baseDir);
    const fp = configFingerprint(s);
    const entry = {
      client: s.client,
      launch: s.launch ? { kind: s.launch.kind, package: s.launch.name ?? null, version: s.launch.version ?? null } : undefined,
      configHash: sha256(fp),
    };
    const insp = inspections?.get(key);
    if (insp?.ok) {
      entry.serverInfo = { name: insp.serverInfo?.name ?? null, version: insp.serverInfo?.version ?? null };
      entry.instructionsHash = insp.instructions ? sha256(insp.instructions) : null;
      entry.tools = {};
      for (const t of [...insp.tools].sort((a, b) => a.name.localeCompare(b.name))) {
        const tf = toolFingerprint(t);
        entry.tools[t.name] = { hash: sha256(tf), description: tf.description };
      }
    }
    entries[key] = entry;
  }
  return {
    lockfileVersion: 1,
    generatedBy: `mcpguard ${VERSION}`,
    generatedAt: new Date().toISOString(),
    servers: Object.fromEntries(Object.entries(entries).sort(([a], [b]) => a.localeCompare(b))),
  };
}

export function readLock(dir) {
  const file = path.join(dir, LOCK_FILE);
  if (!fs.existsSync(file)) return null;
  return { file, lock: JSON.parse(fs.readFileSync(file, 'utf8')) };
}

export function writeLock(dir, lock) {
  const file = path.join(dir, LOCK_FILE);
  fs.writeFileSync(file, JSON.stringify(lock, null, 2) + '\n');
  return file;
}

function lineDiff(a, b) {
  const al = String(a).split('\n');
  const bl = String(b).split('\n');
  const removed = al.filter((l) => !bl.includes(l)).map((l) => `- ${l}`);
  const added = bl.filter((l) => !al.includes(l)).map((l) => `+ ${l}`);
  return [...removed, ...added].slice(0, 12).join('\n');
}

/** Compare current state to the lockfile and return drift findings. */
export function diffLock({ lock, lockFile, servers, inspections, baseDir }) {
  const findings = [];
  const current = new Map(servers.map((s) => [serverKey(s, baseDir), s]));
  const add = (ruleId, severity, server, detail, fix, extra = {}) => findings.push({
    ruleId, rule: DRIFT_RULES[ruleId].name, title: DRIFT_RULES[ruleId].title, severity,
    server: server?.name ?? extra.serverName, file: server?.file ?? lockFile, line: server?.line ?? 1, detail, fix, ...extra,
  });

  for (const [key, s] of current) {
    const locked = lock.servers?.[key];
    if (!locked) {
      add('MCPD001', 'high', s, `"${s.name}" (${s.client}) is configured but was never approved in ${LOCK_FILE}. New servers can be slipped in via a pull request or a cloned repo.`,
        'Review the server, then run "mcpguard lock" to approve it.');
      continue;
    }
    if (locked.configHash !== sha256(configFingerprint(s))) {
      add('MCPD002', 'high', s, `Launch configuration (command/args/url/env keys) of "${s.name}" differs from the approved version.`,
        'Review the change; if intended, run "mcpguard lock".');
    }
    const insp = inspections?.get(key);
    if (!insp?.ok || !locked.tools) continue;
    if (locked.serverInfo?.version && insp.serverInfo?.version && locked.serverInfo.version !== insp.serverInfo.version) {
      add('MCPD007', 'medium', s, `"${s.name}" now reports version ${insp.serverInfo.version} (approved: ${locked.serverInfo.version}).`,
        'Check the changelog, then re-approve with "mcpguard lock --connect".');
    }
    if ((locked.instructionsHash ?? null) !== (insp.instructions ? sha256(insp.instructions) : null)) {
      add('MCPD003', 'high', s, `Server-level instructions sent to the model changed for "${s.name}".`, 'Review the new instructions before re-approving.', { tool: '(instructions)' });
    }
    const now = new Map(insp.tools.map((t) => [t.name, t]));
    for (const [name, lt] of Object.entries(locked.tools)) {
      const t = now.get(name);
      if (!t) {
        add('MCPD005', 'low', s, `Tool "${name}" is no longer offered by "${s.name}".`, 'Re-approve with "mcpguard lock --connect" if expected.', { tool: name });
        continue;
      }
      const tf = toolFingerprint(t);
      if (sha256(tf) !== lt.hash) {
        const descChanged = tf.description !== lt.description;
        add('MCPD003', 'critical', s,
          `Tool "${name}" on "${s.name}" changed after it was approved${descChanged ? ':\n' + lineDiff(lt.description, tf.description) : ' (input schema or annotations changed)'}`,
          'Do not re-approve until the change is reviewed. Silent tool changes are how "rug pull" attacks work.', { tool: name });
      }
    }
    for (const [name] of now) {
      if (!locked.tools[name]) {
        add('MCPD004', 'high', s, `New tool "${name}" appeared on "${s.name}" since approval.`, 'Review the tool, then run "mcpguard lock --connect".', { tool: name });
      }
    }
  }
  for (const key of Object.keys(lock.servers || {})) {
    if (!current.has(key)) add('MCPD006', 'info', null, `Approved server "${key}" is no longer configured.`, 'Run "mcpguard lock" to clean up the lockfile.', { serverName: key.split('#').pop() });
  }
  return findings;
}
