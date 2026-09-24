import path from 'node:path';
import { discover } from './discover.js';
import { checkServerConfig, unpublishedPackageFinding } from './config-rules.js';
import { checkInspection } from './tool-rules.js';
import { inspectServer } from './mcp-client.js';
import { queryOsv, packageExists, isMissingPackageError } from './advisories.js';
import { readLock, diffLock, serverKey } from './lock.js';
import { sevRank, VERSION } from './util.js';

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) { const idx = i++; results[idx] = await fn(items[idx], idx); }
  });
  await Promise.all(workers);
  return results;
}

/**
 * Run a full scan.
 * @param {object} opts
 * @param {string} [opts.dir]
 * @param {boolean} [opts.includeGlobal]
 * @param {boolean} [opts.connect]   launch/contact servers to inspect their tools
 * @param {boolean} [opts.online]    query OSV.dev for vulnerabilities and the registries for unpublished packages
 * @param {{npm?: string, pypi?: string}} [opts.registries]  registry base URLs (defaults: public npm / PyPI)
 * @param {boolean} [opts.useLock]   compare against mcp.lock.json when present
 * @param {number}  [opts.timeoutMs]
 * @param {(msg:string)=>void} [opts.log]
 */
export async function runScan(opts = {}) {
  const dir = path.resolve(opts.dir || process.cwd());
  const log = opts.log || (() => {});
  const { configs, servers, errors } = discover({ dir, includeProject: true, includeGlobal: opts.includeGlobal !== false, home: opts.home });
  const findings = [];
  if (opts.only?.length) {
    const keep = new Set(opts.only);
    for (let i = servers.length - 1; i >= 0; i--) if (!keep.has(servers[i].name)) servers.splice(i, 1);
  }

  for (const s of servers) {
    s.cwd = s.origin === 'project' ? dir : undefined;
    const { launch, findings: f } = checkServerConfig(s);
    s.launch = launch;
    findings.push(...f);
  }

  // MCPG009 can be found both online and from a failed launch; report it once per server.
  const unpublished = new Set();
  const reportUnpublished = (s, how) => {
    const key = s.name + '\0' + s.file;
    if (unpublished.has(key)) return;
    unpublished.add(key);
    findings.push(unpublishedPackageFinding(s, s.launch, how));
  };

  if (opts.online) {
    const published = servers.filter((s) => (s.launch?.kind === 'npm' || s.launch?.kind === 'pypi') && s.launch.source === 'registry' && s.launch.name);
    await mapLimit(published, 6, async (s) => {
      const { exists, error } = await packageExists(s.launch.kind, s.launch.name, { registry: opts.registries?.[s.launch.kind] });
      if (error) log(`Registry lookup failed for ${s.launch.name}: ${error}`);
      else if (exists === false) reportUnpublished(s, 'registry returned 404');
    });

    const pinned = servers.filter((s) => (s.launch?.kind === 'npm' || s.launch?.kind === 'pypi') && s.launch.pinned && s.launch.source === 'registry');
    await mapLimit(pinned, 6, async (s) => {
      const { vulns, error } = await queryOsv(s.launch.kind, s.launch.name, s.launch.version);
      if (error) { log(`OSV lookup failed for ${s.launch.name}: ${error}`); return; }
      for (const v of vulns) {
        if (findings.some((f) => f.server === s.name && f.advisory && (v.aliases || []).concat(v.id).some((a) => f.advisory.includes(a)))) continue;
        findings.push({
          ruleId: 'MCPG006', rule: 'known-vulnerable-package', title: 'Known vulnerable MCP package version',
          severity: /critical/i.test(v.database_specific?.severity || '') ? 'critical' : 'high',
          server: s.name, file: s.file, line: s.line, advisory: v.id, package: s.launch.name,
          detail: `${s.launch.name}@${s.launch.version} is affected by ${v.id}${v.aliases?.length ? ` (${v.aliases.join(', ')})` : ''}: ${v.summary || 'see advisory'}`,
          fix: `See https://osv.dev/vulnerability/${v.id} and upgrade.`,
        });
      }
    });
  }

  const inspections = new Map();
  if (opts.connect) {
    // Never launch servers whose command pipes remote code into a shell.
    const unsafe = new Set(findings.filter((f) => f.ruleId === 'MCPG003' && f.severity === 'high').map((f) => f.server + '\0' + f.file));
    const targets = servers.filter((s) => !s.disabled && !unsafe.has(s.name + '\0' + s.file));
    for (const s of servers) if (unsafe.has(s.name + '\0' + s.file)) s.inspection = { ok: false, error: 'Not launched: command pipes remote code into a shell' };
    log(`Connecting to ${targets.length} server(s) to read their tool definitions (no tools are called)…`);
    await mapLimit(targets, 4, async (s) => {
      const res = await inspectServer(s, { timeoutMs: opts.timeoutMs || 20000 });
      inspections.set(serverKey(s, dir), res);
      s.inspection = res.ok
        ? { ok: true, serverInfo: res.serverInfo, tools: res.tools.map((t) => t.name), prompts: res.prompts.map((p) => p.name) }
        : { ok: false, error: res.error };
      if (res.ok) findings.push(...checkInspection(s, res));
      else {
        log(`  ${s.name}: ${res.error}`);
        if (isMissingPackageError(s.launch, res.error)) reportUnpublished(s, 'the package manager reported it missing when launching the server');
      }
    });

    // Cross-server tool name collisions let one server hijack calls meant for another.
    const owners = new Map();
    for (const s of servers) {
      const res = inspections.get(serverKey(s, dir));
      if (!res?.ok) continue;
      for (const t of res.tools) {
        if (!owners.has(t.name)) owners.set(t.name, []);
        owners.get(t.name).push(s);
      }
    }
    for (const [tool, list] of owners) {
      const unique = [...new Map(list.map((s) => [s.name, s])).values()];
      if (unique.length > 1) {
        findings.push({
          ruleId: 'MCPT010', rule: 'tool-name-collision', title: 'Same tool name exposed by multiple servers', severity: 'medium',
          server: unique.map((s) => s.name).join(', '), tool, file: unique[0].file, line: unique[0].line,
          detail: `Tool "${tool}" is offered by ${unique.map((s) => `"${s.name}"`).join(' and ')}. The model may call the wrong one, and a malicious server can shadow a trusted tool this way.`,
          fix: 'Remove one of the servers or disable the duplicate tool.',
        });
      }
    }
  }

  let lockInfo = null;
  if (opts.useLock !== false) {
    const found = readLock(dir);
    if (found) {
      lockInfo = { file: found.file, hasTools: Object.values(found.lock.servers || {}).some((e) => e.tools) };
      findings.push(...diffLock({ lock: found.lock, lockFile: found.file, servers, inspections: opts.connect ? inspections : null, baseDir: dir }));
    }
  }

  findings.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || String(a.server).localeCompare(String(b.server)));
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;

  return {
    tool: 'mcpguard', version: VERSION, scannedAt: new Date().toISOString(), dir,
    options: { connect: !!opts.connect, online: !!opts.online, includeGlobal: opts.includeGlobal !== false },
    configs, errors, servers, findings, summary, lock: lockInfo, inspections,
  };
}
