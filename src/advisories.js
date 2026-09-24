import { compareVersions } from './util.js';

/**
 * Starter set of known-vulnerable MCP packages. `--online` adds live OSV.dev lookups.
 * Ranges: affected when introduced <= version < fixed.
 */
export const ADVISORIES = [
  {
    id: 'CVE-2025-6514', ecosystem: 'npm', package: 'mcp-remote', severity: 'critical',
    ranges: [{ introduced: '0.0.5', fixed: '0.1.16' }],
    summary: 'OS command injection when connecting to a malicious remote MCP server (crafted authorization_endpoint). CVSS 9.6.',
  },
  {
    id: 'CVE-2025-49596', ecosystem: 'npm', package: '@modelcontextprotocol/inspector', severity: 'critical',
    ranges: [{ introduced: '0.0.0', fixed: '0.14.1' }],
    summary: 'MCP Inspector proxy lacks authentication, allowing remote code execution from a malicious website. CVSS 9.4.',
  },
  {
    id: 'CVE-2025-53109 / CVE-2025-53110', ecosystem: 'npm', package: '@modelcontextprotocol/server-filesystem', severity: 'high',
    ranges: [{ introduced: '0.0.0', fixed: '0.6.3' }, { introduced: '2025.0.0', fixed: '2025.7.1' }],
    summary: 'Directory containment bypass and symlink escape let the server read/write outside allowed directories.',
  },
];

export function matchAdvisories(ecosystem, name, version) {
  if (!name || !version) return [];
  return ADVISORIES.filter((a) => a.ecosystem === ecosystem && a.package === name && a.ranges.some(
    (r) => compareVersions(version, r.introduced) >= 0 && compareVersions(version, r.fixed) < 0,
  ));
}

/** Query OSV.dev for a pinned package version. Network failures are non-fatal. */
export async function queryOsv(ecosystem, name, version, timeoutMs = 6000) {
  const eco = ecosystem === 'npm' ? 'npm' : ecosystem === 'pypi' ? 'PyPI' : null;
  if (!eco || !name || !version) return { vulns: [], error: null };
  try {
    const res = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ package: { name, ecosystem: eco }, version }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return { vulns: [], error: `OSV HTTP ${res.status}` };
    const data = await res.json();
    return { vulns: data.vulns || [], error: null };
  } catch (e) {
    return { vulns: [], error: e.message };
  }
}

/**
 * Check whether a package name is published at all. `exists` is null when the answer is unknown
 * (unsupported ecosystem or a network error). Only the package name is sent, never the config.
 */
export async function packageExists(ecosystem, name, { timeoutMs = 6000, registry } = {}) {
  const url = !name ? null
    : ecosystem === 'npm' ? `${registry || 'https://registry.npmjs.org'}/${name.replace('/', '%2f')}`
      : ecosystem === 'pypi' ? `${registry || 'https://pypi.org/pypi'}/${encodeURIComponent(name)}/json`
        : null;
  if (!url) return { exists: null, error: null };
  try {
    // The abbreviated npm document is much smaller than the full packument.
    const res = await fetch(url, { headers: { accept: 'application/vnd.npm.install-v1+json, application/json' }, signal: AbortSignal.timeout(timeoutMs) });
    try { await res.body?.cancel(); } catch { /* ignore */ }
    if (res.status === 404) return { exists: false, error: null };
    if (!res.ok) return { exists: null, error: `HTTP ${res.status}` };
    return { exists: true, error: null };
  } catch (e) {
    return { exists: null, error: e.message };
  }
}

/** True when a failed launch's error output shows the package manager could not find the package. */
export function isMissingPackageError(launch, error) {
  if (!error || !launch || launch.source !== 'registry') return false;
  if (launch.kind === 'npm') return /\bE404\b|npm (error|ERR!) 404\b/.test(error);
  if (launch.kind === 'pypi') return /not found in the package registry|No matching distribution found/i.test(error);
  return false;
}
