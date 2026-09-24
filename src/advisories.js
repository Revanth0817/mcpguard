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
