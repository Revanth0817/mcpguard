import path from 'node:path';
import { c, displayPath, VERSION, SEVERITIES } from './util.js';
import { CONFIG_RULES, redact } from './config-rules.js';
import { TOOL_RULES } from './tool-rules.js';
import { DRIFT_RULES } from './lock.js';

const SEV_STYLE = {
  critical: (s) => c.bgRed(` ${s.toUpperCase()} `),
  high: (s) => c.red(c.bold(s.toUpperCase())),
  medium: (s) => c.yellow(s.toUpperCase()),
  low: (s) => c.blue(s.toUpperCase()),
  info: (s) => c.gray(s.toUpperCase()),
};

function publicServer(s, dir) {
  return {
    name: s.name, client: s.client, origin: s.origin, file: displayPath(s.file, dir), line: s.line, transport: s.transport,
    command: s.command, args: s.args.map(redact), url: redact(s.url), envKeys: Object.keys(s.env || {}), headerKeys: Object.keys(s.headers || {}),
    disabled: s.disabled, launch: s.launch, inspection: s.inspection,
  };
}

function publicFinding(f, dir) {
  return { ...f, file: f.file ? displayPath(f.file, dir) : undefined };
}

export function toJson(result) {
  return JSON.stringify({
    tool: result.tool, version: result.version, scannedAt: result.scannedAt, options: result.options,
    summary: result.summary,
    configs: result.configs.map((x) => ({ ...x, file: displayPath(x.file, result.dir) })),
    errors: result.errors,
    servers: result.servers.map((s) => publicServer(s, result.dir)),
    findings: result.findings.map((f) => publicFinding(f, result.dir)),
    lockfile: result.lock ? displayPath(result.lock.file, result.dir) : null,
  }, null, 2);
}

export function toText(result, { verbose = false } = {}) {
  const out = [];
  const dir = result.dir;
  out.push(c.bold(`mcpguard ${VERSION}`) + c.gray(` — scanned ${result.configs.length} config file(s), ${result.servers.length} MCP server(s)`));
  out.push('');

  if (result.servers.length === 0) {
    out.push(c.gray('No MCP servers found. Looked for .mcp.json, .cursor/mcp.json, .vscode/mcp.json, Claude Desktop, Claude Code, Cursor, VS Code, Windsurf and Gemini configs.'));
  } else {
    const byFile = new Map();
    for (const s of result.servers) {
      const k = `${s.client} — ${displayPath(s.file, dir)}`;
      if (!byFile.has(k)) byFile.set(k, []);
      byFile.get(k).push(s);
    }
    out.push(c.bold('Servers'));
    for (const [k, list] of byFile) {
      out.push('  ' + c.cyan(k));
      for (const s of list) {
        const target = redact(s.url || [s.command, ...s.args].join(' '));
        const insp = s.inspection ? (s.inspection.ok ? c.green(` ✓ ${s.inspection.tools.length} tools`) : c.yellow(' ✗ not inspected')) : '';
        const count = result.findings.filter((f) => f.server === s.name && f.file === s.file).length;
        const badge = count ? c.red(` ${count} issue${count > 1 ? 's' : ''}`) : c.green(' ok');
        out.push(`    • ${c.bold(s.name)}${s.disabled ? c.gray(' (disabled)') : ''} ${c.gray(target.length > 80 ? target.slice(0, 77) + '…' : target)}${insp}${badge}`);
      }
    }
    out.push('');
  }

  for (const e of result.errors) out.push(c.yellow(`! ${displayPath(e.file, dir)}: ${e.error}`));

  const shown = verbose ? result.findings : result.findings.filter((f) => f.severity !== 'info');
  if (shown.length) {
    out.push(c.bold('Findings'));
    for (const f of shown) {
      const loc = f.file ? c.gray(`${displayPath(f.file, dir)}:${f.line || 1}`) : '';
      out.push(`  ${SEV_STYLE[f.severity](f.severity)} ${c.bold(f.title)} ${c.gray(`[${f.ruleId}]`)}`);
      out.push(`    server: ${f.server}${f.tool ? `  tool: ${f.tool}` : ''}  ${loc}`);
      for (const line of String(f.detail).split('\n')) out.push(`    ${line}`);
      if (f.fix) out.push(`    ${c.green('fix:')} ${f.fix}`);
      out.push('');
    }
  } else if (result.servers.length) {
    out.push(c.green('✓ No issues found.'));
    out.push('');
  }

  const s = result.summary;
  out.push(c.bold('Summary ') + [
    s.critical ? c.red(`${s.critical} critical`) : `${s.critical} critical`,
    s.high ? c.red(`${s.high} high`) : `${s.high} high`,
    s.medium ? c.yellow(`${s.medium} medium`) : `${s.medium} medium`,
    `${s.low} low`, `${s.info} info`,
  ].join(c.gray(' · ')));
  const tips = [];
  if (!result.options.connect && result.servers.length) tips.push('Run with --connect to inspect tool descriptions for poisoning (launches the servers, calls no tools).');
  if (!result.lock && result.servers.length) tips.push('Run "mcpguard lock" to approve the current servers and detect future changes (rug pulls).');
  if (result.lock?.hasTools && !result.options.connect) tips.push('Lockfile has tool fingerprints; add --connect to check them for drift.');
  for (const t of tips) out.push(c.gray('→ ' + t));
  return out.join('\n');
}

export function toMarkdown(result) {
  const s = result.summary;
  const lines = [`## 🛡️ mcpguard: ${result.servers.length} MCP server(s) scanned`, '',
    `**${s.critical}** critical · **${s.high}** high · **${s.medium}** medium · ${s.low} low · ${s.info} info`, ''];
  const shown = result.findings.filter((f) => f.severity !== 'info');
  if (!shown.length) { lines.push('✅ No issues found.'); return lines.join('\n'); }
  lines.push('| Severity | Finding | Server | Location |', '|---|---|---|---|');
  for (const f of shown) {
    const detail = String(f.detail).split('\n')[0].replace(/\|/g, '\\|');
    lines.push(`| ${f.severity} | **${f.title}** (${f.ruleId})<br>${detail} | \`${f.server}\`${f.tool ? ` / \`${f.tool}\`` : ''} | \`${displayPath(f.file, result.dir)}:${f.line || 1}\` |`);
  }
  return lines.join('\n');
}

export function toSarif(result) {
  const allRules = { ...CONFIG_RULES, ...TOOL_RULES, ...DRIFT_RULES, MCPT010: { name: 'tool-name-collision', title: 'Same tool name exposed by multiple servers' } };
  const used = [...new Set(result.findings.map((f) => f.ruleId))];
  const level = (sev) => (sev === 'critical' || sev === 'high' ? 'error' : sev === 'medium' ? 'warning' : 'note');
  const score = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };
  const rules = used.map((id) => {
    const worst = result.findings.filter((f) => f.ruleId === id).map((f) => f.severity).sort((a, b) => SEVERITIES.indexOf(b) - SEVERITIES.indexOf(a))[0];
    return {
      id, name: allRules[id]?.name || id,
      shortDescription: { text: allRules[id]?.title || id },
      helpUri: `https://github.com/Revanth0817/mcpguard#${id.toLowerCase()}`,
      properties: { tags: ['security', 'mcp', 'ai-agents'], 'security-severity': score[worst] },
    };
  });
  const results = result.findings.map((f) => {
    const file = f.file ? path.relative(result.dir, f.file).split(path.sep).join('/') : undefined;
    const inRepo = file && !file.startsWith('..') && !path.isAbsolute(file);
    return {
      ruleId: f.ruleId,
      ruleIndex: used.indexOf(f.ruleId),
      level: level(f.severity),
      message: { text: `[${f.server}${f.tool ? ' / ' + f.tool : ''}] ${f.detail}${f.fix ? `\nFix: ${f.fix}` : ''}` },
      locations: inRepo ? [{ physicalLocation: { artifactLocation: { uri: file }, region: { startLine: f.line || 1 } } }] : [],
      partialFingerprints: { mcpguard: `${f.ruleId}:${f.server}:${f.tool || ''}:${file || ''}` },
    };
  });
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'mcpguard', version: VERSION, informationUri: 'https://github.com/Revanth0817/mcpguard', rules } }, results }],
  }, null, 2);
}
