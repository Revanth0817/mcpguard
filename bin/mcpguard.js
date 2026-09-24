#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { runScan } from '../src/scan.js';
import { buildLock, writeLock, LOCK_FILE } from '../src/lock.js';
import { toText, toJson, toSarif, toMarkdown } from '../src/report.js';
import { CONFIG_RULES, redact } from '../src/config-rules.js';
import { TOOL_RULES } from '../src/tool-rules.js';
import { DRIFT_RULES } from '../src/lock.js';
import { VERSION, sevRank, c } from '../src/util.js';

const HELP = `${c.bold('mcpguard')} ${VERSION} — find risky MCP servers before your AI agents use them

${c.bold('Usage')}
  mcpguard [scan] [dir] [options]   Scan MCP configs (project + user-level)
  mcpguard lock [dir] [options]     Approve current servers into ${LOCK_FILE}
  mcpguard list [dir]               List discovered MCP servers
  mcpguard rules                    List all detection rules

${c.bold('Options')}
  --connect           Launch/contact each server and analyse its tool definitions
                      (runs server code; only read-only list calls are made)
  --online            Check pinned packages against the OSV.dev vulnerability database
  --global            Include user-level configs (default when no dir is given, outside CI)
  --no-global         Only scan the project directory
  --no-lock           Ignore ${LOCK_FILE} when scanning
  --format <f>        text (default) | json | sarif | markdown
  --output <file>     Write the report to a file instead of stdout
  --fail-on <sev>     Exit 1 if a finding is at/above: critical | high (default) | medium | low | none
  --timeout <sec>     Per-server connection timeout (default 20)
  --server <names>    Only scan these server names (comma-separated, repeatable)
  --verbose           Also show info-level findings
  -h, --help          Show help
  -v, --version       Show version

${c.bold('Examples')}
  npx mcpguard                         # audit this machine + current project
  npx mcpguard --connect               # also detect tool poisoning
  npx mcpguard lock --connect          # approve servers & tool definitions
  npx mcpguard . --no-global --format sarif --output mcpguard.sarif   # CI
`;

function parseArgs(argv) {
  const opts = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { const v = argv[++i]; if (v === undefined) throw new Error(`Missing value for ${a}`); return v; };
    switch (a) {
      case '--connect': opts.connect = true; break;
      case '--online': opts.online = true; break;
      case '--global': opts.global = true; break;
      case '--no-global': opts.global = false; break;
      case '--no-lock': opts.noLock = true; break;
      case '--format': case '-f': opts.format = val(); break;
      case '--output': case '-o': opts.output = val(); break;
      case '--fail-on': opts.failOn = val(); break;
      case '--timeout': opts.timeout = Number(val()); break;
      case '--verbose': opts.verbose = true; break;
      case '--server': case '-s': (opts.only ||= []).push(...val().split(',')); break;
      case '-h': case '--help': opts.help = true; break;
      case '-v': case '--version': opts.version = true; break;
      default:
        if (a.startsWith('--') && a.includes('=')) { const [k, v] = a.split('='); argv.splice(i + 1, 0, v); argv[i] = k; i--; break; }
        if (a.startsWith('-')) throw new Error(`Unknown option: ${a}`);
        opts._.push(a);
    }
  }
  return opts;
}

async function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); } catch (e) { console.error(c.red(e.message)); console.error('Run "mcpguard --help".'); return 2; }
  if (opts.version) { console.log(VERSION); return 0; }
  if (opts.help) { console.log(HELP); return 0; }

  const commands = ['scan', 'lock', 'list', 'rules'];
  const command = commands.includes(opts._[0]) ? opts._.shift() : 'scan';
  const dirArg = opts._[0];
  const dir = path.resolve(dirArg || process.cwd());
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) { console.error(c.red(`Not a directory: ${dir}`)); return 2; }

  if (command === 'rules') {
    for (const [group, rules] of [['Config', CONFIG_RULES], ['Tool definitions (--connect)', TOOL_RULES], ['Drift / lockfile', DRIFT_RULES]]) {
      console.log(c.bold(group));
      for (const [id, r] of Object.entries(rules)) console.log(`  ${c.cyan(id)}  ${r.name.padEnd(30)} ${c.gray(r.title)}`);
    }
    console.log(`  ${c.cyan('MCPT010')}  ${'tool-name-collision'.padEnd(30)} ${c.gray('Same tool name exposed by multiple servers')}`);
    return 0;
  }

  const includeGlobal = opts.global ?? (command === 'lock' ? false : !dirArg && !process.env.CI);
  const log = (m) => process.stderr.write(c.gray(m) + '\n');
  if (opts.connect && process.stderr.isTTY) log('Note: --connect starts each configured server process to read its tool list.');

  const result = await runScan({
    dir, includeGlobal, connect: !!opts.connect, online: !!opts.online,
    useLock: command === 'scan' && !opts.noLock, only: opts.only, timeoutMs: (opts.timeout || 20) * 1000, log,
  });

  if (command === 'list') {
    for (const s of result.servers) console.log(`${s.name}\t${s.client}\t${redact(s.url || [s.command, ...s.args].join(' '))}`);
    return 0;
  }

  if (command === 'lock') {
    const lock = buildLock({ servers: result.servers, inspections: result.inspections, baseDir: dir });
    const file = writeLock(dir, lock);
    const n = Object.keys(lock.servers).length;
    const withTools = Object.values(lock.servers).filter((e) => e.tools).length;
    console.log(c.green(`✓ Wrote ${path.relative(process.cwd(), file) || file}`) + ` — ${n} server(s) approved${withTools ? `, ${withTools} with tool fingerprints` : ''}.`);
    if (!opts.connect) console.log(c.gray('→ Tip: "mcpguard lock --connect" also fingerprints tool descriptions to catch rug pulls.'));
    const serious = result.findings.filter((f) => sevRank(f.severity) >= sevRank('high'));
    if (serious.length) console.log(c.yellow(`! ${serious.length} high/critical issue(s) exist in the servers you just approved. Run "mcpguard" to review them.`));
    console.log(c.gray('Commit the lockfile so CI and teammates are alerted when servers or tools change.'));
    return 0;
  }

  const format = opts.format || 'text';
  const render = { text: () => toText(result, { verbose: opts.verbose }), json: () => toJson(result), sarif: () => toSarif(result), markdown: () => toMarkdown(result), md: () => toMarkdown(result) }[format];
  if (!render) { console.error(c.red(`Unknown format: ${format}`)); return 2; }
  const output = render();
  if (opts.output) {
    fs.writeFileSync(opts.output, output + '\n');
    log(`Report written to ${opts.output}`);
    if (format !== 'text') console.log(toText(result, { verbose: opts.verbose }));
  } else {
    console.log(output);
  }

  const failOn = opts.failOn || 'high';
  if (failOn === 'none') return 0;
  if (sevRank(failOn) === -1) { console.error(c.red(`Invalid --fail-on value: ${failOn}`)); return 2; }
  return result.findings.some((f) => sevRank(f.severity) >= sevRank(failOn)) ? 1 : 0;
}

main().then((code) => { process.exitCode = code; }, (e) => { console.error(c.red(`mcpguard error: ${e.stack || e.message}`)); process.exitCode = 2; });
