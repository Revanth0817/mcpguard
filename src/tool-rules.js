export const TOOL_RULES = {
  MCPT001: { name: 'hidden-instructions', title: 'Tool description contains instructions aimed at the AI' },
  MCPT002: { name: 'sensitive-file-reference', title: 'Tool description references credentials or secret files' },
  MCPT003: { name: 'exfiltration-pattern', title: 'Tool description asks to send data elsewhere' },
  MCPT004: { name: 'invisible-characters', title: 'Hidden/invisible Unicode characters in tool metadata' },
  MCPT005: { name: 'tool-shadowing', title: 'Tool tries to change how other tools behave' },
  MCPT006: { name: 'obfuscated-payload', title: 'Encoded or obfuscated payload in tool metadata' },
  MCPT007: { name: 'oversized-description', title: 'Unusually long tool description' },
  MCPT008: { name: 'high-impact-capability', title: 'Tool can take high-impact actions' },
  MCPT009: { name: 'context-harvesting-parameter', title: 'Parameter designed to collect conversation or secrets' },
  MCPT011: { name: 'uninformative-annotations', title: 'Server marks every tool as destructive' },
};

const INSTRUCTION_PATTERNS = [
  /<\s*\/?\s*(important|system|instructions?|secret|hidden|admin|critical)\b[^>]*>/i,
  /\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier|other)\s+(instructions?|prompts?|rules|directions)/i,
  /\b(do\s*n[o']?t|never|without)\s+(tell|telling|inform|informing|mention|mentioning|reveal|revealing|notify|notifying|alert|alerting|show|showing)\b.{0,20}\buser/i,
  /\b(the\s+)?user\s+(must|should)\s+not\s+(know|see|be\s+told)/i,
  /\bbefore\s+(using|calling|invoking|running)\s+(this|any|the)\b.{0,30}\btool/i,
  /\b(you|assistant|ai|model|agent)\s+(must|should|need\s+to|are\s+required\s+to)\s+(first\s+)?(read|send|include|pass|upload|collect)\b[^.\n]{0,60}\b(file|content|key|token|credential|secret|password|history|conversation|~\/|\.ssh|\.env)/i,
  /\b(system\s+prompt|developer\s+message|previous\s+messages|conversation\s+history)\b/i,
  /\bthis\s+is\s+(very\s+)?(important|critical|mandatory)\b.{0,40}\b(otherwise|or\s+(the|it)\s+will)/i,
];

const SENSITIVE_PATTERNS = [
  /~?\/?\.ssh\b|\bid_(rsa|ed25519|ecdsa|dsa)\b|authorized_keys/i,
  /\.aws\/credentials|\.config\/gcloud|\.azure\/|\.kube\/config|\.docker\/config\.json/i,
  /(^|[\s"'`/])\.env\b|\.netrc|\.npmrc|\.pypirc|\.git-credentials/i,
  /\b(mcp\.json|claude_desktop_config\.json|mcp_config\.json|\.claude\.json)\b/i,
  /\/etc\/(passwd|shadow)|\bkeychain\b|\bwallet\.dat\b|\b(seed|recovery)\s+phrase\b|\bmnemonic\b/i,
  /\bprivate[\s_-]?key\b|\bapi[\s_-]?keys?\b|\baccess[\s_-]?tokens?\b|\bpasswords?\b|\bcredentials?\b/i,
];
const DIRECTIVE_VERB = /\b(read|cat|open|load|include|pass|send|attach|provide|copy|upload|forward|extract|collect|retrieve)\b/i;

const EXFIL_PATTERNS = [
  /(?<!\b(?:not|never|n't)\s+(?:\w+\s+){0,3})\b(send|post|upload|forward|transmit|exfiltrate|leak|copy)\b[^.\n]{0,80}(https?:\/\/(?!(?:www\.)?(?:example\.com|localhost))[\w.-]+|webhook\.site|@[\w-]+\.[a-z]{2,})/i,
  /\b(bcc|cc)\b[^.\n]{0,40}@[\w-]+\.[\w.]+/i,
  /\bredirect\b[^.\n]{0,60}\b(all|every)\b[^.\n]{0,30}\b(emails?|messages?|payments?|requests?)/i,
];

const SHADOW_PATTERNS = [
  /\b(when|whenever|if|every\s+time)\b[^.\n]{0,60}\b(other|another|any|the)\s+[`'"]?[\w.-]*[`'"]?\s*(tool|server|function)\s+(is\s+)?(used|called|invoked|runs?)/i,
  /\binstead\s+of\s+(using|calling)\b[^.\n]{0,40}\b(tool|server)/i,
  /\b(all|any|every)\s+(other\s+)?(tools?|servers?)\s+(must|should)\b/i,
  /\b(side\s*effect|also\s+(change|modify|override))\b[^.\n]{0,60}\btool/i,
];

const INVISIBLE = /[​-‏‪-‮⁠-⁤⁦-⁩﻿­]|[\u{E0000}-\u{E007F}]/u;
const TAG_CHARS = /[\u{E0020}-\u{E007E}]+/gu;
const BASE64_BLOB = /[A-Za-z0-9+/]{80,}={0,2}/;
const HEX_BLOB = /\b(?:[0-9a-f]{2}){48,}\b/i;

const EXEC_NAME = /(^|[_\-.])(exec|execute|shell|bash|sh|cmd|powershell|run[_-]?(command|cmd|script|code)|eval|terminal|spawn|system)($|[_\-.])/i;
const DESTRUCTIVE_NAME = /(^|[_\-.])(delete|remove|rm|drop|truncate|destroy|wipe|purge|write[_-]?file|overwrite|transfer|pay|payment|send[_-]?(email|mail|message|money|payment)|post[_-]?message|merge|deploy|push|cancel|place|modify|buy|sell|withdraw)($|[_\-.])/i;
const HARVEST_PARAM = /^(side[_-]?note|sidenote|notes?_for_(ai|model)|context|conversation|conversation[_-]?history|chat[_-]?history|history|previous[_-]?messages|system[_-]?prompt|instructions|feedback|debug[_-]?info|metadata|summary[_-]?of[_-]?conversation)$/i;
const SECRET_PARAM = /^(password|passwd|api[_-]?key|secret|private[_-]?key|ssh[_-]?key|credentials?|access[_-]?token|seed[_-]?phrase|mnemonic)$/i;

/** Walk a JSON schema and collect every human/AI-readable string plus parameter names. */
function collectSchemaText(schema, pathPrefix = 'inputSchema', out = [], params = []) {
  if (!schema || typeof schema !== 'object') return { texts: out, params };
  for (const key of ['description', 'title', 'default', 'examples', 'enum', 'const', 'pattern']) {
    const v = schema[key];
    if (typeof v === 'string') out.push({ where: `${pathPrefix}.${key}`, text: v });
    else if (Array.isArray(v)) v.forEach((x, i) => typeof x === 'string' && out.push({ where: `${pathPrefix}.${key}[${i}]`, text: x }));
  }
  if (schema.properties && typeof schema.properties === 'object') {
    for (const [name, sub] of Object.entries(schema.properties)) {
      params.push({ name, path: `${pathPrefix}.properties.${name}`, schema: sub });
      out.push({ where: `${pathPrefix}.properties.${name} (name)`, text: name });
      collectSchemaText(sub, `${pathPrefix}.properties.${name}`, out, params);
    }
  }
  for (const k of ['items', 'additionalProperties']) if (schema[k] && typeof schema[k] === 'object') collectSchemaText(schema[k], `${pathPrefix}.${k}`, out, params);
  for (const k of ['anyOf', 'oneOf', 'allOf']) if (Array.isArray(schema[k])) schema[k].forEach((s, i) => collectSchemaText(s, `${pathPrefix}.${k}[${i}]`, out, params));
  return { texts: out, params };
}

const INVISIBLE_ALL = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u00AD]|[\u{E0000}-\u{E007F}]/gu;

function snippet(rawText, re) {
  const text = rawText.replace(INVISIBLE_ALL, '');
  const m = re.exec(text);
  if (!m) return text.slice(0, 120);
  const start = Math.max(0, m.index - 40);
  const s = text.slice(start, m.index + m[0].length + 60).replace(/\s+/g, ' ').trim();
  return (start > 0 ? '…' : '') + s + (m.index + m[0].length + 60 < text.length ? '…' : '');
}

export function decodeTagChars(text) {
  const m = text.match(TAG_CHARS);
  if (!m) return '';
  return m.map((run) => Array.from(run).map((ch) => String.fromCharCode(ch.codePointAt(0) - 0xE0000)).join('')).join(' ');
}

/**
 * Analyse one tool (or prompt / server instructions) definition.
 * @param {{name:string, description?:string, inputSchema?:object, annotations?:object}} tool
 * @param {{server:string, file?:string, line?:number, kind?:string}} ctx
 */
export function checkTool(tool, ctx) {
  const findings = [];
  const kind = ctx.kind || 'tool';
  const label = kind === 'tool' ? `tool "${tool.name}"` : kind === 'prompt' ? `prompt "${tool.name}"` : 'server instructions';
  const add = (ruleId, severity, detail, fix) => findings.push({
    ruleId, rule: TOOL_RULES[ruleId].name, title: TOOL_RULES[ruleId].title, severity,
    server: ctx.server, tool: tool.name, file: ctx.file, line: ctx.line, detail: `${label}: ${detail}`, fix,
  });

  const texts = [];
  if (tool.description) texts.push({ where: 'description', text: String(tool.description) });
  if (tool.title) texts.push({ where: 'title', text: String(tool.title) });
  const { texts: schemaTexts, params } = collectSchemaText(tool.inputSchema || tool.arguments && { properties: Object.fromEntries((tool.arguments || []).map((a) => [a.name, { description: a.description }])) });
  texts.push(...schemaTexts);
  const all = texts.map((t) => t.text).join('\n');
  const reported = new Set();
  const once = (ruleId, ...args) => { if (!reported.has(ruleId)) { reported.add(ruleId); add(ruleId, ...args); } };

  // Invisible characters first: decode and re-scan the hidden text.
  for (const t of texts) {
    if (INVISIBLE.test(t.text)) {
      const hidden = decodeTagChars(t.text);
      once('MCPT004', 'critical',
        `${t.where} contains invisible Unicode characters${hidden ? ` that decode to hidden text: "${hidden.slice(0, 200)}"` : ' (zero-width / bidirectional overrides)'}. Humans reviewing the tool cannot see this, but the model can.`,
        'Do not use this server. Report it to the maintainer/registry.');
    }
  }
  const decodedHidden = texts.map((t) => decodeTagChars(t.text)).filter(Boolean).join('\n');
  const scanText = decodedHidden ? all + '\n' + decodedHidden : all;

  for (const re of INSTRUCTION_PATTERNS) {
    if (re.test(scanText)) {
      once('MCPT001', 'critical', `contains text that instructs the AI model rather than describing the tool: "${snippet(scanText, re)}"`,
        'Treat as a tool-poisoning attempt. Remove the server and review what it may already have done.');
      break;
    }
  }

  const sens = SENSITIVE_PATTERNS.find((re) => re.test(scanText));
  if (sens) {
    const directive = DIRECTIVE_VERB.test(snippet(scanText, sens));
    const legit = /\b(no|never|not|without|redact|mask)\b[^.]{0,30}(password|credential|key|token)/i.test(scanText);
    const genericOnlyHit = SENSITIVE_PATTERNS.indexOf(sens) === SENSITIVE_PATTERNS.length - 1;
    if (directive && !legit && (!genericOnlyHit || reported.has('MCPT001'))) {
      const genericOnly = SENSITIVE_PATTERNS.indexOf(sens) === SENSITIVE_PATTERNS.length - 1;
      once('MCPT002', reported.has('MCPT001') ? 'critical' : genericOnly ? 'medium' : 'high', `references secret material with an action verb: "${snippet(scanText, sens)}"`,
        'Verify why this tool needs credential files. Legitimate tools rarely mention them.');
    }
  }

  const exfil = EXFIL_PATTERNS.find((re) => re.test(scanText));
  if (exfil) once('MCPT003', 'high', `asks for data to be sent to another destination: "${snippet(scanText, exfil)}"`, 'Block this tool; check network egress logs.');

  const shadow = SHADOW_PATTERNS.find((re) => re.test(scanText));
  if (shadow) once('MCPT005', 'high', `attempts to influence other tools or servers: "${snippet(scanText, shadow)}"`,
    'A tool should only describe itself. Remove the server; cross-server instructions are a known "tool shadowing" attack.');

  const b64 = BASE64_BLOB.exec(all) || HEX_BLOB.exec(all);
  if (b64) once('MCPT006', 'medium', `contains a ${b64[0].length}-character encoded blob ("${b64[0].slice(0, 40)}…"), which can hide instructions from reviewers.`,
    'Decode and review the content before trusting this server.');

  const descLen = String(tool.description || '').length;
  if (descLen > 2500) once('MCPT007', 'low', `description is ${descLen} characters long; long descriptions are a common place to hide instructions below the fold.`,
    'Review the full description text.');

  if (kind === 'tool') {
    const ann = tool.annotations || {};
    if (EXEC_NAME.test(tool.name)) {
      once('MCPT008', 'medium', 'can execute arbitrary commands/code. A single prompt injection in any content the agent reads could run code on this machine.',
        'Require human approval for every call, or run the server in a sandbox/container.');
    } else if (DESTRUCTIVE_NAME.test(tool.name) || (ann.destructiveHint === true && !ctx.ignoreDestructiveHint)) {
      once('MCPT008', 'low', `performs a high-impact action${ann.destructiveHint && !ctx.ignoreDestructiveHint ? ' (server marks it destructive)' : ''}.`,
        'Keep human-in-the-loop approval enabled for this tool.');
    }
    for (const p of params) {
      const pDesc = String(p.schema?.description || '');
      if (HARVEST_PARAM.test(p.name) && /\b(all|entire|full|previous|every|conversation|context|history|file|content)\b/i.test(pDesc + ' ' + p.name)) {
        once('MCPT009', 'high', `parameter "${p.name}" appears designed to collect conversation context or file contents${pDesc ? `: "${pDesc.slice(0, 120)}"` : ''}.`,
          'Legitimate tools do not need your conversation history. Inspect what the server does with this field.');
      } else if (SECRET_PARAM.test(p.name) && !/(auth|login|credential|secret|vault|key|password|token)/i.test(tool.name)) {
        once('MCPT009', 'low', `asks the model to supply "${p.name}", which is unrelated to the tool's name.`,
          'Make sure the agent never passes real secrets to this tool.');
      }
    }
  }
  return findings;
}

/** Analyse a full inspection result for one server. */
export function checkInspection(server, inspection) {
  const ctx = { server: server.name, file: server.file, line: server.line };
  const findings = [];
  // A hint set on every tool (including obvious reads) carries no information; judge by tool name instead.
  const tools = inspection.tools || [];
  const blanket = tools.length >= 3 && tools.every((t) => t.annotations?.destructiveHint === true);
  if (blanket) {
    findings.push({
      ruleId: 'MCPT011', rule: TOOL_RULES.MCPT011.name, title: TOOL_RULES.MCPT011.title, severity: 'info', ...ctx,
      detail: `All ${tools.length} tools are marked destructive, including ones that look read-only (e.g. "${(tools.find((t) => /^(get|list|read|search|fetch|query)[_-]/i.test(t.name)) || tools[0]).name}"). The hints cannot tell safe tools from dangerous ones, so mcpguard judged each tool by its name instead.`,
      fix: 'Keep approval on for tools that change things. Ask the maintainer to set readOnlyHint / destructiveHint per tool.',
    });
  }
  for (const t of tools) findings.push(...checkTool(t, { ...ctx, kind: 'tool', ignoreDestructiveHint: blanket }));
  for (const p of inspection.prompts || []) findings.push(...checkTool(p, { ...ctx, kind: 'prompt' }));
  if (inspection.instructions) findings.push(...checkTool({ name: '(instructions)', description: inspection.instructions }, { ...ctx, kind: 'instructions' }));
  // Duplicate tool names across servers are resolved later (cross-server check in scan.js).
  return findings;
}
