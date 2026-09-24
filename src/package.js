import path from 'node:path';

/**
 * Work out what a stdio server actually launches: npm package, PyPI package,
 * docker image, git source, local script or plain binary.
 */
export function resolveLaunch(server) {
  if (server.transport !== 'stdio' || !server.command) return { kind: 'remote', url: server.url };
  let cmd = path.basename(String(server.command)).toLowerCase().replace(/\.(exe|cmd|bat)$/, '');
  let args = [...server.args];

  // Windows wrapper: cmd /c npx ...
  if (cmd === 'cmd' && /^\/c$/i.test(args[0] || '')) {
    cmd = path.basename(args[1] || '').toLowerCase().replace(/\.(exe|cmd|bat)$/, '');
    args = args.slice(2);
  }

  if (cmd === 'npx' || cmd === 'bunx' || (cmd === 'pnpm' && args[0] === 'dlx') || (cmd === 'yarn' && args[0] === 'dlx')) {
    if (cmd === 'pnpm' || cmd === 'yarn') args = args.slice(1);
    let spec;
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '-p' || a === '--package') { spec = args[i + 1]; break; }
      if (a.startsWith('--package=')) { spec = a.slice(10); break; }
      if (a.startsWith('-')) continue;
      spec = a; break;
    }
    return { kind: 'npm', runner: cmd, ...parseNpmSpec(spec) };
  }

  if (cmd === 'uvx' || (cmd === 'uv' && args[0] === 'tool' && args[1] === 'run') || (cmd === 'pipx' && args[0] === 'run')) {
    if (cmd === 'uv') args = args.slice(2);
    if (cmd === 'pipx') args = args.slice(1);
    let spec;
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '--from' || a === '--spec') { spec = args[i + 1]; break; }
      if (a.startsWith('--from=')) { spec = a.slice(7); break; }
      if (a === '--python' || a === '--with' || a === '--index-url') { i++; continue; }
      if (a.startsWith('-')) continue;
      spec = a; break;
    }
    return { kind: 'pypi', runner: cmd, ...parsePySpec(spec) };
  }

  if ((cmd === 'docker' || cmd === 'podman') && args.includes('run')) {
    const valueFlags = new Set(['-e', '--env', '-v', '--volume', '--name', '--network', '--net', '-p', '--publish', '--mount',
      '-w', '--workdir', '-u', '--user', '--env-file', '--entrypoint', '--platform', '-l', '--label', '--cap-add', '--cap-drop', '--add-host', '--pull', '-m', '--memory', '--cpus']);
    const start = args.indexOf('run') + 1;
    let image;
    for (let i = start; i < args.length; i++) {
      const a = args[i];
      if (valueFlags.has(a)) { i++; continue; }
      if (a.startsWith('-')) continue;
      image = a; break;
    }
    return { kind: 'docker', runner: cmd, ...parseImage(image) };
  }

  if (['node', 'python', 'python3', 'deno', 'bun', 'ruby', 'java'].includes(cmd)) {
    const script = args.find((a) => !a.startsWith('-'));
    return { kind: 'local-script', runner: cmd, script };
  }
  return { kind: 'binary', runner: cmd };
}

export function parseNpmSpec(spec) {
  if (!spec) return { name: undefined, version: undefined, pinned: false };
  if (/^(github:|git\+|git:|https?:\/\/|[\w.-]+\/[\w.-]+#)/.test(spec) || /^[\w-]+\/[\w.-]+$/.test(spec) && !spec.startsWith('@')) {
    return { name: spec, version: undefined, pinned: /#[0-9a-f]{40}$/.test(spec), source: 'git' };
  }
  if (spec.startsWith('.') || spec.startsWith('/')) return { name: spec, version: undefined, pinned: true, source: 'local' };
  let name = spec;
  let version;
  const at = spec.lastIndexOf('@');
  if (at > 0) { name = spec.slice(0, at); version = spec.slice(at + 1); }
  const pinned = !!version && /^\d+\.\d+\.\d+([-.+][\w.]+)?$/.test(version);
  return { name, version, pinned, source: 'registry' };
}

export function parsePySpec(spec) {
  if (!spec) return { name: undefined, version: undefined, pinned: false };
  if (/^(git\+|https?:\/\/)/.test(spec)) return { name: spec, version: undefined, pinned: /@[0-9a-f]{40}$/.test(spec), source: 'git' };
  const m = spec.match(/^([A-Za-z0-9_.\-\[\]]+?)\s*(==|@|>=|~=|<=|>|<)\s*(.+)$/);
  if (m) return { name: m[1].replace(/\[.*\]$/, ''), version: m[3], pinned: m[2] === '==' || m[2] === '@', source: 'registry' };
  return { name: spec.replace(/\[.*\]$/, ''), version: undefined, pinned: false, source: 'registry' };
}

export function parseImage(image) {
  if (!image) return { name: undefined, version: undefined, pinned: false };
  if (image.includes('@sha256:')) {
    const [name, digest] = image.split('@');
    return { name, version: digest, pinned: true, source: 'registry' };
  }
  const lastSlash = image.lastIndexOf('/');
  const colon = image.indexOf(':', lastSlash + 1);
  const name = colon === -1 ? image : image.slice(0, colon);
  const tag = colon === -1 ? undefined : image.slice(colon + 1);
  return { name, version: tag, pinned: !!tag && tag !== 'latest', source: 'registry', digestPinned: false };
}
