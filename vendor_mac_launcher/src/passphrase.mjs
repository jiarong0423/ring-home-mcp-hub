import { coded } from './config.mjs';
// Passphrase from env RING_MAC_KEY_PASSPHRASE, piped stdin, or (on a TTY) a hidden no-echo prompt. Never argv. Returns a Buffer the caller must zero.
export async function readPassphrase({ env = process.env, stdin = process.stdin, stderr = process.stderr, confirm = false } = {}) {
  if (env.RING_MAC_KEY_PASSPHRASE) { const b = Buffer.from(env.RING_MAC_KEY_PASSPHRASE, 'utf8'); delete env.RING_MAC_KEY_PASSPHRASE; return b; }
  if (stdin.isTTY) {
    const first = await hiddenPrompt('Mac key passphrase (hidden, min 10 chars): ', { stdin, stderr });
    if (confirm) { const second = await hiddenPrompt('Type it again to confirm (hidden): ', { stdin, stderr });
      if (!first.equals(second)) { first.fill(0); second.fill(0); throw coded('PASSPHRASE_MISMATCH'); } second.fill(0); }
    if (first.length === 0) throw coded('PASSPHRASE_REQUIRED_ENV_OR_PIPED_STDIN');
    return first;
  }
  const chunks = []; let size = 0;
  for await (const c of stdin) { size += c.length; if (size > 2048) throw coded('PASSPHRASE_TOO_LONG'); chunks.push(c); }
  let b = Buffer.concat(chunks);
  if (b.at(-1) === 0x0a) b = b.subarray(0, b.length - (b.at(-2) === 0x0d ? 2 : 1));
  if (b.length === 0) throw coded('PASSPHRASE_REQUIRED_ENV_OR_PIPED_STDIN');
  return Buffer.from(b);
}


// No-echo prompt on a TTY. Returns a Buffer (caller zeroes). Backspace supported, Ctrl-C aborts.
export function hiddenPrompt(label, { stdin = process.stdin, stderr = process.stderr } = {}) {
  return new Promise((resolve, reject) => {
    stderr.write(label); let buf = []; stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
    const done = () => { stdin.setRawMode(false); stdin.pause(); stdin.off('data', on); stderr.write('\n'); };
    const on = chunk => { for (const c of chunk) {
      if (c === '\n' || c === '\r' || c === '\u0004') { done(); return resolve(Buffer.from(buf.join(''), 'utf8')); }
      if (c === '\u0003') { done(); return reject(coded('PASSPHRASE_ABORTED')); }
      if (c === '\u007f' || c === '\b') buf.pop(); else buf.push(c); } };
    stdin.on('data', on);
  });
}

// Secret line (e.g. Ring Playground token): env var name, else stdin (TTY: no-echo prompt). Never argv.
export async function readSecretLine(envName, { env = process.env, stdin = process.stdin, stderr = process.stderr } = {}) {
  if (env[envName]) { const v = env[envName]; delete env[envName]; return v.trim(); }
  let v;
  if (stdin.isTTY) {
    stderr.write('Token (input hidden): ');
    v = await new Promise(resolve => { let buf = ''; stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
      const on = ch => { for (const c of ch) { if (c === '\n' || c === '\r' || c === '\u0004') { stdin.setRawMode(false); stdin.pause(); stdin.off('data', on); stderr.write('\n'); return resolve(buf); } if (c === '\u0003') process.exit(130); buf += c; } };
      stdin.on('data', on); });
  } else {
    const chunks = []; let size = 0;
    for await (const c of stdin) { size += c.length; if (size > 16384) throw coded('SECRET_TOO_LONG'); chunks.push(c); }
    v = Buffer.concat(chunks).toString('utf8');
  }
  v = v.trim();
  if (v.length < 8 || /[\s\x00-\x1f\x7f]/u.test(v)) throw coded('SECRET_REQUIRED_ENV_OR_STDIN');
  return v;
}
