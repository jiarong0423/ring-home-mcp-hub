#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { DEFAULT_CONFIG, resolveConfig } from './src/config.mjs';
import { defaultStateDir } from './src/state.mjs';
import { readPassphrase, readSecretLine } from './src/passphrase.mjs';
import { keygen, loginUrl, run, status, bootstrap, enroll, ringDemo, accountIdSha256, demoSwitch } from './src/launcher.mjs';

const USAGE = `usage: mac-worker.mjs <keygen|login-url|bootstrap|enroll|run|demo-switch|ring-demo|status> [options]
  keygen    --owner-ref <ref> --association-revision <n>     (passphrase: hidden prompt on a terminal, or env RING_MAC_KEY_PASSPHRASE / piped stdin)
  login-url                                                  (prints Cognito authorize URL; PKCE verifier stays in a 0600 file)
  run       --callback-url <url> [--polls n] [--interval-ms n]   (passphrase as for keygen; env RING_MAC_CALLBACK_URL also accepted)
  demo-switch --callback-url <url> --enabled <true|false> [--polls n] [--interval-ms n]   (one login: MCP set -> worker -> MCP result; passphrase as for run)
  bootstrap --callback-url <url> | enroll --callback-url <url> | ring-demo | local-sha account-id-sha256
  status
state dir: $RING_MAC_STATE_DIR or ~/.ring-mac-worker (0700)`;
function fail(code, exit = 1) { process.stderr.write('ERROR ' + code + '\n'); process.exitCode = exit; }
async function main(argv) {
  const [cmd, ...rest] = argv;
  if (!['keygen', 'login-url', 'run', 'status', 'bootstrap', 'enroll', 'ring-demo', 'local-sha', 'demo-switch'].includes(cmd)) { process.stderr.write(USAGE + '\n'); process.exitCode = 2; return; }
  let o;
  try { o = parseArgs({ args: rest, strict: true, allowPositionals: true, options: { 'owner-ref': { type: 'string' }, 'association-revision': { type: 'string' },
    'callback-url': { type: 'string' }, polls: { type: 'string' }, 'interval-ms': { type: 'string' }, enabled: { type: 'string' } } }).values; }
  catch { return fail('USAGE', 2); }
  const cfg = resolveConfig(DEFAULT_CONFIG); const stateDir = defaultStateDir();
  const out = v => process.stdout.write(JSON.stringify(v, null, 2) + '\n');
  if (cmd === 'login-url') {
    const r = await loginUrl({ stateDir, cfg });
    process.stdout.write(r.url + '\n');
    process.stderr.write('Open in a browser, log in, then copy the FINAL address-bar URL (it will show an error page from the API: expected) and run:\n  mac-worker.mjs run --callback-url "<url>"\nValid until ' + new Date(r.expiresAt).toISOString() + '. Enqueue the command (software_test_switch.set) only just before running: command TTL is 30 s.\n');
    return;
  }
  const cbUrl = o['callback-url'] ?? process.env.RING_MAC_CALLBACK_URL;
  if (cmd === 'local-sha') {
    if (rest[0] !== 'account-id-sha256') return fail('USAGE', 2);
    const chunks = []; for await (const c of process.stdin) chunks.push(c);
    return void process.stdout.write(accountIdSha256(Buffer.concat(chunks).toString('utf8')) + '\n');
  }
  if (cmd === 'ring-demo') { const r = await ringDemo({ cfg, ringToken: await readSecretLine('RING_PLAYGROUND_TOKEN') }); out(r); if (!r.ok) fail('RING_DEMO_HTTP_NOT_OK'); return; }
  if (cmd === 'bootstrap' || cmd === 'enroll') {
    if (!cbUrl) return fail('USAGE', 2);
    const common = { stateDir, cfg, callbackUrl: cbUrl };
    const r = cmd === 'bootstrap' ? await bootstrap({ ...common, ringToken: await readSecretLine('RING_PLAYGROUND_TOKEN') }) : await enroll(common);
    out(r); if (!r.ok) fail(r.operation.toUpperCase() + '_HTTP_' + r.httpStatus); return;
  }
  if (cmd === 'status') return out(await status({ stateDir, cfg }));
  if (cmd === 'demo-switch' && (!cbUrl || !['true', 'false'].includes(o.enabled))) return fail('USAGE', 2);
  const passphrase = await readPassphrase({ confirm: cmd === 'keygen' });
  try {
    if (cmd === 'keygen') {
      const rev = Number(o['association-revision']);
      if (!o['owner-ref'] || !/^[0-9]+$/u.test(o['association-revision'] ?? '')) return fail('USAGE', 2);
      const r = await keygen({ stateDir, cfg, passphrase, ownerRef: o['owner-ref'], associationRevision: rev });
      out(r);
      process.stderr.write('Next: add "expiresAt" (epoch ms, now < expiresAt <= now+86400000 when POST /mac/enroll runs) to approvalSkeleton, save it as mac-enrollment-approval-v1.json in the Lambda layer, and set MacEnrollmentApprovalSha256 to its sha256 (see README, section C).\n');
    } else if (cmd === 'demo-switch') {
      const r = await demoSwitch({ stateDir, cfg, passphrase, callbackUrl: cbUrl, enabled: o.enabled === 'true',
        polls: o.polls ? Number(o.polls) : 5, intervalMs: o['interval-ms'] ? Number(o['interval-ms']) : 1000 });
      out(r); if (!r.ok) fail('DEMO_NOT_EXECUTED');
    } else {
      const callbackUrl = o['callback-url'] ?? process.env.RING_MAC_CALLBACK_URL;
      if (!callbackUrl) return fail('USAGE', 2);
      const r = await run({ stateDir, cfg, passphrase, callbackUrl, polls: o.polls ? Number(o.polls) : 1,
        intervalMs: o['interval-ms'] ? Number(o['interval-ms']) : 1000 });
      out(r);
    }
  } finally { passphrase.fill(0); }
}
main(process.argv.slice(2)).catch(e => fail(typeof e?.code === 'string' ? e.code : 'INTERNAL'));
