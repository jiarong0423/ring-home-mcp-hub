// SNS notifier with a fake AWS CLI: nothing leaves the machine.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createSnsNotifier, cleanText, resolveAwsCli } from '../src/notify_sns.mjs';

const ARN = 'arn:aws:sns:ap-southeast-1:123456789012:home-mcp-alerts';
function setup({ fail = 0, configured = true, now = 0 } = {}) {
  const calls = []; const logs = []; let failures = fail; let t = now;
  const execFileImpl = (bin, args, opts, cb) => { calls.push({ bin, args, opts }); if (failures > 0) { failures -= 1; cb(Object.assign(new Error('x'), { code: 1 })); } else cb(null, '{}'); };
  const n = createSnsNotifier(configured ? { topicArn: ARN, profile: 'home-mcp-notify', region: 'ap-southeast-1', awsBin: '/opt/homebrew/bin/aws',
    execFileImpl, clock: () => t, sleep: async () => {}, log: (l) => logs.push(l) } : { execFileImpl, log: (l) => logs.push(l) });
  return { n, calls, logs, tick: (ms) => { t += ms; } };
}

test('publish: AWS CLI with the dedicated profile and region, fixed argument list, no shell, minimal env', async () => {
  const s = setup();
  assert.deepEqual(await s.n.publish({ subject: '[Home MCP] Camera offline', message: '15:42 camera offline' }), { sent: true });
  const c = s.calls[0];
  assert.equal(c.bin, '/opt/homebrew/bin/aws');
  assert.deepEqual(c.args, ['sns', 'publish', '--topic-arn=' + ARN, '--subject=[Home MCP] Camera offline', '--message=15:42 camera offline',
    '--region', 'ap-southeast-1', '--profile', 'home-mcp-notify', '--output', 'json']);
  assert.equal(c.opts.shell, false); assert.deepEqual(Object.keys(c.opts.env).sort(), ['AWS_PAGER', 'HOME', 'PATH']);
  assert.equal(s.n.status().email, 'enabled');
});

test('heartbeat writes HomeMcp/HubHeartbeat with the hub dimension', async () => {
  const s = setup();
  assert.deepEqual(await s.n.heartbeat(), { sent: true });
  assert.deepEqual(s.calls[0].args.slice(0, 12), ['cloudwatch', 'put-metric-data', '--namespace', 'HomeMcp', '--metric-name', 'HubHeartbeat',
    '--dimensions', 'Hub=home', '--value', '1', '--unit', 'Count']);
});

test('failure: retries 3 times, then ERROR line, never success; status shows the error', async () => {
  const s = setup({ fail: 9 });
  const r = await s.n.publish({ subject: 'x', message: 'y' });
  assert.equal(r.sent, false); assert.equal(s.calls.length, 4);
  assert.deepEqual(s.logs, ['ERROR sns publish failed after 4 attempts code=CLI_FAILED']);
  assert.equal(s.n.status().email, 'error'); assert.equal(s.n.status().sent, 0);
  const ok = setup({ fail: 2 });
  assert.deepEqual(await ok.n.publish({ subject: 'x', message: 'y' }), { sent: true }); assert.equal(ok.calls.length, 3);
});

test('rate limit: 10 per rolling hour; held-back alerts are mentioned in the next email', async () => {
  const s = setup();
  for (let i = 0; i < 10; i += 1) assert.equal((await s.n.publish({ subject: 's', message: 'm' + i })).sent, true);
  assert.deepEqual(await s.n.publish({ subject: 's', message: 'm10' }), { sent: false, reason: 'RATE_LIMITED' });
  assert.equal(s.n.status().heldBack, 1);
  s.tick(3_600_000);
  await s.n.publish({ subject: 's', message: 'later' });
  assert.match(s.calls.at(-1).args[4], /^--message=later\n\(\+1 more alert were held back/u);
});

test('disabled when not configured; misconfigured is an ERROR, not silence; text is cleaned', async () => {
  const off = setup({ configured: false });
  assert.deepEqual(await off.n.publish({ subject: 's', message: 'm' }), { sent: false, reason: 'NOTIFY_DISABLED' });
  assert.equal(off.n.status().email, 'disabled'); assert.equal(off.calls.length, 0);
  const logs = [];
  const bad = createSnsNotifier({ topicArn: 'arn:aws:sns:x', profile: 'p', region: 'ap-southeast-1', awsBin: '/x', log: (l) => logs.push(l) });
  assert.equal(bad.status().email, 'misconfigured'); assert.match(logs[0], /^ERROR sns notifications disabled/u);
  assert.equal(cleanText('Cam\u0007era\u001b[2J‮X', 50), 'Camera[2JX');
  const s = setup();
  await s.n.publish({ subject: 'line1\nline2', message: 'ok' });
  assert.equal(s.calls[0].args[3], '--subject=line1 line2');
  const dash = setup();
  await dash.n.publish({ subject: '--debug', message: '--no-verify-ssl' });
  assert.deepEqual(dash.calls[0].args.slice(3, 5), ['--subject=--debug', '--message=--no-verify-ssl'], 'dash-leading text stays inside one --opt=value');
  const weird = setup();
  assert.equal((await weird.n.publish({ subject: { a: 1 }, message: 42 })).sent, true);
  assert.deepEqual(weird.calls[0].args.slice(3, 5), ['--subject=Home MCP alert', '--message=(empty)']);
  const thrownLogs = [];
  const thrower = createSnsNotifier({ topicArn: ARN, profile: 'p', region: 'ap-southeast-1', awsBin: '/opt/homebrew/bin/aws', sleep: async () => {},
    execFileImpl: () => { throw new Error('sync'); }, log: (l) => thrownLogs.push(l) });
  assert.equal((await thrower.publish({ subject: 's', message: 'm' })).sent, false);
  assert.match(thrownLogs[0], /^ERROR sns publish failed/u); assert.equal(thrower.status().email, 'error');
  assert.equal(createSnsNotifier({ topicArn: ARN, profile: 'p', region: 'ap-southeast-1', awsBin: 'aws' }).status().email, 'misconfigured');
  assert.equal(resolveAwsCli('relative/aws', () => true), null);
  assert.equal(resolveAwsCli(undefined, (p) => p === '/usr/local/bin/aws'), '/usr/local/bin/aws');
});
