// Family email alerts through Amazon SNS, plus the hub heartbeat metric that drives the CloudWatch dead-man alarm
// (cloud/aws/notify/notify-template.json). It shells out to the installed AWS CLI with a dedicated profile, so this code
// never sees an access key. Disabled unless a topic ARN and profile are configured; the page banner works either way.
//
// Failure is never reported as success: every failed send prints a greppable `ERROR sns ...` line and is kept in status().
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';

const TOPIC_ARN = /^arn:aws:sns:[a-z0-9-]{4,30}:\d{12}:[A-Za-z0-9_-]{1,256}$/u;
const PROFILE = /^[A-Za-z0-9_.-]{1,64}$/u;
const REGION = /^[a-z]{2}-[a-z]+-\d$/u;
const MAX_PER_HOUR = 10;
const RETRY_DELAYS_MS = [1000, 2000, 4000];
const AWS_CANDIDATES = ['/opt/homebrew/bin/aws', '/usr/local/bin/aws', '/usr/bin/aws'];

// Fixed-alphabet text: no control characters, no newlines in the subject, bounded length.
export function cleanText(value, max) {
  return (typeof value === 'string' ? value : '').replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f‪-‮⁦-⁩]/gu, '').slice(0, max);
}

export function resolveAwsCli(explicit, exists = existsSync) {
  if (explicit) return explicit.startsWith('/') && exists(explicit) ? explicit : null;
  return AWS_CANDIDATES.find((path) => exists(path)) ?? null;
}

export function createSnsNotifier({ topicArn, profile, region, awsBin, hubName = 'home', execFileImpl = execFile, clock = Date.now,
  sleep = (ms) => new Promise((r) => { const t = setTimeout(r, ms); t.unref?.(); }), log = () => {} } = {}) {
  const configured = Boolean(topicArn || profile);
  // Absolute CLI path only: cron/launchd PATH is /usr/bin:/bin and cannot find Homebrew tools.
  const valid = TOPIC_ARN.test(topicArn ?? '') && PROFILE.test(profile ?? '') && REGION.test(region ?? '') && typeof awsBin === 'string' && awsBin.startsWith('/');
  let lastError = configured && !valid ? 'NOTIFY_CONFIG_INVALID' : null;
  let sent = 0, suppressed = 0;
  const window = [];
  if (configured && !valid) log('ERROR sns notifications disabled: topic ARN, profile, region or AWS CLI path is invalid');

  function run(args) {
    return new Promise((resolve) => {
      try {
        execFileImpl(awsBin, [...args, '--region', region, '--profile', profile, '--output', 'json'],
          { timeout: 10_000, maxBuffer: 65536, shell: false, env: { HOME: process.env.HOME ?? '', PATH: '/usr/bin:/bin', AWS_PAGER: '' } },
          (error, stdout) => resolve(error ? { ok: false, code: error.code === 'ETIMEDOUT' || error.killed ? 'TIMEOUT' : 'CLI_FAILED' } : { ok: true, stdout }));
      } catch { resolve({ ok: false, code: 'CLI_FAILED' }); }   // a synchronous throw is a failure too, never silent
    });
  }
  async function withRetry(label, args) {
    for (let attempt = 0; ; attempt += 1) {
      const r = await run(args);
      if (r.ok) return r;
      if (attempt >= RETRY_DELAYS_MS.length) {
        lastError = label.toUpperCase() + '_' + r.code;
        log(`ERROR sns ${label} failed after ${attempt + 1} attempts code=${r.code}`);
        return r;
      }
      await sleep(RETRY_DELAYS_MS[attempt]);
    }
  }

  // One email per state change. Over 10 per rolling hour, later alerts are counted and folded into the next email.
  async function publish({ subject, message }) {
    if (!valid) return { sent: false, reason: configured ? 'NOTIFY_CONFIG_INVALID' : 'NOTIFY_DISABLED' };
    const now = clock();
    while (window.length && now - window[0] >= 3_600_000) window.shift();
    if (window.length >= MAX_PER_HOUR) { suppressed += 1; return { sent: false, reason: 'RATE_LIMITED' }; }
    window.push(now);
    let body = cleanText(message, 1500);
    if (suppressed) { body += `\n(+${suppressed} more alert${suppressed === 1 ? '' : 's'} were held back by the hourly limit; see the console timeline.)`; suppressed = 0; }
    // --opt=value: alert text that starts with "-" can never be read by the CLI as an option.
    const r = await withRetry('publish', ['sns', 'publish', `--topic-arn=${topicArn}`,
      `--subject=${cleanText(subject, 90).replace(/\n/gu, ' ') || 'Home MCP alert'}`, `--message=${body || '(empty)'}`]);
    if (!r.ok) return { sent: false, reason: lastError };
    sent += 1; lastError = null;
    return { sent: true };
  }
  async function heartbeat() {
    if (!valid) return { sent: false, reason: configured ? 'NOTIFY_CONFIG_INVALID' : 'NOTIFY_DISABLED' };
    const r = await withRetry('heartbeat', ['cloudwatch', 'put-metric-data', '--namespace', 'HomeMcp', '--metric-name', 'HubHeartbeat',
      '--dimensions', `Hub=${hubName}`, '--value', '1', '--unit', 'Count']);
    return r.ok ? { sent: true } : { sent: false, reason: lastError };
  }
  const status = () => ({ email: !configured ? 'disabled' : !valid ? 'misconfigured' : lastError ? 'error' : 'enabled',
    lastError, sent, heldBack: suppressed });
  return Object.freeze({ enabled: valid, publish, heartbeat, status });
}
