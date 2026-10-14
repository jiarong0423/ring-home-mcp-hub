import { createHmac } from 'node:crypto';
import { execFile } from 'node:child_process';

const EXECUTABLE = '/usr/sbin/networksetup';
const ARGV = Object.freeze(['-getairportnetwork', 'en0']);
const PREFIX = Buffer.from('Current Wi-Fi Network: ', 'utf8');
const MINIMAL_ENV = Object.freeze({ PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' });

export class MacosWifiObserverError extends Error {
  constructor(code) {
    super(code);
    this.name = 'MacosWifiObserverError';
    this.code = code;
  }
}

function deny(code) {
  throw new MacosWifiObserverError(code);
}

function defaultRunner(file, args, options) {
  return new Promise((resolve, reject) => {
    execFile(file, args, options, (error, stdout, stderr) => {
      if (error) reject(error);
      else resolve({ stdout, stderr });
    });
  });
}

function ownedBuffer(value, code) {
  if (!Buffer.isBuffer(value) || value.length === 0) deny(code);
  return value;
}

export async function observeKeyedFingerprint({ runner, key }) {
  if (typeof runner !== 'function') deny('B02_WIFI_OBSERVER_RUNNER_DENIED');
  const sourceKey = ownedBuffer(key, 'B02_WIFI_OBSERVER_KEY_DENIED');
  const keyCopy = Buffer.from(sourceKey);
  let stdout = null;
  let stderr = null;
  try {
    const result = await runner(EXECUTABLE, [...ARGV], {
      shell: false,
      timeout: 2_000,
      maxBuffer: 4_096,
      encoding: 'buffer',
      env: { ...MINIMAL_ENV }
    });
    if (result === null || typeof result !== 'object') deny('B02_WIFI_OBSERVER_RESULT_DENIED');
    stdout = ownedBuffer(result.stdout, 'B02_WIFI_OBSERVER_RESULT_DENIED');
    if (!Buffer.isBuffer(result.stderr)) deny('B02_WIFI_OBSERVER_RESULT_DENIED');
    stderr = result.stderr;
    if (stdout.length > 4_096 || (stderr && stderr.length > 4_096) || (stderr && stderr.length !== 0)) {
      deny('B02_WIFI_OBSERVER_RESULT_DENIED');
    }
    let end = stdout.length;
    while (end > 0 && (stdout[end - 1] === 10 || stdout[end - 1] === 13)) end -= 1;
    if (end <= PREFIX.length || !stdout.subarray(0, PREFIX.length).equals(PREFIX)) {
      deny('B02_WIFI_OBSERVER_NOT_ASSOCIATED');
    }
    const identity = stdout.subarray(PREFIX.length, end);
    if (identity.length === 0 || identity.length > 512 || identity.includes(0)) {
      deny('B02_WIFI_OBSERVER_RESULT_DENIED');
    }
    const digest = createHmac('sha256', keyCopy).update(identity).digest('base64url');
    return `wfk1.${digest}`;
  } catch (error) {
    if (error instanceof MacosWifiObserverError) throw error;
    deny('B02_WIFI_OBSERVER_EXECUTION_DENIED');
  } finally {
    keyCopy.fill(0);
    sourceKey.fill(0);
    if (stdout) stdout.fill(0);
    if (stderr) stderr.fill(0);
  }
}

export function createMacosWifiObserver({ runner = defaultRunner, keyProvider }) {
  if (typeof runner !== 'function' || typeof keyProvider !== 'function') {
    deny('B02_WIFI_OBSERVER_CONFIGURATION_DENIED');
  }
  return Object.freeze({
    async observeKeyedFingerprint() {
      const key = await keyProvider();
      return observeKeyedFingerprint({ runner, key });
    }
  });
}

export const macosWifiObserverConstants = Object.freeze({
  executable: EXECUTABLE,
  argv: ARGV,
  timeoutMs: 2_000,
  maxBufferBytes: 4_096,
  minimalEnvironment: MINIMAL_ENV
});
