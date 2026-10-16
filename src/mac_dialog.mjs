// A plain macOS system dialog for the one decision that must be made AT the Mac: "add this phone as admin?". Nobody needs a
// terminal. The phone can reach the hub's HTTP port but never this dialog, so a phone cannot approve itself.
// Text goes in as osascript arguments (never pasted into the script). It closes itself when time is up; no default button, so
// a stray Enter does nothing.
import { execFile } from 'node:child_process';

const SCRIPT = [
  'on run argv',
  'activate',
  'set r to display dialog (item 1 of argv) with title (item 2 of argv) buttons {(item 3 of argv), (item 4 of argv)} giving up after ((item 5 of argv) as integer) with icon caution',
  'if gave up of r then return "timeout"',
  'if button returned of r is (item 4 of argv) then return "allow"',
  'return "deny"',
  'end run'
].join('\n');

// enabled: only on a Mac, never when HOME_MCP_PAIR_DIALOG=off; by default only when a person started the hub (a terminal), so
// tests and background runs never pop windows. HOME_MCP_PAIR_DIALOG=on forces it (e.g. a double-click launcher).
export function macDialogEnabled({ platform = process.platform, env = process.env, isTTY = Boolean(process.stdin.isTTY) } = {}) {
  if (platform !== 'darwin' || env.HOME_MCP_PAIR_DIALOG === 'off') return false;
  return env.HOME_MCP_PAIR_DIALOG === 'on' || isTTY;
}

export function createMacDialog({ execFileImpl = execFile, osascript = '/usr/bin/osascript' } = {}) {
  // ask() -> { answer: Promise<'allow'|'deny'|'timeout'|'unavailable'>, close() }
  function ask({ message, title, deny, allow, seconds }) {
    let child = null;
    const answer = new Promise((resolve) => {
      try {
        child = execFileImpl(osascript, ['-e', SCRIPT, String(message), String(title), String(deny), String(allow), String(Math.max(1, Math.floor(seconds)))],
          { timeout: (seconds + 10) * 1000 }, (error, stdout) => {
            if (error) return resolve('unavailable');
            const out = String(stdout).trim();
            resolve(['allow', 'deny', 'timeout'].includes(out) ? out : 'unavailable');
          });
      } catch { resolve('unavailable'); }
    });
    return { answer, close: () => { try { child?.kill('SIGTERM'); } catch { /* already gone */ } } };
  }
  return Object.freeze({ ask });
}
