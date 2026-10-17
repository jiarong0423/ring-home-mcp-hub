// The numbers this repository claims in public text, read from README.md, and the checks against measured results.
// Used by tests/claims.mjs (fast: README vs the committed eval result) and scripts/check_claims.mjs (full: re-run).
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const EVAL_RESULT = join(ROOT, 'docs', 'eval', 'guardian_30d.json');

const one = (text, re, what) => {
  const m = text.match(re);
  if (!m) throw new Error(`claim not found in README: ${what}`);
  return m;
};

// Every number README.md states about the guardian evaluation and the test suites.
export function readmeClaims(text = readFileSync(join(ROOT, 'README.md'), 'utf8')) {
  const det = one(text, /Gateway outages over 5 min detected[^|]*\|\s*\*\*(\d+) \/ (\d+)\*\*, alert (\d+\.\d)–(\d+\.\d) min/u, 'outages detected');
  const blips = one(text, /alerts from blips under 3 min[^|]*\|\s*\*\*(\d+) \/ (\d+)\*\*/u, 'false alarms from blips');
  const mail = one(text, /Emails sent vs\.[^|]*\|\s*\*\*(\d+) vs (\d+)\*\*/u, 'emails vs baseline');
  const tests = one(text, /npm test\s+# (\d+) tests/u, 'npm test count');
  const mac = one(text, /npm run test:mac-worker\s+# (\d+) tests/u, 'mac worker test count');
  return {
    detected: Number(det[1]), outages: Number(det[2]), delayMin: det[3], delayMax: det[4],
    blipAlerts: Number(blips[1]), blips: Number(blips[2]),
    emails: Number(mail[1]), naive: Number(mail[2]),
    tests: Number(tests[1]), macTests: Number(mac[1])
  };
}

// README vs an eval summary (the JSON printed by scripts/eval_guardian.mjs). Returns a list of mismatches.
export function compareEval(claims, summary) {
  const g = summary.gateway;
  const measured = {
    detected: g.detected, outages: g.outages_over_5min, delayMin: g.detection_delay_min.min.toFixed(1), delayMax: g.detection_delay_min.max.toFixed(1),
    blipAlerts: g.offline_alerts_from_blips, blips: g.blips_under_3min, emails: summary.emails_sent, naive: summary.naive_alerts_one_per_missed_heartbeat
  };
  return Object.entries(measured).filter(([k, v]) => claims[k] !== v).map(([k, v]) => `${k}: README says ${claims[k]}, measured ${v}`);
}

export const committedEval = () => JSON.parse(readFileSync(EVAL_RESULT, 'utf8'));
export const testFiles = () => JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).scripts.test.split('--test')[1].trim().split(/\s+/u);

// "ℹ tests 275" (spec reporter) or "# tests 275" (TAP, the default without a terminal on Node 20/22).
export function readTestSummary(output) {
  const n = (k) => { const m = output.match(new RegExp(`^(?:ℹ|#) ${k} (\\d+)$`, 'mu')); return m ? Number(m[1]) : null; };
  return { tests: n('tests'), pass: n('pass'), fail: n('fail'), skipped: n('skipped') };
}
