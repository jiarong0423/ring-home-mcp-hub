// Full claims check (CI): re-run the 30-day eval and both test suites, and compare with what README.md says.
//   node scripts/check_claims.mjs            -> eval + npm test + Mac worker tests
//   node scripts/check_claims.mjs --eval-only
// Prints CLAIMS_OK and exits 0 only when everything matches; every mismatch prints a line starting with ERROR.
import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { compareEval, committedEval, readmeClaims, readTestSummary, ROOT, testFiles } from './claims_lib.mjs';

const errors = [];
const claims = readmeClaims();

// 1. The eval is deterministic (fixed seed): a fresh run must equal the committed result and README.
const out = execFileSync(process.execPath, [join(ROOT, 'scripts', 'eval_guardian.mjs')], { cwd: ROOT, encoding: 'utf8', maxBuffer: 8 << 20 });
const fresh = JSON.parse(out.slice(0, out.indexOf('\n\n|')));
if (JSON.stringify(fresh) !== JSON.stringify(committedEval())) errors.push('eval: a fresh run differs from docs/eval/guardian_30d.json (re-run `npm run eval` and commit the result)');
for (const m of compareEval(claims, fresh)) errors.push('eval: ' + m);
console.log(`eval: ${fresh.gateway.detected}/${fresh.gateway.outages_over_5min} outages, ${fresh.gateway.offline_alerts_from_blips}/${fresh.gateway.blips_under_3min} blip alarms, ${fresh.emails_sent} vs ${fresh.naive_alerts_one_per_missed_heartbeat} emails`);

// 2. Test counts: README's numbers must be the counts node --test actually ran, with no failures.
function runTests(args, cwd) {
  try { return execFileSync(process.execPath, ['--test', ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 << 20 }); }
  catch (error) { return String(error.stdout ?? '') + String(error.stderr ?? ''); }
}
if (!process.argv.includes('--eval-only')) {
  const main = readTestSummary(runTests(testFiles(), ROOT));
  console.log(`npm test: ${main.tests} tests, ${main.pass} pass, ${main.fail} fail, ${main.skipped} skipped`);
  if (main.tests !== claims.tests) errors.push(`npm test: README says ${claims.tests} tests, ran ${main.tests}`);
  if (main.fail !== 0) errors.push(`npm test: ${main.fail} failing`);
  const macFiles = readdirSync(join(ROOT, 'vendor_mac_launcher', 'tests')).filter((f) => f.endsWith('.test.mjs')).sort().map((f) => 'tests/' + f);
  const mac = readTestSummary(runTests(macFiles, join(ROOT, 'vendor_mac_launcher')));
  console.log(`test:mac-worker: ${mac.tests} tests, ${mac.pass} pass, ${mac.fail} fail`);
  if (mac.tests !== claims.macTests) errors.push(`test:mac-worker: README says ${claims.macTests} tests, ran ${mac.tests}`);
  if (mac.fail !== 0) errors.push(`test:mac-worker: ${mac.fail} failing`);
}

for (const e of errors) console.error('ERROR ' + e);
if (errors.length) process.exit(1);
console.log('CLAIMS_OK');
