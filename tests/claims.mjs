// Public numbers must match the measured ones. Fast part, inside `npm test`: README.md vs the committed 30-day eval result
// (docs/eval/guardian_30d.json). The full check (re-run the eval and the test suites) is `npm run check:claims`, run in CI.
import assert from 'node:assert/strict';
import test from 'node:test';
import { compareEval, committedEval, readmeClaims, readTestSummary } from '../scripts/claims_lib.mjs';

test('claims: every guardian number in README matches the committed 30-day eval result', () => {
  const claims = readmeClaims();
  assert.deepEqual(compareEval(claims, committedEval()), []);
});

test('claims: a README edit that drifts from the measured numbers is caught', () => {
  const summary = committedEval();
  const drifted = readmeClaims(`
| Gateway outages over 5 min detected (30 simulated days) | **12 / 12**, alert 4.0–4.9 min after it went quiet |
| "Offline" alerts from blips under 3 min (false alarms) | **0 / 22** |
| Emails sent vs. "alert on every missed heartbeat" | **58 vs 765** |
npm test                  # 275 tests
npm run test:mac-worker   # 40 tests`);
  assert.deepEqual(compareEval(drifted, summary), ['emails: README says 58, measured 59']);
  assert.throws(() => readmeClaims('no numbers here'), /claim not found/u);
});

test('claims: the node --test summary is read exactly', () => {
  assert.deepEqual(readTestSummary('…\nℹ tests 275\nℹ suites 0\nℹ pass 273\nℹ fail 0\nℹ skipped 2\n'), { tests: 275, pass: 273, fail: 0, skipped: 2 });
  assert.deepEqual(readTestSummary('TAP version 13\n# tests 40\n# pass 40\n# fail 0\n# skipped 0\n'), { tests: 40, pass: 40, fail: 0, skipped: 0 });
  assert.equal(readTestSummary('nothing').tests, null);
});
