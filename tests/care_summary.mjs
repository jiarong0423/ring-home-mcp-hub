// Daily care summary: facts from the guardian log, Bedrock Converse through the AWS CLI (fake here), and a template fallback
// whenever Bedrock is off, fails, or mentions a number that is not in the facts.
import assert from 'node:assert/strict';
import test from 'node:test';
import { buildDayFacts, createCareSummary, createDayLog, dropUnbackedSentences, onlyKnownNumbers, templateSummary } from '../src/care_summary.mjs';

const ev = (time, kind, target, params = {}) => ({ at: `2026-10-16T${time}:00`, time, kind, target, params });
const DAY = [
  ev('07:00', 'routine_done', 'living_light', { scheduled: '07:00', action: 'on' }),
  ev('09:00', 'offline', 'gateway', { lastHeartbeat: '08:55' }),
  ev('09:00', 'routine_missed', 'dehumidifier', { scheduled: '09:00', action: 'on', reason: 'gateway offline' }),
  ev('09:20', 'recovered', 'gateway'),
  ev('10:02', 'door_requested', 'front_door', { requesterKind: 'ring' }),
  ev('10:02', 'doorbell_again', 'front_door', { requesterKind: 'ring' }),
  ev('10:03', 'door_approved', 'front_door', { requesterKind: 'ring', approver: 'Amy (remote)', receipt: 'abc' })
];

test('facts and template: missed steps, outages, door outcomes; no snapshot or token fields exist', () => {
  const f = buildDayFacts(DAY, { date: '2026-10-16' });
  assert.deepEqual(f, { date: '2026-10-16', routine: { done: 1, missed: [{ time: '09:00', device: 'dehumidifier', action: 'turn on', reason: 'gateway offline' }] },
    outages: [{ device: 'home gateway', from: '09:00', to: '09:20' }], door: [{ time: '10:03', asked: 'Ring doorbell', outcome: 'approved', decidedBy: 'Amy (remote)' }], doorbellRepeats: 1 });
  assert.equal(templateSummary(f), '1 routine steps ran; 1 did not: 09:00 dehumidifier turn on (gateway offline). Outages: home gateway 09:00–09:20. Front door: 10:03 Ring doorbell → approved by Amy (remote).');
  assert.equal(onlyKnownNumbers('At 9:00 the dehumidifier did not start; the gateway was back by 9:20.', f), true);
  assert.equal(onlyKnownNumbers('She took 3 walks.', f), false);
  const log = createDayLog({ clock: () => Date.parse('2026-10-16T12:00:00') });
  for (const e of DAY) log.note(e);
  assert.equal(log.today().length, DAY.length);
  log.note(ev('00:01', 'routine_done', 'living_light'));   // same day: kept
  assert.equal(log.today().length, DAY.length + 1);
});

test('Bedrock: Converse via the CLI with argv (no shell), facts only; ungrounded or failed notes fall back to the template', async () => {
  const facts = buildDayFacts(DAY, { date: '2026-10-16' });
  const off = await createCareSummary({}).write(facts);
  assert.equal(off.source, 'template'); assert.equal(off.reason, 'BEDROCK_NOT_CONFIGURED');
  const calls = []; const logs = []; let reply = null;
  const execFileImpl = (bin, args, opts, cb) => { calls.push({ bin, args, opts }); reply(cb); };
  const care = createCareSummary({ awsBin: '/opt/homebrew/bin/aws', profile: 'home-mcp-notify', region: 'ap-southeast-1', modelId: 'apac.anthropic.claude-test', execFileImpl, log: (l) => logs.push(l) });
  reply = (cb) => cb(null, JSON.stringify({ output: { message: { content: [{ text: 'A calm day. The dehumidifier did not start at 09:00 while the gateway was down until 09:20. At 10:03 Amy let the visitor in from her phone.' }] } } }));
  const good = await care.write(facts);
  assert.equal(good.source, 'bedrock'); assert.match(good.text, /09:20/u);
  const c = calls[0];
  assert.equal(c.bin, '/opt/homebrew/bin/aws'); assert.equal(c.opts.shell, false); assert.equal(c.opts.env.PATH, '/usr/bin:/bin');
  assert.deepEqual(c.args.slice(0, 3), ['bedrock-runtime', 'converse', '--model-id=apac.anthropic.claude-test']);
  assert.ok(c.args.includes('--profile') && c.args.includes('home-mcp-notify'));
  const msg = c.args.find((a) => a.startsWith('--messages='));
  assert.match(msg, /dehumidifier/u); assert.doesNotMatch(msg, /snapshot|token|face/iu);
  reply = (cb) => cb(null, JSON.stringify({ output: { message: { content: [{ text: 'She slept 8 hours and took 2 walks.' }] } } }));
  const made = await care.write(facts);
  assert.equal(made.source, 'template'); assert.equal(made.reason, 'BEDROCK_UNGROUNDED');
  reply = (cb) => { const e = new Error('x'); e.code = 255; cb(e, ''); };
  assert.equal((await care.write(facts)).reason, 'BEDROCK_CLI_FAILED');
  reply = (cb) => cb(null, 'not json');
  assert.equal((await care.write(facts)).reason, 'BEDROCK_OUTPUT_INVALID');
  assert.equal(logs.filter((l) => l.startsWith('ERROR care summary')).length, 3);
  assert.equal(care.status().last.source, 'template');
});

test('unbacked "everything else was fine" sentences are removed before sending; real sentences stay', () => {
  assert.equal(dropUnbackedSentences('The light did not turn off at 09:00. At 10:00 Amy approved the AI agent. Everything else worked normally today.'),
    'The light did not turn off at 09:00. At 10:00 Amy approved the AI agent.');
  assert.equal(dropUnbackedSentences('Otherwise, it was a quiet day with no other issues to report.'), '');
  assert.equal(dropUnbackedSentences('The gateway was offline from 09:00 to 09:20.'), 'The gateway was offline from 09:00 to 09:20.');
});
