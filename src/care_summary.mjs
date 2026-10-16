// Daily care summary for the family: the hub turns today's guardian events into a small fact sheet (times, devices,
// outcomes; never snapshots, faces or tokens), asks Amazon Bedrock (Converse API, through the AWS CLI profile, so this code
// never sees a key) to write a short warm note from those facts only, and emails it through SNS. If Bedrock is not set up,
// fails, or the note mentions a number that is not in the facts, the family gets a plain template note instead, labelled so.
// The care agent writes; it cannot act. Door opening stays request-only and the admin phone decides.
import { execFile } from 'node:child_process';

const DEVICE = Object.freeze({ living_light: 'living room light', dehumidifier: 'dehumidifier', air_conditioner: 'air conditioner',
  alarm_clock: 'alarm clock', camera: 'Ring camera', gateway: 'home gateway', front_door: 'front door' });
const ACTION = Object.freeze({ on: 'turn on', off: 'turn off', set_alarm: 'set the alarm', start: 'start', pause: 'pause', dock: 'dock' });
const MODEL_ID = /^[A-Za-z0-9.:_/-]{3,200}$/u;
const PROFILE = /^[A-Za-z0-9_.-]{1,64}$/u;
const REGION = /^[a-z]{2}-[a-z]+-\d$/u;

// One day's event log, fed from the guardian event stream (the UI list keeps only the newest ones).
export function createDayLog({ clock = Date.now } = {}) {
  let day = null; let events = [];
  const key = (ms) => new Date(ms).toDateString();
  return Object.freeze({
    note(e) { const k = key(Date.parse(e.at)); if (k !== day) { day = k; events = []; } events.push(e); },
    today() { return key(clock()) === day ? events.slice() : []; }
  });
}

export function buildDayFacts(events, { date = null } = {}) {
  const facts = { date, routine: { done: 0, missed: [] }, outages: [], door: [], doorbellRepeats: 0 };
  const open = {};
  for (const e of events) {
    const p = e.params ?? {};
    if (e.kind === 'routine_done') facts.routine.done += 1;
    else if (e.kind === 'routine_missed') facts.routine.missed.push({ time: p.scheduled, device: DEVICE[e.target] ?? e.target, action: ACTION[p.action] ?? p.action ?? 'run', reason: p.reason ?? 'unknown' });
    else if (e.kind === 'offline') open[e.target] = { device: DEVICE[e.target] ?? e.target, from: e.time, to: null };
    else if (e.kind === 'recovered' && open[e.target]) { open[e.target].to = e.time; facts.outages.push(open[e.target]); delete open[e.target]; }
    else if (e.kind.startsWith('door_') && e.kind !== 'door_requested') {
      facts.door.push({ time: e.time, asked: p.requesterKind === 'ring' ? 'Ring doorbell' : p.requesterKind === 'mcp' ? 'AI agent' : p.requesterKind === 'phone' ? 'family phone' : 'console',
        outcome: e.kind.slice(5), decidedBy: p.approver ?? null });
    } else if (e.kind === 'doorbell_again') facts.doorbellRepeats += 1;
  }
  facts.outages.push(...Object.values(open));   // still down at summary time (to: null)
  return facts;
}

export function templateSummary(f) {
  const lines = [];
  lines.push(f.routine.missed.length === 0 ? `All ${f.routine.done} routine steps ran as planned.`
    : `${f.routine.done} routine steps ran; ${f.routine.missed.length} did not: ${f.routine.missed.map((m) => `${m.time} ${m.device} ${m.action} (${m.reason})`).join('; ')}.`);
  lines.push(f.outages.length === 0 ? 'No device went offline.'
    : `Outages: ${f.outages.map((o) => `${o.device} ${o.from}–${o.to ?? 'still offline'}`).join('; ')}.`);
  lines.push(f.door.length === 0 ? 'Nobody asked to open the front door.'
    : `Front door: ${f.door.map((d) => `${d.time} ${d.asked} → ${d.outcome}${d.decidedBy ? ` by ${d.decidedBy}` : ''}`).join('; ')}.`);
  return lines.join(' ');
}

// Every number in the note must already be in the facts: a clock time only as that whole time ("09:20" = "9:20"), a count only
// as that count, the date only as its parts. Otherwise the note is not used.
const TOKEN = /\d{1,2}:\d{2}|\d+/gu;
const norm = (t) => (t.includes(':') ? t.replace(/^0(\d):/u, '$1:') : String(Number(t)));
// Sentences that summarise "everything else" are never backed by the facts (the log lists what happened, not what did not),
// so they are removed before the note is sent.
const UNBACKED = /\b(everything else|all else|otherwise|no other|nothing else|all other|as expected|went (?:fine|well|smoothly)|worked normally|quiet day)\b/iu;
export function dropUnbackedSentences(text) {
  const sentences = text.match(/[^.!?]+[.!?]+(?=\s|$)|[^.!?]+$/gu) ?? [text];
  return sentences.filter((x) => !UNBACKED.test(x)).join(' ').replace(/\s+/gu, ' ').trim();
}
export function onlyKnownNumbers(text, facts) {
  const known = new Set();
  (function walk(v) {
    if (typeof v === 'number') known.add(String(v));
    else if (typeof v === 'string') { if (/^\d{1,2}:\d{2}$/u.test(v)) known.add(norm(v)); else if (/^\d{4}-\d{2}-\d{2}$/u.test(v)) v.split('-').forEach((p) => known.add(norm(p))); }
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  })(facts);
  for (const k of ['routine', 'outages', 'door']) known.add(String(k === 'routine' ? facts.routine.missed.length : facts[k].length));
  return (text.match(TOKEN) ?? []).every((t) => known.has(norm(t)));
}

const SYSTEM = 'You write a short daily note for the family of an older person who lives alone. Use ONLY the facts in the JSON. '
  + 'Plain, warm English, at most 5 sentences, no headings, no lists. Mention anything that did not run or went offline first, with its time. '
  + 'Use the exact action words and requester names from the facts (for example "turn off", "AI agent"); never swap on and off. '
  + 'Only mention what is in the facts; do not add general statements such as "everything else ran as expected" or "no other issues". '
  + 'Do not guess causes, give medical advice, or invent events, people or numbers. Door and appliances are simulated; do not say so unless asked.';

export function createCareSummary({ awsBin, profile, region, modelId, execFileImpl = execFile, log = () => {} } = {}) {
  const ready = typeof awsBin === 'string' && awsBin.startsWith('/') && PROFILE.test(profile ?? '') && REGION.test(region ?? '') && MODEL_ID.test(modelId ?? '');
  let last = null;
  function converse(facts) {
    const args = ['bedrock-runtime', 'converse', `--model-id=${modelId}`,
      `--system=${JSON.stringify([{ text: SYSTEM }])}`,
      `--messages=${JSON.stringify([{ role: 'user', content: [{ text: 'Facts for today:\n' + JSON.stringify(facts) }] }])}`,
      `--inference-config=${JSON.stringify({ maxTokens: 300, temperature: 0 })}`,
      '--region', region, '--profile', profile, '--output', 'json'];
    return new Promise((resolve) => {
      try {
        execFileImpl(awsBin, args, { timeout: 30_000, maxBuffer: 262_144, shell: false, env: { HOME: process.env.HOME ?? '', PATH: '/usr/bin:/bin', AWS_PAGER: '' } },
          (error, stdout) => {
            if (error) return resolve({ ok: false, reason: error.code === 'ETIMEDOUT' || error.killed ? 'BEDROCK_TIMEOUT' : 'BEDROCK_CLI_FAILED' });
            try { resolve({ ok: true, text: JSON.parse(stdout)?.output?.message?.content?.find((c) => typeof c.text === 'string')?.text ?? '' }); }
            catch { resolve({ ok: false, reason: 'BEDROCK_OUTPUT_INVALID' }); }
          });
      } catch { resolve({ ok: false, reason: 'BEDROCK_CLI_FAILED' }); }
    });
  }
  async function write(facts) {
    const fallback = (reason) => { last = { source: 'template', reason }; return { text: templateSummary(facts), source: 'template', reason }; };
    if (!ready) return fallback('BEDROCK_NOT_CONFIGURED');
    const r = await converse(facts);
    if (!r.ok) { log(`ERROR care summary: Bedrock not used (${r.reason}); template note sent instead`); return fallback(r.reason); }
    const text = r.text.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/gu, '').trim();
    const kept = dropUnbackedSentences(text);
    if (!kept || kept.length > 1200) { log('ERROR care summary: Bedrock note empty or too long; template note sent instead'); return fallback('BEDROCK_OUTPUT_INVALID'); }
    if (!onlyKnownNumbers(kept, facts)) { log('ERROR care summary: Bedrock note had a number not in the facts; template note sent instead'); return fallback('BEDROCK_UNGROUNDED'); }
    last = { source: 'bedrock', reason: null };
    return { text: kept, source: 'bedrock', reason: null };
  }
  return Object.freeze({ write, status: () => ({ bedrock: ready ? 'configured' : 'off', modelId: ready ? modelId : null, last }) });
}
