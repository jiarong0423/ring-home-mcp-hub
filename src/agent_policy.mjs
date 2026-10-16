// What an AI agent (any MCP client) may do on its own, decided per device and action before anything reaches the simulator.
//   allow  - low-risk, inside the family's limits: runs at once and is audited like any other command
//   ask    - the agent may only ask; a trusted family phone decides (front door unlock, src/door_requests.mjs)
//   family - only a family member on a paired phone may do it; the agent's call is refused and shown on the timeline
// Limits are plain numbers and hours so the agent can read them back (tool result `policy`) and stay inside them.
const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/u;

export const AGENT_POLICY = Object.freeze({
  living_light: { on: 'allow', off: 'allow' },
  air_conditioner: { on: 'allow', off: 'allow', set_temperature: { tier: 'allow', min: 24, max: 28, unit: '°C' } },
  dehumidifier: { on: 'allow', off: 'allow', set_target_humidity: { tier: 'allow', min: 40, max: 60, unit: '%' } },
  robot_vacuum: { start: { tier: 'allow', from: '08:00', to: '20:00' }, pause: 'allow', dock: 'allow' },
  alarm_clock: { set_alarm: { tier: 'allow', from: '05:00', to: '10:00' }, clear_alarm: 'family' },
  camera: { arm: 'allow', disarm: 'family' },
  front_door: { lock: 'allow', unlock: 'ask' }
});

const PARAM = Object.freeze({ set_temperature: 'temperature', set_target_humidity: 'humidity', set_alarm: 'time' });
const inWindow = (t, from, to) => t >= from && t < to;

// now: the home's local time "HH:MM" (the guardian clock, so an accelerated demo day follows the same rules).
export function decideAgentAction({ deviceId, action, parameters = {}, now }) {
  const rule = AGENT_POLICY[deviceId]?.[action];
  if (!rule) return { tier: 'family', allowed: false, reason: 'NOT_IN_POLICY' };
  const spec = typeof rule === 'string' ? { tier: rule } : rule;
  if (spec.tier !== 'allow') return { tier: spec.tier, allowed: false, reason: spec.tier === 'ask' ? 'FAMILY_APPROVAL_REQUIRED' : 'FAMILY_ONLY' };
  const limit = { ...spec }; delete limit.tier;
  if (spec.min !== undefined) {
    const value = parameters?.[PARAM[action]];
    if (typeof value !== 'number' || !Number.isFinite(value) || value < spec.min || value > spec.max) {
      return { tier: 'family', allowed: false, reason: 'OUTSIDE_FAMILY_LIMITS', limit };
    }
  }
  if (spec.from !== undefined) {
    // vacuum: the time of day now; alarm: the alarm time being set
    const t = action === 'set_alarm' ? parameters?.time : now;
    if (typeof t !== 'string' || !HHMM.test(t) || !inWindow(t, spec.from, spec.to)) {
      return { tier: 'family', allowed: false, reason: action === 'set_alarm' ? 'OUTSIDE_FAMILY_LIMITS' : 'OUTSIDE_ALLOWED_HOURS', limit };
    }
  }
  return { tier: 'allow', allowed: true, reason: null, ...(Object.keys(limit).length ? { limit } : {}) };
}

// The whole policy in one readable object, for the tool result and the README.
export function describeAgentPolicy() {
  const out = {};
  for (const [deviceId, actions] of Object.entries(AGENT_POLICY)) {
    out[deviceId] = Object.fromEntries(Object.entries(actions).map(([a, r]) => [a, typeof r === 'string' ? r : { ...r }]));
  }
  return out;
}
