// Spoken notices for the person at home (the elder living alone): the Mac speaker says, in plain words, what the hub just
// did on their behalf — "someone is at the door, I've asked your family", "the door is unlocked", "the 7:00 light did not
// turn on, I've told your family". Fixed phrases only (no free text from requesters), one at a time, no repeats within a
// minute. Off unless HOME_MCP_VOICE=on. Uses /usr/bin/say by absolute path (cron/launchd PATH has no Homebrew).
import { execFile } from 'node:child_process';

const DEVICE = Object.freeze({
  living_light: ['living room light', '客廳燈'], dehumidifier: ['dehumidifier', '除濕機'], air_conditioner: ['air conditioner', '冷氣'],
  alarm_clock: ['alarm clock', '鬧鐘'], camera: ['Ring camera', 'Ring 攝影機'], gateway: ['home gateway', '家中閘道'], front_door: ['front door', '前門']
});
const DID_NOT = Object.freeze({ on: ['turn on', '打開'], off: ['turn off', '關掉'], set_alarm: ['get set', '設定'] });
const VOICES = Object.freeze({ en: 'Samantha', zh: 'Meijia' });

// e: a guardian event { kind, target, params }. Returns the sentence to say, or null for events the person need not hear.
export function phraseFor(e, lang = 'en') {
  const zh = lang === 'zh';
  const [dev, devZh] = DEVICE[e.target] ?? [null, null];
  const ring = e.params?.requesterKind === 'ring';
  switch (e.kind) {
    case 'door_requested':
      return ring ? (zh ? '有人在前門。我已經問你的家人了，請稍等。' : 'Someone is at the front door. I have asked your family. Please wait.')
        : (zh ? '有人想開前門。由你的家人決定。' : 'Someone asked to open the front door. Your family will decide.');
    case 'door_approved': return zh ? '家人同意了。前門已經打開。' : 'Your family said yes. The front door is now unlocked.';
    case 'door_denied': return zh ? '家人沒有同意。門保持上鎖。' : 'Your family said no. The door stays locked.';
    case 'door_expired': return zh ? '沒有人及時回覆。門保持上鎖。' : 'No answer in time. The door stays locked.';
    case 'door_failed': return zh ? '門沒有打開，保持上鎖。' : 'The door could not be opened. It stays locked.';
    case 'routine_missed': {
      if (!dev) return null;
      const [act, actZh] = DID_NOT[e.params?.action] ?? ['work', '完成'];
      const at = /^\d{2}:\d{2}$/u.test(e.params?.scheduled ?? '') ? e.params.scheduled : '';
      return zh ? `${at} 的${devZh}沒有${actZh}。我已經通知你的家人。` : `The ${at} ${dev} did not ${act}. I have told your family.`.replace(/ {2,}/gu, ' ');
    }
    case 'offline':
      return dev ? (zh ? `${devZh}沒有回應。我已經通知你的家人。` : `The ${dev} stopped answering. I have told your family.`) : null;
    case 'recovered': return dev ? (zh ? `${devZh}恢復了。` : `The ${dev} is back.`) : null;
    default: return null;
  }
}

export function createVoiceNotice({ enabled = process.env.HOME_MCP_VOICE === 'on', lang = process.env.HOME_MCP_VOICE_LANG === 'zh' ? 'zh' : 'en',
  sayBin = '/usr/bin/say', execFileImpl = execFile, clock = Date.now, log = () => {} } = {}) {
  const queue = []; const recent = new Map(); let speaking = false; let spoken = 0;
  function next() {
    if (speaking || queue.length === 0) return;
    speaking = true;
    const text = queue.shift();
    execFileImpl(sayBin, ['-v', VOICES[lang], text], { timeout: 20_000 }, (error) => {
      if (error) log(`ERROR voice notice not spoken: ${error.code ?? 'say failed'}`);
      else { spoken += 1; log(`voice notice: "${text}"`); }
      speaking = false; next();
    });
  }
  function say(text) {
    if (!enabled || !text) return false;
    const now = clock();
    for (const [k, at] of recent) if (now - at > 60_000) recent.delete(k);
    if (recent.has(text) || queue.length >= 3) return false;   // no repeats within a minute; never a backlog
    recent.set(text, now); queue.push(text); next();
    return true;
  }
  return Object.freeze({
    onGuardianEvent: (e) => say(phraseFor(e, lang)),
    status: () => ({ enabled, lang, spoken })
  });
}
