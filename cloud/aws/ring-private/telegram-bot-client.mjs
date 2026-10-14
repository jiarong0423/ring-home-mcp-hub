const TELEGRAM_ORIGIN = 'https://api.telegram.org';
const METHODS = Object.freeze({
  getMe: 'getMe',
  sendMessage: 'sendMessage'
});
const MAX_RESPONSE_BYTES = 65_536;
const TOKEN = /^([1-9][0-9]{0,19}):([A-Za-z0-9_-]{20,128})$/;
const BOT_ID = /^[1-9][0-9]{0,19}$/;

export class TelegramBotClientError extends Error {
  constructor(code) {
    super(code);
    this.name = 'TelegramBotClientError';
    this.code = code;
  }
}

function fail(code) {
  throw new TelegramBotClientError(code);
}

function exact(value, keys, code) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(code);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) fail(code);
    const names = Reflect.ownKeys(value);
    if (names.some(name => typeof name !== 'string' || !keys.includes(name))) fail(code);
    const result = Object.create(null);
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.value === undefined) fail(code);
      result[name] = descriptor.value;
    }
    return result;
  } catch (error) {
    if (error instanceof TelegramBotClientError) throw error;
    fail(code);
  }
}

function scalar(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function boundedText(value, minimum, maximum, pattern, code) {
  if (typeof value !== 'string' || !scalar(value) || /[\x00-\x1f\x7f]/.test(value)) fail(code);
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.toString('utf8') !== value || bytes.length < minimum || bytes.length > maximum ||
      (pattern && !pattern.test(value))) fail(code);
  return value;
}

function config(value) {
  const options = exact(value ?? {}, [
    'fetchImpl', 'timeoutMs', 'token', 'botId', 'username', 'botGeneration'
  ], 'telegram_client_config');
  const fetchImpl = options.fetchImpl;
  const timeoutMs = options.timeoutMs === undefined ? 4_000 : options.timeoutMs;
  const token = boundedText(options.token, 23, 149, TOKEN, 'telegram_client_config');
  const botId = boundedText(options.botId, 1, 20, BOT_ID, 'telegram_client_config');
  const match = TOKEN.exec(token);
  if (typeof fetchImpl !== 'function' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 ||
      timeoutMs > 10_000 || match[1] !== botId || options.username !== 'Homemcphub_bot' ||
      !Number.isSafeInteger(options.botGeneration) || options.botGeneration < 1) {
    fail('telegram_client_config');
  }
  return Object.freeze({ fetchImpl, timeoutMs, token, botId, username: options.username });
}

async function readBoundedJson(response, signal) {
  const reader = response?.body?.getReader?.();
  if (!reader) fail('telegram_response_invalid');
  const chunks = [];
  let size = 0;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  if (signal.aborted) cancel();
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      if (!(part.value instanceof Uint8Array)) fail('telegram_response_invalid');
      size += part.value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        void reader.cancel().catch(() => {});
        fail('telegram_response_invalid');
      }
      chunks.push(Buffer.from(part.value));
    }
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
    return JSON.parse(decoded);
  } catch (error) {
    if (error instanceof TelegramBotClientError) throw error;
    fail('telegram_response_invalid');
  } finally {
    signal.removeEventListener('abort', cancel);
    reader.releaseLock();
  }
}

function dataField(value, key, code) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(code);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail(code);
    return descriptor.value;
  } catch (error) {
    if (error instanceof TelegramBotClientError) throw error;
    fail(code);
  }
}

function verifyGetMe(value, botId, username) {
  if (dataField(value, 'ok', 'telegram_identity_mismatch') !== true) fail('telegram_identity_mismatch');
  const result = dataField(value, 'result', 'telegram_identity_mismatch');
  const id = dataField(result, 'id', 'telegram_identity_mismatch');
  const isBot = dataField(result, 'is_bot', 'telegram_identity_mismatch');
  const returnedUsername = dataField(result, 'username', 'telegram_identity_mismatch');
  if (!Number.isSafeInteger(id) || String(id) !== botId || isBot !== true || returnedUsername !== username) {
    fail('telegram_identity_mismatch');
  }
  return Object.freeze({ botId, username, verified: true });
}

function verifySend(value, chatId, botId, username) {
  if (dataField(value, 'ok', 'telegram_response_invalid') !== true) fail('telegram_response_invalid');
  const result = dataField(value, 'result', 'telegram_response_invalid');
  const messageId = dataField(result, 'message_id', 'telegram_response_invalid');
  const chat = dataField(result, 'chat', 'telegram_response_invalid');
  const from = dataField(result, 'from', 'telegram_response_invalid');
  if (!Number.isSafeInteger(messageId) || messageId < 1 ||
      !Number.isSafeInteger(dataField(chat, 'id', 'telegram_response_invalid')) ||
      String(dataField(chat, 'id', 'telegram_response_invalid')) !== chatId ||
      dataField(chat, 'type', 'telegram_response_invalid') !== 'private' ||
      !Number.isSafeInteger(dataField(from, 'id', 'telegram_response_invalid')) ||
      String(dataField(from, 'id', 'telegram_response_invalid')) !== botId ||
      dataField(from, 'is_bot', 'telegram_response_invalid') !== true ||
      dataField(from, 'username', 'telegram_response_invalid') !== username) {
    fail('telegram_response_invalid');
  }
  return Object.freeze({ messageId, delivered: true });
}

export function createTelegramBotClient(options) {
  const { fetchImpl, timeoutMs, token, botId, username } = config(options);

  function methodUrl(method) {
    if (!Object.values(METHODS).includes(method)) fail('telegram_client_config');
    return `${TELEGRAM_ORIGIN}/bot${token}/${method}`;
  }

  async function request(method, body, mutating) {
    const controller = new AbortController();
    let timer;
    const expiration = new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new TelegramBotClientError(mutating ? 'telegram_outcome_unknown' : 'telegram_unavailable'));
      }, timeoutMs);
    });
    const operation = (async () => {
      const response = await fetchImpl(methodUrl(method), {
        method: 'POST',
        headers: Object.freeze({
          accept: 'application/json',
          'content-type': 'application/json'
        }),
        body: JSON.stringify(body),
        redirect: 'error',
        signal: controller.signal
      });
      if (response?.status !== 200 || response.redirected === true ||
          !/^application\/(?:json|[A-Za-z0-9.+-]+\+json)(?:\s*;|\s*$)/i.test(
            response.headers?.get?.('content-type') ?? '')) {
        fail('telegram_response_invalid');
      }
      return readBoundedJson(response, controller.signal);
    })();
    try {
      return await Promise.race([operation, expiration]);
    } catch (error) {
      if (mutating) fail('telegram_outcome_unknown');
      if (error instanceof TelegramBotClientError &&
          ['telegram_response_invalid', 'telegram_identity_mismatch'].includes(error.code)) throw error;
      fail('telegram_unavailable');
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
  }

  return Object.freeze({
    async getMe() {
      return verifyGetMe(await request(METHODS.getMe, {}, false), botId, username);
    },
    async sendPrivate(value) {
      const input = exact(value, ['chatId', 'text'], 'telegram_input_invalid');
      const chatId = boundedText(input.chatId, 1, 20, BOT_ID, 'telegram_input_invalid');
      const text = boundedText(input.text, 1, 4096, null, 'telegram_input_invalid');
      try {
        const response = await request(METHODS.sendMessage, Object.freeze({
          chat_id: chatId,
          text,
          disable_notification: true,
          protect_content: true
        }), true);
        return verifySend(response, chatId, botId, username);
      } catch {
        fail('telegram_outcome_unknown');
      }
    }
  });
}
