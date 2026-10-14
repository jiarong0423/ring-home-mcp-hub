import { parseVerifiedWebhook, ProtocolError } from './protocol.mjs';
import { TextDecoder } from 'node:util';

const ISO_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const MAX_DATE_MS = 8_640_000_000_000_000;
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

function validIsoTime(value) {
  if (typeof value !== 'string') return false;
  const match = ISO_TIME.exec(value);
  if (!match) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, , offsetHourText, offsetMinuteText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth ||
      hour > 23 || minute > 59 || second > 59) return false;
  if (offsetHourText !== undefined &&
      (Number(offsetHourText) > 14 || Number(offsetMinuteText) > 59 ||
       (Number(offsetHourText) === 14 && Number(offsetMinuteText) !== 0))) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && Math.abs(parsed) <= MAX_DATE_MS;
}

export function parseSignedAppIntegrationRemoved({ rawBody, signature, signingKey } = {}) {
  const verified = parseVerifiedWebhook(rawBody, signature, signingKey);
  try {
    utf8Decoder.decode(rawBody);
  } catch {
    throw new ProtocolError('invalid_removal_event');
  }
  const attributes = verified.payload.data?.attributes;
  const sentAt = verified.payload.meta.time;
  const occurredAt = attributes?.timestamp;

  if (verified.eventType !== 'app_integration_removed' ||
      attributes?.source_type !== 'users' ||
      attributes?.source !== verified.accountId ||
      !validIsoTime(sentAt) ||
      !Number.isSafeInteger(occurredAt) ||
      occurredAt < 0 || occurredAt > MAX_DATE_MS) {
    throw new ProtocolError('invalid_removal_event');
  }

  return Object.freeze({
    type: 'app_integration_removed',
    accountId: verified.accountId,
    requestId: verified.requestId,
    eventId: verified.eventId,
    sentAt,
    occurredAt
  });
}
