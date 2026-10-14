export const LOCAL_PASSPHRASE_MIN_CHARACTERS = 10;
export const LOCAL_PASSPHRASE_MAX_BYTES = 1024;
export const LOCAL_PASSPHRASE_PROFILE = 'B02_LOCAL_SECRET_UTF8_EGC_V1';

function inRange(value, first, last) {
  return value >= first && value <= last;
}

function nextScalar(bytes, offset) {
  const first = bytes[offset];
  if (first <= 0x7f) return Object.freeze({ scalar: first, next: offset + 1 });
  if (inRange(first, 0xc2, 0xdf)) {
    const second = bytes[offset + 1];
    if (!inRange(second, 0x80, 0xbf)) return null;
    return Object.freeze({ scalar: ((first & 0x1f) << 6) | (second & 0x3f), next: offset + 2 });
  }
  if (inRange(first, 0xe0, 0xef)) {
    const second = bytes[offset + 1];
    const third = bytes[offset + 2];
    if (!inRange(third, 0x80, 0xbf) ||
        (first === 0xe0 ? !inRange(second, 0xa0, 0xbf) :
          first === 0xed ? !inRange(second, 0x80, 0x9f) : !inRange(second, 0x80, 0xbf))) return null;
    return Object.freeze({
      scalar: ((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f),
      next: offset + 3
    });
  }
  if (inRange(first, 0xf0, 0xf4)) {
    const second = bytes[offset + 1];
    const third = bytes[offset + 2];
    const fourth = bytes[offset + 3];
    if (!inRange(third, 0x80, 0xbf) || !inRange(fourth, 0x80, 0xbf) ||
        (first === 0xf0 ? !inRange(second, 0x90, 0xbf) :
          first === 0xf4 ? !inRange(second, 0x80, 0x8f) : !inRange(second, 0x80, 0xbf))) return null;
    return Object.freeze({
      scalar: ((first & 0x07) << 18) | ((second & 0x3f) << 12) |
        ((third & 0x3f) << 6) | (fourth & 0x3f),
      next: offset + 4
    });
  }
  return null;
}

function prohibitedScalar(value) {
  return value === 0 || value === 0x7f || inRange(value, 1, 0x1f) || inRange(value, 0x80, 0x9f) ||
    value === 0x061c || value === 0x00ad || value === 0x034f || value === 0x180e ||
    inRange(value, 0x200b, 0x200c) || inRange(value, 0x200e, 0x200f) ||
    inRange(value, 0x2028, 0x202e) || inRange(value, 0x2060, 0x206f) || value === 0xfeff ||
    value === 0xfffd || inRange(value, 0xd800, 0xdfff) ||
    inRange(value, 0xe000, 0xf8ff) || inRange(value, 0xf0000, 0xffffd) ||
    inRange(value, 0x100000, 0x10fffd) || inRange(value, 0xfdd0, 0xfdef) ||
    (value & 0xffff) === 0xfffe || (value & 0xffff) === 0xffff;
}

function unassignedInPinnedProfile(value) {
  return inRange(value, 0x378, 0x379) || inRange(value, 0x380, 0x383) || value === 0x38b ||
    value === 0x38d || value === 0x3a2 || inRange(value, 0x557, 0x558) ||
    inRange(value, 0x58b, 0x58c) || inRange(value, 0x5c8, 0x5cf) ||
    inRange(value, 0x5eb, 0x5ee) || inRange(value, 0x1acf, 0x1aff) || value === 0x2065 ||
    inRange(value, 0x2072, 0x2073) || value === 0x208f || inRange(value, 0x209d, 0x209f) ||
    inRange(value, 0x20c1, 0x20cf) || inRange(value, 0x20f1, 0x20ff) ||
    inRange(value, 0x218c, 0x218f) || inRange(value, 0x2427, 0x243f) ||
    inRange(value, 0x244b, 0x245f) || inRange(value, 0x2b74, 0x2b75) || value === 0x2b96 ||
    value === 0x3040 || inRange(value, 0x3097, 0x3098) || inRange(value, 0x3100, 0x3104) ||
    inRange(value, 0xffbf, 0xffc1) || inRange(value, 0xffc8, 0xffc9) ||
    inRange(value, 0xffd0, 0xffd1) || inRange(value, 0xffd8, 0xffd9) ||
    inRange(value, 0xffdd, 0xffdf) || value === 0xffe7 || inRange(value, 0x1f0af, 0x1f0b0) ||
    value === 0x1f0c0 || value === 0x1f0d0 || inRange(value, 0x1f23c, 0x1f23f) ||
    inRange(value, 0x1f249, 0x1f24f) || inRange(value, 0x1fa7d, 0x1fa7f);
}

function assignedInPinnedProfile(value) {
  if (inRange(value, 0x20, 0x7e) || inRange(value, 0xa0, 0x2ff) ||
      inRange(value, 0x300, 0x36f) || inRange(value, 0x370, 0x52f) ||
      inRange(value, 0x531, 0x58f) || inRange(value, 0x591, 0x5f4) ||
      inRange(value, 0x600, 0x6ff) || inRange(value, 0x750, 0x77f) ||
      inRange(value, 0x900, 0x97f) || inRange(value, 0x1ab0, 0x1aff) ||
      inRange(value, 0x1dc0, 0x1dff) || inRange(value, 0x2000, 0x2bff) ||
      inRange(value, 0x3000, 0x30ff) || inRange(value, 0x3100, 0x312f) ||
      inRange(value, 0x31a0, 0x31bf) || inRange(value, 0x3400, 0x4dbf) ||
      inRange(value, 0x4e00, 0x9fff) || inRange(value, 0xac00, 0xd7a3) ||
      inRange(value, 0xfe00, 0xfe0f) || inRange(value, 0xfe20, 0xfe2f) ||
      inRange(value, 0xff01, 0xffee) || inRange(value, 0x1f000, 0x1f02b) ||
      inRange(value, 0x1f0a0, 0x1f0f5) || inRange(value, 0x1f100, 0x1f1ad) ||
      inRange(value, 0x1f1e6, 0x1f202) || inRange(value, 0x1f210, 0x1f251) ||
      inRange(value, 0x1f300, 0x1f6d7) || inRange(value, 0x1f6dc, 0x1f6ec) ||
      inRange(value, 0x1f6f0, 0x1f6fc) || inRange(value, 0x1f7e0, 0x1f7eb) ||
      inRange(value, 0x1f90c, 0x1f9ff) || inRange(value, 0x1fa70, 0x1fa88) ||
      inRange(value, 0x1fa90, 0x1fabd) || inRange(value, 0x1fabf, 0x1fac5) ||
      inRange(value, 0x1face, 0x1fadb) || inRange(value, 0x1fae0, 0x1fae8) ||
      inRange(value, 0x1faf0, 0x1faf8) || inRange(value, 0xe0100, 0xe01ef)) {
    return !unassignedInPinnedProfile(value);
  }
  return false;
}

function combining(value) {
  return inRange(value, 0x300, 0x36f) || inRange(value, 0x591, 0x5bd) || value === 0x5bf ||
    inRange(value, 0x5c1, 0x5c2) || inRange(value, 0x5c4, 0x5c5) || value === 0x5c7 ||
    inRange(value, 0x610, 0x61a) || inRange(value, 0x64b, 0x65f) || value === 0x670 ||
    inRange(value, 0x6d6, 0x6ed) || inRange(value, 0x93a, 0x94d) || inRange(value, 0x951, 0x957) ||
    inRange(value, 0x962, 0x963) || inRange(value, 0x1ab0, 0x1aff) ||
    inRange(value, 0x1dc0, 0x1dff) || inRange(value, 0x20d0, 0x20ff) ||
    inRange(value, 0xfe00, 0xfe0f) || inRange(value, 0xfe20, 0xfe2f) ||
    inRange(value, 0x1f3fb, 0x1f3ff) || inRange(value, 0xe0100, 0xe01ef);
}

function regionalIndicator(value) {
  return inRange(value, 0x1f1e6, 0x1f1ff);
}

function extendedPictographic(value) {
  return value === 0x00a9 || value === 0x00ae || value === 0x203c || value === 0x2049 ||
    value === 0x2122 || value === 0x2139 || inRange(value, 0x2194, 0x21ff) ||
    inRange(value, 0x2300, 0x23ff) || inRange(value, 0x2460, 0x27bf) ||
    inRange(value, 0x2b00, 0x2bff) || inRange(value, 0x1f000, 0x1f02b) ||
    inRange(value, 0x1f0a0, 0x1f0f5) || inRange(value, 0x1f200, 0x1f251) ||
    inRange(value, 0x1f300, 0x1f6fc) || inRange(value, 0x1f7e0, 0x1f7eb) ||
    inRange(value, 0x1f90c, 0x1f9ff) || inRange(value, 0x1fa70, 0x1faf8);
}

export function validateLocalPassphraseBytes(value) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array) || value.byteLength > LOCAL_PASSPHRASE_MAX_BYTES ||
      value.byteLength === 0) return false;
  let offset = 0;
  let clusters = 0;
  let clusterHasBase = false;
  let clusterHasPictograph = false;
  let pendingJoiner = false;
  let regionalCount = 0;
  while (offset < value.byteLength) {
    const decoded = nextScalar(value, offset);
    if (!decoded || decoded.next > value.byteLength) return false;
    offset = decoded.next;
    const scalar = decoded.scalar;
    if (prohibitedScalar(scalar) || !assignedInPinnedProfile(scalar)) return false;
    if (scalar === 0x200d) {
      if (!clusterHasBase || !clusterHasPictograph || pendingJoiner) return false;
      pendingJoiner = true;
      continue;
    }
    const isCombining = combining(scalar);
    const isPictograph = extendedPictographic(scalar);
    const isRegional = regionalIndicator(scalar);
    if (pendingJoiner) {
      if (!isPictograph) return false;
      pendingJoiner = false;
      clusterHasBase = true;
      clusterHasPictograph = true;
      regionalCount = 0;
      continue;
    }
    if (isCombining) {
      if (!clusterHasBase || (inRange(scalar, 0x1f3fb, 0x1f3ff) && !clusterHasPictograph)) return false;
      continue;
    }
    if (isRegional && regionalCount % 2 === 1) {
      regionalCount += 1;
      clusterHasBase = true;
      continue;
    }
    clusters += 1;
    clusterHasBase = true;
    clusterHasPictograph = isPictograph;
    regionalCount = isRegional ? 1 : 0;
  }
  if (pendingJoiner || clusters < LOCAL_PASSPHRASE_MIN_CHARACTERS) return false;
  return Object.freeze({
    valid: true,
    graphemeClusters: clusters,
    byteLength: value.byteLength,
    profile: LOCAL_PASSPHRASE_PROFILE
  });
}
