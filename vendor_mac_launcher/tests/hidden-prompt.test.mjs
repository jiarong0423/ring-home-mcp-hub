import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readPassphrase } from '../src/passphrase.mjs';
function fakeTty(lines) {
  const e = new EventEmitter(); e.isTTY = true; e.raw = false;
  e.setRawMode = v => { e.raw = v; }; e.resume = () => {}; e.pause = () => {}; e.setEncoding = () => {};
  const out = []; const err = { write: t => out.push(t) };
  let i = 0; const feed = () => { if (i < lines.length) setImmediate(() => { e.emit('data', lines[i++]); feed(); }); };
  return { stdin: e, stderr: err, out, start: feed };
}
test('hidden prompt: confirm match returns the passphrase, nothing echoed', async () => {
  const t = fakeTty(['correct-horse-1\r', 'correct-horse-1\r']); t.start();
  const b = await readPassphrase({ env: {}, stdin: t.stdin, stderr: t.stderr, confirm: true });
  assert.equal(b.toString('utf8'), 'correct-horse-1');
  assert.ok(!t.out.join('').includes('correct-horse'));
  assert.equal(t.stdin.raw, false);
});
test('hidden prompt: mismatch is rejected', async () => {
  const t = fakeTty(['aaaaaaaaaaaa\r', 'bbbbbbbbbbbb\r']); t.start();
  await assert.rejects(() => readPassphrase({ env: {}, stdin: t.stdin, stderr: t.stderr, confirm: true }), /PASSPHRASE_MISMATCH/);
});
test('hidden prompt: backspace edits, ctrl-c aborts', async () => {
  const t = fakeTty(['abcdefghijkX\u007f\r']); t.start();
  const b = await readPassphrase({ env: {}, stdin: t.stdin, stderr: t.stderr });
  assert.equal(b.toString('utf8'), 'abcdefghijk');
  const t2 = fakeTty(['abc\u0003']); t2.start();
  await assert.rejects(() => readPassphrase({ env: {}, stdin: t2.stdin, stderr: t2.stderr }), /PASSPHRASE_ABORTED/);
});
