import { constants } from 'node:fs';
import { mkdir, lstat, open } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { COMMAND_ID, command, receipt, deny, record, freeze } from './mac-command-contract.mjs';

export async function createMacCommandJournal({ directory } = {}) {
  if (typeof directory !== 'string' || !directory.startsWith('/') || resolve(directory) !== directory) deny('MAC_JOURNAL_DIRECTORY');
  await mkdir(directory, { mode: 0o700, recursive: false }).catch(error => { if (error.code !== 'EEXIST') throw error; });
  const root = await lstat(directory);
  if (!root.isDirectory() || root.isSymbolicLink() || root.uid !== process.getuid() || (root.mode & 0o777) !== 0o700) deny('MAC_JOURNAL_DIRECTORY');
  const safeId = id => { if (typeof id !== 'string' || !COMMAND_ID.test(id)) deny('MAC_COMMAND_ID'); return id; };
  async function assertRoot() {
    const current = await lstat(directory);
    if (!current.isDirectory() || current.isSymbolicLink() || current.dev !== root.dev || current.ino !== root.ino ||
        current.uid !== process.getuid() || (current.mode & 0o777) !== 0o700) deny('MAC_JOURNAL_DIRECTORY_CHANGED');
  }
  async function create(id, suffix, data) {
    await assertRoot(); let handle;
    try {
      handle = await open(join(directory, safeId(id) + suffix), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      await handle.writeFile(JSON.stringify(data)); await handle.sync();
    } finally { if (handle) await handle.close(); }
    const parent = await open(directory, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { await parent.sync(); } finally { await parent.close(); }
  }
  async function read(id, suffix) {
    await assertRoot(); let handle;
    try {
      handle = await open(join(directory, safeId(id) + suffix), constants.O_RDONLY | constants.O_NOFOLLOW);
      const stat = await handle.stat();
      if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o600 || stat.size > 16_384) deny('MAC_JOURNAL_FILE');
      return JSON.parse(await handle.readFile('utf8'));
    } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    finally { if (handle) await handle.close(); }
  }
  return Object.freeze({
    async claim(value) {
      const c = command(value);
      try { await create(c.commandId, '.claim.json', { schema: 'ring-mac-local-claim-v1', command: c }); return true; }
      catch (error) { if (error.code === 'EEXIST') return false; throw error; }
    },
    async complete(value) {
      const r = receipt(value); const claim = await read(r.commandId, '.claim.json');
      if (!claim || claim.schema !== 'ring-mac-local-claim-v1' || command(claim.command).envelopeSha256 !== r.envelopeSha256) deny('MAC_JOURNAL_NO_CLAIM');
      try { await create(r.commandId, '.receipt.json', r); }
      catch (error) {
        if (error.code !== 'EEXIST') throw error;
        const previous = receipt(await read(r.commandId, '.receipt.json'));
        if (JSON.stringify(previous) !== JSON.stringify(r)) deny('MAC_JOURNAL_RECEIPT_CONFLICT');
      }
      return r;
    },
    async readReceipt(id) { const value = await read(id, '.receipt.json'); return value === null ? null : receipt(value); },
    async readCommand(id) {
      const value = await read(id, '.claim.json'); if (!value) return null;
      const row = record(value, ['schema', 'command']);
      if (row.schema !== 'ring-mac-local-claim-v1') deny('MAC_JOURNAL_FILE');
      return freeze(command(row.command));
    }
  });
}
