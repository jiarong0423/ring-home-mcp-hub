#!/usr/bin/env node
// Regenerates docs/I18N_MAPPING.md from public/i18n-map.mjs (the single source of every UI string).
// Usage: node scripts/gen_i18n_mapping.mjs          -> rewrites docs/I18N_MAPPING.md
//        node scripts/gen_i18n_mapping.mjs --check  -> exit 1 if the doc is out of date (writes nothing)
// No dependencies. Read-only except for docs/I18N_MAPPING.md. The "where used" column is computed by scanning
// public/*.html, public/*.mjs and src/*.mjs for the key as a string literal, or for a dynamic prefix (a literal ending in '.', or `a.b.${x}`).
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const docPath = join(root, 'docs', 'I18N_MAPPING.md');
const { I18N_MAP } = await import(join(root, 'public', 'i18n-map.mjs'));

const MAP_FILE = 'i18n-map.mjs';
const sources = [
  ...readdirSync(join(root, 'public')).filter((f) => /\.(html|mjs)$/u.test(f)).sort().map((f) => ({ label: f, path: join(root, 'public', f) })),
  ...readdirSync(join(root, 'src')).filter((f) => f.endsWith('.mjs')).sort().map((f) => ({ label: `src/${f}`, path: join(root, 'src', f) })),
].map((s) => ({ ...s, text: readFileSync(s.path, 'utf8') }));

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
const cell = (s) => String(s).replace(/\r?\n/gu, ' ').replace(/\|/gu, '\\|');

// Dynamic prefixes per file: any string literal that ends in a dot ('a.b.' + x, pick("a.b.", [...])) or `a.b.${x}`
function dynamicPrefixes(text) {
  const out = new Set();
  for (const m of text.matchAll(/(['"])([a-z][A-Za-z0-9]*(?:\.[A-Za-z0-9_]+)*\.)\1/gu)) out.add(m[2]);
  for (const m of text.matchAll(/`([a-z][A-Za-z0-9]*(?:\.[A-Za-z0-9_]+)*\.)\$\{/gu)) out.add(m[1]);
  return [...out];
}
for (const s of sources) s.prefixes = s.label === MAP_FILE ? [] : dynamicPrefixes(s.text);

function headerRange(text) {
  const start = text.indexOf('<header');
  const end = start < 0 ? -1 : text.indexOf('</header>', start);
  return start < 0 || end < 0 ? null : [start, end];
}

function whereUsed(key) {
  const places = [];
  const add = (p) => { if (!places.includes(p)) places.push(p); };
  const literal = new RegExp(`(["'\`])${escapeRe(key)}\\1`, 'gu');
  for (const s of sources) {
    if (s.label === MAP_FILE) {
      // Inside the table file only calls such as t('locale', ...) count, not the table entries themselves.
      if (new RegExp(`\\bt\\((["'])${escapeRe(key)}\\1`, 'u').test(s.text)) add(MAP_FILE);
      continue;
    }
    const isHtml = s.label.endsWith('.html');
    const header = isHtml ? headerRange(s.text) : null;
    for (const m of s.text.matchAll(literal)) {
      if (!isHtml) { add(s.label); continue; }
      const before = s.text.slice(Math.max(0, m.index - 40), m.index);
      const attr = /data-i18n(-aria-label|-placeholder)?=$/u.exec(before);
      if (!attr) { add(`${s.label} (script)`); continue; }
      const inHeader = header && m.index > header[0] && m.index < header[1];
      add(`${s.label}${inHeader ? ' header' : ''}${attr[1] === '-aria-label' ? ' (aria-label)' : attr[1] === '-placeholder' ? ' (placeholder)' : ''}`);
    }
  }
  if (places.length === 0) {
    for (const s of sources) {
      const prefix = s.prefixes.filter((p) => key.startsWith(p)).sort((a, b) => b.length - a.length)[0];
      if (prefix) add(`${s.label}${s.label.endsWith('.html') ? ' (script)' : ''} (dynamic \`${prefix}*\`)`);
    }
  }
  return places.length ? places.join(', ') : '— (not referenced: unused key)';
}

const keys = Object.keys(I18N_MAP);
const rows = keys.map((key) => `| \`${key}\` | ${cell(I18N_MAP[key].zh)} | ${cell(I18N_MAP[key].en)} | ${cell(whereUsed(key))} |`);

const doc = `# I18N_MAPPING — UI text mapping table (中文 ↔ English)

> Generated file — do not edit by hand. Regenerate with \`node scripts/gen_i18n_mapping.mjs\` (check only: \`node scripts/gen_i18n_mapping.mjs --check\`).

English is the default UI language; Chinese is available with \`?lang=zh\`.

* Source of truth: \`public/i18n-map.mjs\` (\`I18N_MAP\`, frozen \`{ key: { en, zh } }\`, plus \`t(key, params)\`). This file is generated from the same table.
* Default language: **English**. Chinese: open \`http://127.0.0.1:8765/?lang=zh\` (or click the \`中文\` / \`English\` link in the header; it reloads the page, so pick the language **before** logging in).
* Markup uses \`data-i18n="key"\` / \`data-i18n-aria-label="key"\`; scripts call \`t('key', { param })\`. \`{name}\` = runtime parameter.
* "where used" is computed by scanning \`public/*.html\`, \`public/*.mjs\` and \`src/*.mjs\` for the key as a literal, or for a dynamic prefix (a string literal ending in a dot such as \`'a.b.' + x\`, or \`\` \`a.b.\${x}\` \`\`). "unused key" = no reference found.
* \`cloud.*\` keys belong to the optional earlier-phase Cloud MCP panel, shown only when the server starts with \`HOME_MCP_CLOUD_PANEL=1\`. Its step lines are sent as stable codes \`{ key: 'cloud.step.*', params }\` by \`src/cloud_mcp_panel.mjs\` and rendered by the client through this table.
* Not translated (by design): protocol / code values shown verbatim (\`result.status=SUCCEEDED\`, \`executed=true\`, \`commandId=cmd_…\`, error codes such as \`MAC_KEY_NOT_READY\`, device ids), audit \`outcome\`/\`action\` codes from the simulator, device icons (◇ ❄ ▣ ◷ ☼ ◎ ♧) and the brand mark \`M\`.

Total keys: **${keys.length}**

| key | 中文 | English | where used |
| --- | --- | --- | --- |
${rows.join('\n')}
`;

if (process.argv.includes('--check')) {
  let current = '';
  try { current = readFileSync(docPath, 'utf8'); } catch { current = ''; }
  if (current !== doc) { console.error(`ERROR docs/I18N_MAPPING.md is out of date; run node scripts/gen_i18n_mapping.mjs (${keys.length} keys)`); process.exit(1); }
  console.log(`OK docs/I18N_MAPPING.md is up to date (${keys.length} keys)`);
} else {
  writeFileSync(docPath, doc);
  console.log(`Wrote docs/I18N_MAPPING.md (${keys.length} keys)`);
}
