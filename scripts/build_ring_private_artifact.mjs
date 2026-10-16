import { promises as fs, constants } from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const FIXED = Object.freeze([{"path":"cloud/aws/ring-private/account-identity-projection.mjs","sha256":"b4c0a1c157915e6b6e7f5cb3e07574902baa24b15244cfb1a8a63ba747411315","bytes":5966,"mode":"0644"},{"path":"cloud/aws/ring-private/account-link-http.mjs","sha256":"cdbe7473bc59d5b4e5ef239ef253a0f66f2fe1d3ad8e8bac4b674c298cc949b9","bytes":15412,"mode":"0644"},{"path":"cloud/aws/ring-private/api-gateway-account-link-event.mjs","sha256":"c7ce6efd7c6f37ecda35ac89cf4b2d27cb73200fff420d68559584431ac4367e","bytes":7729,"mode":"0644"},{"path":"cloud/aws/ring-private/api-gateway-event.mjs","sha256":"aa19c0bfb627684a4cd5fe1b6bea8829e8b5e4855b855da2eb8d32649734d29e","bytes":5555,"mode":"0644"},{"path":"cloud/aws/ring-private/api-gateway-telegram-event.mjs","sha256":"74f700e197b21f100bcc1883cb43d34968dfd74cf3f927b625189536aa74bb55","bytes":4765,"mode":"0644"},{"path":"cloud/aws/ring-private/aws-composition.mjs","sha256":"8928ab7b73b211a66aa1a065627f6937ec058b5bcc4cfa64f4d73ae4d015580c","bytes":16595,"mode":"0644"},{"path":"cloud/aws/ring-private/aws-sdk-v3-ports.mjs","sha256":"33c36231c7c50857fb800c3ad01de6e89a14ad08c2ee290e71732f42bb82f258","bytes":4196,"mode":"0644"},{"path":"cloud/aws/ring-private/b02-layer-runtime.mjs","sha256":"7dbed4a4a0b8fc2b674a9e7b968671670d55278d2b94796eb113e607bd8bf1e9","bytes":15266,"mode":"0644"},{"path":"cloud/aws/ring-private/b02-session-seam.mjs","sha256":"42f9a3abf3b740ad1a5d26a46f14ba268e6fe907d5eb263c9c93dfa32f5ec6b0","bytes":2061,"mode":"0644"},{"path":"cloud/aws/ring-private/browser-session-http.mjs","sha256":"516e943d8a0f3dc9e9907fbe9e5275804f2e2b3406859f55e53cbdd29570a8c8","bytes":9059,"mode":"0644"},{"path":"cloud/aws/ring-private/browser-session-production.mjs","sha256":"603ced605f99af9d9a002986055c1c81a379329478cc6155c59b29d88187de07","bytes":7064,"mode":"0644"},{"path":"cloud/aws/ring-private/capability-intent-contract.mjs","sha256":"33c6ba7bb43a02c3ea562edf1d4633deb84876be09daf6e27d27d64520965c34","bytes":9164,"mode":"0644"},{"path":"cloud/aws/ring-private/cloud-browser-session.mjs","sha256":"c8a34fd20e4ac4cbfb9170f99376979adca7334447d77d3bdbfb7f8dfcd5285c","bytes":5798,"mode":"0644"},{"path":"cloud/aws/ring-private/cloud-owner-association.mjs","sha256":"1069ce1cb7f88c48c0b0dd409b5c6a18514bf693fe10080589f7dafdff24804a","bytes":13706,"mode":"0644"},{"path":"cloud/aws/ring-private/cloud-owner-bootstrap.mjs","sha256":"4db3a181a143bc71b9c3bf631794dad9e7777d2c556b04cd4942032570a082ea","bytes":25606,"mode":"0644"},{"path":"cloud/aws/ring-private/completion-state.mjs","sha256":"cdce39255544b06e1ff0b6f388f5ff21dc351962b2f88aad5b16ec6c07c3f045","bytes":5156,"mode":"0644"},{"path":"cloud/aws/ring-private/config/runtime-contract.json","sha256":"7086739de73c32c22c299734b8f674b5703011eb06b2f493e302da1bca928653","bytes":9203,"mode":"0644"},{"path":"cloud/aws/ring-private/dynamo-event-ledger.mjs","sha256":"38ec5e35a5e22b369501da08d5ec431bfa4f20214d8f1f69bd9328b479f8bcb4","bytes":5014,"mode":"0644"},{"path":"cloud/aws/ring-private/dynamo-identity-authority-store.mjs","sha256":"d7dccda67f3bef968d7a3ff077d028552128739e49ffbd7f0aa67e498223fdb3","bytes":20974,"mode":"0644"},{"path":"cloud/aws/ring-private/dynamo-link-store.mjs","sha256":"a3fa21fdae7d7c641c6fc3b90fe035f65c4c881756760e08d1fdd031b68cd2cc","bytes":37495,"mode":"0644"},{"path":"cloud/aws/ring-private/dynamo-linked-device-authorizer.mjs","sha256":"5987f1733a94cbadeee70dcc33350303358e2e1f02e106badb6ee87907609c15","bytes":3339,"mode":"0644"},{"path":"cloud/aws/ring-private/existing-session-identity-authority.mjs","sha256":"51f0046bb77fd93a6b590118a56eed85483f718a4c0815fd1027bebe1fb52026","bytes":18502,"mode":"0644"},{"path":"cloud/aws/ring-private/handler.mjs","sha256":"669e7439a2c60c0160be10fb4bea03a68591c5a3718aa51509dea9c53f4c11a7","bytes":11695,"mode":"0644"},{"path":"cloud/aws/ring-private/identity-envelope.mjs","sha256":"55ad5641a0369d7cdb4128aac1680c96aabf420218e09b3717d37bd201be8498","bytes":6617,"mode":"0644"},{"path":"cloud/aws/ring-private/mac-command-proof-authority.mjs","sha256":"97885a8baf2110bbf3db389fd8911377000a381a24bc663ab29d75dc71577ef2","bytes":5680,"mode":"0644"},{"path":"cloud/aws/ring-private/mac-command-service.mjs","sha256":"09b2d9bed14c4f1d3e431509e9273eca6d191c8bf11e23c53c073ad941d6a3b0","bytes":4341,"mode":"0644"},{"path":"cloud/aws/ring-private/mac-command-store.mjs","sha256":"38730ddd6a89170b3beab17e84c2de0116bd72aa2f36212c231d008aec6bbae6","bytes":10107,"mode":"0644"},{"path":"cloud/aws/ring-private/mcp-production-ports.mjs","sha256":"78683a87d6082215d27a29f9192dc5eec265759c29f8961552fdaacb22cd9ee4","bytes":23221,"mode":"0644"},{"path":"cloud/aws/ring-private/mcp-rest-composition.mjs","sha256":"3b67fc7cea0907dc930702b95d9c517a3207ab715d54940befb4de3a68464aa8","bytes":18943,"mode":"0644"},{"path":"cloud/aws/ring-private/package-lock.json","sha256":"3ab52fc349e8e24e34ad41badb837958607467fc9c80962367e87510dadf8007","bytes":18744,"mode":"0644"},{"path":"cloud/aws/ring-private/package.json","sha256":"7e09e31601efaf09ea94012b0de82e0e5486153d140ef79c28c233f1a491d52a","bytes":368,"mode":"0644"},{"path":"cloud/aws/ring-private/projecting-identity-authority.mjs","sha256":"ac7ea70c5327793c77dbf22c8b5f859bf9e050d658aea1dfafe6e2a80c057561","bytes":3720,"mode":"0644"},{"path":"cloud/aws/ring-private/protocol.mjs","sha256":"6cbe347e155d2c6ec6362b78ed50de0623993419a2af4b59cb699a61681318df","bytes":3528,"mode":"0644"},{"path":"cloud/aws/ring-private/rest-v1-dispatcher.mjs","sha256":"59db03bd69adaa654d5f6101760ba60558305f2c496854b80108fdeab2ab93a4","bytes":8650,"mode":"0644"},{"path":"cloud/aws/ring-private/ring-client.mjs","sha256":"7053c7e30cb96e927818161661f16cefb07f6f53328ce1d0382b1aca4cc3d6bb","bytes":7915,"mode":"0644"},{"path":"cloud/aws/ring-private/ring-token-client.mjs","sha256":"ebd4c7e35b17edc922f5822812bdaca844a9fb577014bd6b11f3232316de6bc8","bytes":3514,"mode":"0644"},{"path":"cloud/aws/ring-private/runtime-composition.mjs","sha256":"36bde2da0ba949c430a66fd7a66064b98db56ef92748f75c2ab0a48d15a86262","bytes":6114,"mode":"0644"},{"path":"cloud/aws/ring-private/secret-loader.mjs","sha256":"11caa3fb3173b7b49b4e8920fc477253138ef1d0d134165e2d26ec93e1e80f05","bytes":16594,"mode":"0644"},{"path":"cloud/aws/ring-private/telegram-bot-client.mjs","sha256":"8def27114a618d98e4122f8fd2c5afbe555b285498f6370bcde5095853fc6358","bytes":8862,"mode":"0644"},{"path":"cloud/aws/ring-private/telegram-owner-authority.mjs","sha256":"d38f50c9a699d895bd56621abb96b8920e3aa1bd2e13fe036d9cdcb3c8e0902b","bytes":5577,"mode":"0644"},{"path":"cloud/aws/ring-private/telegram-webhook-handler.mjs","sha256":"118ac948383be234a4b24c4e7e84b55549937f186c7c608b34a839ccded1a737","bytes":6368,"mode":"0644"},{"path":"cloud/aws/ring-private/token-envelope.mjs","sha256":"32c6077b43a5b644b12b224998bceeb59375f8c4cf8372338134295eb49aaca4","bytes":10093,"mode":"0644"},{"path":"cloud/aws/ring-private/webhook-adapter.mjs","sha256":"d909032c3671c1625d2f1a8b0ef70d2d6e88921208e94242a892b81e3282c5a6","bytes":4151,"mode":"0644"},{"path":"cloud/aws/ring-private/webhook-http-handler.mjs","sha256":"7021d8abd31fd6e97a8885faac146ec726255e22dc640c1068c3765e412070e5","bytes":2326,"mode":"0644"},{"path":"cloud/aws/ring-private/workflow.mjs","sha256":"e93fdff9a542f2c640fbc50808da64e2abaf4e7479fd0b9c2ab0b0eaea1c11a7","bytes":20213,"mode":"0644"},{"path":"src/formal-runtime/mac-command-contract.mjs","sha256":"5cb4d08e133a6b0c19001f23b39dc18eded096aa663781284180b318f76c42de","bytes":7142,"mode":"0644"},{"path":"src/formal-runtime/mac-command-proof.mjs","sha256":"96d4ad25342db6bf9cf897b85affea044e1c66098ccb3fea7a2039b32f243e65","bytes":5316,"mode":"0644"},{"path":"src/formal-runtime/production-ports.mjs","sha256":"16f2beb02b59624b853c2a2cc77bd68ba56b1226a4ff933d0ce719b28acece90","bytes":4910,"mode":"0644"},{"path":"src/formal-runtime/protocol.mjs","sha256":"6f9e93b2671fb3f2c9e016cf9751c58078ee3602a7d2e5de8674b63d0797d5ce","bytes":5672,"mode":"0644"},{"path":"src/formal-runtime/request-authorization-policy.mjs","sha256":"6d63468400570a7f1c96796823f6ede9d686c29689051ac7a68c4fa61dc2ebbf","bytes":8406,"mode":"0644"},{"path":"src/formal-runtime/server-composition.mjs","sha256":"973ffe1b56842c59fbc71ae8efbffbaabb8aa0d989721df7ef20dfe2e6e5428b","bytes":6635,"mode":"0644"},{"path":"src/formal-runtime/stateless-wire.mjs","sha256":"261216187f8fa027b3cb0db71c1766ccfaa168b6b457c73692943ff5ac6f822c","bytes":13043,"mode":"0644"},{"path":"src/local_ring/components/oidc-jwt-verifier.mjs","sha256":"7a2d6200be6c0085563d6fddf07dc00aea05dd5af9574901a021134a86ec20a3","bytes":21076,"mode":"0644"}]);
const ENTRYPOINTS = Object.freeze(['cloud/aws/ring-private/handler.mjs', 'cloud/aws/ring-private/b02-layer-runtime.mjs']);
const MEMBERS = new Set(FIXED.map(pin => pin.path));
const EXTERNAL = new Set(['node:crypto', 'node:util', 'node:https', 'node:fs/promises', 'node:fs', '@aws-sdk/client-dynamodb',
  '@aws-sdk/client-kms', '@aws-sdk/client-secrets-manager']);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function deny(code) { throw new Error(code); }
function relative(value) {
  if (typeof value !== 'string' || !value || path.isAbsolute(value) || value.includes('\\') ||
    value.split('/').some(part => !part || part === '.' || part === '..') ||
    /[\u0000-\u001f\u007f]/u.test(value)) deny('path_denied');
  return value;
}
function pin(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
    Object.keys(value).sort().join(',') !== 'bytes,mode,path,sha256' ||
    !/^[a-f0-9]{64}$/u.test(value.sha256) || !Number.isSafeInteger(value.bytes) || value.bytes < 0 ||
    !/^0[0-7]{3}$/u.test(value.mode)) deny('pin_denied');
  relative(value.path);
  return value;
}
async function safePath(root, value, directory = false) {
  const parts = relative(value).split('/');
  let current = root;
  for (let index = 0; index < parts.length; index++) {
    current = path.join(current, parts[index]);
    const stat = await fs.lstat(current);
    if (stat.isSymbolicLink() || ((index < parts.length - 1 || directory) ?
      !stat.isDirectory() : !stat.isFile())) deny('file_type_denied');
  }
  return current;
}
async function readPinned(root, supplied) {
  const expected = pin(supplied);
  const name = await safePath(root, expected.path);
  const handle = await fs.open(name, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (!before.isFile() || before.dev !== after.dev || before.ino !== after.ino ||
      before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs ||
      bytes.length !== expected.bytes || (before.mode & 0o777).toString(8).padStart(4, '0') !== expected.mode ||
      sha(bytes) !== expected.sha256) deny('pin_mismatch');
    return bytes;
  } finally { await handle.close(); }
}
function imports(source) {
  const result = [];
  const pattern = /(?:^|\n)\s*import\s+(?:[^;'" ](?:[^;'"]*?)\s+from\s+)?['"]([^'"]+)['"]|import\s*\(\s*['"]([^'"]+)['"]\s*\)/gu;
  for (const match of source.matchAll(pattern)) result.push(match[1] ?? match[2]);
  for (const match of source.matchAll(/(?:^|\n)\s*export\s+(?:\*|\{[^}]*\})\s+from\s+['"]([^'"]+)['"]/gu)) result.push(match[1]);
  return result;
}
async function vendorInventory(root, roots) {
  const files = new Set();
  async function visit(rel) {
    const absolute = await safePath(root, rel, true);
    for (const entry of await fs.readdir(absolute, { withFileTypes: true })) {
      const name = rel + '/' + entry.name;
      if (entry.isSymbolicLink() || (!entry.isFile() && !entry.isDirectory())) deny('vendor_type_denied');
      if (entry.isDirectory()) await visit(name); else files.add(name);
    }
  }
  for (const rel of roots) await visit(rel);
  return [...files].sort();
}
function identity(stat) { return [stat.dev, stat.ino, stat.uid, stat.gid, stat.mode]; }
async function syncDirectory(name) {
  const handle = await fs.open(name, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await handle.sync(); } finally { await handle.close(); }
}
export async function buildRingPrivateArtifact({ root, output, sourcePins, vendorPins, failAfter = null } = {}) {
  if (typeof root !== 'string' || typeof output !== 'string' ||
    (failAfter !== null && (!Number.isSafeInteger(failAfter) || failAfter < 1))) deny('arguments_denied');
  root = path.resolve(root);
  const rootStat = await fs.lstat(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || await fs.realpath(root) !== root) deny('root_denied');
  output = path.resolve(output);
  const relativeOutput = path.relative(root, output).split(path.sep).join('/');
  relative(relativeOutput);
  if (!relativeOutput.startsWith('output/isolation/current_runs/') || path.basename(output) !== 'artifact') deny('output_denied');
  const parentRelative = path.posix.dirname(relativeOutput);
  const parent = await safePath(root, parentRelative, true);
  const parentIdentity = identity(await fs.lstat(parent));
  try { await fs.lstat(output); deny('output_exists'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!Array.isArray(sourcePins) || sourcePins.length !== MEMBERS.size || !Array.isArray(vendorPins) || !vendorPins.length) deny('members_denied');
  const supplied = new Map();
  for (const value of sourcePins) {
    pin(value);
    if (!MEMBERS.has(value.path) || supplied.has(value.path)) deny('members_denied');
    supplied.set(value.path, value);
  }
  for (const expected of FIXED) if (
    JSON.stringify(supplied.get(expected.path)) !== JSON.stringify(expected)) {
    const observed = supplied.get(expected.path);
    if (!observed || ['sha256', 'bytes', 'mode'].some(key => observed[key] !== expected[key])) deny('fixed_source_denied');
  }
  if (sourcePins.some(value => value.mode !== '0644')) deny('source_mode_denied');
  const contents = new Map();
  for (const value of [...sourcePins].sort((a, b) => a.path.localeCompare(b.path))) contents.set(value.path, await readPinned(root, value));
  const edges = [];
  for (const [name, bytes] of contents) if (name.endsWith('.mjs')) {
    for (const specifier of imports(bytes.toString('utf8'))) {
      if (specifier.startsWith('.')) {
        const target = path.posix.normalize(path.posix.join(path.posix.dirname(name), specifier));
        relative(target);
        if (!contents.has(target)) deny('closure_missing');
        edges.push({ from: name, specifier, to: target });
      } else if (!EXTERNAL.has(specifier)) deny('external_import_denied');
    }
  }
  const sourceCount = [...contents.keys()].filter(name => name.endsWith('.mjs')).length;
  if (sourceCount !== 50) deny('closure_count_denied');
  const reachable = new Set(ENTRYPOINTS);
  for (let changed = true; changed;) {
    changed = false;
    for (const edge of edges) if (reachable.has(edge.from) && !reachable.has(edge.to)) {
      reachable.add(edge.to); changed = true;
    }
  }
  if (reachable.size !== sourceCount || [...contents.keys()].some(name => name.endsWith('.mjs') && !reachable.has(name))) {
    deny('closure_unreachable');
  }
  const packageName = 'cloud/aws/ring-private/package.json';
  const lockName = 'cloud/aws/ring-private/package-lock.json';
  const pkg = JSON.parse(contents.get(packageName));
  const lock = JSON.parse(contents.get(lockName));
  if (lock.lockfileVersion !== 3 || JSON.stringify(pkg.dependencies) !== JSON.stringify(lock.packages[''].dependencies) ||
    Object.keys(pkg.dependencies).sort().join(',') !== '@aws-sdk/client-dynamodb,@aws-sdk/client-kms,@aws-sdk/client-secrets-manager') deny('package_lock_denied');
  const vendorRoots = Object.keys(lock.packages).filter(name => name.startsWith('node_modules/'))
    .map(name => 'cloud/aws/ring-private/' + relative(name)).sort();
  const vendorNames = await vendorInventory(root, vendorRoots);
  const vendorMap = new Map();
  for (const value of vendorPins) {
    pin(value);
    if (vendorMap.has(value.path) || !vendorNames.includes(value.path)) deny('vendor_members_denied');
    vendorMap.set(value.path, value);
  }
  if (vendorMap.size !== vendorNames.length) deny('vendor_members_denied');
  for (const name of vendorNames) contents.set(name, await readPinned(root, vendorMap.get(name)));
  for (const [name, info] of Object.entries(lock.packages)) if (name) {
    const packageBytes = contents.get('cloud/aws/ring-private/' + name + '/package.json');
    if (!packageBytes || JSON.parse(packageBytes).version !== info.version) deny('vendor_lock_mismatch');
  }
  const stage = path.join(parent, '.ring-artifact-' + randomUUID());
  await fs.mkdir(stage, { mode: 0o700 });
  const created = [];
  const written = [];
  let published = false;
  let count = 0;
  async function directory(rel) {
    let name = stage;
    for (const part of rel.split('/')) {
      name = path.join(name, part);
      try { await fs.mkdir(name, { mode: 0o755 }); created.push(path.relative(stage, name)); }
      catch (error) { if (error.code !== 'EEXIST' || !(await fs.lstat(name)).isDirectory()) throw error; }
    }
  }
  async function write(name, bytes, mode) {
    await directory(path.posix.dirname(name));
    const absolute = path.join(stage, name);
    const handle = await fs.open(absolute, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, Number.parseInt(mode, 8));
    const owned = await handle.stat();
    let failure = null;
    try { await handle.writeFile(bytes); await handle.chmod(Number.parseInt(mode, 8)); await handle.sync(); }
    catch (error) { failure = error; }
    try { await handle.close(); } catch (error) { failure ??= error; }
    if (failure !== null) {
      const current = await fs.lstat(absolute);
      if (!current.isFile() || current.isSymbolicLink() || current.dev !== owned.dev ||
        current.ino !== owned.ino || current.uid !== owned.uid || current.gid !== owned.gid) deny('partial_write_ownership_denied');
      await fs.unlink(absolute);
      throw failure;
    }
    written.push({ path: name, sha256: sha(bytes), bytes: bytes.length, mode });
    await readPinned(stage, written.at(-1));
    count++;
    if (failAfter === count) deny('injected_failure');
  }
  try {
    for (const [name, bytes] of [...contents].sort((a, b) => a[0].localeCompare(b[0])))
      await write(name, bytes, supplied.get(name)?.mode ?? vendorMap.get(name).mode);
    const receipt = { schema: 'ring-private-artifact-v1', admitted: false, sourceCount,
      baselineSourceCount: 38, missingImports: 0, entrypoints: ENTRYPOINTS, layerWrappersIncluded: false, sourcePins, vendorPins, edges };
    await write('artifact-manifest.json', Buffer.from(JSON.stringify(receipt, null, 2) + '\n'), '0600');
    for (const rel of [...created].reverse()) await syncDirectory(path.join(stage, rel));
    await syncDirectory(stage);
    if (JSON.stringify(identity(await fs.lstat(root))) !== JSON.stringify(identity(rootStat)) ||
      JSON.stringify(identity(await fs.lstat(parent))) !== JSON.stringify(parentIdentity)) deny('root_drift');
    await fs.rename(stage, output);
    published = true;
    await syncDirectory(parent);
    return Object.freeze({ result: 'PASS_ARTIFACT_BUILT', sourceCount, baselineSourceCount: 38,
      missingImports: 0, vendorFiles: vendorNames.length, copiedFiles: contents.size, admitted: false,
      manifestSha256: sha(Buffer.from(JSON.stringify(receipt, null, 2) + '\n')) });
  } catch (error) {
    const rollbackRoot = published ? output : stage;
    for (const item of [...written].reverse()) {
      await readPinned(rollbackRoot, item);
      await fs.unlink(path.join(rollbackRoot, item.path));
    }
    for (const rel of [...created].reverse()) await fs.rmdir(path.join(rollbackRoot, rel));
    await fs.rmdir(rollbackRoot);
    await syncDirectory(parent);
    throw error;
  }
}
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 6 || args[0] !== '--root' || args[2] !== '--out' || args[4] !== '--pins') deny('cli_denied');
    const root = path.resolve(args[1]);
    const pinsRelative = path.relative(root, path.resolve(args[5])).split(path.sep).join('/');
    if (!pinsRelative.startsWith('output/isolation/current_runs/')) deny('pins_path_denied');
    const pins = JSON.parse(await fs.readFile(await safePath(root, pinsRelative), 'utf8'));
    console.log(JSON.stringify(await buildRingPrivateArtifact({ root, output: args[3],
      sourcePins: pins.sourcePins, vendorPins: pins.vendorPins })));
  } catch {
    console.error(JSON.stringify({ result: 'RING_ARTIFACT_DENIED' }));
    process.exitCode = 1;
  }
}

