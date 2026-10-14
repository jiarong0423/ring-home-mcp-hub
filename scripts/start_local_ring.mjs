import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const env = { PATH: process.env.PATH || '/usr/bin:/bin', LANG: 'en_US.UTF-8', TZ: 'UTC', HOME_MCP_LOCAL_RING_SIMULATION: '1' };
if (process.env.HOME_MCP_PORT !== undefined) env.HOME_MCP_PORT = process.env.HOME_MCP_PORT;
const child = spawn(process.execPath, ['src/server.mjs'], { cwd: root, env, stdio: 'inherit' });
child.on('error', () => { console.error('Local simulation startup failed'); process.exitCode = 1; });
child.on('exit', code => { process.exitCode = Number.isInteger(code) ? code : 1; });
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
