// The real home gateway: an ESP32-C3 running firmware/home_gateway, plugged into the Mac over USB. No Wi-Fi and no
// credentials; the hub still listens on 127.0.0.1 only. Off unless HOME_MCP_USB_GATEWAY=on.
// Which ports are tried: only USB serial ports whose USB device is made by Espressif (vendor id 0x303a, the ESP32-C3's
// built-in USB) according to macOS (ioreg), or the one port named in HOME_MCP_USB_GATEWAY_PORT. A monitor's control port,
// a phone or another USB modem is never opened. Of the Espressif boards, only one that first says hello with id
// "hmg-home-gateway" is used; another project's ESP32 is asked once for its identity and closed.
// Each line is one small JSON object; anything else is ignored.
//   {"t":"hello","id":"hmg-home-gateway","fw":"hmg-gw-1",...}  {"t":"beat","n":12,"upMs":...}  {"t":"button","press":"short"|"long","n":3}
import { execFile, execFileSync } from 'node:child_process';
import { closeSync, openSync, readdirSync, writeSync, createReadStream } from 'node:fs';

export const GATEWAY_ID = 'hmg-home-gateway';
export const ESPRESSIF_VID = 0x303a;
const PORT = /^cu\.usbmodem[0-9A-Za-z]{1,24}$/u;
const MAX_LINE = 256;

export function parseGatewayLine(line) {
  if (typeof line !== 'string' || line.length === 0 || line.length > MAX_LINE || line[0] !== '{') return null;
  let m; try { m = JSON.parse(line); } catch { return null; }
  if (!m || typeof m !== 'object' || Array.isArray(m)) return null;
  if (m.t === 'hello' && typeof m.id === 'string' && typeof m.fw === 'string') return { t: 'hello', id: m.id.slice(0, 40), fw: m.fw.slice(0, 40) };
  if (m.t === 'beat' && Number.isSafeInteger(m.n) && m.n >= 0) return { t: 'beat', n: m.n };
  if (m.t === 'button' && (m.press === 'short' || m.press === 'long') && Number.isSafeInteger(m.n)) return { t: 'button', press: m.press, n: m.n };
  return null;
}

// Real serial I/O on macOS: /bin/stty sets 115200 raw on the port, then the device file is read and written directly.
function realOpen(path) {
  return new Promise((resolve, reject) => {
    execFile('/bin/stty', ['-f', path, '115200', 'raw', '-echo', 'clocal'], { timeout: 3000 }, (error) => {
      if (error) { reject(error); return; }
      let fd;
      try { fd = openSync(path, 'r+'); } catch (e) { reject(e); return; }
      const stream = createReadStream(null, { fd, autoClose: false, highWaterMark: 1024 });
      resolve({
        onData: (fn) => stream.on('data', (b) => fn(b.toString('utf8'))),
        onEnd: (fn) => { stream.on('end', fn); stream.on('error', fn); },
        write: (s) => { try { writeSync(fd, s); } catch { /* port gone; onEnd follows */ } },
        close: () => { try { stream.destroy(); } catch { /* ignore */ } try { closeSync(fd); } catch { /* ignore */ } }
      });
    });
  });
}
// ioreg prints the USB tree; each serial port (IOCalloutDevice) sits below the USB device that owns it. Walk up from the
// port to the nearest USB device and keep the port only when that device's idVendor is Espressif.
export function espressifPortsFromIoreg(text) {
  const stack = []; const ports = [];
  for (const line of String(text).split('\n')) {
    const at = line.indexOf('+-o ');
    if (at >= 0) {
      while (stack.length && stack.at(-1).col >= at) stack.pop();
      stack.push({ col: at, usb: /<class IOUSBHostDevice[,>]/u.test(line), vid: null });
      continue;
    }
    const vid = line.match(/"idVendor" = (\d+)/u);
    if (vid && stack.length) { stack.at(-1).vid = Number(vid[1]); continue; }
    const port = line.match(/"IOCalloutDevice" = "(\/dev\/cu\.usbmodem[0-9A-Za-z]{1,24})"/u);
    if (port) {
      const owner = [...stack].reverse().find((n) => n.usb && n.vid !== null);
      if (owner?.vid === ESPRESSIF_VID && !ports.includes(port[1])) ports.push(port[1]);
    }
  }
  return ports;
}
const realList = () => {
  const named = process.env.HOME_MCP_USB_GATEWAY_PORT;
  if (named) return PORT.test(named.replace(/^\/dev\//u, '')) && readdirSync('/dev').includes(named.replace(/^\/dev\//u, '')) ? [named] : [];
  try { return espressifPortsFromIoreg(execFileSync('/usr/sbin/ioreg', ['-r', '-c', 'IOUSBHostDevice', '-l', '-w0'], { encoding: 'utf8', timeout: 5000, maxBuffer: 32 << 20 })); }
  catch { return []; }
};

export function createUsbGateway({ enabled = process.env.HOME_MCP_USB_GATEWAY === 'on', listPorts = realList, openPort = realOpen,
  onHello = () => {}, onBeat = () => {}, onButton = () => {}, onLost = () => {}, log = () => {}, helloTimeoutMs = 4000,
  scanEveryMs = 5000, setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
  let active = null;            // { path, port, fw }
  const probing = new Set();
  const rejected = new Set();   // ports that answered as something else; skipped until they disappear
  let timer = null; let stopped = !enabled;

  function attach(path, port) {
    let buf = ''; let identified = false;
    const helloTimer = setTimer(() => { if (!identified) { rejected.add(path); probing.delete(path); port.close(); } }, helloTimeoutMs);
    port.onData((chunk) => {
      buf += chunk; if (buf.length > 4 * MAX_LINE) buf = buf.slice(-MAX_LINE);
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).replace(/\r$/u, ''); buf = buf.slice(i + 1);
        const m = parseGatewayLine(line);
        if (!m) continue;
        if (!identified) {
          if (m.t !== 'hello') continue;
          if (m.id !== GATEWAY_ID || active) { clearTimer(helloTimer); rejected.add(path); probing.delete(path); port.close(); return; }
          identified = true; clearTimer(helloTimer); probing.delete(path);
          active = { path, port, fw: m.fw };
          log(`usb gateway: connected (${m.fw}) on ${path.slice(5)}`);
          onHello({ fw: m.fw });
          port.write('h');      // ask for one heartbeat now instead of waiting up to a minute
          continue;
        }
        if (m.t === 'beat') onBeat({ n: m.n });
        else if (m.t === 'button') { log(`usb gateway: button ${m.press}`); onButton({ press: m.press }); }
      }
    });
    port.onEnd(() => {
      clearTimer(helloTimer); probing.delete(path);
      if (active?.path === path) { active = null; log('usb gateway: disconnected'); onLost(); }
    });
    port.write('?');
  }

  async function scan() {
    if (stopped) return;
    const ports = listPorts();
    for (const r of [...rejected]) if (!ports.includes(r)) rejected.delete(r);
    if (active && !ports.includes(active.path)) { const a = active; active = null; a.port.close(); log('usb gateway: disconnected'); onLost(); }
    if (!active) {
      for (const path of ports) {
        if (rejected.has(path) || probing.has(path)) continue;
        probing.add(path);
        try { attach(path, await openPort(path)); } catch { probing.delete(path); rejected.add(path); }
        break;   // one probe at a time
      }
    }
    if (!stopped) timer = setTimer(() => { void scan(); }, scanEveryMs);
  }

  return Object.freeze({
    start: () => { if (enabled) { stopped = false; void scan(); } },
    stop: () => { stopped = true; if (timer) clearTimer(timer); active?.port.close(); active = null; },
    status: () => ({ enabled, connected: Boolean(active), fw: active?.fw ?? null }),
    scanNow: scan
  });
}
