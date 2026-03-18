/* server.js — v5
   ① CSP mit unsafe-inline für Styles
   ② HSTS wenn TLS aktiv
   ③ Rate-Limit erhöht (Dummy-Traffic berücksichtigt)
   ④ Max 10 Peers pro Raum
   ⑤ Keine Logs, kein State außer Routing
*/
const https  = require('https');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const { WebSocketServer } = require('ws');

const PORT     = process.env.PORT || 3000;
const TLS_KEY  = path.join(__dirname, 'key.pem');
const TLS_CERT = path.join(__dirname, 'cert.pem');
let tlsOpts = null;
if (fs.existsSync(TLS_KEY) && fs.existsSync(TLS_CERT)) {
  tlsOpts = { key: fs.readFileSync(TLS_KEY), cert: fs.readFileSync(TLS_CERT) };
}

// Dynamischer Room-Salt: zufällig bei jedem Serverstart generiert.
// Verhindert Rainbow-Table-Angriffe auf Raumnamen.
// Salt wird NICHT gespeichert — nach Neustart sind alle Räume neu.
const ROOM_SALT = crypto.randomBytes(32);
function hashRoom(name) { return crypto.createHmac('sha256', ROOM_SALT).update(name).digest('hex'); }

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',  '.json': 'application/json',
  '.png':  'image/png',                '.svg': 'image/svg+xml'
};

// TLS-Pflicht: ohne Zertifikat wird gewarnt und nur auf localhost gestartet.
// Für Produktion: key.pem + cert.pem müssen vorhanden sein.
if (!tlsOpts) {
  process.stderr.write(
    '\n⚠  WARNUNG: Kein TLS-Zertifikat gefunden (key.pem / cert.pem).\n' +
    '   Der Server läuft im HTTP/WS-Modus — NUR für lokale Entwicklung.\n' +
    '   Für Produktion: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\n\n'
  );
}

const server = tlsOpts
  ? https.createServer(tlsOpts, handleReq)
  : require('http').createServer(handleReq);

// Immer auf 0.0.0.0 binden — in Container-Deployments übernimmt der
// Reverse-Proxy (nginx/Caddy) das TLS-Termination. Der interne Port
// ist ohnehin nicht von außen erreichbar.
const BIND_ADDR = '0.0.0.0';

function handleReq(req, res) {
  // Security Headers
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "connect-src 'self' wss: ws:",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'none'"
  ].join('; '));
  res.setHeader('X-Content-Type-Options',  'nosniff');
  res.setHeader('X-Frame-Options',         'DENY');
  res.setHeader('Referrer-Policy',         'no-referrer');
  res.setHeader('Permissions-Policy',      'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cache-Control',           'no-store');
  if (tlsOpts) res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');

  const url = req.url.split('?')[0];
  if (url === '/api/fingerprint') {
    const fp = tlsOpts ? crypto.createHash('sha256').update(tlsOpts.cert).digest('hex') : null;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ fingerprint: fp })); return;
  }
  const filePath = path.join(__dirname, url === '/' ? 'index.html' : url);
  if (!filePath.startsWith(path.resolve(__dirname))) { res.writeHead(403); res.end(); return; }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(data);
  });
}

const wss   = new WebSocketServer({ server });
const rooms = new Map();

// Rate-Limit pro Connection: 80 Nachrichten / 10s (Dummy-Traffic berücksichtigt)
const RATE_WINDOW = 10000, RATE_MAX = 80;
function allowRate(ws) {
  const now = Date.now();
  if (!ws._rt) ws._rt = [];
  ws._rt = ws._rt.filter(t => now - t < RATE_WINDOW);
  if (ws._rt.length >= RATE_MAX) return false;
  ws._rt.push(now); return true;
}

// IP-Rate-Limit: max 5 neue Verbindungen pro IP pro Minute (Join-Flood-Schutz)
const ipJoinMap = new Map();
const IP_JOIN_WINDOW = 60000, IP_JOIN_MAX = 5;
function allowIPJoin(ip) {
  const now = Date.now();
  if (!ipJoinMap.has(ip)) ipJoinMap.set(ip, []);
  const times = ipJoinMap.get(ip).filter(t => now - t < IP_JOIN_WINDOW);
  if (times.length >= IP_JOIN_MAX) return false;
  times.push(now);
  ipJoinMap.set(ip, times);
  return true;
}
// Cleanup IP-Map alle 5 Minuten
setInterval(() => {
  const now = Date.now();
  for (const [ip, times] of ipJoinMap) {
    const fresh = times.filter(t => now - t < IP_JOIN_WINDOW);
    if (fresh.length === 0) ipJoinMap.delete(ip);
    else ipJoinMap.set(ip, fresh);
  }
}, 300000);

const hbInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws._ok === false) return ws.terminate();
    ws._ok = false; ws.ping();
  });
}, 30000);
wss.on('close', () => clearInterval(hbInterval));

wss.on('connection', ws => {
  ws._ok = true; ws._rt = [];
  ws.on('pong', () => { ws._ok = true; });
  let roomId = null, anonId = null;

  ws.on('message', raw => {
    if (!allowRate(ws)) return;
    if (raw.length > 65536) { ws.close(1009, 'Too large'); return; }
    let msg; try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'join') {
      if (roomId) return; // Doppeltes Join verhindern
      if (!msg.room || typeof msg.room !== 'string' || msg.room.length > 128) return;
      if (!msg.anonId || typeof msg.anonId !== 'string' || msg.anonId.length > 80) return;
      // IP-Flood-Schutz
      const ip = (ws._socket?.remoteAddress || ws._req?.socket?.remoteAddress || 'unknown');
      if (!allowIPJoin(ip)) { ws.close(1008, 'Rate limit'); return; }
      roomId = hashRoom(msg.room); anonId = msg.anonId;
      if (!rooms.has(roomId)) rooms.set(roomId, new Map());
      const room = rooms.get(roomId);
      if (room.size >= 10) { ws.close(1013, 'Full'); return; }
      const peers = []; room.forEach((_, id) => peers.push({ a: id }));
      ws.send(JSON.stringify({ t: 'peers', p: peers }));
      room.set(anonId, { ws });
      const joined = JSON.stringify({ t: 'join', a: anonId });
      room.forEach((c, id) => { if (id !== anonId && c.ws.readyState === 1) c.ws.send(joined); });
      return;
    }

    if (msg.type === 'relay') {
      if (!roomId || !msg.to || msg.d === undefined) return;
      if (typeof msg.to !== 'string' || msg.to.length > 80) return;
      const room = rooms.get(roomId); if (!room) return;
      const target = room.get(msg.to);
      if (!target || target.ws.readyState !== 1) return;
      target.ws.send(JSON.stringify({ t: 'msg', d: msg.d })); return;
    }

    if (msg.type === 'broadcast') {
      if (!roomId || msg.d === undefined) return;
      const room = rooms.get(roomId); if (!room) return;
      room.forEach((c, id) => { if (id !== anonId && c.ws.readyState === 1) c.ws.send(JSON.stringify({ t: 'msg', d: msg.d })); });
      return;
    }
  });

  ws.on('close', () => {
    if (!roomId || !anonId) return;
    const room = rooms.get(roomId); if (!room) return;
    room.delete(anonId);
    if (room.size === 0) { rooms.delete(roomId); return; }
    const leave = JSON.stringify({ t: 'leave', a: anonId });
    room.forEach(c => { if (c.ws.readyState === 1) c.ws.send(leave); });
  });
});

server.listen(PORT, BIND_ADDR, () => {
  process.stdout.write(`Relay :${PORT} ${tlsOpts ? '(WSS/TLS ✓)' : '(WS — nur localhost!)'}\n`);
});
