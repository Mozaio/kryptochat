/* ═══════════════════════════════════════════════════
   server.js — Zero-Knowledge Relay v2

   NEU: Opakes Relay-Envelope
   - Verschlüsselte Nachrichten (enc/heartbeat) kommen als
     base64-String in msg.d an — der Server sieht keinen type.
   - Key-Exchange-Nachrichten (commit/key) kommen als Objekt an.
   - In beiden Fällen: Server leitet weiter, liest Inhalt nicht.
   - Kompatibel mit beiden Formaten (String + Objekt).
   ═══════════════════════════════════════════════════ */

const https  = require('https');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;

const TLS_KEY  = path.join(__dirname, 'key.pem');
const TLS_CERT = path.join(__dirname, 'cert.pem');
let tlsOpts = null;
if (fs.existsSync(TLS_KEY) && fs.existsSync(TLS_CERT)) {
  tlsOpts = { key: fs.readFileSync(TLS_KEY), cert: fs.readFileSync(TLS_CERT) };
}

const ROOM_SALT = crypto.createHash('sha256').update('kc-v4-ratchet-salt').digest();
function hashRoom(name) {
  return crypto.createHmac('sha256', ROOM_SALT).update(name).digest('hex');
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png':  'image/png',
  '.svg':  'image/svg+xml'
};

const server = tlsOpts
  ? https.createServer(tlsOpts, handleReq)
  : require('http').createServer(handleReq);

function handleReq(req, res) {
  const url = req.url.split('?')[0];
  if (url === '/api/fingerprint') {
    const fp = tlsOpts
      ? crypto.createHash('sha256').update(tlsOpts.cert).digest('hex') : null;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ fingerprint: fp }));
    return;
  }
  const filePath = path.join(__dirname, url === '/' ? 'index.html' : url);
  if (!filePath.startsWith(__dirname)) { res.writeHead(403); res.end(); return; }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(data);
  });
}

const wss   = new WebSocketServer({ server });
const rooms = new Map();

// Rate Limiting
const RATE_WINDOW = 10000;
const RATE_MAX    = 50;
function allowRate(ws) {
  const now = Date.now();
  if (!ws._rt) ws._rt = [];
  ws._rt = ws._rt.filter(t => now - t < RATE_WINDOW);
  if (ws._rt.length >= RATE_MAX) return false;
  ws._rt.push(now);
  return true;
}

// Heartbeat
const hb = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws._ok === false) return ws.terminate();
    ws._ok = false;
    ws.ping();
  });
}, 30000);
wss.on('close', () => clearInterval(hb));

wss.on('connection', (ws) => {
  ws._ok = true;
  ws.on('pong', () => { ws._ok = true; });

  let roomId = null;
  let anonId = null;

  ws.on('message', (raw) => {
    if (!allowRate(ws)) return;
    if (raw.length > 262144) { ws.close(1009, 'Too large'); return; }

    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // ── JOIN ──
    if (msg.type === 'join') {
      if (!msg.room || !msg.anonId || typeof msg.anonId !== 'string' || msg.anonId.length > 64) return;

      roomId = hashRoom(msg.room);
      anonId = msg.anonId;

      if (!rooms.has(roomId)) rooms.set(roomId, new Map());
      const room = rooms.get(roomId);
      if (room.size >= 20) { ws.close(1013, 'Full'); return; }

      const peers = [];
      room.forEach((_, id) => peers.push({ a: id }));
      ws.send(JSON.stringify({ t: 'peers', p: peers }));

      room.set(anonId, { ws });

      const joined = JSON.stringify({ t: 'join', a: anonId });
      room.forEach((c, id) => {
        if (id !== anonId && c.ws.readyState === 1) c.ws.send(joined);
      });
      return;
    }

    // ── RELAY ──
    // msg.d ist entweder:
    //   - ein Objekt (Key-Exchange: commit/key) → wird als JSON weitergeleitet
    //   - ein String (opakes Envelope: enc/heartbeat) → wird direkt weitergeleitet
    // Der Server liest msg.d in beiden Fällen NICHT — er leitet nur weiter.
    // Zero-Knowledge: Server kennt weder Sender noch Inhalt.

    if (msg.type === 'relay') {
      if (!roomId || !msg.to || msg.d === undefined) return;
      const room = rooms.get(roomId);
      if (!room) return;
      const target = room.get(msg.to);
      if (!target || target.ws.readyState !== 1) return;

      // Weiterleitung: d unverändert übernehmen (Objekt oder String)
      target.ws.send(JSON.stringify({ t: 'msg', d: msg.d }));
      return;
    }

    // ── BROADCAST ──
    if (msg.type === 'broadcast') {
      if (!roomId || msg.d === undefined) return;
      const room = rooms.get(roomId);
      if (!room) return;
      room.forEach((c, id) => {
        if (id !== anonId && c.ws.readyState === 1) {
          c.ws.send(JSON.stringify({ t: 'msg', d: msg.d }));
        }
      });
      return;
    }
  });

  ws.on('close', () => {
    if (!roomId || !anonId) return;
    const room = rooms.get(roomId);
    if (!room) return;
    room.delete(anonId);
    const leave = JSON.stringify({ t: 'leave', a: anonId });
    room.forEach(c => { if (c.ws.readyState === 1) c.ws.send(leave); });
    if (room.size === 0) rooms.delete(roomId);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Relay on :${PORT} (${tlsOpts ? 'WSS' : 'WS'})`);
});
