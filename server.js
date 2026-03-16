/* ═══════════════════════════════════════════════════
   server.js — Trustless Relay (vollständig gehärtet)
   - Keine Logs, kein Storage, kein Verständnis
   - Raumnamen werden mit Salt gehasht
   - Keine IPs protokolliert
   - Rate-Limiting anonym
   ═══════════════════════════════════════════════════ */

const https   = require('https');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;

// ── TLS ──
const TLS_KEY  = path.join(__dirname, 'key.pem');
const TLS_CERT = path.join(__dirname, 'cert.pem');
let tlsOpts = null;
if (fs.existsSync(TLS_KEY) && fs.existsSync(TLS_CERT)) {
  tlsOpts = {
    key:  fs.readFileSync(TLS_KEY),
    cert: fs.readFileSync(TLS_CERT)
  };
}

// ── Raum-Hash mit Salt (Server sieht nie Klartext-Raumnamen) ──
const ROOM_SALT = crypto.createHash('sha256').update('kc-relay-v3-salt').digest();

function hashRoom(name) {
  return crypto.createHmac('sha256', ROOM_SALT).update(name).digest('hex');
}

// ── Static Files ──
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
      ? crypto.createHash('sha256').update(tlsOpts.cert).digest('hex')
      : null;
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

// ── WebSocket ──
const wss = new WebSocketServer({ server });

// rooms: Map<hashRoomId, Map<anonId, { ws }>>
// Das ist ALLES, was der Server im RAM hält.
const rooms = new Map();

// ── Anonymes Rate-Limiting ──
const RATE_WINDOW = 10000;
const RATE_MAX    = 40;

function allowRate(ws) {
  const now = Date.now();
  if (!ws._rt) ws._rt = [];
  ws._rt = ws._rt.filter(t => now - t < RATE_WINDOW);
  if (ws._rt.length >= RATE_MAX) return false;
  ws._rt.push(now);
  return true;
}

// ── Heartbeat (ohne Logging) ──
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
    if (raw.length > 131072) { ws.close(1009, 'Too large'); return; }

    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // ── JOIN ──
    if (msg.type === 'join') {
      if (!msg.room || !msg.anonId || typeof msg.anonId !== 'string' || msg.anonId.length > 64) return;

      roomId = hashRoom(msg.room);
      anonId = msg.anonId;

      if (!rooms.has(roomId)) rooms.set(roomId, new Map());
      const room = rooms.get(roomId);

      if (room.size >= 20) { ws.close(1013, 'Room full'); return; }

      // Bestehende Peers mitteilen (nur anonyme IDs)
      const peers = [];
      room.forEach((_, id) => peers.push({ a: id }));
      ws.send(JSON.stringify({ t: 'peers', p: peers }));

      room.set(anonId, { ws });

      // Neuen Peer ankündigen
      const joined = JSON.stringify({ t: 'join', a: anonId });
      room.forEach((c, id) => {
        if (id !== anonId && c.ws.readyState === 1) c.ws.send(joined);
      });
      return;
    }

    // ── RELAY (anonym, verschlüsselt) ──
    if (msg.type === 'relay') {
      if (!roomId || !msg.to || !msg.d) return;
      const room = rooms.get(roomId);
      if (!room) return;
      const target = room.get(msg.to);
      if (!target || target.ws.readyState !== 1) return;

      // Server leitet weiter — ohne zu wissen, was drin ist
      target.ws.send(JSON.stringify({
        t: 'msg',
        d: msg.d
      }));
      return;
    }

    // ── BROADCAST (an alle im Raum, anonym) ──
    if (msg.type === 'broadcast') {
      if (!roomId || !msg.d) return;
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
    room.forEach(c => {
      if (c.ws.readyState === 1) c.ws.send(leave);
    });

    if (room.size === 0) rooms.delete(roomId);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Relay on :${PORT} (${tlsOpts ? 'WSS' : 'WS'})`);
});
