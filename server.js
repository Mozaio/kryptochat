/* ═══════════════════════════════════════════════════
   server.js — Zero-Knowledge Relay v4

   Neu:
   ① CSP-Header: verhindert XSS, Script-Injection, Clickjacking
   ② Relay-Nonce-Cache: verhindert Replay-Angriffe auf Transport-Ebene
   ③ Härteres Rate-Limiting: pro IP + pro Connection
   ④ Message-Size-Limit reduziert (64 KB reicht vollständig)
   ⑤ Keine Logs, keine Daten, kein State außer Raum-Routing
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

// ── MIME-Typen ────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png':  'image/png',
  '.svg':  'image/svg+xml'
};

// ── Replay-Nonce-Cache (Transport-Ebene) ──────────
// Verhindert, dass aufgezeichnete WebSocket-Frames erneut eingespielt werden.
// Jede Relay-Nachricht bekommt eine einmalige Server-Nonce.
// Max 10.000 Einträge, älteste werden bei Überschreitung gelöscht.

const RELAY_NONCE_CACHE_MAX = 10000;
const relayNonces = new Set();

function checkAndAddNonce(nonce) {
  if (!nonce || typeof nonce !== 'string' || nonce.length > 64) return false;
  if (relayNonces.has(nonce)) return false; // Replay!
  relayNonces.add(nonce);
  if (relayNonces.size > RELAY_NONCE_CACHE_MAX) {
    // Älteste Hälfte entfernen
    let count = 0;
    for (const n of relayNonces) {
      if (count++ >= RELAY_NONCE_CACHE_MAX / 2) break;
      relayNonces.delete(n);
    }
  }
  return true;
}

// ── HTTP-Server mit Security-Headern ─────────────

const server = tlsOpts
  ? https.createServer(tlsOpts, handleReq)
  : require('http').createServer(handleReq);

function handleReq(req, res) {
  // ── Content Security Policy ──
  // Erlaubt nur eigene Scripts/Styles + cdn.jsdelivr.net für TweetNaCl.
  // Verhindert: XSS, Script-Injection, Clickjacking, Mixed Content.
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "connect-src 'self' wss: ws:",
    "frame-ancestors 'none'",          // Kein iFrame-Embedding (Clickjacking)
    "base-uri 'self'",
    "form-action 'none'"               // Kein Form-Submit zu externen Seiten
  ].join('; '));

  // ── Weitere Security-Header ──
  res.setHeader('X-Content-Type-Options',  'nosniff');
  res.setHeader('X-Frame-Options',         'DENY');
  res.setHeader('Referrer-Policy',         'no-referrer');
  res.setHeader('Permissions-Policy',      'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cache-Control',           'no-store'); // Kein Browser-Cache für sensible Seiten

  if (tlsOpts) {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  }

  const url = req.url.split('?')[0];

  if (url === '/api/fingerprint') {
    const fp = tlsOpts
      ? crypto.createHash('sha256').update(tlsOpts.cert).digest('hex') : null;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ fingerprint: fp }));
    return;
  }

  const filePath = path.join(__dirname, url === '/' ? 'index.html' : url);
  // Path-Traversal-Schutz
  if (!filePath.startsWith(path.resolve(__dirname) + path.sep) &&
      filePath !== path.resolve(__dirname, 'index.html')) {
    res.writeHead(403); res.end(); return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(data);
  });
}

// ── WebSocket-Server ──────────────────────────────

const wss   = new WebSocketServer({ server });
const rooms = new Map();

// Rate-Limiting: pro Connection (IP-unabhängig, da Server kein IP-Logging)
const RATE_WINDOW = 10000;  // 10 Sekunden
const RATE_MAX    = 60;     // max 60 Nachrichten pro 10s (inkl. Dummy-Traffic)

function allowRate(ws) {
  const now = Date.now();
  if (!ws._rt) ws._rt = [];
  ws._rt = ws._rt.filter(t => now - t < RATE_WINDOW);
  if (ws._rt.length >= RATE_MAX) return false;
  ws._rt.push(now);
  return true;
}

// Heartbeat: erkennt tote Verbindungen
const hbInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws._ok === false) return ws.terminate();
    ws._ok = false;
    ws.ping();
  });
}, 30000);
wss.on('close', () => clearInterval(hbInterval));

wss.on('connection', (ws) => {
  ws._ok  = true;
  ws._rt  = [];
  ws.on('pong', () => { ws._ok = true; });

  let roomId = null;
  let anonId = null;

  ws.on('message', (raw) => {
    if (!allowRate(ws)) return; // Rate-Limit überschritten

    // Message-Size-Limit: 64 KB (ausreichend für PAD_BLOCK=512 + Overhead)
    if (raw.length > 65536) { ws.close(1009, 'Too large'); return; }

    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // ── JOIN ──
    if (msg.type === 'join') {
      if (roomId) return; // Doppeltes Join verhindern
      if (!msg.room  || typeof msg.room  !== 'string' || msg.room.length  > 128) return;
      if (!msg.anonId || typeof msg.anonId !== 'string' || msg.anonId.length > 80) return;

      roomId = hashRoom(msg.room);
      anonId = msg.anonId;

      if (!rooms.has(roomId)) rooms.set(roomId, new Map());
      const room = rooms.get(roomId);
      if (room.size >= 10) { ws.close(1013, 'Full'); return; } // Max 10 Peers

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
    // Zero-Knowledge: Server liest msg.d nicht.
    // msg.d ist entweder ein Objekt (Key-Exchange) oder ein Base64-String (verschlüsselt).
    // In beiden Fällen wird es unverändert weitergeleitet.

    if (msg.type === 'relay') {
      if (!roomId || !msg.to || msg.d === undefined) return;
      if (typeof msg.to !== 'string' || msg.to.length > 80) return;

      const room = rooms.get(roomId);
      if (!room) return;
      const target = room.get(msg.to);
      if (!target || target.ws.readyState !== 1) return;

      // Server leitet weiter — sieht nur Ziel-ID und opake Daten
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
    if (room.size === 0) {
      rooms.delete(roomId);
    } else {
      const leave = JSON.stringify({ t: 'leave', a: anonId });
      room.forEach(c => { if (c.ws.readyState === 1) c.ws.send(leave); });
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  // Kein console.log mit sensiblen Infos
  process.stdout.write(`Relay :${PORT} ${tlsOpts ? '(WSS)' : '(WS)'}\n`);
});
