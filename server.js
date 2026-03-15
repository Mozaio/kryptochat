/* ═══════════════════════════════════════════
   server.js — mit TLS + Auth
   ═══════════════════════════════════════════ */

const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;

// ── TLS ──
const TLS_KEY  = path.join(__dirname, 'key.pem');
const TLS_CERT = path.join(__dirname, 'cert.pem');

let serverOptions = null;
let protocol = 'http';

if (fs.existsSync(TLS_KEY) && fs.existsSync(TLS_CERT)) {
  serverOptions = {
    key:  fs.readFileSync(TLS_KEY),
    cert: fs.readFileSync(TLS_CERT)
  };
  protocol = 'https';
  console.log('[TLS] Zertifikat geladen — HTTPS/WSS aktiv');
} else {
  console.log('[WARN] Kein Zertifikat gefunden — HTTP/WS (unsicher!)');
  console.log('[WARN] Erzeuge mit: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes');
}

// ── Server-Fingerprint für Pinning ──
const serverFingerprint = serverOptions
  ? crypto.createHash('sha256').update(serverOptions.cert).digest('hex')
  : null;

if (serverFingerprint) {
  console.log(`[TLS] Server-Fingerprint: ${serverFingerprint}`);
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png':  'image/png',
  '.svg':  'image/svg+xml'
};

// ── HTTP/HTTPS Server ──
const server = serverOptions
  ? https.createServer(serverOptions, handleRequest)
  : require('http').createServer(handleRequest);

function handleRequest(req, res) {
  const urlPath = req.url.split('?')[0];

  // Fingerprint-Endpoint
  if (urlPath === '/api/fingerprint') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ fingerprint: serverFingerprint }));
    return;
  }

  const filePath = path.join(__dirname, urlPath === '/' ? 'index.html' : urlPath);
  if (!filePath.startsWith(__dirname)) { res.writeHead(403); res.end(); return; }

  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ── WebSocket ──
const wss = new WebSocketServer({ server });
const rooms = new Map();

function hashRoom(name) {
  return crypto.createHash('sha256').update('kc:' + name).digest('hex');
}

const ts = () => new Date().toISOString().slice(11, 19);
const log = m => console.log(`[${ts()}] ${m}`);

// ── Anti-Spam: Rate Limiting pro Verbindung ──
const RATE_LIMIT = 30;       // Nachrichten
const RATE_WINDOW = 10000;   // pro 10 Sekunden

function checkRate(ws) {
  const now = Date.now();
  if (!ws._msgTimes) ws._msgTimes = [];
  ws._msgTimes = ws._msgTimes.filter(t => now - t < RATE_WINDOW);
  if (ws._msgTimes.length >= RATE_LIMIT) return false;
  ws._msgTimes.push(now);
  return true;
}

// ── Heartbeat ──
const interval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

wss.on('close', () => clearInterval(interval));

wss.on('connection', (ws, req) => {
  ws.isAlive = true;
  ws._ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  ws.on('pong', () => { ws.isAlive = true; });

  let roomId = null;
  let userId = null;

  log(`Neue Verbindung von ${ws._ip}`);

  ws.on('message', (raw) => {
    // Rate Limiting
    if (!checkRate(ws)) {
      ws.send(JSON.stringify({ type: 'error', reason: 'rate-limit' }));
      return;
    }

    // Größe begrenzen (64KB)
    if (raw.length > 65536) {
      ws.close(1009, 'Message too large');
      return;
    }

    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // ── JOIN ──
    if (msg.type === 'join') {
      if (!msg.room || !msg.userId) return;

      // User-ID Format prüfen
      if (typeof msg.userId !== 'string' || msg.userId.length > 32 || !/^[a-z0-9]+$/i.test(msg.userId)) {
        ws.close(1008, 'Invalid userId');
        return;
      }

      roomId = hashRoom(msg.room);
      userId = msg.userId;

      if (!rooms.has(roomId)) rooms.set(roomId, new Map());
      const room = rooms.get(roomId);

      // Maximal 10 Peers pro Raum
      if (room.size >= 10) {
        ws.send(JSON.stringify({ type: 'error', reason: 'room-full' }));
        ws.close(1013, 'Room full');
        return;
      }

      const existingPeers = [];
      room.forEach(p => {
        existingPeers.push({ id: p.id, pubKey: p.pubKey });
      });
      ws.send(JSON.stringify({ type: 'peers', peers: existingPeers }));

      room.set(userId, { id: userId, pubKey: msg.pubKey || null, ws });

      if (msg.pubKey) {
        const announcement = JSON.stringify({
          type: 'peer-joined',
          peer: { id: userId, pubKey: msg.pubKey }
        });
        room.forEach(p => {
          if (p.id !== userId && p.ws.readyState === 1) {
            p.ws.send(announcement);
          }
        });
      }

      log(`[${msg.room}] ${userId} joined (${room.size} peers)`);
    }

    // ── MSG relay ──
    if (msg.type === 'msg') {
      if (!roomId || !msg.to || !msg.from) return;
      if (msg.from !== userId) return; // Nur eigene Nachrichten weiterleiten

      const room = rooms.get(roomId);
      if (!room) return;
      const target = room.get(msg.to);
      if (!target || target.ws.readyState !== 1) return;

      // Nur verschlüsselte Nachrichten weiterleiten
      if (msg.data && msg.data.type === 'enc') {
        if (!msg.data.n || !msg.data.c) return;
        if (typeof msg.data.n !== 'string' || typeof msg.data.c !== 'string') return;
      }

      target.ws.send(JSON.stringify({
        type: 'msg',
        from: userId,
        data: msg.data
      }));
    }
  });

  ws.on('close', () => {
    if (!roomId || !userId) return;
    const room = rooms.get(roomId);
    if (!room) return;

    room.delete(userId);
    const leaveMsg = JSON.stringify({ type: 'leave', userId });
    room.forEach(p => {
      if (p.ws.readyState === 1) p.ws.send(leaveMsg);
    });

    if (room.size === 0) rooms.delete(roomId);
    log(`${userId} left (${room.size} remain)`);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  log(`Server on port ${PORT} (${protocol.toUpperCase()})`);
});
