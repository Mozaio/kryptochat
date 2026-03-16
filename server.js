/* ═══════════════════════════════════════════
   server.js — Trustless Relay
   - Keine Logs
   - Keine IPs
   - Kein Verständnis der Nachrichten
   - Nur im RAM, nichts auf Disk
   ═══════════════════════════════════════════ */

const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;

// ── TLS (optional, aber empfohlen) ──
const TLS_KEY  = path.join(__dirname, 'key.pem');
const TLS_CERT = path.join(__dirname, 'cert.pem');

let serverOptions = null;

if (fs.existsSync(TLS_KEY) && fs.existsSync(TLS_CERT)) {
  serverOptions = {
    key:  fs.readFileSync(TLS_KEY),
    cert: fs.readFileSync(TLS_CERT)
  };
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png':  'image/png',
  '.svg':  'image/svg+xml'
};

const server = serverOptions
  ? https.createServer(serverOptions, handleRequest)
  : require('http').createServer(handleRequest);

function handleRequest(req, res) {
  const urlPath = req.url.split('?')[0];

  // Fingerprint-Endpoint (für Client-Pinning)
  if (urlPath === '/api/fingerprint' && serverOptions) {
    const fp = crypto.createHash('sha256').update(serverOptions.cert).digest('hex');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ fingerprint: fp }));
    return;
  }

  // Kein Fingerprint bei HTTP
  if (urlPath === '/api/fingerprint') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ fingerprint: null }));
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

// Rooms: Map<roomId, Set<Connection>>
// Connection: { ws, anonId }
// Das ist ALLES, was der Server weiß:
//   - Welche anonyme ID gehört zu welcher WS-Verbindung
//   - In welchem Channel (gehasht) sind welche anonymen IDs
// Keine IPs, keine echten Namen, keine Logs.

const rooms = new Map();

function hashRoom(name) {
  return crypto.createHash('sha256').update('kc:' + name).digest('hex');
}

// ── Rate Limiting (anonym, nur pro Verbindung) ──
const RATE_LIMIT = 30;
const RATE_WINDOW = 10000;

function checkRate(ws) {
  const now = Date.now();
  if (!ws._times) ws._times = [];
  ws._times = ws._times.filter(t => now - t < RATE_WINDOW);
  if (ws._times.length >= RATE_LIMIT) return false;
  ws._times.push(now);
  return true;
}

// ── Heartbeat (ohne Logging) ──
const heartbeat = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws._alive === false) return ws.terminate();
    ws._alive = false;
    ws.ping();
  });
}, 30000);

wss.on('close', () => clearInterval(heartbeat));

wss.on('connection', (ws) => {
  ws._alive = true;
  ws.on('pong', () => { ws._alive = true; });

  let roomId = null;
  let anonId = null;

  ws.on('message', (raw) => {
    // Rate Limit
    if (!checkRate(ws)) return;

    // Größe begrenzen (128KB)
    if (raw.length > 131072) {
      ws.close(1009, 'Too large');
      return;
    }

    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // ── JOIN ──
    // Der Client sagt uns seinen gehashten Raumnamen und eine anonyme ID
    // Wir speichern NUR die anonyme ID — wir wissen nicht, wer das ist
    if (msg.type === 'join') {
      if (!msg.room || !msg.anonId) return;

      roomId = hashRoom(msg.room);
      anonId = msg.anonId;

      if (!rooms.has(roomId)) rooms.set(roomId, new Map());
      const room = rooms.get(roomId);

      // Max 20 Connections pro Raum
      if (room.size >= 20) {
        ws.close(1013, 'Full');
        return;
      }

      // Bestehende anonyme IDs an neuen Client
      const existing = [];
      room.forEach((conn, id) => {
        existing.push({ anonId: id });
      });
      ws.send(JSON.stringify({ type: 'peers', peers: existing }));

      // Neue Verbindung registrieren
      room.set(anonId, { ws });

      // Alle anderen über neuen Peer informieren
      const joined = JSON.stringify({ type: 'peer-joined', anonId });
      room.forEach((conn, id) => {
        if (id !== anonId && conn.ws.readyState === 1) {
          conn.ws.send(joined);
        }
      });

      return;
    }

    // ── RELAY ──
    // Der Server weiß nicht, was in msg.data steht.
    // Er leitet es einfach an msg.to weiter.
    // msg.to ist eine anonyme ID — der Server weiß nicht, wer das ist.
    if (msg.type === 'relay') {
      if (!roomId || !msg.to || !msg.data) return;

      // Sicherstellen, dass der Sender existiert
      if (!anonId) return;

      const room = rooms.get(roomId);
      if (!room) return;

      const target = room.get(msg.to);
      if (!target || target.ws.readyState !== 1) return;

      // Weiterleiten — ohne zu verstehen, was drin ist
      // Der Server kennt nicht mal den Sender
      target.ws.send(JSON.stringify({
        type: 'msg',
        data: msg.data
      }));

      return;
    }

    // ── BROADCAST (an alle im Raum, außer sich selbst) ──
    if (msg.type === 'broadcast') {
      if (!roomId || !msg.data) return;
      const room = rooms.get(roomId);
      if (!room) return;

      room.forEach((conn, id) => {
        if (id !== anonId && conn.ws.readyState === 1) {
          conn.ws.send(JSON.stringify({
            type: 'msg',
            data: msg.data
          }));
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

    // Leave-Broadcast
    const leave = JSON.stringify({ type: 'leave', anonId });
    room.forEach(conn => {
      if (conn.ws.readyState === 1) conn.ws.send(leave);
    });

    if (room.size === 0) rooms.delete(roomId);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  const proto = serverOptions ? 'HTTPS' : 'HTTP';
  console.log(`Relay server on port ${PORT} (${proto})`);
  console.log('No logging. No storage. No knowledge.');
});
