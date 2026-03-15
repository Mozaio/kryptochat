const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

// HTTP-Server — dient nur die statische Datei aus
const server = http.createServer((req, res) => {
  // Sicherheits-Header
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' https://cdn.jsdelivr.net; " +
    "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; " +
    "font-src https://fonts.gstatic.com; " +
    "connect-src 'self' ws: wss:; " +
    "img-src 'self' data:;"
  );

  const urlPath = req.url.split('?')[0];
  const filePath = path.join(__dirname, urlPath === '/' ? 'index.html' : urlPath);

  // Path Traversal Schutz
  if (!filePath.startsWith(__dirname)) {
    res.writeHead(403);
    res.end();
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(data);
  });
});

// WebSocket-Server
const wss = new WebSocketServer({ server });

// Raumname-Hash: Server sieht nie den echten Raumnamen
function hashRoom(name) {
  return crypto.createHash('sha256').update('kryptochat_room_v2:' + name).digest('hex');
}

// Räume: Map<hashedRoomId, Map<userId, userData>>
const activeRooms = new Map();

wss.on('connection', (ws) => {
  let currentRoomId = null;
  let currentUser = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {
      case 'join': {
        // Raumname wird gehasht — Server speichert nie Klartext
        currentRoomId = hashRoom(msg.room);

        currentUser = {
          id: msg.userId,
          pubKey: msg.pubKey,
          ratchetPub: msg.ratchetPub,
          ws
        };

        if (!activeRooms.has(currentRoomId)) {
          activeRooms.set(currentRoomId, new Map());
        }
        const room = activeRooms.get(currentRoomId);

        // Existierende Peers an neuen User senden
        const existingPeers = [];
        room.forEach((peer) => {
          existingPeers.push({
            id: peer.id,
            pubKey: peer.pubKey,
            ratchetPub: peer.ratchetPub
          });
        });
        ws.send(JSON.stringify({ type: 'peers', peers: existingPeers }));

        room.set(currentUser.id, currentUser);
        break;
      }

      case 'ratchet-msg': {
        const room = activeRooms.get(currentRoomId);
        if (!room) return;
        const target = room.get(msg.to);
        if (target && target.ws.readyState === 1) {
          target.ws.send(JSON.stringify({
            type: 'ratchet-msg',
            from: msg.from,
            data: msg.data
          }));
        }
        break;
      }
    }
  });

  ws.on('close', () => {
    if (!currentRoomId || !currentUser) return;
    const room = activeRooms.get(currentRoomId);
    if (!room) return;

    room.delete(currentUser.id);

    // Verbleibende Peers benachrichtigen
    room.forEach((peer) => {
      if (peer.ws.readyState === 1) {
        peer.ws.send(JSON.stringify({
          type: 'peer-left',
          userId: currentUser.id
        }));
      }
    });

    // Raum sofort löschen wenn leer — nichts bleibt gespeichert
    if (room.size === 0) {
      activeRooms.delete(currentRoomId);
    }
  });

  ws.on('error', () => {
    // Fehler ignorieren — keine Logs
  });
});

// Graceful Shutdown — alles aufräumen
function shutdown() {
  wss.clients.forEach(client => client.close());
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Starten
server.listen(PORT, '0.0.0.0', () => {
  // Nur beim Start melden, keine User-Daten loggen
});
