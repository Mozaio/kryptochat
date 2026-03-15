const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png':  'image/png',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon'
};

// ── HTTP Static File Server ─────────────────────────────────────────

const server = http.createServer((req, res) => {
  const urlPath = req.url.split('?')[0];
  const filePath = path.join(__dirname, urlPath === '/' ? 'index.html' : urlPath);

  // Directory traversal block
  if (!filePath.startsWith(__dirname)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }

    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Server error');
        return;
      }

      const ext = path.extname(filePath);
      res.writeHead(200, {
        'Content-Type': MIME[ext] || 'application/octet-stream',
        'Cache-Control': 'no-cache'
      });
      res.end(data);
    });
  });
});

// ── WebSocket Signaling Server ──────────────────────────────────────

const wss = new WebSocketServer({ server });

// rooms: Map<roomId, Map<userId, PeerEntry>>
// PeerEntry: { id, pubKey, ratchetPub, ws }
const rooms = new Map();

// Track which users are connected (for dedup/logging)
let connectionCount = 0;

function hashRoom(name) {
  return crypto.createHash('sha256').update('kc:' + name).digest('hex');
}

function log(msg) {
  const ts = new Date().toISOString().slice(11, 19);
  console.log(`[${ts}] ${msg}`);
}

wss.on('connection', (ws) => {
  connectionCount++;
  let roomId = null;
  let userId = null;

  log(`+ Connection #${connectionCount} (${wss.clients.size} total)`);

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    // ── JOIN ────────────────────────────────────────────────────────

    if (msg.type === 'join') {
      if (!msg.room || !msg.userId) return;

      roomId = hashRoom(msg.room);
      userId = msg.userId;

      if (!rooms.has(roomId)) {
        rooms.set(roomId, new Map());
      }
      const room = rooms.get(roomId);

      // 1) Sammle bestehende Peers (pubKey + ratchetPub)
      const existingPeers = [];
      room.forEach((peer) => {
        existingPeers.push({
          id: peer.id,
          pubKey: peer.pubKey,
          ratchetPub: peer.ratchetPub
        });
      });

      // 2) Peer-Liste an den neuen User
      ws.send(JSON.stringify({
        type: 'peers',
        peers: existingPeers
      }));

      // 3) Neuen User in der Room-Map registrieren
      room.set(userId, {
        id: userId,
        pubKey: msg.pubKey || null,
        ratchetPub: msg.ratchetPub || null,
        ws
      });

      // 4) ★ Alle bestehenden Peers über den neuen User informieren
      //    damit sie ebenfalls KX (Key Exchange) initiieren
      if (msg.pubKey && msg.ratchetPub) {
        const announcement = JSON.stringify({
          type: 'peer-joined',
          peer: {
            id: userId,
            pubKey: msg.pubKey,
            ratchetPub: msg.ratchetPub
          }
        });

        room.forEach((peer) => {
          if (peer.id !== userId && peer.ws.readyState === 1) {
            peer.ws.send(announcement);
          }
        });
      }

      log(`[${msg.room}] ${userId} joined (${room.size} peer${room.size !== 1 ? 's' : ''})`);
    }

    // ── MSG (KX + verschlüsselte Nachrichten) ───────────────────────

    if (msg.type === 'msg') {
      if (!roomId || !msg.to || !msg.from) return;

      const room = rooms.get(roomId);
      if (!room) return;

      const target = room.get(msg.to);
      if (!target) return;

      if (target.ws.readyState !== 1) return;

      target.ws.send(JSON.stringify({
        type: 'msg',
        from: msg.from,
        data: msg.data
      }));
    }
  });

  // ── CLOSE ────────────────────────────────────────────────────────

  ws.on('close', () => {
    if (!roomId || !userId) {
      log(`- Connection closed (no room) (${wss.clients.size} total)`);
      return;
    }

    const room = rooms.get(roomId);
    if (!room) return;

    room.delete(userId);

    // Verbleibenden Peers Bescheid sagen
    const leaveMsg = JSON.stringify({ type: 'leave', userId });
    room.forEach((peer) => {
      if (peer.ws.readyState === 1) {
        peer.ws.send(leaveMsg);
      }
    });

    // Leeren Raum aufräumen
    if (room.size === 0) {
      rooms.delete(roomId);
    }

    log(`${userId} left (${room.size} peer${room.size !== 1 ? 's' : ''} remain)`);
  });

  // ── ERROR ────────────────────────────────────────────────────────

  ws.on('error', (err) => {
    log(`WS error: ${err.message}`);
  });
});

// ── Start ───────────────────────────────────────────────────────────

server.listen(PORT, '0.0.0.0', () => {
  log(`Server läuft auf http://0.0.0.0:${PORT}`);
  log(`WS   läuft auf ws://0.0.0.0:${PORT}`);
});

// ── Graceful Shutdown ───────────────────────────────────────────────

process.on('SIGINT', () => {
  log('Shutdown...');
  wss.clients.forEach((ws) => ws.close(1001, 'Server shutting down'));
  server.close(() => process.exit(0));
});
