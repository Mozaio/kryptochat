const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml'
};

const server = http.createServer((req, res) => {
  const urlPath = req.url.split('?')[0];
  const filePath = path.join(__dirname, urlPath === '/' ? 'index.html' : urlPath);
  if (!filePath.startsWith(__dirname)) { res.writeHead(403); res.end(); return; }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
});

const wss = new WebSocketServer({ server });
const rooms = new Map();

function hashRoom(name) {
  return crypto.createHash('sha256').update('kc:' + name).digest('hex');
}

const ts = () => new Date().toISOString().slice(11, 19);
const log = m => console.log(`[${ts()}] ${m}`);

// Heartbeat: tote Verbindungen aufräumen
const interval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

wss.on('close', () => clearInterval(interval));

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  let roomId = null;
  let userId = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // ── JOIN ──
    if (msg.type === 'join') {
      if (!msg.room || !msg.userId) return;

      roomId = hashRoom(msg.room);
      userId = msg.userId;

      if (!rooms.has(roomId)) rooms.set(roomId, new Map());
      const room = rooms.get(roomId);

      // Bestehende Peers an neuen User
      const existingPeers = [];
      room.forEach(p => {
        existingPeers.push({ id: p.id, pubKey: p.pubKey });
      });
      ws.send(JSON.stringify({ type: 'peers', peers: existingPeers }));

      // Neuen User registrieren
      room.set(userId, { id: userId, pubKey: msg.pubKey || null, ws });

      // Bestehende Peers über neuen User informieren
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
      const room = rooms.get(roomId);
      if (!room) return;
      const target = room.get(msg.to);
      if (!target || target.ws.readyState !== 1) return;

      target.ws.send(JSON.stringify({
        type: 'msg',
        from: msg.from,
        data: msg.data
      }));
    }
  });

  ws.on('close', () => {
    if (!roomId || !userId) return;
    const room = rooms.get(roomId);
    if (!room) return;

    room.delete(userId);

    // Peers benachrichtigen
    const leaveMsg = JSON.stringify({ type: 'leave', userId });
    room.forEach(p => {
      if (p.ws.readyState === 1) p.ws.send(leaveMsg);
    });

    if (room.size === 0) rooms.delete(roomId);
    log(`${userId} left (${room.size} remain)`);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  log(`Server on port ${PORT}`);
});
