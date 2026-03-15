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
  '.json': 'application/json'
};

const server = http.createServer((req, res) => {
  const urlPath = req.url.split('?')[0];
  const filePath = path.join(__dirname, urlPath === '/' ? 'index.html' : urlPath);
  if (!filePath.startsWith(__dirname)) { res.writeHead(403); res.end(); return; }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(data);
  });
});

const wss = new WebSocketServer({ server });
const rooms = new Map();

function hashRoom(name) {
  return crypto.createHash('sha256').update('kc:' + name).digest('hex');
}

wss.on('connection', (ws) => {
  let roomId = null;
  let userId = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'join') {
      roomId = hashRoom(msg.room);
      userId = msg.userId;

      if (!rooms.has(roomId)) rooms.set(roomId, new Map());
      const room = rooms.get(roomId);

      // Existierende Peers an neuen User
      const peers = [];
      room.forEach((p) => {
        peers.push({ id: p.id, pubKey: p.pubKey, ratchetPub: p.ratchetPub });
      });
      ws.send(JSON.stringify({ type: 'peers', peers }));

      room.set(userId, { id: userId, pubKey: msg.pubKey, ratchetPub: msg.ratchetPub, ws });
      console.log(`[${msg.room}] ${userId} joined (${room.size} peers)`);
    }

    if (msg.type === 'msg') {
      const room = rooms.get(roomId);
      if (!room) return;
      const target = room.get(msg.to);
      if (target && target.ws.readyState === 1) {
        target.ws.send(JSON.stringify({
          type: 'msg',
          from: msg.from,
          data: msg.data
        }));
      }
    }
  });

  ws.on('close', () => {
    if (!roomId || !userId) return;
    const room = rooms.get(roomId);
    if (!room) return;
    room.delete(userId);
    room.forEach((p) => {
      if (p.ws.readyState === 1) {
        p.ws.send(JSON.stringify({ type: 'leave', userId }));
      }
    });
    if (room.size === 0) rooms.delete(roomId);
    console.log(`${userId} left`);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server on port ${PORT}`);
});
