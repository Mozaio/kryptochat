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
  '.png': 'image/png'
};

const server = http.createServer((req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');

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
const activeRooms = new Map();

function hashRoom(name) {
  return crypto.createHash('sha256').update('kc_v2:' + name).digest('hex');
}

wss.on('connection', (ws) => {
  let roomId = null;
  let user = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'join') {
      roomId = hashRoom(msg.room);
      user = { id: msg.userId, pubKey: msg.pubKey, ratchetPub: msg.ratchetPub, ws };

      if (!activeRooms.has(roomId)) activeRooms.set(roomId, new Map());
      const room = activeRooms.get(roomId);

      const peers = [];
      room.forEach(p => peers.push({ id: p.id, pubKey: p.pubKey, ratchetPub: p.ratchetPub }));
      ws.send(JSON.stringify({ type: 'peers', peers }));

      room.set(user.id, user);
      console.log(`[${msg.room.substring(0, 8)}...] ${user.id} joined (${room.size} total)`);
    }

    if (msg.type === 'ratchet-msg') {
      const room = activeRooms.get(roomId);
      if (!room) { console.log('Room not found!'); return; }
      const target = room.get(msg.to);
      if (target && target.ws.readyState === 1) {
        target.ws.send(JSON.stringify({ type: 'ratchet-msg', from: msg.from, data: msg.data }));
        console.log(`Message routed: ${msg.from} -> ${msg.to}`);
      } else {
        console.log(`Target not found: ${msg.to} in room. Available: ${[...room.keys()].join(', ')}`);
      }
    }
  });

  ws.on('close', () => {
    if (!roomId || !user) return;
    const room = activeRooms.get(roomId);
    if (!room) return;
    room.delete(user.id);
    room.forEach(p => {
      if (p.ws.readyState === 1) p.ws.send(JSON.stringify({ type: 'peer-left', userId: user.id }));
    });
    if (room.size === 0) activeRooms.delete(roomId);
    console.log(`${user.id} left`);
  });
});

process.on('SIGTERM', () => { wss.clients.forEach(c => c.close()); process.exit(0); });
server.listen(PORT, '0.0.0.0', () => console.log(`Running on port ${PORT}`));
