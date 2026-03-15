/* ═══════════════════════════════════════════
   app.js — Hauptanwendung: WebSocket, Logik
   ═══════════════════════════════════════════ */

(() => {

  // ── State ──
  const myKeys = Crypto.generateKeyPair();
  const myId = uid();
  let socket = null;
  let room = null;
  let peers = new Map();
  let msgCount = 0;

  // ── Init ──
  $('mid').textContent = myId;
  UI.initLogToggle();
  UI.log(`ID: ${myId}`, 'ok');

  if (typeof nacl === 'undefined') {
    UI.log('TweetNaCl fehlt!', 'no');
  }

  window.onerror = (msg, src, line) => UI.log(`JS: ${msg} (${line})`, 'no');

  // ── Join ──
  $('rin').addEventListener('keydown', e => { if (e.key === 'Enter') joinRoom(); });
  $('jbtn').addEventListener('click', joinRoom);

  function joinRoom() {
    const r = $('rin').value.trim();
    if (!r) { $('rin').focus(); return; }
    UI.setJoinStatus('Verbinde...');
    UI.setJoinDisabled(true);
    room = r;
    connect(r);
  }

  // ── WebSocket ──
  function connect(r) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${location.host}`;
    UI.log(`WS → ${url}`, 'inf');

    try {
      socket = new WebSocket(url);
    } catch (e) {
      UI.log(`WS Error: ${e.message}`, 'no');
      UI.setJoinDisabled(false);
      return;
    }

    socket.onopen = () => {
      UI.log('WS ✓', 'ok');
      socket.send(JSON.stringify({
        type: 'join',
        room: r,
        userId: myId,
        pubKey: B64.enc(myKeys.publicKey)
      }));
      setTimeout(() => UI.showRoom(r), 500);
    };

    socket.onmessage = e => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      handleMessage(msg);
    };

    socket.onclose = ev => {
      UI.log(`WS closed (${ev.code})`, 'no');
      socket = null;
      $('est').textContent = 'Getrennt';
      $('est').style.color = 'var(--rd)';
      UI.addSystem('Verbindung verloren...');
      peers.clear();
      UI.updatePeers(peers);
      setTimeout(() => { if (room) connect(room); }, 3000);
    };

    socket.onerror = () => {
      UI.log('WS error', 'no');
      UI.setJoinStatus('Fehler!');
      UI.setJoinDisabled(false);
    };
  }

  // ── Message Handling ──
  function handleMessage(msg) {

    // Peer-Liste
    if (msg.type === 'peers') {
      UI.log(`← peers: ${msg.peers.length}`, msg.peers.length ? 'ok' : 'wr');
      for (const p of msg.peers) {
        if (!p.pubKey) continue;
        peers.set(p.id, {
          pubKey: B64.dec(p.pubKey),
          verified: false,
          nonces: new Set()
        });
        sendKeyExchange(p.id);
      }
      UI.updatePeers(peers);
    }

    // Neuer Peer
    if (msg.type === 'peer-joined') {
      const p = msg.peer;
      UI.log(`← peer-joined: ${p.id}`, 'ok');
      if (p.pubKey) sendKeyExchange(p.id);
      UI.updatePeers(peers);
    }

    // Daten-Nachricht
    if (msg.type === 'msg' && msg.data) {
      const d = msg.data;

      // Key Exchange
      if (d.type === 'kx') {
        UI.log(`← KX von ${msg.from}`, 'ok');
        if (d.pubKey) {
          peers.set(msg.from, {
            pubKey: B64.dec(d.pubKey),
            verified: false,
            nonces: new Set()
          });
          UI.addSystem(`${msg.from} verbunden`, true);
          UI.updatePeers(peers);
        }
      }

      // Verschlüsselte Nachricht
      if (d.type === 'enc') {
        const peer = peers.get(msg.from);
        if (!peer) { UI.log(`ENC von unbekanntem ${msg.from}`, 'wr'); return; }
        if (peer.nonces.has(d.n)) { UI.log('Replay!', 'no'); return; }

        const nonce = B64.dec(d.n);
        const ciphertext = B64.dec(d.c);
        const plaintext = Crypto.decrypt(ciphertext, nonce, peer.pubKey, myKeys.secretKey);

        if (plaintext === null) { UI.log('Decrypt failed!', 'no'); return; }

        peer.nonces.add(d.n);
        UI.addMessage(msg.from, plaintext, false);
        msgCount++;
        UI.updateStats(msgCount);
      }
    }

    // Peer hat verlassen
    if (msg.type === 'leave') {
      UI.log(`${msg.userId} left`);
      peers.delete(msg.userId);
      UI.updatePeers(peers);
      UI.addSystem(`${msg.userId} hat verlassen`);
    }
  }

  // ── Key Exchange senden ──
  function sendKeyExchange(peerId) {
    socket.send(JSON.stringify({
      type: 'msg',
      from: myId,
      to: peerId,
      data: {
        type: 'kx',
        pubKey: B64.enc(myKeys.publicKey)
      }
    }));
    UI.log(`KX → ${peerId}`, 'ok');
  }

  // ── Senden ──
  $('sbtn').addEventListener('click', sendMessage);
  $('min').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
  $('min').addEventListener('input', () => {
    $('min').style.height = 'auto';
    $('min').style.height = Math.min($('min').scrollHeight, 120) + 'px';
  });

  function sendMessage() {
    const text = $('min').value.trim();
    if (!text) return;
    if (!socket || socket.readyState !== 1) { UI.log('WS nicht bereit', 'no'); return; }
    if (peers.size === 0) { UI.addSystem('Kein Peer verbunden'); return; }

    let sent = 0;
    for (const [pid, peer] of peers) {
      try {
        const nonce = Crypto.randomNonce();
        const encrypted = Crypto.encrypt(text, nonce, peer.pubKey, myKeys.secretKey);
        if (!encrypted) continue;
        socket.send(JSON.stringify({
          type: 'msg', from: myId, to: pid,
          data: { type: 'enc', n: B64.enc(nonce), c: B64.enc(encrypted) }
        }));
        sent++;
      } catch (e) {
        UI.log(`Send error ${pid}: ${e.message}`, 'no');
      }
    }

    if (sent > 0) {
      UI.addMessage(myId, text, true);
      msgCount++;
      UI.updateStats(msgCount);
      $('min').value = '';
      $('min').style.height = 'auto';
    }
  }

  // ── Fingerprint Verification ──
  $('pl').addEventListener('click', e => {
    const btn = e.target.closest('.bv');
    if (!btn) return;
    const peerId = btn.dataset.p;
    const peer = peers.get(peerId);
    if (!peer) return;
    UI.showFingerprint(myKeys.publicKey, peer.pubKey, peerId);
  });

  $('fpy').addEventListener('click', () => {
    const peerId = $('fpm').dataset.peer;
    if (peerId && peers.has(peerId)) {
      peers.get(peerId).verified = true;
      UI.updatePeers(peers);
    }
    UI.hideFingerprint();
  });

  $('fpn').addEventListener('click', () => UI.hideFingerprint());

  UI.log('Bereit', 'ok');
})();
