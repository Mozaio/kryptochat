/* ═══════════════════════════════════════════
   app.js — Erweitert: Session-basierte E2E
   ═══════════════════════════════════════════ */

(() => {

  // ── State ──
  const myKeys = Crypto.generateKeyPair();
  const myId = uid();
  let socket = null;
  let room = null;
  let msgCount = 0;
  let lockedUntilVerified = true;  // ← SICHERHEIT: Nachrichten erst nach Verifizierung

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

      // Alle Sessions aufräumen
      Session.getAll().forEach((_, id) => Session.removeSession(id));
      UI.updatePeers(Session.getAll());

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

    // ── Peer-Liste ──
    if (msg.type === 'peers') {
      UI.log(`← peers: ${msg.peers.length}`, msg.peers.length ? 'ok' : 'wr');
      for (const p of msg.peers) {
        if (!p.pubKey) continue;
        const pubKey = B64.dec(p.pubKey);
        Session.createSession(p.id, pubKey);
        sendKeyExchange(p.id);
      }
      UI.updatePeers(Session.getAll());
    }

    // ── Neuer Peer ──
    if (msg.type === 'peer-joined') {
      const p = msg.peer;
      UI.log(`← peer-joined: ${p.id}`, 'ok');
      if (p.pubKey) {
        const pubKey = B64.dec(p.pubKey);
        Session.createSession(p.id, pubKey);
        sendKeyExchange(p.id);
      }
      UI.updatePeers(Session.getAll());
    }

    // ── Daten ──
    if (msg.type === 'msg' && msg.data) {
      const d = msg.data;

      // ── Key Exchange (signiert) ──
      if (d.type === 'kx') {
        handleKeyExchange(msg.from, d);
      }

      // ── Key Exchange Response ──
      if (d.type === 'kx-response') {
        handleKeyExchangeResponse(msg.from, d);
      }

      // ── Verschlüsselte Nachricht (mit Session Key) ──
      if (d.type === 'enc') {
        handleEncrypted(msg.from, d);
      }

      // ── Rotation Init ──
      if (d.type === 'rotate') {
        handleRotation(msg.from, d);
      }
    }

    // ── Peer verlassen ──
    if (msg.type === 'leave') {
      UI.log(`${msg.userId} left`);
      Session.removeSession(msg.userId);
      UI.updatePeers(Session.getAll());
      UI.addSystem(`${msg.userId} hat verlassen`);
    }
  }

  // ── Key Exchange senden (signiert + ephemeral) ──
  function sendKeyExchange(peerId) {
    const session = Session.getSession(peerId);
    if (!session) return;

    const timestamp = Date.now();
    const payload = {
      from: myId,
      to: peerId,
      pubKey: B64.enc(myKeys.publicKey),
      ephemeralPubKey: B64.enc(session.myEphemeral.publicKey),
      timestamp: timestamp
    };

    // Signieren
    Crypto.signKeyExchange(payload);

    socket.send(JSON.stringify({
      type: 'msg',
      from: myId,
      to: peerId,
      data: { type: 'kx', ...payload }
    }));

    UI.log(`KX (signed) → ${peerId}`, 'ok');
  }

  // ── Key Exchange bearbeiten ──
  function handleKeyExchange(from, d) {
    UI.log(`← KX von ${from}`, 'ok');

    // Timestamp prüfen (max 30 Sekunden alt)
    const age = Math.abs(Date.now() - d.timestamp);
    if (age > 30000) {
      UI.log(`KX von ${from} abgelaufen (${age}ms alt)`, 'wr');
      return;
    }

    // Signatur verifizieren
    if (!Crypto.verifyKeyExchange(d)) {
      UI.log(`⚠ KX Signatur von ${from} UNGÜLTIG!`, 'no');
      UI.addSystem(`⚠ Warnung: ${from} hat ungültige Signatur!`);
      return;
    }

    const pubKey = B64.dec(d.pubKey);
    const ephemeralPubKey = B64.dec(d.ephemeralPubKey);

    // Session erstellen oder aktualisieren
    let session = Session.getSession(from);
    if (!session) {
      session = Session.createSession(from, pubKey);
    }

    session.theirPubKey = pubKey;
    session.theirEphemeralPub = ephemeralPubKey;

    // Shared Secret berechnen
    if (Session.computeSharedSecret(session)) {
      UI.log(`Session mit ${from} etabliert`, 'ok');
      UI.addSystem(`${from} verbunden — verifiziere Fingerabdruck!`, true);
    }

    // Response senden (unseren Key zurück)
    sendKeyExchangeResponse(from);
    UI.updatePeers(Session.getAll());
  }

  // ── Key Exchange Response ──
  function sendKeyExchangeResponse(peerId) {
    const session = Session.getSession(peerId);
    if (!session) return;

    const payload = {
      from: myId,
      to: peerId,
      pubKey: B64.enc(myKeys.publicKey),
      ephemeralPubKey: B64.enc(session.myEphemeral.publicKey),
      timestamp: Date.now()
    };

    Crypto.signKeyExchange(payload);

    socket.send(JSON.stringify({
      type: 'msg',
      from: myId,
      to: peerId,
      data: { type: 'kx-response', ...payload }
    }));
  }

  function handleKeyExchangeResponse(from, d) {
    UI.log(`← KX-Response von ${from}`, 'ok');

    const age = Math.abs(Date.now() - d.timestamp);
    if (age > 30000) return;

    if (!Crypto.verifyKeyExchange(d)) {
      UI.log(`⚠ KX-Response Signatur von ${from} UNGÜLTIG!`, 'no');
      return;
    }

    const session = Session.getSession(from);
    if (!session) return;

    session.theirEphemeralPub = B64.dec(d.ephemeralPubKey);

    if (Session.computeSharedSecret(session)) {
      UI.log(`Session mit ${from} vollständig`, 'ok');
      UI.updatePeers(Session.getAll());
    }
  }

  // ── Verschlüsselte Nachricht empfangen ──
  function handleEncrypted(from, d) {
    const session = Session.getSession(from);
    if (!session || !session.established) {
      UI.log(`ENC von ${from}, aber keine Session`, 'wr');
      return;
    }

    // Replay-Schutz
    if (session.recvNonces.has(d.n)) {
      UI.log(`Replay-Angriff von ${from}!`, 'no');
      return;
    }

    try {
      const nonce = B64.dec(d.n);
      const ciphertext = B64.dec(d.c);
      const plaintext = Crypto.decryptWithSession(
        ciphertext, nonce, session.sharedSecret
      );

      if (plaintext === null) {
        UI.log(`Decrypt failed von ${from}`, 'no');
        return;
      }

      session.recvNonces.add(d.n);
      session.msgCount++;

      UI.addMessage(from, plaintext, false);
      msgCount++;
      UI.updateStats(msgCount);

      // Rotation prüfen
      if (Session.needsRotation(from)) {
        triggerRotation(from);
      }

    } catch (e) {
      UI.log(`Decrypt error von ${from}: ${e.message}`, 'no');
    }
  }

  // ── Senden (mit Session Key) ──
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
    if (!socket || socket.readyState !== 1) {
      UI.log('WS nicht bereit', 'no');
      return;
    }

    const sessions = Session.getAll();
    if (sessions.size === 0) {
      UI.addSystem('Kein Peer verbunden');
      return;
    }

    // ── SICHERHEIT: Prüfe ob alle Peers verifiziert sind ──
    if (lockedUntilVerified) {
      let unverified = [];
      sessions.forEach((s, id) => {
        if (!s.verified) unverified.push(id);
      });
      if (unverified.length > 0) {
        UI.addSystem(
          `🔒 Verifiziere zuerst den Fingerabdruck von: ${unverified.join(', ')}`
        );
        UI.addSystem(
          `Klicke auf "?" neben dem Peer-Namen in der Seitenleiste.`
        );
        return;
      }
    }

    let sent = 0;
    for (const [pid, session] of sessions) {
      if (!session.established || !session.sharedSecret) {
        UI.log(`Session mit ${pid} nicht bereit`, 'wr');
        continue;
      }

      try {
        const nonce = Crypto.monotonicNonce(session.sendNonce);
        session.sendNonce++;

        const encrypted = Crypto.encryptWithSession(
          text, session.sharedSecret, nonce
        );
        if (!encrypted) continue;

        socket.send(JSON.stringify({
          type: 'msg',
          from: myId,
          to: pid,
          data: {
            type: 'enc',
            n: B64.enc(nonce),
            c: B64.enc(encrypted)
          }
        }));
        sent++;
        session.msgCount++;

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

  // ── Key Rotation ──
  function triggerRotation(peerId) {
    UI.log(`Rotation → ${peerId}`, 'inf');
    const session = Session.getSession(peerId);
    if (!session) return;

    const theirPubKey = session.theirPubKey;
    Session.rotate(peerId, theirPubKey);
    sendKeyExchange(peerId);

    UI.addSystem(`🔄 Schlüssel-Rotation mit ${peerId}`);
  }

  // ── Fingerprint Verification ──
  $('pl').addEventListener('click', e => {
    const btn = e.target.closest('.bv');
    if (!btn) return;
    const peerId = btn.dataset.p;
    const session = Session.getSession(peerId);
    if (!session) return;
    UI.showFingerprint(myKeys.publicKey, session.theirPubKey, peerId);
  });

  $('fpy').addEventListener('click', () => {
    const peerId = $('fpm').dataset.peer;
    const session = Session.getSession(peerId);
    if (session) {
      session.verified = true;
      UI.log(`${peerId} verifiziert ✓`, 'ok');
      UI.updatePeers(Session.getAll());

      // Prüfe ob alle verifiziert
      let allVerified = true;
      Session.getAll().forEach(s => {
        if (!s.verified) allVerified = false;
      });
      if (allVerified) {
        lockedUntilVerified = false;
        UI.addSystem('🔓 Alle Peers verifiziert — Chat freigeschaltet!', true);
      }
    }
    UI.hideFingerprint();
  });

  $('fpn').addEventListener('click', () => UI.hideFingerprint());

  UI.log('Bereit', 'ok');
})();
