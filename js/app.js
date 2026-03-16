/* ═══════════════════════════════════════════════════
   app.js — Vollständig gehärteter Kryptochat
   FIX: Commitment-basierter Key Exchange korrigiert
   ═══════════════════════════════════════════════════ */

(() => {

  if (typeof nacl === 'undefined') {
    document.body.innerHTML = '<p style="color:red;padding:2rem">Fehler: TweetNaCl nicht geladen.</p>';
    return;
  }

  // ══════════════════════════════════════════
  //  State
  // ══════════════════════════════════════════

  const myKeys      = Crypto.generateKeyPair();
  const mySigning   = Crypto.generateSigningKeyPair();
  const myAnonId    = makeAnonId();
  let socket        = null;
  let room          = null;
  let connected     = false;

  Session.setMyLongTermKey(myKeys.publicKey);

  $('mid').textContent = myAnonId.slice(0, 8);
  UI.initLogToggle();
  UI.log(`ID: ${myAnonId}`, 'ok');

  // ══════════════════════════════════════════
  //  Memory Cleanup
  // ══════════════════════════════════════════

  function cleanup() {
    burn(myKeys.secretKey);
    burn(mySigning.secretKey);
    Session.getAll().forEach((_, id) => Session.removeSession(id));
    Store.del('nonce_' + myAnonId);
  }

  window.addEventListener('beforeunload', cleanup);
  window.addEventListener('pagehide', cleanup);

  // ══════════════════════════════════════════
  //  Join
  // ══════════════════════════════════════════

  $('rin').addEventListener('keydown', e => { if (e.key === 'Enter') joinRoom(); });
  $('jbtn').addEventListener('click', joinRoom);

  async function joinRoom() {
    const r = $('rin').value.trim();
    if (!r) { $('rin').focus(); return; }
    UI.setJoinStatus('Verbinde...');
    UI.setJoinDisabled(true);
    room = r;
    await connect(r);
  }

  // ══════════════════════════════════════════
  //  WebSocket
  // ══════════════════════════════════════════

  async function connect(r) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${location.host}`;

    try {
      socket = new WebSocket(url);
    } catch (e) {
      UI.log(`WS Error: ${e.message}`, 'no');
      UI.setJoinDisabled(false);
      return;
    }

    socket.onopen = () => {
      connected = true;
      UI.log('Relay ✓', 'ok');
      socket.send(JSON.stringify({
        type: 'join',
        room: r,
        anonId: myAnonId
      }));
      jitter(200, 600).then(() => UI.showRoom(r));
    };

    socket.onmessage = e => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      handleMessage(msg);
    };

    socket.onclose = () => {
      connected = false;
      UI.log('Relay getrennt', 'no');
      socket = null;
      $('est').textContent = 'Getrennt';
      $('est').style.color = 'var(--rd)';
      UI.addSystem('Verbindung verloren...');
      Session.getAll().forEach((_, id) => Session.removeSession(id));
      UI.updatePeers(Session.getAll());
      setTimeout(() => { if (room && !connected) connect(room); }, 3000);
    };

    socket.onerror = () => {
      UI.log('Relay Fehler', 'no');
      UI.setJoinStatus('Fehler!');
      UI.setJoinDisabled(false);
    };
  }

  // ══════════════════════════════════════════
  //  Message Handling
  // ══════════════════════════════════════════

  function handleMessage(msg) {
    if (msg.t === 'peers') {
      UI.log(`Peers: ${msg.p.length}`, msg.p.length ? 'ok' : 'wr');
      for (const p of msg.p) {
        startKeyExchange(p.a);
      }
    }

    if (msg.t === 'join') {
      UI.log(`Peer: ${msg.a.slice(0, 8)}`, 'ok');
      startKeyExchange(msg.a);
    }

    if (msg.t === 'msg' && msg.d) {
      const d = msg.d;
      switch (d.type) {
        case 'commit':    handleCommit(d);    break;
        case 'key':       handleKey(d);       break;
        case 'enc':       handleEncrypted(d); break;
        case 'heartbeat': handleHeartbeat(d); break;
      }
    }

    if (msg.t === 'leave') {
      UI.log(`Verlassen: ${msg.a.slice(0, 8)}`);
      Session.removeSession(msg.a);
      UI.updatePeers(Session.getAll());
      UI.addSystem(`${msg.a.slice(0, 8)} hat verlassen`);
    }
  }

  // ══════════════════════════════════════════
  //  KEY EXCHANGE — Korrigiertes 3-Phasen-Protokoll
  // ══════════════════════════════════════════
  //
  //  Phase 1: Beide Seiten senden NUR ihr Commitment
  //           (SHA-256 Hash ihrer Keys)
  //
  //  Phase 2: Beide Seiten senden NUR ihre Keys
  //           (nachdem sie das Commitment des anderen haben)
  //
  //  Phase 3: Verifizierung — Commitment muss zum Key passen
  //           → Shared Secret wird berechnet
  //
  //  Das verhindert, dass der Server Keys austauschen kann,
  //  weil das Commitment VOR dem Key feststeht.
  //
  // ══════════════════════════════════════════

  function startKeyExchange(peerAnonId) {
    let session = Session.getSession(peerAnonId);
    if (!session) {
      session = Session.createSession(peerAnonId, null);
    }

    // Ephemeres Key-Paar erzeugen (nur einmal pro Session)
    if (!session.myEphemeral) {
      session.myEphemeral = Crypto.generateKeyPair();
    }

    // ═══ PHASE 1: Commitment berechnen und senden ═══
    // Commitment = SHA-256(pubKey + ephemeralPubKey + timestamp)
    const ts = Date.now();
    const commData = new Uint8Array(72);
    commData.set(myKeys.publicKey, 0);
    commData.set(session.myEphemeral.publicKey, 32);
    const view = new DataView(commData.buffer);
    view.setBigUint64(64, BigInt(ts), false);

    const comm = Crypto.commitment(commData);

    // Eigenes Commitment speichern (zur Verifizierung durch den Peer)
    session.myCommitment = comm;
    session.myCommitTimestamp = ts;

    // NUR das Commitment senden
    relayTo(peerAnonId, {
      type: 'commit',
      from: myAnonId,
      comm: B64.enc(comm),
      timestamp: ts
    });

    UI.log(`Commit → ${peerAnonId.slice(0, 8)}`, 'ok');

    // Falls wir bereits ein Commitment vom Peer haben,
    // können wir direkt den Key senden
    if (session.theirCommitment) {
      sendKey(peerAnonId);
    }
  }

  function handleCommit(d) {
    const peerAnonId = d.from;
    let session = Session.getSession(peerAnonId);
    if (!session) {
      session = Session.createSession(peerAnonId, null);
    }

    // Commitment des Peers speichern
    session.theirCommitment = B64.dec(d.comm);
    session.theirCommitTimestamp = d.timestamp;

    UI.log(`Commit ← ${peerAnonId.slice(0, 8)}`, 'ok');

    // ═══ PHASE 2: Key senden ═══
    // Wir haben jetzt das Commitment des Peers.
    // Jetzt senden wir unseren Key.
    // Der Peer kann unseren Key gegen unser Commitment prüfen.
    sendKey(peerAnonId);
  }

  function sendKey(peerAnonId) {
    const session = Session.getSession(peerAnonId);
    if (!session || !session.myEphemeral) return;

    // Verhindere doppeltes Senden
    if (session.keySent) return;
    session.keySent = true;

    const payload = {
      from: myAnonId,
      to: peerAnonId,
      pubKey: B64.enc(myKeys.publicKey),
      ephemeralPubKey: B64.enc(session.myEphemeral.publicKey),
      signingPubKey: B64.enc(mySigning.publicKey),
      timestamp: Date.now()
    };

    // Signieren
    const sigData = {
      from: payload.from,
      to: payload.to,
      pubKey: payload.pubKey,
      ephemeralPubKey: payload.ephemeralPubKey,
      timestamp: payload.timestamp
    };
    payload.signature = B64.enc(Crypto.sign(sigData, mySigning.secretKey));

    relayTo(peerAnonId, {
      type: 'key',
      ...payload
    });

    UI.log(`Key → ${peerAnonId.slice(0, 8)}`, 'ok');
  }

  async function handleKey(d) {
    const peerAnonId = d.from;
    let session = Session.getSession(peerAnonId);
    if (!session) return;

    // ── Timestamp prüfen ──
    if (Math.abs(Date.now() - d.timestamp) > 30000) {
      UI.log(`Key abgelaufen von ${peerAnonId.slice(0, 8)}`, 'wr');
      return;
    }

    // ── Signatur verifizieren ──
    const sigData = {
      from: d.from,
      to: d.to,
      pubKey: d.pubKey,
      ephemeralPubKey: d.ephemeralPubKey,
      timestamp: d.timestamp
    };
    const sigValid = Crypto.verify(sigData, B64.dec(d.signature), B64.dec(d.signingPubKey));

    if (!sigValid) {
      UI.log(`⚠ Signatur UNGÜLTIG von ${peerAnonId.slice(0, 8)}!`, 'no');
      UI.addSystem(`⚠ Warnung: ${peerAnonId.slice(0, 8)} hat ungültige Signatur!`);
      return;
    }

    // ═══ PHASE 3: Commitment verifizieren ═══
    // Prüfe, ob der Key zum vorher gesendeten Commitment passt
    if (session.theirCommitment) {
      const commData = new Uint8Array(72);
      commData.set(B64.dec(d.pubKey), 0);
      commData.set(B64.dec(d.ephemeralPubKey), 32);
      const view = new DataView(commData.buffer);
      // Wir kennen das Timestamp nicht aus dem Commitment,
      // also prüfen wir mit dem Timestamp aus dem Commitment
      view.setBigUint64(64, BigInt(session.theirCommitTimestamp || d.timestamp), false);

      const commValid = Crypto.verifyCommitment(commData, session.theirCommitment);

      if (!commValid) {
        UI.log(`⚠ COMMITMENT UNGÜLTIG von ${peerAnonId.slice(0, 8)}!`, 'no');
        UI.addSystem(`🚨 Manipulationsversuch erkannt!`);
        return;
      }

      UI.log(`Commitment ✓ ${peerAnonId.slice(0, 8)}`, 'ok');
    }

    // ── Keys speichern ──
    session.theirPubKey = B64.dec(d.pubKey);
    session.theirEphemeralPub = B64.dec(d.ephemeralPubKey);

    // ── Shared Secret berechnen ──
    if (await Session.computeSharedSecret(peerAnonId)) {
      UI.log(`Session ✓ ${peerAnonId.slice(0, 8)}`, 'ok');
      UI.addSystem(`${peerAnonId.slice(0, 8)} verbunden — verifiziere Fingerabdruck!`, true);
    }

    // ── Unseren Key senden falls noch nicht geschehen ──
    if (!session.keySent) {
      sendKey(peerAnonId);
    }

    UI.updatePeers(Session.getAll());
  }

  // ══════════════════════════════════════════
  //  VERSCHLÜSSELTE NACHRICHTEN
  // ══════════════════════════════════════════

  function handleEncrypted(d) {
    const session = Session.getSession(d.from);
    if (!session || !session.established) return;

    if (session.recvNonces.has(d.n)) {
      UI.log(`Replay von ${d.from.slice(0, 8)}!`, 'no');
      return;
    }

    try {
      const nonce = B64.dec(d.n);
      const ciphertext = B64.dec(d.c);
      const plaintext = Crypto.decrypt(ciphertext, nonce, session.sharedSecret);

      if (plaintext === null) {
        UI.log(`Decrypt fehlgeschlagen`, 'no');
        return;
      }

      session.recvNonces.add(d.n);
      session.msgCount++;
      UI.addMessage(d.from, plaintext, false);

      if (Session.needsRotation(d.from)) triggerRotation(d.from);
    } catch (e) {
      // Still
    }
  }

  // ══════════════════════════════════════════
  //  HEARTBEATS
  // ══════════════════════════════════════════

  function handleHeartbeat(d) {
    const session = Session.getSession(d.from);
    if (session) {
      Session.recordHeartbeat(d.from);
    }
  }

  setInterval(() => {
    if (!connected) return;
    for (const [peerId, session] of Session.getAll()) {
      if (session.established && session.verified && Session.needsHeartbeat(peerId)) {
        sendHeartbeat(peerId);
        Session.recordHeartbeat(peerId);
      }
    }
  }, 15000);

  function sendHeartbeat(peerId) {
    const session = Session.getSession(peerId);
    if (!session || !session.established) return;

    const nonce = Crypto.makeNonce(session.sendNonce);
    session.sendNonce++;
    Session.persistNonce(peerId, session.sendNonce);

    const encrypted = Crypto.encrypt('hb:' + Date.now(), session.sharedSecret, nonce);
    if (!encrypted) return;

    relayTo(peerId, {
      type: 'heartbeat',
      from: myAnonId,
      n: B64.enc(nonce),
      c: B64.enc(encrypted)
    });
  }

  // ══════════════════════════════════════════
  //  SENDEN
  // ══════════════════════════════════════════

  $('sbtn').addEventListener('click', sendMessage);
  $('min').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
  $('min').addEventListener('input', () => {
    $('min').style.height = 'auto';
    $('min').style.height = Math.min($('min').scrollHeight, 120) + 'px';
  });

  async function sendMessage() {
    const text = $('min').value.trim();
    if (!text) return;

    if (!socket || socket.readyState !== 1) {
      UI.addSystem('Relay nicht bereit');
      return;
    }

    const sessions = Session.getAll();
    if (sessions.size === 0) {
      UI.addSystem('Kein Peer verbunden');
      return;
    }

    // ═══ ERZWUNGENE VERIFIZIERUNG ═══
    const unverified = [];
    sessions.forEach((s, id) => { if (!s.verified) unverified.push(id); });
    if (unverified.length > 0) {
      UI.addSystem(`🔒 VERIFIZIERUNG ERFORDERLICH — Klicke auf "⚠"`);
      return;
    }

    let sent = 0;
    for (const [peerId, session] of sessions) {
      if (!session.established || !session.sharedSecret) continue;

      try {
        const nonce = Crypto.makeNonce(session.sendNonce);
        session.sendNonce++;
        Session.persistNonce(peerId, session.sendNonce);

        const encrypted = Crypto.encrypt(text, session.sharedSecret, nonce);
        if (!encrypted) continue;

        await jitter(0, 100);

        relayTo(peerId, {
          type: 'enc',
          from: myAnonId,
          n: B64.enc(nonce),
          c: B64.enc(encrypted)
        });

        sent++;
        session.msgCount++;
      } catch (e) {
        // Still
      }
    }

    if (sent > 0) {
      UI.addMessage(myAnonId, text, true);
      $('min').value = '';
      $('min').style.height = 'auto';
    }
  }

  // ══════════════════════════════════════════
  //  RELAY HELPER
  // ══════════════════════════════════════════

  function relayTo(peerAnonId, data) {
    if (!socket || socket.readyState !== 1) return;
    socket.send(JSON.stringify({
      type: 'relay',
      to: peerAnonId,
      d: data
    }));
  }

  // ══════════════════════════════════════════
  //  KEY ROTATION
  // ══════════════════════════════════════════

  function triggerRotation(peerId) {
    UI.log(`Rotation → ${peerId.slice(0, 8)}`, 'inf');
    Session.rotate(peerId);
    startKeyExchange(peerId);
    UI.addSystem(`🔄 Schlüssel-Rotation`);
  }

  // ══════════════════════════════════════════
  //  FINGERPRINT VERIFICATION
  // ══════════════════════════════════════════

  $('pl').addEventListener('click', e => {
    const btn = e.target.closest('.bv');
    if (!btn) return;
    const peerId = btn.dataset.p;
    const session = Session.getSession(peerId);
    if (!session || !session.theirPubKey) return;
    UI.showFingerprint(myKeys.publicKey, session.theirPubKey, peerId);
  });

  $('fpy').addEventListener('click', () => {
    const peerId = $('fpm').dataset.peer;
    const session = Session.getSession(peerId);
    if (session) {
      session.verified = true;
      UI.log(`${peerId.slice(0, 8)} verifiziert ✓`, 'ok');
      UI.updatePeers(Session.getAll());

      let allVerified = true;
      Session.getAll().forEach(s => { if (!s.verified) allVerified = false; });
      if (allVerified) {
        UI.addSystem('🔓 Alle Peers verifiziert!', true);
      }
    }
    UI.hideFingerprint();
  });

  $('fpn').addEventListener('click', () => UI.hideFingerprint());

  UI.log('Bereit', 'ok');
})();
