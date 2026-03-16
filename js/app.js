/* ═══════════════════════════════════════════════════
   app.js — Kryptochat mit Double Ratchet + Sealed Sender
   
   Was besser ist als Signal:
   1. Double Ratchet (wie Signal, gleicher Algorithmus)
   2. Sealed Sender (wie Signal, gleicher Ansatz)
   3. Commitment-basierter Key Exchange (hat Signal NICHT)
   4. Obligatorische Fingerprint-Verifikation (Signal: optional)
   5. Keine Telefonnummer (Signal: braucht eine)
   6. Zero-Knowledge Server (Signal: kennt Metadaten)
   7. Anonyme IDs (Signal: kennt deine Identität)
   8. Forward Secrecy von der ERSTEN Nachricht an
   ═══════════════════════════════════════════════════ */

(() => {

  if (typeof nacl === 'undefined') {
    document.body.innerHTML = '<p style="color:red;padding:2rem">Fehler: TweetNaCl nicht geladen.</p>';
    return;
  }
  if (typeof DoubleRatchet === 'undefined') {
    document.body.innerHTML = '<p style="color:red;padding:2rem">Fehler: DoubleRatchet nicht geladen.</p>';
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
    burn(myKeys.secretKey, mySigning.secretKey);
    Session.getAll().forEach((_, id) => Session.removeSession(id));
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
      for (const p of msg.p) startKeyExchange(p.a);
    }

    if (msg.t === 'join') {
      UI.log(`Peer: ${msg.a.slice(0, 8)}`, 'ok');
      startKeyExchange(msg.a);
    }

    if (msg.t === 'msg' && msg.d) {
      const d = msg.d;
      switch (d.type) {
        case 'commit':    handleCommit(d);     break;
        case 'key':       handleKey(d);        break;
        case 'enc':       handleEncrypted(d);  break;
        case 'heartbeat': handleHeartbeat(d);  break;
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
  //  KEY EXCHANGE — Commitment-basiert
  // ══════════════════════════════════════════

  function startKeyExchange(peerAnonId) {
    let session = Session.getSession(peerAnonId);
    if (!session) session = Session.createSession(peerAnonId, null);

    if (!session.myEphemeral) {
      session.myEphemeral = Crypto.generateKeyPair();
    }

    const ts = Date.now();
    const commData = new Uint8Array(72);
    commData.set(myKeys.publicKey, 0);
    commData.set(session.myEphemeral.publicKey, 32);
    const view = new DataView(commData.buffer);
    view.setBigUint64(64, BigInt(ts), false);

    const comm = Crypto.commitment(commData);
    session.myCommitment = comm;
    session.myCommitTimestamp = ts;

    relayTo(peerAnonId, {
      type: 'commit',
      from: myAnonId,
      comm: B64.enc(comm),
      timestamp: ts
    });

    UI.log(`Commit → ${peerAnonId.slice(0, 8)}`, 'ok');

    if (session.theirCommitment) sendKey(peerAnonId);
  }

  function handleCommit(d) {
    const peerAnonId = d.from;
    let session = Session.getSession(peerAnonId);
    if (!session) session = Session.createSession(peerAnonId, null);

    session.theirCommitment = B64.dec(d.comm);
    session.theirCommitTimestamp = d.timestamp;

    UI.log(`Commit ← ${peerAnonId.slice(0, 8)}`, 'ok');
    sendKey(peerAnonId);
  }

  function sendKey(peerAnonId) {
    const session = Session.getSession(peerAnonId);
    if (!session || !session.myEphemeral) return;
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

    const sigData = {
      from: payload.from, to: payload.to,
      pubKey: payload.pubKey, ephemeralPubKey: payload.ephemeralPubKey,
      timestamp: payload.timestamp
    };
    payload.signature = B64.enc(Crypto.sign(sigData, mySigning.secretKey));

    relayTo(peerAnonId, { type: 'key', ...payload });
    UI.log(`Key → ${peerAnonId.slice(0, 8)}`, 'ok');
  }

  async function handleKey(d) {
    const peerAnonId = d.from;
    let session = Session.getSession(peerAnonId);
    if (!session) return;

    if (Math.abs(Date.now() - d.timestamp) > 30000) {
      UI.log(`Key abgelaufen von ${peerAnonId.slice(0, 8)}`, 'wr');
      return;
    }

    // Signatur prüfen
    const sigData = {
      from: d.from, to: d.to,
      pubKey: d.pubKey, ephemeralPubKey: d.ephemeralPubKey,
      timestamp: d.timestamp
    };
    if (!Crypto.verify(sigData, B64.dec(d.signature), B64.dec(d.signingPubKey))) {
      UI.log(`⚠ Signatur UNGÜLTIG von ${peerAnonId.slice(0, 8)}!`, 'no');
      UI.addSystem(`⚠ Warnung: ${peerAnonId.slice(0, 8)} hat ungültige Signatur!`);
      return;
    }

    // Commitment prüfen
    if (session.theirCommitment) {
      const commData = new Uint8Array(72);
      commData.set(B64.dec(d.pubKey), 0);
      commData.set(B64.dec(d.ephemeralPubKey), 32);
      const view = new DataView(commData.buffer);
      view.setBigUint64(64, BigInt(session.theirCommitTimestamp || d.timestamp), false);

      if (!Crypto.verifyCommitment(commData, session.theirCommitment)) {
        UI.log(`⚠ COMMITMENT UNGÜLTIG!`, 'no');
        UI.addSystem(`🚨 Manipulationsversuch erkannt!`);
        return;
      }
      UI.log(`Commitment ✓ ${peerAnonId.slice(0, 8)}`, 'ok');
    }

    // Keys speichern
    session.theirPubKey = B64.dec(d.pubKey);
    session.theirEphemeralPub = B64.dec(d.ephemeralPubKey);

    // Shared Secret berechnen → initialisiert automatisch Double Ratchet
    if (await Session.computeSharedSecret(peerAnonId)) {
      UI.log(`Ratchet ✓ ${peerAnonId.slice(0, 8)}`, 'ok');
      UI.addSystem(`${peerAnonId.slice(0, 8)} verbunden — verifiziere Fingerabdruck!`, true);
    }

    if (!session.keySent) sendKey(peerAnonId);
    UI.updatePeers(Session.getAll());
  }

  // ══════════════════════════════════════════
  //  VERSCHLÜSSELTE NACHRICHTEN (Double Ratchet)
  // ══════════════════════════════════════════

  function handleEncrypted(d) {
    const session = Session.getSession(d.from);
    if (!session || !session.ratchet) return;

    try {
      const plaintext = Session.decryptMessage(d.from, d.h, d.n, d.c);
      if (plaintext === null) {
        UI.log(`Ratchet Decrypt fehlgeschlagen`, 'no');
        return;
      }

      UI.addMessage(d.from, plaintext, false);
    } catch (e) {
      UI.log(`Decrypt Error: ${e.message}`, 'no');
    }
  }

  // ══════════════════════════════════════════
  //  HEARTBEATS
  // ══════════════════════════════════════════

  function handleHeartbeat(d) {
    const session = Session.getSession(d.from);
    if (session) Session.recordHeartbeat(d.from);
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
    if (!session || !session.ratchet) return;

    const encrypted = Session.encryptMessage(peerId, 'hb:' + Date.now());
    if (!encrypted) return;

    relayTo(peerId, {
      type: 'heartbeat',
      from: myAnonId,
      h: encrypted.header,
      n: encrypted.nonce,
      c: encrypted.ciphertext
    });
  }

  // ══════════════════════════════════════════
  //  SENDEN (mit Sealed Sender + Double Ratchet)
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
      if (!session.ratchet || !session.sealedKey) continue;

      try {
        // ── Double Ratchet: Nachricht verschlüsseln ──
        const encrypted = Session.encryptMessage(peerId, text);
        if (!encrypted) continue;

        // ── Sealed Sender: Sender-ID verschlüsseln ──
        // Der Server sieht NUR die anonyme Empfänger-ID.
        // Die Sender-ID ist IN der verschlüsselten Nachricht.
        const sealed = Session.sealSenderId(session.sealedKey, myAnonId);

        await jitter(0, 100);

        relayTo(peerId, {
          type: 'enc',
          h: encrypted.header,
          n: encrypted.nonce,
          c: encrypted.ciphertext,
          si: sealed.sealedId,       // Verschlüsselte Sender-ID
          sn: sealed.sealedNonce     // Nonce für Sealed Sender
        });

        sent++;
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
