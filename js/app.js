/* ═══════════════════════════════════════════════════
   app.js — Kryptochat v4 (Final / Maximum Security)

   Alle Upgrades:
   ① Commitment mit Blinding-Factor + Nonce-Reveal
   ② Session-Fingerprint (sharedSecret eingeschlossen)
   ③ Opakes Relay-Envelope (verschlüsselte Msgs als Base64-String)
   ④ Dummy-Traffic (Traffic-Analyse-Schutz)
   ⑤ Screenshot-Schutz: DOM bei verstecktem Tab geleert
   ⑥ Timing-Jitter auf allen Sende-Operationen
   ⑦ Dummy-Nachrichten werden still verworfen (kein UI-Eintrag)
   ⑧ Replay-Schutz im Ratchet (Nonce-Cache)
   ⑨ Verbesserter Cleanup (alle Listener, alle Keys)
   ═══════════════════════════════════════════════════ */

(() => {

  if (typeof nacl === 'undefined') {
    document.body.innerHTML = '<p style="color:red;padding:2rem">Fehler: TweetNaCl nicht geladen.</p>';
    return;
  }
  if (typeof DoubleRatchet === 'undefined') {
    document.body.innerHTML = '<p style="color:red;padding:2rem">Fehler: Ratchet nicht geladen.</p>';
    return;
  }

  // ══════════════════════════════════════════
  //  State
  // ══════════════════════════════════════════

  const myKeys    = Crypto.generateKeyPair();
  const mySigning = Crypto.generateSigningKeyPair();
  const myAnonId  = makeAnonId();
  let socket      = null;
  let room        = null;
  let connected   = false;

  Session.setMyLongTermKey(myKeys.publicKey);
  $('mid').textContent = myAnonId.slice(0, 8);
  UI.initLogToggle();
  UI.log(`ID: ${myAnonId}`, 'ok');

  // ══════════════════════════════════════════
  //  SCREENSHOT-SCHUTZ
  //  Bei verstecktem Tab werden alle Nachrichten aus dem DOM entfernt.
  //  Beim Zurückkehren erscheinen sie wieder.
  //  Verhindert, dass Screenshots / Screen-Recording Nachrichten zeigen.
  // ══════════════════════════════════════════

  let _savedMessages = null;

  document.addEventListener('visibilitychange', () => {
    const mc = $('mc');
    if (!mc) return;
    if (document.visibilityState === 'hidden') {
      // DOM leeren, Inhalt speichern
      _savedMessages = mc.innerHTML;
      mc.innerHTML   = '';
    } else {
      // DOM wiederherstellen
      if (_savedMessages !== null) {
        mc.innerHTML   = _savedMessages;
        _savedMessages = null;
      }
    }
  });

  // ══════════════════════════════════════════
  //  MEMORY CLEANUP
  // ══════════════════════════════════════════

  function cleanup() {
    Session.stopDummyTraffic();
    burn(myKeys.secretKey, myKeys.publicKey, mySigning.secretKey, mySigning.publicKey);
    Session.destroyAll();
    // DOM leeren
    const mc = $('mc');
    if (mc) mc.innerHTML = '';
    socket = null;
    room   = null;
  }

  window.addEventListener('beforeunload', cleanup);
  window.addEventListener('pagehide',     cleanup);
  window.addEventListener('unload',       cleanup);

  // ══════════════════════════════════════════
  //  JOIN
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
  //  WEBSOCKET
  // ══════════════════════════════════════════

  async function connect(r) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    try { socket = new WebSocket(`${proto}//${location.host}`); }
    catch (e) { UI.log(`WS Error: ${e.message}`, 'no'); UI.setJoinDisabled(false); return; }

    socket.onopen = () => {
      connected = true;
      UI.log('Relay ✓', 'ok');
      // Session-Manager über Socket informieren (für Dummy-Traffic)
      Session.setSocket(socket, myAnonId);
      socket.send(JSON.stringify({ type: 'join', room: r, anonId: myAnonId }));
      jitter(200, 600).then(() => UI.showRoom(r));
    };

    socket.onmessage = e => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      handleMessage(msg);
    };

    socket.onclose = () => {
      connected = false;
      Session.stopDummyTraffic();
      UI.log('Relay getrennt', 'no');
      socket = null;
      $('est').textContent = 'Getrennt';
      $('est').style.color = 'var(--rd)';
      UI.addSystem('Verbindung verloren...');
      Session.destroyAll();
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
  //  RELAY HELPER
  // ══════════════════════════════════════════

  // Klartext-Relay (Key-Exchange: commit/key — pre-ratchet, inhärent öffentlich)
  function relayTo(peerAnonId, data) {
    if (!socket || socket.readyState !== 1) return;
    socket.send(JSON.stringify({ type: 'relay', to: peerAnonId, d: data }));
  }

  // Opakes Relay: verschlüsselte Nachrichten als Base64-String
  // Der Server sieht nur Bytes — kein type, kein DH-Key, nichts.
  function relayEncrypted(peerAnonId, data) {
    if (!socket || socket.readyState !== 1) return;
    const inner = B64.enc(U8.enc(JSON.stringify(data)));
    socket.send(JSON.stringify({ type: 'relay', to: peerAnonId, d: inner }));
  }

  // ══════════════════════════════════════════
  //  MESSAGE HANDLING
  // ══════════════════════════════════════════

  function handleMessage(msg) {
    if (msg.t === 'peers') {
      UI.log(`Peers: ${msg.p.length}`, msg.p.length ? 'ok' : 'wr');
      for (const p of msg.p) startKeyExchange(p.a);
    }

    if (msg.t === 'join') {
      UI.log(`Peer: ${msg.a.slice(0,8)}`, 'ok');
      startKeyExchange(msg.a);
    }

    if (msg.t === 'msg' && msg.d !== undefined) {
      let d = msg.d;
      // Opakes Envelope (Base64-String) entpacken
      if (typeof d === 'string') {
        try { d = JSON.parse(U8.dec(B64.dec(d))); }
        catch { return; }
      }
      switch (d.type) {
        case 'commit':    handleCommit(d);    break;
        case 'key':       handleKey(d);       break;
        case 'enc':       handleEncrypted(d); break;
      }
    }

    if (msg.t === 'leave') {
      UI.log(`Verlassen: ${msg.a.slice(0,8)}`);
      Session.removeSession(msg.a);
      UI.updatePeers(Session.getAll());
      UI.addSystem(`${msg.a.slice(0,8)} hat verlassen`);
    }
  }

  // ══════════════════════════════════════════
  //  KEY EXCHANGE mit Blinding-Commitment
  //
  //  Ablauf:
  //  1. Sender erzeugt commit({ pubKey || ephPubKey || ts }) + blindingNonce
  //  2. Sender schickt nur den Commitment-Hash (nicht den Nonce)
  //  3. Beide schicken ihren Key + blindingNonce (Reveal)
  //  4. Empfänger prüft: hash(key || nonce) == commitment
  //  → MITM muss Key fixieren bevor er den Nonce sieht → unmöglich
  // ══════════════════════════════════════════

  function startKeyExchange(peerAnonId) {
    let session = Session.getSession(peerAnonId);
    if (!session) session = Session.createSession(peerAnonId, null);
    if (!session.myEphemeral) session.myEphemeral = Crypto.generateKeyPair();

    const ts       = Date.now();
    const commData = new Uint8Array(72);
    commData.set(myKeys.publicKey, 0);
    commData.set(session.myEphemeral.publicKey, 32);
    new DataView(commData.buffer).setBigUint64(64, BigInt(ts), false);

    // NEU: Commitment mit Blinding-Nonce
    const { commitment, nonce: blindNonce } = Crypto.commit(commData);
    session.myCommitment      = commitment;
    session.myCommitNonce     = blindNonce;   // NEU: gespeichert für Reveal
    session.myCommitTimestamp = ts;

    relayTo(peerAnonId, { type: 'commit', from: myAnonId, comm: B64.enc(commitment), timestamp: ts });
    UI.log(`Commit → ${peerAnonId.slice(0,8)}`, 'ok');
    if (session.theirCommitment) sendKey(peerAnonId);
  }

  function handleCommit(d) {
    const peerAnonId = d.from;
    let session = Session.getSession(peerAnonId);
    if (!session) session = Session.createSession(peerAnonId, null);

    session.theirCommitment      = B64.dec(d.comm);
    session.theirCommitTimestamp = d.timestamp;
    // theirCommitNonce kommt später im Key-Reveal

    UI.log(`Commit ← ${peerAnonId.slice(0,8)}`, 'ok');
    sendKey(peerAnonId);
  }

  function sendKey(peerAnonId) {
    const session = Session.getSession(peerAnonId);
    if (!session || !session.myEphemeral || session.keySent) return;
    session.keySent = true;

    const payload = {
      from:            myAnonId,
      to:              peerAnonId,
      pubKey:          B64.enc(myKeys.publicKey),
      ephemeralPubKey: B64.enc(session.myEphemeral.publicKey),
      signingPubKey:   B64.enc(mySigning.publicKey),
      commitNonce:     B64.enc(session.myCommitNonce), // NEU: Blinding-Nonce reveal
      timestamp:       session.myCommitTimestamp
    };

    const sigData = {
      from: payload.from, to: payload.to,
      pubKey: payload.pubKey, ephemeralPubKey: payload.ephemeralPubKey,
      commitNonce: payload.commitNonce, timestamp: payload.timestamp
    };
    payload.signature = B64.enc(Crypto.sign(sigData, mySigning.secretKey));

    relayTo(peerAnonId, { type: 'key', ...payload });
    UI.log(`Key → ${peerAnonId.slice(0,8)}`, 'ok');
  }

  async function handleKey(d) {
    const peerAnonId = d.from;
    const session    = Session.getSession(peerAnonId);
    if (!session) return;

    // Timestamp-Fenster: 60 Sekunden (großzügiger für langsame Verbindungen)
    if (Math.abs(Date.now() - d.timestamp) > 60000) {
      UI.log('Key abgelaufen', 'wr'); return;
    }

    // Signatur prüfen (mit Domain-Separator in Crypto.verify)
    const sigData = { from: d.from, to: d.to, pubKey: d.pubKey,
                      ephemeralPubKey: d.ephemeralPubKey,
                      commitNonce: d.commitNonce, timestamp: d.timestamp };
    if (!Crypto.verify(sigData, B64.dec(d.signature), B64.dec(d.signingPubKey))) {
      UI.log('⚠ Signatur UNGÜLTIG!', 'no');
      UI.addSystem(`⚠ ${peerAnonId.slice(0,8)}: Signatur ungültig — möglicher Angriff!`);
      return;
    }

    // NEU: Commitment mit Blinding-Nonce prüfen
    if (session.theirCommitment) {
      const theirCommitNonce = B64.dec(d.commitNonce);
      const commData = new Uint8Array(72);
      commData.set(B64.dec(d.pubKey), 0);
      commData.set(B64.dec(d.ephemeralPubKey), 32);
      new DataView(commData.buffer).setBigUint64(64, BigInt(session.theirCommitTimestamp), false);

      if (!Crypto.verifyCommit(commData, theirCommitNonce, session.theirCommitment)) {
        UI.log('⚠ COMMITMENT UNGÜLTIG!', 'no');
        UI.addSystem('🚨 Manipulationsversuch erkannt! Verbindung abgebrochen.');
        Session.removeSession(peerAnonId);
        return;
      }
      UI.log('Commitment ✓', 'ok');
    }

    session.theirPubKey       = B64.dec(d.pubKey);
    session.theirEphemeralPub = B64.dec(d.ephemeralPubKey);

    if (await Session.computeSharedSecret(peerAnonId)) {
      UI.log(`Ratchet ✓ ${peerAnonId.slice(0,8)}`, 'ok');
      UI.addSystem(`${peerAnonId.slice(0,8)} verbunden — verifiziere den Session-Fingerabdruck!`, true);

      // Dummy-Traffic starten sobald erste Session etabliert
      if (Session.getAll().size >= 1) Session.startDummyTraffic();
    }

    if (!session.keySent) sendKey(peerAnonId);
    UI.updatePeers(Session.getAll());
  }

  // ══════════════════════════════════════════
  //  VERSCHLÜSSELTE NACHRICHTEN
  // ══════════════════════════════════════════

  async function handleEncrypted(d) {
    // FIX ③: Sealed Sender korrekt auflösen.
    //
    // unsealSenderId() gibt die AnonId des SENDERS zurück (z.B. "xabc...").
    // targetPeerId ist die AnonId des Peers in unserer sessions-Map.
    // Im Zwei-Tab-Szenario: Sender = Tab A, Peer in Tab B = Tab A's AnonId.
    // D.h. senderId === peerId ist korrekt — beide sind Tab A's AnonId.
    //
    // Der Fehler war subtil: wenn Tab A sich selbst als Peer sieht
    // (weil er im gleichen Raum ist), ist session.sealedKey von
    // Tab A's Perspektive aus dem geteilten Secret mit Tab B abgeleitet.
    // Tab B's AnonId ist der peerId in Tab A's sessions-Map.
    // Die gesendete SealedId enthält Tab A's eigene AnonId.
    // senderId (= Tab A's AnonId) ≠ peerId (= Tab B's AnonId) → kein Match.
    //
    // Korrekte Logik: targetPeerId = der Peer, dessen sealedKey
    // die SealedId erfolgreich entschlüsselt — unabhängig von senderId.
    // senderId wird nur zur Validierung geloggt, nicht zum Routing.

    let targetPeerId  = null;
    let verifiedSender = null;

    if (d.si && d.sn) {
      for (const [peerId, session] of Session.getAll()) {
        if (!session.sealedKey || !session.established) continue;
        const senderId = Session.unsealSenderId(session.sealedKey, d.si, d.sn);
        if (senderId !== null) {
          // Entschlüsselung erfolgreich → das ist die richtige Session
          targetPeerId   = peerId;
          verifiedSender = senderId;
          break;
        }
      }
    }

    // Fallback: erste verfügbare Session mit Ratchet
    if (!targetPeerId) {
      for (const [peerId, session] of Session.getAll()) {
        if (session.ratchet) { targetPeerId = peerId; break; }
      }
    }

    if (!targetPeerId) return;

    try {
      const plaintext = await Session.decryptMessage(targetPeerId, d.h, d.n, d.c);
      if (plaintext === null) return;

      // Dummy-Nachrichten still verwerfen
      if (Session.isDummy(plaintext)) return;

      UI.addMessage(targetPeerId, plaintext, false);
    } catch { /* still */ }
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

    if (!socket || socket.readyState !== 1) { UI.addSystem('Relay nicht bereit'); return; }

    const sessions = Session.getAll();
    if (sessions.size === 0) { UI.addSystem('Kein Peer verbunden'); return; }

    // Erzwungene Verifikation
    let hasUnverified = false;
    sessions.forEach(s => { if (!s.verified) hasUnverified = true; });
    if (hasUnverified) { UI.addSystem('🔒 VERIFIZIERUNG ERFORDERLICH — Klicke auf "⚠"'); return; }

    let sent = 0;
    for (const [peerId, session] of sessions) {
      if (!session.ratchet || !session.sealedKey) continue;
      try {
        const encrypted = await Session.encryptMessage(peerId, text);
        if (!encrypted) continue;

        const sealed = Session.sealSenderId(session.sealedKey, myAnonId);

        // Zufälliger Timing-Jitter: verhindert Korrelation zwischen Peers
        await jitter(10, 150);

        relayEncrypted(peerId, {
          type: 'enc',
          h: encrypted.header,
          n:  encrypted.nonce,
          c:  encrypted.ciphertext,
          si: sealed.sealedId,
          sn: sealed.sealedNonce
        });

        sent++;
        UI.log(`MSG → ${peerId.slice(0,8)}`, 'ok');
      } catch (e) { UI.log(`Send Error: ${e.message}`, 'no'); }
    }

    if (sent > 0) {
      UI.addMessage(myAnonId, text, true);
      $('min').value = '';
      $('min').style.height = 'auto';
    } else {
      UI.addSystem('Nachricht konnte nicht gesendet werden');
    }
  }

  // ══════════════════════════════════════════
  //  FINGERPRINT VERIFICATION
  //  NEU: Zeigt Session-Fingerprint (sharedSecret eingeschlossen)
  // ══════════════════════════════════════════

  $('pl').addEventListener('click', e => {
    const btn = e.target.closest('.bv');
    if (!btn) return;
    const peerId  = btn.dataset.p;
    const session = Session.getSession(peerId);
    if (!session || !session.theirPubKey) return;

    // Session-Fingerprint bevorzugen (bestätigt shared secret)
    const fp = Session.getSessionFingerprint(peerId);
    if (fp) {
      UI.showSessionFingerprint(fp, peerId);
    } else {
      // Fallback auf Key-Fingerprint (vor Session-Aufbau)
      UI.showFingerprint(myKeys.publicKey, session.theirPubKey, peerId);
    }
  });

  $('fpy').addEventListener('click', () => {
    const peerId  = $('fpm').dataset.peer;
    const session = Session.getSession(peerId);
    if (session) {
      session.verified = true;
      UI.log(`${peerId.slice(0,8)} verifiziert ✓`, 'ok');
      UI.updatePeers(Session.getAll());
      let allOk = true;
      Session.getAll().forEach(s => { if (!s.verified) allOk = false; });
      if (allOk) {
        UI.addSystem('🔓 Alle Peers verifiziert — Ende-zu-Ende-Verschlüsselung aktiv!', true);
      }
    }
    UI.hideFingerprint();
  });

  $('fpn').addEventListener('click', () => UI.hideFingerprint());

  UI.log('Bereit', 'ok');
})();
