/* ═══════════════════════════════════════════════════
   app.js — Kryptochat v3

   NEU:
   ① Opakes Relay-Envelope:
      Alle Nachrichten an den Server haben die Form { d: "..." }.
      Der Typ (commit/key/enc/heartbeat) ist innerhalb von d
      verpackt und für den Server nicht lesbar.
      Nur Key-Exchange-Nachrichten (commit/key) bleiben Klartext-JSON,
      da sie noch vor dem Ratchet-Aufbau gesendet werden.
      Echte Nachrichten (enc/heartbeat) sind vollständig opak.

   ② encHeader statt header:
      Session.encryptMessage gibt { encHeader, nonce, ciphertext } zurück.
      Session.decryptMessage erwartet (peerId, encHeader, nonce, ciphertext).
      Der DH-Key ist nicht mehr im Klartext — der Relay sieht nur Bytes.
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
  //  Memory Cleanup
  // ══════════════════════════════════════════

  function cleanup() {
    burn(myKeys.secretKey, myKeys.publicKey, mySigning.secretKey, mySigning.publicKey);
    Session.destroyAll();
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
  //
  //  relayTo: sendet opak — der Server sieht nur { type:'relay', to, d }
  //  wobei d für verschlüsselte Nachrichten ein base64-String ist.
  //  Für Key-Exchange (commit/key) bleibt d ein JSON-Objekt,
  //  da diese Nachrichten vor dem Ratchet-Aufbau gesendet werden
  //  und inhärent öffentlich sind (nur Public Keys, keine Klartexte).
  // ══════════════════════════════════════════

  function relayTo(peerAnonId, data) {
    if (!socket || socket.readyState !== 1) return;
    socket.send(JSON.stringify({ type: 'relay', to: peerAnonId, d: data }));
  }

  // Sendet eine verschlüsselte Nachricht als opakes Envelope.
  // data = beliebiges Objekt, wird JSON→Base64 kodiert.
  // Der Server sieht nur einen base64-String, keinen type.

  function relayEncrypted(peerAnonId, data) {
    if (!socket || socket.readyState !== 1) return;
    // Inneres Payload: JSON → Bytes → Base64
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

    if (msg.t === 'msg' && msg.d) {
      // Versuche d zu dekodieren: Base64-String = opakes Envelope, Objekt = Key-Exchange
      let d = msg.d;
      if (typeof d === 'string') {
        // Opakes Envelope entpacken
        try { d = JSON.parse(U8.dec(B64.dec(d))); }
        catch { UI.log('Envelope-Fehler', 'no'); return; }
      }
      switch (d.type) {
        case 'commit':    handleCommit(d);    break;
        case 'key':       handleKey(d);       break;
        case 'enc':       handleEncrypted(d); break;
        case 'heartbeat': handleHeartbeat(d); break;
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
  //  KEY EXCHANGE (unverändert — Klartext-JSON, da pre-ratchet)
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

    const comm = Crypto.commitment(commData);
    session.myCommitment      = comm;
    session.myCommitTimestamp = ts;

    // Key-Exchange bleibt als Klartext-JSON (kein encHeader nötig)
    relayTo(peerAnonId, { type: 'commit', from: myAnonId, comm: B64.enc(comm), timestamp: ts });
    UI.log(`Commit → ${peerAnonId.slice(0,8)}`, 'ok');
    if (session.theirCommitment) sendKey(peerAnonId);
  }

  function handleCommit(d) {
    const peerAnonId = d.from;
    let session = Session.getSession(peerAnonId);
    if (!session) session = Session.createSession(peerAnonId, null);
    session.theirCommitment      = B64.dec(d.comm);
    session.theirCommitTimestamp = d.timestamp;
    UI.log(`Commit ← ${peerAnonId.slice(0,8)}`, 'ok');
    sendKey(peerAnonId);
  }

  function sendKey(peerAnonId) {
    const session = Session.getSession(peerAnonId);
    if (!session || !session.myEphemeral || session.keySent) return;
    session.keySent = true;

    const payload = {
      from: myAnonId, to: peerAnonId,
      pubKey:          B64.enc(myKeys.publicKey),
      ephemeralPubKey: B64.enc(session.myEphemeral.publicKey),
      signingPubKey:   B64.enc(mySigning.publicKey),
      timestamp:       Date.now()
    };
    const sigData = { from: payload.from, to: payload.to, pubKey: payload.pubKey,
                      ephemeralPubKey: payload.ephemeralPubKey, timestamp: payload.timestamp };
    payload.signature = B64.enc(Crypto.sign(sigData, mySigning.secretKey));

    relayTo(peerAnonId, { type: 'key', ...payload });
    UI.log(`Key → ${peerAnonId.slice(0,8)}`, 'ok');
  }

  async function handleKey(d) {
    const peerAnonId = d.from;
    const session    = Session.getSession(peerAnonId);
    if (!session) return;

    if (Math.abs(Date.now() - d.timestamp) > 30000) { UI.log('Key abgelaufen', 'wr'); return; }

    const sigData = { from: d.from, to: d.to, pubKey: d.pubKey,
                      ephemeralPubKey: d.ephemeralPubKey, timestamp: d.timestamp };
    if (!Crypto.verify(sigData, B64.dec(d.signature), B64.dec(d.signingPubKey))) {
      UI.log('⚠ Signatur UNGÜLTIG!', 'no');
      UI.addSystem(`⚠ Warnung: ${peerAnonId.slice(0,8)} hat ungültige Signatur!`);
      return;
    }

    if (session.theirCommitment) {
      const commData = new Uint8Array(72);
      commData.set(B64.dec(d.pubKey), 0);
      commData.set(B64.dec(d.ephemeralPubKey), 32);
      new DataView(commData.buffer).setBigUint64(64, BigInt(session.theirCommitTimestamp || d.timestamp), false);
      if (!Crypto.verifyCommitment(commData, session.theirCommitment)) {
        UI.log('⚠ COMMITMENT UNGÜLTIG!', 'no');
        UI.addSystem('🚨 Manipulationsversuch erkannt!');
        return;
      }
      UI.log('Commitment ✓', 'ok');
    }

    session.theirPubKey       = B64.dec(d.pubKey);
    session.theirEphemeralPub = B64.dec(d.ephemeralPubKey);

    if (await Session.computeSharedSecret(peerAnonId)) {
      UI.log(`Ratchet ✓ ${peerAnonId.slice(0,8)}`, 'ok');
      UI.addSystem(`${peerAnonId.slice(0,8)} verbunden — verifiziere Fingerabdruck!`, true);
    }

    if (!session.keySent) sendKey(peerAnonId);
    UI.updatePeers(Session.getAll());
  }

  // ══════════════════════════════════════════
  //  VERSCHLÜSSELTE NACHRICHTEN
  //  Neu: encHeader statt header
  // ══════════════════════════════════════════

  async function handleEncrypted(d) {
    // d.eh = encHeader { enc, nonce }, d.n = nonce, d.c = ciphertext
    // d.si / d.sn = Sealed Sender
    let targetPeerId = null;

    if (d.si && d.sn) {
      for (const [peerId, session] of Session.getAll()) {
        if (!session.sealedKey || !session.established) continue;
        const senderId = Session.unsealSenderId(session.sealedKey, d.si, d.sn);
        if (senderId === peerId) { targetPeerId = peerId; break; }
      }
    }

    if (!targetPeerId) {
      for (const [peerId, session] of Session.getAll()) {
        if (session.ratchet) { targetPeerId = peerId; break; }
      }
    }

    if (!targetPeerId) { UI.log('Enc: Kein Ziel', 'wr'); return; }

    try {
      // encHeader = d.eh, nonce = d.n, ciphertext = d.c
      const plaintext = await Session.decryptMessage(targetPeerId, d.eh, d.n, d.c);
      if (plaintext === null) { UI.log(`Decrypt fehlgeschlagen von ${targetPeerId.slice(0,8)}`, 'no'); return; }
      UI.addMessage(targetPeerId, plaintext, false);
    } catch (e) { UI.log(`Decrypt Error: ${e.message}`, 'no'); }
  }

  async function handleHeartbeat(d) {
    let targetPeerId = null;
    if (d.si && d.sn) {
      for (const [peerId, session] of Session.getAll()) {
        if (!session.sealedKey || !session.established) continue;
        const sid = Session.unsealSenderId(session.sealedKey, d.si, d.sn);
        if (sid === peerId) { targetPeerId = peerId; break; }
      }
    }
    if (!targetPeerId) {
      for (const [peerId, session] of Session.getAll()) {
        if (session.ratchet) { targetPeerId = peerId; break; }
      }
    }
    if (!targetPeerId) return;
    try {
      const pt = await Session.decryptMessage(targetPeerId, d.eh, d.n, d.c);
      if (pt?.startsWith('hb:')) Session.recordHeartbeat(targetPeerId);
    } catch { /* still */ }
  }

  // ══════════════════════════════════════════
  //  SENDEN
  //  Neu: relayEncrypted statt relayTo für verschlüsselte Msgs
  //       encHeader (d.eh) statt header (d.h)
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

    // Erzwungene Verifizierung
    const unverified = [];
    sessions.forEach((s, id) => { if (!s.verified) unverified.push(id); });
    if (unverified.length > 0) { UI.addSystem('🔒 VERIFIZIERUNG ERFORDERLICH — Klicke auf "⚠"'); return; }

    let sent = 0;
    for (const [peerId, session] of sessions) {
      if (!session.ratchet || !session.sealedKey) {
        UI.log(`Session ${peerId.slice(0,8)} nicht bereit`, 'wr');
        continue;
      }
      try {
        const encrypted = await Session.encryptMessage(peerId, text);
        // encrypted = { encHeader: {enc, nonce}, nonce, ciphertext }
        if (!encrypted) { UI.log(`Encrypt fehlgeschlagen für ${peerId.slice(0,8)}`, 'no'); continue; }

        const sealed = Session.sealSenderId(session.sealedKey, myAnonId);
        await jitter(0, 100);

        // Opakes Envelope: type ist INNEN, für den Server unsichtbar
        relayEncrypted(peerId, {
          type: 'enc',
          eh: encrypted.encHeader,   // verschlüsselter Header (kein DH-Key im Klartext!)
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
  // ══════════════════════════════════════════

  $('pl').addEventListener('click', e => {
    const btn = e.target.closest('.bv');
    if (!btn) return;
    const peerId  = btn.dataset.p;
    const session = Session.getSession(peerId);
    if (!session || !session.theirPubKey) return;
    UI.showFingerprint(myKeys.publicKey, session.theirPubKey, peerId);
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
      if (allOk) UI.addSystem('🔓 Alle Peers verifiziert!', true);
    }
    UI.hideFingerprint();
  });

  $('fpn').addEventListener('click', () => UI.hideFingerprint());

  UI.log('Bereit', 'ok');
})();
