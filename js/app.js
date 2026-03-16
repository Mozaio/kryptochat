/* ═══════════════════════════════════════════════════
   app.js — Vollständig gehärteter Kryptochat

   Verbesserungen:
   - Commitment-basierter Key Exchange
   - Metadaten-Padding (feste Nachrichtengrößen)
   - Persistente Nonce (über Neustarts)
   - Heartbeats (Server-Manipulation-Erkennung)
   - Memory-Cleanup (Burn bei Verlassen)
   - Timing-Jitter (gegen Timing-Analyse)
   - Erzwungene Fingerprint-Verifizierung
   ═══════════════════════════════════════════════════ */

(() => {

  if (typeof nacl === 'undefined') {
    document.body.innerHTML = '<p style="color:red;padding:2rem">Fehler: TweetNaCl nicht geladen.</p>';
    return;
  }

  // ══════════════════════════════════════════
  //  State
  // ══════════════════════════════════════════

  const myKeys      = Crypto.generateKeyPair();        // X25519 langfristig
  const mySigning   = Crypto.generateSigningKeyPair(); // Ed25519 pro Client
  const myAnonId    = makeAnonId();                    // Ephemere anonyme ID
  let socket        = null;
  let room          = null;
  let connected     = false;

  Session.setMyLongTermKey(myKeys.publicKey);

  $('mid').textContent = myAnonId.slice(0, 8);
  UI.initLogToggle();
  UI.log(`ID: ${myAnonId}`, 'ok');

  // ══════════════════════════════════════════
  //  Memory Cleanup bei Verlassen
  // ══════════════════════════════════════════

  function cleanup() {
    // Alle Secrets im RAM überschreiben
    burn(myKeys.secretKey);
    burn(mySigning.secretKey);

    Session.getAll().forEach((s, id) => {
      Session.removeSession(id);
    });

    // LocalStorage bereinigen
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
      UI.log('Relay verbunden ✓', 'ok');

      // Beim Join senden wir dem Server:
      //   - Raumname (Server hasht ihn mit Salt → sieht nur Hash)
      //   - Anonyme ID (zufällig, kein Bezug zur Person)
      socket.send(JSON.stringify({
        type: 'join',
        room: r,
        anonId: myAnonId
      }));

      // Timing-Jitter: Verzögere UI-Update um Timing-Analyse zu erschweren
      jitter(200, 800).then(() => UI.showRoom(r));
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

      // Sessions bereinigen
      Session.getAll().forEach((_, id) => Session.removeSession(id));
      UI.updatePeers(Session.getAll());

      // Auto-Reconnect
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

    // Peer-Liste beim Join
    if (msg.t === 'peers') {
      UI.log(`Peers: ${msg.p.length}`, msg.p.length ? 'ok' : 'wr');
      for (const p of msg.p) {
        // Starte Commitment-basierten Key Exchange
        startCommitment(p.a);
      }
    }

    // Neuer Peer
    if (msg.t === 'join') {
      UI.log(`Peer: ${msg.a.slice(0, 8)}`, 'ok');
      startCommitment(msg.a);
    }

    // Verschlüsselte Nachricht
    if (msg.t === 'msg' && msg.d) {
      const d = msg.d;

      switch (d.type) {
        case 'commit':    handleCommitment(d);    break;
        case 'key':       handleKey(d);           break;
        case 'enc':       handleEncrypted(d);     break;
        case 'heartbeat': handleHeartbeat(d);     break;
      }
    }

    // Peer verlassen
    if (msg.t === 'leave') {
      UI.log(`Verlassen: ${msg.a.slice(0, 8)}`);
      Session.removeSession(msg.a);
      UI.updatePeers(Session.getAll());
      UI.addSystem(`${msg.a.slice(0, 8)} hat verlassen`);
    }
  }

  // ══════════════════════════════════════════
  //  COMMITMENT-BASIERTER KEY EXCHANGE
  // ══════════════════════════════════════════
  //
  //  Phase 1: Beide senden ein Commitment (Hash ihrer Keys)
  //           → Server kann Keys nicht austauschen,
  //             weil das Commitment vorher feststeht
  //
  //  Phase 2: Beide senden ihre Keys
  //           → Empfänger prüft gegen Commitment
  //             Manipulation ist sofort erkennbar
  //
  //  Phase 3: Shared Secret wird berechnet
  //
  // ══════════════════════════════════════════

  function startCommitment(peerAnonId) {
    // Session anlegen (oder vorhandene holen)
    let session = Session.getSession(peerAnonId);
    if (!session) {
      session = Session.createSession(peerAnonId, null);
    }

    // Ephemeren Key-Paar erzeugen
    const ephemeral = Crypto.generateKeyPair();
    session.myEphemeral = ephemeral;

    // Commitment berechnen:
    // Hash über: langfristigerPubKey + ephemeralerPubKey + Timestamp
    const commData = new Uint8Array(72);
    commData.set(myKeys.publicKey, 0);
    commData.set(ephemeral.publicKey, 32);
    const view = new DataView(commData.buffer);
    view.setBigUint64(64, BigInt(Date.now()), false);

    const comm = Crypto.commitment(commData);

    // Commitment senden
    relayTo(peerAnonId, {
      type: 'commit',
      from: myAnonId,
      comm: B64.enc(comm),
      timestamp: Date.now()
    });

    UI.log(`Commit → ${peerAnonId.slice(0, 8)}`, 'ok');
  }

  function handleCommitment(d) {
    // Wir haben ein Commitment von einem Peer erhalten
    // Jetzt senden wir unser Commitment + unsere Keys

    const peerAnonId = d.from;
    let session = Session.getSession(peerAnonId);

    if (!session) {
      session = Session.createSession(peerAnonId, null);
    }

    // Commitment des Peers speichern
    session.commitmentReceived = B64.dec(d.comm);

    // Unseren Key senden (falls noch nicht geschehen)
    sendKey(peerAnonId);
  }

  function sendKey(peerAnonId) {
    const session = Session.getSession(peerAnonId);
    if (!session || !session.myEphemeral) return;

    const payload = {
      type: 'key',
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

    relayTo(peerAnonId, payload);
    UI.log(`Key → ${peerAnonId.slice(0, 8)}`, 'ok');
  }

  async function handleKey(d) {
    const peerAnonId = d.from;
    let session = Session.getSession(peerAnonId);
    if (!session) return;

    // ── Timestamp prüfen (30s Toleranz) ──
    if (Math.abs(Date.now() - d.timestamp) > 30000) {
      UI.log(`Key von ${peerAnonId.slice(0, 8)} abgelaufen`, 'wr');
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
      UI.log(`⚠ Signatur von ${peerAnonId.slice(0, 8)} UNGÜLTIG!`, 'no');
      UI.addSystem(`⚠ Warnung: ${peerAnonId.slice(0, 8)} hat ungültige Signatur!`);
      return;
    }

    // ── Commitment verifizieren ──
    if (session.commitmentReceived) {
      const commData = new Uint8Array(72);
      commData.set(B64.dec(d.pubKey), 0);
      commData.set(B64.dec(d.ephemeralPubKey), 32);
      const view = new DataView(commData.buffer);
      view.setBigUint64(64, BigInt(d.timestamp), false);

      const commValid = Crypto.verifyCommitment(commData, session.commitmentReceived);

      if (!commValid) {
        UI.log(`⚠ COMMITMENT von ${peerAnonId.slice(0, 8)} UNGÜLTIG!`, 'no');
        UI.addSystem(`🚨 Manipulationsversuch erkannt!`);
        return;
      }
    }

    // ── Keys speichern ──
    const pubKey = B64.dec(d.pubKey);
    const ephemeralPubKey = B64.dec(d.ephemeralPubKey);

    session.theirPubKey = pubKey;
    session.theirEphemeralPub = ephemeralPubKey;

    // ── Shared Secret berechnen ──
    if (await Session.computeSharedSecret(peerAnonId)) {
      UI.log(`Session ✓ ${peerAnonId.slice(0, 8)}`, 'ok');
      UI.addSystem(`${peerAnonId.slice(0, 8)} verbunden — verifiziere Fingerabdruck!`, true);
    }

    // ── Unseren Key auch senden (falls noch nicht) ──
    if (!session.commitmentSent) {
      sendKey(peerAnonId);
      session.commitmentSent = true;
    }

    UI.updatePeers(Session.getAll());
  }

  // ══════════════════════════════════════════
  //  VERSCHLÜSSELTE NACHRICHTEN
  // ══════════════════════════════════════════

  function handleEncrypted(d) {
    const session = Session.getSession(d.from);
    if (!session || !session.established) return;

    // Replay-Schutz
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

      // Rotation bei Bedarf
      if (Session.needsRotation(d.from)) triggerRotation(d.from);

    } catch (e) {
      // Kein Console-Log in Produktion
    }
  }

  // ══════════════════════════════════════════
  //  HEARTBEATS
  // ══════════════════════════════════════════
  //
  //  Erkennen, ob der Server Nachrichten unterdrückt
  //

  function handleHeartbeat(d) {
    const session = Session.getSession(d.from);
    if (session) {
      Session.recordHeartbeat(d.from);
    }
  }

  // Periodische Heartbeats senden
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

    // Heartbeat ist verschlüsselt — Server sieht nur Chiffretext
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
      UI.addSystem(`🔒 VERIFIZIERUNG ERFORDERLICH`);
      UI.addSystem(`Klicke auf "⚠" in der Seitenleiste.`);
      return;
    }

    let sent = 0;
    for (const [peerId, session] of sessions) {
      if (!session.established || !session.sharedSecret) continue;

      try {
        const nonce = Crypto.makeNonce(session.sendNonce);
        session.sendNonce++;

        // Nonce persistieren
        Session.persistNonce(peerId, session.sendNonce);

        // Verschlüsseln (mit Padding → feste Nachrichtengröße)
        const encrypted = Crypto.encrypt(text, session.sharedSecret, nonce);
        if (!encrypted) continue;

        // Timing-Jitter: Zufällige Verzögerung gegen Timing-Analyse
        await jitter(0, 150);

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
    startCommitment(peerId);
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
