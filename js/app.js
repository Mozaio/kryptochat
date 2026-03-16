/* ═══════════════════════════════════════════
   app.js — Trustless Relay Client
   ═══════════════════════════════════════════ */

(() => {

  // ── Guard ──
  if (typeof nacl === 'undefined') {
    document.body.innerHTML = '<p style="color:red;padding:2rem">Fehler: TweetNaCl nicht geladen.</p>';
    return;
  }

  // ── State ──
  const myKeys = Crypto.generateKeyPair();     // X25519 Schlüsselpaar
  const signingKeys = nacl.sign.keyPair();     // Ed25519 Signing Keys
  const myAnonId = anonId();                   // Anonyme ID für den Server
  let socket = null;
  let room = null;

  Session.setMyLongTermKey(myKeys.publicKey);
  $('mid').textContent = myAnonId.slice(0, 8);
  UI.initLogToggle();
  UI.log(`Anon-ID: ${myAnonId}`, 'ok');

  // ══════════════════════════════════════════
  //  Join
  // ══════════════════════════════════════════

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

  // ══════════════════════════════════════════
  //  WebSocket
  // ══════════════════════════════════════════

  function connect(r) {
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
      UI.log('Relay verbunden ✓', 'ok');

      // Beim Join senden wir dem Server NUR:
      //   - Raumname (wird gehasht, Server sieht nur den Hash)
      //   - Anonyme ID (zufällig, nicht an Person gebunden)
      //   - Öffentlicher Key (für anderen Clients, nicht für Server)
      socket.send(JSON.stringify({
        type: 'join',
        room: r,
        anonId: myAnonId,
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
      UI.log(`Relay getrennt (${ev.code})`, 'no');
      socket = null;
      $('est').textContent = 'Getrennt';
      $('est').style.color = 'var(--rd)';
      UI.addSystem('Verbindung verloren...');

      // Alle Sessions bereinigen
      Session.getAll().forEach((_, id) => Session.removeSession(id));
      UI.updatePeers(Session.getAll());

      // Auto-Reconnect
      setTimeout(() => { if (room) connect(room); }, 3000);
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
    if (msg.type === 'peers') {
      UI.log(`Peers: ${msg.peers.length}`, msg.peers.length ? 'ok' : 'wr');
      // Wir bekommen anonyme IDs — wir müssen uns mit denen verbinden
      // Aber wir brauchen deren öffentliche Keys
      // Die bekommen wir durch den Key Exchange
      for (const p of msg.peers) {
        // Peer existiert, aber wir haben noch keinen Key
        // → Key Exchange starten, sobald wir den Key bekommen
        requestKey(p.anonId);
      }
    }

    // Neuer Peer
    if (msg.type === 'peer-joined') {
      UI.log(`Peer beigetreten: ${msg.anonId.slice(0, 8)}`, 'ok');
      requestKey(msg.anonId);
    }

    // Nachricht vom Relay
    if (msg.type === 'msg' && msg.data) {
      const d = msg.data;

      if (d.type === 'key-request')     handleKeyRequest(d);
      if (d.type === 'key-response')    handleKeyResponse(d);
      if (d.type === 'kx')             handleKeyExchange(d);
      if (d.type === 'kx-response')    handleKeyExchangeResponse(d);
      if (d.type === 'enc')            handleEncrypted(d);
    }

    // Peer verlassen
    if (msg.type === 'leave') {
      UI.log(`Peer verlassen: ${msg.anonId.slice(0, 8)}`);
      Session.removeSession(msg.anonId);
      UI.updatePeers(Session.getAll());
      UI.addSystem(`${msg.anonId.slice(0, 8)} hat verlassen`);
    }
  }

  // ══════════════════════════════════════════
  //  Key Request / Response
  // ══════════════════════════════════════════

  // Wir brauchen eine Möglichkeit, den öffentlichen Key eines Peers zu bekommen
  // Das läuft über den Relay, aber der Server kann den Key nicht fälschen,
  // weil der Key Exchange signiert ist

  function requestKey(peerAnonId) {
    relayTo(peerAnonId, {
      type: 'key-request',
      from: myAnonId,
      pubKey: B64.enc(myKeys.publicKey),
      signingPubKey: B64.enc(signingKeys.publicKey),
      timestamp: Date.now()
    });
  }

  function handleKeyRequest(d) {
    // Jemand bittet um unseren öffentlichen Key
    // Wir antworten mit unserem Key + unserem ephemeralen Key + Signatur

    const ephemeral = nacl.box.keyPair();

    // Session anlegen oder aktualisieren
    let session = Session.getSession(d.from);
    if (!session) {
      session = Session.createSession(d.from, B64.dec(d.pubKey));
    }

    // Ephemeral Key für diese Session speichern
    session.myEphemeral = ephemeral;

    const response = {
      type: 'key-response',
      from: myAnonId,
      to: d.from,
      pubKey: B64.enc(myKeys.publicKey),
      ephemeralPubKey: B64.enc(ephemeral.publicKey),
      signingPubKey: B64.enc(signingKeys.publicKey),
      timestamp: Date.now()
    };

    // Signieren
    const data = U8.enc(JSON.stringify({
      from: response.from,
      to: response.to,
      pubKey: response.pubKey,
      ephemeralPubKey: response.ephemeralPubKey,
      timestamp: response.timestamp
    }));
    response.signature = B64.enc(nacl.sign.detached(data, signingKeys.secretKey));

    relayTo(d.from, response);
  }

  async function handleKeyResponse(d) {
    if (Math.abs(Date.now() - d.timestamp) > 30000) return;

    // Signatur verifizieren
    const data = U8.enc(JSON.stringify({
      from: d.from,
      to: d.to,
      pubKey: d.pubKey,
      ephemeralPubKey: d.ephemeralPubKey,
      timestamp: d.timestamp
    }));
    const sigValid = nacl.sign.detached.verify(
      data,
      B64.dec(d.signature),
      B64.dec(d.signingPubKey)
    );

    if (!sigValid) {
      UI.log(`⚠ Signatur von ${d.from.slice(0, 8)} ungültig!`, 'no');
      return;
    }

    const pubKey = B64.dec(d.pubKey);
    const ephemeralPubKey = B64.dec(d.ephemeralPubKey);

    let session = Session.getSession(d.from);
    if (!session) {
      session = Session.createSession(d.from, pubKey);
    }

    session.theirPubKey = pubKey;
    session.theirEphemeralPub = ephemeralPubKey;

    // Shared Secret berechnen
    if (await Session.computeSharedSecret(d.from)) {
      UI.log(`Session mit ${d.from.slice(0, 8)} etabliert`, 'ok');
      UI.addSystem(`${d.from.slice(0, 8)} verbunden — verifiziere Fingerabdruck!`, true);
    }

    // Unseren Key auch senden (falls noch nicht geschehen)
    sendKeyExchange(d.from);
    UI.updatePeers(Session.getAll());
  }

  // ══════════════════════════════════════════
  //  Key Exchange (zusätzlicher Austausch)
  // ══════════════════════════════════════════

  function sendKeyExchange(peerAnonId) {
    const session = Session.getSession(peerAnonId);
    if (!session || !session.myEphemeral) return;

    const payload = {
      from: myAnonId,
      to: peerAnonId,
      pubKey: B64.enc(myKeys.publicKey),
      ephemeralPubKey: B64.enc(session.myEphemeral.publicKey),
      timestamp: Date.now()
    };

    // Signieren
    const data = U8.enc(JSON.stringify({
      from: payload.from,
      to: payload.to,
      pubKey: payload.pubKey,
      ephemeralPubKey: payload.ephemeralPubKey,
      timestamp: payload.timestamp
    }));
    payload.signature = B64.enc(nacl.sign.detached(data, signingKeys.secretKey));
    payload.signingPubKey = B64.enc(signingKeys.publicKey);

    relayTo(peerAnonId, { type: 'kx', ...payload });
    UI.log(`KX → ${peerAnonId.slice(0, 8)}`, 'ok');
  }

  async function handleKeyExchange(d) {
    if (Math.abs(Date.now() - d.timestamp) > 30000) return;

    if (!Crypto.verifyKeyExchange(d)) {
      UI.log(`⚠ KX Signatur ungültig!`, 'no');
      return;
    }

    const pubKey = B64.dec(d.pubKey);
    const ephemeralPubKey = B64.dec(d.ephemeralPubKey);

    let session = Session.getSession(d.from);
    if (!session) {
      session = Session.createSession(d.from, pubKey);
    }

    session.theirPubKey = pubKey;
    session.theirEphemeralPub = ephemeralPubKey;

    if (await Session.computeSharedSecret(d.from)) {
      UI.log(`Session mit ${d.from.slice(0, 8)} vollständig`, 'ok');
      UI.updatePeers(Session.getAll());
    }

    // Response senden
    const resp = {
      from: myAnonId,
      to: d.from,
      pubKey: B64.enc(myKeys.publicKey),
      ephemeralPubKey: B64.enc(session.myEphemeral.publicKey),
      timestamp: Date.now()
    };

    const data = U8.enc(JSON.stringify({
      from: resp.from, to: resp.to,
      pubKey: resp.pubKey, ephemeralPubKey: resp.ephemeralPubKey,
      timestamp: resp.timestamp
    }));
    resp.signature = B64.enc(nacl.sign.detached(data, signingKeys.secretKey));
    resp.signingPubKey = B64.enc(signingKeys.publicKey);

    relayTo(d.from, { type: 'kx-response', ...resp });
  }

  async function handleKeyExchangeResponse(d) {
    if (Math.abs(Date.now() - d.timestamp) > 30000) return;
    if (!Crypto.verifyKeyExchange(d)) return;

    const session = Session.getSession(d.from);
    if (!session) return;

    session.theirEphemeralPub = B64.dec(d.ephemeralPubKey);

    if (await Session.computeSharedSecret(d.from)) {
      UI.log(`Session mit ${d.from.slice(0, 8)} vollständig`, 'ok');
      UI.updatePeers(Session.getAll());
    }
  }

  // ══════════════════════════════════════════
  //  Verschlüsselte Nachrichten
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
      const plaintext = Crypto.decryptWithSession(ciphertext, nonce, session.sharedSecret);

      if (plaintext === null) {
        UI.log(`Decrypt fehlgeschlagen von ${d.from.slice(0, 8)}`, 'no');
        return;
      }

      session.recvNonces.add(d.n);
      session.msgCount++;
      UI.addMessage(d.from, plaintext, false);

      if (Session.needsRotation(d.from)) triggerRotation(d.from);

    } catch (e) {
      UI.log(`Decrypt error: ${e.message}`, 'no');
    }
  }

  // ══════════════════════════════════════════
  //  Senden
  // ══════════════════════════════════════════

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
      UI.log('Relay nicht bereit', 'no');
      return;
    }

    const sessions = Session.getAll();
    if (sessions.size === 0) {
      UI.addSystem('Kein Peer verbunden');
      return;
    }

    // ERZWUNGENE Verifizierung
    const unverified = [];
    sessions.forEach((s, id) => { if (!s.verified) unverified.push(id); });
    if (unverified.length > 0) {
      UI.addSystem(`🔒 VERIFIZIERUNG ERFORDERLICH`);
      UI.addSystem(`Klicke auf "⚠" in der Seitenleiste.`);
      return;
    }

    let sent = 0;
    for (const [peerAnonId, session] of sessions) {
      if (!session.established || !session.sharedSecret) continue;

      try {
        const nonce = Crypto.monotonicNonce(session.sendNonce);
        session.sendNonce++;

        const encrypted = Crypto.encryptWithSession(text, session.sharedSecret, nonce);
        if (!encrypted) continue;

        // Der Server sieht: { type: 'relay', to: 'anonyme_id', data: { type: 'enc', n: '...', c: '...' } }
        // Er kann den Inhalt nicht lesen
        relayTo(peerAnonId, {
          type: 'enc',
          from: myAnonId,
          n: B64.enc(nonce),
          c: B64.enc(encrypted)
        });

        sent++;
        session.msgCount++;

      } catch (e) {
        UI.log(`Send error: ${e.message}`, 'no');
      }
    }

    if (sent > 0) {
      UI.addMessage(myAnonId, text, true);
      $('min').value = '';
      $('min').style.height = 'auto';
    }
  }

  // ══════════════════════════════════════════
  //  Relay Helper
  // ══════════════════════════════════════════

  function relayTo(peerAnonId, data) {
    if (!socket || socket.readyState !== 1) return;
    socket.send(JSON.stringify({
      type: 'relay',
      to: peerAnonId,
      data: data
    }));
  }

  // ══════════════════════════════════════════
  //  Key Rotation
  // ══════════════════════════════════════════

  function triggerRotation(peerAnonId) {
    UI.log(`Rotation → ${peerAnonId.slice(0, 8)}`, 'inf');
    Session.rotate(peerAnonId);
    sendKeyExchange(peerAnonId);
    UI.addSystem(`🔄 Schlüssel-Rotation`);
  }

  // ══════════════════════════════════════════
  //  Fingerprint Verification
  // ══════════════════════════════════════════

  $('pl').addEventListener('click', e => {
    const btn = e.target.closest('.bv');
    if (!btn) return;
    const peerAnonId = btn.dataset.p;
    const session = Session.getSession(peerAnonId);
    if (!session || !session.theirPubKey) return;
    UI.showFingerprint(myKeys.publicKey, session.theirPubKey, peerAnonId);
  });

  $('fpy').addEventListener('click', () => {
    const peerAnonId = $('fpm').dataset.peer;
    const session = Session.getSession(peerAnonId);
    if (session) {
      session.verified = true;
      UI.log(`${peerAnonId.slice(0, 8)} verifiziert ✓`, 'ok');
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
