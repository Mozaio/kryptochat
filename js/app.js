/* ═══════════════════════════════════════════
   app.js — mit Server-Pinning + erzwungener Verifizierung
   ═══════════════════════════════════════════ */

(() => {

  if (typeof nacl === 'undefined') {
    document.body.innerHTML = '<p style="color:red;padding:2rem">Fehler: TweetNaCl nicht geladen.</p>';
    return;
  }

  // ── State ──
  const myKeys = Crypto.generateKeyPair();
  const myId = uid();
  let socket = null;
  let room = null;
  let msgCount = 0;
  let lockedUntilVerified = true;

  // ── Server-Fingerprint-Pinning ──
  // Beim ersten Besuch wird der Fingerprint gespeichert.
  // Bei jedem weiteren Besuch wird er verglichen.
  // Stimmt er nicht überein → Warnung, keine Verbindung.

  const KNOWN_SERVER_FP = localStorage.getItem('kc_server_fp');

  async function verifyServer() {
    try {
      const resp = await fetch('/api/fingerprint');
      const data = await resp.json();
      if (!data.fingerprint) return true; // Kein TLS, kein Pinning möglich

      if (!KNOWN_SERVER_FP) {
        // Erster Besuch — Fingerprint speichern
        localStorage.setItem('kc_server_fp', data.fingerprint);
        UI.log('Server-Fingerprint gespeichert (erster Besuch)', 'ok');
        return true;
      }

      if (KNOWN_SERVER_FP !== data.fingerprint) {
        // Fingerprints passen nicht!
        UI.log('⚠ SERVER-FINGERPRINT HAT SICH VERÄNDERT!', 'no');
        const msg = '🚨 SICHERHEITSWARNUNG: Das Server-Zertifikat hat sich verändert!\n\n' +
          'Möglicherweise läuft ein Man-in-the-Middle-Angriff.\n\n' +
          'Erwartet: ' + KNOWN_SERVER_FP.slice(0, 16) + '...\n' +
          'Erhalten: ' + data.fingerprint.slice(0, 16) + '...\n\n' +
          'Nur fortfahren, wenn du das neue Zertifikat erwartest.';
        if (!confirm(msg)) return false;
        localStorage.setItem('kc_server_fp', data.fingerprint);
      }

      return true;
    } catch {
      // Server unterstützt kein Fingerprinting (HTTP)
      return true;
    }
  }

  Session.setMyLongTermKey(myKeys.publicKey);
  $('mid').textContent = myId;
  UI.initLogToggle();
  UI.log(`ID: ${myId}`, 'ok');

  // ── Join ──
  $('rin').addEventListener('keydown', e => { if (e.key === 'Enter') joinRoom(); });
  $('jbtn').addEventListener('click', joinRoom);

  async function joinRoom() {
    const r = $('rin').value.trim();
    if (!r) { $('rin').focus(); return; }

    UI.setJoinStatus('Verifiziere Server...');
    UI.setJoinDisabled(true);

    // Server verifizieren bevor wir uns verbinden
    const serverOk = await verifyServer();
    if (!serverOk) {
      UI.setJoinStatus('Server-Verifizierung fehlgeschlagen!');
      UI.setJoinDisabled(false);
      return;
    }

    UI.setJoinStatus('Verbinde...');
    room = r;
    connect(r);
  }

  // ── WebSocket (nur wss://) ──
  function connect(r) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';

    // Warnung bei unsicherem Protokoll
    if (proto === 'ws:') {
      UI.log('⚠ UNSICHERE VERBINDUNG (ws://) — Kein TLS!', 'no');
      UI.addSystem('⚠ Ungesicherte Verbindung! Nachrichten können abgefangen werden.');
    }

    const url = `${proto}//${location.host}`;

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

    // Server-Fehler
    if (msg.type === 'error') {
      UI.log(`Server-Fehler: ${msg.reason}`, 'no');
      if (msg.reason === 'rate-limit') UI.addSystem('⚠ Rate-Limit erreicht. Kurz warten.');
      if (msg.reason === 'room-full') UI.addSystem('⚠ Raum ist voll (max. 10 Peers).');
      return;
    }

    if (msg.type === 'peers') {
      UI.log(`← peers: ${msg.peers.length}`, msg.peers.length ? 'ok' : 'wr');
      for (const p of msg.peers) {
        if (!p.pubKey) continue;
        Session.createSession(p.id, B64.dec(p.pubKey));
        sendKeyExchange(p.id);
      }
      UI.updatePeers(Session.getAll());
    }

    if (msg.type === 'peer-joined') {
      const p = msg.peer;
      UI.log(`← peer-joined: ${p.id}`, 'ok');
      if (p.pubKey) {
        Session.createSession(p.id, B64.dec(p.pubKey));
        sendKeyExchange(p.id);
      }
      UI.updatePeers(Session.getAll());
    }

    if (msg.type === 'msg' && msg.data) {
      const d = msg.data;
      if (d.type === 'kx')          handleKeyExchange(msg.from, d);
      if (d.type === 'kx-response') handleKeyExchangeResponse(msg.from, d);
      if (d.type === 'enc')         handleEncrypted(msg.from, d);
      if (d.type === 'rotate')      handleRotationRequest(msg.from, d);
    }

    if (msg.type === 'leave') {
      UI.log(`${msg.userId} left`);
      Session.removeSession(msg.userId);
      UI.updatePeers(Session.getAll());
      UI.addSystem(`${msg.userId} hat verlassen`);
    }
  }

  // ── Key Exchange ──
  function sendKeyExchange(peerId) {
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
      data: { type: 'kx', ...payload }
    }));

    UI.log(`KX → ${peerId}`, 'ok');
  }

  async function handleKeyExchange(from, d) {
    UI.log(`← KX von ${from}`, 'ok');

    if (Math.abs(Date.now() - d.timestamp) > 30000) {
      UI.log(`KX von ${from} abgelaufen`, 'wr');
      return;
    }

    if (!Crypto.verifyKeyExchange(d)) {
      UI.log(`⚠ KX Signatur von ${from} UNGÜLTIG!`, 'no');
      UI.addSystem(`⚠ Warnung: ${from} hat ungültige Signatur!`);
      return;
    }

    const pubKey = B64.dec(d.pubKey);
    const ephemeralPubKey = B64.dec(d.ephemeralPubKey);

    let session = Session.getSession(from);
    if (!session) {
      session = Session.createSession(from, pubKey);
    }

    session.theirPubKey = pubKey;
    session.theirEphemeralPub = ephemeralPubKey;

    if (await Session.computeSharedSecret(from)) {
      UI.log(`Session mit ${from} etabliert`, 'ok');
      UI.addSystem(`${from} verbunden — verifiziere Fingerabdruck!`, true);
    }

    sendKeyExchangeResponse(from);
    UI.updatePeers(Session.getAll());
  }

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

  async function handleKeyExchangeResponse(from, d) {
    UI.log(`← KX-Response von ${from}`, 'ok');

    if (Math.abs(Date.now() - d.timestamp) > 30000) return;
    if (!Crypto.verifyKeyExchange(d)) {
      UI.log(`⚠ KX-Response Signatur von ${from} UNGÜLTIG!`, 'no');
      return;
    }

    const session = Session.getSession(from);
    if (!session) return;

    session.theirEphemeralPub = B64.dec(d.ephemeralPubKey);

    if (await Session.computeSharedSecret(from)) {
      UI.log(`Session mit ${from} vollständig`, 'ok');
      UI.updatePeers(Session.getAll());
    }
  }

  // ── Verschlüsselte Nachrichten ──
  function handleEncrypted(from, d) {
    const session = Session.getSession(from);
    if (!session || !session.established) {
      UI.log(`ENC von ${from}, keine Session`, 'wr');
      return;
    }

    if (session.recvNonces.has(d.n)) {
      UI.log(`Replay-Angriff von ${from}!`, 'no');
      return;
    }

    try {
      const nonce = B64.dec(d.n);
      const ciphertext = B64.dec(d.c);
      const plaintext = Crypto.decryptWithSession(ciphertext, nonce, session.sharedSecret);

      if (plaintext === null) {
        UI.log(`Decrypt failed von ${from}`, 'no');
        return;
      }

      session.recvNonces.add(d.n);
      session.msgCount++;
      UI.addMessage(from, plaintext, false);
      msgCount++;
      UI.updateStats(msgCount);

      if (Session.needsRotation(from)) triggerRotation(from);

    } catch (e) {
      UI.log(`Decrypt error von ${from}: ${e.message}`, 'no');
    }
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

    if (!socket || socket.readyState !== 1) {
      UI.log('WS nicht bereit', 'no');
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
      UI.addSystem(`🔒 VERIFIZIERUNG ERFORDERLICH: ${unverified.join(', ')}`);
      UI.addSystem(`Klicke auf "⚠" in der Seitenleiste, um Fingerabdrücke zu vergleichen.`);
      return;
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

        const encrypted = Crypto.encryptWithSession(text, session.sharedSecret, nonce);
        if (!encrypted) continue;

        socket.send(JSON.stringify({
          type: 'msg',
          from: myId,
          to: pid,
          data: { type: 'enc', n: B64.enc(nonce), c: B64.enc(encrypted) }
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
    Session.rotate(peerId);
    sendKeyExchange(peerId);
    UI.addSystem(`🔄 Schlüssel-Rotation mit ${peerId}`);
  }

  function handleRotationRequest(from, d) {
    UI.log(`← Rotation von ${from}`, 'inf');
    const session = Session.getSession(from);
    if (session) {
      session.msgCount = 0;
    }
  }

  // ── Fingerprint Verification ──
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
      UI.log(`${peerId} verifiziert ✓`, 'ok');
      UI.updatePeers(Session.getAll());

      let allVerified = true;
      Session.getAll().forEach(s => { if (!s.verified) allVerified = false; });
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
