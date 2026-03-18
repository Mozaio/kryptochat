/* app.js — v5
   ① Commitment mit Blinding-Nonce
   ② Session-Fingerprint (sharedSecret einbezogen)
   ③ Opakes Relay-Envelope
   ④ Screenshot-Schutz (korrekt — kein DOM-Überschreibungs-Bug)
   ⑤ Transcript-Hash sichtbar im UI
   ⑥ Dummy-Traffic startet nach erstem Key-Exchange
   ⑦ Verifizierung optional (Warnung, kein Blocker)
*/
(() => {
  if (typeof nacl === 'undefined') {
    document.body.innerHTML = '<p style="color:red;padding:2rem">TweetNaCl nicht geladen.</p>'; return;
  }

  const myKeys    = KCrypto.generateKeyPair();
  const mySigning = KCrypto.generateSigningKeyPair();
  const myAnonId  = makeAnonId();
  let socket = null, room = null, connected = false;
  let _disappearAfter = 0; // 0 = aus, sonst Millisekunden
  const _seenCommits = new Set(); // Replay-Schutz für Key-Exchange-Commits

  Session.setMyLongTermKey(myKeys.publicKey);
  $('mid').textContent = myAnonId.slice(0, 8);
  UI.initLogToggle();
  UI.log(`ID: ${myAnonId}`, 'ok');

  // ── ML-KEM-768 API Normalization ──────────────────
  // Normalizes @noble/post-quantum export shapes into a unified API.
  // window.nobleKyber is set by the ESM <script type=module> in index.html.
  function _initMlkem() {
    const lib = window.nobleKyber;
    if (!lib) return null;
    const k = lib.kyber768 || lib.ml_kem768 || lib.mlkem768;
    if (!k) return null;
    return {
      generateKeyPair() {
        const r = k.keygen ? k.keygen() : k.generateKeyPair();
        return { publicKey: r.publicKey || r.pk, secretKey: r.secretKey || r.sk };
      },
      encapsulate(pk) {
        const r = k.encapsulate(pk);
        return {
          cipherText:   r.cipherText   || r.ciphertext   || r.ct,
          ciphertext:   r.cipherText   || r.ciphertext   || r.ct,
          sharedSecret: r.sharedSecret || r.sharedKey    || r.ss
        };
      },
      decapsulate(ct, sk) {
        const r = k.decapsulate(ct, sk);
        return { sharedSecret: r.sharedSecret || r.sharedKey || r.ss || r };
      }
    };
  }
  // Try immediately, then retry once after 800ms for slow ESM loads
  window._mlkem = _initMlkem();
  if (!window._mlkem) {
    setTimeout(() => {
      window._mlkem = _initMlkem();
      UI.log(window._mlkem ? 'ML-KEM-768 loaded ✓' : 'ML-KEM-768 not available — classical only', window._mlkem ? 'ok' : 'wr');
    }, 800);
  } else {
    UI.log('ML-KEM-768 loaded ✓', 'ok');
  }

  // ── Screenshot-Schutz (korrekt) ──────────────────
  // Tab versteckt → DOM leeren. Tab sichtbar → nichts überschreiben.
  // Nachrichten die ankamen während Tab versteckt war, werden
  // normal durch addMessage angezeigt wenn der Tab wieder aktiv ist.
  document.addEventListener('visibilitychange', () => {
    const mc = $('mc');
    if (!mc) return;
    if (document.visibilityState === 'hidden') mc.innerHTML = '';
  });

  // ── Cleanup ──────────────────────────────────────
  function cleanup() {
    Session.stopDummyTraffic();
    burn(myKeys.secretKey, myKeys.publicKey, mySigning.secretKey, mySigning.publicKey);
    Session.destroyAll();
    KCrypto.resetTranscript();
    const mc = $('mc'); if (mc) mc.innerHTML = '';
    socket = null; room = null; _seenCommits.clear();
  }
  window.addEventListener('beforeunload', cleanup);
  window.addEventListener('pagehide',     cleanup);
  window.addEventListener('unload',       cleanup);

  // ── Join ─────────────────────────────────────────
  $('rin').addEventListener('keydown', e => { if (e.key === 'Enter') joinRoom(); });
  $('jbtn').addEventListener('click', joinRoom);

  async function joinRoom() {
    const r = $('rin').value.trim();
    if (!r) { $('rin').focus(); return; }
    UI.setJoinStatus('Connecting...');
    UI.setJoinDisabled(true);
    room = r; await connect(r);
  }

  // ── WebSocket ────────────────────────────────────
  async function connect(r) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    try { socket = new WebSocket(`${proto}//${location.host}`); }
    catch (e) { UI.log(`WS Error: ${e.message}`, 'no'); UI.setJoinDisabled(false); return; }

    socket.onopen = () => {
      connected = true;
      Session.setSocket(socket, myAnonId);
      UI.log('Relay ✓', 'ok');
      socket.send(JSON.stringify({ type: 'join', room: r, anonId: myAnonId }));
      jitter(200, 600).then(() => UI.showRoom(r));
    };
    socket.onmessage = e => {
      let msg; try { msg = JSON.parse(e.data); } catch { return; }
      handleMessage(msg);
    };
    socket.onclose = () => {
      connected = false;
      Session.stopDummyTraffic();
      socket = null;
      $('est').textContent = 'Disconnected'; $('est').style.color = 'var(--rd)';
      UI.addSystem('Connection lost — reconnecting...');
      // Do NOT destroy sessions on reconnect — ratchet state is preserved.
      // When the peer reconnects, the key exchange runs again and the
      // existing ratchet is replaced by a new one. This is safe.
      UI.updatePeers(Session.getAll());
      setTimeout(() => { if (room && !connected) connect(room); }, 3000);
    };
    socket.onerror = () => { UI.log('Relay error', 'no'); UI.setJoinStatus('Error!'); UI.setJoinDisabled(false); };
  }

  // ── Relay ─────────────────────────────────────────
  // Klartext für Key-Exchange (vor Ratchet)
  function relayTo(peerId, data) {
    if (!socket || socket.readyState !== 1) return;
    socket.send(JSON.stringify({ type: 'relay', to: peerId, d: data }));
  }
  // Opakes Envelope für verschlüsselte Nachrichten
  function relayEncrypted(peerId, data) {
    if (!socket || socket.readyState !== 1) return;
    const inner = B64.enc(new TextEncoder().encode(JSON.stringify(data)));
    socket.send(JSON.stringify({ type: 'relay', to: peerId, d: inner }));
  }

  // ── Message Handling ──────────────────────────────
  function handleMessage(msg) {
    if (msg.t === 'peers') { for (const p of msg.p) startKeyExchange(p.a); }
    if (msg.t === 'join')  { startKeyExchange(msg.a); }
    if (msg.t === 'msg' && msg.d !== undefined) {
      let d = msg.d;
      if (typeof d === 'string') {
        try { d = JSON.parse(new TextDecoder().decode(B64.dec(d))); } catch { return; }
      }
      switch (d.type) {
        case 'commit': handleCommit(d); break;
        case 'key':    handleKey(d);    break;
        case 'kem':    handleKem(d);    break;
        case 'enc':    handleEncrypted(d); break;
      }
    }
    if (msg.t === 'leave') {
      Session.removeSession(msg.a);
      UI.updatePeers(Session.getAll());
      UI.addSystem(`${msg.a.slice(0,8)} has left`);
    }
  }

  // ── Key Exchange mit Commitment + Blinding ─────────
  function startKeyExchange(peerId) {
    let s = Session.getSession(peerId);
    if (!s) {
      s = Session.createSession(peerId, null);
    } else {
      // Reset keySent so we can re-exchange keys after reconnect
      s.keySent = false;
      s.myEphemeral = null; // force new ephemeral keypair
    }
    if (!s.myEphemeral) s.myEphemeral = KCrypto.generateKeyPair();
    // Generate ML-KEM keypair lazily (library may not have been ready at createSession time)
    if (!s.mlkemKeyPair && window._mlkem) {
      try { s.mlkemKeyPair = window._mlkem.generateKeyPair(); } catch {}
    }

    const ts       = Date.now();
    const commData = new Uint8Array(72);
    commData.set(myKeys.publicKey, 0);
    commData.set(s.myEphemeral.publicKey, 32);
    new DataView(commData.buffer).setBigUint64(64, BigInt(ts), false);

    const { commitment, nonce: blindNonce } = KCrypto.commit(commData);
    s.myCommitment      = commitment;
    s.myCommitNonce     = blindNonce;
    s.myCommitTimestamp = ts;

    relayTo(peerId, { type: 'commit', from: myAnonId, comm: B64.enc(commitment), timestamp: ts });
    if (s.theirCommitment) sendKey(peerId);
  }

  function handleCommit(d) {
    // Replay-Schutz: gleicher Commit darf nicht zweimal verarbeitet werden
    const commitKey = d.from + ':' + d.comm + ':' + d.timestamp;
    if (_seenCommits.has(commitKey)) return;
    _seenCommits.add(commitKey);
    // Cache-Größe begrenzen
    if (_seenCommits.size > 200) {
      const iter = _seenCommits.values();
      while (_seenCommits.size > 100) { const v = iter.next(); if (v.done) break; _seenCommits.delete(v.value); }
    }
    // Timestamp prüfen (Commit darf max. 60s alt sein)
    if (Math.abs(Date.now() - d.timestamp) > 60000) return;

    let s = Session.getSession(d.from);
    if (!s) s = Session.createSession(d.from, null);
    s.theirCommitment      = B64.dec(d.comm);
    s.theirCommitTimestamp = d.timestamp;
    sendKey(d.from);
  }

  function sendKey(peerId) {
    const s = Session.getSession(peerId);
    if (!s || !s.myEphemeral || s.keySent) return;
    s.keySent = true;
    const payload = {
      from: myAnonId, to: peerId,
      pubKey:          B64.enc(myKeys.publicKey),
      ephemeralPubKey: B64.enc(s.myEphemeral.publicKey),
      signingPubKey:   B64.enc(mySigning.publicKey),
      commitNonce:     B64.enc(s.myCommitNonce),
      timestamp:       s.myCommitTimestamp,
      // ML-KEM-768 public key (post-quantum)
      mlkemPubKey: s.mlkemKeyPair ? B64.enc(s.mlkemKeyPair.publicKey) : null
    };
    const sigData = { from: payload.from, to: payload.to, pubKey: payload.pubKey, ephemeralPubKey: payload.ephemeralPubKey, commitNonce: payload.commitNonce, timestamp: payload.timestamp };
    payload.signature = B64.enc(KCrypto.sign(sigData, mySigning.secretKey));
    relayTo(peerId, { type: 'key', ...payload });
  }

  async function handleKey(d) {
    const s = Session.getSession(d.from);
    if (!s) return;
    if (Math.abs(Date.now() - d.timestamp) > 30000) return;

    const sigData = { from: d.from, to: d.to, pubKey: d.pubKey, ephemeralPubKey: d.ephemeralPubKey, commitNonce: d.commitNonce, timestamp: d.timestamp };
    if (!KCrypto.verify(sigData, B64.dec(d.signature), B64.dec(d.signingPubKey))) {
      UI.addSystem(`⚠ ${d.from.slice(0,8)}: invalid signature — possible attack!`); return;
    }

    // Commitment mit Blinding-Nonce prüfen
    if (s.theirCommitment) {
      const commData = new Uint8Array(72);
      commData.set(B64.dec(d.pubKey), 0);
      commData.set(B64.dec(d.ephemeralPubKey), 32);
      new DataView(commData.buffer).setBigUint64(64, BigInt(s.theirCommitTimestamp), false);
      if (!KCrypto.verifyCommit(commData, B64.dec(d.commitNonce), s.theirCommitment)) {
        UI.addSystem('🚨 Tampering attempt detected! Connection aborted.');
        Session.removeSession(d.from); return;
      }
    }

    s.theirPubKey       = B64.dec(d.pubKey);
    s.theirEphemeralPub = B64.dec(d.ephemeralPubKey);

    // ── ML-KEM-768 Post-Quantum Hybrid ──────────────
    // isAlice (smaller LT key) encapsulates and sends KEM ciphertext.
    // Bob decapsulates when he receives it.
    if (d.mlkemPubKey) {
      s.theirMlkemPub = B64.dec(d.mlkemPubKey);
      // Determine isAlice (same logic as session.js)
      let isAlice = false;
      for (let i = 0; i < 32; i++) {
        if (myKeys.publicKey[i] < s.theirPubKey[i]) { isAlice = true;  break; }
        if (myKeys.publicKey[i] > s.theirPubKey[i]) { isAlice = false; break; }
      }
      if (isAlice && window._mlkem) {
        // Alice: encapsulate with Bob's ML-KEM pub key
        try {
          // Note: { cipherText } or { ciphertext } depending on library version
          const kemResult = window._mlkem.encapsulate(s.theirMlkemPub);
          const kemCT = kemResult.cipherText || kemResult.ciphertext;
          const kemSS = kemResult.sharedSecret;
          s.kemSecret     = new Uint8Array(kemSS); // copy — do NOT burn original yet
          s.kemCiphertext = kemCT;
          // Send KEM ciphertext to Bob
          relayTo(d.from, { type: 'kem', from: myAnonId, ct: B64.enc(kemCT) });
        } catch (e) { UI.log('ML-KEM encap error: ' + e.message, 'wr'); }
      }
    }

    // isAlice check for timing: Alice encapsulates KEM and already has kemSecret,
    // so she can compute sharedSecret immediately.
    // Bob has NOT received the KEM ciphertext yet — his kemSecret is still null.
    // Bob will call computeSharedSecret from handleKem after decapsulation.
    const isAliceForKem = d.mlkemPubKey && s.kemSecret; // Alice: has kemSecret
    // noKem = PQ not available, OR Bob has no keypair (keygen failed)
    const noKem = !d.mlkemPubKey || !window._mlkem || (!s.kemSecret && !s.mlkemKeyPair);

    if (isAliceForKem || noKem) {
      // Alice or no-PQ: compute immediately
      if (await Session.computeSharedSecret(d.from)) {
        const pqLabel = s.kemSecret ? ' + ML-KEM-768 ✓' : '';
        UI.addSystem(`${d.from.slice(0,8)} connected${pqLabel} — verify fingerprint`, true);
        if (Session.getAll().size >= 1) Session.startDummyTraffic();
      }
    }
    // Bob with PQ: waits for handleKem to call computeSharedSecret

    if (!s.keySent) sendKey(d.from);
    UI.updatePeers(Session.getAll());
  }

  // ── KEM Ciphertext Handler (Post-Quantum) ───────────
  async function handleKem(d) {
    const s = Session.getSession(d.from);
    if (!s || !s.mlkemKeyPair || !d.ct) return;
    // Bob: decapsulate KEM ciphertext from Alice
    try {
      if (window._mlkem) {
        const ct = B64.dec(d.ct);
        const decapResult = window._mlkem.decapsulate(ct, s.mlkemKeyPair.secretKey);
        const kemSS = decapResult.sharedSecret;
        if (!kemSS) { UI.log('ML-KEM decap: no sharedSecret', 'wr'); return; }
        s.kemSecret = new Uint8Array(kemSS);
        UI.log('ML-KEM-768 decapsulated ✓', 'ok');
        // Bob now has kemSecret — compute the real sharedSecret
        if (!s.established) {
          // Normal path: compute for first time with real kemSecret
          if (await Session.computeSharedSecret(d.from)) {
            UI.addSystem(`${d.from.slice(0,8)} connected + ML-KEM-768 ✓ — verify fingerprint`, true);
            if (Session.getAll().size >= 1) Session.startDummyTraffic();
          }
        } else {
          // Already established (shouldn't happen in normal flow, but handle gracefully)
          await Session.recomputeWithKem(d.from);
        }
      }
    } catch (e) { UI.log('ML-KEM decap error: ' + e.message, 'wr'); }
  }

  // ── Encrypted Messages ────────────────────────────
  async function handleEncrypted(d) {
    let targetPeerId = null;

    if (d.si && d.sn) {
      for (const [peerId, s] of Session.getAll()) {
        if (!s.sealedKey || !s.established) continue;
        if (Session.unsealSenderId(s.sealedKey, d.si, d.sn) !== null) {
          targetPeerId = peerId; break;
        }
      }
    }
    if (!targetPeerId) {
      for (const [peerId, s] of Session.getAll()) {
        if (s.ratchet) { targetPeerId = peerId; break; }
      }
    }
    if (!targetPeerId) return;

    try {
      // Support encHeader (v7) and header (v6 fallback)
      const pt = await Session.decryptMessage(targetPeerId, d.eh || d.h, d.n, d.c);
      if (pt === null) return;
      if (Session.isDummy(pt)) return;

      // Transcript-Hash aktualisieren
      KCrypto.updateTranscript(pt);
      UI.updateTranscript(KCrypto.getTranscriptHash());

      const recvEl = UI.addMessage(targetPeerId, pt, false);
      if (_disappearAfter > 0 && recvEl) scheduleDelete(recvEl);
    } catch {}
  }

  // ── Senden ───────────────────────────────────────
  // ── Disappearing Messages ────────────────────────
  function scheduleDelete(el) {
    if (!el || _disappearAfter <= 0) return;
    setTimeout(() => {
      el.style.transition = 'opacity 0.5s';
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 500);
    }, _disappearAfter);
  }

  // Disappear-Toggle in UI (falls vorhanden)
  const disappearSel = $('disappear-sel');
  if (disappearSel) {
    disappearSel.addEventListener('change', () => {
      _disappearAfter = parseInt(disappearSel.value) * 1000;
      const label = _disappearAfter > 0
        ? `Messages disappear after ${disappearSel.value}s`
        : 'Message disappearing: off';
      UI.addSystem(label);
    });
  }

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
    if (!socket || socket.readyState !== 1) { UI.addSystem('Relay not ready'); return; }

    const sessions = Session.getAll();
    if (sessions.size === 0) { UI.addSystem('No peer connected'); return; }

    // Blockiert nur wenn kein Ratchet — nicht bei fehlender Verifikation
    let hasNoRatchet = false;
    sessions.forEach(s => { if (!s.established) hasNoRatchet = true; });
    if (hasNoRatchet) { UI.addSystem('Waiting for key exchange...'); return; }

    // Optionale Warnung bei nicht verifizierten Peers
    let anyUnverified = false;
    sessions.forEach(s => { if (!s.verified) anyUnverified = true; });
    if (anyUnverified) UI.addSystem('⚠ Fingerprint not verified — click ⚠ in the sidebar');

    let sent = 0;
    for (const [peerId, s] of sessions) {
      if (!s.ratchet || !s.sealedKey) continue;
      try {
        const enc = await Session.encryptMessage(peerId, text);
        if (!enc) continue;
        const sealed = Session.sealSenderId(s.sealedKey, myAnonId);
        await jitter(10, 80);
        // enc.encHeader = verschlüsselter Header (v7), enc.header = Klartext (v6 fallback)
        relayEncrypted(peerId, { type: 'enc', eh: enc.encHeader, h: enc.header, n: enc.nonce, c: enc.ciphertext, si: sealed.sealedId, sn: sealed.sealedNonce });
        sent++;
      } catch (e) { UI.log(`Send Error: ${e.message}`, 'no'); }
    }

    if (sent > 0) {
      KCrypto.updateTranscript(text);
      UI.updateTranscript(KCrypto.getTranscriptHash());
      const sentEl = UI.addMessage(myAnonId, text, true);
      if (_disappearAfter > 0 && sentEl) scheduleDelete(sentEl);
      $('min').value = ''; $('min').style.height = 'auto';
    }
  }

  // ── Fingerprint ───────────────────────────────────
  $('pl').addEventListener('click', e => {
    const btn = e.target.closest('.bv');
    if (!btn) return;
    const peerId = btn.dataset.p;
    const s = Session.getSession(peerId);
    if (!s || !s.theirPubKey) return;
    const fp = Session.getSessionFingerprint(peerId);
    if (fp) UI.showSessionFingerprint(fp, peerId);
    else UI.showFingerprint(myKeys.publicKey, s.theirPubKey, peerId);
  });

  $('fpy').addEventListener('click', () => {
    const peerId = $('fpm').dataset.peer;
    const s = Session.getSession(peerId);
    if (s) {
      s.verified = true;
      UI.updatePeers(Session.getAll());
      let allOk = true;
      Session.getAll().forEach(s => { if (!s.verified) allOk = false; });
      if (allOk) UI.addSystem('🔓 All peers verified — maximum security!', true);
    }
    UI.hideFingerprint();
  });
  $('fpn').addEventListener('click', () => UI.hideFingerprint());

  UI.log('Ready', 'ok');
})();
