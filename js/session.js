/* ═══════════════════════════════════════════════════
   session.js — v4 (Security-Hardened)

   Neu:
   ① Session-Fingerprint: bestätigt shared secret beidseitig
   ② Dummy-Traffic: sendet verschlüsselte Fake-Pakete in Pausen
      → Traffic-Analyse kann nicht unterscheiden ob jemand schreibt
   ③ Key-Rotation-Warnung nach 1000 Nachrichten
   ④ Alle sensiblen Daten werden bei removeSession geburnt
   ═══════════════════════════════════════════════════ */

const Session = (() => {
  const sessions = new Map();
  let _myLongTermPubKey = null;
  let _socket           = null;
  let _myAnonId         = null;
  let _dummyTimer       = null;

  function setMyLongTermKey(pubKey) { _myLongTermPubKey = pubKey; }

  // Wird von app.js gesetzt, damit Session.sendDummy() den Socket nutzen kann
  function setSocket(socket, anonId) {
    _socket   = socket;
    _myAnonId = anonId;
  }

  function createSession(peerAnonId, theirPubKey) {
    const session = {
      peerAnonId,
      theirPubKey,
      myEphemeral:          null,
      theirEphemeralPub:    null,
      sharedSecret:         null,
      ratchet:              null,
      sealedKey:            null,
      verified:             false,
      established:          false,
      keySent:              false,
      myCommitment:         null,   // Uint8Array(32)
      myCommitNonce:        null,   // NEU: Blinding-Nonce für Reveal
      myCommitTimestamp:    0,
      theirCommitment:      null,
      theirCommitNonce:     null,   // NEU: Nonce vom Peer für Verifikation
      theirCommitTimestamp: 0,
      msgCount:             0,      // NEU: für Key-Rotation-Warnung
      lastHeartbeat:        0,
      createdAt:            Date.now()
    };
    sessions.set(peerAnonId, session);
    return session;
  }

  function getSession(peerAnonId)  { return sessions.get(peerAnonId); }

  function removeSession(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (!s) return;
    burn(s.sharedSecret, s.sealedKey, s.myCommitment, s.myCommitNonce,
         s.theirCommitment, s.theirCommitNonce);
    if (s.myEphemeral)  burn(s.myEphemeral.secretKey, s.myEphemeral.publicKey);
    if (s.ratchet)      DoubleRatchet.destroy(s.ratchet);
    sessions.delete(peerAnonId);
  }

  function initRatchet(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.sharedSecret) return false;

    s.ratchet = DoubleRatchet.create(s.sharedSecret);

    // Sealed-Sender-Key ableiten
    const si = new Uint8Array(64);
    si.set(s.sharedSecret, 0);
    si.set(U8.enc('sealed-sender-v1'), 32);
    s.sealedKey = nacl.hash(si).slice(0, 32);
    burn(si);
    return true;
  }

  function computeSharedSecret(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.theirEphemeralPub || !s.myEphemeral || !_myLongTermPubKey)
      return Promise.resolve(false);

    const ephShared = nacl.box.before(s.theirEphemeralPub, s.myEphemeral.secretKey);

    // Canonical Ordering der Long-Term-Keys
    let lt1, lt2, cmp = false;
    for (let i = 0; i < 32; i++) {
      if (_myLongTermPubKey[i] < s.theirPubKey[i]) { cmp = true;  break; }
      if (_myLongTermPubKey[i] > s.theirPubKey[i]) { cmp = false; break; }
    }
    lt1 = cmp ? _myLongTermPubKey : s.theirPubKey;
    lt2 = cmp ? s.theirPubKey     : _myLongTermPubKey;

    const combined = new Uint8Array(96);
    combined.set(ephShared, 0);
    combined.set(lt1, 32);
    combined.set(lt2, 64);

    return crypto.subtle.digest('SHA-512', combined).then(buf => {
      const h = new Uint8Array(buf);
      s.sharedSecret = h.slice(0, 32);
      s.established  = true;
      initRatchet(peerAnonId);
      burn(combined, ephShared, h);
      return true;
    });
  }

  // ── Session-Fingerprint ───────────────────────────
  // Gibt einen Fingerprint zurück, der den Shared Secret einschließt.
  // Stimmt der Fingerprint auf beiden Seiten überein, ist garantiert:
  //   - Kein MITM (sonst wäre sharedSecret verschieden)
  //   - Beidseitige Authentizität

  function getSessionFingerprint(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.sharedSecret || !_myLongTermPubKey || !s.theirPubKey) return null;
    return Crypto.fingerprintSession(s.sharedSecret, _myLongTermPubKey, s.theirPubKey);
  }

  // ── Encrypt / Decrypt (async) ─────────────────────

  async function encryptMessage(peerAnonId, plaintext) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.ratchet) return null;

    // Key-Rotation-Warnung bei langen Sessions
    s.msgCount = (s.msgCount || 0) + 1;
    if (s.msgCount >= 900 && s.msgCount % 100 === 0) {
      console.warn(`[Kryptochat] Session ${peerAnonId.slice(0,8)} hat ${s.msgCount} Nachrichten. Neue Session empfohlen.`);
    }

    return await DoubleRatchet.encrypt(s.ratchet, plaintext);
  }

  async function decryptMessage(peerAnonId, encHeader, nonce, ciphertext) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.ratchet) return null;
    return await DoubleRatchet.decrypt(s.ratchet, encHeader, nonce, ciphertext);
  }

  // ── Sealed Sender ─────────────────────────────────

  function sealSenderId(sealedKey, senderAnonId) {
    const nonce = nacl.randomBytes(24);
    const data  = U8.enc(senderAnonId);
    const enc   = nacl.secretbox(data, nonce, sealedKey);
    burn(data);
    return { sealedId: B64.enc(enc), sealedNonce: B64.enc(nonce) };
  }

  function unsealSenderId(sealedKey, sealedIdB64, sealedNonceB64) {
    try {
      const data = nacl.secretbox.open(B64.dec(sealedIdB64), B64.dec(sealedNonceB64), sealedKey);
      return data ? U8.dec(data) : null;
    } catch { return null; }
  }

  // ── Dummy-Traffic ─────────────────────────────────
  // Sendet verschlüsselte Fake-Nachrichten in zufälligen Intervallen.
  // Ein Netzwerk-Beobachter kann nicht unterscheiden, ob echte oder
  // Dummy-Nachrichten gesendet werden → Traffic-Analyse erschwert.
  //
  // Dummy-Nachrichten werden mit dem echten Ratchet verschlüsselt,
  // beginnen intern mit "dummy:" und werden vom Empfänger still verworfen.

  async function _sendDummy() {
    if (!_socket || _socket.readyState !== 1) return;
    for (const [peerId, s] of sessions) {
      if (!s.ratchet || !s.sealedKey || !s.verified) continue;
      try {
        const dummy   = 'dummy:' + B64.enc(nacl.randomBytes(16));
        const enc     = await DoubleRatchet.encrypt(s.ratchet, dummy);
        const sealed  = sealSenderId(s.sealedKey, _myAnonId);
        const payload = { type: 'enc', eh: enc.encHeader, n: enc.nonce, c: enc.ciphertext,
                          si: sealed.sealedId, sn: sealed.sealedNonce };
        const inner   = B64.enc(U8.enc(JSON.stringify(payload)));
        _socket.send(JSON.stringify({ type: 'relay', to: peerId, d: inner }));
      } catch { /* still */ }
    }
  }

  function startDummyTraffic() {
    stopDummyTraffic();
    // Zufälliges Intervall: 8-25 Sekunden
    function schedule() {
      const delay = 8000 + (nacl.randomBytes(4)[0] / 255) * 17000;
      _dummyTimer = setTimeout(async () => {
        await _sendDummy();
        schedule(); // rekursiv mit neuem zufälligem Delay
      }, delay);
    }
    schedule();
  }

  function stopDummyTraffic() {
    if (_dummyTimer) { clearTimeout(_dummyTimer); _dummyTimer = null; }
  }

  // Prüft ob eine entschlüsselte Nachricht ein Dummy ist
  function isDummy(plaintext) {
    return typeof plaintext === 'string' && plaintext.startsWith('dummy:');
  }

  // ── Heartbeat ─────────────────────────────────────

  function needsHeartbeat(peerAnonId) {
    const s = sessions.get(peerAnonId);
    return s?.established && (Date.now() - s.lastHeartbeat) > 20000;
  }

  function recordHeartbeat(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (s) s.lastHeartbeat = Date.now();
  }

  function getAll()     { return sessions; }
  function destroyAll() { sessions.forEach((_, id) => removeSession(id)); stopDummyTraffic(); }

  return {
    setMyLongTermKey, setSocket,
    createSession, getSession, removeSession,
    computeSharedSecret, initRatchet,
    getSessionFingerprint,        // NEU: Session-basierter Fingerprint
    encryptMessage, decryptMessage,
    sealSenderId, unsealSenderId,
    startDummyTraffic,            // NEU
    stopDummyTraffic,             // NEU
    isDummy,                      // NEU
    needsHeartbeat, recordHeartbeat,
    getAll, destroyAll
  };
})();
