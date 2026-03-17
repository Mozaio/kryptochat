/* ═══════════════════════════════════════════════════
   session.js — v4.1 (Bugfix)

   FIX ①: initRatchet() leitet nextRecvHeaderKey aus
           demselben DUMMY_DH-Pfad ab, den encrypt()
           beim ersten Senden nutzt.
           → Bob kann Alices erste Nachricht entschlüsseln.

   FIX ②: Dummy-Traffic prüft isDummy() korrekt
           (war bereits richtig, keine Änderung).
   ═══════════════════════════════════════════════════ */

const Session = (() => {
  const sessions = new Map();
  let _myLongTermPubKey = null;
  let _socket           = null;
  let _myAnonId         = null;
  let _dummyTimer       = null;

  function setMyLongTermKey(pubKey) { _myLongTermPubKey = pubKey; }

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
      myCommitment:         null,
      myCommitNonce:        null,
      myCommitTimestamp:    0,
      theirCommitment:      null,
      theirCommitNonce:     null,
      theirCommitTimestamp: 0,
      msgCount:             0,
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
    if (s.myEphemeral) burn(s.myEphemeral.secretKey, s.myEphemeral.publicKey);
    if (s.ratchet)     DoubleRatchet.destroy(s.ratchet);
    sessions.delete(peerAnonId);
  }

  // ══════════════════════════════════════════
  //  initRatchet — FIX ①
  //
  //  Beide Seiten (Alice und Bob) leiten beim Start aus demselben
  //  sharedSecret + DUMMY_DH denselben rootKey → headerKey ab.
  //
  //  Alice (Sender der ersten Nachricht):
  //    encrypt() → DUMMY_DH → sendHeaderKey = X
  //
  //  Bob (Empfänger der ersten Nachricht):
  //    Muss X in nextRecvHeaderKey haben, damit decrypt() Stufe 2 trifft.
  //    (recvHeaderKey ist noch null, da kein DH-Ratchet stattgefunden hat)
  //
  //  Da kdfRK deterministisch ist und beide denselben sharedSecret haben,
  //  leiten beide dasselbe headerKey ab.
  //  Bob setzt nextRecvHeaderKey = dieses headerKey → decrypt() Stufe 2 ✓
  // ══════════════════════════════════════════

  async function initRatchet(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.sharedSecret) return false;

    s.ratchet = DoubleRatchet.create(s.sharedSecret);

    // FIX ①: nextRecvHeaderKey vorinitialisieren.
    // HKDF ist async → initRatchet muss async sein.
    // Wir leiten denselben headerKey ab, den encrypt() beim ersten
    // Aufruf (DUMMY_DH-Pfad) berechnen würde:
    //   kdfRK(sharedSecret, DUMMY_DH) → rootKey2 + chainKey + headerKey
    // Dieses headerKey ist Alices sendHeaderKey für die erste Nachricht.
    // Bob speichert es als nextRecvHeaderKey.
    try {
      const ikmKey = await crypto.subtle.importKey(
        'raw', new Uint8Array(32), // DUMMY_DH
        { name: 'HKDF' }, false, ['deriveBits']
      );
      const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-512',
          salt: s.sharedSecret,
          info: new TextEncoder().encode('kryptochat-ratchet-root-v1') },
        ikmKey, 96 * 8
      );
      const out = new Uint8Array(bits);
      // out[64..96] = headerKey, identisch mit Alices sendHeaderKey
      s.ratchet.nextRecvHeaderKey = out.slice(64, 96);
      burn(out);
    } catch (e) {
      console.error('[Kryptochat] initRatchet HKDF Fehler:', e);
      return false;
    }

    // Sealed-Sender-Key ableiten
    const si = new Uint8Array(64);
    si.set(s.sharedSecret, 0);
    si.set(new TextEncoder().encode('sealed-sender-v1'), 32);
    s.sealedKey = nacl.hash(si).slice(0, 32);
    burn(si);

    return true;
  }

  function computeSharedSecret(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.theirEphemeralPub || !s.myEphemeral || !_myLongTermPubKey)
      return Promise.resolve(false);

    const ephShared = nacl.box.before(s.theirEphemeralPub, s.myEphemeral.secretKey);

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

    return crypto.subtle.digest('SHA-512', combined).then(async buf => {
      const h = new Uint8Array(buf);
      s.sharedSecret = h.slice(0, 32);
      s.established  = true;

      // initRatchet ist jetzt async
      await initRatchet(peerAnonId);

      burn(combined, ephShared, h);
      return true;
    });
  }

  // ── Session-Fingerprint ───────────────────────────

  function getSessionFingerprint(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.sharedSecret || !_myLongTermPubKey || !s.theirPubKey) return null;
    return Crypto.fingerprintSession(s.sharedSecret, _myLongTermPubKey, s.theirPubKey);
  }

  // ── Encrypt / Decrypt ─────────────────────────────

  async function encryptMessage(peerAnonId, plaintext) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.ratchet) return null;
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
    const data  = new TextEncoder().encode(senderAnonId);
    const enc   = nacl.secretbox(data, nonce, sealedKey);
    burn(data);
    return { sealedId: B64.enc(enc), sealedNonce: B64.enc(nonce) };
  }

  function unsealSenderId(sealedKey, sealedIdB64, sealedNonceB64) {
    try {
      const data = nacl.secretbox.open(B64.dec(sealedIdB64), B64.dec(sealedNonceB64), sealedKey);
      return data ? new TextDecoder().decode(data) : null;
    } catch { return null; }
  }

  // ── Dummy-Traffic ─────────────────────────────────

  async function _sendDummy() {
    if (!_socket || _socket.readyState !== 1) return;
    for (const [peerId, s] of sessions) {
      if (!s.ratchet || !s.sealedKey || !s.verified) continue;
      try {
        const dummy  = 'dummy:' + B64.enc(nacl.randomBytes(16));
        const enc    = await DoubleRatchet.encrypt(s.ratchet, dummy);
        const sealed = sealSenderId(s.sealedKey, _myAnonId);
        const payload = { type: 'enc', eh: enc.encHeader, n: enc.nonce, c: enc.ciphertext,
                          si: sealed.sealedId, sn: sealed.sealedNonce };
        const inner  = B64.enc(new TextEncoder().encode(JSON.stringify(payload)));
        _socket.send(JSON.stringify({ type: 'relay', to: peerId, d: inner }));
      } catch { /* still */ }
    }
  }

  function startDummyTraffic() {
    stopDummyTraffic();
    function schedule() {
      const delay = 8000 + (nacl.randomBytes(4)[0] / 255) * 17000;
      _dummyTimer = setTimeout(async () => {
        await _sendDummy();
        schedule();
      }, delay);
    }
    schedule();
  }

  function stopDummyTraffic() {
    if (_dummyTimer) { clearTimeout(_dummyTimer); _dummyTimer = null; }
  }

  function isDummy(pt) {
    return typeof pt === 'string' && pt.startsWith('dummy:');
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
    getSessionFingerprint,
    encryptMessage, decryptMessage,
    sealSenderId, unsealSenderId,
    startDummyTraffic, stopDummyTraffic, isDummy,
    needsHeartbeat, recordHeartbeat,
    getAll, destroyAll
  };
})();
