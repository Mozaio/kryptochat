/* ═══════════════════════════════════════════════════
   session.js — Session-Management v3

   Anpassungen an ratchet.js v3:
   - encryptMessage / decryptMessage sind async (HKDF)
   - encrypt gibt { encHeader, nonce, ciphertext } zurück
   - decrypt erwartet (peerAnonId, encHeader, nonce, ciphertext)
     statt vorher (peerAnonId, header, nonce, ciphertext)
   ═══════════════════════════════════════════════════ */

const Session = (() => {
  const sessions = new Map();
  let _myLongTermPubKey = null;

  function setMyLongTermKey(pubKey) { _myLongTermPubKey = pubKey; }

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
      myCommitTimestamp:    0,
      theirCommitment:      null,
      theirCommitTimestamp: 0,
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
    _burn(s.sharedSecret, s.sealedKey);
    if (s.myEphemeral)    _burn(s.myEphemeral.secretKey, s.myEphemeral.publicKey);
    if (s.ratchet)        DoubleRatchet.destroy(s.ratchet);
    if (s.myCommitment)   _burn(s.myCommitment);
    if (s.theirCommitment) _burn(s.theirCommitment);
    sessions.delete(peerAnonId);
  }

  function initRatchet(peerAnonId) {
    const session = sessions.get(peerAnonId);
    if (!session || !session.sharedSecret) return false;
    session.ratchet = DoubleRatchet.create(session.sharedSecret);
    // Sealed Sender Key ableiten
    const si = new Uint8Array(64);
    si.set(session.sharedSecret, 0);
    si.set(U8.enc('sealed-sender-v1'), 32);
    session.sealedKey = nacl.hash(si).slice(0, 32);
    _burn(si);
    return true;
  }

  function computeSharedSecret(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.theirEphemeralPub || !s.myEphemeral || !_myLongTermPubKey)
      return Promise.resolve(false);

    const ephShared = nacl.box.before(s.theirEphemeralPub, s.myEphemeral.secretKey);

    let lt1, lt2;
    let cmp = false;
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
      _burn(combined, ephShared, h);
      return true;
    });
  }

  // ── async: HKDF in ratchet erfordert await ──

  async function encryptMessage(peerAnonId, plaintext) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.ratchet) return null;
    return await DoubleRatchet.encrypt(s.ratchet, plaintext);
    // Gibt zurück: { encHeader: {enc,nonce}, nonce, ciphertext }
  }

  // encHeader ist jetzt { enc, nonce } statt { dh, n, pn }

  async function decryptMessage(peerAnonId, encHeader, nonce, ciphertext) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.ratchet) return null;
    return await DoubleRatchet.decrypt(s.ratchet, encHeader, nonce, ciphertext);
  }

  // ── Sealed Sender (unverändert) ──

  function sealSenderId(sealedKey, senderAnonId) {
    const nonce = nacl.randomBytes(24);
    const data  = U8.enc(senderAnonId);
    const enc   = nacl.secretbox(data, nonce, sealedKey);
    _burn(data);
    return { sealedId: B64.enc(enc), sealedNonce: B64.enc(nonce) };
  }

  function unsealSenderId(sealedKey, sealedIdB64, sealedNonceB64) {
    try {
      const data = nacl.secretbox.open(B64.dec(sealedIdB64), B64.dec(sealedNonceB64), sealedKey);
      return data ? U8.dec(data) : null;
    } catch { return null; }
  }

  function needsHeartbeat(peerAnonId) {
    const s = sessions.get(peerAnonId);
    return s?.established && (Date.now() - s.lastHeartbeat) > 20000;
  }

  function recordHeartbeat(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (s) s.lastHeartbeat = Date.now();
  }

  function getAll()     { return sessions; }
  function destroyAll() { sessions.forEach((_, id) => removeSession(id)); }

  function _burn(...arrays) {
    arrays.forEach(a => {
      if (a instanceof Uint8Array) { a.set(nacl.randomBytes(a.length)); a.fill(0); }
    });
  }

  return {
    setMyLongTermKey, createSession, getSession, removeSession,
    computeSharedSecret, initRatchet,
    encryptMessage, decryptMessage,   // beide async
    sealSenderId, unsealSenderId,
    needsHeartbeat, recordHeartbeat,
    getAll, destroyAll
  };
})();
