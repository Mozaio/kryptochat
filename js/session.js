/* ═══════════════════════════════════════════════════
   session.js — Session-Management mit Double Ratchet

   Änderung: encryptMessage und decryptMessage sind jetzt
   async, da DoubleRatchet.encrypt/decrypt HKDF (Web Crypto)
   verwenden und deshalb Promises zurückgeben.
   ═══════════════════════════════════════════════════ */

const Session = (() => {
  const sessions = new Map();
  let _myLongTermPubKey = null;

  function setMyLongTermKey(pubKey) {
    _myLongTermPubKey = pubKey;
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
      myCommitTimestamp:    0,
      theirCommitment:      null,
      theirCommitTimestamp: 0,
      lastHeartbeat:        0,
      createdAt:            Date.now()
    };
    sessions.set(peerAnonId, session);
    return session;
  }

  function getSession(peerAnonId) {
    return sessions.get(peerAnonId);
  }

  function removeSession(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (!s) return;

    _burn(s.sharedSecret);
    _burn(s.sealedKey);

    if (s.myEphemeral) {
      _burn(s.myEphemeral.secretKey);
      _burn(s.myEphemeral.publicKey);
    }

    if (s.ratchet) {
      DoubleRatchet.destroy(s.ratchet);
    }

    if (s.myCommitment)   _burn(s.myCommitment);
    if (s.theirCommitment) _burn(s.theirCommitment);

    sessions.delete(peerAnonId);
  }

  function initRatchet(peerAnonId) {
    const session = sessions.get(peerAnonId);
    if (!session || !session.sharedSecret) return false;

    session.ratchet = DoubleRatchet.create(session.sharedSecret);

    const sealedInput = new Uint8Array(64);
    sealedInput.set(session.sharedSecret, 0);
    sealedInput.set(U8.enc('sealed-sender-v1'), 32);
    session.sealedKey = nacl.hash(sealedInput).slice(0, 32);
    _burn(sealedInput);

    return true;
  }

  function computeSharedSecret(peerAnonId) {
    const session = sessions.get(peerAnonId);
    if (!session || !session.theirEphemeralPub || !session.myEphemeral) {
      return Promise.resolve(false);
    }
    if (!_myLongTermPubKey) return Promise.resolve(false);

    const ephemeralShared = nacl.box.before(
      session.theirEphemeralPub,
      session.myEphemeral.secretKey
    );

    let lt1, lt2;
    let cmp = false;
    for (let i = 0; i < 32; i++) {
      if (_myLongTermPubKey[i] < session.theirPubKey[i]) { cmp = true;  break; }
      if (_myLongTermPubKey[i] > session.theirPubKey[i]) { cmp = false; break; }
    }
    if (cmp) { lt1 = _myLongTermPubKey; lt2 = session.theirPubKey; }
    else      { lt1 = session.theirPubKey; lt2 = _myLongTermPubKey; }

    const combined = new Uint8Array(96);
    combined.set(ephemeralShared, 0);
    combined.set(lt1, 32);
    combined.set(lt2, 64);

    return crypto.subtle.digest('SHA-512', combined).then(hashBuf => {
      const fullHash = new Uint8Array(hashBuf);
      session.sharedSecret = fullHash.slice(0, 32);
      session.established  = true;

      initRatchet(peerAnonId);

      _burn(combined);
      _burn(ephemeralShared);
      _burn(fullHash);

      return true;
    });
  }

  // ── Verschlüsseln — jetzt async ──
  // Grund: DoubleRatchet.encrypt verwendet HKDF (Web Crypto = Promise)

  async function encryptMessage(peerAnonId, plaintext) {
    const session = sessions.get(peerAnonId);
    if (!session || !session.ratchet) return null;
    return await DoubleRatchet.encrypt(session.ratchet, plaintext);
  }

  // ── Entschlüsseln — jetzt async ──

  async function decryptMessage(peerAnonId, header, nonce, ciphertext) {
    const session = sessions.get(peerAnonId);
    if (!session || !session.ratchet) return null;
    return await DoubleRatchet.decrypt(session.ratchet, header, nonce, ciphertext);
  }

  // ── Sealed Sender (unverändert) ──

  function sealSenderId(sealedKey, senderAnonId) {
    const nonce     = nacl.randomBytes(24);
    const data      = U8.enc(senderAnonId);
    const encrypted = nacl.secretbox(data, nonce, sealedKey);
    _burn(data);
    return {
      sealedId:    B64.enc(encrypted),
      sealedNonce: B64.enc(nonce)
    };
  }

  function unsealSenderId(sealedKey, sealedIdB64, sealedNonceB64) {
    try {
      const encrypted = B64.dec(sealedIdB64);
      const nonce     = B64.dec(sealedNonceB64);
      const data      = nacl.secretbox.open(encrypted, nonce, sealedKey);
      if (!data) return null;
      return U8.dec(data);
    } catch { return null; }
  }

  function needsHeartbeat(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.established) return false;
    return (Date.now() - s.lastHeartbeat) > 20000;
  }

  function recordHeartbeat(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (s) s.lastHeartbeat = Date.now();
  }

  function getAll() { return sessions; }

  function destroyAll() {
    sessions.forEach((_, id) => removeSession(id));
  }

  function _burn(...arrays) {
    arrays.forEach(a => {
      if (a && a instanceof Uint8Array) {
        a.set(nacl.randomBytes(a.length));
        a.fill(0);
      }
    });
  }

  return {
    setMyLongTermKey,
    createSession,
    getSession,
    removeSession,
    computeSharedSecret,
    initRatchet,
    encryptMessage,   // async
    decryptMessage,   // async
    sealSenderId,
    unsealSenderId,
    needsHeartbeat,
    recordHeartbeat,
    getAll,
    destroyAll
  };
})();
