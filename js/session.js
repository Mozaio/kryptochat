/* ═══════════════════════════════════════════
   session.js — Session-Management
   ═══════════════════════════════════════════ */

const Session = (() => {
  const ROTATE_AFTER = 50;
  const sessions = new Map();
  let _myLongTermPubKey = null;

  function setMyLongTermKey(pubKey) {
    _myLongTermPubKey = pubKey;
  }

  function createSession(peerAnonId, theirPubKey) {
    const ephemeral = nacl.box.keyPair();
    const session = {
      peerAnonId,
      theirPubKey,
      myEphemeral: ephemeral,
      theirEphemeralPub: null,
      sharedSecret: null,
      sendNonce: BigInt(0),
      recvNonces: new Set(),
      msgCount: 0,
      verified: false,
      established: false,
      createdAt: Date.now()
    };
    sessions.set(peerAnonId, session);
    return session;
  }

  function getSession(peerAnonId) {
    return sessions.get(peerAnonId);
  }

  function removeSession(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (s) {
      if (s.sharedSecret) s.sharedSecret.fill(0);
      if (s.myEphemeral?.secretKey) s.myEphemeral.secretKey.fill(0);
      sessions.delete(peerAnonId);
    }
  }

  // Shared Secret berechnen: Kombiniert ephemeren Shared Secret + langfristige Keys
  function computeSharedSecret(peerAnonId) {
    const session = sessions.get(peerAnonId);
    if (!session || !session.theirEphemeralPub || !session.myEphemeral) return Promise.resolve(false);
    if (!_myLongTermPubKey) return Promise.resolve(false);

    const ephemeralShared = nacl.box.before(
      session.theirEphemeralPub,
      session.myEphemeral.secretKey
    );

    // Canonical ordering der langfristigen Keys
    let lt1, lt2;
    let cmp = false;
    for (let i = 0; i < 32; i++) {
      if (_myLongTermPubKey[i] < session.theirPubKey[i]) { cmp = true; break; }
      if (_myLongTermPubKey[i] > session.theirPubKey[i]) { cmp = false; break; }
    }
    if (cmp) {
      lt1 = _myLongTermPubKey;
      lt2 = session.theirPubKey;
    } else {
      lt1 = session.theirPubKey;
      lt2 = _myLongTermPubKey;
    }

    const combined = new Uint8Array(96);
    combined.set(ephemeralShared, 0);
    combined.set(lt1, 32);
    combined.set(lt2, 64);

    return crypto.subtle.digest('SHA-512', combined).then(hashBuf => {
      const fullHash = new Uint8Array(hashBuf);
      session.sharedSecret = fullHash.slice(0, 32);
      session.established = true;
      combined.fill(0);
      ephemeralShared.fill(0);
      return true;
    });
  }

  function needsRotation(peerAnonId) {
    const s = sessions.get(peerAnonId);
    return s && s.msgCount >= ROTATE_AFTER;
  }

  function rotate(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (!s) return null;
    const theirPubKey = s.theirPubKey;
    removeSession(peerAnonId);
    return createSession(peerAnonId, theirPubKey);
  }

  function getAll() {
    return sessions;
  }

  return {
    setMyLongTermKey,
    createSession,
    getSession,
    removeSession,
    computeSharedSecret,
    needsRotation,
    rotate,
    getAll
  };
})();
