/* ═══════════════════════════════════════════
   session.js — Ephemeral Session Keys
   ═══════════════════════════════════════════ */

const Session = (() => {

  const ROTATE_AFTER = 50;
  const sessions = new Map();
  let _myLongTermPubKey = null;

  function setMyLongTermKey(pubKey) {
    _myLongTermPubKey = pubKey;
  }

  function createSession(peerId, theirPubKey) {
    const ephemeral = nacl.box.keyPair();
    const session = {
      peerId,
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
    sessions.set(peerId, session);
    return session;
  }

  function getSession(peerId) {
    return sessions.get(peerId);
  }

  function removeSession(peerId) {
    const s = sessions.get(peerId);
    if (s) {
      if (s.sharedSecret) s.sharedSecret.fill(0);
      if (s.myEphemeral && s.myEphemeral.secretKey) {
        s.myEphemeral.secretKey.fill(0);
      }
      sessions.delete(peerId);
    }
  }

  // ASYNC: nutzt SHA-512 via Web Crypto statt nacl.hash
  async function computeSharedSecret(peerId) {
    const session = sessions.get(peerId);
    if (!session || !session.theirEphemeralPub || !session.myEphemeral) return false;
    if (!_myLongTermPubKey) return false;

    // DH
    const ephemeralShared = nacl.box.before(
      session.theirEphemeralPub,
      session.myEphemeral.secretKey
    );

    // Binding: SHA-512(ephemeralShared ‖ myLongPub ‖ theirLongPub)
    const combined = new Uint8Array(
      ephemeralShared.length + _myLongTermPubKey.length + session.theirPubKey.length
    );
    combined.set(ephemeralShared, 0);
    combined.set(_myLongTermPubKey, ephemeralShared.length);
    combined.set(
      session.theirPubKey,
      ephemeralShared.length + _myLongTermPubKey.length
    );

    // SHA-512 via Web Crypto (deterministisch, nativ)
    const fullHash = await sha512(combined);
    session.sharedSecret = fullHash.slice(0, 32);
    session.established = true;

    // Cleanup
    combined.fill(0);
    ephemeralShared.fill(0);

    return true;
  }

  function needsRotation(peerId) {
    const s = sessions.get(peerId);
    return s && s.msgCount >= ROTATE_AFTER;
  }

  function rotate(peerId) {
    const s = sessions.get(peerId);
    if (!s) return null;
    const theirPubKey = s.theirPubKey;
    removeSession(peerId);
    return createSession(peerId, theirPubKey);
  }

  function getAll() { return sessions; }

  return {
    setMyLongTermKey,
    createSession, getSession, removeSession,
    computeSharedSecret,
    needsRotation, rotate,
    getAll
  };
})();
