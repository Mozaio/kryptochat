/* ═══════════════════════════════════════════
   session.js — Ephemeral Session Keys
   ═══════════════════════════════════════════ */

const Session = (() => {

  const ROTATE_AFTER = 50;
  const sessions = new Map();

  let _myLongTermPubKey = null;

  function _keyHex(key, len) {
    return Array.from(key.slice(0, len || 8)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function setMyLongTermKey(pubKey) {
    _myLongTermPubKey = pubKey;
    const hash = nacl.hash(pubKey).slice(0, 8);
    console.log('[SESSION] Long-Term Key gesetzt, len:', pubKey.length,
      'first8:', _keyHex(pubKey, 8),
      'hash8:', _keyHex(hash, 8));
  }

  function createSession(peerId, theirPubKey) {
    const ephemeral = nacl.box.keyPair();
    const theirHash = nacl.hash(theirPubKey).slice(0, 8);
    console.log('[SESSION] Create', peerId,
      'theirPubKey first8:', _keyHex(theirPubKey, 8),
      'theirPubKey hash8:', _keyHex(theirHash, 8));

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

  function computeSharedSecret(peerId) {
    const session = sessions.get(peerId);
    if (!session || !session.theirEphemeralPub || !session.myEphemeral) return false;
    if (!_myLongTermPubKey) return false;

    // DH
    const ephemeralShared = nacl.box.before(
      session.theirEphemeralPub,
      session.myEphemeral.secretKey
    );

    // === DEBUG: Long-Term Keys ===
    console.log('[KDF-BIND]', peerId,
      'MY_LT:', _keyHex(_myLongTermPubKey, 8), '(hash:', _keyHex(nacl.hash(_myLongTermPubKey).slice(0, 4), 4), ')',
      'THEIR_LT:', _keyHex(session.theirPubKey, 8), '(hash:', _keyHex(nacl.hash(session.theirPubKey).slice(0, 4), 4), ')');
    console.log('[KDF-EPH]', peerId,
      'ephShared:', _keyHex(ephemeralShared, 8));

    // Binding
    const combined = new Uint8Array(
      ephemeralShared.length + _myLongTermPubKey.length + session.theirPubKey.length
    );
    combined.set(ephemeralShared, 0);
    combined.set(_myLongTermPubKey, ephemeralShared.length);
    combined.set(
      session.theirPubKey,
      ephemeralShared.length + _myLongTermPubKey.length
    );

    // Debug: combined buffer first/last bytes
    console.log('[KDF-COMBINED]',
      'first8:', _keyHex(combined, 8),
      'mid8:', _keyHex(combined.slice(32, 40), 8),
      'last8:', _keyHex(combined.slice(combined.length - 8), 8),
      'totalLen:', combined.length);

    session.sharedSecret = nacl.hash(combined).slice(0, 32);
    session.established = true;

    console.log('[KDF-SECRET]', peerId,
      'FINAL:', _keyHex(session.sharedSecret, 16));

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
