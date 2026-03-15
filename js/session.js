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
    console.log('[SESS-CREATE]', peerId, 'theirPubKey first16:', _keyHex(theirPubKey, 16));
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

    // === FULL KEY DEBUG ===
    console.log('[KDF-ENTRY]', peerId,
      'sessionObj_id:', session.peerId,
      'myLT_first16:', _keyHex(_myLongTermPubKey, 16),
      'theirLT_first16:', _keyHex(session.theirPubKey, 16),
      'theirLT_last16:', _keyHex(session.theirPubKey.slice(16), 16));

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

    // === Verify buffer ===
    const theirKeyInBuffer = combined.slice(64, 96);
    console.log('[KDF-BUFFER]',
      'combinedLen:', combined.length,
      'theirKeyInBuf_first16:', _keyHex(theirKeyInBuffer, 16),
      'theirKeyInBuf_last16:', _keyHex(theirKeyInBuffer.slice(16), 16),
      'MATCH:', _keyHex(theirKeyInBuffer, 16) === _keyHex(session.theirPubKey, 16));

    session.sharedSecret = nacl.hash(combined).slice(0, 32);
    session.established = true;

    console.log('[KDF-DONE]', peerId,
      'secret_first16:', _keyHex(session.sharedSecret, 16));

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
