/* ═══════════════════════════════════════════
   session.js — Ephemeral Session Keys
   ═══════════════════════════════════════════ */

const Session = (() => {

  const ROTATE_AFTER = 50;
  const sessions = new Map();
  let _myLongTermPubKey = null;

  function _hex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function setMyLongTermKey(pubKey) {
    _myLongTermPubKey = pubKey;
    console.log('[MYKEY] FULL:', _hex(pubKey));
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
    console.log('[CREATE]', peerId, 'theirPub FULL:', _hex(theirPubKey));
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

  async function computeSharedSecret(peerId) {
    const session = sessions.get(peerId);
    if (!session || !session.theirEphemeralPub || !session.myEphemeral) return false;
    if (!_myLongTermPubKey) return false;

    // === VOR dem KDF: VOLLER Key loggen ===
    console.log('[BEFORE-KDF]', peerId,
      'myLT FULL:', _hex(_myLongTermPubKey),
      'theirLT FULL:', _hex(session.theirPubKey));

    const ephemeralShared = nacl.box.before(
      session.theirEphemeralPub,
      session.myEphemeral.secretKey
    );

    const combined = new Uint8Array(96);
    combined.set(ephemeralShared, 0);
    combined.set(_myLongTermPubKey, 32);
    combined.set(session.theirPubKey, 64);

    // === VOLLER Buffer loggen ===
    console.log('[BUF-FULL]', peerId, _hex(combined));

    // SHA-512
    let fullHash;
    if (typeof sha512 === 'function') {
      fullHash = await sha512(combined);
    } else {
      const h = await crypto.subtle.digest('SHA-512', combined);
      fullHash = new Uint8Array(h);
    }

    session.sharedSecret = fullHash.slice(0, 32);
    session.established = true;

    console.log('[SECRET]', peerId, _hex(session.sharedSecret));

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
