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
    console.log('[SESS] Created', peerId,
      'myEphPub:', _hex(ephemeral.publicKey),
      'theirPub:', _hex(theirPubKey));
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

    // DH
    const ephemeralShared = nacl.box.before(
      session.theirEphemeralPub,
      session.myEphemeral.secretKey
    );

    // === DEBUG: VOLLER ephemeralShared ===
    console.log('[DH]', peerId,
      'ephShared FULL:', _hex(ephemeralShared));
    console.log('[KEYS]', peerId,
      'myLT:', _hex(_myLongTermPubKey),
      'theirLT:', _hex(session.theirPubKey));

    // Combined Buffer
    const combined = new Uint8Array(
      ephemeralShared.length + _myLongTermPubKey.length + session.theirPubKey.length
    );
    combined.set(ephemeralShared, 0);
    combined.set(_myLongTermPubKey, ephemeralShared.length);
    combined.set(
      session.theirPubKey,
      ephemeralShared.length + _myLongTermPubKey.length
    );

    // === DEBUG: Buffer-Checksum ===
    let checksum = 0;
    for (let i = 0; i < combined.length; i++) checksum += combined[i];
    console.log('[BUF]', peerId,
      'checksum:', checksum,
      'first16:', _hex(combined.slice(0, 16)),
      'last16:', _hex(combined.slice(80, 96)));

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

    console.log('[SECRET]', peerId,
      'FULL:', _hex(session.sharedSecret));

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
