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

  // Vergleicht zwei Keys byte-für-byte, gibt -1/0/1 zurück
  function _compareKeys(a, b) {
    for (let i = 0; i < a.length && i < b.length; i++) {
      if (a[i] < b[i]) return -1;
      if (a[i] > b[i]) return 1;
    }
    return 0;
  }

  async function computeSharedSecret(peerId) {
    const session = sessions.get(peerId);
    if (!session || !session.theirEphemeralPub || !session.myEphemeral) return false;
    if (!_myLongTermPubKey) return false;

    // DH mit ephemeral Keys
    const ephemeralShared = nacl.box.before(
      session.theirEphemeralPub,
      session.myEphemeral.secretKey
    });

    // BEIDE Seiten müssen dieselbe Reihenfolge verwenden!
    // → Deterministisch sortieren: kleinerer Key zuerst
    const [ltFirst, ltSecond] = _compareKeys(_myLongTermPubKey, session.theirPubKey) <= 0
      ? [_myLongTermPubKey, session.theirPubKey]
      : [session.theirPubKey, _myLongTermPubKey];

    // SHA-512(ephemeralShared ‖ ltFirst ‖ ltSecond)
    const combined = new Uint8Array(96);
    combined.set(ephemeralShared, 0);
    combined.set(ltFirst, 32);
    combined.set(ltSecond, 64);

    // SHA-512 via Web Crypto API
    const fullHash = await crypto.subtle.digest('SHA-512', combined);
    session.sharedSecret = new Uint8Array(fullHash).slice(0, 32);
    session.established = true;

    // Aufräumen
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
