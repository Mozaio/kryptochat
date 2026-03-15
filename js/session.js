/* ═══════════════════════════════════════════
   session.js — Ephemeral Session Keys
   ═══════════════════════════════════════════ */

const Session = (() => {

  const ROTATE_AFTER = 50;
  const sessions = new Map();

  let _myLongTermPubKey = null;

  function setMyLongTermKey(pubKey) {
    _myLongTermPubKey = pubKey;
    console.log('[SESSION] Long-Term Key gesetzt, len:', pubKey.length);
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
    const myEphPub = Array.from(ephemeral.publicKey.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log('[SESSION] Created:', peerId, 'myEphPub:', myEphPub);
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

    // Debug: print inputs
    const myEphSec = Array.from(session.myEphemeral.secretKey.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('');
    const theirEphPub = Array.from(session.theirEphemeralPub.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('');
    const ephShared = Array.from(ephemeralShared.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log('[KDF]', peerId,
      'myEphSec:', myEphSec,
      'theirEphPub:', theirEphPub,
      'ephShared:', ephShared);

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

    session.sharedSecret = nacl.hash(combined).slice(0, 32);
    session.established = true;

    // Debug: print final secret
    const finalSecret = Array.from(session.sharedSecret.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log('[KDF]', peerId, 'FINAL SECRET:', finalSecret);

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
