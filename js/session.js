/* ═══════════════════════════════════════════
   session.js — Session mit persistenter Nonce
   und Key Rotation
   ═══════════════════════════════════════════ */

const Session = (() => {
  const ROTATE_AFTER = 50;       // Nach 50 Nachrichten rotieren
  const HEARTBEAT_INTERVAL = 20; // Sekunden
  const sessions = new Map();
  let _myLongTermPubKey = null;

  function setMyLongTermKey(pubKey) {
    _myLongTermPubKey = pubKey;
  }

  function createSession(peerAnonId, theirPubKey) {
    // Persistenten Nonce-Offset laden
    const storedOffset = parseInt(Store.get(`nonce_${peerAnonId}`, '0'));

    const session = {
      peerAnonId,
      theirPubKey,
      myEphemeral: null,          // Wird später gesetzt
      theirEphemeralPub: null,
      sharedSecret: null,
      sendNonce: BigInt(storedOffset),
      recvNonces: new Set(),
      msgCount: 0,
      verified: false,
      established: false,
      lastHeartbeat: 0,
      heartbeatSeq: 0,
      commitmentSent: false,
      commitmentReceived: null,
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
      // Sensible Daten im Speicher überschreiben
      burn(s.sharedSecret);
      if (s.myEphemeral) burn(s.myEphemeral.secretKey);
      if (s.myEphemeral) burn(s.myEphemeral.publicKey);
      sessions.delete(peerAnonId);
    }
  }

  // ── Shared Secret berechnen ──
  // Kombiniert ephemeren X25519 Shared Secret + langfristige Keys
  function computeSharedSecret(peerAnonId) {
    const session = sessions.get(peerAnonId);
    if (!session || !session.theirEphemeralPub || !session.myEphemeral) return Promise.resolve(false);
    if (!_myLongTermPubKey) return Promise.resolve(false);

    // Ephemerer Shared Secret
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

    // Kombinieren: ephemeralShared(32) + lt1(32) + lt2(32) = 96 Bytes
    const combined = new Uint8Array(96);
    combined.set(ephemeralShared, 0);
    combined.set(lt1, 32);
    combined.set(lt2, 64);

    return crypto.subtle.digest('SHA-512', combined).then(hashBuf => {
      const fullHash = new Uint8Array(hashBuf);
      session.sharedSecret = fullHash.slice(0, 32);
      session.established = true;

      // Temporäre Daten bereinigen
      burn(combined, ephemeralShared);
      burn(fullHash);

      return true;
    });
  }

  // ── Nonce persistieren ──
  function persistNonce(peerAnonId, nonce) {
    Store.set(`nonce_${peerAnonId}`, nonce.toString());
  }

  // ── Rotation ──
  function needsRotation(peerAnonId) {
    const s = sessions.get(peerAnonId);
    return s && s.msgCount >= ROTATE_AFTER;
  }

  function rotate(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (!s) return null;
    const theirPubKey = s.theirPubKey;
    const wasVerified = s.verified;
    removeSession(peerAnonId);
    const newSession = createSession(peerAnonId, theirPubKey);
    newSession.verified = wasVerified; // Verifizierung behalten
    return newSession;
  }

  function getAll() {
    return sessions;
  }

  function needsHeartbeat(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.established) return false;
    return (Date.now() - s.lastHeartbeat) > HEARTBEAT_INTERVAL * 1000;
  }

  function recordHeartbeat(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (s) s.lastHeartbeat = Date.now();
  }

  return {
    setMyLongTermKey,
    createSession,
    getSession,
    removeSession,
    computeSharedSecret,
    persistNonce,
    needsRotation,
    rotate,
    getAll,
    needsHeartbeat,
    recordHeartbeat,
    ROTATE_AFTER
  };
})();
