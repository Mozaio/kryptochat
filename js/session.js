/* ═══════════════════════════════════════════════════
   session.js — Session-Management mit Double Ratchet
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
      myEphemeral: null,
      theirEphemeralPub: null,
      sharedSecret: null,
      ratchet: null,           // Double Ratchet State
      sealedKey: null,         // Sealed Sender Key (abgeleitet)
      verified: false,
      established: false,
      keySent: false,
      myCommitment: null,
      myCommitTimestamp: 0,
      theirCommitment: null,
      theirCommitTimestamp: 0,
      lastHeartbeat: 0,
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
      // Sensible Daten im RAM überschreiben
      _burn(s.sharedSecret, s.sealedKey);
      if (s.myEphemeral) {
        _burn(s.myEphemeral.secretKey, s.myEphemeral.publicKey);
      }
      if (s.ratchet) {
        _burn(s.ratchet.rootKey, s.ratchet.sendChainKey, s.ratchet.recvChainKey);
        if (s.ratchet.dhSendKeyPair) {
          _burn(s.ratchet.dhSendKeyPair.secretKey, s.ratchet.dhSendKeyPair.publicKey);
        }
      }
      sessions.delete(peerAnonId);
    }
  }

  // ── Shared Secret + Double Ratchet Initialisierung ──

  function initRatchet(peerAnonId) {
    const session = sessions.get(peerAnonId);
    if (!session || !session.sharedSecret) return false;

    // Neues DH-Schlüsselpaar für den Ratchet
    const dhKeyPair = nacl.box.keyPair();

    // Ratchet initialisieren
    session.ratchet = DoubleRatchet.create(dhKeyPair, session.sharedSecret);

    // Sealed Sender Key ableiten
    // Aus sharedSecret + "sealed" ein separater Key
    const sealedInput = new Uint8Array([...session.sharedSecret, ...U8.enc('sealed-sender-v1')]);
    session.sealedKey = nacl.hash(sealedInput).slice(0, 32);
    _burn(sealedInput);

    // Root Key für den Ratchet mit erstem DH-Schritt updaten
    // Beide Seiten haben bereits die ephemeralen Keys aus dem Key Exchange
    if (session.theirEphemeralPub) {
      const dhOutput = nacl.box.before(session.theirEphemeralPub, dhKeyPair.secretKey);
      // Diesen DH-Output im Ratchet verarbeiten
      // (Der Initiator macht den ersten Schritt)
    }

    return true;
  }

  // ── Shared Secret berechnen (bleibt gleich) ──

  function computeSharedSecret(peerAnonId) {
    const session = sessions.get(peerAnonId);
    if (!session || !session.theirEphemeralPub || !session.myEphemeral) return Promise.resolve(false);
    if (!_myLongTermPubKey) return Promise.resolve(false);

    const ephemeralShared = nacl.box.before(
      session.theirEphemeralPub,
      session.myEphemeral.secretKey
    );

    // Canonical ordering
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

      // Double Ratchet initialisieren
      initRatchet(peerAnonId);

      // Temporäre Daten bereinigen
      _burn(combined, ephemeralShared, fullHash);

      return true;
    });
  }

  // ── Verschlüsseln mit Double Ratchet ──

  function encryptMessage(peerAnonId, plaintext) {
    const session = sessions.get(peerAnonId);
    if (!session || !session.ratchet) return null;
    return DoubleRatchet.encrypt(session.ratchet, plaintext);
  }

  // ── Entschlüsseln mit Double Ratchet ──

  function decryptMessage(peerAnonId, header, nonce, ciphertext) {
    const session = sessions.get(peerAnonId);
    if (!session || !session.ratchet) return null;
    return DoubleRatchet.decrypt(session.ratchet, header, nonce, ciphertext);
  }

  // ── Sealed Sender ──

  function sealSenderId(sealedKey, senderAnonId) {
    const nonce = nacl.randomBytes(24);
    const data = U8.enc(senderAnonId);
    const encrypted = nacl.secretbox(data, nonce, sealedKey);
    return { sealedId: B64.enc(encrypted), sealedNonce: B64.enc(nonce) };
  }

  function unsealSenderId(sealedKey, sealedIdB64, sealedNonceB64) {
    try {
      const encrypted = B64.dec(sealedIdB64);
      const nonce = B64.dec(sealedNonceB64);
      const data = nacl.secretbox.open(encrypted, nonce, sealedKey);
      if (!data) return null;
      return U8.dec(data);
    } catch {
      return null;
    }
  }

  // ── Heartbeat ──

  function needsHeartbeat(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (!s || !s.established) return false;
    return (Date.now() - s.lastHeartbeat) > 20000;
  }

  function recordHeartbeat(peerAnonId) {
    const s = sessions.get(peerAnonId);
    if (s) s.lastHeartbeat = Date.now();
  }

  function getAll() {
    return sessions;
  }

  // ── Hilfsfunktionen ──

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
    encryptMessage,
    decryptMessage,
    sealSenderId,
    unsealSenderId,
    needsHeartbeat,
    recordHeartbeat,
    getAll
  };
})();
