/* ═══════════════════════════════════════════════════
   session.js — Ephemeral Session Keys + Forward Secrecy
   ═══════════════════════════════════════════════════ */

const Session = (() => {

  // ── Key Rotation Interval (Nachrichten) ──
  const ROTATE_AFTER = 50;

  // ── Session State pro Peer ──
  const sessions = new Map();

  function createSession(peerId, theirPubKey) {
    const ephemeral = nacl.box.keyPair();
    const session = {
      peerId,
      theirPubKey,                          // Long-term public key des Peers
      myEphemeral: ephemeral,               // Ephemeral Key Pair für diese Session
      theirEphemeralPub: null,              // Wird beim Key Exchange empfangen
      sharedSecret: null,                   // Abgeleitet nach KX
      sendNonce: BigInt(0),                 // Monotoner Send-Nonce
      recvNonces: new Set(),                // Empfangene Nonces (Replay-Schutz)
      msgCount: 0,                          // Nachrichten seit letzter Rotation
      verified: false,                      // Fingerabdruck verifiziert
      established: false,                   // Session etabliert
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
      // Sensible Daten überschreiben
      if (s.sharedSecret) s.sharedSecret.fill(0);
      if (s.myEphemeral) {
        s.myEphemeral.secretKey.fill(0);
        s.myEphemeral.publicKey.fill(0);
      }
      sessions.delete(peerId);
    }
  }

  // ── Shared Secret ableiten ──
  //    NaCl box vorberechnen: scalarMult der ephemeral Keys
  function computeSharedSecret(session) {
    if (!session.theirEphemeralPub || !session.myEphemeral) return false;

    // NaCl box.keyPair erzeugt x25519 keys
    // Das Shared Secret = scalarMult(mein.secretKey, ihr.publicKey)
    const sharedKey = nacl.box.before(
      session.theirEphemeralPub,
      session.myEphemeral.secretKey
    );

    // Zusätzlich mit Long-Term Keys hashen für Binding
    // H(sharedKey ‖ myLongPub ‖ theirLongPub)
    const combined = new Uint8Array(
      sharedKey.length + myKeys.publicKey.length + session.theirPubKey.length
    );
    combined.set(sharedKey, 0);
    combined.set(myKeys.publicKey, sharedKey.length);
    combined.set(
      session.theirPubKey,
      sharedKey.length + myKeys.publicKey.length
    );

    session.sharedSecret = nacl.hash(combined).slice(0, 32);
    session.established = true;

    // Temporäre Daten löschen
    combined.fill(0);
    sharedKey.fill(0);

    return true;
  }

  // ── Nachschauen ob Rotation nötig ──
  function needsRotation(peerId) {
    const s = sessions.get(peerId);
    return s && s.msgCount >= ROTATE_AFTER;
  }

  // ── Rotation triggern ──
  function rotate(peerId, theirPubKey) {
    removeSession(peerId);
    return createSession(peerId, theirPubKey);
  }

  // ── Alle Sessions ──
  function getAll() { return sessions; }

  return {
    createSession, getSession, removeSession,
    computeSharedSecret,
    needsRotation, rotate,
    getAll
  };
})();
