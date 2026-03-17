/* crypto.js — v5
   ① Commitment mit Blinding-Factor (Hiding + Binding)
   ② Session-Fingerprint (sharedSecret + beide PubKeys)
   ③ Signing mit Domain-Separator (Cross-Protocol-Schutz)
   ④ Transcript-Hash (laufender SHA-512 über alle Nachrichten)
*/
const KCrypto = (() => {

  const SIGN_DOMAIN = 'kryptochat-sign-v1:';

  function generateKeyPair()        { return nacl.box.keyPair(); }
  function generateSigningKeyPair() { return nacl.sign.keyPair(); }

  // ── Commitment mit Blinding-Factor ──
  // commit(data) → { commitment: Uint8Array(32), nonce: Uint8Array(32) }
  // Binding:  hash(data || nonce) ist eindeutig für data
  // Hiding:   ohne nonce kann man commitment nicht aus data berechnen
  function commit(data) {
    const nonce = nacl.randomBytes(32);
    const input = new Uint8Array(data.length + 32);
    input.set(data, 0); input.set(nonce, data.length);
    const comm = nacl.hash(input).slice(0, 32);
    burn(input);
    return { commitment: comm, nonce };
  }

  // Constant-Time-Vergleich in verifyCommit
  function verifyCommit(data, nonce, commitment) {
    if (!(nonce instanceof Uint8Array) || nonce.length !== 32) return false;
    const input = new Uint8Array(data.length + 32);
    input.set(data, 0); input.set(nonce, data.length);
    const expected = nacl.hash(input).slice(0, 32);
    burn(input);
    return ctEqual(expected, commitment);
  }

  // ── Session-Fingerprint (sharedSecret einbezogen) ──
  // Wenn beide Seiten denselben Fingerprint sehen → kein MITM möglich
  function fingerprintSession(sharedSecret, myPubKey, theirPubKey) {
    const input = new Uint8Array(96);
    input.set(sharedSecret, 0);
    input.set(myPubKey,     32);
    input.set(theirPubKey,  64);
    const h = nacl.hash(input);
    burn(input);
    return Array.from(h.slice(0, 16))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('').match(/.{1,8}/g).join(' ');
  }

  function fingerprintKey(pubKey) {
    const h = nacl.hash(pubKey).slice(0, 12);
    return Array.from(h).map(b => b.toString(16).padStart(2, '0')).join('').match(/.{1,4}/g).join(' ');
  }

  // ── Transcript-Hash ──
  // Laufender Hash über alle Nachrichten — Manipulation am Verlauf erkennbar
  // Jede neue Nachricht: hash(prevHash || msgHash)
  let _transcriptHash = new Uint8Array(64); // SHA-512 Nullen = initial

  function updateTranscript(message) {
    const msgHash = nacl.hash(U8.enc(message));
    const combined = new Uint8Array(128);
    combined.set(_transcriptHash, 0);
    combined.set(msgHash, 64);
    _transcriptHash = nacl.hash(combined);
    burn(combined);
  }

  function getTranscriptHash() {
    return Array.from(_transcriptHash.slice(0, 8))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function resetTranscript() {
    _transcriptHash = new Uint8Array(64);
  }

  // ── Signing mit Domain-Separator ──
  function sign(payload, secretKey) {
    return nacl.sign.detached(U8.enc(SIGN_DOMAIN + JSON.stringify(payload)), secretKey);
  }

  function verify(payload, signature, publicKey) {
    try { return nacl.sign.detached.verify(U8.enc(SIGN_DOMAIN + JSON.stringify(payload)), signature, publicKey); }
    catch { return false; }
  }

  return {
    generateKeyPair, generateSigningKeyPair,
    commit, verifyCommit,
    fingerprintSession, fingerprintKey,
    updateTranscript, getTranscriptHash, resetTranscript,
    sign, verify
  };
})();
