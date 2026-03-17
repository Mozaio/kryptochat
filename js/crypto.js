/* ═══════════════════════════════════════════════════
   crypto.js — v4 (Security-Hardened)

   Änderungen:
   ① Commitment mit Blinding-Factor:
      Vorher: hash(data) → deterministisch, kein Hiding
      Jetzt:  hash(data || random_nonce) → echtes Hiding
              Der Nonce wird beim Reveal mitgeschickt.
              Ein Angreifer, der pubKey kennt, kann das
              Commitment nicht vorab berechnen.

   ② Fingerprint über Session-Key (nicht nur Long-Term-Key):
      Vorher: SHA-512(pubKey).slice(0,12)
      Jetzt:  SHA-512(sharedSecret || myPubKey || theirPubKey)
              → Fingerprint ändert sich pro Session,
              bestätigt dass BEIDE Seiten denselben Secret haben.
              Kein MITM möglich ohne sichtbaren Fingerprint-Mismatch.

   ③ Constant-Time-Vergleich in verifyCommitment (via ctEqual).

   ④ Signing-Domain-Separator: Payload wird mit Prefix versehen
      bevor signiert → verhindert Cross-Protocol-Angriffe.
   ═══════════════════════════════════════════════════ */

const Crypto = (() => {

  const SIGN_DOMAIN = 'kryptochat-sign-v1:';

  // ── Keypair-Generierung ───────────────────────────

  function generateKeyPair() {
    return nacl.box.keyPair();
  }

  function generateSigningKeyPair() {
    return nacl.sign.keyPair();
  }

  // ── Fingerprint über Session-Secret ──────────────
  // Bestätigt, dass beide Seiten denselben Shared Secret haben.
  // Format: SHA-512(sharedSecret || myPubKey || theirPubKey).slice(0,16)
  // → 16 Byte = 128 Bit = 32 Hex-Zeichen, in 8er-Gruppen angezeigt.
  //
  // Wenn der Fingerprint übereinstimmt, ist sichergestellt:
  //   - Kein MITM (sharedSecret wäre verschieden)
  //   - Identität bestätigt (pubKeys sind Teil des Hash)

  function fingerprintSession(sharedSecret, myPubKey, theirPubKey) {
    const input = new Uint8Array(96);
    input.set(sharedSecret, 0);
    input.set(myPubKey,     32);
    input.set(theirPubKey,  64);
    const h = nacl.hash(input); // SHA-512
    burn(input);
    return Array.from(h.slice(0, 16))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .match(/.{1,8}/g)
      .join(' ');
  }

  // Fallback: Fingerprint nur über Public Key (vor Session-Aufbau)
  function fingerprintKey(pubKey) {
    const h = nacl.hash(pubKey).slice(0, 12);
    return Array.from(h)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .match(/.{1,4}/g)
      .join(' ');
  }

  // ── Commitment mit Blinding-Factor ───────────────
  // commit(data) → { commitment: Uint8Array(32), nonce: Uint8Array(32) }
  //
  // Binding:  hash(data || nonce) ist eindeutig für data
  // Hiding:   Ohne nonce kann man commitment nicht aus data berechnen
  //
  // Ablauf:
  //   1. Sender schickt commitment (vor dem Key)
  //   2. Sender schickt Key + nonce (reveal)
  //   3. Empfänger prüft: hash(key || nonce) == commitment

  function commit(data) {
    const nonce = nacl.randomBytes(32);
    const input = new Uint8Array(data.length + 32);
    input.set(data,  0);
    input.set(nonce, data.length);
    const comm = nacl.hash(input).slice(0, 32);
    burn(input);
    return { commitment: comm, nonce };
  }

  // Prüft Commitment mit Constant-Time-Vergleich (kein Timing-Leak)
  function verifyCommit(data, nonce, commitment) {
    if (!(nonce instanceof Uint8Array) || nonce.length !== 32) return false;
    const input = new Uint8Array(data.length + 32);
    input.set(data,  0);
    input.set(nonce, data.length);
    const expected = nacl.hash(input).slice(0, 32);
    burn(input);
    return ctEqual(expected, commitment); // Constant-Time!
  }

  // ── Signing mit Domain-Separator ─────────────────
  // Prefix verhindert Cross-Protocol-Signatur-Angriffe:
  // Eine Signatur aus Kryptochat kann nicht in einem anderen
  // Protokoll wiederverwendet werden, das denselben Key nutzt.

  function sign(payload, secretKey) {
    const json = SIGN_DOMAIN + JSON.stringify(payload);
    return nacl.sign.detached(U8.enc(json), secretKey);
  }

  function verify(payload, signature, publicKey) {
    try {
      const json = SIGN_DOMAIN + JSON.stringify(payload);
      return nacl.sign.detached.verify(U8.enc(json), signature, publicKey);
    } catch { return false; }
  }

  return {
    generateKeyPair,
    generateSigningKeyPair,
    fingerprintSession,   // NEU: Session-basierter Fingerprint
    fingerprintKey,       // Fallback: nur Public Key
    commit,               // NEU: gibt { commitment, nonce } zurück
    verifyCommit,         // NEU: erwartet (data, nonce, commitment)
    sign,
    verify
  };
})();
