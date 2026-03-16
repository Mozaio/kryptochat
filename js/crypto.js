/* ═══════════════════════════════════════════
   crypto.js — NaCl Wrappers
   Keine Logs, kein Console, kein Leak
   ═══════════════════════════════════════════ */

const Crypto = (() => {

  // ── Feste Nachrichtengröße gegen Metadaten-Analyse ──
  const PAD_BLOCK = 512; // Alle Nachrichten auf 512 Bytes gepadded

  function generateKeyPair() {
    return nacl.box.keyPair();
  }

  function generateSigningKeyPair() {
    return nacl.sign.keyPair();
  }

  function fingerprint(pubKey) {
    const h = nacl.hash(pubKey).slice(0, 12);
    return Array.from(h)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .match(/.{1,4}/g)
      .join(' ');
  }

  // ── Commitment (SHA-256) ──
  function commitment(data) {
    // SHA-256 Hash über die Daten — nicht zurückrechenbar
    const hash = nacl.hash(data); // SHA-512, wir nehmen die ersten 32 Bytes
    return hash.slice(0, 32);
  }

  function verifyCommitment(data, comm) {
    const expected = commitment(data);
    if (expected.length !== comm.length) return false;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) {
      diff |= expected[i] ^ comm[i];
    }
    return diff === 0;
  }

  // ── Padding ──
  function pad(data) {
    // data: Uint8Array
    // Format: [data_length (2 bytes BE)] [data] [random padding]
    const padded = new Uint8Array(PAD_BLOCK);
    const view = new DataView(padded.buffer);
    view.setUint16(0, data.length, false);
    padded.set(data, 2);
    // Rest mit zufälligen Bytes füllen (nicht null!)
    const rand = nacl.randomBytes(PAD_BLOCK - 2 - data.length);
    padded.set(rand, 2 + data.length);
    return padded;
  }

  function unpad(padded) {
    // padded: Uint8Array
    if (!padded || padded.length < 2) return null;
    const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
    const len = view.getUint16(0, false);
    if (len > padded.length - 2) return null;
    return padded.slice(2, 2 + len);
  }

  // ── Verschlüsselung mit Padding ──
  function encrypt(plaintext, sharedSecret, nonce) {
    const data = U8.enc(plaintext);
    const padded = pad(data);
    const result = nacl.secretbox(padded, nonce, sharedSecret);
    burn(padded);
    return result;
  }

  function decrypt(ciphertext, nonce, sharedSecret) {
    const padded = nacl.secretbox.open(ciphertext, nonce, sharedSecret);
    if (!padded) return null;
    const data = unpad(padded);
    burn(padded);
    if (!data) return null;
    return U8.dec(data);
  }

  // ── Monotone Nonce mit Persistenz ──
  function makeNonce(counter) {
    const nonce = new Uint8Array(24);
    const rand = nacl.randomBytes(24);
    nonce.set(rand);
    const view = new DataView(nonce.buffer);
    view.setBigUint64(0, BigInt(counter), false);
    return nonce;
  }

  // ── Key Exchange Signing ──
  function sign(payload, secretKey) {
    const data = U8.enc(JSON.stringify(payload));
    return nacl.sign.detached(data, secretKey);
  }

  function verify(payload, signature, publicKey) {
    try {
      const data = U8.enc(JSON.stringify(payload));
      return nacl.sign.detached.verify(data, signature, publicKey);
    } catch {
      return false;
    }
  }

  return {
    generateKeyPair,
    generateSigningKeyPair,
    fingerprint,
    commitment,
    verifyCommitment,
    encrypt,
    decrypt,
    makeNonce,
    sign,
    verify,
    burn,
    PAD_BLOCK
  };
})();
