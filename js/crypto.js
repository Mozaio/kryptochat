/* ═══════════════════════════════════════════
   crypto.js — NaCl Key Management & Helpers
   ═══════════════════════════════════════════ */

const Crypto = (() => {

  // Erzeuge ein neues Schlüsselpaar
  function generateKeyPair() {
    return nacl.box.keyPair();
  }

  // Fingerprint aus Public Key (SHA-512, erste 12 Bytes, hex-gruppiert)
  function fingerprint(pubKey) {
    const h = nacl.hash(pubKey).slice(0, 12);
    return Array.from(h)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .match(/.{1,4}/g)
      .join(' ');
  }

  // Verschlüsseln
  function encrypt(plaintext, nonce, theirPub, mySecret) {
    const data = U8.enc(plaintext);
    return nacl.box(data, nonce, theirPub, mySecret);
  }

  // Entschlüsseln
  function decrypt(ciphertext, nonce, theirPub, mySecret) {
    const plain = nacl.box.open(ciphertext, nonce, theirPub, mySecret);
    if (plain === null) return null;
    return U8.dec(plain);
  }

  // Zufälliger Nonce
  function randomNonce() {
    return nacl.randomBytes(24);
  }

  return { generateKeyPair, fingerprint, encrypt, decrypt, randomNonce };
})();
