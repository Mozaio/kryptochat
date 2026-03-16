/* ═══════════════════════════════════════════
   crypto.js — NaCl Wrappers
   Alles passiert hier. Der Server sieht nichts.
   ═══════════════════════════════════════════ */

const Crypto = (() => {

  function generateKeyPair() {
    return nacl.box.keyPair();
  }

  function fingerprint(pubKey) {
    const h = nacl.hash(pubKey).slice(0, 12);
    return Array.from(h)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .match(/.{1,4}/g)
      .join(' ');
  }

  function encryptWithSession(plaintext, sharedSecret, nonce) {
    const data = U8.enc(plaintext);
    return nacl.secretbox(data, nonce, sharedSecret);
  }

  function decryptWithSession(ciphertext, nonce, sharedSecret) {
    const plain = nacl.secretbox.open(ciphertext, nonce, sharedSecret);
    if (plain === null) return null;
    return U8.dec(plain);
  }

  function monotonicNonce(counter) {
    const nonce = new Uint8Array(24);
    const rand = nacl.randomBytes(24);
    nonce.set(rand);
    const view = new DataView(nonce.buffer);
    const bigCounter = typeof counter === 'bigint' ? counter : BigInt(counter);
    view.setBigUint64(0, bigCounter, false);
    return nonce;
  }

  // Signierter Key Exchange — damit der Server den Inhalt nicht fälschen kann
  // Der Server sieht die Signatur, kann sie aber ohne den geheimen Schlüssel nicht fälschen
  function signKeyExchange(payload, signingKeys) {
    const data = U8.enc(JSON.stringify({
      from: payload.from,
      to: payload.to,
      pubKey: payload.pubKey,
      ephemeralPubKey: payload.ephemeralPubKey,
      timestamp: payload.timestamp
    }));
    const sig = nacl.sign.detached(data, signingKeys.secretKey);
    payload.signature = B64.enc(sig);
    payload.signingPubKey = B64.enc(signingKeys.publicKey);
    return payload;
  }

  function verifyKeyExchange(payload) {
    try {
      const data = U8.enc(JSON.stringify({
        from: payload.from,
        to: payload.to,
        pubKey: payload.pubKey,
        ephemeralPubKey: payload.ephemeralPubKey,
        timestamp: payload.timestamp
      }));
      const sig = B64.dec(payload.signature);
      const signingPub = B64.dec(payload.signingPubKey);
      return nacl.sign.detached.verify(data, sig, signingPub);
    } catch {
      return false;
    }
  }

  return {
    generateKeyPair,
    fingerprint,
    encryptWithSession,
    decryptWithSession,
    monotonicNonce,
    signKeyExchange,
    verifyKeyExchange
  };
})();
