/* ═══════════════════════════════════════════
   crypto.js — NaCl Wrappers + Signing
   ═══════════════════════════════════════════ */

const Crypto = (() => {

  let _signingKeys = null;

  function _ensureSigningKeys() {
    if (!_signingKeys) {
      _signingKeys = nacl.sign.keyPair();
    }
    return _signingKeys;
  }

  function generateKeyPair() {
    return nacl.box.keyPair();
  }

  function fingerprint(pubKey) {
    // SHA-256 via Web Crypto (synchrone Variante mit nacl.hash für Fingerprint ist OK — kurzer Input)
    const h = nacl.hash(pubKey).slice(0, 12);
    return Array.from(h)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .match(/.{1,4}/g)
      .join(' ');
  }

  function signedFingerprint(pubKey) {
    const sk = _ensureSigningKeys();
    const fp = nacl.hash(pubKey).slice(0, 12);
    const signature = nacl.sign.detached(fp, sk.secretKey);
    return {
      fingerprint: Array.from(fp).map(b => b.toString(16).padStart(2, '0')).join(''),
      signature: B64.enc(signature),
      signingPubKey: B64.enc(sk.publicKey)
    };
  }

  function verifySignedFingerprint(pubKey, signatureB64, signingPubKeyB64) {
    try {
      const fp = nacl.hash(pubKey).slice(0, 12);
      const signature = B64.dec(signatureB64);
      const signingPubKey = B64.dec(signingPubKeyB64);
      return nacl.sign.detached.verify(fp, signature, signingPubKey);
    } catch {
      return false;
    }
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

  function signKeyExchange(payload) {
    const sk = _ensureSigningKeys();
    const data = U8.enc(JSON.stringify({
      from: payload.from,
      to: payload.to,
      pubKey: payload.pubKey,
      ephemeralPubKey: payload.ephemeralPubKey,
      timestamp: payload.timestamp
    }));
    const sig = nacl.sign.detached(data, sk.secretKey);
    payload.signature = B64.enc(sig);
    payload.signingPubKey = B64.enc(sk.publicKey);
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
    signedFingerprint, verifySignedFingerprint,
    encryptWithSession, decryptWithSession,
    monotonicNonce,
    signKeyExchange, verifyKeyExchange,
    getSigningPublicKey() { return _ensureSigningKeys().publicKey; }
  };
})();
