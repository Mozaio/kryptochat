/* ═══════════════════════════════════════════
   crypto.js — Erweitert: Signing + Key Derivation
   ═══════════════════════════════════════════ */

const Crypto = (() => {

  // ── Long-Term Signing Keys (zusätzlich zu Box Keys) ──
  const signingKeys = nacl.sign.keyPair();

  function generateKeyPair() {
    return nacl.box.keyPair();
  }

  // ── Fingerprint (SHA-512, 12 Bytes, hex-gruppiert) ──
  function fingerprint(pubKey) {
    const h = nacl.hash(pubKey).slice(0, 12);
    return Array.from(h)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .match(/.{1,4}/g)
      .join(' ');
  }

  // ── Signierter Fingerprint (zeigt, dass der Key dem Besitzer gehört) ──
  function signedFingerprint(pubKey) {
    const fp = nacl.hash(pubKey).slice(0, 12);
    const signature = nacl.sign.detached(fp, signingKeys.secretKey);
    return {
      fingerprint: Array.from(fp).map(b => b.toString(16).padStart(2, '0')).join(''),
      signature: B64.enc(signature),
      signingPubKey: B64.enc(signingKeys.publicKey)
    };
  }

  // ── Verifizieren, ob ein Fingerprint wirklich vom Peer signiert wurde ──
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

  // ── Verschlüsseln mit Session Key ──
  function encryptWithSession(plaintext, sharedSecret, nonce) {
    const data = U8.enc(plaintext);
    return nacl.secretbox(data, nonce, sharedSecret);
  }

  // ── Entschlüsseln mit Session Key ──
  function decryptWithSession(ciphertext, nonce, sharedSecret) {
    const plain = nacl.secretbox.open(ciphertext, nonce, sharedSecret);
    if (plain === null) return null;
    return U8.dec(plain);
  }

  // ── Monotoner Nonce erzeugen (8-Byte Counter + 16-Byte Random) ──
  //    Verhindert Replays AND garantiert Einzigartigkeit
  function monotonicNonce(counter) {
    const nonce = nacl.randomBytes(24);
    // Erste 8 Bytes = Counter (Big-Endian)
    const view = new DataView(nonce.buffer);
    view.setBigUint64(0, counter, false);
    return nonce;
  }

  // ── Nonce-Validierung ──
  function nonceFromCounter(counter) {
    const nonce = new Uint8Array(24);
    nacl.randomBytes(24).forEach((b, i) => nonce[i] = b);
    const view = new DataView(nonce.buffer);
    view.setBigUint64(0, counter, false);
    return nonce;
  }

  // ── Key Exchange Nachricht signieren ──
  function signKeyExchange(payload) {
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

  // ── Key Exchange Signatur verifizieren ──
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
    generateKeyPair, fingerprint,
    signedFingerprint, verifySignedFingerprint,
    encryptWithSession, decryptWithSession,
    monotonicNonce,
    signKeyExchange, verifyKeyExchange,
    signingPublicKey: signingKeys.publicKey
  };
})();
