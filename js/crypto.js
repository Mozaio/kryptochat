/* ═══════════════════════════════════════════
   crypto.js — Basis-Kryptographie
   ═══════════════════════════════════════════ */

const Crypto = (() => {

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

  // ── Commitment ──
  function commitment(data) {
    const hash = nacl.hash(data);
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

  // ── Signing ──
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
    sign,
    verify
  };
})();
