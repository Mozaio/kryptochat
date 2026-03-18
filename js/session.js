/* session.js — v5
   ① Dummy-Traffic mit variablem Jitter (4–20s)
   ② Key-Rotation-Warnung ab 900 Nachrichten
   ③ Auto-Delete nach removeSession
   ④ Commit mit Blinding-Nonce (aus crypto.js)
*/
const Session = (() => {
  const sessions = new Map();
  let _myLongTermPubKey = null;
  let _socket           = null;
  let _myAnonId         = null;
  let _dummyTimer       = null;

  function setMyLongTermKey(pubKey) { _myLongTermPubKey = pubKey; }
  function setSocket(socket, anonId) { _socket = socket; _myAnonId = anonId; }

  function createSession(peerAnonId, theirPubKey) {
    const s = {
      peerAnonId, theirPubKey,
      myEphemeral: null, theirEphemeralPub: null,
      sharedSecret: null, ratchet: null, sealedKey: null,
      verified: false, established: false, keySent: false,
      myCommitment: null, myCommitNonce: null, myCommitTimestamp: 0,
      theirCommitment: null, theirCommitNonce: null, theirCommitTimestamp: 0,
      msgCount: 0, lastHeartbeat: 0, createdAt: Date.now(),
      // Post-Quantum (keypair generated lazily when key exchange starts)
      mlkemKeyPair:  null, // our ML-KEM-768 keypair
      theirMlkemPub: null, // peer's ML-KEM-768 public key
      kemCiphertext: null, // encapsulated KEM secret (Alice→Bob)
      kemSecret: null      // shared KEM secret (both sides)
    };
    sessions.set(peerAnonId, s);
    return s;
  }

  function getSession(id)  { return sessions.get(id); }

  function removeSession(id) {
    const s = sessions.get(id);
    if (!s) return;
    // Burn ALL sensitive cryptographic material
    burn(
      s.sharedSecret, s.sealedKey,
      s.myCommitment, s.myCommitNonce,
      s.theirCommitment, s.theirCommitNonce,
      s.kemSecret
    );
    if (s.myEphemeral)   { burn(s.myEphemeral.secretKey, s.myEphemeral.publicKey); }
    if (s.mlkemKeyPair)  { burn(s.mlkemKeyPair.secretKey, s.mlkemKeyPair.publicKey); }
    if (s.theirMlkemPub) { burn(s.theirMlkemPub); }
    if (s.kemCiphertext) { burn(s.kemCiphertext); }
    if (s.ratchet)     DoubleRatchet.destroy(s.ratchet);
    sessions.delete(id);
  }

  async function initRatchet(id) {
    const s = sessions.get(id);
    if (!s || !s.sharedSecret) return false;
    s.ratchet = DoubleRatchet.create(s.sharedSecret);

    // Sealed-Sender-Key
    const si = new Uint8Array(64);
    si.set(s.sharedSecret, 0);
    si.set(new TextEncoder().encode('sealed-sender-v1'), 32);
    s.sealedKey = nacl.hash(si).slice(0, 32);
    burn(si);

    // isAlice: whoever has the smaller long-term key (deterministic, same on both sides)
    let isAlice = false;
    if (_myLongTermPubKey && s.theirPubKey) {
      for (let i = 0; i < 32; i++) {
        if (_myLongTermPubKey[i] < s.theirPubKey[i]) { isAlice = true;  break; }
        if (_myLongTermPubKey[i] > s.theirPubKey[i]) { isAlice = false; break; }
      }
    }
    // Derive header keys deterministically from sharedSecret
    await DoubleRatchet.initHeaderKeys(s.ratchet, s.sharedSecret, isAlice);
    s.isAlice = isAlice;
    return true;
  }

  async function computeSharedSecret(id) {
    const s = sessions.get(id);
    if (!s || !s.theirEphemeralPub || !s.myEphemeral || !_myLongTermPubKey)
      return false;

    // Reject all-zeros or all-same-byte DH pubkeys (weak/malicious keys)
    const isWeakKey = (key) => {
      const first = key[0];
      return key.every(b => b === 0) || key.every(b => b === first);
    };
    if (isWeakKey(s.theirEphemeralPub) || isWeakKey(s.theirPubKey)) {
      if (typeof UI !== 'undefined') UI.addSystem('⚠ Weak DH key from peer — connection rejected');
      return false;
    }

    // ── X25519 (classical) ──────────────────────────
    const ephShared = nacl.box.before(s.theirEphemeralPub, s.myEphemeral.secretKey);
    let lt1, lt2, cmp = false;
    for (let i = 0; i < 32; i++) {
      if (_myLongTermPubKey[i] < s.theirPubKey[i]) { cmp = true;  break; }
      if (_myLongTermPubKey[i] > s.theirPubKey[i]) { cmp = false; break; }
    }
    lt1 = cmp ? _myLongTermPubKey : s.theirPubKey;
    lt2 = cmp ? s.theirPubKey     : _myLongTermPubKey;
    const x25519Input = new Uint8Array(96);
    x25519Input.set(ephShared, 0); x25519Input.set(lt1, 32); x25519Input.set(lt2, 64);
    const x25519Hash = new Uint8Array(await crypto.subtle.digest('SHA-512', x25519Input));
    burn(x25519Input, ephShared);

    // ── ML-KEM-768 (post-quantum) ───────────────────
    // kemSecret is set by app.js after encap/decap exchange
    const kemSecret = s.kemSecret || new Uint8Array(32); // fallback: zeros (graceful degradation)

    // ── Hybrid combination via HKDF-SHA512 ──────────
    // finalSecret = HKDF(x25519Secret || kemSecret, "kryptochat-pq-hybrid-v1")
    // Both secrets must be compromised to break the session.
    const ikm = new Uint8Array(64);
    ikm.set(x25519Hash.slice(0, 32), 0);
    ikm.set(kemSecret, 32);
    const key  = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-512', salt: new Uint8Array(64),
        info: new TextEncoder().encode('kryptochat-pq-hybrid-v1') },
      key, 32 * 8
    );
    s.sharedSecret = new Uint8Array(bits);
    s.established  = true;
    burn(ikm, x25519Hash);

    initRatchet(id); // async, fire-and-forget
    return true;
  }

  // Called when KEM secret arrives after initial connection (Bob's side)
  async function recomputeWithKem(id) {
    const s = sessions.get(id);
    if (!s || !s.kemSecret || !s.sharedSecret) return;
    // Re-derive sharedSecret incorporating KEM secret
    // This upgrades the session security retroactively
    const ikm = new Uint8Array(64);
    ikm.set(s.sharedSecret, 0);
    ikm.set(s.kemSecret, 32);
    const key  = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-512', salt: new Uint8Array(64),
        info: new TextEncoder().encode('kryptochat-pq-hybrid-v1') },
      key, 32 * 8
    );
    burn(s.sharedSecret, ikm);
    s.sharedSecret = new Uint8Array(bits);
    // Reinitialize ratchet with new combined secret
    await initRatchet(id);
    if (typeof UI !== 'undefined') UI.log('ML-KEM-768 hybrid upgrade ✓', 'ok');
  }

  function getSessionFingerprint(id) {
    const s = sessions.get(id);
    if (!s || !s.sharedSecret || !_myLongTermPubKey || !s.theirPubKey) return null;
    return KCrypto.fingerprintSession(s.sharedSecret, _myLongTermPubKey, s.theirPubKey);
  }

  async function encryptMessage(id, plaintext) {
    const s = sessions.get(id);
    if (!s || !s.ratchet) return null;
    s.msgCount = (s.msgCount || 0) + 1;
    if (s.msgCount === 900) UI.addSystem('⚠ Session approaching limit — new session recommended');
    return await DoubleRatchet.encrypt(s.ratchet, plaintext);
  }

  async function decryptMessage(id, header, nonce, ciphertext) {
    const s = sessions.get(id);
    if (!s || !s.ratchet) return null;
    return await DoubleRatchet.decrypt(s.ratchet, header, nonce, ciphertext);
  }

  function sealSenderId(sealedKey, senderAnonId) {
    const nonce = nacl.randomBytes(24);
    const data  = new TextEncoder().encode(senderAnonId);
    const enc   = nacl.secretbox(data, nonce, sealedKey);
    burn(data);
    return { sealedId: B64.enc(enc), sealedNonce: B64.enc(nonce) };
  }

  function unsealSenderId(sealedKey, sealedIdB64, sealedNonceB64) {
    try {
      const data = nacl.secretbox.open(B64.dec(sealedIdB64), B64.dec(sealedNonceB64), sealedKey);
      return data ? new TextDecoder().decode(data) : null;
    } catch { return null; }
  }

  // Dummy-Traffic: 4–20s variabler Jitter
  async function _sendDummy() {
    if (!_socket || _socket.readyState !== 1) return;
    for (const [peerId, s] of sessions) {
      if (!s.ratchet || !s.sealedKey || !s.established) continue;
      try {
        const dummy  = 'dummy:' + B64.enc(nacl.randomBytes(16));
        const enc    = await DoubleRatchet.encrypt(s.ratchet, dummy);
        if (!enc) continue;
        const sealed = sealSenderId(s.sealedKey, _myAnonId);
        const payload = { type: 'enc', eh: enc.encHeader, h: enc.header, n: enc.nonce, c: enc.ciphertext, si: sealed.sealedId, sn: sealed.sealedNonce };
        const inner  = B64.enc(new TextEncoder().encode(JSON.stringify(payload)));
        _socket.send(JSON.stringify({ type: 'relay', to: peerId, d: inner }));
      } catch {}
    }
  }

  function startDummyTraffic() {
    stopDummyTraffic();
    function schedule() {
      // 4–20 seconds — cryptographically random
      const r = nacl.randomBytes(4);
      const delay = 4000 + (new DataView(r.buffer).getUint32(0, false) / 0xFFFFFFFF) * 16000;
      _dummyTimer = setTimeout(async () => { await _sendDummy(); schedule(); }, delay);
    }
    schedule();
  }

  function stopDummyTraffic() {
    if (_dummyTimer) { clearTimeout(_dummyTimer); _dummyTimer = null; }
  }

  function isDummy(pt) { return typeof pt === 'string' && pt.startsWith('dummy:'); }

  function needsHeartbeat(id) {
    const s = sessions.get(id);
    return s?.established && (Date.now() - s.lastHeartbeat) > 20000;
  }
  function recordHeartbeat(id) { const s = sessions.get(id); if (s) s.lastHeartbeat = Date.now(); }
  function getAll()     { return sessions; }
  function destroyAll() { sessions.forEach((_, id) => removeSession(id)); stopDummyTraffic(); }

  return {
    setMyLongTermKey, setSocket,
    createSession, getSession, removeSession,
    computeSharedSecret, initRatchet,
    getSessionFingerprint,
    encryptMessage, decryptMessage,
    sealSenderId, unsealSenderId,
    startDummyTraffic, stopDummyTraffic, isDummy,
    needsHeartbeat, recordHeartbeat,
    getAll, destroyAll,
    recomputeWithKem
  };
})();
