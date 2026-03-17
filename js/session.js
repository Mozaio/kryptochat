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
      msgCount: 0, lastHeartbeat: 0, createdAt: Date.now()
    };
    sessions.set(peerAnonId, s);
    return s;
  }

  function getSession(id)  { return sessions.get(id); }

  function removeSession(id) {
    const s = sessions.get(id);
    if (!s) return;
    burn(s.sharedSecret, s.sealedKey, s.myCommitment, s.myCommitNonce, s.theirCommitment, s.theirCommitNonce);
    if (s.myEphemeral) burn(s.myEphemeral.secretKey, s.myEphemeral.publicKey);
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

    // isAlice: wer den kleineren Long-Term-Key hat (deterministisch, beide Seiten gleich)
    let isAlice = false;
    if (_myLongTermPubKey && s.theirPubKey) {
      for (let i = 0; i < 32; i++) {
        if (_myLongTermPubKey[i] < s.theirPubKey[i]) { isAlice = true;  break; }
        if (_myLongTermPubKey[i] > s.theirPubKey[i]) { isAlice = false; break; }
      }
    }
    // Header-Keys deterministisch aus sharedSecret ableiten
    await DoubleRatchet.initHeaderKeys(s.ratchet, s.sharedSecret, isAlice);
    s.isAlice = isAlice;
    return true;
  }

  function computeSharedSecret(id) {
    const s = sessions.get(id);
    if (!s || !s.theirEphemeralPub || !s.myEphemeral || !_myLongTermPubKey)
      return Promise.resolve(false);
    const ephShared = nacl.box.before(s.theirEphemeralPub, s.myEphemeral.secretKey);
    let lt1, lt2, cmp = false;
    for (let i = 0; i < 32; i++) {
      if (_myLongTermPubKey[i] < s.theirPubKey[i]) { cmp = true;  break; }
      if (_myLongTermPubKey[i] > s.theirPubKey[i]) { cmp = false; break; }
    }
    lt1 = cmp ? _myLongTermPubKey : s.theirPubKey;
    lt2 = cmp ? s.theirPubKey     : _myLongTermPubKey;
    const combined = new Uint8Array(96);
    combined.set(ephShared, 0); combined.set(lt1, 32); combined.set(lt2, 64);
    return crypto.subtle.digest('SHA-512', combined).then(buf => {
      const h = new Uint8Array(buf);
      s.sharedSecret = h.slice(0, 32);
      s.established  = true;
      await initRatchet(id);
      burn(combined, ephShared, h);
      return true;
    });
  }

  function getSessionFingerprint(id) {
    const s = sessions.get(id);
    if (!s || !s.sharedSecret || !_myLongTermPubKey || !s.theirPubKey) return null;
    return Crypto.fingerprintSession(s.sharedSecret, _myLongTermPubKey, s.theirPubKey);
  }

  async function encryptMessage(id, plaintext) {
    const s = sessions.get(id);
    if (!s || !s.ratchet) return null;
    s.msgCount = (s.msgCount || 0) + 1;
    if (s.msgCount === 900) UI.addSystem('⚠ Session nähert sich Limit — neue Session empfohlen');
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
      // 4–20 Sekunden — kryptographisch zufällig
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
    getAll, destroyAll
  };
})();
