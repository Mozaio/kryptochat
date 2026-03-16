/* ═══════════════════════════════════════════════════
   ratchet.js — Double Ratchet (KORRIGIERT)

   Ablauf:
   1. Beide starten mit sharedSecret als rootKey
   2. Alice: sendChainKey = KDF(rootKey), sendet erste Nachricht
   3. Bob: recvChainKey = KDF(rootKey + DH(Alice)), empfängt
   4. Bob: sendChainKey = KDF(rootKey + DH(Bob)), antwortet
   5. Alice: recvChainKey = KDF(rootKey + DH(Bob)), empfängt
   6. Ab jetzt: normales DH-Ratchet bei Richtungswechsel
   ═══════════════════════════════════════════════════ */

const DoubleRatchet = (() => {

  // ── KDF ──

  function kdfRK(rootKey, dhOutput) {
    const hmac = nacl.hash(new Uint8Array([...rootKey, ...dhOutput]));
    return {
      rootKey:  hmac.slice(0, 32),
      chainKey: hmac.slice(32, 64)
    };
  }

  function kdfCK(chainKey) {
    const newChainKey = nacl.hash(new Uint8Array([...chainKey, 0x01])).slice(0, 32);
    const messageKey  = nacl.hash(new Uint8Array([...chainKey, 0x02])).slice(0, 32);
    return { chainKey: newChainKey, messageKey };
  }

  // ── Verschlüsselung ──

  function encryptWithMK(messageKey, plaintext) {
    const nonce = nacl.randomBytes(24);
    const padded = _pad(plaintext);
    const ciphertext = nacl.secretbox(padded, nonce, messageKey);
    _burn(padded);
    return { nonce, ciphertext };
  }

  function decryptWithMK(messageKey, nonce, ciphertext) {
    const padded = nacl.secretbox.open(ciphertext, nonce, messageKey);
    if (!padded) return null;
    const plaintext = _unpad(padded);
    _burn(padded);
    return plaintext;
  }

  // ── Padding ──

  const PAD_BLOCK = 512;

  function _pad(plaintext) {
    const data = typeof plaintext === 'string'
      ? new TextEncoder().encode(plaintext)
      : plaintext;
    if (data.length > PAD_BLOCK - 2) return data;
    const padded = new Uint8Array(PAD_BLOCK);
    const view = new DataView(padded.buffer);
    view.setUint16(0, data.length, false);
    padded.set(data, 2);
    padded.set(nacl.randomBytes(PAD_BLOCK - 2 - data.length), 2 + data.length);
    return padded;
  }

  function _unpad(padded) {
    if (!padded || padded.length < 2) return null;
    if (padded.length <= PAD_BLOCK) {
      const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
      const len = view.getUint16(0, false);
      if (len > padded.length - 2) return null;
      return new TextDecoder().decode(padded.slice(2, 2 + len));
    }
    return new TextDecoder().decode(padded);
  }

  function _burn(...arrays) {
    arrays.forEach(a => {
      if (a && a instanceof Uint8Array) {
        a.set(nacl.randomBytes(a.length));
        a.fill(0);
      }
    });
  }

  // ══════════════════════════════════════════
  //  ERSTELLEN
  // ══════════════════════════════════════════
  //
  //  Beide Seiten starten identisch:
  //  rootKey = SHA-512(sharedSecret)[0..31]
  //  Alles andere = null
  //

  function create(sharedSecret) {
    return {
      rootKey:       nacl.hash(sharedSecret).slice(0, 32),
      sendChainKey:  null,
      recvChainKey:  null,
      dhSendKeyPair: null,
      dhRecvPubKey:  null,
      sendCount:     0,
      recvCount:     0,
      prevCount:     0,
      skippedKeys:   new Map()
    };
  }

  // ══════════════════════════════════════════
  //  VERCHLÜSSELN
  // ══════════════════════════════════════════

  function encrypt(ratchet, plaintext) {

    // ── Erstes Senden: DH-Key erstellen ──
    if (!ratchet.dhSendKeyPair) {
      ratchet.dhSendKeyPair = nacl.box.keyPair();

      if (ratchet.dhRecvPubKey) {
        // Wir haben bereits einen empfangenen DH-Key (wir sind Bob, antworten)
        // → DH-Ratchet für Send Chain
        const dhOut = nacl.box.before(ratchet.dhRecvPubKey, ratchet.dhSendKeyPair.secretKey);
        const kdf = kdfRK(ratchet.rootKey, dhOut);
        ratchet.rootKey = kdf.rootKey;
        ratchet.sendChainKey = kdf.chainKey;
        ratchet.prevCount = ratchet.sendCount;
        ratchet.sendCount = 0;
        _burn(dhOut);
      } else {
        // Wir sind Alice, erste Nachricht überhaupt
        // → Send Chain direkt aus Root Key
        const kdf = kdfCK(ratchet.rootKey);
        ratchet.sendChainKey = kdf.chainKey;
      }
    }

    if (!ratchet.sendChainKey) {
      const kdf = kdfCK(ratchet.rootKey);
      ratchet.sendChainKey = kdf.chainKey;
    }

    // Chain ratcheten
    const kdf = kdfCK(ratchet.sendChainKey);
    ratchet.sendChainKey = kdf.chainKey;
    const messageKey = kdf.messageKey;
    const msgIndex = ratchet.sendCount;
    ratchet.sendCount++;

    const encrypted = encryptWithMK(messageKey, plaintext);
    _burn(messageKey);

    return {
      header: {
        dh: B64.enc(ratchet.dhSendKeyPair.publicKey),
        n:  msgIndex,
        pn: ratchet.prevCount
      },
      nonce:      B64.enc(encrypted.nonce),
      ciphertext: B64.enc(encrypted.ciphertext)
    };
  }

  // ══════════════════════════════════════════
  //  ENTSCHLÜSSELN
  // ══════════════════════════════════════════

  function decrypt(ratchet, header, nonceB64, ciphertextB64) {
    const theirDHPubKey = B64.dec(header.dh);
    const counter       = header.n;
    const prevCount     = header.pn;

    const nonce      = B64.dec(nonceB64);
    const ciphertext = B64.dec(ciphertextB64);

    // DH-Key gewechselt?
    const dhChanged = !ratchet.dhRecvPubKey ||
      !_arraysEqual(theirDHPubKey, ratchet.dhRecvPubKey);

    if (dhChanged) {
      // ══════════════════════════════════════
      //  DH-RATCHET SCHRITT (NUR Receive Chain!)
      // ══════════════════════════════════════

      // Unseren DH-Key erstellen falls noch keiner da ist
      // (Bob beim ersten Empfang)
      if (!ratchet.dhSendKeyPair) {
        ratchet.dhSendKeyPair = nacl.box.keyPair();
      }

      // NUR Receive Chain updaten (mit unserem aktuellen DH-Key)
      // NICHT den DH-Key rotieren — das passiert beim nächsten Senden
      const dhOutput = nacl.box.before(theirDHPubKey, ratchet.dhSendKeyPair.secretKey);
      const kdf = kdfRK(ratchet.rootKey, dhOutput);
      ratchet.rootKey = kdf.rootKey;
      ratchet.recvChainKey = kdf.chainKey;

      // State updaten
      ratchet.dhRecvPubKey = theirDHPubKey;
      ratchet.recvCount = 0;
      ratchet.prevCount = ratchet.sendCount;
      // sendCount NICHT zurücksetzen — das passiert beim nächsten Encrypt

      _burn(dhOutput);

      // WICHTIG: sendChainKey = null, damit beim nächsten Encrypt
      // ein neuer DH-Key erzeugt und die Send Chain aktualisiert wird
      ratchet.sendChainKey = null;
    }

    // Übersprungene Message Keys
    if (counter > ratchet.recvCount) {
      _skipKeys(ratchet, counter);
    }

    // Message Key holen
    let messageKey = null;

    if (counter === ratchet.recvCount) {
      if (ratchet.recvChainKey) {
        const kdf = kdfCK(ratchet.recvChainKey);
        ratchet.recvChainKey = kdf.chainKey;
        messageKey = kdf.messageKey;
        ratchet.recvCount++;
      }
    } else {
      const skipKey = B64.enc(theirDHPubKey) + ':' + counter;
      if (ratchet.skippedKeys.has(skipKey)) {
        messageKey = ratchet.skippedKeys.get(skipKey);
        ratchet.skippedKeys.delete(skipKey);
      }
    }

    if (!messageKey) return null;

    const plaintext = decryptWithMK(messageKey, nonce, ciphertext);
    _burn(messageKey);
    return plaintext;
  }

  // ── Übersprungene Keys ──

  function _skipKeys(ratchet, until) {
    if (!ratchet.recvChainKey) return;

    while (ratchet.recvCount < until) {
      const kdf = kdfCK(ratchet.recvChainKey);
      ratchet.recvChainKey = kdf.chainKey;
      const key = B64.enc(ratchet.dhRecvPubKey) + ':' + ratchet.recvCount;
      ratchet.skippedKeys.set(key, kdf.messageKey);
      ratchet.recvCount++;
    }

    if (ratchet.skippedKeys.size > 500) {
      const iter = ratchet.skippedKeys.keys();
      while (ratchet.skippedKeys.size > 250) {
        ratchet.skippedKeys.delete(iter.next().value);
      }
    }
  }

  function _arraysEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  // ── Serialisierung ──

  function serialize(r) {
    return JSON.stringify({
      rootKey:      B64.enc(r.rootKey),
      sendChainKey: r.sendChainKey ? B64.enc(r.sendChainKey) : null,
      recvChainKey: r.recvChainKey ? B64.enc(r.recvChainKey) : null,
      dhSendPubKey: r.dhSendKeyPair ? B64.enc(r.dhSendKeyPair.publicKey) : null,
      dhSendSecKey: r.dhSendKeyPair ? B64.enc(r.dhSendKeyPair.secretKey) : null,
      dhRecvPubKey: r.dhRecvPubKey ? B64.enc(r.dhRecvPubKey) : null,
      sendCount:    r.sendCount,
      recvCount:    r.recvCount,
      prevCount:    r.prevCount
    });
  }

  function deserialize(json) {
    const d = JSON.parse(json);
    return {
      rootKey:      B64.dec(d.rootKey),
      sendChainKey: d.sendChainKey ? B64.dec(d.sendChainKey) : null,
      recvChainKey: d.recvChainKey ? B64.dec(d.recvChainKey) : null,
      dhSendKeyPair: d.dhSendPubKey ? {
        publicKey: B64.dec(d.dhSendPubKey),
        secretKey: B64.dec(d.dhSendSecKey)
      } : null,
      dhRecvPubKey: d.dhRecvPubKey ? B64.dec(d.dhRecvPubKey) : null,
      sendCount:    d.sendCount,
      recvCount:    d.recvCount,
      prevCount:    d.prevCount,
      skippedKeys:  new Map()
    };
  }

  return {
    create,
    encrypt,
    decrypt,
    serialize,
    deserialize
  };
})();
