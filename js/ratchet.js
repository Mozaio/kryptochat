/* ═══════════════════════════════════════════════════
   ratchet.js — Double Ratchet (FINALE VERSION)
   
   FIX: sharedSecret ist bereits 32 Bytes (X25519).
   Es wird NICHT nochmal gehasht — das war der Bug!
   ═══════════════════════════════════════════════════ */

const DoubleRatchet = (() => {

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

  function create(sharedSecret) {
    // ══════════════════════════════════════
    //  FIX: sharedSecret IST der rootKey!
    //  Nicht nochmal hashen — das war der Bug.
    //  sharedSecret = X25519 DH = 32 Bytes = perfekt für rootKey
    // ══════════════════════════════════════
    return {
      rootKey:       new Uint8Array(sharedSecret), // KOPIE, nicht Hash!
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

    // Erstes Senden: DH-Key erstellen
    if (!ratchet.dhSendKeyPair) {
      ratchet.dhSendKeyPair = nacl.box.keyPair();

      if (ratchet.dhRecvPubKey) {
        // Bob antwortet: DH-Ratchet für Send Chain
        const dhOut = nacl.box.before(ratchet.dhRecvPubKey, ratchet.dhSendKeyPair.secretKey);
        const kdf = kdfRK(ratchet.rootKey, dhOut);
        ratchet.rootKey = kdf.rootKey;
        ratchet.sendChainKey = kdf.chainKey;
        ratchet.prevCount = ratchet.sendCount;
        ratchet.sendCount = 0;
        _burn(dhOut);
      } else {
        // Alice erste Nachricht: Send Chain direkt aus Root Key
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

    const nonce      = B64.dec(nonceB64);
    const ciphertext = B64.dec(ciphertextB64);

    // DH-Key gewechselt?
    const dhChanged = !ratchet.dhRecvPubKey ||
      !_arraysEqual(theirDHPubKey, ratchet.dhRecvPubKey);

    if (dhChanged) {
      // DH-Ratchet: NUR Receive Chain
      if (!ratchet.dhSendKeyPair) {
        ratchet.dhSendKeyPair = nacl.box.keyPair();
      }

      const dhOutput = nacl.box.before(theirDHPubKey, ratchet.dhSendKeyPair.secretKey);
      const kdf = kdfRK(ratchet.rootKey, dhOutput);
      ratchet.rootKey = kdf.rootKey;
      ratchet.recvChainKey = kdf.chainKey;

      ratchet.dhRecvPubKey = theirDHPubKey;
      ratchet.recvCount = 0;
      ratchet.prevCount = ratchet.sendCount;
      ratchet.sendChainKey = null; // Wird beim nächsten Encrypt neu erstellt

      _burn(dhOutput);
    }

    // Übersprungene Keys
    if (counter > ratchet.recvCount) {
      _skipKeys(ratchet, counter);
    }

    // Message Key
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

  return { create, encrypt, decrypt };
})();
