/* ═══════════════════════════════════════════════════
   ratchet.js — Double Ratchet (KORRIGIERT)

   Ablauf (Symmetrischer Start ohne Pre-Keys):
   1. Beide starten mit sharedSecret als rootKey.
   2. Alice: Generiert DH_A. Derive sendChainKey symmetrisch (mit Dummy-DH). Sendet erste Nachricht.
   3. Bob: Empfängt. Da er noch keinen eigenen DH-Key hat, leitet er recvChainKey ebenfalls symmetrisch ab. Speichert DH_A.
   4. Bob (Antwort): Generiert DH_B. Berechnet DH(DH_B, DH_A). Derive sendChainKey. Sendet Antwort.
   5. Alice: Empfängt. Berechnet DH(DH_A, DH_B). Derive recvChainKey.
   6. Ab jetzt: Normales DH-Ratchet bei jedem Richtungswechsel.
   ═══════════════════════════════════════════════════ */

const DoubleRatchet = (() => {

  // ── KDF (Korrigiert für Performance) ──

  function kdfRK(rootKey, dhOutput) {
    // Performantes Zusammenfügen von TypedArrays
    const input = new Uint8Array(rootKey.length + dhOutput.length);
    input.set(rootKey);
    input.set(dhOutput, rootKey.length);
    
    const hmac = nacl.hash(input);
    return {
      rootKey:  hmac.slice(0, 32),
      chainKey: hmac.slice(32, 64)
    };
  }

  function kdfCK(chainKey) {
    const input1 = new Uint8Array(chainKey.length + 1);
    input1.set(chainKey);
    input1[chainKey.length] = 0x01;

    const input2 = new Uint8Array(chainKey.length + 1);
    input2.set(chainKey);
    input2[chainKey.length] = 0x02;

    const newChainKey = nacl.hash(input1).slice(0, 32);
    const messageKey  = nacl.hash(input2).slice(0, 32);
    return { chainKey: newChainKey, messageKey };
  }

  // ── Verschlüsselung (Unverändert) ──

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

  // ── Padding (Unverändert) ──

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
  //  VERCHLÜSSELN (Korrigierte State Machine)
  // ══════════════════════════════════════════

  function encrypt(ratchet, plaintext) {
    // Wenn wir keinen aktiven Send-Chain-Key haben, MÜSSEN wir einen DH-Ratchet-Schritt machen
    if (!ratchet.sendChainKey) {
      ratchet.dhSendKeyPair = nacl.box.keyPair(); // Immer einen neuen Key generieren!

      if (ratchet.dhRecvPubKey) {
        // Normaler DH-Ratchet (Wir antworten auf eine Nachricht von Bob)
        const dhOut = nacl.box.before(ratchet.dhRecvPubKey, ratchet.dhSendKeyPair.secretKey);
        const kdf = kdfRK(ratchet.rootKey, dhOut);
        ratchet.rootKey = kdf.rootKey;
        ratchet.sendChainKey = kdf.chainKey;
        ratchet.prevCount = ratchet.sendCount;
        ratchet.sendCount = 0;
        _burn(dhOut);
      } else {
        // Wir sind Alice, allererste Nachricht überhaupt (Symmetrischer Start)
        const dummyDH = new Uint8Array(32); // 32 Null-Bytes als Platzhalter
        const kdf = kdfRK(ratchet.rootKey, dummyDH);
        ratchet.rootKey = kdf.rootKey;
        ratchet.sendChainKey = kdf.chainKey;
      }
    }

    // Chain ratcheten (Message Key ableiten)
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
  //  ENTSCHLÜSSELN (Korrigierte DH Logik)
  // ══════════════════════════════════════════

  function decrypt(ratchet, header, nonceB64, ciphertextB64) {
    const theirDHPubKey = B64.dec(header.dh);
    const counter       = header.n;
    // prevCount wird in einer erweiterten Implementierung für Message-Loss Recovery genutzt

    const nonce      = B64.dec(nonceB64);
    const ciphertext = B64.dec(ciphertextB64);

    // DH-Key gewechselt?
    const dhChanged = !ratchet.dhRecvPubKey || !_arraysEqual(theirDHPubKey, ratchet.dhRecvPubKey);

    if (dhChanged) {
      // ── DH-RATCHET SCHRITT FÜR RECEIVE CHAIN ──
      
      if (!ratchet.dhSendKeyPair) {
        // Bob empfängt Alices allererste Nachricht.
        // Alice hat diese rein symmetrisch (mit Dummy-DH) abgeleitet. Wir tun dasselbe.
        const dummyDH = new Uint8Array(32);
        const kdf = kdfRK(ratchet.rootKey, dummyDH);
        ratchet.rootKey = kdf.rootKey;
        ratchet.recvChainKey = kdf.chainKey;
      } else {
        // Normaler DH-Schritt: Unseren aktuellen Send-Key mit dem neuen fremden Public-Key kombinieren
        const dhOutput = nacl.box.before(theirDHPubKey, ratchet.dhSendKeyPair.secretKey);
        const kdf = kdfRK(ratchet.rootKey, dhOutput);
        ratchet.rootKey = kdf.rootKey;
        ratchet.recvChainKey = kdf.chainKey;
        _burn(dhOutput);
      }

      // State updaten
      ratchet.dhRecvPubKey = theirDHPubKey;
      ratchet.recvCount = 0;
      ratchet.prevCount = ratchet.sendCount;
      
      // WICHTIG: Sagt encrypt(), dass beim nächsten Senden ein neuer DH-Key fällig ist
      ratchet.sendChainKey = null; 
    }

    // Übersprungene Message Keys generieren & speichern
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
      // Out-of-Order Message aus dem Speicher holen
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

  // ── Helper (Unverändert) ──

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

  function serialize(r) { /* Code unverändert */ }
  function deserialize(json) { /* Code unverändert */ }

  return {
    create,
    encrypt,
    decrypt,
    serialize,
    deserialize
  };
})();
