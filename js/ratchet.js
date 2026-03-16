/* ═══════════════════════════════════════════════════
   ratchet.js — Double Ratchet (Gehärtet)
   
   Änderungen (nur Sicherheit, keine Logik-Änderung):
   1. FIX: rootKey = sharedSecret (nicht gehasht — X25519 ist bereits ein sicherer Key)
   2. FIX: prevCount wird KORREKT gespeichert (vor sendCount Reset)
   3. FIX: Sensible Daten werden nach Verwendung gelöscht
   4. FIX: Kein unnötiger DH-Output bei normalem Ratchet
   5. FIX: Maximale Chain-Länge gegen Memory-DoS
   6. FIX: Validate Header vor Verarbeitung
   ═══════════════════════════════════════════════════ */

const DoubleRatchet = (() => {

  const MAX_CHAIN_LENGTH = 1000;   // Max Nachrichten pro Chain
  const MAX_SKIPPED_KEYS = 500;    // Max gespeicherte übersprungene Keys
  const PAD_BLOCK = 512;           // Nachrichten-Padding-Größe

  // Dummy-DH für symmetrischen Start (32 Null-Bytes)
  // Beide Seiten verwenden denselben Wert → gleiche Ableitung
  const DUMMY_DH = new Uint8Array(32);

  // ══════════════════════════════════════════
  //  KDF-Funktionen
  // ══════════════════════════════════════════

  function kdfRK(rootKey, dhOutput) {
    const input = new Uint8Array(64);
    input.set(rootKey, 0);
    input.set(dhOutput, 32);
    const hash = nacl.hash(input);
    _burn(input);
    return {
      rootKey:  hash.slice(0, 32),
      chainKey: hash.slice(32, 64)
    };
  }

  function kdfCK(chainKey) {
    // Zwei separate KDF-Aufrufe mit verschiedenen Domains (0x01 und 0x02)
    const input1 = new Uint8Array(33);
    input1.set(chainKey, 0);
    input1[32] = 0x01;

    const input2 = new Uint8Array(33);
    input2.set(chainKey, 0);
    input2[32] = 0x02;

    const newChainKey = nacl.hash(input1).slice(0, 32);
    const messageKey  = nacl.hash(input2).slice(0, 32);

    _burn(input1, input2);
    return { chainKey: newChainKey, messageKey };
  }

  // ══════════════════════════════════════════
  //  Verschlüsselung / Entschlüsselung
  // ══════════════════════════════════════════

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

  // ══════════════════════════════════════════
  //  Padding (feste Nachrichtengröße)
  // ══════════════════════════════════════════

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
      if (len > padded.length - 2 || len === 0) return null;
      return new TextDecoder().decode(padded.slice(2, 2 + len));
    }
    return new TextDecoder().decode(padded);
  }

  // ══════════════════════════════════════════
  //  Memory Cleanup
  // ══════════════════════════════════════════

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
  //  sharedSecret IST bereits ein sicherer 32-Byte-Key (X25519 DH).
  //  Kein zusätzliches Hashing nötig.
  //

  function create(sharedSecret) {
    return {
      rootKey:       new Uint8Array(sharedSecret), // Direkte Kopie, kein Hash!
      sendChainKey:  null,
      recvChainKey:  null,
      dhSendKeyPair: null,
      dhRecvPubKey:  null,
      sendCount:     0,
      recvCount:     0,
      prevCount:     0,
      skippedKeys:   new Map(),
      totalSent:     0,     // Gesamtanzahl gesendeter Nachrichten
      totalRecv:     0      // Gesamtanzahl empfangener Nachrichten
    };
  }

  // ══════════════════════════════════════════
  //  VERCHLÜSSELN
  // ══════════════════════════════════════════

  function encrypt(ratchet, plaintext) {
    // Chain-Längen-Limit
    if (ratchet.sendCount >= MAX_CHAIN_LENGTH) {
      // Erzwinge DH-Ratchet durch sendChainKey zurücksetzen
      ratchet.sendChainKey = null;
    }

    // Kein sendChainKey → DH-Ratchet
    if (!ratchet.sendChainKey) {
      ratchet.dhSendKeyPair = nacl.box.keyPair();

      if (ratchet.dhRecvPubKey) {
        // Normaler DH-Ratchet: Wir antworten
        const dhOut = nacl.box.before(ratchet.dhRecvPubKey, ratchet.dhSendKeyPair.secretKey);
        const kdf = kdfRK(ratchet.rootKey, dhOut);
        ratchet.rootKey = kdf.rootKey;
        ratchet.sendChainKey = kdf.chainKey;
        // FIX: prevCount VOR sendCount Reset
        ratchet.prevCount = ratchet.sendCount;
        ratchet.sendCount = 0;
        _burn(dhOut);
      } else {
        // Erste Nachricht: Symmetrischer Start mit Dummy-DH
        const kdf = kdfRK(ratchet.rootKey, DUMMY_DH);
        ratchet.rootKey = kdf.rootKey;
        ratchet.sendChainKey = kdf.chainKey;
        ratchet.prevCount = 0;
        ratchet.sendCount = 0;
      }
    }

    // Chain ratcheten
    const kdf = kdfCK(ratchet.sendChainKey);
    ratchet.sendChainKey = kdf.chainKey;
    const messageKey = kdf.messageKey;
    const msgIndex = ratchet.sendCount;
    ratchet.sendCount++;
    ratchet.totalSent++;

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
    // Header validieren
    if (!header || !header.dh || typeof header.n !== 'number') return null;

    const theirDHPubKey = B64.dec(header.dh);
    if (!theirDHPubKey || theirDHPubKey.length !== 32) return null;

    const counter = header.n;

    // Counter-Limit (Schutz gegen DoS)
    if (counter > MAX_CHAIN_LENGTH) return null;

    const nonce      = B64.dec(nonceB64);
    const ciphertext = B64.dec(ciphertextB64);

    // DH-Key gewechselt?
    const dhChanged = !ratchet.dhRecvPubKey ||
      !_arraysEqual(theirDHPubKey, ratchet.dhRecvPubKey);

    if (dhChanged) {
      // ── DH-RATCHET SCHRITT ──

      if (!ratchet.dhSendKeyPair) {
        // Bob empfängt Alices erste Nachricht
        // Alice hat mit Dummy-DH abgeleitet → wir tun dasselbe
        const kdf = kdfRK(ratchet.rootKey, DUMMY_DH);
        ratchet.rootKey = kdf.rootKey;
        ratchet.recvChainKey = kdf.chainKey;
      } else {
        // Normaler DH-Schritt
        const dhOutput = nacl.box.before(theirDHPubKey, ratchet.dhSendKeyPair.secretKey);
        const kdf = kdfRK(ratchet.rootKey, dhOutput);
        ratchet.rootKey = kdf.rootKey;
        ratchet.recvChainKey = kdf.chainKey;
        _burn(dhOutput);
      }

      ratchet.dhRecvPubKey = theirDHPubKey;
      ratchet.recvCount = 0;
      ratchet.prevCount = ratchet.sendCount;
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
        ratchet.totalRecv++;
      }
    } else {
      // Out-of-Order aus Cache
      const skipKey = B64.enc(theirDHPubKey) + ':' + counter;
      if (ratchet.skippedKeys.has(skipKey)) {
        messageKey = ratchet.skippedKeys.get(skipKey);
        ratchet.skippedKeys.delete(skipKey);
        ratchet.totalRecv++;
      }
    }

    if (!messageKey) return null;

    const plaintext = decryptWithMK(messageKey, nonce, ciphertext);
    _burn(messageKey);
    return plaintext;
  }

  // ══════════════════════════════════════════
  //  Übersprungene Keys
  // ══════════════════════════════════════════

  function _skipKeys(ratchet, until) {
    if (!ratchet.recvChainKey) return;

    while (ratchet.recvCount < until) {
      // Chain-Längen-Limit
      if (ratchet.recvCount >= MAX_CHAIN_LENGTH) break;

      const kdf = kdfCK(ratchet.recvChainKey);
      ratchet.recvChainKey = kdf.chainKey;
      const key = B64.enc(ratchet.dhRecvPubKey) + ':' + ratchet.recvCount;
      ratchet.skippedKeys.set(key, kdf.messageKey);
      ratchet.recvCount++;
    }

    // Memory-Limit: Älteste Keys löschen
    if (ratchet.skippedKeys.size > MAX_SKIPPED_KEYS) {
      const iter = ratchet.skippedKeys.keys();
      while (ratchet.skippedKeys.size > MAX_SKIPPED_KEYS / 2) {
        const k = iter.next();
        if (k.done) break;
        const mk = ratchet.skippedKeys.get(k.value);
        if (mk) _burn(mk);
        ratchet.skippedKeys.delete(k.value);
      }
    }
  }

  // ══════════════════════════════════════════
  //  Ratchet komplett löschen
  // ══════════════════════════════════════════

  function destroy(ratchet) {
    if (!ratchet) return;

    _burn(
      ratchet.rootKey,
      ratchet.sendChainKey,
      ratchet.recvChainKey
    );

    if (ratchet.dhSendKeyPair) {
      _burn(ratchet.dhSendKeyPair.secretKey, ratchet.dhSendKeyPair.publicKey);
    }

    // Alle gespeicherten Message Keys verbrennen
    ratchet.skippedKeys.forEach(mk => _burn(mk));
    ratchet.skippedKeys.clear();

    // Alles nullen
    Object.keys(ratchet).forEach(k => { ratchet[k] = null; });
  }

  // ══════════════════════════════════════════
  //  Serialisierung (für Persistenz)
  // ══════════════════════════════════════════

  function serialize(r) {
    if (!r) return null;
    return JSON.stringify({
      rootKey:      B64.enc(r.rootKey),
      sendChainKey: r.sendChainKey ? B64.enc(r.sendChainKey) : null,
      recvChainKey: r.recvChainKey ? B64.enc(r.recvChainKey) : null,
      dhSendPubKey: r.dhSendKeyPair ? B64.enc(r.dhSendKeyPair.publicKey) : null,
      dhSendSecKey: r.dhSendKeyPair ? B64.enc(r.dhSendKeyPair.secretKey) : null,
      dhRecvPubKey: r.dhRecvPubKey ? B64.enc(r.dhRecvPubKey) : null,
      sendCount:    r.sendCount,
      recvCount:    r.recvCount,
      prevCount:    r.prevCount,
      totalSent:    r.totalSent,
      totalRecv:    r.totalRecv
    });
  }

  function deserialize(json) {
    if (!json) return null;
    try {
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
        sendCount:    d.sendCount || 0,
        recvCount:    d.recvCount || 0,
        prevCount:    d.prevCount || 0,
        totalSent:    d.totalSent || 0,
        totalRecv:    d.totalRecv || 0,
        skippedKeys:  new Map()
      };
    } catch {
      return null;
    }
  }

  // ══════════════════════════════════════════
  //  Helper
  // ══════════════════════════════════════════

  function _arraysEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  return {
    create,
    encrypt,
    decrypt,
    destroy,
    serialize,
    deserialize,
    MAX_CHAIN_LENGTH,
    MAX_SKIPPED_KEYS
  };
})();
