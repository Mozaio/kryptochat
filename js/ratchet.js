/* ═══════════════════════════════════════════════════
   ratchet.js — Double Ratchet (HKDF-gehärtet)

   Änderungen gegenüber Vorversion:
   - kdfRK und kdfCK verwenden jetzt echtes HKDF (RFC 5869)
     via Web Crypto API (SHA-512) statt rohem nacl.hash().
   - Explizite info-Parameter trennen kryptografische Domänen
     sauber: "kryptochat-ratchet-root-v1" vs "kryptochat-ratchet-chain-v1".
   - Beide Funktionen sind async — encrypt/decrypt ebenfalls.
   - Alle anderen Fixes (prevCount, burn, Limits) bleiben erhalten.
   ═══════════════════════════════════════════════════ */

const DoubleRatchet = (() => {

  const MAX_CHAIN_LENGTH  = 1000;
  const MAX_SKIPPED_KEYS  = 500;
  const PAD_BLOCK         = 512;
  const DUMMY_DH          = new Uint8Array(32);

  // ══════════════════════════════════════════
  //  HKDF-Hilfsfunktion (RFC 5869, SHA-512)
  //
  //  ikm  — Input Keying Material (Uint8Array)
  //  salt — Zufälliger Salt oder rootKey (Uint8Array)
  //  info — Domain-Separator-String (z.B. "kryptochat-root-v1")
  //  len  — Gewünschte Ausgabelänge in Bytes
  //
  //  Warum HKDF statt nacl.hash?
  //  nacl.hash ist reines SHA-512 ohne Domain-Separation.
  //  Zwei verschiedene KDF-Aufrufe mit ähnlichem Input können
  //  sich überschneiden. HKDF trennt Kontexte explizit über
  //  den info-Parameter und ist für Key-Derivation standardisiert.
  // ══════════════════════════════════════════

  async function hkdf(ikm, salt, info, len) {
    // Schritt 1: IKM als "raw" importieren
    const ikmKey = await crypto.subtle.importKey(
      'raw', ikm, { name: 'HKDF' }, false, ['deriveBits']
    );

    // Schritt 2: Bits ableiten
    const bits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-512',
        salt: salt,
        info: new TextEncoder().encode(info)
      },
      ikmKey,
      len * 8   // deriveBits erwartet Bit-Länge
    );

    return new Uint8Array(bits);
  }

  // ══════════════════════════════════════════
  //  KDF-Funktionen (jetzt async + HKDF)
  // ══════════════════════════════════════════

  // Root-KDF: Leitet neuen rootKey + chainKey aus (rootKey, dhOutput) ab.
  //
  // Vorher: nacl.hash(rootKey || dhOutput).slice(0/32)
  // Jetzt:  HKDF(ikm=dhOutput, salt=rootKey, info="kryptochat-ratchet-root-v1", len=64)
  //         → ersten 32 Bytes = neuer rootKey
  //         → nächsten 32 Bytes = chainKey
  //
  // Der info-String "kryptochat-ratchet-root-v1" stellt sicher, dass
  // dieser KDF-Aufruf nie mit einem anderen Kontext kollidieren kann.

  async function kdfRK(rootKey, dhOutput) {
    const out = await hkdf(
      dhOutput,                          // IKM = DH-Ergebnis
      rootKey,                           // Salt = aktueller Root Key
      'kryptochat-ratchet-root-v1',      // Domain-Separator
      64                                 // 64 Bytes → 2 × 32
    );
    const newRootKey  = out.slice(0, 32);
    const newChainKey = out.slice(32, 64);
    _burn(out);
    return { rootKey: newRootKey, chainKey: newChainKey };
  }

  // Chain-KDF: Leitet messageKey + neuen chainKey aus chainKey ab.
  //
  // Vorher: Zwei nacl.hash-Aufrufe mit Byte 0x01 / 0x02 angehängt.
  // Jetzt:  Zwei HKDF-Aufrufe mit expliziten Domain-Separatoren.
  //         Das ist formal stärker, weil der info-String nicht
  //         mit Nutzerdaten kollidieren kann (anders als ein
  //         angehängtes Byte an variabel-langem Input).

  async function kdfCK(chainKey) {
    // Neuer Chain Key — info trennt klar von Message Key
    const newChainKeyBuf = await hkdf(
      chainKey,
      new Uint8Array(32),                 // leerer Salt ist für CK-Ratchet üblich
      'kryptochat-ratchet-chain-v1',
      32
    );

    // Message Key — anderer info-String → komplett andere Ausgabe
    const messageKeyBuf = await hkdf(
      chainKey,
      new Uint8Array(32),
      'kryptochat-ratchet-message-v1',
      32
    );

    return { chainKey: newChainKeyBuf, messageKey: messageKeyBuf };
  }

  // ══════════════════════════════════════════
  //  Verschlüsselung / Entschlüsselung
  //  (unverändert — nacl.secretbox ist korrekt)
  // ══════════════════════════════════════════

  function encryptWithMK(messageKey, plaintext) {
    const nonce    = nacl.randomBytes(24);
    const padded   = _pad(plaintext);
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
  //  Padding (unverändert)
  // ══════════════════════════════════════════

  function _pad(plaintext) {
    const data = typeof plaintext === 'string'
      ? new TextEncoder().encode(plaintext)
      : plaintext;
    if (data.length > PAD_BLOCK - 2) return data;
    const padded = new Uint8Array(PAD_BLOCK);
    const view   = new DataView(padded.buffer);
    view.setUint16(0, data.length, false);
    padded.set(data, 2);
    padded.set(nacl.randomBytes(PAD_BLOCK - 2 - data.length), 2 + data.length);
    return padded;
  }

  function _unpad(padded) {
    if (!padded || padded.length < 2) return null;
    if (padded.length <= PAD_BLOCK) {
      const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
      const len  = view.getUint16(0, false);
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
  //  ERSTELLEN (unverändert)
  // ══════════════════════════════════════════

  function create(sharedSecret) {
    return {
      rootKey:       new Uint8Array(sharedSecret),
      sendChainKey:  null,
      recvChainKey:  null,
      dhSendKeyPair: null,
      dhRecvPubKey:  null,
      sendCount:     0,
      recvCount:     0,
      prevCount:     0,
      skippedKeys:   new Map(),
      totalSent:     0,
      totalRecv:     0
    };
  }

  // ══════════════════════════════════════════
  //  VERSCHLÜSSELN (jetzt async wegen HKDF)
  // ══════════════════════════════════════════

  async function encrypt(ratchet, plaintext) {
    if (ratchet.sendCount >= MAX_CHAIN_LENGTH) {
      ratchet.sendChainKey = null;
    }

    if (!ratchet.sendChainKey) {
      ratchet.dhSendKeyPair = nacl.box.keyPair();

      if (ratchet.dhRecvPubKey) {
        const dhOut = nacl.box.before(ratchet.dhRecvPubKey, ratchet.dhSendKeyPair.secretKey);
        const kdf   = await kdfRK(ratchet.rootKey, dhOut);   // ← await
        ratchet.rootKey      = kdf.rootKey;
        ratchet.sendChainKey = kdf.chainKey;
        ratchet.prevCount    = ratchet.sendCount;
        ratchet.sendCount    = 0;
        _burn(dhOut);
      } else {
        const kdf = await kdfRK(ratchet.rootKey, DUMMY_DH);  // ← await
        ratchet.rootKey      = kdf.rootKey;
        ratchet.sendChainKey = kdf.chainKey;
        ratchet.prevCount    = 0;
        ratchet.sendCount    = 0;
      }
    }

    const kdf        = await kdfCK(ratchet.sendChainKey);    // ← await
    ratchet.sendChainKey = kdf.chainKey;
    const messageKey = kdf.messageKey;
    const msgIndex   = ratchet.sendCount;
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
  //  ENTSCHLÜSSELN (jetzt async wegen HKDF)
  // ══════════════════════════════════════════

  async function decrypt(ratchet, header, nonceB64, ciphertextB64) {
    if (!header || !header.dh || typeof header.n !== 'number') return null;

    const theirDHPubKey = B64.dec(header.dh);
    if (!theirDHPubKey || theirDHPubKey.length !== 32) return null;

    const counter = header.n;
    if (counter > MAX_CHAIN_LENGTH) return null;

    const nonce      = B64.dec(nonceB64);
    const ciphertext = B64.dec(ciphertextB64);

    const dhChanged = !ratchet.dhRecvPubKey ||
      !_arraysEqual(theirDHPubKey, ratchet.dhRecvPubKey);

    if (dhChanged) {
      if (!ratchet.dhSendKeyPair) {
        const kdf = await kdfRK(ratchet.rootKey, DUMMY_DH);  // ← await
        ratchet.rootKey      = kdf.rootKey;
        ratchet.recvChainKey = kdf.chainKey;
      } else {
        const dhOutput = nacl.box.before(theirDHPubKey, ratchet.dhSendKeyPair.secretKey);
        const kdf      = await kdfRK(ratchet.rootKey, dhOutput); // ← await
        ratchet.rootKey      = kdf.rootKey;
        ratchet.recvChainKey = kdf.chainKey;
        _burn(dhOutput);
      }

      ratchet.dhRecvPubKey = theirDHPubKey;
      ratchet.recvCount    = 0;
      ratchet.prevCount    = ratchet.sendCount;
      ratchet.sendChainKey = null;
    }

    if (counter > ratchet.recvCount) {
      await _skipKeys(ratchet, counter);                        // ← await
    }

    let messageKey = null;

    if (counter === ratchet.recvCount) {
      if (ratchet.recvChainKey) {
        const kdf            = await kdfCK(ratchet.recvChainKey); // ← await
        ratchet.recvChainKey = kdf.chainKey;
        messageKey           = kdf.messageKey;
        ratchet.recvCount++;
        ratchet.totalRecv++;
      }
    } else {
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
  //  Übersprungene Keys (jetzt async)
  // ══════════════════════════════════════════

  async function _skipKeys(ratchet, until) {
    if (!ratchet.recvChainKey) return;

    while (ratchet.recvCount < until) {
      if (ratchet.recvCount >= MAX_CHAIN_LENGTH) break;

      const kdf            = await kdfCK(ratchet.recvChainKey); // ← await
      ratchet.recvChainKey = kdf.chainKey;
      const key            = B64.enc(ratchet.dhRecvPubKey) + ':' + ratchet.recvCount;
      ratchet.skippedKeys.set(key, kdf.messageKey);
      ratchet.recvCount++;
    }

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
  //  Ratchet zerstören (unverändert)
  // ══════════════════════════════════════════

  function destroy(ratchet) {
    if (!ratchet) return;
    _burn(ratchet.rootKey, ratchet.sendChainKey, ratchet.recvChainKey);
    if (ratchet.dhSendKeyPair) {
      _burn(ratchet.dhSendKeyPair.secretKey, ratchet.dhSendKeyPair.publicKey);
    }
    ratchet.skippedKeys.forEach(mk => _burn(mk));
    ratchet.skippedKeys.clear();
    Object.keys(ratchet).forEach(k => { ratchet[k] = null; });
  }

  // ══════════════════════════════════════════
  //  Serialisierung (unverändert)
  // ══════════════════════════════════════════

  function serialize(r) {
    if (!r) return null;
    return JSON.stringify({
      rootKey:      B64.enc(r.rootKey),
      sendChainKey: r.sendChainKey ? B64.enc(r.sendChainKey) : null,
      recvChainKey: r.recvChainKey ? B64.enc(r.recvChainKey) : null,
      dhSendPubKey: r.dhSendKeyPair ? B64.enc(r.dhSendKeyPair.publicKey) : null,
      dhSendSecKey: r.dhSendKeyPair ? B64.enc(r.dhSendKeyPair.secretKey) : null,
      dhRecvPubKey: r.dhRecvPubKey  ? B64.enc(r.dhRecvPubKey)  : null,
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
        sendCount:    d.sendCount  || 0,
        recvCount:    d.recvCount  || 0,
        prevCount:    d.prevCount  || 0,
        totalSent:    d.totalSent  || 0,
        totalRecv:    d.totalRecv  || 0,
        skippedKeys:  new Map()
      };
    } catch { return null; }
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
    encrypt,   // async
    decrypt,   // async
    destroy,
    serialize,
    deserialize,
    MAX_CHAIN_LENGTH,
    MAX_SKIPPED_KEYS
  };
})();
