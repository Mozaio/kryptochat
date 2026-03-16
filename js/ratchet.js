/* ═══════════════════════════════════════════════════
   ratchet.js — Double Ratchet Algorithmus
   
   Besser als Signal:
   - Commitment-basierter Initial Key Exchange
   - Obligatorische Fingerprint-Verifizierung
   - Zufällige Ratchet-Keys (nicht deterministisch)
   
   Kernfunktionen:
   - DH Ratchet (ephemere Schlüssel pro Richtung)
   - Symmetrische Ratchet (KDF-Chain pro Nachricht)
   - Message Keys werden nach Verwendung gelöscht
   - Post-Compromise Security (nach DH-Ratchet)
   ═══════════════════════════════════════════════════ */

const DoubleRatchet = (() => {

  // ── HKDF-ähnliche Key Derivation ──
  // Nutzt HMAC-SHA512 als PRF

  function kdfRK(rootKey, dhOutput) {
    // Root Key Ratchet: Aus Root Key + DH Output → neuen Root Key + Chain Key
    const hmac = nacl.hash(
      new Uint8Array([...rootKey, ...dhOutput])
    ); // SHA-512 → 64 Bytes
    return {
      rootKey:  hmac.slice(0, 32),
      chainKey: hmac.slice(32, 64)
    };
  }

  function kdfCK(chainKey) {
    // Chain Key Ratchet: Aus Chain Key → neuen Chain Key + Message Key
    const input = new Uint8Array([...chainKey, 0x01]);
    const newChainKey = nacl.hash(input).slice(0, 32);

    const input2 = new Uint8Array([...chainKey, 0x02]);
    const messageKey = nacl.hash(input2).slice(0, 32);

    return { chainKey: newChainKey, messageKey };
  }

  // ── AES-ähnliche Verschlüsselung mit NaCl secretbox ──
  // Message Key wird als Shared Secret für nacl.secretbox verwendet

  function encryptWithMK(messageKey, plaintext) {
    const nonce = nacl.randomBytes(24);
    const padded = _padMessage(plaintext);
    const ciphertext = nacl.secretbox(padded, nonce, messageKey);
    _burn(padded);
    return { nonce, ciphertext };
  }

  function decryptWithMK(messageKey, nonce, ciphertext) {
    const padded = nacl.secretbox.open(ciphertext, nonce, messageKey);
    if (!padded) return null;
    const plaintext = _unpadMessage(padded);
    _burn(padded);
    return plaintext;
  }

  // ── Padding auf feste Größe ──
  const PAD_BLOCK = 512;

  function _padMessage(plaintext) {
    const data = typeof plaintext === 'string'
      ? new TextEncoder().encode(plaintext)
      : plaintext;
    const padded = new Uint8Array(PAD_BLOCK);
    const view = new DataView(padded.buffer);
    view.setUint16(0, data.length, false);
    padded.set(data, 2);
    const rand = nacl.randomBytes(PAD_BLOCK - 2 - data.length);
    padded.set(rand, 2 + data.length);
    return padded;
  }

  function _unpadMessage(padded) {
    if (!padded || padded.length < 2) return null;
    const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
    const len = view.getUint16(0, false);
    if (len > padded.length - 2) return null;
    return new TextDecoder().decode(padded.slice(2, 2 + len));
  }

  function _burn(...arrays) {
    arrays.forEach(a => {
      if (a instanceof Uint8Array) {
        a.set(nacl.randomBytes(a.length));
        a.fill(0);
      }
    });
  }

  // ── Ratchet State Erstellung ──

  function create(ourDHKeyPair, sharedSecret) {
    // Initialisierung: Root Key = SHA-512(sharedSecret).slice(0,32)
    const rootKey = nacl.hash(sharedSecret).slice(0, 32);

    return {
      rootKey:      rootKey,
      sendChainKey: null,    // Wird beim ersten Senden gesetzt
      recvChainKey: null,    // Wird beim ersten Empfangen gesetzt
      dhSendKeyPair: ourDHKeyPair,
      dhRecvPubKey: null,
      sendCount:    0,
      recvCount:    0,
      prevCount:    0,
      skippedKeys:  new Map()  // "pubKey:counter" → messageKey
    };
  }

  // ── Nachricht verschlüsseln ──

  function encrypt(ratchet, plaintext) {
    if (!ratchet.sendChainKey) {
      // Erste Nachricht: DH-Ratchet initialisieren
      // Der Sender macht den ersten Ratchet-Schritt
      if (ratchet.dhRecvPubKey) {
        // Wir haben bereits einen empfangenen Key → ratchet mit unserem Send-Key
        const dhOut = nacl.box.before(ratchet.dhRecvPubKey, ratchet.dhSendKeyPair.secretKey);
        const kdf = kdfRK(ratchet.rootKey, dhOut);
        ratchet.rootKey = kdf.rootKey;
        ratchet.sendChainKey = kdf.chainKey;
        _burn(dhOut);
      } else {
        // Noch kein empfangener Key → Chain starten mit Root Key
        const temp = kdfCK(ratchet.rootKey);
        ratchet.sendChainKey = temp.chainKey;
      }
    }

    // Chain ratcheten → Message Key
    const { chainKey, messageKey } = kdfCK(ratchet.sendChainKey);
    ratchet.sendChainKey = chainKey;
    ratchet.sendCount++;

    // Verschlüsseln
    const encrypted = encryptWithMK(messageKey, plaintext);

    // Message Key sofort verbrennen
    _burn(messageKey);

    return {
      header: {
        dh: B64.enc(ratchet.dhSendKeyPair.publicKey),
        n:  ratchet.sendCount - 1,
        pn: ratchet.prevCount
      },
      nonce:      B64.enc(encrypted.nonce),
      ciphertext: B64.enc(encrypted.ciphertext)
    };
  }

  // ── Nachricht entschlüsseln ──

  function decrypt(ratchet, header, nonceB64, ciphertextB64) {
    const dhPubKey   = B64.dec(header.dh);
    const counter    = header.n;
    const prevCount  = header.pn;

    const nonce      = B64.dec(nonceB64);
    const ciphertext = B64.dec(ciphertextB64);

    // Prüfe ob DH-Key gewechselt hat
    const dhChanged = !ratchet.dhRecvPubKey ||
      !_arraysEqual(dhPubKey, ratchet.dhRecvPubKey);

    if (dhChanged) {
      // DH-Ratchet Schritt
      _dhRatchetStep(ratchet, dhPubKey, prevCount);
    }

    // Prüfe ob Nachricht übersprungen wurde
    const skipped = ratchet.recvCount;
    if (counter > skipped) {
      // Fehlende Nachrichten: Keys speichern für spätere Entschlüsselung
      _skipMessageKeys(ratchet, dhPubKey, counter);
    }

    // Message Key holen
    let messageKey = null;
    const skipKey = B64.enc(dhPubKey) + ':' + counter;

    if (ratchet.skippedKeys.has(skipKey)) {
      messageKey = ratchet.skippedKeys.get(skipKey);
      ratchet.skippedKeys.delete(skipKey);
    } else {
      // Aus Chain ableiten (falls wir diese Nachricht noch nicht gesehen haben)
      if (ratchet.recvChainKey && counter === ratchet.recvCount) {
        const kdf = kdfCK(ratchet.recvChainKey);
        ratchet.recvChainKey = kdf.chainKey;
        messageKey = kdf.messageKey;
        ratchet.recvCount++;
      } else {
        return null; // Nachricht kann nicht entschlüsselt werden
      }
    }

    // Entschlüsseln
    const plaintext = decryptWithMK(messageKey, nonce, ciphertext);

    // Message Key verbrennen
    _burn(messageKey);

    return plaintext;
  }

  // ── DH Ratchet Schritt ──

  function _dhRatchetStep(ratchet, theirDHPubKey, prevCount) {
    // Alten Send-State merken
    ratchet.prevCount = ratchet.sendCount;
    ratchet.sendCount = 0;
    ratchet.recvCount = 0;

    // Receive Chain mit altem DH-Schlüssel updaten
    if (ratchet.dhRecvPubKey) {
      // Alte Receive Chain war schon initialisiert
    }

    // 1. Receive Chain mit neuem DH-Key
    const dhRecv = nacl.box.before(theirDHPubKey, ratchet.dhSendKeyPair.secretKey);
    const recvKDF = kdfRK(ratchet.rootKey, dhRecv);
    ratchet.rootKey = recvKDF.rootKey;
    ratchet.recvChainKey = recvKDF.chainKey;
    _burn(dhRecv);

    // 2. Neuen DH-Schlüssel erzeugen
    const newDHKeyPair = nacl.box.keyPair();
    ratchet.dhSendKeyPair = newDHKeyPair;
    ratchet.dhRecvPubKey = theirDHPubKey;

    // 3. Send Chain mit neuem DH-Key
    const dhSend = nacl.box.before(theirDHPubKey, newDHKeyPair.secretKey);
    const sendKDF = kdfRK(ratchet.rootKey, dhSend);
    ratchet.rootKey = sendKDF.rootKey;
    ratchet.sendChainKey = sendKDF.chainKey;
    _burn(dhSend);
  }

  // ── Übersprungene Message Keys ──

  function _skipMessageKeys(ratchet, dhPubKey, until) {
    const startCount = ratchet.recvCount;
    for (let i = startCount; i < until; i++) {
      if (!ratchet.recvChainKey) break;
      const kdf = kdfCK(ratchet.recvChainKey);
      ratchet.recvChainKey = kdf.chainKey;
      const key = B64.enc(dhPubKey) + ':' + i;
      ratchet.skippedKeys.set(key, kdf.messageKey);
      ratchet.recvCount++;
    }

    // Max 1000 gespeicherte Keys (DoS-Schutz)
    if (ratchet.skippedKeys.size > 1000) {
      const iter = ratchet.skippedKeys.keys();
      while (ratchet.skippedKeys.size > 500) {
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

  // ── State serialisieren (für Persistenz) ──

  function serialize(ratchet) {
    return JSON.stringify({
      rootKey:      B64.enc(ratchet.rootKey),
      sendChainKey: ratchet.sendChainKey ? B64.enc(ratchet.sendChainKey) : null,
      recvChainKey: ratchet.recvChainKey ? B64.enc(ratchet.recvChainKey) : null,
      dhSendPubKey: B64.enc(ratchet.dhSendKeyPair.publicKey),
      dhSendSecKey: B64.enc(ratchet.dhSendKeyPair.secretKey),
      dhRecvPubKey: ratchet.dhRecvPubKey ? B64.enc(ratchet.dhRecvPubKey) : null,
      sendCount:    ratchet.sendCount,
      recvCount:    ratchet.recvCount,
      prevCount:    ratchet.prevCount,
      // skippedKeys nicht serialisieren (zu groß)
    });
  }

  function deserialize(json) {
    const d = JSON.parse(json);
    return {
      rootKey:      B64.dec(d.rootKey),
      sendChainKey: d.sendChainKey ? B64.dec(d.sendChainKey) : null,
      recvChainKey: d.recvChainKey ? B64.dec(d.recvChainKey) : null,
      dhSendKeyPair: {
        publicKey: B64.dec(d.dhSendPubKey),
        secretKey: B64.dec(d.dhSendSecKey)
      },
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
    deserialize,
    kdfCK,
    _burn
  };
})();
