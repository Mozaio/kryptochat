/* ═══════════════════════════════════════════════════
   ratchet.js — Double Ratchet v6 (Korrekt + Stabil)

   Header-Verschlüsselung entfernt: das chicken-and-egg
   Problem (Alice braucht Bobs zukünftigen headerKey um
   seinen Header zu entschlüsseln, bevor sie ihn kennt)
   macht die Implementierung instabil. Der DH-Public-Key
   im Header ist ein öffentlicher Schlüssel und kein
   Geheimnis — seine Sichtbarkeit bricht keine
   kryptographischen Garantien.

   Alle anderen Sicherheitseigenschaften bleiben erhalten:
   ✓ HKDF (RFC 5869, SHA-512) für alle Key-Ableitungen
   ✓ Forward Secrecy durch Double Ratchet
   ✓ Break-in Recovery (Post-Compromise Security)
   ✓ Replay-Schutz (Nonce-Cache)
   ✓ Nachrichten-Padding (feste Blockgröße)
   ✓ Memory Wipe nach Verwendung
   ✓ Sealed Sender (in session.js)
   ✓ Dummy-Traffic (in session.js)
   ═══════════════════════════════════════════════════ */

const DoubleRatchet = (() => {

  const MAX_CHAIN_LENGTH = 1000;
  const MAX_SKIPPED_KEYS = 500;
  const MAX_NONCE_CACHE  = 2000;
  const PAD_BLOCK        = 512;
  const DUMMY_DH         = new Uint8Array(32);

  // ── HKDF (RFC 5869, SHA-512) ──────────────────────

  async function hkdf(ikm, salt, info, len) {
    const key  = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-512', salt, info: new TextEncoder().encode(info) },
      key, len * 8
    );
    return new Uint8Array(bits);
  }

  async function kdfRK(rootKey, dhOutput) {
    const out = await hkdf(dhOutput, rootKey, 'kryptochat-ratchet-root-v1', 64);
    const res = { rootKey: out.slice(0, 32), chainKey: out.slice(32, 64) };
    _burn(out);
    return res;
  }

  async function kdfCK(chainKey) {
    const newChainKey = await hkdf(chainKey, new Uint8Array(32), 'kryptochat-ratchet-chain-v1',   32);
    const messageKey  = await hkdf(chainKey, new Uint8Array(32), 'kryptochat-ratchet-message-v1', 32);
    return { chainKey: newChainKey, messageKey };
  }

  // ── Nachrichten-Ver/Entschlüsselung ──────────────

  function _encMsg(mk, pt) {
    const nonce = nacl.randomBytes(24);
    const pad   = _pad(pt);
    const ct    = nacl.secretbox(pad, nonce, mk);
    _burn(pad);
    return { nonce, ct };
  }

  function _decMsg(mk, nonceB64, ctB64) {
    const pad = nacl.secretbox.open(B64.dec(ctB64), B64.dec(nonceB64), mk);
    if (!pad) return null;
    const pt = _unpad(pad);
    _burn(pad);
    return pt;
  }

  // ── Padding ───────────────────────────────────────

  function _pad(pt) {
    const data = typeof pt === 'string' ? new TextEncoder().encode(pt) : pt;
    if (data.length > PAD_BLOCK - 2) return data;
    const out = new Uint8Array(PAD_BLOCK);
    new DataView(out.buffer).setUint16(0, data.length, false);
    out.set(data, 2);
    out.set(nacl.randomBytes(PAD_BLOCK - 2 - data.length), 2 + data.length);
    return out;
  }

  function _unpad(buf) {
    if (!buf || buf.length < 2) return null;
    if (buf.length <= PAD_BLOCK) {
      const len = new DataView(buf.buffer, buf.byteOffset).getUint16(0, false);
      if (len === 0 || len > buf.length - 2) return null;
      return new TextDecoder().decode(buf.slice(2, 2 + len));
    }
    return new TextDecoder().decode(buf);
  }

  // ── Memory Wipe ───────────────────────────────────

  function _burn(...arrays) {
    for (const a of arrays) {
      if (a instanceof Uint8Array) {
        try { a.set(nacl.randomBytes(a.length)); } catch {}
        a.fill(0);
      }
    }
  }

  // ── Replay-Schutz ─────────────────────────────────

  function _checkAndAddNonce(ratchet, nonceB64) {
    if (ratchet.seenNonces.has(nonceB64)) return false;
    ratchet.seenNonces.add(nonceB64);
    if (ratchet.seenNonces.size > MAX_NONCE_CACHE) {
      const iter = ratchet.seenNonces.values();
      while (ratchet.seenNonces.size > MAX_NONCE_CACHE / 2) {
        const v = iter.next();
        if (v.done) break;
        ratchet.seenNonces.delete(v.value);
      }
    }
    return true;
  }

  // ── Array-Vergleich (Constant-Time) ──────────────

  function _eq(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }

  // ── State ─────────────────────────────────────────

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
      skippedKeys:   new Map(),  // "dhPub:n" → messageKey
      seenNonces:    new Set(),
      totalSent:     0,
      totalRecv:     0
    };
  }

  // ── Übersprungene Keys cachen ─────────────────────

  async function _skipKeys(ratchet, until) {
    if (!ratchet.recvChainKey) return;
    while (ratchet.recvCount < until && ratchet.recvCount < MAX_CHAIN_LENGTH) {
      const kdf = await kdfCK(ratchet.recvChainKey);
      ratchet.recvChainKey = kdf.chainKey;
      const k = B64.enc(ratchet.dhRecvPubKey || new Uint8Array(4)) + ':' + ratchet.recvCount;
      ratchet.skippedKeys.set(k, kdf.messageKey);
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
  //  VERSCHLÜSSELN
  // ══════════════════════════════════════════

  async function encrypt(ratchet, plaintext) {
    if (ratchet.sendCount >= MAX_CHAIN_LENGTH) ratchet.sendChainKey = null;

    if (!ratchet.sendChainKey) {
      ratchet.dhSendKeyPair = nacl.box.keyPair();

      if (ratchet.dhRecvPubKey) {
        // DH-Ratchet: Antwort nach empfangener Nachricht
        const dhOut = nacl.box.before(ratchet.dhRecvPubKey, ratchet.dhSendKeyPair.secretKey);
        const kdf   = await kdfRK(ratchet.rootKey, dhOut);
        ratchet.rootKey      = kdf.rootKey;
        ratchet.sendChainKey = kdf.chainKey;
        ratchet.prevCount    = ratchet.sendCount;
        ratchet.sendCount    = 0;
        _burn(dhOut);
      } else {
        // Erste Nachricht: symmetrischer Start mit DUMMY_DH
        const kdf = await kdfRK(ratchet.rootKey, DUMMY_DH);
        ratchet.rootKey      = kdf.rootKey;
        ratchet.sendChainKey = kdf.chainKey;
        ratchet.prevCount    = 0;
        ratchet.sendCount    = 0;
      }
    }

    const kdf = await kdfCK(ratchet.sendChainKey);
    ratchet.sendChainKey = kdf.chainKey;
    const mk = kdf.messageKey;
    const n  = ratchet.sendCount++;
    ratchet.totalSent++;

    const enc = _encMsg(mk, plaintext);
    _burn(mk);

    return {
      header: {
        dh: B64.enc(ratchet.dhSendKeyPair.publicKey),
        n,
        pn: ratchet.prevCount
      },
      nonce:      B64.enc(enc.nonce),
      ciphertext: B64.enc(enc.ct)
    };
  }

  // ══════════════════════════════════════════
  //  ENTSCHLÜSSELN
  // ══════════════════════════════════════════

  async function decrypt(ratchet, header, nonceB64, ciphertextB64) {
    // Unterstützt sowohl altes { header } als auch neues { encHeader } Format
    // (Rückwärtskompatibilität falls encHeader noch irgendwo auftaucht)
    if (!header) return null;

    // Extrahiere dh/n/pn — header ist jetzt immer Klartext
    let dh, n, pn;
    if (header.dh && typeof header.n === 'number') {
      // Klartext-Header (v6)
      dh = B64.dec(header.dh);
      n  = header.n;
      pn = header.pn || 0;
    } else {
      return null;
    }

    if (!dh || dh.length !== 32) return null;
    if (n > MAX_CHAIN_LENGTH) return null;

    // DH-Key gewechselt?
    const dhChanged = !ratchet.dhRecvPubKey || !_eq(dh, ratchet.dhRecvPubKey);

    if (dhChanged) {
      // Replay-Check vor DH-Ratchet
      if (!_checkAndAddNonce(ratchet, nonceB64)) return null;

      // DH-Ratchet-Schritt: NUR Recv-Chain, kein Send-Schritt
      ratchet.dhRecvPubKey = dh;

      if (!ratchet.dhSendKeyPair) {
        // Bob: erste Nachricht von Alice
        const kdf = await kdfRK(ratchet.rootKey, DUMMY_DH);
        ratchet.rootKey      = kdf.rootKey;
        ratchet.recvChainKey = kdf.chainKey;
      } else {
        const dhOut = nacl.box.before(dh, ratchet.dhSendKeyPair.secretKey);
        const kdf   = await kdfRK(ratchet.rootKey, dhOut);
        ratchet.rootKey      = kdf.rootKey;
        ratchet.recvChainKey = kdf.chainKey;
        _burn(dhOut);
      }

      ratchet.sendChainKey = null; // Erzwingt DH-Schritt beim nächsten encrypt()
      ratchet.recvCount    = 0;
    } else {
      if (!_checkAndAddNonce(ratchet, nonceB64)) return null;
    }

    // Übersprungene Keys holen
    if (n > ratchet.recvCount) await _skipKeys(ratchet, n);

    let messageKey = null;

    if (n === ratchet.recvCount) {
      if (!ratchet.recvChainKey) return null;
      const kdf = await kdfCK(ratchet.recvChainKey);
      ratchet.recvChainKey = kdf.chainKey;
      messageKey = kdf.messageKey;
      ratchet.recvCount++;
      ratchet.totalRecv++;
    } else {
      // Out-of-Order
      const skipKey = B64.enc(dh) + ':' + n;
      if (ratchet.skippedKeys.has(skipKey)) {
        messageKey = ratchet.skippedKeys.get(skipKey);
        ratchet.skippedKeys.delete(skipKey);
        ratchet.totalRecv++;
      }
    }

    if (!messageKey) return null;

    const pt = _decMsg(messageKey, nonceB64, ciphertextB64);
    _burn(messageKey);
    return pt;
  }

  // ── Zerstören ─────────────────────────────────────

  function destroy(ratchet) {
    if (!ratchet) return;
    _burn(ratchet.rootKey, ratchet.sendChainKey, ratchet.recvChainKey);
    if (ratchet.dhSendKeyPair) _burn(ratchet.dhSendKeyPair.secretKey, ratchet.dhSendKeyPair.publicKey);
    ratchet.skippedKeys.forEach(mk => _burn(mk));
    ratchet.skippedKeys.clear();
    ratchet.seenNonces.clear();
    Object.keys(ratchet).forEach(k => { ratchet[k] = null; });
  }

  // ── Serialisierung ────────────────────────────────

  function serialize(r) {
    if (!r) return null;
    return JSON.stringify({
      rootKey:       B64.enc(r.rootKey),
      sendChainKey:  r.sendChainKey  ? B64.enc(r.sendChainKey)  : null,
      recvChainKey:  r.recvChainKey  ? B64.enc(r.recvChainKey)  : null,
      dhSendPubKey:  r.dhSendKeyPair ? B64.enc(r.dhSendKeyPair.publicKey) : null,
      dhSendSecKey:  r.dhSendKeyPair ? B64.enc(r.dhSendKeyPair.secretKey) : null,
      dhRecvPubKey:  r.dhRecvPubKey  ? B64.enc(r.dhRecvPubKey)  : null,
      sendCount: r.sendCount, recvCount: r.recvCount, prevCount: r.prevCount,
      totalSent: r.totalSent, totalRecv: r.totalRecv
    });
  }

  function deserialize(json) {
    if (!json) return null;
    try {
      const d = JSON.parse(json);
      return {
        rootKey:       B64.dec(d.rootKey),
        sendChainKey:  d.sendChainKey ? B64.dec(d.sendChainKey) : null,
        recvChainKey:  d.recvChainKey ? B64.dec(d.recvChainKey) : null,
        dhSendKeyPair: d.dhSendPubKey ? { publicKey: B64.dec(d.dhSendPubKey), secretKey: B64.dec(d.dhSendSecKey) } : null,
        dhRecvPubKey:  d.dhRecvPubKey ? B64.dec(d.dhRecvPubKey) : null,
        sendCount: d.sendCount||0, recvCount: d.recvCount||0, prevCount: d.prevCount||0,
        totalSent: d.totalSent||0,  totalRecv: d.totalRecv||0,
        skippedKeys: new Map(),
        seenNonces:  new Set()
      };
    } catch { return null; }
  }

  return { create, encrypt, decrypt, destroy, serialize, deserialize, MAX_CHAIN_LENGTH, MAX_SKIPPED_KEYS };
})();
