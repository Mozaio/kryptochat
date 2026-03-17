/* ═══════════════════════════════════════════════════
   ratchet.js — Double Ratchet v3
   ① HKDF (RFC 5869, SHA-512) in kdfRK + kdfCK
   ② Header-Verschlüsselung: DH-Key im Header ist
      nicht mehr im Klartext sichtbar.
      kdfRK gibt 96 Byte: rootKey(32)+chainKey(32)+headerKey(32)
      Der Header wird mit nacl.secretbox + headerKey verschlüsselt.
      Für den Server/Angreifer ist jedes Paket vollständig opak.
   ═══════════════════════════════════════════════════ */

const DoubleRatchet = (() => {

  const MAX_CHAIN_LENGTH = 1000;
  const MAX_SKIPPED_KEYS = 500;
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

  // ── Root-KDF: 96 Byte → rootKey + chainKey + headerKey ──

  async function kdfRK(rootKey, dhOutput) {
    const out = await hkdf(dhOutput, rootKey, 'kryptochat-ratchet-root-v1', 96);
    const res = { rootKey: out.slice(0,32), chainKey: out.slice(32,64), headerKey: out.slice(64,96) };
    _burn(out);
    return res;
  }

  // ── Chain-KDF: chainKey → neuer chainKey + messageKey ──

  async function kdfCK(chainKey) {
    const newChainKey = await hkdf(chainKey, new Uint8Array(32), 'kryptochat-ratchet-chain-v1',   32);
    const messageKey  = await hkdf(chainKey, new Uint8Array(32), 'kryptochat-ratchet-message-v1', 32);
    return { chainKey: newChainKey, messageKey };
  }

  // ── Header-Verschlüsselung ────────────────────────
  // Serialisiert { dh(32), n(4), pn(4) } = 40 Byte → nacl.secretbox

  function _encryptHeader(headerKey, dh, n, pn) {
    const plain = new Uint8Array(40);
    plain.set(dh, 0);
    const dv = new DataView(plain.buffer);
    dv.setUint32(32, n,  false);
    dv.setUint32(36, pn, false);
    const nonce = nacl.randomBytes(24);
    const enc   = nacl.secretbox(plain, nonce, headerKey);
    _burn(plain);
    return { enc: B64.enc(enc), nonce: B64.enc(nonce) };
  }

  // Gibt geparsten Header zurück oder null bei falschem Key

  function _tryDecryptHeader(headerKey, encB64, nonceB64) {
    if (!headerKey || !encB64 || !nonceB64) return null;
    try {
      const plain = nacl.secretbox.open(B64.dec(encB64), B64.dec(nonceB64), headerKey);
      if (!plain || plain.length !== 40) return null;
      const dv = new DataView(plain.buffer, plain.byteOffset);
      const res = { dh: plain.slice(0,32), n: dv.getUint32(32,false), pn: dv.getUint32(36,false) };
      _burn(plain);
      return res;
    } catch { return null; }
  }

  // ── Nachrichten-Ver/Entschlüsselung ──────────────

  function _encMsg(mk, plaintext) {
    const nonce = nacl.randomBytes(24);
    const padded = _pad(plaintext);
    const ct = nacl.secretbox(padded, nonce, mk);
    _burn(padded);
    return { nonce, ct };
  }

  function _decMsg(mk, nonceB64, ctB64) {
    const padded = nacl.secretbox.open(B64.dec(ctB64), B64.dec(nonceB64), mk);
    if (!padded) return null;
    const pt = _unpad(padded);
    _burn(padded);
    return pt;
  }

  // ── Padding ───────────────────────────────────────

  function _pad(plaintext) {
    const data = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
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

  // ── Memory Cleanup ────────────────────────────────

  function _burn(...arrays) {
    arrays.forEach(a => {
      if (a instanceof Uint8Array) { a.set(nacl.randomBytes(a.length)); a.fill(0); }
    });
  }

  // ── State erstellen ───────────────────────────────
  // Neu: sendHeaderKey, recvHeaderKey, nextRecvHeaderKey, skippedHeaders

  function create(sharedSecret) {
    return {
      rootKey:           new Uint8Array(sharedSecret),
      sendChainKey:      null,
      recvChainKey:      null,
      dhSendKeyPair:     null,
      dhRecvPubKey:      null,
      sendHeaderKey:     null,   // verschlüsselt ausgehende Header
      recvHeaderKey:     null,   // entschlüsselt eingehende Header (aktueller Schritt)
      nextRecvHeaderKey: null,   // entschlüsselt Header des NÄCHSTEN DH-Schritts
      sendCount:         0,
      recvCount:         0,
      prevCount:         0,
      skippedHeaders:    new Map(), // { n+dhKey → { headerKey, messageKey } }
      totalSent:         0,
      totalRecv:         0
    };
  }

  // ── DH-Ratchet-Schritt (intern) ───────────────────
  // Führt einen vollständigen DH-Ratchet-Schritt aus:
  // 1. Recv-Chain mit neuem DH-Key aufbauen
  // 2. Neues Send-Keypair erzeugen + Send-Chain aufbauen
  // nextRecvHeaderKey = headerKey des neuen Send-Schritts
  // (damit kann der Empfänger den übernächsten DH-Schritt erkennen)

  async function _dhRatchet(ratchet, theirDHPub) {
    ratchet.dhRecvPubKey = theirDHPub;

    if (!ratchet.dhSendKeyPair) {
      // Bob-Seite: erster Empfang, kein eigenes Send-Keypair vorhanden
      const kdf = await kdfRK(ratchet.rootKey, DUMMY_DH);
      ratchet.rootKey           = kdf.rootKey;
      ratchet.recvChainKey      = kdf.chainKey;
      ratchet.recvHeaderKey     = kdf.headerKey;
    } else {
      // Normaler DH-Ratchet
      const dhOut = nacl.box.before(theirDHPub, ratchet.dhSendKeyPair.secretKey);
      const kdf   = await kdfRK(ratchet.rootKey, dhOut);
      ratchet.rootKey       = kdf.rootKey;
      ratchet.recvChainKey  = kdf.chainKey;
      ratchet.recvHeaderKey = kdf.headerKey;
      _burn(dhOut);
    }

    // Neues Send-Keypair + Send-Chain
    ratchet.dhSendKeyPair = nacl.box.keyPair();
    const dhOut2 = nacl.box.before(theirDHPub, ratchet.dhSendKeyPair.secretKey);
    const kdf2   = await kdfRK(ratchet.rootKey, dhOut2);
    ratchet.rootKey           = kdf2.rootKey;
    ratchet.sendChainKey      = kdf2.chainKey;
    ratchet.sendHeaderKey     = kdf2.headerKey;
    ratchet.nextRecvHeaderKey = kdf2.headerKey; // Gegenseite nutzt diesen als recvHeaderKey
    _burn(dhOut2);

    ratchet.prevCount = ratchet.sendCount;
    ratchet.sendCount = 0;
    ratchet.recvCount = 0;
  }

  // ── Übersprungene Keys cachen ─────────────────────

  async function _skipKeys(ratchet, until) {
    if (!ratchet.recvChainKey) return;
    while (ratchet.recvCount < until && ratchet.recvCount < MAX_CHAIN_LENGTH) {
      const kdf = await kdfCK(ratchet.recvChainKey);
      ratchet.recvChainKey = kdf.chainKey;
      const cacheKey = ratchet.recvCount + ':' + B64.enc(ratchet.dhRecvPubKey || new Uint8Array(4));
      ratchet.skippedHeaders.set(cacheKey, {
        headerKey:  ratchet.recvHeaderKey,
        messageKey: kdf.messageKey,
        n:          ratchet.recvCount
      });
      ratchet.recvCount++;
    }
    // Memory-Limit
    if (ratchet.skippedHeaders.size > MAX_SKIPPED_KEYS) {
      const iter = ratchet.skippedHeaders.keys();
      while (ratchet.skippedHeaders.size > MAX_SKIPPED_KEYS / 2) {
        const k = iter.next();
        if (k.done) break;
        const c = ratchet.skippedHeaders.get(k.value);
        if (c) _burn(c.messageKey);
        ratchet.skippedHeaders.delete(k.value);
      }
    }
  }

  // ══════════════════════════════════════════
  //  VERSCHLÜSSELN
  //  Gibt zurück: { encHeader: {enc,nonce}, nonce, ciphertext }
  //  statt vorher: { header: {dh,n,pn}, nonce, ciphertext }
  // ══════════════════════════════════════════

  async function encrypt(ratchet, plaintext) {
    if (ratchet.sendCount >= MAX_CHAIN_LENGTH) ratchet.sendChainKey = null;

    if (!ratchet.sendChainKey) {
      ratchet.dhSendKeyPair = nacl.box.keyPair();
      if (ratchet.dhRecvPubKey) {
        const dhOut = nacl.box.before(ratchet.dhRecvPubKey, ratchet.dhSendKeyPair.secretKey);
        const kdf   = await kdfRK(ratchet.rootKey, dhOut);
        ratchet.rootKey       = kdf.rootKey;
        ratchet.sendChainKey  = kdf.chainKey;
        ratchet.sendHeaderKey = kdf.headerKey;
        ratchet.prevCount     = ratchet.sendCount;
        ratchet.sendCount     = 0;
        _burn(dhOut);
      } else {
        const kdf = await kdfRK(ratchet.rootKey, DUMMY_DH);
        ratchet.rootKey       = kdf.rootKey;
        ratchet.sendChainKey  = kdf.chainKey;
        ratchet.sendHeaderKey = kdf.headerKey;
        ratchet.prevCount     = 0;
        ratchet.sendCount     = 0;
      }
    }

    const kdf = await kdfCK(ratchet.sendChainKey);
    ratchet.sendChainKey = kdf.chainKey;
    const mk = kdf.messageKey;
    const n  = ratchet.sendCount++;
    ratchet.totalSent++;

    // Header verschlüsseln — für Server/Angreifer opak
    const encHeader = _encryptHeader(ratchet.sendHeaderKey, ratchet.dhSendKeyPair.publicKey, n, ratchet.prevCount);
    const enc       = _encMsg(mk, plaintext);
    _burn(mk);

    return { encHeader, nonce: B64.enc(enc.nonce), ciphertext: B64.enc(enc.ct) };
  }

  // ══════════════════════════════════════════
  //  ENTSCHLÜSSELN
  //  Erwartet: { encHeader: {enc,nonce}, nonce, ciphertext }
  //
  //  3-Stufen-Strategie:
  //  1. recvHeaderKey → gleicher DH-Schritt
  //  2. nextRecvHeaderKey → neuer DH-Schritt nötig
  //  3. skippedHeaders-Cache → Out-of-Order
  // ══════════════════════════════════════════

  async function decrypt(ratchet, encHeader, nonceB64, ciphertextB64) {
    if (!encHeader?.enc || !encHeader?.nonce) return null;

    // Stufe 1: aktueller recvHeaderKey
    let hdr = _tryDecryptHeader(ratchet.recvHeaderKey, encHeader.enc, encHeader.nonce);
    if (hdr) {
      if (typeof hdr.n !== 'number' || hdr.n > MAX_CHAIN_LENGTH) return null;
      if (hdr.n > ratchet.recvCount) await _skipKeys(ratchet, hdr.n);
      if (hdr.n !== ratchet.recvCount || !ratchet.recvChainKey) return null;
      const kdf = await kdfCK(ratchet.recvChainKey);
      ratchet.recvChainKey = kdf.chainKey;
      const mk = kdf.messageKey;
      ratchet.recvCount++;
      ratchet.totalRecv++;
      const pt = _decMsg(mk, nonceB64, ciphertextB64);
      _burn(mk);
      return pt;
    }

    // Stufe 2: nextRecvHeaderKey → neuer DH-Ratchet-Schritt
    hdr = _tryDecryptHeader(ratchet.nextRecvHeaderKey, encHeader.enc, encHeader.nonce);
    if (hdr) {
      if (typeof hdr.n !== 'number' || hdr.n > MAX_CHAIN_LENGTH) return null;
      await _dhRatchet(ratchet, hdr.dh);
      if (hdr.n > ratchet.recvCount) await _skipKeys(ratchet, hdr.n);
      if (hdr.n !== ratchet.recvCount || !ratchet.recvChainKey) return null;
      const kdf = await kdfCK(ratchet.recvChainKey);
      ratchet.recvChainKey = kdf.chainKey;
      const mk = kdf.messageKey;
      ratchet.recvCount++;
      ratchet.totalRecv++;
      const pt = _decMsg(mk, nonceB64, ciphertextB64);
      _burn(mk);
      return pt;
    }

    // Stufe 3: Out-of-Order-Cache
    for (const [cacheKey, cached] of ratchet.skippedHeaders) {
      const h = _tryDecryptHeader(cached.headerKey, encHeader.enc, encHeader.nonce);
      if (h && h.n === cached.n) {
        const mk = cached.messageKey;
        ratchet.skippedHeaders.delete(cacheKey);
        const pt = _decMsg(mk, nonceB64, ciphertextB64);
        _burn(mk);
        ratchet.totalRecv++;
        return pt;
      }
    }

    return null;
  }

  // ── Ratchet zerstören ─────────────────────────────

  function destroy(ratchet) {
    if (!ratchet) return;
    _burn(ratchet.rootKey, ratchet.sendChainKey, ratchet.recvChainKey,
          ratchet.sendHeaderKey, ratchet.recvHeaderKey, ratchet.nextRecvHeaderKey);
    if (ratchet.dhSendKeyPair) _burn(ratchet.dhSendKeyPair.secretKey, ratchet.dhSendKeyPair.publicKey);
    ratchet.skippedHeaders.forEach(c => _burn(c.messageKey));
    ratchet.skippedHeaders.clear();
    Object.keys(ratchet).forEach(k => { ratchet[k] = null; });
  }

  // ── Serialisierung ────────────────────────────────

  function serialize(r) {
    if (!r) return null;
    return JSON.stringify({
      rootKey:           B64.enc(r.rootKey),
      sendChainKey:      r.sendChainKey      ? B64.enc(r.sendChainKey)      : null,
      recvChainKey:      r.recvChainKey      ? B64.enc(r.recvChainKey)      : null,
      sendHeaderKey:     r.sendHeaderKey     ? B64.enc(r.sendHeaderKey)     : null,
      recvHeaderKey:     r.recvHeaderKey     ? B64.enc(r.recvHeaderKey)     : null,
      nextRecvHeaderKey: r.nextRecvHeaderKey ? B64.enc(r.nextRecvHeaderKey) : null,
      dhSendPubKey:      r.dhSendKeyPair     ? B64.enc(r.dhSendKeyPair.publicKey) : null,
      dhSendSecKey:      r.dhSendKeyPair     ? B64.enc(r.dhSendKeyPair.secretKey) : null,
      dhRecvPubKey:      r.dhRecvPubKey      ? B64.enc(r.dhRecvPubKey)      : null,
      sendCount: r.sendCount, recvCount: r.recvCount, prevCount: r.prevCount,
      totalSent: r.totalSent, totalRecv: r.totalRecv
    });
  }

  function deserialize(json) {
    if (!json) return null;
    try {
      const d = JSON.parse(json);
      return {
        rootKey:           B64.dec(d.rootKey),
        sendChainKey:      d.sendChainKey      ? B64.dec(d.sendChainKey)      : null,
        recvChainKey:      d.recvChainKey      ? B64.dec(d.recvChainKey)      : null,
        sendHeaderKey:     d.sendHeaderKey     ? B64.dec(d.sendHeaderKey)     : null,
        recvHeaderKey:     d.recvHeaderKey     ? B64.dec(d.recvHeaderKey)     : null,
        nextRecvHeaderKey: d.nextRecvHeaderKey ? B64.dec(d.nextRecvHeaderKey) : null,
        dhSendKeyPair:     d.dhSendPubKey ? { publicKey: B64.dec(d.dhSendPubKey), secretKey: B64.dec(d.dhSendSecKey) } : null,
        dhRecvPubKey:      d.dhRecvPubKey ? B64.dec(d.dhRecvPubKey) : null,
        sendCount: d.sendCount||0, recvCount: d.recvCount||0, prevCount: d.prevCount||0,
        totalSent: d.totalSent||0, totalRecv: d.totalRecv||0,
        skippedHeaders: new Map()
      };
    } catch { return null; }
  }

  return { create, encrypt, decrypt, destroy, serialize, deserialize, MAX_CHAIN_LENGTH, MAX_SKIPPED_KEYS };
})();
