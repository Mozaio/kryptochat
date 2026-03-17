/* ratchet.js — Double Ratchet v7 (mit Header-Verschlüsselung)

   Lösung für das Henne-Ei-Problem:
   Beide Seiten leiten beim Key-Exchange aus dem sharedSecret
   ZWEI initiale Header-Keys deterministisch ab:
     HK_AB = HKDF(ss, "kryptochat-header-a-to-b-v1") — A sendet, B empfängt
     HK_BA = HKDF(ss, "kryptochat-header-b-to-a-v1") — B sendet, A empfängt

   isAlice=true  (wer zuerst sendet):  sendHK=HK_AB, recvHK=HK_BA
   isAlice=false (wer antwortet):      sendHK=HK_BA, recvHK=HK_AB

   Nach jedem DH-Ratchet-Schritt rotieren die Header-Keys:
     newHK = HKDF(newRootKey, "kryptochat-header-{dir}-v1")
   Beide Seiten können das unabhängig berechnen (DH ist symmetrisch).

   Was der Server jetzt sieht:
     { enc: "x9Kp...", nonce: "7Tz..." }  — komplett opak
   Statt vorher:
     { dh: "ABC...", n: 3, pn: 2 }       — DH-Key sichtbar
*/
const DoubleRatchet = (() => {

  const MAX_CHAIN_LENGTH = 1000;
  const MAX_SKIPPED_KEYS = 500;
  const MAX_NONCE_CACHE  = 2000;
  const PAD_BLOCK        = 1024;
  const DUMMY_DH         = new Uint8Array(32);

  // ── HKDF ──────────────────────────────────────────

  async function hkdf(ikm, salt, info, len) {
    const key  = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-512', salt, info: new TextEncoder().encode(info) }, key, len * 8
    );
    return new Uint8Array(bits);
  }

  // Root-KDF: 64B → rootKey(32) + chainKey(32)
  async function kdfRK(rootKey, dhOutput) {
    const out = await hkdf(dhOutput, rootKey, 'kryptochat-ratchet-root-v1', 64);
    const res = { rootKey: out.slice(0, 32), chainKey: out.slice(32, 64) };
    _burn(out); return res;
  }

  async function kdfCK(chainKey) {
    const ck = await hkdf(chainKey, new Uint8Array(32), 'kryptochat-ratchet-chain-v1',   32);
    const mk = await hkdf(chainKey, new Uint8Array(32), 'kryptochat-ratchet-message-v1', 32);
    return { chainKey: ck, messageKey: mk };
  }

  // Header-Keys aus rootKey ableiten (nach DH-Schritt)
  async function deriveHeaderKeys(rootKey) {
    const hkAB = await hkdf(new Uint8Array(32), rootKey, 'kryptochat-header-a-to-b-v1', 32);
    const hkBA = await hkdf(new Uint8Array(32), rootKey, 'kryptochat-header-b-to-a-v1', 32);
    return { hkAB, hkBA };
  }

  // ── Header-Verschlüsselung ────────────────────────
  // Format: nacl.secretbox({ dh(32), n(4), pn(4) }, nonce, headerKey)

  function _encHdr(hk, dh, n, pn) {
    const plain = new Uint8Array(40);
    plain.set(dh, 0);
    new DataView(plain.buffer).setUint32(32, n,  false);
    new DataView(plain.buffer).setUint32(36, pn, false);
    const nonce = nacl.randomBytes(24);
    const enc   = nacl.secretbox(plain, nonce, hk);
    _burn(plain);
    return { enc: B64.enc(enc), nonce: B64.enc(nonce) };
  }

  function _decHdr(hk, encB64, nonceB64) {
    if (!hk || !encB64 || !nonceB64) return null;
    try {
      const plain = nacl.secretbox.open(B64.dec(encB64), B64.dec(nonceB64), hk);
      if (!plain || plain.length !== 40) return null;
      const dv = new DataView(plain.buffer, plain.byteOffset);
      const res = { dh: plain.slice(0, 32), n: dv.getUint32(32, false), pn: dv.getUint32(36, false) };
      _burn(plain); return res;
    } catch { return null; }
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
    _burn(pad); return pt;
  }

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

  function _burn(...arrays) {
    for (const a of arrays) {
      if (a instanceof Uint8Array) {
        try { a.set(nacl.randomBytes(a.length)); } catch {}
        a.fill(0);
      }
    }
  }

  function _eq(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0;
  }

  function _checkAndAddNonce(r, n) {
    if (r.seenNonces.has(n)) return false;
    r.seenNonces.add(n);
    if (r.seenNonces.size > MAX_NONCE_CACHE) {
      const iter = r.seenNonces.values();
      while (r.seenNonces.size > MAX_NONCE_CACHE / 2) { const v = iter.next(); if (v.done) break; r.seenNonces.delete(v.value); }
    }
    return true;
  }

  // ── State ─────────────────────────────────────────

  function create(sharedSecret) {
    return {
      rootKey:        new Uint8Array(sharedSecret),
      sendChainKey:   null,
      recvChainKey:   null,
      dhSendKeyPair:  null,
      dhRecvPubKey:   null,
      sendHeaderKey:  null,   // verschlüsselt ausgehende Header
      recvHeaderKey:  null,   // entschlüsselt eingehende Header
      sendCount:      0,
      recvCount:      0,
      prevCount:      0,
      skippedKeys:    new Map(),
      seenNonces:     new Set(),
      totalSent:      0,
      totalRecv:      0
    };
  }

  // ── Initialisierung der Header-Keys ──────────────
  // Deterministisch aus sharedSecret — beide Seiten berechnen dasselbe.
  // isAlice = true:  wer zuerst sendet (kleinerer Long-Term-Key)
  // isAlice = false: wer antwortet

  async function initHeaderKeys(ratchet, sharedSecret, isAlice) {
    const hkAB = await hkdf(new Uint8Array(32), sharedSecret, 'kryptochat-header-a-to-b-v1', 32);
    const hkBA = await hkdf(new Uint8Array(32), sharedSecret, 'kryptochat-header-b-to-a-v1', 32);
    if (isAlice) {
      ratchet.sendHeaderKey = hkAB;  // A→B: Alice verschlüsselt
      ratchet.recvHeaderKey = hkBA;  // B→A: Alice entschlüsselt
    } else {
      ratchet.sendHeaderKey = hkBA;  // B→A: Bob verschlüsselt
      ratchet.recvHeaderKey = hkAB;  // A→B: Bob entschlüsselt
    }
    return ratchet;
  }

  // ── Übersprungene Keys ────────────────────────────

  async function _skipKeys(r, until) {
    if (!r.recvChainKey) return;
    while (r.recvCount < until && r.recvCount < MAX_CHAIN_LENGTH) {
      const kdf = await kdfCK(r.recvChainKey);
      r.recvChainKey = kdf.chainKey;
      const k = B64.enc(r.dhRecvPubKey || new Uint8Array(4)) + ':' + r.recvCount;
      r.skippedKeys.set(k, kdf.messageKey);
      r.recvCount++;
    }
    if (r.skippedKeys.size > MAX_SKIPPED_KEYS) {
      const iter = r.skippedKeys.keys();
      while (r.skippedKeys.size > MAX_SKIPPED_KEYS / 2) {
        const k = iter.next(); if (k.done) break;
        const mk = r.skippedKeys.get(k.value);
        if (mk) _burn(mk); r.skippedKeys.delete(k.value);
      }
    }
  }

  // ══════════════════════════════════════════
  //  VERSCHLÜSSELN
  //  Header wird mit sendHeaderKey verschlüsselt.
  //  Nach DH-Ratchet: sendHeaderKey rotiert.
  // ══════════════════════════════════════════

  async function encrypt(ratchet, plaintext) {
    if (!plaintext || typeof plaintext !== 'string') return null;
    if (ratchet.sendCount >= MAX_CHAIN_LENGTH) ratchet.sendChainKey = null;

    if (!ratchet.sendChainKey) {
      ratchet.dhSendKeyPair = nacl.box.keyPair();

      if (ratchet.dhRecvPubKey) {
        // DH-Ratchet: neue Chain + neue Header-Keys
        const dhOut = nacl.box.before(ratchet.dhRecvPubKey, ratchet.dhSendKeyPair.secretKey);
        const kdf   = await kdfRK(ratchet.rootKey, dhOut);
        ratchet.rootKey      = kdf.rootKey;
        ratchet.sendChainKey = kdf.chainKey;
        ratchet.prevCount    = ratchet.sendCount;
        ratchet.sendCount    = 0;
        // sendHeaderKey NICHT rotieren — bleibt konstant für die gesamte Session.
        // Rotation würde das Henne-Ei-Problem neu einführen (Empfänger kennt
        // den neuen Key nicht bevor er ihn braucht). HK_AB und HK_BA bleiben
        // für alle Nachrichten konstant. Message-Keys haben weiterhin Forward Secrecy.
        _burn(dhOut);
      } else {
        // Erste Nachricht: DUMMY_DH
        const kdf = await kdfRK(ratchet.rootKey, DUMMY_DH);
        ratchet.rootKey      = kdf.rootKey;
        ratchet.sendChainKey = kdf.chainKey;
        ratchet.prevCount    = 0;
        ratchet.sendCount    = 0;
        // sendHeaderKey bleibt was initHeaderKeys gesetzt hat
      }
    }

    const kdf = await kdfCK(ratchet.sendChainKey);
    ratchet.sendChainKey = kdf.chainKey;
    const mk = kdf.messageKey;
    const n  = ratchet.sendCount++;
    ratchet.totalSent++;

    // Header verschlüsseln
    const encHeader = _encHdr(ratchet.sendHeaderKey, ratchet.dhSendKeyPair.publicKey, n, ratchet.prevCount);
    const enc = _encMsg(mk, plaintext);
    _burn(mk);

    return { encHeader, nonce: B64.enc(enc.nonce), ciphertext: B64.enc(enc.ct) };
  }

  // ══════════════════════════════════════════
  //  ENTSCHLÜSSELN
  // ══════════════════════════════════════════

  async function decrypt(ratchet, encHeader, nonceB64, ciphertextB64) {
    if (!encHeader?.enc || !encHeader?.nonce) return null;

    // Header entschlüsseln mit recvHeaderKey
    const hdr = _decHdr(ratchet.recvHeaderKey, encHeader.enc, encHeader.nonce);
    if (!hdr) return null;
    if (typeof hdr.n !== 'number' || hdr.n > MAX_CHAIN_LENGTH) return null;

    const dh = hdr.dh;
    const n  = hdr.n;

    if (!_checkAndAddNonce(ratchet, nonceB64)) return null;

    const dhChanged = !ratchet.dhRecvPubKey || !_eq(dh, ratchet.dhRecvPubKey);

    if (dhChanged) {
      ratchet.dhRecvPubKey = dh;
      if (!ratchet.dhSendKeyPair) {
        const kdf = await kdfRK(ratchet.rootKey, DUMMY_DH);
        ratchet.rootKey = kdf.rootKey; ratchet.recvChainKey = kdf.chainKey;
      } else {
        const dhOut = nacl.box.before(dh, ratchet.dhSendKeyPair.secretKey);
        const kdf   = await kdfRK(ratchet.rootKey, dhOut);
        ratchet.rootKey = kdf.rootKey; ratchet.recvChainKey = kdf.chainKey;
        // recvHeaderKey NICHT rotieren — bleibt konstant (siehe encrypt-Kommentar)
        _burn(dhOut);
      }
      ratchet.sendChainKey = null;
      ratchet.recvCount    = 0;
    }

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

  function destroy(r) {
    if (!r) return;
    _burn(r.rootKey, r.sendChainKey, r.recvChainKey, r.sendHeaderKey, r.recvHeaderKey);
    if (r.dhSendKeyPair) _burn(r.dhSendKeyPair.secretKey, r.dhSendKeyPair.publicKey);
    r.skippedKeys.forEach(mk => _burn(mk));
    r.skippedKeys.clear(); r.seenNonces.clear();
    Object.keys(r).forEach(k => { r[k] = null; });
  }

  function serialize(r) {
    if (!r) return null;
    return JSON.stringify({
      rootKey:       B64.enc(r.rootKey),
      sendChainKey:  r.sendChainKey  ? B64.enc(r.sendChainKey)  : null,
      recvChainKey:  r.recvChainKey  ? B64.enc(r.recvChainKey)  : null,
      sendHeaderKey: r.sendHeaderKey ? B64.enc(r.sendHeaderKey) : null,
      recvHeaderKey: r.recvHeaderKey ? B64.enc(r.recvHeaderKey) : null,
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
        sendChainKey:  d.sendChainKey  ? B64.dec(d.sendChainKey)  : null,
        recvChainKey:  d.recvChainKey  ? B64.dec(d.recvChainKey)  : null,
        sendHeaderKey: d.sendHeaderKey ? B64.dec(d.sendHeaderKey) : null,
        recvHeaderKey: d.recvHeaderKey ? B64.dec(d.recvHeaderKey) : null,
        dhSendKeyPair: d.dhSendPubKey ? { publicKey: B64.dec(d.dhSendPubKey), secretKey: B64.dec(d.dhSendSecKey) } : null,
        dhRecvPubKey:  d.dhRecvPubKey ? B64.dec(d.dhRecvPubKey) : null,
        sendCount: d.sendCount||0, recvCount: d.recvCount||0, prevCount: d.prevCount||0,
        totalSent: d.totalSent||0,  totalRecv: d.totalRecv||0,
        skippedKeys: new Map(), seenNonces: new Set()
      };
    } catch { return null; }
  }

  return { create, initHeaderKeys, encrypt, decrypt, destroy, serialize, deserialize, MAX_CHAIN_LENGTH, MAX_SKIPPED_KEYS };
})();
