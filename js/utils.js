/* ═══════════════════════════════════════════════════
   utils.js — v4 (Security-Hardened)

   Änderungen:
   - B64.enc: Chunked btoa (verhindert Stack-Overflow bei großen Arrays)
   - ctEqual: Constant-Time-Vergleich (kein Timing-Leak)
   - burn: Überschreibt Uint8Arrays mit Zufallsdaten + Nullen
   - jitter: Kryptographisch besserer Jitter via nacl.randomBytes
   - makeAnonId: 32 Byte statt 20 (mehr Entropie)
   - Store: Kein localStorage für sensible Daten (nur Room-Name)
   ═══════════════════════════════════════════════════ */

const $ = id => document.getElementById(id);

// ── Base64 ────────────────────────────────────────
// Chunked, um Stack-Overflows bei großen Uint8Arrays zu verhindern.

const B64 = {
  enc(u) {
    let s = '';
    const chunk = 4096;
    for (let i = 0; i < u.length; i += chunk) {
      s += String.fromCharCode(...u.subarray(i, i + chunk));
    }
    return btoa(s);
  },
  dec(s) {
    const b = atob(s);
    const a = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
    return a;
  }
};

// ── TextEncoder/Decoder ───────────────────────────

const U8 = {
  enc: t => new TextEncoder().encode(t),
  dec: u => new TextDecoder().decode(u)
};

// ── Constant-Time-Vergleich ───────────────────────
// Verhindert Timing-Angriffe beim Vergleichen von Hashes/Keys.
// Läuft immer in gleicher Zeit unabhängig davon wo der erste
// Unterschied auftritt.

function ctEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ── Memory Wipe ───────────────────────────────────
// Überschreibt sensible Uint8Arrays zweifach: erst mit
// Zufallsdaten (verhindert Compiler-Optimierung), dann mit 0.

function burn(...arrays) {
  for (const a of arrays) {
    if (a instanceof Uint8Array) {
      try { a.set(nacl.randomBytes(a.length)); } catch {}
      a.fill(0);
    }
  }
}

// ── Anonyme ID ───────────────────────────────────
// 32 Byte = 256 Bit Entropie (statt vorher 160 Bit)

const makeAnonId = () => {
  const b = nacl.randomBytes(32);
  return 'x' + Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
};

// ── Kryptographischer Jitter ──────────────────────
// Verwendet nacl.randomBytes für echte Zufälligkeit.
// Verhindert Traffic-Timing-Korrelation.

function jitter(min, max) {
  const range = max - min;
  const rand  = nacl.randomBytes(4);
  const val   = new DataView(rand.buffer).getUint32(0, false);
  const delay = min + (val / 0xFFFFFFFF) * range;
  return new Promise(r => setTimeout(r, delay));
}

// ── HTML-Escape ───────────────────────────────────

const esc = s => {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
};

// ── Storage ───────────────────────────────────────
// NUR für nicht-sensible Daten (Room-Name, UI-Präferenzen).
// NIEMALS für Keys, Secrets oder Nachrichten verwenden.

const Store = {
  get(key, fallback = null) {
    try { return localStorage.getItem('kc_' + key) ?? fallback; }
    catch { return fallback; }
  },
  set(key, val) {
    try { localStorage.setItem('kc_' + key, val); } catch {}
  },
  del(key) {
    try { localStorage.removeItem('kc_' + key); } catch {}
  }
};
