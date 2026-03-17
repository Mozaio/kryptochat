/* utils.js — v5 */
const $ = id => document.getElementById(id);

const B64 = {
  enc(u) {
    let s = '';
    for (let i = 0; i < u.length; i += 4096)
      s += String.fromCharCode(...u.subarray(i, Math.min(i + 4096, u.length)));
    return btoa(s);
  },
  dec(s) {
    const b = atob(s); const a = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
    return a;
  }
};

const U8 = {
  enc: t => new TextEncoder().encode(t),
  dec: u => new TextDecoder().decode(u)
};

// Constant-Time-Vergleich — kein Timing-Leak
function ctEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// Sicheres Löschen — erst Zufallsdaten, dann Nullen
function burn(...arrays) {
  for (const a of arrays) {
    if (a instanceof Uint8Array) {
      try { a.set(nacl.randomBytes(a.length)); } catch {}
      a.fill(0);
    }
  }
}

// Kryptographischer Jitter via nacl.randomBytes
function jitter(min, max) {
  const range = max - min;
  const rand  = nacl.randomBytes(4);
  const val   = new DataView(rand.buffer).getUint32(0, false);
  return new Promise(r => setTimeout(r, min + (val / 0xFFFFFFFF) * range));
}

// 32 Byte = 256 Bit Entropie
const makeAnonId = () => {
  const b = nacl.randomBytes(32);
  return 'x' + Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
};

const esc = s => { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; };

// Nur für nicht-sensible Daten (Room-Name, UI-Prefs)
const Store = {
  get(key, fallback = null) { try { return localStorage.getItem('kc_' + key) ?? fallback; } catch { return fallback; } },
  set(key, val) { try { localStorage.setItem('kc_' + key, val); } catch {} },
  del(key) { try { localStorage.removeItem('kc_' + key); } catch {} }
};
