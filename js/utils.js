/* ═══════════════════════════════════════════
   utils.js — DOM, Encoding, Helpers
   ═══════════════════════════════════════════ */

const $ = id => document.getElementById(id);

const B64 = {
  enc: u => btoa(String.fromCharCode(...u)),
  dec: s => {
    const b = atob(s);
    const a = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
    return a;
  }
};

const U8 = {
  enc: t => new TextEncoder().encode(t),
  dec: u => new TextDecoder().decode(u)
};

// Anonyme, ephemere ID
const makeAnonId = () => {
  const b = nacl.randomBytes(20);
  return 'x' + Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
};

// Zufälliges Delay gegen Timing-Analyse
const jitter = (min, max) => new Promise(r =>
  setTimeout(r, min + Math.random() * (max - min))
);

// HTML-Escaping
const esc = s => {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
};

// Sicheres Löschen von Uint8Arrays
function burn(...arrays) {
  arrays.forEach(a => {
    if (a && a instanceof Uint8Array) {
      const rand = nacl.randomBytes(a.length);
      a.set(rand);
      a.fill(0);
    }
  });
}

// Persistenz-Helper
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
