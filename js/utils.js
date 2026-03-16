/* ═══════════════════════════════════════════
   utils.js
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

const makeAnonId = () => {
  const b = nacl.randomBytes(20);
  return 'x' + Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
};

const jitter = (min, max) => new Promise(r =>
  setTimeout(r, min + Math.random() * (max - min))
);

const esc = s => {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
};

function burn(...arrays) {
  arrays.forEach(a => {
    if (a && a instanceof Uint8Array) {
      a.set(nacl.randomBytes(a.length));
      a.fill(0);
    }
  });
}

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
