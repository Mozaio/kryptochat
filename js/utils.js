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

// Anonyme ID — zufällig, nicht an Person gebunden
const anonId = () => {
  const b = nacl.randomBytes(16);
  return 'a' + Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
};

const esc = s => {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
};
