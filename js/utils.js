/* ═══════════════════════════════════════════
   utils.js — DOM, Encoding, Helpers
   ═══════════════════════════════════════════ */

const $ = id => document.getElementById(id);

// ── Base64 ──
const B64 = {
  enc: u => btoa(String.fromCharCode(...u)),
  dec: s => {
    const b = atob(s);
    const a = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
    return a;
  }
};

// ── Text Encoding ──
const U8 = {
  enc: t => new TextEncoder().encode(t),
  dec: u => new TextDecoder().decode(u)
};

// ── Random ID ──
const uid = () => {
  const b = nacl.randomBytes(6);
  return Array.from(b).map(x => x.toString(36)).join('').substring(0, 8);
};

// ── HTML Escape ──
const esc = s => {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
};
