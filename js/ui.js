/* ═══════════════════════════════════════════
   ui.js — DOM-Interaktion & Anzeige
   ═══════════════════════════════════════════ */

const UI = (() => {

  let logVisible = false;

  // ── Log ──
  function log(msg, cls) {
    const el = $('log');
    if (!el) return;
    const d = document.createElement('div');
    d.className = 'lo ' + (cls || '');
    d.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    el.appendChild(d);
    el.scrollTop = el.scrollHeight;
  }

  function initLogToggle() {
    const btn = $('toglog');
    const el = $('log');
    if (!btn || !el) return;
    el.style.display = 'none';
    btn.addEventListener('click', () => {
      logVisible = !logVisible;
      el.style.display = logVisible ? 'block' : 'none';
      btn.textContent = logVisible ? 'LOG ✕' : 'LOG';
    });
  }

  // ── Join-Status ──
  function setJoinStatus(text) {
    const el = $('jst');
    if (el) el.textContent = text;
  }

  function setJoinDisabled(disabled) {
    const btn = $('jbtn');
    const inp = $('rin');
    if (btn) btn.disabled = disabled;
    if (inp) inp.disabled = disabled;
  }

  function showRoom(name) {
    const overlay = $('ov');
    const app = $('app');
    const drm = $('drm');
    const ct = $('ct');
    if (overlay) overlay.style.display = 'none';
    if (app) app.style.display = 'grid';
    if (drm) drm.textContent = name;
    if (ct) ct.textContent = name;
    const inp = $('min');
    if (inp) { inp.disabled = false; inp.placeholder = 'Nachricht schreiben...'; }
    const btn = $('sbtn');
    if (btn) btn.disabled = false;
  }

  // ── System-Nachricht ──
  function addSystem(text, important) {
    const container = $('mc');
    if (!container) return;
    const es = $('es');
    if (es) es.remove();

    const d = document.createElement('div');
    d.className = 'sy' + (important ? ' im' : '');
    d.textContent = text;
    container.appendChild(d);
    container.scrollTop = container.scrollHeight;
  }

  // ── Chat-Nachricht ──
  function addMessage(peerId, text, isMine) {
    const container = $('mc');
    if (!container) return;
    const es = $('es');
    if (es) es.remove();

    const wrap = document.createElement('div');
    wrap.className = 'mg' + (isMine ? ' me' : '');

    const sender = document.createElement('div');
    sender.className = 'mg-s';
    sender.textContent = isMine ? 'Du' : peerId;

    const body = document.createElement('div');
    body.className = 'mg-b';
    body.textContent = text;

    const time = document.createElement('div');
    time.className = 'mg-t';
    time.textContent = new Date().toLocaleTimeString();

    wrap.appendChild(sender);
    wrap.appendChild(body);
    wrap.appendChild(time);
    container.appendChild(wrap);
    container.scrollTop = container.scrollHeight;
  }

  // ── Peers (dein Code, in UI-Objekt eingebaut) ──
  function updatePeers(sessionsMap) {
    const pl = $('pl');
    if (!pl) return;

    if (sessionsMap.size === 0) {
      pl.innerHTML = '<li style="font-family:var(--fm);font-size:10px;color:var(--t3)">Warte...</li>';
      const onc = $('onc');
      const est = $('est');
      if (onc) onc.textContent = '1';
      if (est) { est.textContent = 'Getrennt'; est.style.color = 'var(--am)'; }
      return;
    }

    const onc = $('onc');
    const est = $('est');
    if (onc) onc.textContent = sessionsMap.size + 1;
    if (est) { est.textContent = sessionsMap.size + ' Peer(s)'; est.style.color = 'var(--gn)'; }

    pl.innerHTML = '';
    sessionsMap.forEach((s, id) => {
      const li = document.createElement('li');
      li.className = 'p-i';

      let statusDot = 'sd';
      let statusText = '?';
      let btnClass = 'bv';
      if (s.verified) {
        statusDot = 'sd';
        statusText = '✓';
        btnClass = 'bv ok';
      } else if (s.established) {
        statusDot = 'sd w';
        statusText = '⚠';
      } else {
        statusDot = 'sd w';
        statusText = '?';
      }

      li.innerHTML = `
        <div class="p-inf">
          <div class="${statusDot}"></div>
          <span class="p-nm">${id}</span>
        </div>
        <
