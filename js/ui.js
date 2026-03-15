/* ═══════════════════════════════════════════
   ui.js — DOM-Manipulation & Rendering
   ═══════════════════════════════════════════ */

const UI = (() => {

  function log(msg, cls) {
    const logEl = $('log');
    if (!logEl) return;
    const t = new Date().toLocaleTimeString('de-DE');
    const d = document.createElement('div');
    d.className = cls || '';
    d.textContent = `[${t}] ${msg}`;
    logEl.appendChild(d);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function initLogToggle() {
    const btn = $('toglog');
    if (btn) btn.addEventListener('click', () => $('log').classList.toggle('show'));
  }

  function scrollToBottom() {
    const mc = $('mc');
    if (mc) requestAnimationFrame(() => { mc.scrollTop = mc.scrollHeight; });
  }

  function addMessage(sender, text, isOutgoing) {
    const es = $('es');
    if (es) es.remove();

    const g = document.createElement('div');
    g.className = `mg ${isOutgoing ? 'out' : 'in'}`;
    const t = new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });

    g.innerHTML = `
      ${!isOutgoing ? `<div class="ms">${esc(sender)}</div>` : ''}
      <div class="mb">${esc(text)}</div>
      <div class="mm"><span class="mt">${t}</span></div>
    `;

    $('mc').appendChild(g);
    scrollToBottom();
  }

  function addSystem(text, highlight) {
    const d = document.createElement('div');
    d.className = `mg sys ${highlight ? 'h' : ''}`;
    d.innerHTML = `<span>${text}</span>`;
    $('mc').appendChild(d);
    scrollToBottom();
  }

  function updatePeers(sessionsMap) {
    const pl = $('pl');
    if (!pl) return;

    if (sessionsMap.size === 0) {
      pl.innerHTML = '<li style="font-family:var(--fm);font-size:10px;color:var(--t3)">Warte...</li>';
      $('onc').textContent = '1';
      $('est').textContent = 'Getrennt';
      $('est').style.color = 'var(--am)';
      return;
    }

    $('onc').textContent = sessionsMap.size + 1;
    $('est').textContent = sessionsMap.size + ' Peer(s)';
    $('est').style.color = 'var(--gn)';

    pl.innerHTML = '';
    sessionsMap.forEach((s, id) => {
      const li = document.createElement('li');
      li.className = 'p-i';

      let dotClass = s.verified ? 'sd' : 'sd w';
      let btnLabel = s.verified ? '✓' : (s.established ? '⚠' : '?');
      let btnClass = s.verified ? 'bv ok' : 'bv';

      li.innerHTML = `
        <div class="p-inf">
          <div class="${dotClass}"></div>
          <span class="p-nm">${id}</span>
        </div>
        <button class="${btnClass}" data-p="${id}">${btnLabel}</button>
      `;
      pl.appendChild(li);
    });
  }

  function showFingerprint(myPubKey, peerPubKey, peerId) {
    $('mfp').textContent = Crypto.fingerprint(myPubKey);
    $('pfp').textContent = Crypto.fingerprint(peerPubKey);
    $('fpm').dataset.peer = peerId;
    $('fpm').classList.add('v');
  }

  function hideFingerprint() {
    $('fpm').classList.remove('v');
  }

  function updateStats(count) {
    $('sm').textContent = count;
  }

  function showRoom(roomName) {
    $('ov').classList.add('h');
    $('app').classList.add('v');
    $('drm').textContent = roomName;
    $('ct').textContent = '#' + roomName;
    $('min').disabled = false;
    $('sbtn').disabled = false;
    $('min').focus();
    $('est').textContent = 'Verbunden';
    $('est').style.color = 'var(--gn)';
  }

  function setJoinStatus(text) {
    const el = $('jst');
    if (el) el.textContent = text;
  }

  function setJoinDisabled(disabled) {
    const el = $('jbtn');
    if (el) el.disabled = disabled;
  }

  return {
    log, initLogToggle, scrollToBottom,
    addMessage, addSystem,
    updatePeers, showFingerprint, hideFingerprint,
    updateStats, showRoom,
    setJoinStatus, setJoinDisabled
  };
})();
