/* ═══════════════════════════════════════════
   ui.js — DOM-Manipulation & Rendering
   ═══════════════════════════════════════════ */

const UI = (() => {

  // ── Debug Log ──
  function log(msg, cls) {
    const logEl = $('log');
    const t = new Date().toLocaleTimeString('de-DE');
    const d = document.createElement('div');
    d.className = cls || '';
    d.textContent = `[${t}] ${msg}`;
    logEl.appendChild(d);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function initLogToggle() {
    $('toglog').addEventListener('click', () => $('log').classList.toggle('show'));
  }

  // ── Scroll ──
  function scrollToBottom() {
    const mc = $('mc');
    requestAnimationFrame(() => { mc.scrollTop = mc.scrollHeight; });
  }

  // ── Messages ──
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

  // ── Peers ──
  function updatePeers(peersMap, myPubKey) {
    const pl = $('pl');

    if (peersMap.size === 0) {
      pl.innerHTML = '<li style="font-family:var(--fm);font-size:10px;color:var(--t3)">Warte...</li>';
      $('onc').textContent = '1';
      $('est').textContent = 'Getrennt';
      $('est').style.color = 'var(--am)';
      return;
    }

    $('onc').textContent = peersMap.size + 1;
    $('est').textContent = peersMap.size + ' Peer(s)';
    $('est').style.color = 'var(--gn)';

    pl.innerHTML = '';
    peersMap.forEach((p, id) => {
      const li = document.createElement('li');
      li.className = 'p-i';
      li.innerHTML = `
        <div class="p-inf">
          <div class="sd ${p.verified ? '' : 'w'}"></div>
          <span class="p-nm">${id}</span>
        </div>
        <button class="bv ${p.verified ? 'ok' : ''}" data-p="${id}">
          ${p.verified ? '✓' : '?'}
        </button>
      `;
      pl.appendChild(li);
    });
  }

  // ── Fingerprint Modal ──
  function showFingerprint(myPubKey, peerPubKey, peerId) {
    $('mfp').textContent = Crypto.fingerprint(myPubKey);
    $('pfp').textContent = Crypto.fingerprint(peerPubKey);
    $('fpm').dataset.peer = peerId;
    $('fpm').classList.add('v');
  }

  function hideFingerprint() {
    $('fpm').classList.remove('v');
  }

  // ── Stats ──
  function updateStats(count) {
    $('sm').textContent = count;
  }

  // ── Room Joined ──
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

  // ── Join Button ──
  function setJoinStatus(text) {
    $('jst').textContent = text;
  }

  function setJoinDisabled(disabled) {
    $('jbtn').disabled = disabled;
  }

  return {
    log, initLogToggle, scrollToBottom,
    addMessage, addSystem,
    updatePeers, showFingerprint, hideFingerprint,
    updateStats, showRoom,
    setJoinStatus, setJoinDisabled
  };
})();
