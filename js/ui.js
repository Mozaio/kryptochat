/* ui.js — v5
   Neu: updateTranscript(), showSessionFingerprint()
*/
const UI = (() => {

  function log(msg, cls) {
    const el = $('log'); if (!el) return;
    const d = document.createElement('div');
    d.className = cls || '';
    d.textContent = `[${new Date().toLocaleTimeString('de-DE')}] ${msg}`;
    el.appendChild(d); el.scrollTop = el.scrollHeight;
  }

  function initLogToggle() {
    const btn = $('toglog');
    if (btn) btn.addEventListener('click', () => $('log').classList.toggle('show'));
  }

  function scrollToBottom() {
    const mc = $('mc');
    if (mc) requestAnimationFrame(() => { mc.scrollTop = mc.scrollHeight; });
  }

  function shortId(id) { return id.slice(0, 8) + '..'; }

  function addMessage(senderId, text, isOutgoing) {
    const es = $('es'); if (es) es.remove();
    const g = document.createElement('div');
    g.className = `mg ${isOutgoing ? 'out' : 'in'}`;
    const t = new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
    g.innerHTML = `
      ${!isOutgoing ? `<div class="ms">${esc(shortId(senderId))}</div>` : ''}
      <div class="mb">${esc(text)}</div>
      <div class="mm"><span class="mt">${t}</span></div>
    `;
    $('mc').appendChild(g);
    scrollToBottom();
  }

  function addSystem(text, highlight) {
    const d = document.createElement('div');
    d.className = `mg sys ${highlight ? 'h' : ''}`;
    d.innerHTML = `<span>${esc(text)}</span>`;
    $('mc').appendChild(d);
    scrollToBottom();
  }

  // Transcript-Hash im UI anzeigen (Manipulation erkennbar)
  function updateTranscript(hash) {
    const el = $('transcript-hash');
    if (el) el.textContent = hash;
  }

  function updatePeers(sessionsMap) {
    const pl = $('pl'); if (!pl) return;
    if (sessionsMap.size === 0) {
      pl.innerHTML = '<li style="font-family:var(--fm);font-size:10px;color:var(--t3)">Warte...</li>';
      $('onc').textContent = '1';
      $('est').textContent = 'Getrennt'; $('est').style.color = 'var(--am)';
      return;
    }
    $('onc').textContent = sessionsMap.size + 1;
    $('est').textContent = `${sessionsMap.size} Peer${sessionsMap.size > 1 ? 's' : ''}`;
    $('est').style.color = 'var(--gn)';
    pl.innerHTML = '';
    sessionsMap.forEach((s, id) => {
      const li = document.createElement('li');
      li.className = 'p-i';
      li.innerHTML = `
        <div class="p-inf"><div class="${s.verified ? 'sd' : 'sd w'}"></div><span class="p-nm">${esc(shortId(id))}</span></div>
        <button class="${s.verified ? 'bv ok' : 'bv'}" data-p="${esc(id)}">${s.verified ? '✓' : (s.established ? '⚠' : '?')}</button>
      `;
      pl.appendChild(li);
    });
  }

  function showSessionFingerprint(fp, peerId) {
    $('mfp').textContent = fp;
    $('pfp').textContent = fp;
    const labels = document.querySelectorAll('.fp-b label');
    if (labels[0]) labels[0].textContent = 'Session-Fingerprint (deine Seite)';
    if (labels[1]) labels[1].textContent = 'Session-Fingerprint (Peer-Seite)';
    $('fpm').dataset.peer = peerId;
    $('fpm').classList.add('v');
  }

  function showFingerprint(myPubKey, peerPubKey, peerId) {
    $('mfp').textContent = KCrypto.fingerprintKey(myPubKey);
    $('pfp').textContent = KCrypto.fingerprintKey(peerPubKey);
    const labels = document.querySelectorAll('.fp-b label');
    if (labels[0]) labels[0].textContent = 'Dein Fingerabdruck';
    if (labels[1]) labels[1].textContent = 'Peer Fingerabdruck';
    $('fpm').dataset.peer = peerId;
    $('fpm').classList.add('v');
  }

  function hideFingerprint() { $('fpm').classList.remove('v'); }

  function showRoom(roomName) {
    $('ov').classList.add('h'); $('app').classList.add('v');
    $('drm').textContent = roomName; $('ct').textContent = '#' + roomName;
    $('min').disabled = false; $('sbtn').disabled = false;
    $('min').focus();
    $('est').textContent = 'Verbunden'; $('est').style.color = 'var(--gn)';
  }

  function setJoinStatus(text)     { const el = $('jst'); if (el) el.textContent = text; }
  function setJoinDisabled(disabled) { const el = $('jbtn'); if (el) el.disabled = disabled; }

  return {
    log, initLogToggle, scrollToBottom,
    addMessage, addSystem,
    updateTranscript,
    updatePeers, showSessionFingerprint, showFingerprint, hideFingerprint,
    showRoom, setJoinStatus, setJoinDisabled
  };
})();
