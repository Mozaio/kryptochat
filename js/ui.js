// In der updatePeers-Funktion die alte Referenz ersetzen:
// Alt:  peersMap (Map mit { pubKey, verified, nonces })
// Neu:  sessions (Map mit Session-Objekten aus session.js)

function updatePeers(sessionsMap) {
  const pl = $('pl');

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

    // Status-Indikator
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
      <button class="${btnClass}" data-p="${id}">${statusText}</button>
    `;
    pl.appendChild(li);
  });
}
