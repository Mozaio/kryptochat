const Session = (function() {
  var ROTATE_AFTER = 50;
  var sessions = new Map();
  var _myLongTermPubKey = null;

  function setMyLongTermKey(pubKey) {
    _myLongTermPubKey = pubKey;
  }

  function createSession(peerId, theirPubKey) {
    var ephemeral = nacl.box.keyPair();
    var session = {
      peerId: peerId,
      theirPubKey: theirPubKey,
      myEphemeral: ephemeral,
      theirEphemeralPub: null,
      sharedSecret: null,
      sendNonce: BigInt(0),
      recvNonces: new Set(),
      msgCount: 0,
      verified: false,
      established: false,
      createdAt: Date.now()
    };
    sessions.set(peerId, session);
    return session;
  }

  function getSession(peerId) {
    return sessions.get(peerId);
  }

  function removeSession(peerId) {
    var s = sessions.get(peerId);
    if (s) {
      if (s.sharedSecret) s.sharedSecret.fill(0);
      if (s.myEphemeral && s.myEphemeral.secretKey) {
        s.myEphemeral.secretKey.fill(0);
      }
      sessions.delete(peerId);
    }
  }

  function computeSharedSecret(peerId) {
    var session = sessions.get(peerId);
    if (!session || !session.theirEphemeralPub || !session.myEphemeral) return Promise.resolve(false);
    if (!_myLongTermPubKey) return Promise.resolve(false);

    var ephemeralShared = nacl.box.before(
      session.theirEphemeralPub,
      session.myEphemeral.secretKey
    );

    var lt1, lt2;
    var cmp = false;
    for (var i = 0; i < 32; i++) {
      if (_myLongTermPubKey[i] < session.theirPubKey[i]) { cmp = true; break; }
      if (_myLongTermPubKey[i] > session.theirPubKey[i]) { cmp = false; break; }
    }
    if (cmp) {
      lt1 = _myLongTermPubKey;
      lt2 = session.theirPubKey;
    } else {
      lt1 = session.theirPubKey;
      lt2 = _myLongTermPubKey;
    }

    var combined = new Uint8Array(96);
    combined.set(ephemeralShared, 0);
    combined.set(lt1, 32);
    combined.set(lt2, 64);

    return crypto.subtle.digest('SHA-512', combined).then(function(hashBuf) {
      var fullHash = new Uint8Array(hashBuf);
      session.sharedSecret = fullHash.slice(0, 32);
      session.established = true;
      combined.fill(0);
      ephemeralShared.fill(0);
      return true;
    });
  }

  function needsRotation(peerId) {
    var s = sessions.get(peerId);
    return s && s.msgCount >= ROTATE_AFTER;
  }

  function rotate(peerId) {
    var s = sessions.get(peerId);
    if (!s) return null;
    var theirPubKey = s.theirPubKey;
    removeSession(peerId);
    return createSession(peerId, theirPubKey);
  }

  function getAll() {
    return sessions;
  }

  return {
    setMyLongTermKey: setMyLongTermKey,
    createSession: createSession,
    getSession: getSession,
    removeSession: removeSession,
    computeSharedSecret: computeSharedSecret,
    needsRotation: needsRotation,
    rotate: rotate,
    getAll: getAll
  };
})();
