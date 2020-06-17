"use strict";

function Encryption(cryptic) {
  if (!cryptic) {
    throw "An instance of Starbase Cryptic is require.";
  }

  async function createUser() {
    return cryptic.createECDH();
  }

  async function createSession(user, card) {
    let epk = await cryptic.createECDH();
    let dh1 = await cryptic.ecdh(user.key, card.opk);
    let dh2 = await cryptic.ecdh(epk.key, card.user);
    let dh3 = await cryptic.ecdh(epk.key, card.opk);
    let combined = cryptic.combine(
      cryptic.combine(cryptic.decode(dh1), cryptic.decode(dh2)),
      cryptic.decode(dh3)
    );
    let sk = await cryptic.kdf(
      combined,
      new Uint8Array(32),
      cryptic.fromText("SESSION"),
      256
    );
    let AD = cryptic.encode(
      cryptic.combine(cryptic.decode(user.pub), cryptic.decode(card.user))
    );
    let init = {
      type: "init",
      to: card.user,
      from: user.pub,
      epk: epk.pub,
      opk: card.opk,
    };
    return { type: "session", user: card.user, sk, AD, init };
  }

  async function openSession(user, opk, init) {
    let dh1 = await cryptic.ecdh(opk.key, init.from);
    let dh2 = await cryptic.ecdh(user.key, init.epk);
    let dh3 = await cryptic.ecdh(opk.key, init.epk);
    let combined = cryptic.combine(
      cryptic.combine(cryptic.decode(dh1), cryptic.decode(dh2)),
      cryptic.decode(dh3)
    );
    let sk = await cryptic.kdf(
      combined,
      new Uint8Array(32),
      cryptic.fromText("SESSION"),
      256
    );
    let AD = cryptic.encode(
      cryptic.combine(cryptic.decode(init.from), cryptic.decode(user.pub))
    );
    return { type: "session", user: init.from, sk, AD };
  }

  async function rootKDF(rk, dh) {
    let ratchet = await cryptic.kdf(
      cryptic.decode(dh),
      cryptic.decode(rk),
      cryptic.fromText("ROOT"),
      512
    );
    let RK = cryptic.encode(cryptic.decode(ratchet).slice(0, 32));
    let CK = cryptic.encode(cryptic.decode(ratchet).slice(32));
    return [RK, CK];
  }

  async function chainKDF(ck) {
    let mk = await cryptic.hmacSign(cryptic.decode(ck), "\x01");
    let CK = await cryptic.hmacSign(cryptic.decode(ck), "\x02");
    return [CK, mk];
  }

  async function createInitRatchet(session) {
    let state = {};
    state.DHs = await cryptic.createECDH();
    state.DHr = session.init.opk;
    let dh = await cryptic.ecdh(state.DHs.key, state.DHr);
    [state.RK, state.CKs] = await rootKDF(session.sk, dh);
    state.CKr = null;
    state.Ns = 0;
    state.Nr = 0;
    state.PN = 0;
    state.MKSKIPPED = {};
    return state;
  }

  async function openInitRatchet(session, opk) {
    let state = {};
    state.DHs = opk;
    state.DHr = null;
    state.RK = session.sk;
    state.CKs = null;
    state.CKr = null;
    state.Ns = 0;
    state.Nr = 0;
    state.PN = 0;
    state.MKSKIPPED = {};
    return state;
  }

  async function trySkippedMessageKeys(state, header, ciphertext, AEAD) {
    if (state.MKSKIPPED[header.dh] && state.MKSKIPPED[header.dh][header.n]) {
      let mk = state.MKSKIPPED[header.dh][header.n];
      let KEY = await cryptic.kdf(
        cryptic.combine(
          cryptic.decode(mk),
          cryptic.fromText(JSON.stringify(header))
        ),
        new Uint8Array(32),
        cryptic.fromText("ENCRYPT"),
        256
      );
      let plaintext = await cryptic
        .decrypt(ciphertext, cryptic.decode(KEY), cryptic.decode(AEAD))
        .catch((err) => {
          return null;
        });
      if (plaintext) {
        delete state.MKSKIPPED[header.dh][header.n];
        return { header: header, plaintext: plaintext };
      } else {
        return null;
      }
    }
  }

  async function skipMessageKeys(state, until, maxSkip) {
    if (state.Nr + maxSkip < until) {
      return Promise.reject({
        message: "Too many skipped messages!",
      });
    }
    if (state.CKr) {
      while (state.Nr < until) {
        let mk = null;
        [state.CKr, mk] = await chainKDF(state.CKr);
        if (!state.MKSKIPPED[state.DHr]) {
          state.MKSKIPPED[state.DHr] = {};
        }
        state.MKSKIPPED[state.DHr][state.Nr] = mk;
        state.Nr += 1;
      }
    }
  }

  async function DHRatchet(state, header) {
    state.PN = state.Ns;
    state.Ns = 0;
    state.Nr = 0;
    state.DHr = header.dh;
    let dh1 = await cryptic.ecdh(state.DHs.key, state.DHr);
    [state.RK, state.CKr] = await rootKDF(state.RK, dh1);
    state.DHs = await cryptic.createECDH();
    let dh2 = await cryptic.ecdh(state.DHs.key, state.DHr);
    [state.RK, state.CKs] = await rootKDF(state.RK, dh2);
    return true;
  }

  async function ratchetEncrypt(state, msg, AD, init) {
    let mk = null;
    [state.CKs, mk] = await chainKDF(state.CKs, state);
    let header = {
      dh: state.DHs.pub,
      pn: state.PN,
      n: state.Ns,
    };
    state.Ns += 1;
    let AEAD = await cryptic.kdf(
      cryptic.combine(
        cryptic.decode(AD),
        cryptic.fromText(JSON.stringify(header))
      ),
      new Uint8Array(32),
      cryptic.fromText("AEAD"),
      256
    );
    let KEY = await cryptic.kdf(
      cryptic.combine(
        cryptic.decode(mk),
        cryptic.fromText(JSON.stringify(header))
      ),
      new Uint8Array(32),
      cryptic.fromText("ENCRYPT"),
      256
    );
    let encrypted = {
      header,
      ciphertext: await cryptic.encrypt(
        JSON.stringify(msg),
        cryptic.decode(KEY),
        cryptic.decode(AEAD)
      ),
    };
    if (init) {
      encrypted.init = cloneState(init);
    }
    return encrypted;
  }

  async function ratchetDecrypt(state, msgPayload = {}, AD, maxSkip = 10) {
    let { header, ciphertext } = msgPayload;
    let AEAD = await cryptic.kdf(
      cryptic.combine(
        cryptic.decode(AD),
        cryptic.fromText(JSON.stringify(header))
      ),
      new Uint8Array(32),
      cryptic.fromText("AEAD"),
      256
    );
    let found = await trySkippedMessageKeys(
      state,
      header,
      ciphertext,
      AEAD || null
    );
    if (found) {
      return found;
    }
    if (header.dh !== state.DHr) {
      await skipMessageKeys(state, header.pn, maxSkip);
      await DHRatchet(state, header);
    }
    await skipMessageKeys(state, header.n, maxSkip);
    let mk = null;
    [state.CKr, mk] = await chainKDF(state.CKr);
    state.Nr += 1;
    let KEY = await cryptic.kdf(
      cryptic.combine(
        cryptic.decode(mk),
        cryptic.fromText(JSON.stringify(header))
      ),
      new Uint8Array(32),
      cryptic.fromText("ENCRYPT"),
      256
    );
    let plaintext = await cryptic
      .decrypt(ciphertext, cryptic.decode(KEY), cryptic.decode(AEAD))
      .catch((err) => {
        throw {
          error: "failed to decrypt",
        };
      });
    delete state.init;
    return {
      header,
      plaintext: JSON.parse(plaintext),
    };
  }

  function cloneState(src) {
    let target = {};
    if (typeof src === "string") {
      target = src.toString();
      return target;
    }
    if (src instanceof Array) {
      target = [];
    }
    for (let prop in src) {
      if (src[prop] && typeof src[prop] === "object") {
        target[prop] = cloneState(src[prop]);
      } else {
        target[prop] = src[prop];
      }
    }
    return target;
  }

  async function sealEnvelope(user, to, message) {
    let ek = await cryptic.createECDH();
    let dh1 = await cryptic.ecdh(ek.key, to);
    let sbits = await cryptic.kdf(
      cryptic.decode(dh1),
      new Uint8Array(32),
      cryptic.fromText("SEAL"),
      512
    );
    let sealkey = cryptic.decode(sbits).slice(0, 32);
    let chainkey = cryptic.decode(sbits).slice(32, 64);
    let sealAD = cryptic.combine(cryptic.decode(ek.pub), cryptic.decode(to));
    let seal = await cryptic.encrypt(user.pub, sealkey, sealAD);
    let dh2 = await cryptic.ecdh(user.key, to);
    let mbits = await cryptic.kdf(
      cryptic.decode(dh2),
      chainkey,
      cryptic.fromText("MESSAGE"),
      256
    );
    let msgkey = cryptic.decode(mbits);
    let msgAD = cryptic.combine(cryptic.decode(user.pub), cryptic.decode(to));
    let ciphertext = await cryptic.encrypt(
      JSON.stringify(message),
      msgkey,
      msgAD
    );
    return {
      type: "envelope",
      to: to,
      ek: ek.pub,
      seal: seal,
      ciphertext: ciphertext,
    };
  }

  async function openEnvelope(user, envelope) {
    let dh1 = await cryptic.ecdh(user.key, envelope.ek);
    let sbits = await cryptic.kdf(
      cryptic.decode(dh1),
      new Uint8Array(32),
      cryptic.fromText("SEAL"),
      512
    );
    let sealkey = cryptic.decode(sbits).slice(0, 32);
    let chainkey = cryptic.decode(sbits).slice(32, 64);
    let sealAD = cryptic.combine(
      cryptic.decode(envelope.ek),
      cryptic.decode(user.pub)
    );
    let from = await cryptic.decrypt(envelope.seal, sealkey, sealAD);
    let dh2 = await cryptic.ecdh(user.key, from);
    let mbits = await cryptic.kdf(
      cryptic.decode(dh2),
      chainkey,
      cryptic.fromText("MESSAGE"),
      256
    );
    let msgkey = cryptic.decode(mbits);
    let msgAD = cryptic.combine(cryptic.decode(from), cryptic.decode(user.pub));
    let decrypted = await cryptic.decrypt(envelope.ciphertext, msgkey, msgAD);
    return {
      type: "envelope",
      to: envelope.to,
      from: from,
      plaintext: JSON.parse(decrypted),
    };
  }

  function Session(sessionData) {
    let sessionState = cloneState(sessionData);
    let session = {};

    session.to = () => {
      return cloneState(sessionData).user;
    };

    session.send = async (message) => {
      let state = cloneState(sessionState.state);
      let payload = await ratchetEncrypt(
        state,
        message,
        sessionState.AD || null,
        sessionState.init || null
      );
      payload.to = sessionData.user.toString();
      sessionState.state = cloneState(state);
      return payload;
    };

    session.read = async (payload) => {
      let state = cloneState(sessionState.state);
      let decrypted = await ratchetDecrypt(
        state,
        payload,
        sessionState.AD || null
      );
      if (sessionState.init) {
        delete sessionState.init;
      }
      let msg = {
        header: payload.header,
        plaintext: decrypted.plaintext,
        from: session.to(),
      };
      sessionState.state = cloneState(state);
      return msg;
    };

    session.save = () => {
      let backup = {
        state: cloneState(sessionState.state),
      };
      if (sessionState.init) {
        backup.init = cloneState(sessionState.init);
      }
      if (sessionState.user) {
        backup.user = cloneState(sessionState.user);
      }
      if (sessionState.AD) {
        backup.AD = cloneState(sessionState.AD);
      }
      return backup;
    };

    return session;
  }

  function User(userData) {
    let userState = cloneState(userData);
    let user = {};

    let useUser = () => {
      return userState;
    };

    user.createOPK = async () => {
      let secret = await cryptic.createECDH();
      let card = { user: userState.pub, opk: secret.pub };
      return { card, secret };
    };

    user.sealEnvelope = async (to, msg) => {
      return sealEnvelope(useUser(), to, msg);
    };

    user.openEnvelope = async (env) => {
      return openEnvelope(useUser(), env);
    };

    user.createSession = async (card) => {
      let session = await createSession(useUser(), card);
      session.state = await createInitRatchet(session);
      delete session.sk;
      return Session(session);
    };

    user.openSession = async (init, secretOPK) => {
      let session = await openSession(useUser(), secretOPK, init);
      session.state = await openInitRatchet(session, secretOPK);
      delete session.sk;
      return Session(session);
    };

    user.loadSession = async (session) => {
      return Session(session);
    };

    user.save = () => {
      return cloneState(userState);
    };

    user.getID = () => {
      return cloneState(userState).pub;
    };

    return user;
  }

  let cynops = {};

  cynops.cloneState = cloneState;
  cynops.cryptic = cryptic;

  cynops.createUser = async () => {
    let userData = await createUser();
    return User(userData);
  };

  cynops.loadUser = async (userData) => {
    return User(userData);
  };

  return cynops;
}

// if is node module
if (typeof module !== "undefined" && module && module.exports) {
  module.exports = Encryption;
}
