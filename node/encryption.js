'use strict';

const WebCrypto = require('node-webcrypto-ossl');
const crypto = new WebCrypto();

function Encryption() {

  let encryption = {};

  const TextEncoder = () => {
    let encoder = {};
    encoder.encode = (str) => {
      return new Uint8Array(str.split('').map(val=>{
        return val.charCodeAt(0);
      }));
    };
    return encoder;
  };

  const TextDecoder = () => {
    let decoder = {};
    decoder.decode = (arr) => {
      return Array.from(new Uint8Array(arr)).map(val=>{
        return String.fromCharCode(val);
      }).join('');
    };
    return decoder;
  };

  encryption.encrypt = async (message,options={}) => {

    if (!message || typeof message !== 'string') {
      return Promise.reject({"code":400,"message":"Message must be a string."});
    }

    if (typeof options !== 'object') {
      return Promise.reject({"code":400,"message":"Invalid options parameters."});
    }

    let {password,passwordBits,iterations,hmacBits} = options;

    if (!password && !passwordBits) {
      return Promise.reject({"code":400,"message":"No password or passwordBits was provided."});
    }

    let rounds = iterations || 500000;
    let iterationsHash = btoa(rounds.toString()).replace(/\=/g,'').replace(/\+/g,'-').replace(/\//g,'_');

    let msg = TextEncoder().encode(message);

    let pass;
    if (password) {
      pass = await crypto.subtle.importKey('raw', TextEncoder().encode(password), {
        "name": "PBKDF2"
      }, false, ['deriveBits']);
    }

    if (passwordBits) {
      pass = await crypto.subtle.importKey('raw', new Uint8Array(passwordBits), {
        "name": "PBKDF2"
      }, false, ['deriveBits']);
    }

    let salt = crypto.getRandomValues(new Uint8Array(32));
    let saltHash = btoa(Array.from(new Uint8Array(salt)).map(val => {
      return String.fromCharCode(val);
    }).join('')).replace(/\=/g,'').replace(/\+/g,'-').replace(/\//g,'_');

    let iv = crypto.getRandomValues(new Uint8Array(12));
    let ivHash = btoa(Array.from(new Uint8Array(iv)).map(val => {
      return String.fromCharCode(val)
    }).join('')).replace(/\=/g,'').replace(/\+/g,'-').replace(/\//g,'_');

    let bits = await crypto.subtle.deriveBits({
      "name": "PBKDF2",
      "salt": salt,
      "iterations": rounds,
      "hash": {
        "name": "SHA-256"
      }
    }, pass, 512);

    let aesBits = bits.slice(32, 64);

    let aesKey = await crypto.subtle.importKey('raw', aesBits, {
      "name": "AES-GCM"
    }, false, ['encrypt']);

    if (!hmacBits) {
      hmacBits = bits.slice(0, 32);
    }

    let hmacKey = await crypto.subtle.importKey('raw', hmacBits, {
      "name": "HMAC",
      "hash": {
        "name": "SHA-256"
      }
    }, false, ['sign']);

    let enc = await crypto.subtle.encrypt({
      "name": "AES-GCM",
      "iv": iv
    }, aesKey, msg);

    let encHash = btoa(Array.from(new Uint8Array(enc)).map(val => {
      return String.fromCharCode(val);
       }).join('')).replace(/\=/g,'').replace(/\+/g,'-').replace(/\//g,'_');

    let encrypted = iterationsHash + '.' + saltHash + '.' + ivHash + '.' + encHash;

    let sigData = TextEncoder().encode(encrypted);
    let signature = await crypto.subtle.sign({
      "name": "HMAC"
    }, hmacKey, sigData);

    let sigHash = btoa(Array.from(new Uint8Array(signature)).map(val => {
      return String.fromCharCode(val);
    }).join('')).replace(/\=/g,'').replace(/\+/g,'-').replace(/\//g,'_');

    return encrypted + '.' + sigHash;

  };

  encryption.decrypt = async (encrypted, options={}) => {

    if (!encrypted || typeof encrypted !== 'string') {
      return Promise.reject({"code":400,"message":"Encrypted text must be a string."});
    }

    if (typeof options !== 'object') {
      return Promise.reject({"code":400,"message":"Invalid options parameters."});
    }

    let {password,passwordBits,hmacBits} = options;

    if (!password && !passwordBits) {
      return Promise.reject({"code":400,"message":"No password or passwordBits was provided."});
    }

    let parts = encrypted.split('.');

    let rounds = parseInt(atob(parts[0]));

    let salt = new Uint8Array(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')).split('').map(val => {
      return val.charCodeAt(0);
    }));

    let iv = new Uint8Array(atob(parts[2].replace(/-/g,'+').replace(/_/g,'/')).split('').map(val => {
      return val.charCodeAt(0);
    }));

    let enc = new Uint8Array(atob(parts[3].replace(/-/g,'+').replace(/_/g,'/')).split('').map(val => {
      return val.charCodeAt(0);
    }));

    let sig = new Uint8Array(atob(parts[4].replace(/-/g,'+').replace(/_/g,'/')).split('').map(val => {
      return val.charCodeAt(0);
    }));

    let pass;

    if (password) {
      pass = await crypto.subtle.importKey('raw', TextEncoder().encode(password), {
        "name": "PBKDF2"
      }, false, ['deriveBits']);
    }

    if (passwordBits) {
      pass = await crypto.subtle.importKey('raw', new Uint8Array(passwordBits), {
        "name": "PBKDF2"
      }, false, ['deriveBits']);
    }

    let bits = await crypto.subtle.deriveBits({
      "name": "PBKDF2",
      "salt": salt,
      "iterations": rounds,
      "hash": {
        "name": "SHA-256"
      }
    }, pass, 512);

    let aesBits = bits.slice(32, 64);

    let aesKey = await crypto.subtle.importKey('raw', aesBits, {
      "name": "AES-GCM"
    }, false, ['decrypt']);

    if (!hmacBits) {
      hmacBits = bits.slice(0, 32);
    }

    let hmacKey = await crypto.subtle.importKey('raw', hmacBits, {
      "name": "HMAC",
      "hash": {
        "name": "SHA-256"
      }
    }, false, ['verify']);

    let sigData = TextEncoder().encode(encrypted.split('.').slice(0, 4).join('.'));
    let verified = await crypto.subtle.verify({
      "name": "HMAC"
    }, hmacKey, sig, sigData);

    if (!verified) {
      return Promise.reject({
        "error": "Password or signature does not match."
      });
    }

    let dec = await crypto.subtle.decrypt({
      "name": "AES-GCM",
      "iv": iv
    }, aesKey, enc);
    return (TextDecoder().decode(dec));
  };

  return encryption;

}

module.exports = Encryption;
