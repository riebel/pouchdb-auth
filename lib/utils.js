/*
	Copyright 2014-2015, Marten de Vries

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

'use strict';
import * as Crypto from 'expo-crypto';

const Promise = require('pouchdb-promise');
const Random = require('expo-random');

export const dbData = {
  dbs: [],
  dataByDBIdx: []
};

export const dbDataFor = function (db) {
  const i = dbData.dbs.indexOf(db);
  return dbData.dataByDBIdx[i];
};

export const nodify = function (promise, callback) {
  require('promise-nodify')(promise, callback);
  return promise;
};

export const processArgs = function (db, opts, callback) {
  if (typeof opts === "function") {
    callback = opts;
    opts = {};
  }
  opts = opts || {};

  return {
    db: db,
    //|| {} for hashAdminPasswords e.g.
    PouchDB: (db || {}).constructor,
    opts: opts,
    callback: callback
  };
};

export const iterations = function (args) {
  return args.opts.iterations || 10;
};

export const generateSecret = async function () {
  const arr = await Random.getRandomBytesAsync(16);
  return arrayToString(arr);
};

function arrayToString(array) {
  let result = '';
  for (let i = 0; i < array.length; i += 1) {
    result += ((array[i] & 0xFF) + 0x100).toString(16);
  }
  return result;
}

function i2s(a) { // integer array to hex string
  for (let i = a.length; i--;) a[i] = ("0000000"+(a[i]>>>0).toString(16)).slice(-8);
  return a.join("")
}

function s2i(s) { // string to integer array
  s = unescape(encodeURIComponent(s));
  let len = s.length
      , i = 0
      , bin = [];

  while (i < len) {
    bin[i>>2] = s.charCodeAt(i++)<<24 |
        s.charCodeAt(i++)<<16 |
        s.charCodeAt(i++)<<8 |
        s.charCodeAt(i++)
  }
  bin.len = len;
  return bin
}

function hmac(hasher, key, txt, raw) {
  let len
      , i = 0
      , ipad = []
      , opad = [];

  key = (key.length > 64) ? hasher(key, 1) : s2i(key);

  while (i < 16) {
    ipad[i] = key[i]^0x36363636;
    opad[i] = key[i++]^0x5c5c5c5c;
  }

  if (typeof txt == "string") {
    txt = s2i(txt);
    len = txt.len;
  } else len = txt.length * 4;
  i = hasher(opad.concat(hasher(ipad.concat(txt), 1, 64 + len)), 1);
  return raw ? i : i2s(i);
}

function pbkdf2(secret, salt, count, length, digest, callback) {
  if (typeof digest == "function") {
    callback = digest;
    digest = "SHA1";
  }
  let hasher = Crypto.CryptoDigestAlgorithm[digest] || Crypto.CryptoDigestAlgorithm.SHA1;
  count = count || 1000;

  let u, ui, i, j, k
      , out = []
      , wlen = length>>2 || 5;

  for (k = 1; out.length < wlen; k++) {
    u = ui = hmac(hasher, secret, salt+String.fromCharCode(k >> 24 & 0xF, k >> 16 & 0xF, k >>  8 & 0xF, k  & 0xF), 1);

    for (i = count; --i;) {
      ui = hmac(hasher, secret, ui, 1);
      for (j = ui.length; j--;) u[j] ^= ui[j]
    }

    //out = out.concat(u)
    out.push.apply(out, u)
  }
  out = i2s(out).slice(0, length*2 || 40);
  if (callback) callback(null, out);
  else return out
}

export const hashPassword = function (password, salt, iterations) {
  return new Promise(function (resolve, reject) {
    pbkdf2(password, salt, iterations, 20, function (err, derived_key) {
      /* istanbul ignore if */
      if (err) {
        reject(err);
      } else {
        resolve(derived_key.toString('hex'));
      }
    });
  });
};
