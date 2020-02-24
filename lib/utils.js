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

const crypto = require('./crypto').default;
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

export const hashPassword = function (password, salt, iterations) {
  return new Promise(function (resolve, reject) {
    crypto.pbkdf2(password, salt, iterations, 20, function (err, derived_key) {
      /* istanbul ignore if */
      if (err) {
        reject(err);
      } else {
        resolve(derived_key.toString('hex'));
      }
    });
  });
};
