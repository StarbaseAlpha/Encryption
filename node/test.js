'use strict';

const path = require('path');
const Encryption = require(__dirname + path.sep + 'encryption');

Encryption().encrypt('hello',{
  "password":"password"
}).then(encrypted=>{
  console.log(encrypted);
  Encryption().decrypt(encrypted,{
    "password":"password"
  }).then(console.log).catch(console.log);
}).catch(console.log);
