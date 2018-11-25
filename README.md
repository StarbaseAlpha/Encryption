# Encryption
Starbase Encryption

Starbase Encryption provides 256-bit AES-GCM encryption with HMAC signatures and PBKDF2 password stretching in the browser and in nodeJS. The web version uses the browser's built-in Web Crypto library. The node-webcrypto-ossl package is used server-side in NodeJS.

## Adding Starbase Encryption to your Project


### On the Web
```HTML
<script src="/path/to/encryption.min.js"></script>
```

### On the Web via jsdelivr CDN
```HTML
<script src="https://cdn.jsdelivr.net/npm/@starbase/encryption/encryption.min.js"></script>
```

### In NodeJS
```bash
npm install @starbase/encryption
```

## Using Encryption


### on the Web using encryption.min.js:
```javascript
var encryption = Encryption();
```

### in Node.js using @starbase/encryption:
```javascript
var Encryption = require('@starbase/encryption');
var encryption = Encryption();
```

## API Methods

- [encryption.encrypt()](#encrypt)
- [encryption.decrypt()](#decrypt)


### <a name="encrypt"></a>encryption.encrypt(data, options)

#### Options
  - password
  - passwordBits
  - hmacBits
  - iterations

NOTE: The data parameter must be a string. The password options parameter is required (not optional) unless a passwordBits options parameter is provided.

##### Encryption a string with a password 
```javascript
encryption.encrypt('hello world', {
  "password":"mysecretpassword"
}).then(encrypted => {
  console.log(encrypted);
});
```

##### Response
```JSON
"NTAwMDAw.LYLXNNjzCppoQr5GNR9wrVbX5HrRJg8045vKhdlEScA.gmRluIouvHmWkeqB.GQY-QDhvkGF0gaM1UYuv4cdho-SGpdj00L0h.GLRsEN-45OrZNM3Hwk96cLL7vMVxepYhEVM-LXJpejA"
```

### <a name="decrypt"></a>encryption.decrypt(encrypted, options)
#### Options
  - password
  - passwordBits
  - hmacBits

NOTE: The encrypted parameter must be an encrypted string produced by the Encryption().encrypt() method. The password options parameter is required (not optional) unless a passwordBits options parameter is provided.


##### Decrypt data with a password 
```javascript
encryption.decrypt(encrypted, {
  "password":"mysecretpassword"
}).then(decrypted => {
  console.log(decrypted);
});
```

##### Response
```JSON
"hello world"
```

## More Information

### Author
Hi, my name is Mike. Thanks for taking an interest in my work.
