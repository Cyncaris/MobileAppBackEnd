const crypto = require('crypto');
const { generateKeyPairSync } = require('crypto');

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',       // Recommended for RSA public keys
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',      // Recommended for RSA private keys
    format: 'pem'
  }
});

// Save the keys to files or use them directly
require('fs').writeFileSync('private.pem', privateKey);
require('fs').writeFileSync('public.pem', publicKey);