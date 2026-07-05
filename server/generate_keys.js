const crypto = require('crypto');
const fs = require('fs');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

fs.writeFileSync('private.pem', privateKey);
fs.writeFileSync('public.pem', publicKey);

console.log('Keys generated successfully.');
console.log('\n=== PUBLIC KEY (upload this to Meta) ===\n');
console.log(publicKey);
console.log('\nprivate.pem and public.pem saved in this directory.');
console.log('KEEP private.pem secret — never share or commit it.');
