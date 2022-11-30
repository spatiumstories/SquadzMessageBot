// Do `npm i elliptic sha256` before hand

const EC = require('elliptic').ec;
const sha256 = require('sha256');

function seedHexToPrivateKey(seedHex) {
  const ec = new EC('secp256k1');
  return ec.keyFromPrivate(seedHex);
}

const uvarint64ToBuf = (uint) => {
  const result = [];

  while (uint >= 0x80) {
    result.push((uint & 0xff) | 0x80);
    uint >>>= 7;
  }

  result.push(uint | 0);

  return new Buffer.from(result);
};

function signTransaction(seedHex, transactionHex) {
  const privateKey = seedHexToPrivateKey(seedHex);

  const transactionBytes = new Buffer.from(transactionHex, 'hex');
  const transactionHash = new Buffer.from(sha256.x2(transactionBytes), 'hex');
  const signature = privateKey.sign(transactionHash);
  const signatureBytes = new Buffer.from(signature.toDER());
  const signatureLength = uvarint64ToBuf(signatureBytes.length);

  const signedTransactionBytes = Buffer.concat([
    transactionBytes.slice(0, -1),
    signatureLength,
    signatureBytes,
  ]);

  return signedTransactionBytes.toString('hex');
}

module.exports = {
    sign: signTransaction
}