const assert = require('assert');
const crypto = require('crypto');
const EC = require('elliptic').ec;
const ec = new EC("secp256k1");
const axios = require('axios');
const bs58check = require('bs58check');


/*
 Backend API endpoints
 */
const api = "https://node.deso.org";
const apiSendMessage = "/api/v0/send-message-stateless";

// Payload from DeSo Identity after using the /get-shared-secrets window API endpoint.
const sharedSecret = "ccf9474d7578658e0c77adb7aea5cc9b61d3bccad5bddddd11e1850dfa4db059";
// Public key of the sender (derived key holder).
const senderPublicKey = "tBCKXyutsCWVbECXqE5zqP7NyGjmXg1SHkYJgKUsNujHfVF7GsVxzU";
// Public key of the recipient.
const recipientPublicKey = "tBCKWkRrNYMLiAygVcKWgYBg9XsELnVbZYhsoUBCWNo8fUmDh1ZY4k";

/*
 Encrypt and submit a message.
 In this example, we implement encryption/decryption of messages using
 shared secrets. We will first encrypt a test message and prepare a
 send-message transaction.
 */

async function SendMessage () {
    // Let's try out message encryption/decryption
    // Step 1. Encrypt our message.
    const msg = "This is a test!";
    const encryptedMsg = encryptMessage(sharedSecret, msg);
    console.log(encryptedMsg.toString('hex'));
    // Step 2. (Optional) Verify that the message was encrypted properly.
    const decryptedMsg = decryptMessage(sharedSecret, encryptedMsg);
    assert(decryptedMsg === msg);
    console.log(decryptedMsg);

    // Step 3. Prepare a send message transaction.
    let payload = {
        EncryptedMessageText: encryptedMsg.toString('hex'),
        RecipientPublicKeyBase58Check: recipientPublicKey,
        SenderPublicKeyBase58Check: senderPublicKey,
        MinFeeRateNanosPerKB: 1000
    }
    let res = await axios.post(api + apiSendMessage, payload);
    const transactionHex = res.data.TransactionHex;

    // We leave out the next steps to simplify this code snippet.

    // Step 4. Sign message with seed hex (most likely derived key)
    // check out authorize-derived-key example for details.

    // Step 5. Submit transaction.
}

/*
 Helper functions
 It might be slightly tricky to reimplement these primitives in another
 language, but it's not impossible. The code is modeled on Parity's Eth implementation.
 */
// SHA256 ConcatKDF.
function kdf (secret, outputLength) {
    let ctr = 1;
    let written = 0;
    let result = Buffer.from('');
    while (written < outputLength) {
        const ctrs = Buffer.from([ctr >> 24, ctr >> 16, ctr >> 8, ctr]);
        const hashResult = crypto.createHash("sha256").update(Buffer.concat([ctrs, secret])).digest();
        result = Buffer.concat([result, hashResult])
        written += 32;
        ctr +=1;
    }
    return result;
}

//ECDH.
function derive (privateKeyA, publicKeyB) {
    // const decoded = bs58check.decode(publicKeyB);
    // const payload = Uint8Array.from(decoded).slice(3);

    const keyB = ec.keyFromPublic(publicKeyB, 'array');

    const keyA = ec.keyFromPrivate(privateKeyA);
    // const keyB = ec.keyFromPublic(publicKeyB);
    const Px = keyA.derive(keyB.getPublic());  // BN instance
    return new Buffer(Px.toArray());
}

// Sha256 HMAC.
function hmacSha256Sign (key, msg) {
    return crypto.createHmac('sha256', key).update(msg).digest();
}

// AES-128-CTR encryption.
function aesCtrEncrypt (counter, key, data) {
    const cipher = crypto.createCipheriv('aes-128-ctr', key, counter);
    const firstChunk = cipher.update(data);
    const secondChunk = cipher.final();
    return Buffer.concat([firstChunk, secondChunk]);
}

// AES-128-CTR decryption.
function aesCtrDecrypt (counter, key, data) {
    const cipher = crypto.createDecipheriv('aes-128-ctr', key, counter);
    const firstChunk = cipher.update(data);
    const secondChunk = cipher.final();
    return Buffer.concat([firstChunk, secondChunk]);
}

// Obtain the public elliptic curve key from a private.
function getPublic (privateKey) {
    assert(privateKey.length === 32, "Bad private key");
    return new Buffer(ec.keyFromPrivate(privateKey).getPublic("arr"));
}

/*
 Encryption/Decryption
 */

// Decrypt a message using shared secret.
function decryptMessage (sharedSecret, encryptedText) {
    const sharedPrivateKey = new Buffer(sharedSecret, 'hex');
    const encrypted = new Buffer(encryptedText, 'hex');

    const metaLength = 1 + 64 + 16 + 32;
    assert(encrypted.length > metaLength, "Invalid Ciphertext. Data is too small")
    assert(encrypted[0] >= 2 && encrypted[0] <= 4, "Not valid ciphertext.")

    // deserialize
    const ephemPublicKey = encrypted.slice(0, 65);
    const cipherTextLength = encrypted.length - metaLength;
    const iv = encrypted.slice(65, 65 + 16);
    const cipherAndIv = encrypted.slice(65, 65 + 16 + cipherTextLength);
    const ciphertext = cipherAndIv.slice(16);
    const msgMac = encrypted.slice(65 + 16 + cipherTextLength);

    // check HMAC
    const px = derive(sharedPrivateKey, ephemPublicKey);
    const hash = kdf(px,32);
    const encryptionKey = hash.slice(0, 16);
    const macKey = crypto.createHash("sha256").update(hash.slice(16)).digest()
    const dataToMac = Buffer.from(cipherAndIv);
    const hmacGood = hmacSha256Sign(macKey, dataToMac);
    assert(hmacGood.equals(msgMac), "Incorrect MAC");

    return aesCtrDecrypt(iv, encryptionKey, ciphertext).toString();
}

// Encrypt a message using shared secret.
function encryptMessage (sharedSecret, msg) {
    const sharedPrivateKey = new Buffer(sharedSecret, 'hex');
    const sharedPublicKey = getPublic(sharedPrivateKey);

    const ephemPrivateKey = crypto.randomBytes(32);
    const ephemPublicKey = getPublic(ephemPrivateKey);

    const sharedPx = derive(ephemPrivateKey, sharedPublicKey);
    const hash = kdf(sharedPx, 32);
    const iv = crypto.randomBytes(16);
    const encryptionKey = hash.slice(0, 16);

    // Generate hmac
    const macKey = crypto.createHash("sha256").update(hash.slice(16)).digest();

    let ciphertext;
    ciphertext = aesCtrEncrypt(iv, encryptionKey, msg);
    const dataToMac = Buffer.from([...iv, ...ciphertext]);
    const HMAC = hmacSha256Sign(macKey, dataToMac);

    return Buffer.from([...ephemPublicKey, ...iv, ...ciphertext, ...HMAC]);
}

module.exports = {
    encryptMessage: encryptMessage,
    decryptMessage: decryptMessage,
    derive: derive,
    kdf: kdf
}