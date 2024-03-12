const crypto = require('crypto');
const { promisify } = require('util');

function generateSalt(length) {
    return crypto.randomBytes(length);
}

function base64ToBuffer(base64) {
    return Buffer.from(base64, 'base64');
}

async function deriveKey(password, salt, kdf, iterations, hash, cipher, keyLength) {
    const keyMaterial = await crypto.webcrypto.subtle.importKey(
        'raw',
        Buffer.from(password),
        { name: kdf },
        false,
        ['deriveKey']
    );
    return crypto.webcrypto.subtle.deriveKey(
        {
            name: kdf,
            salt: salt,
            iterations: iterations,
            hash: hash
        },
        keyMaterial,
        { name: cipher, length: keyLength },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptText(password, passwordHint, text) {
    const salt = generateSalt(16);
    const iv = crypto.randomBytes(12); // 96 bits for AES-GCM
    const key = await deriveKey(password, salt, 'PBKDF2', 100000, 'SHA-256', 'AES-GCM', 256);
    const encryptedData = await crypto.webcrypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128
        },
        key,
        Buffer.from(text)
    );

    return JSON.stringify({
        version: '1',
        cipher: 'AES-GCM',
        tagLength: 128,
        textEncoding: 'utf-8',
        ciphertextEncoding: 'base64',
        kdf: {name: 'PBKDF2', iterations: 100000, hash: 'SHA-256', length: 256},
        passwordHint: passwordHint,
        salt: salt.toString('base64'),
        iv: iv.toString('base64'),
        ciphertext: Buffer.from(encryptedData).toString('base64'),
    }, null, 2);
}

async function decryptText(password, encryptedDataJson) {
    const encryptedData = JSON.parse(encryptedDataJson);
    const salt = base64ToBuffer(encryptedData.salt);
    const iv = base64ToBuffer(encryptedData.iv);
    const ciphertext = base64ToBuffer(encryptedData.ciphertext);

    const key = await deriveKey(password, salt, encryptedData.kdf.name, encryptedData.kdf.iterations, encryptedData.kdf.hash, encryptedData.cipher, encryptedData.kdf.length);
    const decryptedData = await crypto.webcrypto.subtle.decrypt(
        {
            name: encryptedData.cipher,
            iv: iv,
            tagLength: encryptedData.tagLength
        },
        key,
        ciphertext
    );
    return Buffer.from(decryptedData).toString();
}