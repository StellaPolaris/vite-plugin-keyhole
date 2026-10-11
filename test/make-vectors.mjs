// Generates test/vectors.json with node:crypto (createCipheriv), independently of src/core.ts,
// so the core's WebCrypto output is checked against a second implementation.
import { createCipheriv, createHash } from 'node:crypto';

const label = Buffer.from('keyhole/key-id/v1');
const b64url = (buf) => buf.toString('base64url');

function vector(name, keyHex, ivHex, plaintext) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = Buffer.from(ivHex, 'hex');
  const keyId = createHash('sha256').update(Buffer.concat([label, key])).digest().subarray(0, 4);
  const header = Buffer.concat([Buffer.from('KYHL'), Buffer.from([1]), keyId, iv]);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(header);
  const body = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final(), cipher.getAuthTag()]);
  return {
    name,
    key: b64url(key),
    keyId: keyId.toString('hex'),
    iv: iv.toString('hex'),
    plaintext,
    envelope: Buffer.concat([header, body]).toString('hex'),
  };
}

const vectors = [
  vector('empty plaintext, zero key', '00'.repeat(32), '00'.repeat(12), ''),
  vector('short text', '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'cafebabefacedbaddecaf888', 'hello keyhole'),
  vector('multi-block unicode', 'ff'.repeat(32), '0102030405060708090a0b0c', 'Ünïcödé ✓ — '.repeat(10)),
];
console.log(JSON.stringify(vectors, null, 2));
