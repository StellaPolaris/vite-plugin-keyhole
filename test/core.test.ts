import { describe, expect, it } from 'vitest';
import {
  HEADER_BYTES,
  KeyholeError,
  base64UrlEncode,
  decrypt,
  encrypt,
  generateKey,
  gunzip,
  gzip,
  keyId,
  openPayload,
  parseKey,
  readHeader,
  sealPayload,
} from '../src/core.ts';
import vectors from './vectors.json' with { type: 'json' };

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
const fromHex = (text: string) => new Uint8Array(Buffer.from(text, 'hex'));
const utf8 = (text: string) => new TextEncoder().encode(text);

async function kind(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof KeyholeError) return error.kind;
    throw error;
  }
  return 'ok';
}

describe('keys', () => {
  it('generates canonical 43-character keys', () => {
    const key = generateKey();
    expect(key).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(parseKey(key)).toHaveLength(32);
    expect(generateKey()).not.toBe(key);
  });

  it('rejects malformed and non-canonical keys', () => {
    expect(parseKey('')).toBeNull();
    expect(parseKey('A'.repeat(42))).toBeNull();
    expect(parseKey('A'.repeat(44))).toBeNull();
    expect(parseKey('A'.repeat(42) + '+')).toBeNull();
    // Same 32 bytes as "A…A", but with non-zero trailing bits.
    expect(parseKey('A'.repeat(42) + 'B')).toBeNull();
    expect(parseKey('A'.repeat(43))).not.toBeNull();
  });
});

describe('known-answer vectors (generated with node:crypto)', () => {
  for (const v of vectors) {
    it(v.name, async () => {
      const key = parseKey(v.key)!;
      expect(hex(await keyId(key))).toBe(v.keyId);
      expect(hex(await encrypt(utf8(v.plaintext), key, fromHex(v.iv)))).toBe(v.envelope);
      expect(new TextDecoder().decode(await decrypt(fromHex(v.envelope), key))).toBe(v.plaintext);
    });
  }
});

describe('envelope', () => {
  const key = parseKey(generateKey())!;
  const plaintext = utf8('secret content');

  it('round trips with a fresh IV each time', async () => {
    const a = await encrypt(plaintext, key);
    const b = await encrypt(plaintext, key);
    expect(hex(readHeader(a).iv)).not.toBe(hex(readHeader(b).iv));
    expect(await decrypt(a, key)).toEqual(plaintext);
    expect(await decrypt(b, key)).toEqual(plaintext);
  });

  it('fails authentication when any single byte is flipped', async () => {
    const envelope = await encrypt(plaintext, key);
    // Header bytes are covered as AAD; magic, version and key ID have their own checks.
    const expected = (i: number) => (i < 4 ? 'corrupt' : i === 4 ? 'unsupported-version' : i < 9 ? 'wrong-key' : 'auth-failed');
    for (let i = 0; i < envelope.length; i++) {
      const tampered = envelope.slice();
      tampered[i] ^= 0x01;
      expect(await kind(decrypt(tampered, key)), `byte ${i}`).toBe(expected(i));
    }
  });

  it('reports a different key as wrong-key before trying to decrypt', async () => {
    const envelope = await encrypt(plaintext, key);
    expect(await kind(decrypt(envelope, parseKey(generateKey())!))).toBe('wrong-key');
  });

  it('rejects unknown versions and truncated or foreign files', async () => {
    const envelope = await encrypt(plaintext, key);
    const v2 = envelope.slice();
    v2[4] = 2;
    expect(await kind(decrypt(v2, key))).toBe('unsupported-version');
    expect(await kind(decrypt(envelope.slice(0, HEADER_BYTES + 15), key))).toBe('corrupt');
    expect(await kind(decrypt(utf8('<!doctype html><html>'), key))).toBe('corrupt');
    expect(await kind(decrypt(new Uint8Array(), key))).toBe('corrupt');
  });
});

describe('gzip and payload', () => {
  it('caps decompressed size', async () => {
    const big = await gzip(new Uint8Array(100_000));
    expect((await gunzip(big)).length).toBe(100_000);
    expect(await kind(gunzip(big, 99_999))).toBe('too-large');
    expect(await kind(gunzip(utf8('not gzip')))).toBe('corrupt');
  });

  it('seals and opens {html, js}', async () => {
    const key = parseKey(generateKey())!;
    const payload = { html: '<!doctype html><title>t</title>', js: 'console.log("ünï")' };
    const envelope = await sealPayload(payload, key);
    expect(await openPayload(envelope, key)).toEqual(payload);
  });

  it('rejects an authentic envelope that is not a payload', async () => {
    const key = parseKey(generateKey())!;
    expect(await kind(openPayload(await encrypt(await gzip(utf8('[1]')), key), key))).toBe('corrupt');
    expect(await kind(openPayload(await encrypt(utf8('plain'), key), key))).toBe('corrupt');
  });

  it('base64url encodes without padding', () => {
    expect(base64UrlEncode(new Uint8Array([0xfb, 0xff]))).toBe('-_8');
  });
});
