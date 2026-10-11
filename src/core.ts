// The whole cryptographic core: key handling, the v1 envelope format, and gzip helpers.
// Uses only WebCrypto and CompressionStream, so the same code runs in Node 24 and in browsers.
// The format is specified in FORMAT.md.

export const MAGIC = 'KYHL';
export const VERSION = 1;
export const KEY_BYTES = 32;
export const KEY_ID_BYTES = 4;
export const IV_BYTES = 12;
export const TAG_BYTES = 16;
/** magic(4) · version(1) · keyId(4) · iv(12). Used as the AES-GCM additional data. */
export const HEADER_BYTES: number = 4 + 1 + KEY_ID_BYTES + IV_BYTES;
/** Largest envelope the plugin writes and the loader downloads. */
export const MAX_ENVELOPE_BYTES: number = 64 * 1024 * 1024;
/** Largest decompressed payload the loader accepts. */
export const MAX_PLAINTEXT_BYTES: number = 256 * 1024 * 1024;

const KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const KEY_ID_LABEL = 'keyhole/key-id/v1';

export type KeyholeErrorKind =
  | 'corrupt' // not a keyhole envelope, or truncated
  | 'unsupported-version' // a keyhole envelope from a newer (or older) format version
  | 'wrong-key' // the key ID in the header doesn't match this key
  | 'auth-failed' // AES-GCM authentication failed: tampered file or wrong key
  | 'too-large';

export class KeyholeError extends Error {
  constructor(readonly kind: KeyholeErrorKind) {
    super(`keyhole: ${kind}`);
    this.name = 'KeyholeError';
  }
}

export interface Header {
  version: number;
  keyId: Uint8Array<ArrayBuffer>;
  iv: Uint8Array<ArrayBuffer>;
}

// ---- base64url and keys ----

export function base64UrlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('invalid base64url');
  const bin = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** A fresh random 256-bit key as 43 base64url characters. */
export function generateKey(): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(KEY_BYTES)));
}

/** Decode a canonical 43-character key to 32 bytes, or return null if it isn't one. */
export function parseKey(text: string): Uint8Array<ArrayBuffer> | null {
  if (!KEY_PATTERN.test(text)) return null;
  const bytes = base64UrlDecode(text);
  // Reject non-canonical encodings (different trailing bits) so one key has exactly one spelling.
  if (bytes.length !== KEY_BYTES || base64UrlEncode(bytes) !== text) return null;
  return bytes;
}

/** First 4 bytes of SHA-256("keyhole/key-id/v1" ‖ key). Identifies a key without revealing it. */
export async function keyId(key: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const label = new TextEncoder().encode(KEY_ID_LABEL);
  const input = new Uint8Array(label.length + key.length);
  input.set(label);
  input.set(key, label.length);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input)).slice(0, KEY_ID_BYTES);
}

// ---- envelope ----

/** Parse and check the 21-byte header. Throws 'corrupt' or 'unsupported-version'. */
export function readHeader(envelope: Uint8Array): Header {
  const magic = String.fromCharCode(...envelope.subarray(0, 4));
  if (magic !== MAGIC) throw new KeyholeError('corrupt');
  const version = envelope[4];
  if (version !== VERSION) throw new KeyholeError('unsupported-version');
  if (envelope.length < HEADER_BYTES + TAG_BYTES) throw new KeyholeError('corrupt');
  return {
    version,
    keyId: envelope.slice(5, 5 + KEY_ID_BYTES),
    iv: envelope.slice(5 + KEY_ID_BYTES, HEADER_BYTES),
  };
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function importKey(key: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  if (key.length !== KEY_BYTES) throw new Error('keyhole: key must be 32 bytes');
  return crypto.subtle.importKey('raw', new Uint8Array(key), { name: 'AES-GCM' }, false, [usage]);
}

/**
 * Encrypt bytes into a v1 envelope. A fresh random IV is drawn for every call;
 * passing `iv` is only for known-answer test vectors.
 */
export async function encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array = crypto.getRandomValues(new Uint8Array(IV_BYTES)),
): Promise<Uint8Array<ArrayBuffer>> {
  if (iv.length !== IV_BYTES) throw new Error('keyhole: iv must be 12 bytes');
  const header = new Uint8Array(HEADER_BYTES);
  header.set(new TextEncoder().encode(MAGIC));
  header[4] = VERSION;
  header.set(await keyId(key), 5);
  header.set(iv, 5 + KEY_ID_BYTES);
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: new Uint8Array(iv), additionalData: header, tagLength: TAG_BYTES * 8 },
    await importKey(key, 'encrypt'),
    new Uint8Array(plaintext),
  );
  const out = new Uint8Array(HEADER_BYTES + sealed.byteLength);
  out.set(header);
  out.set(new Uint8Array(sealed), HEADER_BYTES);
  return out;
}

/**
 * Check the header and key ID, then authenticate and decrypt.
 * Throws 'corrupt', 'unsupported-version', 'wrong-key' or 'auth-failed'.
 */
export async function decrypt(envelope: Uint8Array, key: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const header = readHeader(envelope);
  if (!equalBytes(header.keyId, await keyId(key))) throw new KeyholeError('wrong-key');
  try {
    const plain = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: header.iv,
        additionalData: envelope.slice(0, HEADER_BYTES),
        tagLength: TAG_BYTES * 8,
      },
      await importKey(key, 'decrypt'),
      envelope.slice(HEADER_BYTES),
    );
    return new Uint8Array(plain);
  } catch {
    throw new KeyholeError('auth-failed');
  }
}

// ---- compression ----

/** Read a stream fully, cancelling and throwing 'too-large' once it passes `cap` bytes. */
export async function readBounded(stream: ReadableStream<Uint8Array>, cap: number): Promise<Uint8Array<ArrayBuffer>> {
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > cap) {
      await reader.cancel().catch(() => {});
      throw new KeyholeError('too-large');
    }
    parts.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

export function gzip(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return readBounded(new Blob([new Uint8Array(bytes)]).stream().pipeThrough(new CompressionStream('gzip')), Infinity);
}

/** Decompress gzip with an output cap. Throws 'corrupt' on invalid gzip, 'too-large' over the cap. */
export async function gunzip(bytes: Uint8Array, cap: number = MAX_PLAINTEXT_BYTES): Promise<Uint8Array<ArrayBuffer>> {
  try {
    return await readBounded(new Blob([new Uint8Array(bytes)]).stream().pipeThrough(new DecompressionStream('gzip')), cap);
  } catch (error) {
    throw error instanceof KeyholeError ? error : new KeyholeError('corrupt');
  }
}

// ---- payload: what the plugin encrypts and the loader restores ----

export interface Payload {
  /** The app's index.html with CSS inlined and the entry script removed. */
  html: string;
  /** The app's single JS module. */
  js: string;
}

/** gzip(JSON {html, js}), then encrypt. */
export async function sealPayload(payload: Payload, key: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const json = new TextEncoder().encode(JSON.stringify({ html: payload.html, js: payload.js }));
  return encrypt(await gzip(json), key);
}

/** Decrypt, gunzip and parse. Throws KeyholeError (see decrypt), 'corrupt' if the contents aren't a payload. */
export async function openPayload(envelope: Uint8Array, key: Uint8Array): Promise<Payload> {
  const json = await gunzip(await decrypt(envelope, key));
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder().decode(json));
  } catch {
    throw new KeyholeError('corrupt');
  }
  const { html, js } = (value ?? {}) as Partial<Payload>;
  if (typeof html !== 'string' || typeof js !== 'string') throw new KeyholeError('corrupt');
  return { html, js };
}
