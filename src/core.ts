// The whole cryptographic core: key handling, the v1 envelope format, password wrapping and gzip.
// Uses only WebCrypto and CompressionStream, so the same code runs in Node and in browsers.
// The format is specified in FORMAT.md.

const MAGIC = 'KYHL';
const VERSION = 1;
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const SALT_BYTES = 16;
/** PBKDF2-SHA256 iterations for passwords (OWASP 2023 recommendation). */
const PBKDF2_ITERATIONS = 600_000;
// Header layout: magic(4) · version(1) · iv(12).
const VERSION_OFFSET = 4;
const IV_OFFSET = VERSION_OFFSET + 1;
/** The header length. The header is the AES-GCM additional data. */
export const HEADER_BYTES: number = IV_OFFSET + IV_BYTES;

const KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export type KeyholeErrorKind =
  | 'corrupt' // not a keyhole envelope, truncated, or not a payload
  | 'unsupported-version' // a keyhole envelope from another format version
  | 'auth-failed'; // AES-GCM authentication failed: wrong key or tampered file

export class KeyholeError extends Error {
  constructor(readonly kind: KeyholeErrorKind) {
    super(`keyhole: ${kind}`);
    this.name = 'KeyholeError';
  }
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
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
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

/** The same bytes as an ArrayBuffer-backed view, which Web APIs require. Copies only SharedArrayBuffer-backed input. */
function bufferView(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes.buffer instanceof ArrayBuffer
    ? new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    : new Uint8Array(bytes);
}

function importKey(key: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  if (key.length !== KEY_BYTES) throw new Error('keyhole: key must be 32 bytes');
  return crypto.subtle.importKey('raw', bufferView(key), { name: 'AES-GCM' }, false, [usage]);
}

// ---- envelope ----

/** Check the 17-byte header and return its IV. Throws 'corrupt' or 'unsupported-version'. */
export function readHeader(envelope: Uint8Array): Uint8Array<ArrayBuffer> {
  const magic = String.fromCharCode(...envelope.subarray(0, VERSION_OFFSET));
  if (magic !== MAGIC || envelope.length < HEADER_BYTES + TAG_BYTES) throw new KeyholeError('corrupt');
  if (envelope[VERSION_OFFSET] !== VERSION) throw new KeyholeError('unsupported-version');
  return envelope.slice(IV_OFFSET, HEADER_BYTES);
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
  header[VERSION_OFFSET] = VERSION;
  header.set(iv, IV_OFFSET);
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: bufferView(iv), additionalData: header, tagLength: TAG_BYTES * 8 },
    await importKey(key, 'encrypt'),
    bufferView(plaintext),
  );
  const out = new Uint8Array(HEADER_BYTES + sealed.byteLength);
  out.set(header);
  out.set(new Uint8Array(sealed), HEADER_BYTES);
  return out;
}

/** Check the header, then authenticate and decrypt. Throws 'corrupt', 'unsupported-version' or 'auth-failed'. */
export async function decrypt(envelope: Uint8Array, key: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const bytes = bufferView(envelope);
  const iv = readHeader(bytes);
  try {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: bytes.subarray(0, HEADER_BYTES), tagLength: TAG_BYTES * 8 },
      await importKey(key, 'decrypt'),
      bytes.subarray(HEADER_BYTES),
    );
    return new Uint8Array(plain);
  } catch {
    throw new KeyholeError('auth-failed');
  }
}

// ---- password wrapping: the page keeps the key encrypted under a password-derived key ----

export interface WrappedKey {
  /** base64url: 16-byte PBKDF2 salt, 12-byte AES-GCM IV, and the encrypted 32-byte key plus tag. */
  salt: string;
  iv: string;
  key: string;
}

async function passwordKey(password: string, salt: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: bufferView(salt), iterations: PBKDF2_ITERATIONS },
    material,
    { name: 'AES-GCM', length: KEY_BYTES * 8 },
    false,
    [usage],
  );
}

/** Encrypt `key` under `password`, with a fresh salt and IV. */
export async function wrapKey(key: Uint8Array, password: string): Promise<WrappedKey> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await passwordKey(password, salt, 'encrypt'), bufferView(key));
  return { salt: base64UrlEncode(salt), iv: base64UrlEncode(iv), key: base64UrlEncode(new Uint8Array(sealed)) };
}

/** The key wrapped under `password`, or null if the password is wrong. */
export async function unwrapKey(wrapped: WrappedKey, password: string): Promise<Uint8Array<ArrayBuffer> | null> {
  try {
    const key = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64UrlDecode(wrapped.iv) },
      await passwordKey(password, base64UrlDecode(wrapped.salt), 'decrypt'),
      base64UrlDecode(wrapped.key),
    );
    return new Uint8Array(key);
  } catch {
    return null;
  }
}

// ---- compression ----

/** A one-chunk stream over `bytes`, without the full copy a Blob would make. */
function streamOf(bytes: Uint8Array): ReadableStream<Uint8Array<ArrayBuffer>> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bufferView(bytes));
      controller.close();
    },
  });
}

async function transform(bytes: Uint8Array, stream: CompressionStream | DecompressionStream): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await new Response(streamOf(bytes).pipeThrough(stream)).arrayBuffer());
}

export function gzip(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return transform(bytes, new CompressionStream('gzip'));
}

/** Decompress gzip. Throws 'corrupt' on invalid gzip. */
export async function gunzip(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  try {
    return await transform(bytes, new DecompressionStream('gzip'));
  } catch {
    throw new KeyholeError('corrupt');
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
