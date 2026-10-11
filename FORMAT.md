# Keyhole file format, version 1

This is the format of the `assets/keyhole-<hash>.bin` file that `vite-plugin-keyhole` writes and its
browser loader reads. `src/core.ts` implements it, and `test/vectors.json` holds known-answer vectors
generated independently with `node:crypto` (`test/make-vectors.mjs`).

## Key

- 32 random bytes (AES-256).
- Written as 43 characters of unpadded base64url (RFC 4648 §5). Only the canonical spelling is
  accepted: the last character's unused low bits must be zero.
- In links it appears as the fragment `#key=<43 characters>`. Browsers don't send fragments to servers.

## Key ID

```
keyId = SHA-256("keyhole/key-id/v1" ‖ key)[0..4]
```

The label is the 17 ASCII bytes `keyhole/key-id/v1`, followed by the 32 raw key bytes. The key ID lets
the loader tell a stale saved key apart from a damaged or missing file without attempting decryption.
It reveals 32 bits of a hash of the key, which doesn't help an attacker recover a 256-bit key.

## Envelope

| Offset | Size | Field      | Value                                     |
| -----: | ---: | ---------- | ----------------------------------------- |
|      0 |    4 | magic      | ASCII `KYHL` (`4b 59 48 4c`)              |
|      4 |    1 | version    | `01`                                      |
|      5 |    4 | keyId      | see above                                 |
|      9 |   12 | iv         | random, fresh for every encryption        |
|     21 |    n | ciphertext | AES-256-GCM ciphertext of the plaintext   |
|   21+n |   16 | tag        | AES-GCM authentication tag (128 bits)     |

- Cipher: AES-256-GCM with the 12-byte `iv` and a 16-byte tag.
- Additional authenticated data: the 21 header bytes (offsets 0 to 20). Changing any header byte makes
  authentication fail.
- The minimum envelope length is 37 bytes (header + tag).

## Plaintext

The decrypted bytes are a gzip stream (RFC 1952). Decompressed, they are UTF-8 JSON:

```json
{ "html": "<!doctype html>…", "js": "…" }
```

- `html`: the app's `index.html` with its stylesheet inlined as `<style>` and its entry `<script>` removed.
- `js`: the app's single ES module, with every asset inlined as a `data:` URL.

## Reading rules

A reader must process an envelope in this order:

1. Magic is not `KYHL`, or the file is shorter than 37 bytes → reject as **corrupt**.
2. Version is not `1` → reject as **unsupported version**. Never guess at other versions.
3. Key ID doesn't match the key → **wrong key**. The browser loader forgets a saved key only here.
4. AES-GCM decryption fails → **authentication failed** (tampered or damaged file).
5. gunzip fails or the JSON isn't `{html: string, js: string}` → **corrupt**.

Readers should cap the download size and the decompressed size; the reference loader uses 64 MiB and
256 MiB. No code runs before steps 1–5 have succeeded.
