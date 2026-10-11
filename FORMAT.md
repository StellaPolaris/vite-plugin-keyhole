# Keyhole format, version 1

This is the format of what `vite-plugin-keyhole` embeds in the published `index.html` and its browser
loader reads. `src/core.ts` implements it, and `test/vectors.json` holds known-answer vectors generated
independently with `node:crypto` (`test/make-vectors.mjs`).

## Page config

The page carries one `<script type="application/json" id="keyhole-config">` with:

```json
{ "payload": "<envelope, base64url>", "storageKey": "keyhole:/my-site/", "remember": true,
  "password": { "salt": "…", "iv": "…", "key": "…" } }
```

`password` is present only when a password is set. All binary values are unpadded base64url
(RFC 4648 §5).

## Key

- 32 random bytes (AES-256).
- Written as 43 characters of unpadded base64url. Only the canonical spelling is accepted: the last
  character's unused low bits must be zero.
- In links it appears as the fragment `#key=<43 characters>`. Browsers don't send fragments to servers.

## Envelope

| Offset | Size | Field      | Value                                     |
| -----: | ---: | ---------- | ----------------------------------------- |
|      0 |    4 | magic      | ASCII `KYHL` (`4b 59 48 4c`)              |
|      4 |    1 | version    | `01`                                      |
|      5 |   12 | iv         | random, fresh for every encryption        |
|     17 |    n | ciphertext | AES-256-GCM ciphertext of the plaintext   |
|   17+n |   16 | tag        | AES-GCM authentication tag (128 bits)     |

- Cipher: AES-256-GCM with the 12-byte `iv` and a 16-byte tag.
- Additional authenticated data: the 17 header bytes (offsets 0 to 16). Changing any header byte makes
  authentication fail.
- The minimum envelope length is 33 bytes (header + tag).

## Plaintext

The decrypted bytes are a gzip stream (RFC 1952). Decompressed, they are UTF-8 JSON:

```json
{ "html": "<!doctype html>…", "js": "…" }
```

- `html`: the app's `index.html` with its stylesheet inlined as `<style>` and its entry `<script>` removed.
- `js`: the app's single ES module, with every asset inlined as a `data:` URL.

## Password

The optional password wraps the key; it never replaces it, so links keep working when the password changes.

```
wrappingKey = PBKDF2-HMAC-SHA256(NFC(password), salt, 600000 iterations, 32 bytes)
password.key = AES-256-GCM(wrappingKey, iv, key)   (32 bytes ciphertext + 16 bytes tag, no AAD)
```

`salt` (16 bytes) and `iv` (12 bytes) are random and fresh for every build.

## Reading rules

A reader must process an envelope in this order:

1. Magic is not `KYHL`, or the envelope is shorter than 33 bytes → reject as **corrupt**.
2. Version is not `1` → reject as **unsupported version**. Never guess at other versions.
3. AES-GCM decryption fails → **authentication failed** (wrong key or tampered page).
4. gunzip fails or the JSON isn't `{html: string, js: string}` → **corrupt**.

No code runs before steps 1–4 have succeeded.
