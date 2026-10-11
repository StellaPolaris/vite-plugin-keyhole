# vite-plugin-keyhole

Encrypt a whole Vite build so it can live on any public static host (GitHub Pages, for example), yet
opens only for people whose link contains the key.

```ts
// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import keyhole from 'vite-plugin-keyhole';

export default defineConfig({
  base: '/my-site/',
  plugins: [react(), keyhole()],
});
```

```sh
npx keyhole keygen                                   # prints a new key
echo "KEYHOLE_KEY=<that key>" >> .env.production.local
npx vite build                                       # dist/ now has 3 files
npx keyhole link https://me.github.io/my-site/about  # prints …/about#key=<key>
```

`vite dev` is unchanged and needs no key. No app code is needed.

## What gets published

| File                          | Contents                                                      |
| ----------------------------- | ------------------------------------------------------------- |
| `index.html`                  | A neutral landing page ("Coming soon") with a small inline loader |
| `404.html`                    | The same page, so deep links like `/my-site/about` work       |
| `assets/keyhole-<hash>.bin`   | Your app's HTML, CSS, JS, fonts and images, gzipped and encrypted |

When someone opens a link with `#key=…`, the loader removes the key from the address bar, downloads
and decrypts the `.bin`, swaps in your app's document and runs it. The key is remembered in that browser,
so later visits open directly. `#logout` makes the browser forget it.

## Options

| Option        | Default        | What it does                                                                |
| ------------- | -------------- | --------------------------------------------------------------------------- |
| `key`         | `KEYHOLE_KEY`  | The 43-character key. Read from the environment or `.env*` files by default. The build fails if it's missing or malformed. |
| `landing`     | built-in page  | Path to your own landing HTML. It needs a `</body>`. An element with `id="keyhole-retry"` is shown when a download fails, and one with `id="keyhole-unsupported"` when a visitor with a key opens it without HTTPS or in an old browser. |
| `remember`    | `'local'`      | Where the key is kept after unlocking: `'local'`, `'session'` or `'none'`. Entries are namespaced by `base`. |
| `spaFallback` | `true`         | Also write `404.html`.                                                      |

The `KEYHOLE_` prefix is not in Vite's `envPrefix`, so the key never ends up in client code.

## What it protects, and what it doesn't

It protects content from anyone without the link, including search engines and anyone reading the
public files.

It does **not** protect against:

- **The host or build machine.** The host can't decrypt the stored file, but it serves the loader. A
  malicious or compromised host could replace the loader and capture the key on someone's next visit.
  Both must be trusted to run the code they were given.
- **Anyone with the link.** This is a shared secret, not access control. Anyone holding the link can
  read everything and keep a copy.
- **Old downloads after a key change.** A new key protects new builds. An encrypted file someone
  downloaded earlier still opens with the old key.
- **The browser.** The key stays in history entries created before it was removed, in chats where the
  link was pasted, and in storage on devices where it was used. App scripts run in the same page as
  the loader and could read it.
- **Metadata.** The size of the encrypted file and the fact that something encrypted is served.
- **Secrets in your app**, such as API keys. Anyone with the link can read them.

## Supported apps

One HTML entry, rendered in the browser (an SPA), fully bundled, with no web workers or service
workers. The plugin forces one JS chunk, one inlined stylesheet and inlined assets, and the build fails
with a list of files if the output looks different. It also fails if anything else ends up in the
output folder, such as stale files or source maps. Files in `public/` fail the build before anything is
written; set `build.copyPublicDir: false` to keep them out. Set the destination with `build.outDir`:
overriding the output `dir` or `file` is refused.

Your app starts after the page has finished loading, so a few things behave differently:

- Inline `<script>` tags in your `index.html` don't run. Put that code in your entry module.
- `DOMContentLoaded` and `load` have already fired. Start your app directly from the entry module, as
  React, Vue and Svelte templates do, rather than waiting for those events.
- Hash-based routers (`#/about`) can't share a URL with `#key=…`. Use path-based routing, which also
  needs an absolute `base` (like `/my-site/`) so deep links can find the payload.

## When something goes wrong

The visitor sees the neutral landing page, never an error message. The only exception is a visitor
who has a key but opened it without HTTPS or in a browser that can't decrypt: they see a short hint,
and the key stays in the address bar. A saved key is forgotten only when
it doesn't match the file (after a key change), never because of a failed download.

| What happened                                        | What the loader does                                     |
| ---------------------------------------------------- | -------------------------------------------------------- |
| No key, or a key for a different build               | Landing page                                             |
| The `.bin` is missing (404, or an HTML page from a host that rewrites every path) or in a newer format | The page is older than the current build: it reloads once to get the current HTML, then offers "Try again" |
| Offline, server error, or a damaged download          | "Try again" downloads again                              |
| The app throws while starting                        | Landing page back, "Try again" reloads; the error is in the console |

## Content Security Policy

The plugin emits no CSP. If your host lets you set headers, this works with the loader:

```
default-src 'self'; script-src 'self' 'unsafe-inline' blob:; style-src 'self' 'unsafe-inline';
img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; base-uri 'none'; object-src 'none'
```

## Format and code

- `FORMAT.md`: the file format: AES-256-GCM, a versioned header used as authenticated data, and a key ID.
- `src/core.ts`: the whole crypto core, WebCrypto only, the same code in Node and browsers.
- `vite-plugin-keyhole/core` exports it: `generateKey`, `parseKey`, `encrypt`, `decrypt`,
  `sealPayload` and `openPayload`.
