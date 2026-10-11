# vite-plugin-keyhole

Encrypt a whole Vite build so it can live on any public static host (GitHub Pages, for example), yet
opens only for people with the link, or the password if you set one.

Best for small client previews, prototypes and interactive reports: the whole encrypted app downloads
upfront, including assets. Requires Vite 8, Node.js 22.12 or newer, and HTTPS in production.

```sh
npm install -D vite-plugin-keyhole
```

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
npx keyhole keygen                                    # prints a new key
echo "KEYHOLE_KEY=<that key>" >> .env.production.local
echo "KEYHOLE_PASSWORD=<a long passphrase>" >> .env.production.local   # optional
npx vite build
```

Share `https://me.github.io/my-site/#key=<that key>`, or the password. `vite dev` is unchanged and
needs no key. No app code is needed.

To check the production build locally, run `npx vite preview` and open the printed address with
`/my-site/#key=<that key>` (matching the `base` above). Visit `#logout` to check the locked page.
Keep `.env.production.local` out of Git; in CI, provide `KEYHOLE_KEY` and the optional
`KEYHOLE_PASSWORD` as build secrets. Deploy only the generated `dist/` folder.

## What gets published

`index.html` holds a neutral landing page ("Coming soon"), a small loader and your whole app (HTML, CSS,
JS, fonts and images), gzipped and encrypted. `404.html` is the same page, so deep links like
`/my-site/about` work on hosts that serve `404.html` for missing paths (GitHub Pages does). Nothing
else is published unless you list it in `publish`: to keep a file from `public/` encrypted, move it
into `src/` and import it.

When someone opens a link with `#key=…`, the loader removes the key from the address bar, decrypts the
app, swaps in its document and runs it. With a password set, the landing page also shows a password
field. The key is remembered in that browser, so later visits open directly. `#logout` makes the
browser forget it.

## Options

| Option        | Default            | What it does |
| ------------- | ------------------ | ------------ |
| `key`         | `KEYHOLE_KEY`      | The 43-character key that links carry. Read from the environment or `.env*` files by default. |
| `password`    | `KEYHOLE_PASSWORD` | Also let visitors type a password. Leave it unset for links only. Changing it doesn't break links. |
| `publish`     | `[]`               | Files that may be published unencrypted, relative to the output folder, e.g. `['favicon.svg', 'CNAME', '_headers']`. A trailing `/` allows a folder. |
| `landing`     | built-in page      | Path to your own landing HTML (see below). |
| `remember`    | `true`             | Keep the key in `localStorage` after unlocking, namespaced by `base` (a relative base by the page's folder). `false` also removes a key an earlier build saved. |
| `spaFallback` | `true`             | Also write `404.html`. Turn it off to publish your own `public/404.html`. |

The `KEYHOLE_` prefix is not in Vite's `envPrefix`, so the key and password don't end up in client code
(the build fails if you set an `envPrefix` that would expose them).
Without a key, the build fails and suggests a fresh one.

### Your own landing page

Any HTML file with a `</body>`. The loader sets `<html data-keyhole="…">` so the page can style itself:
`loading`, `locked` (no key), `password` and `wrong-password` (a password is set), or `unsupported` (no
HTTPS or an old browser; shown only to visitors with a key or a password field). For a password field,
add a `<form id="keyhole-password">` with an `<input name="password">`. The built-in
[`landing.html`](src/landing.html) is a starting point.

## What it protects, and what it doesn't

It protects content from anyone without the link or password, including search engines and anyone
reading the public files.

It does **not** protect against:

- **Weak passwords.** Anyone can download the page and guess passwords offline. Each guess costs
  600,000 PBKDF2 rounds, which slows guessing but doesn't stop it. Use a long passphrase, or links only.
- **The host or build machine.** A malicious or compromised host could replace the loader and capture
  the key or password on someone's next visit.
- **Anyone with the link or password.** This is a shared secret, not access control. Anyone holding it
  can read everything and keep a copy.
- **Old copies after a key change.** A new key protects new builds. A page someone saved earlier
  still opens with the old key or password.
- **Revoking with a new password.** The password only unlocks the link key, so changing it doesn't
  lock anyone out: browsers that saved the key, and anyone who recovered it, still open new builds.
  To cut off access, change `KEYHOLE_KEY` (and the password) and redeploy.
- **Other pages on the same origin.** Browsers isolate storage by origin, not by path, so every page on
  `me.github.io` can read the saved key (and load the page and read the app). Use your own (sub)domain
  if other sites share the origin, or set `remember: false`.
- **The browser.** The key stays in history entries created before it was removed, in chats where the
  link was pasted, and in storage on devices where it was used. App scripts run in the same page as
  the loader and could read it.
- **Metadata.** The size of the encrypted app and the fact that something encrypted is served.
- **Secrets in your app**, such as API keys. Anyone who can open it can read them.
- **Anything outside the build:** data your app fetches at runtime, external assets, and your source
  repository (keep it private if the source is private).

## Supported apps

One HTML entry, rendered in the browser (an SPA), fully bundled. The plugin forces one JS chunk, one
inlined stylesheet and inlined assets, and warns when it overrides your `sourcemap`, `manifest` or chunk
settings. The build fails with a list of files if anything else would be published unencrypted, such as
`public/` files you didn't list in `publish`, stale files, or extra chunks.

- **Workers:** import them with `?worker&inline`. Service workers aren't supported.
- **Not needed:** `@vitejs/plugin-legacy` (the loader needs a modern browser) and compression plugins
  (the app is already gzipped).
- **Frameworks that render their own HTML** (SvelteKit, Astro, SSR) aren't supported.
- **SVG sprites in `public/`** (`<use href="/icons.svg#x">`) need `publish: ['icons.svg']`; browsers
  don't allow `<use>` with inlined `data:` URLs.
- **Your app starts after the page has loaded**, so `DOMContentLoaded` and `load` have already fired.
  Start your app from the entry module, as React, Vue and Svelte templates do. Other `<script>` tags in
  your `index.html` run in order before it (`async` ones don't wait).
- **Hash-based routers** (`#/about`) can't share a URL with `#key=…`, but work once the key is saved.
  Path-based routing needs an absolute `base` (like `/my-site/`).

## Content Security Policy

The plugin emits no CSP. If your host lets you set headers (e.g. `_headers`, added to `publish`), this
works with the loader:

```
default-src 'self'; script-src 'self' 'unsafe-inline' blob:; style-src 'self' 'unsafe-inline';
img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' data:; base-uri 'none'; object-src 'none'
```

Apps that use WebAssembly also need `'wasm-unsafe-eval'` in `script-src`.

## Format

[`FORMAT.md`](FORMAT.md) describes the encryption: AES-256-GCM with a versioned header, and PBKDF2 for
the optional password. [`src/core.ts`](src/core.ts) implements it with WebCrypto only.
