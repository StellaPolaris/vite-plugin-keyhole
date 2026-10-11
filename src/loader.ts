// Browser loader, inlined into the public index.html by the plugin together with the encrypted app.
// Takes the key from #key=…, storage or a password, decrypts the app, swaps in its document and runs it.
// Without a working key the landing page stays. The landing page styles itself from
// <html data-keyhole="loading | locked | password | wrong-password | unsupported">.
import { base64UrlDecode, base64UrlEncode, openPayload, parseKey, unwrapKey } from './core.ts';
import type { Payload, WrappedKey } from './core.ts';

interface Config {
  /** The encrypted app, base64url. */
  payload: string;
  /** Vite's base. Namespaces the storage entry, because sites on one origin share storage. */
  base: string;
  remember: boolean;
  /** The key, encrypted under the site password. Present only when a password is set. */
  password?: WrappedKey;
}

type State = 'loading' | 'locked' | 'password' | 'wrong-password' | 'unsupported';

const config: Config = JSON.parse(document.getElementById('keyhole-config')!.textContent!);
// A relative base ('./') resolves to this site's folder, so two such sites on one origin don't share an entry.
const storageKey = `keyhole:${new URL(config.base, location.href).pathname}`;

function show(state: State): void {
  document.documentElement.dataset.keyhole = state;
}

// ---- storage (blocked storage is fine: links still work, reloads show the landing page) ----

function storedKey(): string | null {
  // With remember off, also drop a key that an earlier build saved.
  if (!config.remember) forgetKey();
  try {
    return localStorage.getItem(storageKey);
  } catch {
    return null;
  }
}

function saveKey(key: Uint8Array): void {
  try {
    if (config.remember) localStorage.setItem(storageKey, base64UrlEncode(key));
  } catch {}
}

function forgetKey(): void {
  try {
    localStorage.removeItem(storageKey);
  } catch {}
}

// ---- unlock ----

function supported(): boolean {
  try {
    new DecompressionStream('gzip');
    return isSecureContext && !!crypto.subtle && typeof DOMParser === 'function';
  } catch {
    return false;
  }
}

/** Decrypt and run the app with `key`. Returns false if the key doesn't open it. */
async function open(key: Uint8Array | null): Promise<boolean> {
  if (!key) return false;
  let payload: Payload;
  try {
    payload = await openPayload(base64UrlDecode(config.payload), key);
  } catch (error) {
    console.warn('keyhole:', error);
    return false;
  }
  saveKey(key);
  await run(payload);
  return true;
}

/** Replace this document with the app's, run its scripts as the browser would have, then import its module. */
async function run(payload: Payload): Promise<void> {
  const app = new DOMParser().parseFromString(payload.html, 'text/html').documentElement;
  document.replaceChild(document.adoptNode(app), document.documentElement);
  // Parsed scripts never run. Re-create them so analytics or theme snippets in index.html work as usual.
  // As during parsing, defer and module scripts run after the others, in order (async ones don't wait).
  // Judge by the originals' attributes: a created script reports async = true by default.
  const deferred: HTMLScriptElement[] = [];
  for (const old of document.querySelectorAll('script')) {
    if (!old.async && (isModule(old) || (old.defer && old.src))) deferred.push(old);
    else await rerun(old);
  }
  for (const old of deferred) await rerun(old);
  const url = URL.createObjectURL(new Blob([payload.js], { type: 'text/javascript' }));
  try {
    await import(url);
  } finally {
    URL.revokeObjectURL(url);
  }
}

function isModule(script: HTMLScriptElement): boolean {
  return script.type.trim().toLowerCase() === 'module';
}

/** Run a parsed script, waiting for it if it is external and not async: created scripts run whenever they load. */
async function rerun(old: HTMLScriptElement): Promise<void> {
  const script = document.createElement('script');
  for (const { name, value } of old.attributes) script.setAttribute(name, value);
  script.text = old.text;
  // Scripts the browser won't run (nomodule, a non-JavaScript type) are never fetched and fire no load event.
  const classic = /^((text|application)\/(x-)?(java|ecma)script|text\/jscript)?$/i.test(old.type.trim()) && !old.noModule;
  const loaded = old.src && !old.async && (classic || isModule(old)) && new Promise((done) => (script.onload = script.onerror = done));
  old.replaceWith(script);
  await loaded;
}

async function unlockWithPassword(password: string): Promise<void> {
  show('loading');
  if (!(await open(await unwrapKey(config.password!, password)))) show('wrong-password');
}

async function main(): Promise<void> {
  // A key or logout link for the page that is already open only changes the fragment: start over.
  addEventListener('hashchange', () => /^#(key=|logout$)/.test(location.hash) && location.reload());

  if (!supported()) {
    // Leave #key=… in the address bar: the same link works over HTTPS or in a newer browser.
    // Only a visitor who has a key, or who is asked for a password, learns why nothing opened.
    const hasKey = location.hash.startsWith('#key=') || !!storedKey() || !!config.password;
    return show(hasKey ? 'unsupported' : 'locked');
  }

  // Remove #key=… or #logout from the address bar before the app runs.
  const hash = location.hash;
  const fromUrl = /^#key=(.*)$/.exec(hash)?.[1];
  if (fromUrl !== undefined || hash === '#logout') history.replaceState(history.state, '', location.pathname + location.search);
  if (hash === '#logout') forgetKey();

  document.getElementById('keyhole-password')?.addEventListener('submit', (event) => {
    event.preventDefault();
    const input = (event.target as HTMLFormElement).elements.namedItem('password') as HTMLInputElement | null;
    if (input?.value) void unlockWithPassword(input.value);
  });

  // A broken link (cut off, or for another site) falls back to the saved key.
  if (fromUrl) {
    show('loading');
    if (await open(parseKey(fromUrl))) return;
  }
  const saved = storedKey();
  if (saved) {
    show('loading');
    if (saved !== fromUrl && (await open(parseKey(saved)))) return;
    // A saved key that no longer opens the app is from before a key change.
    forgetKey();
  }
  show(config.password ? 'password' : 'locked');
}

void main();
