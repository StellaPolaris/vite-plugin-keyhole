// Browser loader, inlined into the public index.html by the plugin together with the encrypted app.
// Takes the key from #key=…, storage or a password, decrypts the app, swaps in its document and runs it.
// Without a working key the landing page stays. The landing page styles itself from
// <html data-keyhole="loading | locked | password | wrong-password | unsupported">.
import { base64UrlDecode, base64UrlEncode, openPayload, parseKey, unwrapKey } from './core.ts';
import type { Payload, WrappedKey } from './core.ts';

interface Config {
  /** The encrypted app, base64url. */
  payload: string;
  /** Storage entry name, namespaced by base path because sites on one origin share storage. */
  storageKey: string;
  remember: boolean;
  /** The key, encrypted under the site password. Present only when a password is set. */
  password?: WrappedKey;
}

type State = 'loading' | 'locked' | 'password' | 'wrong-password' | 'unsupported';

const config: Config = JSON.parse(document.getElementById('keyhole-config')!.textContent!);

function show(state: State): void {
  document.documentElement.dataset.keyhole = state;
}

// ---- storage (blocked storage is fine: links still work, reloads show the landing page) ----

function storedKey(): string | null {
  try {
    return config.remember ? localStorage.getItem(config.storageKey) : null;
  } catch {
    return null;
  }
}

function saveKey(key: string): void {
  try {
    if (config.remember) localStorage.setItem(config.storageKey, key);
  } catch {}
}

function forgetKey(): void {
  try {
    localStorage.removeItem(config.storageKey);
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
async function open(key: string): Promise<boolean> {
  const raw = parseKey(key);
  if (!raw) return false;
  let payload: Payload;
  try {
    payload = await openPayload(base64UrlDecode(config.payload), raw);
  } catch (error) {
    console.warn('keyhole:', error);
    return false;
  }
  saveKey(key);
  await run(payload);
  return true;
}

/** Replace this document with the app's, run its scripts in order, then import its module. */
async function run(payload: Payload): Promise<void> {
  const app = new DOMParser().parseFromString(payload.html, 'text/html').documentElement;
  document.replaceChild(document.adoptNode(app), document.documentElement);
  // Parsed scripts never run. Re-create them so analytics or theme snippets in index.html work as usual.
  for (const old of document.querySelectorAll('script')) {
    const script = document.createElement('script');
    for (const { name, value } of old.attributes) script.setAttribute(name, value);
    script.text = old.text;
    // Judge by the original's attributes: a created script reports async = true by default.
    const blocking = old.src && !old.async && !old.defer && old.type !== 'module';
    const loaded = blocking && new Promise((done) => (script.onload = script.onerror = done));
    old.replaceWith(script);
    await loaded;
  }
  const url = URL.createObjectURL(new Blob([payload.js], { type: 'text/javascript' }));
  try {
    await import(url);
  } finally {
    URL.revokeObjectURL(url);
  }
}

async function unlockWithPassword(password: string): Promise<void> {
  show('loading');
  const key = await unwrapKey(config.password!, password);
  if (!(key && (await open(base64UrlEncode(key))))) show('wrong-password');
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

  const key = fromUrl ?? storedKey();
  if (key) {
    show('loading');
    if (await open(key)) return;
    // A saved key that no longer opens the app is from before a key change.
    if (fromUrl === undefined) forgetKey();
  }
  show(config.password ? 'password' : 'locked');
}

void main();
