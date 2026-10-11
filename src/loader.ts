// Browser loader, inlined into the public index.html by the plugin.
// Takes the key from #key=… (or storage), downloads and decrypts the payload, swaps in the app's
// document and imports its JS from a Blob URL. Without a working key the landing page stays.
import { KeyholeError, MAX_ENVELOPE_BYTES, equalBytes, keyId, openPayload, parseKey, readBounded, readHeader } from './core.ts';
import type { Payload } from './core.ts';

interface Config {
  /** Absolute path of the encrypted payload, e.g. /my-site/assets/keyhole-1a2b3c4d.bin */
  payload: string;
  /** Storage entry name, namespaced by base path because sites on one origin share storage. */
  storageKey: string;
  remember: 'local' | 'session' | 'none';
}

type State = 'loading' | 'landing' | 'retry';

const config: Config = JSON.parse(document.getElementById('keyhole-config')!.textContent!);
/** sessionStorage entry that stops automatic reloads from looping. */
const RELOADED_AT = `${config.storageKey}:reloaded`;
let busy = false;
let running = false;
/** Keys from the current attempt, kept in memory so Retry works even before anything is saved. */
let lastKeys: string[] = [];
/** What Retry does: download again in place, or reload the page to get the current HTML. */
let retryAction: 'again' | 'reload' = 'again';

function show(state: State): void {
  document.documentElement.dataset.keyhole = state;
  const retry = document.getElementById('keyhole-retry');
  if (retry) retry.hidden = state !== 'retry';
}

function offerRetry(action: 'again' | 'reload'): void {
  retryAction = action;
  show('retry');
}

// ---- storage ----

function storage(kind: 'local' | 'session'): Storage | null {
  try {
    return kind === 'local' ? localStorage : sessionStorage;
  } catch {
    return null; // blocked storage: links still work, reloads show the landing page
  }
}

function storedKey(): string | null {
  if (config.remember === 'none') return null;
  try {
    return storage(config.remember)?.getItem(config.storageKey) ?? null;
  } catch {
    return null;
  }
}

function saveKey(key: string): void {
  if (config.remember === 'none') return;
  try {
    storage(config.remember)?.setItem(config.storageKey, key);
  } catch {}
}

function forgetKey(): void {
  for (const kind of ['local', 'session'] as const) {
    try {
      storage(kind)?.removeItem(config.storageKey);
    } catch {}
  }
}

// ---- URL ----

/** Read #key=… or #logout and remove it from the address bar before the app runs. */
function takeFragment(): { key?: string; logout?: boolean } {
  const hash = location.hash;
  const match = /^#key=(.*)$/.exec(hash);
  if (!match && hash !== '#logout') return {};
  history.replaceState(history.state, '', location.pathname + location.search);
  return match ? { key: match[1] } : { logout: true };
}

/** Reload the page, carrying the key in the fragment so it survives even if it was never saved. */
function reloadWithKey(): void {
  const key = lastKeys[0];
  if (key) history.replaceState(history.state, '', `${location.pathname}${location.search}#key=${key}`);
  location.reload();
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

/** The payload this page points to is gone or in another format: the page predates the current build. */
class StalePage extends Error {}

async function download(): Promise<Uint8Array> {
  const response = await fetch(config.payload, { cache: 'no-cache', credentials: 'same-origin' });
  if (response.status === 404 || response.status === 410) throw new StalePage(`payload: HTTP ${response.status}`);
  if (!response.ok || !response.body) throw new Error(`payload: HTTP ${response.status}`);
  return readBounded(response.body, MAX_ENVELOPE_BYTES);
}

/** Reload once to fetch the current HTML. If that already happened in the last minute, offer Retry. */
function recoverStalePage(): void {
  try {
    const session = sessionStorage;
    if (Date.now() - Number(session.getItem(RELOADED_AT)) > 60_000) {
      session.setItem(RELOADED_AT, String(Date.now()));
      return reloadWithKey();
    }
  } catch {}
  offerRetry('reload');
}

async function unlock(keys: string[]): Promise<void> {
  if (busy || running) return;
  busy = true;
  lastKeys = keys;
  show('loading');
  try {
    let envelope: Uint8Array;
    let header;
    try {
      envelope = await download();
      header = readHeader(envelope);
    } catch (error) {
      // Never forget the key here. A missing file or unknown version means this page is outdated;
      // anything else (offline, server error, damaged file) is worth trying again in place.
      console.warn('keyhole:', error);
      const stale = error instanceof StalePage || (error instanceof KeyholeError && error.kind === 'unsupported-version');
      return stale ? recoverStalePage() : offerRetry('again');
    }

    // Pick the key this file was encrypted with. A saved key that doesn't match is stale: forget it.
    let match: { text: string; raw: Uint8Array } | null = null;
    for (const text of keys) {
      const raw = parseKey(text);
      if (raw && equalBytes(await keyId(raw), header.keyId)) {
        match = { text, raw };
        break;
      }
      if (text === storedKey()) forgetKey();
    }
    if (!match) return show('landing');

    let payload: Payload;
    try {
      payload = await openPayload(envelope, match.raw);
    } catch (error) {
      // The key ID matched, so this is a damaged file, not a wrong key: keep the key.
      console.warn('keyhole:', error);
      return offerRetry('again');
    }
    saveKey(match.text);
    try {
      sessionStorage.removeItem(RELOADED_AT);
    } catch {}
    running = true;
    await run(payload);
  } finally {
    busy = false;
  }
}

/** Replace this document with the app's, then run the app's module. */
async function run(payload: Payload): Promise<void> {
  const landing = document.documentElement;
  const app = new DOMParser().parseFromString(payload.html, 'text/html').documentElement;
  document.replaceChild(document.adoptNode(app), landing);
  const url = URL.createObjectURL(new Blob([payload.js], { type: 'text/javascript' }));
  try {
    await import(url);
  } catch (error) {
    // The app threw while starting. Put the landing page back so the visitor isn't left on a blank page.
    console.error('keyhole: the app failed to start', error);
    document.replaceChild(landing, document.documentElement);
    running = false;
    offerRetry('reload');
  } finally {
    URL.revokeObjectURL(url);
  }
}

function start(fromUrl?: string): void {
  const keys = [fromUrl, storedKey()].filter((k, i, all): k is string => !!k && all.indexOf(k) === i);
  if (keys.length === 0) return show('landing');
  if (!supported()) return show('landing');
  void unlock(keys);
}

function main(): void {
  document.getElementById('keyhole-retry')?.addEventListener('click', () =>
    retryAction === 'reload' ? reloadWithKey() : void unlock(lastKeys),
  );

  // A key or logout link for the page that is already open only changes the fragment.
  addEventListener('hashchange', () => {
    const fragment = takeFragment();
    if (fragment.logout) {
      forgetKey();
      location.reload();
    } else if (fragment.key && !running) {
      start(fragment.key);
    }
  });

  const fragment = takeFragment();
  if (fragment.logout) forgetKey();
  start(fragment.key);
}

main();
