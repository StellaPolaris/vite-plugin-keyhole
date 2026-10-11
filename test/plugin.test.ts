// Builds test/fixture with the published plugin (dist/) and checks the output files.
import { mkdirSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { build, createLogger } from 'vite';
import type { InlineConfig } from 'vite';
import { afterEach, describe, expect, it } from 'vitest';
import { base64UrlDecode, generateKey, openPayload, parseKey, unwrapKey } from '../src/core.ts';
import keyhole from '../dist/index.js';
import type { KeyholeOptions } from '../dist/index.js';

const root = path.join(import.meta.dirname, 'fixture');
const outDir = path.join(root, 'dist');
const publicDir = path.join(root, 'public');
const CANARY = 'KEYHOLE-CANARY-7f3a9c';
const TITLE = 'Fixture Secret Title';

function buildFixture(options: KeyholeOptions, extra: InlineConfig = {}) {
  return build({ root, base: '/my-site/', logLevel: 'silent', plugins: [keyhole(options)], ...extra });
}

/** The settings the plugin embedded in a built page. */
function pageConfig(file = 'index.html') {
  const html = readFileSync(path.join(outDir, file), 'utf8');
  return JSON.parse(/<script type="application\/json" id="keyhole-config">(.*?)<\/script>/s.exec(html)![1]);
}

function sealed(file = 'index.html'): Uint8Array {
  return base64UrlDecode(pageConfig(file).payload);
}

function listFiles(dir: string): string[] {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => path.relative(dir, path.join(e.parentPath, e.name)))
    .sort();
}

it('builds a loader that can be inlined in a <script>', () => {
  // publicPage inlines it as-is, so this is checked here, where the loader is built, not in every user's build.
  expect(readFileSync(path.join(import.meta.dirname, '..', 'dist', 'loader.iife.js'), 'utf8')).not.toMatch(/<\/script/i);
});

afterEach(() => {
  rmSync(publicDir, { recursive: true, force: true });
  delete process.env.KEYHOLE_KEY;
  delete process.env.KEYHOLE_PASSWORD;
});

describe('fixture build', () => {
  it('emits only index.html and 404.html, with the app encrypted inside', async () => {
    const key = generateKey();
    await buildFixture({ key });

    const files = listFiles(outDir);
    expect(files).toEqual(['404.html', 'index.html']);

    // Nothing readable leaks into any public file.
    for (const file of files) {
      const text = readFileSync(path.join(outDir, file), 'latin1');
      expect(text, file).not.toContain(CANARY);
      expect(text, file).not.toContain(TITLE);
      expect(text, file).not.toContain('css-canary-91b2');
    }

    const index = readFileSync(path.join(outDir, 'index.html'), 'utf8');
    expect(readFileSync(path.join(outDir, '404.html'), 'utf8')).toBe(index);
    expect(index).toContain('<title>Coming soon</title>');
    expect(pageConfig()).toMatchObject({ base: '/my-site/', remember: true });
    expect(pageConfig().password).toBeUndefined();

    // After decrypting, everything is there.
    const payload = await openPayload(sealed(), parseKey(key)!);
    expect(payload.html).toContain(`<title>${TITLE}</title>`);
    expect(payload.html).toMatch(/<style>[^<]*data:image\/svg\+xml[^<]*css-canary-91b2/);
    expect(payload.html).not.toMatch(/<script|<link/);
    expect(payload.js).toContain(CANARY);
    expect(payload.js).toContain('lazy-loaded');
    // Sealed only after Vite finished rewriting the chunk; a leftover marker throws when the app starts.
    expect(payload.js).not.toContain('__VITE_PRELOAD__');
    expect(payload.js).toContain('data:image/svg+xml');
  });

  it('reads KEYHOLE_KEY from the environment', async () => {
    const key = generateKey();
    process.env.KEYHOLE_KEY = key;
    await buildFixture({});
    await expect(openPayload(sealed(), parseKey(key)!)).resolves.toBeDefined();
  });

  it('lets a password unwrap the same key that links carry', async () => {
    const key = generateKey();
    process.env.KEYHOLE_PASSWORD = 'correct horse';
    await buildFixture({ key });
    const unwrapped = await unwrapKey(pageConfig().password, 'correct horse');
    expect(unwrapped).toEqual(parseKey(key));
    expect(readFileSync(path.join(outDir, 'index.html'), 'utf8')).not.toContain('correct horse');
  });

  it('says which of the user\'s settings it overrides', async () => {
    const warnings: string[] = [];
    const customLogger = { ...createLogger('silent'), warn: (msg: string) => void warnings.push(msg) };
    const manualChunks = (id: string) => (id.includes('lazy') ? 'lazy' : undefined);
    await buildFixture({ key: generateKey() }, { customLogger, build: { sourcemap: true, rolldownOptions: { output: { manualChunks } } } });
    expect(warnings.join('\n')).toMatch(/ignoring build\.sourcemap/);
    expect(warnings.join('\n')).toMatch(/ignoring manualChunks/);
    expect(listFiles(outDir)).toEqual(['404.html', 'index.html']);
  });

  it('applies codeSplitting: false to every output when output is an array', async () => {
    // mergeConfig would otherwise append a second output, and the user's would still split the lazy import.
    await buildFixture({ key: generateKey() }, { build: { rolldownOptions: { output: [{ entryFileNames: 'app.js' }] } } });
    expect(listFiles(outDir)).toEqual(['404.html', 'index.html']);
  });

  it('refuses to overwrite a public/404.html with spaFallback', async () => {
    mkdirSync(publicDir, { recursive: true });
    writeFileSync(path.join(publicDir, '404.html'), 'custom 404');
    await expect(buildFixture({ key: generateKey(), publish: ['404.html'] })).rejects.toThrow(/overwrite public\/404\.html/);
    await buildFixture({ key: generateKey(), publish: ['404.html'], spaFallback: false });
    expect(readFileSync(path.join(outDir, '404.html'), 'utf8')).toBe('custom 404');
  });

  it('follows symlinks in public/ without looping', async () => {
    mkdirSync(path.join(publicDir, 'icons'), { recursive: true });
    writeFileSync(path.join(publicDir, 'icons', 'a.svg'), '<svg/>');
    symlinkSync('..', path.join(publicDir, 'icons', 'loop'));
    symlinkSync('missing', path.join(publicDir, 'broken'));
    await expect(buildFixture({ key: generateKey() })).rejects.toThrow(/copied unencrypted:\s+broken\s+icons\/a\.svg\s+To publish/);
  });

  it('skips 404.html when spaFallback is off', async () => {
    await buildFixture({ key: generateKey(), spaFallback: false });
    expect(listFiles(outDir)).toEqual(['index.html']);
  });

  it('fails without a key or with a malformed one', async () => {
    // The error suggests a freshly generated key to paste.
    await expect(buildFixture({})).rejects.toThrow(/no key[\s\S]*KEYHOLE_KEY=[A-Za-z0-9_-]{43}/);
    await expect(buildFixture({ key: 'not-a-key' })).rejects.toThrow(/not a 43-character/);
  });

  it('fails when envPrefix would expose the key or password', async () => {
    await expect(buildFixture({ key: generateKey() }, { envPrefix: ['VITE_', 'KEY'] })).rejects.toThrow(/envPrefix \["KEY"\]/);
    await expect(buildFixture({ key: generateKey() }, { envPrefix: 'KEYHOLE_PASS' })).rejects.toThrow(/would expose/);
    await buildFixture({ key: generateKey() }, { envPrefix: ['VITE_', 'APP_'] });
  });

  it('fails when public/ files would be copied unencrypted', async () => {
    mkdirSync(publicDir, { recursive: true });
    writeFileSync(path.join(publicDir, 'robots.txt'), 'User-agent: *');
    rmSync(outDir, { recursive: true, force: true });
    await expect(buildFixture({ key: generateKey() })).rejects.toThrow(
      /copied unencrypted:\s+robots\.txt[\s\S]*publish: \["robots\.txt"\]/,
    );
    // Refused before Vite wrote anything.
    expect(() => readdirSync(outDir)).toThrow();
    // Allowed when public/ isn't copied.
    await buildFixture({ key: generateKey() }, { build: { copyPublicDir: false } });
    expect(listFiles(outDir)).toEqual(['404.html', 'index.html']);
  });

  it('publishes the files listed in publish, and nothing else', async () => {
    mkdirSync(path.join(publicDir, 'icons'), { recursive: true });
    writeFileSync(path.join(publicDir, 'CNAME'), 'example.com');
    writeFileSync(path.join(publicDir, 'icons', 'a.svg'), '<svg/>');
    await buildFixture({ key: generateKey(), publish: ['CNAME', 'icons/'] });
    expect(listFiles(outDir)).toEqual(['404.html', 'CNAME', 'icons/a.svg', 'index.html']);
    writeFileSync(path.join(publicDir, 'secret.txt'), 'private');
    await expect(buildFixture({ key: generateKey(), publish: ['CNAME', 'icons/'] })).rejects.toThrow(
      /copied unencrypted:\s+secret\.txt/,
    );
  });

  it('refuses an output destination other than build.outDir', async () => {
    const elsewhere = path.join(root, 'elsewhere');
    try {
      await expect(
        buildFixture({ key: generateKey() }, { build: { rolldownOptions: { output: { dir: elsewhere } } } }),
      ).rejects.toThrow(/set build\.outDir/);
      expect(() => readdirSync(elsewhere)).toThrow();
      // Vite resolves 'dist' from the root (fixture/dist, the outDir), Rolldown from the working directory.
      await expect(
        buildFixture({ key: generateKey() }, { build: { rolldownOptions: { output: { dir: 'dist' } } } }),
      ).rejects.toThrow(/set build\.outDir/);
    } finally {
      rmSync(elsewhere, { recursive: true, force: true });
    }
  });

  it('ignores .git in the output folder, as a folder or a worktree file', async () => {
    const git = path.join(outDir, '.git');
    try {
      await buildFixture({ key: generateKey() });
      writeFileSync(git, 'gitdir: ../.git/worktrees/dist');
      await buildFixture({ key: generateKey() });
      rmSync(git);
      mkdirSync(git);
      writeFileSync(path.join(git, 'HEAD'), 'ref: refs/heads/gh-pages');
      await buildFixture({ key: generateKey() });
    } finally {
      rmSync(git, { recursive: true, force: true });
    }
  });

  it('uses a custom landing page', async () => {
    const landing = path.join(outDir, '..', 'custom-landing.html');
    // 'İ' grows when lowercased, which used to shift the insert position.
    writeFileSync(landing, '<html><body><p>İİİ custom landing</p></BODY></html>');
    try {
      await buildFixture({ key: generateKey(), landing: 'custom-landing.html' });
      const index = readFileSync(path.join(outDir, 'index.html'), 'utf8');
      expect(index).toMatch(/custom landing<\/p><script type="application\/json" id="keyhole-config">/);
      expect(index).toMatch(/<\/script>\n<\/BODY><\/html>$/);
    } finally {
      rmSync(landing);
    }
  });
});
