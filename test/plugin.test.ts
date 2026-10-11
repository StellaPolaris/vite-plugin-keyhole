// Builds test/fixture with the published plugin (dist/) and checks the output files.
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { build } from 'vite';
import type { InlineConfig } from 'vite';
import { afterEach, describe, expect, it } from 'vitest';
import { generateKey, openPayload, parseKey } from '../dist/core.js';
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

function listFiles(dir: string): string[] {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => path.relative(dir, path.join(e.parentPath, e.name)))
    .sort();
}

afterEach(() => {
  rmSync(publicDir, { recursive: true, force: true });
  delete process.env.KEYHOLE_KEY;
});

describe('fixture build', () => {
  it('emits only the landing page, 404.html and the encrypted payload', async () => {
    const key = generateKey();
    await buildFixture({ key });

    const files = listFiles(outDir);
    expect(files).toHaveLength(3);
    expect(files).toContain('index.html');
    expect(files).toContain('404.html');
    const bin = files.find((f) => /^assets\/keyhole-[0-9a-f]{8}\.bin$/.test(f))!;
    expect(bin).toBeDefined();

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
    expect(index).toContain(`"payload":"/my-site/${bin}"`);
    expect(index).toContain('"storageKey":"keyhole:/my-site/"');

    // After decrypting, everything is there.
    const payload = await openPayload(readFileSync(path.join(outDir, bin)), parseKey(key)!);
    expect(payload.html).toContain(`<title>${TITLE}</title>`);
    expect(payload.html).toMatch(/<style>[^<]*data:image\/svg\+xml[^<]*css-canary-91b2/);
    expect(payload.html).not.toMatch(/<script|<link/);
    expect(payload.js).toContain(CANARY);
    expect(payload.js).toContain('lazy-loaded');
    expect(payload.js).toContain('data:image/svg+xml');
  });

  it('reads KEYHOLE_KEY from the environment', async () => {
    const key = generateKey();
    process.env.KEYHOLE_KEY = key;
    await buildFixture({});
    const bin = listFiles(outDir).find((f) => f.endsWith('.bin'))!;
    await expect(openPayload(readFileSync(path.join(outDir, bin)), parseKey(key)!)).resolves.toBeDefined();
  });

  it('skips 404.html when spaFallback is off', async () => {
    await buildFixture({ key: generateKey(), spaFallback: false });
    expect(listFiles(outDir)).toHaveLength(2);
  });

  it('fails without a key or with a malformed one', async () => {
    await expect(buildFixture({})).rejects.toThrow(/no key/);
    await expect(buildFixture({ key: 'not-a-key' })).rejects.toThrow(/not a 43-character/);
  });

  it('fails when public/ files would be copied unencrypted', async () => {
    mkdirSync(publicDir, { recursive: true });
    writeFileSync(path.join(publicDir, 'robots.txt'), 'User-agent: *');
    await expect(buildFixture({ key: generateKey() })).rejects.toThrow(/unencrypted files:\s+robots\.txt/);
  });

  it('uses a custom landing page', async () => {
    const landing = path.join(outDir, '..', 'custom-landing.html');
    writeFileSync(landing, '<html><body><p>custom landing</p></body></html>');
    try {
      await buildFixture({ key: generateKey(), landing: 'custom-landing.html' });
      const index = readFileSync(path.join(outDir, 'index.html'), 'utf8');
      expect(index).toMatch(/custom landing<\/p><script type="application\/json" id="keyhole-config">/);
    } finally {
      rmSync(landing);
    }
  });
});
