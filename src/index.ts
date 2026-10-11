// The Vite plugin. During `vite build` it turns the app's output into index.html (landing page, inline
// loader and the encrypted app) and 404.html (the same, for deep links). `vite dev` is untouched.
import { readFileSync } from 'node:fs';
import { readdir, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { loadEnv } from 'vite';
import type { Plugin, ResolvedConfig, Rolldown, UserConfig } from 'vite';
import { generateKey, parseKey, sealPayload, wrapKey } from './core.ts';
import type { WrappedKey } from './core.ts';

export interface KeyholeOptions {
  /** 43-character base64url key. Defaults to KEYHOLE_KEY from the environment or .env files. */
  key?: string;
  /** Also let visitors unlock with this password. Defaults to KEYHOLE_PASSWORD; without one, links only. */
  password?: string;
  /** Path (from the Vite root) to your own landing page HTML. Must contain </body>. */
  landing?: string;
  /** Keep the key in localStorage after unlocking, so later visits open directly. Default true. */
  remember?: boolean;
  /** Also write 404.html so hosts like GitHub Pages serve the page for deep links. Default true. */
  spaFallback?: boolean;
  /**
   * Files that may be published unencrypted, relative to the output folder: public/ files or assets
   * other plugins emit, e.g. ['favicon.svg', 'CNAME', '_headers']. A trailing '/' allows a whole folder.
   */
  publish?: string[];
}

export default function keyhole(options: KeyholeOptions = {}): Plugin {
  const remember = options.remember ?? true;
  const spaFallback = options.spaFallback ?? true;
  const publish = (options.publish ?? []).map((p) => p.replace(/^\.?\//, ''));
  const published = (file: string) => publish.some((p) => (p.endsWith('/') ? file.startsWith(p) : file === p));
  let key: Uint8Array;
  let wrapped: WrappedKey | undefined;
  let config: ResolvedConfig;
  let outDir: string;
  let landing: string;
  let loader: string;
  let overridden: string[] = [];
  let sealedBytes = 0;

  return {
    name: 'vite-plugin-keyhole',
    apply: 'build',
    enforce: 'post',

    config(user) {
      overridden = ignoredSettings(user);
      // mergeConfig would append an output object to an array of outputs instead of merging into each one.
      const outputs = user.build?.rolldownOptions?.output;
      if (Array.isArray(outputs)) for (const output of outputs) output.codeSplitting = false;
      return {
        build: {
          // Everything must end up inside the one encrypted payload.
          assetsInlineLimit: () => true,
          cssCodeSplit: false,
          sourcemap: false,
          manifest: false,
          modulePreload: { polyfill: false },
          rolldownOptions: Array.isArray(outputs) ? {} : { output: { codeSplitting: false } },
        },
      };
    },

    async configResolved(resolved) {
      config = resolved;
      outDir = path.resolve(resolved.root, resolved.build.outDir);
      if (resolved.build.ssr || resolved.build.lib) {
        throw new Error('vite-plugin-keyhole: SSR and library builds are not supported.');
      }
      for (const setting of overridden) {
        resolved.logger.warn(`vite-plugin-keyhole: ignoring ${setting}: everything is encrypted into one file.`);
      }
      // Vite copies public/ before closeBundle can check the output, so refuse here, before anything is written.
      if (resolved.build.copyPublicDir && resolved.publicDir) {
        const files = await listFiles(resolved.publicDir, { allowMissing: true, skipGit: false });
        if (spaFallback && files.includes('404.html')) {
          throw new Error('vite-plugin-keyhole: spaFallback would overwrite public/404.html. Set spaFallback: false to publish your own.');
        }
        const unlisted = files.filter((f) => !published(f));
        if (unlisted.length) {
          throw new Error(
            `vite-plugin-keyhole: ${path.relative(resolved.root, resolved.publicDir)}/ would be copied unencrypted:\n  ${unlisted.join('\n  ')}\n` +
              `To publish them as they are, add keyhole({ publish: ${JSON.stringify([...publish, ...unlisted])} }).\n` +
              'To encrypt them, move them into src/ and import them. To leave them out, remove them or set build.copyPublicDir to false.',
          );
        }
      }

      // As long as no envPrefix matches KEYHOLE_, Vite never exposes these to client code.
      const exposing = [resolved.envPrefix ?? []].flat().filter((p) => 'KEYHOLE_KEY'.startsWith(p) || 'KEYHOLE_PASSWORD'.startsWith(p));
      if (exposing.length) throw new Error(`vite-plugin-keyhole: envPrefix ${JSON.stringify(exposing)} would expose the key to client code.`);
      const env = loadEnv(resolved.mode, resolved.envDir, 'KEYHOLE_');
      const keyText = (options.key ?? env.KEYHOLE_KEY)?.trim();
      const help = `Set KEYHOLE_KEY, for example in .env.production.local:\n  KEYHOLE_KEY=${generateKey()}`;
      if (!keyText) throw new Error(`vite-plugin-keyhole: no key. ${help}`);
      const parsed = parseKey(keyText);
      if (!parsed) throw new Error(`vite-plugin-keyhole: KEYHOLE_KEY is not a 43-character base64url key. ${help}`);
      key = parsed;
      const password = options.password ?? env.KEYHOLE_PASSWORD;
      wrapped = password ? await wrapKey(key, password) : undefined;

      landing = options.landing
        ? readFileSync(path.resolve(resolved.root, options.landing), 'utf8')
        : readFileSync(new URL('./landing.html', import.meta.url), 'utf8');
      if (!/<\/body>/i.test(landing)) throw new Error('vite-plugin-keyhole: the landing page needs a </body> tag.');
      loader = readFileSync(new URL('./loader.iife.js', import.meta.url), 'utf8');
    },

    outputOptions(output) {
      // Runs before Vite empties the output folder and copies public/, for every output and after other plugins.
      // closeBundle only checks build.outDir, so writing anywhere else would skip the plaintext check.
      // Vite resolves a relative dir from the root but Rolldown from the working directory: both must match.
      const elsewhere = output.dir && (path.resolve(config.root, output.dir) !== outDir || path.resolve(output.dir) !== outDir);
      if (output.file || elsewhere) {
        throw new Error('vite-plugin-keyhole: set build.outDir instead of overriding the output dir or file.');
      }
    },

    generateBundle: {
      // After Vite's own generateBundle hooks, which run after enforce: 'post' plugins and still rewrite
      // chunks (e.g. the __VITE_PRELOAD__ marker of dynamic imports). Sealing earlier would encrypt unfinished code.
      order: 'post',
      async handler(_output, bundle) {
        if (spaFallback && bundle['404.html']) this.error('vite-plugin-keyhole: spaFallback would overwrite the 404.html another plugin emits. Set spaFallback: false to publish it.');
        const files = Object.values(bundle).filter((f) => !published(f.fileName));
        const chunks = files.filter((f): f is Rolldown.OutputChunk => f.type === 'chunk');
        const css = files.filter((f): f is Rolldown.OutputAsset => f.type === 'asset' && f.fileName.endsWith('.css'));
        const html = bundle['index.html'];
        const others = files.filter((f) => f !== html && f.type === 'asset' && !css.includes(f));
        if (chunks.length !== 1 || !chunks[0].isEntry || html?.type !== 'asset' || css.length > 1 || others.length > 0) {
          this.error(
            'vite-plugin-keyhole supports one HTML entry (index.html), one JS chunk and at most one CSS file, ' +
              `with every asset inlined. The build produced:\n  ${files.map((f) => f.fileName).join('\n  ')}\n` +
              'Common causes: workers (import them with ?worker&inline), @vitejs/plugin-legacy and compression ' +
              'plugins (not needed: the loader needs a modern browser and the app is already gzipped). ' +
              'Files that may stay unencrypted can be listed in the publish option.',
          );
        }

        // Restored HTML: the app's own index.html, entry script removed, stylesheet inlined.
        const entry = chunks[0];
        let appHtml = String(html.source);
        const script = tagPattern('script', 'src', entry.fileName, '\\s*</script>');
        if (!script.test(appHtml)) this.error(`vite-plugin-keyhole: can't find the <script> for ${entry.fileName} in index.html.`);
        appHtml = appHtml.replace(script, '');
        if (css[0]) {
          const link = tagPattern('link', 'href', css[0].fileName, '');
          if (!link.test(appHtml)) this.error(`vite-plugin-keyhole: can't find the <link> for ${css[0].fileName} in index.html.`);
          const style = `<style>${String(css[0].source).replace(/<\/style/gi, '<\\/style')}</style>`;
          appHtml = appHtml.replace(link, () => style);
        }
        const dangling = files.map((f) => f.fileName).filter((name) => name !== 'index.html' && appHtml.includes(name));
        if (dangling.length) this.error(`vite-plugin-keyhole: index.html still references ${dangling.join(', ')}.`);

        const envelope = await sealPayload({ html: appHtml, js: entry.code }, key);
        sealedBytes = envelope.length;
        for (const file of files) delete bundle[file.fileName];
        const publicHtml = publicPage(landing, loader, {
          payload: Buffer.from(envelope.buffer, envelope.byteOffset, envelope.byteLength).toString('base64url'),
          base: config.base,
          remember,
          password: wrapped,
        });
        this.emitFile({ type: 'asset', fileName: 'index.html', source: publicHtml });
        if (spaFallback) this.emitFile({ type: 'asset', fileName: '404.html', source: publicHtml });
      },
    },

    async closeBundle() {
      if (!sealedBytes || !config.build.write) return;
      // Check what actually landed on disk: catches stale files, source maps and anything another plugin wrote.
      const allowed = (f: string) => f === 'index.html' || (spaFallback && f === '404.html') || published(f);
      const extra = (await listFiles(outDir)).filter((f) => !allowed(f));
      if (extra.length) {
        throw new Error(
          `vite-plugin-keyhole: ${config.build.outDir} contains unencrypted files:\n  ${extra.join('\n  ')}\n` +
            'Keep build.emptyOutDir on, and list files that may stay unencrypted in the publish option.',
        );
      }
      config.logger.info(`vite-plugin-keyhole: encrypted the app (${(sealedBytes / 1024).toFixed(1)} kB)${wrapped ? ', password enabled' : ''}`);
    },
  };
}

/**
 * Settings the user chose that the plugin has to override, so it can say so instead of ignoring them
 * silently. Chunk settings are removed: Rolldown rejects them next to codeSplitting: false.
 */
function ignoredSettings(user: UserConfig): string[] {
  const outputs = [user.build?.rolldownOptions?.output ?? []].flat();
  const chunks = outputs.some((o) => o.manualChunks || o.advancedChunks);
  for (const output of outputs) {
    delete output.manualChunks;
    delete output.advancedChunks;
  }
  return [
    user.build?.sourcemap && 'build.sourcemap',
    user.build?.manifest && 'build.manifest',
    user.build?.cssCodeSplit && 'build.cssCodeSplit',
    chunks && 'manualChunks/advancedChunks',
  ].filter((s): s is string => !!s);
}

/** The public page: landing HTML + config + inline loader. Never derived from the app's HTML. */
function publicPage(landing: string, loader: string, settings: object): string {
  // test/plugin.test.ts checks that the built loader contains no "</script", so it is safe to inline.
  const json = JSON.stringify(settings).replace(/</g, '\\u003c');
  const tags = `<script type="application/json" id="keyhole-config">${json}</script>\n<script>${loader}</script>\n`;
  // Search the original string: toLowerCase() can change its length (e.g. 'İ'), shifting the index.
  const at = [...landing.matchAll(/<\/body>/gi)].at(-1)!.index;
  return landing.slice(0, at) + tags + landing.slice(at);
}

function tagPattern(tag: string, attr: string, fileName: string, tail: string): RegExp {
  const name = fileName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`<${tag}\\b[^>]*\\b${attr}="[^"]*${name}"[^>]*>${tail}\\s*`);
}

/**
 * Every file under `dir`, following symlinked folders (each real folder once, so loops end). By default skips
 * .git (a folder, or a file in a worktree), which Vite's emptyOutDir keeps. A broken symlink counts as a file.
 * Read errors throw, so the plaintext check never passes on a folder it couldn't read.
 */
async function listFiles(dir: string, { allowMissing = false, skipGit = true, prefix = '', seen = new Set<string>() } = {}): Promise<string[]> {
  let entries;
  try {
    seen.add(await realpath(dir));
    entries = await readdir(dir, { withFileTypes: true });
  } catch (error) {
    if (allowMissing && (error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
  const lists = await Promise.all(
    entries.map(async (entry) => {
      if (skipGit && entry.name === '.git') return [];
      const full = path.join(dir, entry.name);
      const isDir = entry.isDirectory() || (entry.isSymbolicLink() && (await stat(full).catch(() => null))?.isDirectory());
      if (!isDir) return [prefix + entry.name];
      const real = await realpath(full);
      if (seen.has(real)) return [];
      seen.add(real);
      return listFiles(full, { skipGit, prefix: `${prefix}${entry.name}/`, seen });
    }),
  );
  return lists.flat();
}
