// The Vite plugin. During `vite build` it turns the app's output into three public files:
// index.html (landing page + inline loader), 404.html (the same, for deep links) and one
// encrypted assets/keyhole-<hash>.bin holding the app's HTML, CSS and JS. `vite dev` is untouched.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { loadEnv } from 'vite';
import type { Plugin, ResolvedConfig, Rolldown } from 'vite';
import { KeyholeError, MAX_ENVELOPE_BYTES, MAX_PLAINTEXT_BYTES, parseKey, sealPayload } from './core.ts';

export interface KeyholeOptions {
  /** 43-character base64url key. Defaults to KEYHOLE_KEY from the environment or .env files. */
  key?: string;
  /** Path (from the Vite root) to your own landing page HTML. Must contain </body>. */
  landing?: string;
  /** Where the browser keeps the key after a successful unlock. Default 'local'. */
  remember?: 'local' | 'session' | 'none';
  /** Also write 404.html so hosts like GitHub Pages serve the loader for deep links. Default true. */
  spaFallback?: boolean;
}

const KEY_HELP = 'Create one with `npx keyhole keygen` and set KEYHOLE_KEY (for example in .env.production.local).';

export default function keyhole(options: KeyholeOptions = {}): Plugin {
  const remember = options.remember ?? 'local';
  const spaFallback = options.spaFallback ?? true;
  let keyText: string | undefined;
  let key: Uint8Array;
  let config: ResolvedConfig;
  let landing: string;
  let payloadFile: string | undefined;
  let payloadBytes = 0;

  return {
    name: 'vite-plugin-keyhole',
    apply: 'build',
    enforce: 'post',

    config(user, env) {
      const root = path.resolve(user.root ?? process.cwd());
      // The KEYHOLE_ prefix is not in envPrefix, so Vite never exposes the key to client code.
      keyText =
        options.key ??
        (user.envDir === false
          ? process.env.KEYHOLE_KEY
          : loadEnv(env.mode, path.resolve(root, user.envDir ?? ''), 'KEYHOLE_').KEYHOLE_KEY);
      return {
        build: {
          // Everything must end up inside the one encrypted payload.
          assetsInlineLimit: () => true,
          cssCodeSplit: false,
          sourcemap: false,
          modulePreload: { polyfill: false },
          rolldownOptions: { output: { codeSplitting: false } },
        },
      };
    },

    async configResolved(resolved) {
      config = resolved;
      if (resolved.build.ssr || resolved.build.lib) {
        throw new Error('vite-plugin-keyhole: SSR and library builds are not supported.');
      }
      // Vite copies public/ before closeBundle can check the output, so refuse here, before anything is written.
      if (resolved.build.copyPublicDir && resolved.publicDir) {
        const publicFiles = await listFiles(resolved.publicDir, { allowMissing: true, skipGit: false });
        if (publicFiles.length) {
          throw new Error(
            `vite-plugin-keyhole: ${path.relative(resolved.root, resolved.publicDir)}/ would be copied unencrypted:\n  ${publicFiles.join('\n  ')}\n` +
              'Remove these files or set build.copyPublicDir to false.',
          );
        }
      }
      if (!keyText) throw new Error(`vite-plugin-keyhole: no key. ${KEY_HELP}`);
      const parsed = parseKey(keyText.trim());
      if (!parsed) throw new Error(`vite-plugin-keyhole: the key is not a 43-character base64url key. ${KEY_HELP}`);
      key = parsed;
      if (!resolved.base.startsWith('/') && !/^https?:/.test(resolved.base)) {
        resolved.logger.warn(`vite-plugin-keyhole: base "${resolved.base}" is relative, so deep links can't find the payload.`);
      }
      landing = options.landing
        ? readFileSync(path.resolve(resolved.root, options.landing), 'utf8')
        : readFileSync(new URL('./landing.html', import.meta.url), 'utf8');
      if (!/<\/body>/i.test(landing)) throw new Error('vite-plugin-keyhole: the landing page needs a </body> tag.');
    },

    outputOptions(output) {
      // Runs before Vite empties the output folder and copies public/, for every output and after other plugins.
      // closeBundle only checks build.outDir, so writing anywhere else would skip the plaintext check.
      const outDir = path.resolve(config.root, config.build.outDir);
      if (output.file || (output.dir && path.resolve(config.root, output.dir) !== outDir)) {
        throw new Error('vite-plugin-keyhole: set build.outDir instead of overriding the output dir or file.');
      }
    },

    generateBundle: {
      // After Vite's own generateBundle hooks, which run after enforce: 'post' plugins and still rewrite
      // chunks (e.g. the __VITE_PRELOAD__ marker of dynamic imports). Sealing earlier would encrypt unfinished code.
      order: 'post',
      async handler(_output, bundle) {
        const files = Object.values(bundle);
        const chunks = files.filter((f): f is Rolldown.OutputChunk => f.type === 'chunk');
        const css = files.filter((f): f is Rolldown.OutputAsset => f.type === 'asset' && f.fileName.endsWith('.css'));
        const html = bundle['index.html'];
        const others = files.filter((f) => f !== html && f.type === 'asset' && !css.includes(f));
        if (chunks.length !== 1 || !chunks[0].isEntry || html?.type !== 'asset' || css.length > 1 || others.length > 0) {
          this.error(
            'vite-plugin-keyhole supports one HTML entry (index.html), one JS chunk and at most one CSS file, ' +
              `with every asset inlined. The build produced:\n  ${files.map((f) => f.fileName).join('\n  ')}`,
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

        let envelope: Uint8Array<ArrayBuffer>;
        try {
          envelope = await sealPayload({ html: appHtml, js: entry.code }, key);
        } catch (error) {
          if (!(error instanceof KeyholeError && error.kind === 'too-large')) throw error;
          this.error(`vite-plugin-keyhole: the app is over the ${kB(MAX_PLAINTEXT_BYTES)} limit the loader can unpack.`);
        }
        if (envelope.length > MAX_ENVELOPE_BYTES) {
          this.error(`vite-plugin-keyhole: the encrypted payload is ${kB(envelope.length)}, over the ${kB(MAX_ENVELOPE_BYTES)} limit.`);
        }
        const hash = createHash('sha256').update(envelope).digest('hex').slice(0, 8);
        payloadFile = path.posix.join(config.build.assetsDir, `keyhole-${hash}.bin`);
        payloadBytes = envelope.length;

        for (const name of Object.keys(bundle)) delete bundle[name];
        this.emitFile({ type: 'asset', fileName: payloadFile, source: envelope });
        const publicHtml = publicPage(landing, {
          payload: config.base + payloadFile,
          storageKey: `keyhole:${config.base}`,
          remember,
        });
        this.emitFile({ type: 'asset', fileName: 'index.html', source: publicHtml });
        if (spaFallback) this.emitFile({ type: 'asset', fileName: '404.html', source: publicHtml });
      },
    },

    async closeBundle() {
      if (!payloadFile || !config.build.write) return;
      // Check what actually landed on disk: catches stale files, source maps and anything another plugin wrote.
      const outDir = path.resolve(config.root, config.build.outDir);
      const allowed = new Set(['index.html', payloadFile, ...(spaFallback ? ['404.html'] : [])]);
      const extra = (await listFiles(outDir)).filter((f) => !allowed.has(f));
      if (extra.length) {
        throw new Error(
          `vite-plugin-keyhole: ${config.build.outDir} contains unencrypted files:\n  ${extra.join('\n  ')}\n` +
            'Keep build.emptyOutDir on, and remove files other plugins write there.',
        );
      }
      config.logger.info(`vite-plugin-keyhole: encrypted ${payloadFile} (${kB(payloadBytes)})`);
    },
  };
}

/** The public page: landing HTML + config + inline loader. Never derived from the app's HTML. */
function publicPage(landing: string, settings: object): string {
  const loader = readFileSync(new URL('./loader.iife.js', import.meta.url), 'utf8');
  if (/<\/script/i.test(loader)) throw new Error('vite-plugin-keyhole: loader contains "</script".');
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
 * Every file under `dir`, following symlinked folders. By default skips .git (a folder, or a file in a
 * worktree), which Vite's emptyOutDir keeps. Read errors throw, so the plaintext check never passes on a folder it couldn't read.
 */
async function listFiles(dir: string, { allowMissing = false, skipGit = true, prefix = '' } = {}): Promise<string[]> {
  let names: string[];
  try {
    names = await readdir(dir);
  } catch (error) {
    if (allowMissing && (error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
  const out: string[] = [];
  for (const name of names) {
    if (skipGit && name === '.git') continue;
    const full = path.join(dir, name);
    if ((await stat(full)).isDirectory()) out.push(...(await listFiles(full, { skipGit, prefix: `${prefix}${name}/` })));
    else out.push(prefix + name);
  }
  return out;
}

function kB(bytes: number): string {
  return `${(bytes / 1024).toFixed(1)} kB`;
}
