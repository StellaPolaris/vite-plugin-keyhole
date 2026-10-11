import { defineConfig } from 'tsdown';

export default defineConfig([
  {
    // Node side: the plugin, the shared core and the CLI. vite stays external (peer dependency).
    entry: ['src/index.ts', 'src/core.ts', 'src/cli.ts'],
    platform: 'node',
    format: 'esm',
    fixedExtension: false,
    dts: true,
    copy: ['src/landing.html'],
  },
  {
    // Browser loader: one minified, self-contained script that the plugin inlines into the public HTML.
    entry: { loader: 'src/loader.ts' },
    platform: 'browser',
    format: 'iife',
    fixedExtension: false,
    minify: true,
    dts: false,
    clean: false,
  },
]);
