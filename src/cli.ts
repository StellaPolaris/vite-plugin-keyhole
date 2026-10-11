#!/usr/bin/env node
// keyhole keygen            print a fresh random key
// keyhole link <url>        print <url>#key=<KEYHOLE_KEY>
import { parseArgs } from 'node:util';
import { generateKey, parseKey } from './core.ts';

const USAGE = `Usage:
  keyhole keygen                 Print a new random key
  keyhole link <url> [--mode m]  Print a share link, reading KEYHOLE_KEY from the
                                 environment or .env files (mode defaults to production)`;

async function readKey(mode: string): Promise<string | undefined> {
  if (process.env.KEYHOLE_KEY) return process.env.KEYHOLE_KEY;
  // Same .env files and precedence as `vite build --mode <mode>`.
  const { loadEnv } = await import('vite');
  return loadEnv(mode, process.cwd(), 'KEYHOLE_').KEYHOLE_KEY;
}

async function main(args: string[]): Promise<number> {
  const [command, ...rest] = args;
  if (command === 'keygen') {
    console.log(generateKey());
    return 0;
  }
  if (command === 'link') {
    let mode: string | undefined;
    let positionals: string[];
    try {
      ({ values: { mode }, positionals } = parseArgs({ args: rest, options: { mode: { type: 'string' } }, allowPositionals: true }));
    } catch (error) {
      console.error(`keyhole: ${(error as Error).message}\n\n${USAGE}`);
      return 1;
    }
    if (positionals.length !== 1) {
      console.error(USAGE);
      return 1;
    }
    const url = URL.parse(positionals[0]);
    if (!url || (url.protocol !== 'https:' && url.protocol !== 'http:')) {
      console.error(`keyhole: "${positionals[0]}" is not a full URL. Include https://, for example https://me.github.io/site/`);
      return 1;
    }
    const keyText = (await readKey(mode ?? 'production'))?.trim();
    if (!keyText || !parseKey(keyText)) {
      console.error('keyhole: KEYHOLE_KEY is missing or malformed. Create one with `keyhole keygen`.');
      return 1;
    }
    url.hash = `key=${keyText}`;
    console.log(url.href);
    return 0;
  }
  console.error(USAGE);
  return command === 'help' || command === '--help' ? 0 : 1;
}

process.exitCode = await main(process.argv.slice(2));
