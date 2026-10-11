#!/usr/bin/env node
// keyhole keygen            print a fresh random key
// keyhole link <url>        print <url>#key=<KEYHOLE_KEY>
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
  if (command === 'link' && rest[0]) {
    const modeAt = rest.indexOf('--mode');
    const mode = modeAt >= 0 ? rest[modeAt + 1] : 'production';
    const keyText = (await readKey(mode))?.trim();
    if (!keyText || !parseKey(keyText)) {
      console.error('keyhole: KEYHOLE_KEY is missing or malformed. Create one with `keyhole keygen`.');
      return 1;
    }
    const url = new URL(rest[0]);
    url.hash = `key=${keyText}`;
    console.log(url.href);
    return 0;
  }
  console.error(USAGE);
  return command === 'help' || command === '--help' ? 0 : 1;
}

process.exitCode = await main(process.argv.slice(2));
