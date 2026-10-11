#!/usr/bin/env node
// keyhole keygen    print a fresh random key for KEYHOLE_KEY
import { generateKey } from './core.ts';

if (process.argv[2] === 'keygen') {
  console.log(generateKey());
} else {
  console.error('Usage: keyhole keygen    Print a new random key for KEYHOLE_KEY');
  process.exitCode = process.argv[2] === 'help' || process.argv[2] === '--help' ? 0 : 1;
}
