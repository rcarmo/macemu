#!/usr/bin/env node
/* Compatibility wrapper for the shared VNC QA test runner. */
const path = require('path');
const { spawnSync } = require('child_process');

const runner = path.resolve(__dirname, '../../../qa/tests/vnc/run.js');
let args = process.argv.slice(2);
if (!args.includes('--emulator') && !args.includes('--profile')) {
  args = ['--emulator', 'basiliskii', ...args];
}

const result = spawnSync(process.execPath, [runner, ...args], { stdio: 'inherit' });
process.exit(result.status ?? 1);
