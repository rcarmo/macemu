#!/usr/bin/env node
/* Compatibility wrapper for the dedicated VNC QA test runner. */
const path = require('path');
const { spawnSync } = require('child_process');

const runner = path.resolve(__dirname, '../tests/vnc/run.js');
const args = process.argv.slice(2).flatMap((arg, idx, arr) => {
  // Preserve the original --feature/--artifacts/--host/--port CLI used by the
  // first scaffold. The new runner accepts the same options plus --features.
  return [arg];
});

const result = spawnSync(process.execPath, [runner, ...args], { stdio: 'inherit' });
process.exit(result.status ?? 1);
