#!/usr/bin/env node
/*
 * Placeholder VNC/Gherkin runner for BasiliskII desktop QA.
 *
 * This intentionally avoids choosing a VNC automation dependency yet. The
 * scaffold defines the contract expected by qa/features/*.feature and gives us
 * a stable CLI to wire to a VNC client library later.
 */

const fs = require('fs');
const path = require('path');

function usage() {
  console.log(`Usage: vnc-gherkin-runner.js --feature FILE --artifacts DIR [--host HOST] [--port PORT]\n\nDefault host: 127.0.0.1\nDefault port: 5900\n\nCurrent status: scaffold only. It validates inputs and creates the artifact\ndirectory/manifest, but does not yet send VNC events.`);
}

let feature = '';
let artifacts = '';
let host = '127.0.0.1';
let port = '5900';

for (let i = 2; i < process.argv.length; i++) {
  const arg = process.argv[i];
  if (arg === '--feature') feature = process.argv[++i] || '';
  else if (arg === '--artifacts') artifacts = process.argv[++i] || '';
  else if (arg === '--host') host = process.argv[++i] || '';
  else if (arg === '--port') port = process.argv[++i] || '';
  else if (arg === '-h' || arg === '--help') { usage(); process.exit(0); }
  else { console.error(`Unknown argument: ${arg}`); usage(); process.exit(2); }
}

if (!feature || !artifacts) {
  usage();
  process.exit(2);
}
if (!fs.existsSync(feature)) {
  console.error(`Feature file not found: ${feature}`);
  process.exit(1);
}
fs.mkdirSync(artifacts, { recursive: true });

const manifest = {
  status: 'scaffold-only',
  feature: path.resolve(feature),
  artifacts: path.resolve(artifacts),
  vnc: { host, port: Number(port) },
  nextImplementationSteps: [
    'Choose VNC client library or external vncdotool/x11vnc mechanism available on Orange Pi.',
    'Implement step bindings for connect, screenshot, click, type, wait-for-image/region, and close.',
    'Store screenshots under qa/artifacts/screenshots/<run-id>/*.png.',
    'Emit a machine-readable result JSON and update the run report.'
  ]
};

fs.writeFileSync(path.join(artifacts, 'vnc-runner-manifest.json'), JSON.stringify(manifest, null, 2));
console.log(`Prepared VNC/Gherkin scaffold artifacts in ${artifacts}`);
console.log('No VNC actions were performed yet.');
