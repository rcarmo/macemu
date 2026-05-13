#!/usr/bin/env node
const path = require('path');
const { discoverFeatureFiles, readFeatureFile } = require('./lib/gherkin');
const { createRunArtifacts, writeJson, writeReport } = require('./lib/artifacts');
const { createDriver } = require('./lib/vnc-driver');

function usage() {
  console.log(`Usage: run.js (--feature FILE | --features DIR) --artifacts DIR [options]\n\nOptions:\n  --host HOST          VNC host (default 127.0.0.1)\n  --port PORT          VNC port (default 5900)\n  --driver KIND        VNC driver (default noop)\n  --strict             Treat unbound steps as failures (default: skip)\n`);
}

const featureInputs = [];
let artifactsDir = '';
let host = '127.0.0.1';
let port = '5900';
let driverKind = 'noop';
let strict = false;

for (let i = 2; i < process.argv.length; i++) {
  const arg = process.argv[i];
  if (arg === '--feature' || arg === '--features') featureInputs.push(process.argv[++i]);
  else if (arg === '--artifacts') artifactsDir = process.argv[++i] || '';
  else if (arg === '--host') host = process.argv[++i] || '';
  else if (arg === '--port') port = process.argv[++i] || '';
  else if (arg === '--driver') driverKind = process.argv[++i] || '';
  else if (arg === '--strict') strict = true;
  else if (arg === '-h' || arg === '--help') { usage(); process.exit(0); }
  else { console.error(`Unknown argument: ${arg}`); usage(); process.exit(2); }
}

if (!featureInputs.length || !artifactsDir) {
  usage();
  process.exit(2);
}

const artifacts = createRunArtifacts(artifactsDir);
const driver = createDriver(driverKind, {
  host,
  port: Number(port),
  screenshotDir: artifacts.screenshots,
  actionsFile: artifacts.actions
});

const startedAt = new Date().toISOString();
const result = {
  status: 'PASS',
  startedAt,
  finishedAt: null,
  driver: driverKind,
  vnc: { host, port: Number(port) },
  features: []
};

function quoted(text) {
  const match = text.match(/"([^"]*)"/);
  return match ? match[1] : '';
}

function seconds(text) {
  const match = text.match(/(\d+)\s+seconds?/);
  return match ? Number(match[1]) : 0;
}

async function executeStep(step) {
  const text = step.text;
  if (/^the VNC runner connects to the emulator display$/.test(text)) {
    await driver.connect();
  } else if (/^a screenshot named /.test(text)) {
    await driver.screenshot(quoted(text));
  } else if (/^the runner waits for display state /.test(text)) {
    await driver.waitForDisplay(quoted(text), seconds(text) * 1000);
  } else if (/^the runner waits \d+ seconds$/.test(text)) {
    await driver.wait(seconds(text) * 1000);
  } else if (/^the runner clicks target /.test(text)) {
    await driver.click(quoted(text));
  } else if (/^the runner focuses target /.test(text)) {
    await driver.focus(quoted(text));
  } else if (/^the runner types text /.test(text)) {
    await driver.type(quoted(text));
  } else if (/^the runner sends key /.test(text)) {
    await driver.key(quoted(text));
  } else if (/^the runner records manual assertion /.test(text)) {
    await driver.recordManualAssertion(quoted(text));
  } else if (/^the runner records failure classification /.test(text)) {
    await driver.recordFailureClassification(quoted(text));
  } else if (/^the runner records emulator logs and prefs paths$/.test(text)) {
    await driver.recordLogsAndPrefs();
  } else if (/^the emulator should still be running$/.test(text)) {
    await driver.assertEmulatorRunning();
  } else if (/^the VNC display should still respond$/.test(text)) {
    await driver.assertDisplayResponds();
  } else if (/^(the QA case|the emulator is launched|the Finder desktop|a simple app window|the display state)/.test(text)) {
    return { status: 'SKIP', note: 'precondition/manual assertion' };
  } else if (/^the runner opens guest item /.test(text)) {
    await driver.click(`guest-item:${quoted(text)}`);
  } else {
    return { status: strict ? 'FAIL' : 'SKIP', note: 'unbound step' };
  }
  return { status: 'PASS' };
}

(async () => {
  let exitCode = 0;
  try {
    const files = discoverFeatureFiles(featureInputs);
    for (const file of files) {
      const feature = readFeatureFile(file);
      const featureResult = { file: feature.file, name: feature.name, scenarios: [] };
      for (const scenario of feature.scenarios) {
        const scenarioResult = { name: scenario.name, status: 'PASS', steps: [] };
        for (const step of [...feature.background, ...scenario.steps]) {
          const stepResult = { raw: step.raw, ...(await executeStep(step)) };
          if (stepResult.status === 'FAIL') {
            scenarioResult.status = 'FAIL';
            result.status = 'FAIL';
            exitCode = 1;
          }
          scenarioResult.steps.push(stepResult);
        }
        featureResult.scenarios.push(scenarioResult);
      }
      result.features.push(featureResult);
    }
  } catch (err) {
    result.status = 'ERROR';
    result.error = err.stack || String(err);
    exitCode = 1;
  } finally {
    try { await driver.close(); } catch (_) {}
    result.finishedAt = new Date().toISOString();
    writeJson(artifacts.result, result);
    writeReport(artifacts.report, result);
  }

  console.log(`${result.status}: wrote ${artifacts.result}`);
  process.exit(exitCode);
})();
