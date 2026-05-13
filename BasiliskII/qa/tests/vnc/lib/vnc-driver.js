const fs = require('fs');
const path = require('path');
const { appendJsonl, ensureDir } = require('./artifacts');

class NoopVncDriver {
  constructor(options) {
    this.options = options;
    this.connected = false;
    ensureDir(options.screenshotDir);
  }

  log(action, details = {}) {
    appendJsonl(this.options.actionsFile, {
      ts: new Date().toISOString(),
      driver: 'noop',
      action,
      ...details
    });
  }

  async connect() {
    this.connected = true;
    this.log('connect', { host: this.options.host, port: this.options.port });
  }

  async waitForDisplay(label, timeoutMs) {
    this.log('waitForDisplay', { label, timeoutMs, result: 'not-asserted-noop' });
  }

  async wait(ms) {
    this.log('wait', { ms, result: 'skipped-noop' });
  }

  async screenshot(name) {
    const safe = name.replace(/[^A-Za-z0-9_.-]+/g, '-');
    const file = path.join(this.options.screenshotDir, `${safe}.placeholder.json`);
    const payload = {
      type: 'placeholder-screenshot',
      name,
      ts: new Date().toISOString(),
      note: 'Noop VNC driver did not capture pixels.'
    };
    fs.writeFileSync(file, JSON.stringify(payload, null, 2) + '\n');
    this.log('screenshot', { name, file });
    return file;
  }

  async click(target) {
    this.log('click', { target });
  }

  async focus(target) {
    this.log('focus', { target });
  }

  async type(text) {
    this.log('type', { text });
  }

  async key(keyName) {
    this.log('key', { keyName });
  }

  async recordManualAssertion(text) {
    this.log('manualAssertion', { text });
  }

  async recordFailureClassification(classification) {
    this.log('failureClassification', { classification });
  }

  async recordLogsAndPrefs() {
    this.log('recordLogsAndPrefs');
  }

  async assertEmulatorRunning() {
    this.log('assertEmulatorRunning', { result: 'not-asserted-noop' });
  }

  async assertDisplayResponds() {
    this.log('assertDisplayResponds', { result: 'not-asserted-noop' });
  }

  async close() {
    this.log('close');
    this.connected = false;
  }
}

function createDriver(kind, options) {
  if (kind !== 'noop') {
    throw new Error(`Unsupported VNC driver '${kind}'. Currently available: noop`);
  }
  return new NoopVncDriver(options);
}

module.exports = { createDriver };
