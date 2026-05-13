const fs = require('fs');
const path = require('path');

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n');
}

function appendJsonl(file, data) {
  fs.appendFileSync(file, JSON.stringify(data) + '\n');
}

function createRunArtifacts(root) {
  ensureDir(root);
  ensureDir(path.join(root, 'screenshots'));
  return {
    root,
    screenshots: path.join(root, 'screenshots'),
    actions: path.join(root, 'vnc-actions.jsonl'),
    result: path.join(root, 'vnc-run.json'),
    report: path.join(root, 'report.md')
  };
}

function writeReport(file, result) {
  const lines = [];
  lines.push(`# VNC QA run: ${result.status}`);
  lines.push('');
  lines.push(`- Started: ${result.startedAt}`);
  lines.push(`- Finished: ${result.finishedAt}`);
  lines.push(`- Driver: ${result.driver}`);
  lines.push(`- Target: ${result.vnc.host}:${result.vnc.port}`);
  lines.push('');
  for (const feature of result.features) {
    lines.push(`## ${feature.name}`);
    lines.push('');
    for (const scenario of feature.scenarios) {
      lines.push(`- ${scenario.status} — ${scenario.name}`);
      for (const step of scenario.steps) {
        lines.push(`  - ${step.status}: ${step.raw}`);
      }
    }
    lines.push('');
  }
  fs.writeFileSync(file, lines.join('\n'));
}

module.exports = { ensureDir, writeJson, appendJsonl, createRunArtifacts, writeReport };
