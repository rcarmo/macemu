const fs = require('fs');
const path = require('path');

function readFeatureFile(file) {
  const text = fs.readFileSync(file, 'utf8');
  const feature = {
    file: path.resolve(file),
    name: '',
    description: [],
    background: [],
    scenarios: []
  };
  let section = 'preamble';
  let currentScenario = null;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('Feature:')) {
      feature.name = line.slice('Feature:'.length).trim();
      section = 'feature';
      continue;
    }
    if (line.startsWith('Background:')) {
      section = 'background';
      currentScenario = null;
      continue;
    }
    if (line.startsWith('Scenario:')) {
      section = 'scenario';
      currentScenario = { name: line.slice('Scenario:'.length).trim(), steps: [] };
      feature.scenarios.push(currentScenario);
      continue;
    }
    if (/^(Given|When|Then|And|But)\b/.test(line)) {
      const step = parseStep(line);
      if (section === 'background') feature.background.push(step);
      else if (currentScenario) currentScenario.steps.push(step);
      else feature.description.push(line);
      continue;
    }
    if (section === 'feature' || section === 'preamble') feature.description.push(line);
  }
  return feature;
}

function parseStep(line) {
  const match = line.match(/^(Given|When|Then|And|But)\s+(.*)$/);
  return { keyword: match ? match[1] : 'Step', text: match ? match[2] : line, raw: line };
}

function discoverFeatureFiles(inputPaths) {
  const files = [];
  for (const input of inputPaths) {
    const stat = fs.statSync(input);
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(input).sort()) {
        if (entry.endsWith('.feature')) files.push(path.join(input, entry));
      }
    } else if (input.endsWith('.feature')) {
      files.push(input);
    }
  }
  return files;
}

module.exports = { readFeatureFile, discoverFeatureFiles };
