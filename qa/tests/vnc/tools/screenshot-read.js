#!/usr/bin/env node
const fs = require('fs');
const { inspectPng, assertNotBlank, ocrWithTesseract, matchTemplate } = require('../lib/screenshot');

function usage() {
  console.log(`Usage:
  screenshot-read.js inspect IMAGE.png [--ocr]
  screenshot-read.js assert IMAGE.png [--width N] [--height N] [--not-blank] [--min-stddev N] [--ocr-contains TEXT] [--template TEMPLATE.png] [--threshold N]

All checks are deterministic and model-free. OCR uses the tesseract CLI when available. Template matching uses OpenCV when available.`);
}

const [cmd, image, ...rest] = process.argv.slice(2);
if (!cmd || !image || cmd === '-h' || cmd === '--help') {
  usage();
  process.exit(cmd ? 0 : 2);
}
if (!fs.existsSync(image)) {
  console.error(`Image not found: ${image}`);
  process.exit(1);
}

function option(name, fallback = null) {
  const idx = rest.indexOf(name);
  return idx >= 0 ? rest[idx + 1] : fallback;
}
function has(name) { return rest.includes(name); }

if (cmd === 'inspect') {
  const result = { inspect: inspectPng(image) };
  if (has('--ocr')) result.ocr = ocrWithTesseract(image, { psm: option('--psm', 6) });
  console.log(JSON.stringify(result, null, 2));
  process.exit(0);
}

if (cmd === 'assert') {
  const checks = [];
  const info = inspectPng(image);
  let pass = true;

  const width = option('--width');
  if (width !== null) checks.push({ name: 'width', pass: info.width === Number(width), actual: info.width, expected: Number(width) });
  const height = option('--height');
  if (height !== null) checks.push({ name: 'height', pass: info.height === Number(height), actual: info.height, expected: Number(height) });
  if (has('--not-blank')) {
    const check = assertNotBlank(image, Number(option('--min-stddev', 1.0)));
    checks.push({ name: 'not-blank', pass: check.pass, reason: check.reason });
  }
  const ocrContains = option('--ocr-contains');
  if (ocrContains !== null) {
    const ocr = ocrWithTesseract(image, { psm: option('--psm', 6) });
    const contains = ocr.available && ocr.status === 0 && ocr.stdout.toLowerCase().includes(String(ocrContains).toLowerCase());
    checks.push({ name: 'ocr-contains', pass: contains, expected: ocrContains, text: ocr.stdout, available: ocr.available, status: ocr.status, stderr: ocr.stderr });
  }
  const template = option('--template');
  if (template !== null) {
    const threshold = Number(option('--threshold', 0.9));
    const match = matchTemplate(image, template);
    checks.push({ name: 'template-match', pass: match.available && match.score >= threshold, threshold, match });
  }

  for (const check of checks) if (!check.pass) pass = false;
  console.log(JSON.stringify({ pass, image, inspect: info, checks }, null, 2));
  process.exit(pass ? 0 : 1);
}

usage();
process.exit(2);
