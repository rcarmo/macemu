#!/usr/bin/env node
/**
 * Generate a PDF/HTML VNC QA report from qa/tests/vnc/run.js artifacts.
 *
 * Inspired by the report generators in rcarmo/vibes and rcarmo/go-rdp-android:
 * - compact pass/fail summary
 * - scenario/evidence tables
 * - embedded screenshots when present
 * - Playwright Chromium HTML -> PDF rendering, with HTML fallback
 */
import fs from 'node:fs/promises';
import fssync from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

function arg(name, fallback = '') {
  const idx = process.argv.indexOf(`--${name}`);
  return idx >= 0 && process.argv[idx + 1] ? process.argv[idx + 1] : fallback;
}

function flag(name) {
  return process.argv.includes(`--${name}`);
}

function usage() {
  console.log(`Usage: generate-pdf-report.mjs --run DIR|vnc-run.json [--output report.pdf] [--title TITLE]\n\nInputs:\n  --run DIR          Directory containing vnc-run.json, report.md, vnc-actions.jsonl, screenshots/\n  --run FILE         Direct path to vnc-run.json\n\nOutputs:\n  --output FILE      PDF path (default: <run-dir>/vnc-qa-report.pdf)\n  HTML fallback is always written next to the PDF.\n`);
}

const runArg = arg('run');
if (!runArg || flag('help') || flag('h')) {
  usage();
  process.exit(runArg ? 0 : 2);
}

const runPath = path.resolve(runArg);
const runJson = fssync.statSync(runPath).isDirectory() ? path.join(runPath, 'vnc-run.json') : runPath;
const runDir = path.dirname(runJson);
const output = path.resolve(arg('output', path.join(runDir, 'vnc-qa-report.pdf')));
const title = arg('title', 'macemu VNC QA Report');

function esc(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function statusClass(status) {
  const s = String(status || '').toUpperCase();
  if (s === 'PASS') return 'pass';
  if (s === 'FAIL' || s === 'ERROR') return 'fail';
  if (s === 'SKIP') return 'skip';
  return 'unknown';
}

function statusEmoji(status) {
  const s = String(status || '').toUpperCase();
  if (s === 'PASS') return '✅';
  if (s === 'FAIL' || s === 'ERROR') return '❌';
  if (s === 'SKIP') return '⏭️';
  return '•';
}

async function readJson(file, fallback = null) {
  try { return JSON.parse(await fs.readFile(file, 'utf8')); }
  catch { return fallback; }
}

async function readText(file, fallback = '') {
  try { return await fs.readFile(file, 'utf8'); }
  catch { return fallback; }
}

async function listScreenshots(dir) {
  const screenshotDir = path.join(dir, 'screenshots');
  try {
    const names = (await fs.readdir(screenshotDir)).sort();
    return names.map((name) => path.join(screenshotDir, name));
  } catch {
    return [];
  }
}

function imageHtml(file) {
  if (!/\.(png|jpg|jpeg|webp)$/i.test(file)) return '';
  return `<img src="${pathToFileURL(file).href}" alt="${esc(path.basename(file))}">`;
}

function placeholderHtml(file) {
  if (!file.endsWith('.placeholder.json')) return '';
  try {
    const data = JSON.parse(fssync.readFileSync(file, 'utf8'));
    return `<pre>${esc(JSON.stringify(data, null, 2))}</pre>`;
  } catch {
    return `<pre>${esc(path.basename(file))}</pre>`;
  }
}

function scenarioRows(features) {
  const rows = [];
  for (const feature of features || []) {
    for (const scenario of feature.scenarios || []) {
      rows.push({ feature: feature.name, scenario: scenario.name, status: scenario.status, steps: scenario.steps || [] });
    }
  }
  return rows;
}

const result = await readJson(runJson);
if (!result) throw new Error(`Could not read ${runJson}`);
const actionsText = await readText(path.join(runDir, 'vnc-actions.jsonl'));
const screenshots = await listScreenshots(runDir);
const scenarios = scenarioRows(result.features);
const counts = scenarios.reduce((acc, s) => {
  const key = String(s.status || 'UNKNOWN').toUpperCase();
  acc[key] = (acc[key] || 0) + 1;
  return acc;
}, {});
const totalSteps = scenarios.reduce((n, s) => n + s.steps.length, 0);
const failedSteps = scenarios.flatMap((s) => s.steps.map((step) => ({ scenario: s.scenario, ...step }))).filter((step) => String(step.status).toUpperCase() === 'FAIL');

let html = `<!doctype html><html><head><meta charset="utf-8"><title>${esc(title)}</title><style>
  @page{size:A4;margin:14mm 12mm}*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;color:#172033;margin:0;font-size:11px;line-height:1.35}
  h1{font-size:24px;margin:0 0 4px}h2{font-size:16px;margin:20px 0 8px;border-bottom:1px solid #d8dee9;padding-bottom:4px}h3{font-size:12px;margin:12px 0 6px}.muted{color:#687385}.hero{padding:18px 20px;background:linear-gradient(135deg,#eef6ff,#f7f7ff);border:1px solid #d8e7ff;border-radius:10px;margin-bottom:14px}.summary{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}.pill{border-radius:999px;padding:5px 10px;background:#fff;border:1px solid #d8dee9;font-weight:600}.pass{color:#0a7f34}.fail{color:#b42318}.skip{color:#6b7280}.unknown{color:#475569}table{width:100%;border-collapse:collapse;margin:8px 0 14px}th,td{border:1px solid #e5e7eb;padding:5px 6px;text-align:left;vertical-align:top}th{background:#f8fafc;font-weight:700}tr.failrow{background:#fff5f5}.step{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.shot{break-inside:avoid;border:1px solid #e5e7eb;border-radius:8px;padding:8px;margin-bottom:10px}.shot img{max-width:100%;max-height:260px;display:block;margin:auto;border:1px solid #ddd}.shot pre,pre.log{white-space:pre-wrap;background:#f6f8fa;border-radius:6px;padding:8px;font-size:9px;max-height:220px;overflow:hidden}.pagebreak{break-before:page}
</style></head><body>`;

html += `<section class="hero"><h1>${esc(title)}</h1><div class="muted">Generated ${esc(new Date().toISOString())}</div><div class="summary">
  <span class="pill ${statusClass(result.status)}">${statusEmoji(result.status)} ${esc(result.status)}</span>
  <span class="pill">${esc(result.emulatorDisplayName || result.emulator || 'unknown emulator')}</span>
  <span class="pill">${esc(result.driver)} driver</span>
  <span class="pill">${esc(result.vnc?.host)}:${esc(result.vnc?.port)}</span>
  <span class="pill">${scenarios.length} scenarios · ${totalSteps} steps</span>
</div></section>`;

html += `<h2>Run metadata</h2><table><tbody>
<tr><th>Started</th><td>${esc(result.startedAt)}</td></tr>
<tr><th>Finished</th><td>${esc(result.finishedAt)}</td></tr>
<tr><th>Profile</th><td>${esc(result.profile)}</td></tr>
<tr><th>Run JSON</th><td>${esc(runJson)}</td></tr>
<tr><th>Scenario counts</th><td>${esc(JSON.stringify(counts))}</td></tr>
</tbody></table>`;

html += `<h2>Scenario summary</h2><table><thead><tr><th>Status</th><th>Feature</th><th>Scenario</th><th>Steps</th></tr></thead><tbody>`;
for (const s of scenarios) {
  html += `<tr class="${statusClass(s.status) === 'fail' ? 'failrow' : ''}"><td class="${statusClass(s.status)}">${statusEmoji(s.status)} ${esc(s.status)}</td><td>${esc(s.feature)}</td><td>${esc(s.scenario)}</td><td>${s.steps.length}</td></tr>`;
}
html += `</tbody></table>`;

if (failedSteps.length) {
  html += `<h2>Failed steps</h2><table><thead><tr><th>Scenario</th><th>Step</th><th>Details</th></tr></thead><tbody>`;
  for (const step of failedSteps) html += `<tr class="failrow"><td>${esc(step.scenario)}</td><td class="step">${esc(step.raw)}</td><td>${esc(step.note || JSON.stringify(step.details || {}))}</td></tr>`;
  html += `</tbody></table>`;
}

html += `<h2 class="pagebreak">Scenario details</h2>`;
for (const feature of result.features || []) {
  html += `<h3>${esc(feature.name)}</h3>`;
  for (const scenario of feature.scenarios || []) {
    html += `<table><thead><tr><th colspan="3"><span class="${statusClass(scenario.status)}">${statusEmoji(scenario.status)} ${esc(scenario.status)}</span> — ${esc(scenario.name)}</th></tr><tr><th>Status</th><th>Step</th><th>Note</th></tr></thead><tbody>`;
    for (const step of scenario.steps || []) {
      html += `<tr><td class="${statusClass(step.status)}">${esc(step.status)}</td><td class="step">${esc(step.raw)}</td><td>${esc(step.note || '')}</td></tr>`;
    }
    html += `</tbody></table>`;
  }
}

if (screenshots.length) {
  html += `<h2 class="pagebreak">Screenshots and image artifacts</h2><div class="grid">`;
  for (const file of screenshots) {
    html += `<div class="shot"><h3>${esc(path.basename(file))}</h3>${imageHtml(file) || placeholderHtml(file)}</div>`;
  }
  html += `</div>`;
}

if (actionsText.trim()) {
  html += `<h2 class="pagebreak">VNC action log</h2><pre class="log">${esc(actionsText.split('\n').slice(0, 250).join('\n'))}</pre>`;
}

html += `</body></html>`;

await fs.mkdir(path.dirname(output), { recursive: true });
const htmlPath = output.replace(/\.pdf$/i, '.html');
await fs.writeFile(htmlPath, html);
console.log(`HTML report: ${htmlPath}`);

function systemChromiumPath() {
  for (const candidate of ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable']) {
    if (fssync.existsSync(candidate)) return candidate;
  }
  return '';
}

try {
  const { chromium } = await import('playwright');
  const executablePath = systemChromiumPath();
  const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) });
  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: 'load' });
  await page.pdf({
    path: output,
    format: 'A4',
    printBackground: true,
    margin: { top: '14mm', right: '12mm', bottom: '14mm', left: '12mm' }
  });
  await browser.close();
  console.log(`PDF report: ${output}`);
} catch (err) {
  console.error(`PDF rendering failed: ${err.message}`);
  console.error(`HTML report is available at: ${htmlPath}`);
  process.exitCode = 1;
}
