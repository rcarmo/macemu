const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { readPng } = require('./png');

function isPngFile(file) {
  return file && fs.existsSync(file) && path.extname(file).toLowerCase() === '.png';
}

function inspectPng(file) {
  const image = readPng(file);
  const { width, height, rgba } = image;
  const hash = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  const pixels = width * height;
  const sums = [0, 0, 0, 0];
  const sums2 = [0, 0, 0, 0];
  let black = 0;
  let white = 0;
  let transparent = 0;
  const lum = new Array(pixels);

  for (let i = 0, p = 0; i < pixels; i++, p += 4) {
    const r = rgba[p];
    const g = rgba[p + 1];
    const b = rgba[p + 2];
    const a = rgba[p + 3];
    const l = 0.2126 * r + 0.7152 * g + 0.0722 * b;
    lum[i] = l;
    const vals = [r, g, b, a];
    for (let c = 0; c < 4; c++) {
      sums[c] += vals[c];
      sums2[c] += vals[c] * vals[c];
    }
    if (l < 8) black++;
    if (l > 247) white++;
    if (a === 0) transparent++;
  }

  const mean = sums.map(v => v / pixels);
  const stddev = sums2.map((v, c) => Math.sqrt(Math.max(0, v / pixels - mean[c] * mean[c])));
  const lumMean = lum.reduce((a, b) => a + b, 0) / pixels;
  const lumStddev = Math.sqrt(Math.max(0, lum.reduce((a, b) => a + (b - lumMean) ** 2, 0) / pixels));

  return {
    file: path.resolve(file),
    width,
    height,
    sha256: hash,
    mean: { r: mean[0], g: mean[1], b: mean[2], a: mean[3] },
    stddev: { r: stddev[0], g: stddev[1], b: stddev[2], a: stddev[3] },
    luminance: { mean: lumMean, stddev: lumStddev },
    ratios: { black: black / pixels, white: white / pixels, transparent: transparent / pixels },
    ahash8: averageHash8(width, height, lum)
  };
}

function averageHash8(width, height, luminance) {
  const sample = [];
  for (let y = 0; y < 8; y++) {
    for (let x = 0; x < 8; x++) {
      const sx = Math.min(width - 1, Math.floor((x + 0.5) * width / 8));
      const sy = Math.min(height - 1, Math.floor((y + 0.5) * height / 8));
      sample.push(luminance[sy * width + sx]);
    }
  }
  const mean = sample.reduce((a, b) => a + b, 0) / sample.length;
  let bits = '';
  for (const v of sample) bits += v >= mean ? '1' : '0';
  let hex = '';
  for (let i = 0; i < bits.length; i += 4) hex += parseInt(bits.slice(i, i + 4), 2).toString(16);
  return hex;
}

function assertNotBlank(file, minLumaStddev = 1.0) {
  const info = inspectPng(file);
  return {
    pass: info.luminance.stddev >= minLumaStddev,
    reason: `luminance.stddev=${info.luminance.stddev.toFixed(3)} min=${minLumaStddev}`,
    info
  };
}

function ocrWithTesseract(file, options = {}) {
  const args = [file, 'stdout'];
  if (options.psm) args.push('--psm', String(options.psm));
  const result = spawnSync('tesseract', args, { encoding: 'utf8' });
  return {
    available: result.error ? false : true,
    status: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    error: result.error ? String(result.error) : undefined
  };
}

function matchTemplate(image, template) {
  const script = path.resolve(__dirname, '../tools/opencv-match.py');
  const result = spawnSync('python3', [script, image, template], { encoding: 'utf8' });
  if (result.status !== 0) {
    return { available: false, status: result.status, stderr: result.stderr, stdout: result.stdout };
  }
  return { available: true, ...JSON.parse(result.stdout) };
}

module.exports = { isPngFile, inspectPng, assertNotBlank, ocrWithTesseract, matchTemplate };
