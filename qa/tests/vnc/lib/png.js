const fs = require('fs');
const zlib = require('zlib');

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function paeth(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  if (pb <= pc) return b;
  return c;
}

function bytesPerPixel(colorType) {
  switch (colorType) {
    case 0: return 1; // grayscale
    case 2: return 3; // RGB
    case 3: return 1; // indexed color
    case 4: return 2; // grayscale + alpha
    case 6: return 4; // RGBA
    default: throw new Error(`Unsupported PNG color type ${colorType}`);
  }
}

function parsePng(buffer) {
  if (buffer.length < 8 || !buffer.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new Error('Not a PNG file');
  }

  let offset = 8;
  let width = 0;
  let height = 0;
  let bitDepth = 0;
  let colorType = 0;
  let interlace = 0;
  const idat = [];
  let palette = null;
  let transparency = null;

  while (offset + 12 <= buffer.length) {
    const length = buffer.readUInt32BE(offset); offset += 4;
    const type = buffer.toString('ascii', offset, offset + 4); offset += 4;
    const data = buffer.subarray(offset, offset + length); offset += length;
    offset += 4; // crc

    if (type === 'IHDR') {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      bitDepth = data[8];
      colorType = data[9];
      interlace = data[12];
    } else if (type === 'PLTE') {
      palette = data;
    } else if (type === 'tRNS') {
      transparency = data;
    } else if (type === 'IDAT') {
      idat.push(data);
    } else if (type === 'IEND') {
      break;
    }
  }

  if (!width || !height) throw new Error('PNG missing IHDR');
  if (bitDepth !== 8) throw new Error(`Unsupported PNG bit depth ${bitDepth}; expected 8`);
  if (interlace !== 0) throw new Error('Unsupported interlaced PNG');

  const bpp = bytesPerPixel(colorType);
  const stride = width * bpp;
  const inflated = zlib.inflateSync(Buffer.concat(idat));
  const raw = Buffer.alloc(height * stride);

  let src = 0;
  for (let y = 0; y < height; y++) {
    const filter = inflated[src++];
    const rowStart = y * stride;
    const prevRowStart = (y - 1) * stride;
    for (let x = 0; x < stride; x++) {
      const left = x >= bpp ? raw[rowStart + x - bpp] : 0;
      const up = y > 0 ? raw[prevRowStart + x] : 0;
      const upLeft = y > 0 && x >= bpp ? raw[prevRowStart + x - bpp] : 0;
      let value = inflated[src++];
      if (filter === 1) value = (value + left) & 0xff;
      else if (filter === 2) value = (value + up) & 0xff;
      else if (filter === 3) value = (value + Math.floor((left + up) / 2)) & 0xff;
      else if (filter === 4) value = (value + paeth(left, up, upLeft)) & 0xff;
      else if (filter !== 0) throw new Error(`Unsupported PNG filter ${filter}`);
      raw[rowStart + x] = value;
    }
  }

  const rgba = Buffer.alloc(width * height * 4);
  for (let i = 0, o = 0, p = 0; i < width * height; i++, o += bpp, p += 4) {
    if (colorType === 0) {
      const g = raw[o];
      rgba[p] = g; rgba[p + 1] = g; rgba[p + 2] = g; rgba[p + 3] = 255;
    } else if (colorType === 2) {
      rgba[p] = raw[o]; rgba[p + 1] = raw[o + 1]; rgba[p + 2] = raw[o + 2]; rgba[p + 3] = 255;
    } else if (colorType === 3) {
      if (!palette) throw new Error('Indexed PNG missing PLTE');
      const idx = raw[o];
      rgba[p] = palette[idx * 3] ?? 0;
      rgba[p + 1] = palette[idx * 3 + 1] ?? 0;
      rgba[p + 2] = palette[idx * 3 + 2] ?? 0;
      rgba[p + 3] = transparency && idx < transparency.length ? transparency[idx] : 255;
    } else if (colorType === 4) {
      const g = raw[o];
      rgba[p] = g; rgba[p + 1] = g; rgba[p + 2] = g; rgba[p + 3] = raw[o + 1];
    } else if (colorType === 6) {
      rgba[p] = raw[o]; rgba[p + 1] = raw[o + 1]; rgba[p + 2] = raw[o + 2]; rgba[p + 3] = raw[o + 3];
    }
  }

  return { width, height, rgba };
}

function readPng(file) {
  return parsePng(fs.readFileSync(file));
}

module.exports = { readPng, parsePng };
