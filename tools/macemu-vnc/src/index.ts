/**
 * macemu-vnc: VNC client for scripting BasiliskII Classic Mac OS interactions
 *
 * Classic Mac OS uses press-hold-drag-release for menus (not click-to-open).
 * This library provides primitives matching that interaction model.
 */

import { Socket } from "net";

// X11 keysym values
export const Key = {
  Return: 0xff0d,
  Escape: 0xff1b,
  Tab: 0xff09,
  BackSpace: 0xff08,
  Delete: 0xffff,
  Left: 0xff51,
  Up: 0xff52,
  Right: 0xff53,
  Down: 0xff54,
  Home: 0xff50,
  End: 0xff57,
  PageUp: 0xff55,
  PageDown: 0xff56,
  Shift_L: 0xffe1,
  Shift_R: 0xffe2,
  Control_L: 0xffe3,
  Alt_L: 0xffe9,
  Command: 0xffe7, // Meta_L — Mac Command key
  Space: 0x0020,
  Period: 0x002e,
  Comma: 0x002c,
  Slash: 0x002f,
  // F-keys
  F1: 0xffbe, F2: 0xffbf, F3: 0xffc0, F4: 0xffc1,
  F5: 0xffc2, F6: 0xffc3, F7: 0xffc4, F8: 0xffc5,
} as const;

/** Char code to keysym for printable ASCII */
function charToKeysym(ch: string): number {
  const code = ch.charCodeAt(0);
  if (code >= 0x20 && code <= 0x7e) return code;
  if (ch === "\n") return Key.Return;
  if (ch === "\t") return Key.Tab;
  return code;
}

export interface VNCOptions {
  host?: string;
  port?: number;
  timeout?: number;
}

export interface Screenshot {
  width: number;
  height: number;
  /** RGBA pixel data, row-major, 4 bytes per pixel */
  data: Buffer;
}

export class VNCClient {
  private socket: Socket | null = null;
  private width = 0;
  private height = 0;
  private connected = false;
  private mouseX = 0;
  private mouseY = 0;
  private buttonMask = 0;

  constructor(private options: VNCOptions = {}) {
    this.options.host ??= "127.0.0.1";
    this.options.port ??= 5999;
    this.options.timeout ??= 5000;
  }

  // ─── Connection ───────────────────────────────────────────────

  async connect(): Promise<{ width: number; height: number }> {
    return new Promise((resolve, reject) => {
      const sock = new Socket();
      sock.on("error", reject);
      sock.on("timeout", () => reject(new Error("VNC timeout")));
      sock.connect(this.options.port!, this.options.host!, () => {
        this.socket = sock;
        // Set idle timeout only after TCP connect to avoid firing during handshake
        sock.setTimeout(this.options.timeout!);
        this.handshake().then((res) => {
          sock.setTimeout(0); // clear timeout after successful handshake
          resolve(res);
        }).catch(reject);
      });
    });
  }

  close(): void {
    this.socket?.destroy();
    this.socket = null;
    this.connected = false;
  }

  get screenWidth() { return this.width; }
  get screenHeight() { return this.height; }

  // ─── Keyboard ─────────────────────────────────────────────────

  /** Press and release a key with optional modifier keys held */
  async keyPress(keysym: number, modifiers: number[] = []): Promise<void> {
    for (const m of modifiers) await this.keyDown(m);
    await this.keyDown(keysym);
    await this.sleep(30);
    await this.keyUp(keysym);
    for (const m of modifiers.reverse()) await this.keyUp(m);
    await this.sleep(30);
  }

  async keyDown(keysym: number): Promise<void> { await this.sendKey(keysym, true); }
  async keyUp(keysym: number): Promise<void> { await this.sendKey(keysym, false); }

  /** Type a string, one character at a time */
  async typeText(text: string, delayMs = 40): Promise<void> {
    for (const ch of text) {
      const sym = charToKeysym(ch);
      const needShift = ch >= "A" && ch <= "Z";
      if (needShift) await this.keyDown(Key.Shift_L);
      await this.keyPress(sym);
      if (needShift) await this.keyUp(Key.Shift_L);
      await this.sleep(delayMs);
    }
  }

  /** Command+key shortcut (⌘+key) */
  async cmdKey(keysym: number): Promise<void> {
    await this.keyPress(keysym, [Key.Command]);
  }

  // ─── Mouse ────────────────────────────────────────────────────

  /** Move mouse to (x, y) without clicking */
  async moveTo(x: number, y: number): Promise<void> {
    this.mouseX = x;
    this.mouseY = y;
    await this.sendPointer(x, y, this.buttonMask);
  }

  /** Single click at (x, y). Classic Mac: press → release. */
  async click(x: number, y: number, button = 1): Promise<void> {
    await this.moveTo(x, y);
    await this.mouseDown(button);
    await this.sleep(60);
    await this.mouseUp(button);
    await this.sleep(60);
  }

  /** Double-click at (x, y) */
  async doubleClick(x: number, y: number, button = 1): Promise<void> {
    await this.click(x, y, button);
    await this.sleep(80);
    await this.click(x, y, button);
  }

  /** Press mouse button (without releasing) */
  async mouseDown(button = 1): Promise<void> {
    this.buttonMask |= 1 << (button - 1);
    await this.sendPointer(this.mouseX, this.mouseY, this.buttonMask);
  }

  /** Release mouse button */
  async mouseUp(button = 1): Promise<void> {
    this.buttonMask &= ~(1 << (button - 1));
    await this.sendPointer(this.mouseX, this.mouseY, this.buttonMask);
  }

  /** Drag from (x1,y1) to (x2,y2) with smooth interpolation */
  async drag(
    x1: number, y1: number,
    x2: number, y2: number,
    steps = 10, stepDelayMs = 20
  ): Promise<void> {
    await this.moveTo(x1, y1);
    await this.mouseDown();
    await this.sleep(50);
    for (let i = 1; i <= steps; i++) {
      const x = Math.round(x1 + ((x2 - x1) * i) / steps);
      const y = Math.round(y1 + ((y2 - y1) * i) / steps);
      await this.moveTo(x, y);
      await this.sleep(stepDelayMs);
    }
    await this.mouseUp();
  }

  // ─── Classic Mac Menu Interaction ─────────────────────────────
  //
  // Classic Mac OS menus work by:
  //   1. Mouse down on menu title in menu bar
  //   2. Menu drops down
  //   3. Drag to desired item (highlighting as you go)
  //   4. Mouse up on the item to select it
  //
  // This is fundamentally different from modern click-to-open menus.

  /**
   * Open a menu and select an item by position.
   *
   * @param menuX - X coordinate of the menu title in the menu bar
   * @param menuY - Y coordinate (typically 11 for menu bar)
   * @param itemX - X coordinate of the menu item
   * @param itemY - Y coordinate of the menu item
   * @param holdMs - How long to hold on menu title before dragging (ms)
   */
  async menuSelect(
    menuX: number, menuY: number,
    itemX: number, itemY: number,
    holdMs = 200
  ): Promise<void> {
    // Press on menu title
    await this.moveTo(menuX, menuY);
    await this.mouseDown();
    await this.sleep(holdMs);
    // Drag to item
    await this.moveTo(itemX, itemY);
    await this.sleep(100);
    // Release to select
    await this.mouseUp();
    await this.sleep(200);
  }

  /**
   * Open a menu by title name and select Nth item.
   * Assumes standard Mac menu bar layout (640×480, 8px font).
   *
   * Menu title X positions (approximate for standard 640×480):
   *   Apple=10, File=50, Edit=90, View=130, Label=175, Special=235
   */
  async menuSelectByIndex(
    menuTitleX: number,
    itemIndex: number,
    menuWidth = 150
  ): Promise<void> {
    const menuBarY = 11;
    const itemHeight = 16;
    const firstItemY = 30; // below menu bar
    const itemY = firstItemY + itemIndex * itemHeight;
    const itemX = menuTitleX + menuWidth / 2;

    await this.menuSelect(menuTitleX, menuBarY, itemX, itemY);
  }

  // ─── Screenshots ──────────────────────────────────────────────

  /** Capture the current screen as RGBA pixel data */
  async screenshot(): Promise<Screenshot> {
    const req = Buffer.alloc(10);
    req[0] = 3; // FramebufferUpdateRequest
    req[1] = 0; // non-incremental
    req.writeUInt16BE(this.width, 6);
    req.writeUInt16BE(this.height, 8);
    this.socket!.write(req);

    const header = await this.read(4);
    const numRects = header.readUInt16BE(2);
    const pixels = Buffer.alloc(this.width * this.height * 4);

    for (let i = 0; i < numRects; i++) {
      const rh = await this.read(12);
      const rx = rh.readUInt16BE(0);
      const ry = rh.readUInt16BE(2);
      const rw = rh.readUInt16BE(4);
      const rhi = rh.readUInt16BE(6);
      const enc = rh.readInt32BE(8);
      if (enc !== 0) throw new Error(`Unsupported encoding ${enc}`);

      const data = await this.read(rw * rhi * 4);
      for (let y = 0; y < rhi; y++) {
        for (let x = 0; x < rw; x++) {
          const si = (y * rw + x) * 4;
          const di = ((ry + y) * this.width + rx + x) * 4;
          pixels[di + 0] = data[si + 2]; // R ← B
          pixels[di + 1] = data[si + 1]; // G
          pixels[di + 2] = data[si + 0]; // B ← R
          pixels[di + 3] = 255;
        }
      }
    }
    return { width: this.width, height: this.height, data: pixels };
  }

  /** Count unique colors in screenshot (sampled) */
  async countColors(sampleSize = 10000): Promise<number> {
    const shot = await this.screenshot();
    const colors = new Set<number>();
    const step = Math.max(1, Math.floor(shot.width * shot.height / sampleSize));
    for (let i = 0; i < shot.width * shot.height; i += step) {
      const off = i * 4;
      colors.add((shot.data[off] << 16) | (shot.data[off + 1] << 8) | shot.data[off + 2]);
    }
    return colors.size;
  }

  // ─── Utilities ────────────────────────────────────────────────

  async sleep(ms: number): Promise<void> {
    return new Promise(r => setTimeout(r, ms));
  }

  /** Wait for screen to have at least N unique colors (indicates boot complete) */
  async waitForDesktop(minColors = 10, timeoutMs = 120000, pollMs = 2000): Promise<boolean> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        const colors = await this.countColors();
        if (colors >= minColors) return true;
      } catch { /* screen not ready */ }
      await this.sleep(pollMs);
    }
    return false;
  }

  // ─── Private ──────────────────────────────────────────────────

  private async handshake(): Promise<{ width: number; height: number }> {
    const sock = this.socket!;
    await this.read(12); // server version
    sock.write(RFB_VERSION);
    const n = (await this.read(1))[0];
    await this.read(n); // security types
    sock.write(Buffer.from([1])); // No auth
    const result = await this.read(4);
    if (result.readUInt32BE(0) !== 0) throw new Error("VNC auth failed");
    sock.write(Buffer.from([1])); // shared

    const si = await this.read(24);
    this.width = si.readUInt16BE(0);
    this.height = si.readUInt16BE(2);
    await this.read(si.readUInt32BE(20)); // name

    // Set pixel format: 32bpp BGRA
    const pf = Buffer.alloc(20);
    pf[0] = 0; pf[4] = 32; pf[5] = 24; pf[7] = 1;
    pf.writeUInt16BE(255, 8); pf.writeUInt16BE(255, 10); pf.writeUInt16BE(255, 12);
    pf[14] = 16; pf[15] = 8; pf[16] = 0;
    sock.write(pf);

    // Encodings: raw
    const enc = Buffer.alloc(8);
    enc[0] = 2; enc.writeUInt16BE(1, 2); enc.writeInt32BE(0, 4);
    sock.write(enc);

    this.connected = true;
    return { width: this.width, height: this.height };
  }

  private async sendKey(keysym: number, down: boolean): Promise<void> {
    const buf = Buffer.alloc(8);
    buf[0] = 4;
    buf[1] = down ? 1 : 0;
    buf.writeUInt32BE(keysym, 4);
    this.socket!.write(buf);
  }

  private async sendPointer(x: number, y: number, mask: number): Promise<void> {
    const buf = Buffer.alloc(6);
    buf[0] = 5;
    buf[1] = mask;
    buf.writeUInt16BE(Math.max(0, Math.min(x, this.width - 1)), 2);
    buf.writeUInt16BE(Math.max(0, Math.min(y, this.height - 1)), 4);
    this.socket!.write(buf);
  }

  private pending: Buffer = Buffer.alloc(0);

  private read(n: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const sock = this.socket!;

      // Check if we already have enough buffered data
      if (this.pending.length >= n) {
        const result = this.pending.subarray(0, n);
        this.pending = this.pending.subarray(n);
        resolve(result);
        return;
      }

      const onData = (data: Buffer) => {
        this.pending = Buffer.concat([this.pending, data]);
        if (this.pending.length >= n) {
          sock.removeListener("data", onData);
          sock.removeListener("error", onError);
          const result = this.pending.subarray(0, n);
          this.pending = this.pending.subarray(n);
          resolve(result);
        }
      };
      const onError = (err: Error) => { sock.removeListener("data", onData); reject(err); };
      sock.on("data", onData);
      sock.on("error", onError);
    });
  }
}

const RFB_VERSION = "RFB 003.008\n";

/** Convenience: connect → action → disconnect */
export async function withVNC<T>(
  action: (vnc: VNCClient) => Promise<T>,
  options?: VNCOptions
): Promise<T> {
  const vnc = new VNCClient(options);
  await vnc.connect();
  try {
    return await action(vnc);
  } finally {
    vnc.close();
  }
}
