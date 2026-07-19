/**
 * Example: open the Special menu and select "Restart"
 *
 * Classic Mac OS menus: mouse-down on title → drag to item → mouse-up
 */
import { VNCClient, Key } from "./index";

async function main() {
  const vnc = new VNCClient({ port: 5999 });
  const { width, height } = await vnc.connect();
  console.log(`Connected: ${width}×${height}`);

  // Wait for desktop
  console.log("Waiting for desktop...");
  const booted = await vnc.waitForDesktop(10, 60000);
  if (!booted) { console.log("Boot timeout"); vnc.close(); return; }
  console.log("Desktop ready!");

  // Dismiss any startup dialog
  await vnc.keyPress(Key.Return);
  await vnc.sleep(500);

  // Open Special menu (≈x=235 in menu bar) and select "Restart" (item ~7)
  // Menu bar Y ≈ 11, items start at Y ≈ 30, each ≈ 16px tall
  console.log("Opening Special menu...");
  await vnc.menuSelect(
    235, 11,   // "Special" menu title
    235, 30 + 7 * 16  // ~7th item (Restart)
  );

  await vnc.sleep(2000);

  // Take a screenshot to see the result
  const colors = await vnc.countColors();
  console.log(`Screen colors: ${colors}`);

  vnc.close();
}

main().catch(console.error);
