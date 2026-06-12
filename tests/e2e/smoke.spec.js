import { test, expect } from "@playwright/test";
import { spawn } from "child_process";
import net from "net";
import path from "path";
import { fileURLToPath } from "url";

function getRandomPort() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, () => { const p = srv.address().port; srv.close(() => resolve(p)); });
  });
}

const EXPECTED_ERROR_PATTERNS = [
  /Failed to load resource/i,
  /ERR_NAME_NOT_RESOLVED/i,
  /ERR_CONNECTION_REFUSED/i,
  /leaflet/i,
  /chart\.js/i,
  /cdn/i,
  /unpkg/i,
  /googleapis/i,
  /fonts/i,
];

function isExpectedError(msg) {
  return EXPECTED_ERROR_PATTERNS.some(p => p.test(msg));
}

test("honeypot dashboard loads without JS errors", async ({ page }) => {
  const projectDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const port = await getRandomPort();
  const server = spawn("python3", ["-m", "http.server", String(port)], {
    cwd: projectDir,
    stdio: "ignore",
  });

  try {
    await new Promise(r => setTimeout(r, 1000));

    const errors = [];
    const warnings = [];
    page.on("console", msg => {
      if (msg.type() === "error") errors.push(msg.text());
      if (msg.type() === "warning") warnings.push(msg.text());
    });
    page.on("pageerror", err => { errors.push(err.message); });

    await page.goto(`http://localhost:${port}/dashboard.html`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(2000);

    await expect(page.locator("#map")).toBeAttached();
    await expect(page.locator("header")).toBeAttached();
    await expect(page.locator("#credsChart")).toBeAttached();

    const realErrors = errors.filter(e => !isExpectedError(e));
    if (warnings.length > 0) console.log("Warnings:", warnings);
    expect(realErrors).toEqual([]);
  } finally {
    server.kill();
  }
});
