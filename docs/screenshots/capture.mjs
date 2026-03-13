// Captures README screenshots from a running DockGuard instance.
// Usage: npm install && node capture.mjs <base-url>
// Example: node capture.mjs http://localhost:8764
import puppeteer from 'puppeteer';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BASE_URL = process.argv[2];
if (!BASE_URL) {
  console.error('Error: base URL is required.\nUsage: node capture.mjs <base-url>\nExample: node capture.mjs http://localhost:8764');
  process.exit(1);
}

const pages = [
  { path: '/', file: 'dashboard.png' },
  { path: '/containers', file: 'containers.png' },
  { path: '/vulnerabilities', file: 'vulnerabilities.png' },
];

const browser = await puppeteer.launch({
  headless: true,
  args: [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
  ],
});

const page = await browser.newPage();
await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 2 });

for (const { path: urlPath, file } of pages) {
  const url = `${BASE_URL}${urlPath}`;
  console.log(`Capturing ${url}...`);
  await page.goto(url, { waitUntil: 'networkidle0', timeout: 30000 });
  // Wait a bit for any animations/charts to settle
  await new Promise(r => setTimeout(r, 1500));

  // For containers page, expand the VEX-tagged container row
  if (urlPath === '/containers') {
    await page.evaluate(() => {
      const vexBadge = [...document.querySelectorAll('button')].find(el => el.textContent.trim() === 'VEX');
      const tr = vexBadge?.closest('tr');
      tr?.querySelector('td:first-child')?.click();
    });
    await new Promise(r => setTimeout(r, 1000));
  }

  const outPath = path.join(__dirname, file);
  await page.screenshot({ path: outPath, fullPage: false });
  console.log(`  Saved to ${outPath}`);
}

await browser.close();
console.log('Done!');
