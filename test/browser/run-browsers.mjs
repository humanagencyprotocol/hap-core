/**
 * Runs the browser entry's vectors in real WebKit and Chromium (headless):
 * browser-entry.json and every device-keys vector file, against src/browser.ts bundled for the
 * browser with all dependencies inlined.
 *
 *   PLAYWRIGHT_DIR=/path/to/a/node_modules/playwright node test/browser/run-browsers.mjs
 *
 * Playwright is not a dependency of hap-core (it would be the only one of its size, for one
 * check); the script takes an existing install by path, with its browsers installed
 * (`npx playwright install webkit chromium`). Without PLAYWRIGHT_DIR it says so and exits 2.
 *
 * The page is served from 127.0.0.1 on a free port (a secure context, so WebCrypto is there),
 * and the server and browsers are stopped before the script exits. Exit 1 if any case fails.
 */
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'tsup';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const pwDir = process.env.PLAYWRIGHT_DIR;
if (!pwDir) {
  console.error('PLAYWRIGHT_DIR is not set: point it at an installed playwright package (see the header of this file).');
  process.exit(2);
}
const { webkit, chromium } = await import(pathToFileURL(join(resolve(pwDir), 'index.mjs')).href);

const out = mkdtempSync(join(tmpdir(), 'hap-core-browsers-'));
await build({
  entry: { bundle: join(root, 'src/browser.ts') }, outDir: out, format: ['esm'], platform: 'browser',
  target: 'es2022', bundle: true, noExternal: [/.*/], dts: false, sourcemap: false, clean: true, silent: true, config: false,
});
const bundleFile = readdirSync(out).find((f) => f.startsWith('bundle'));

const files = {
  '/bundle.mjs': join(out, bundleFile),
  '/browser-entry-runner.mjs': join(root, 'test/vectors/browser-entry/runner.mjs'),
  '/browser-entry.json': join(root, 'test/vectors/browser-entry/browser-entry.json'),
  '/device-keys-runner.mjs': join(root, 'test/vectors/device-keys/runner.mjs'),
};
for (const f of readdirSync(join(root, 'test/vectors/device-keys')).filter((n) => n.endsWith('.json'))) {
  files[`/dk/${f}`] = join(root, 'test/vectors/device-keys', f);
}
const PAGE = `<!doctype html><meta charset="utf-8"><title>hap-core browser vectors</title><script type="module">
import * as hap from '/bundle.mjs';
import { runBrowserEntryVectors } from '/browser-entry-runner.mjs';
import { runVectors, VECTOR_FILES } from '/device-keys-runner.mjs';
const get = (p) => fetch(p).then((r) => r.json());
try {
  const be = await runBrowserEntryVectors(hap, await get('/browser-entry.json'));
  const dk = await runVectors(hap.deviceKeys, await Promise.all(VECTOR_FILES.map((f) => get('/dk/' + f))));
  window.__done = { be, dk, ua: navigator.userAgent };
} catch (e) { window.__done = { error: String(e && e.stack || e) }; }
</script>`;

const server = createServer((req, res) => {
  const path = new URL(req.url, 'http://x').pathname;
  if (path === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end(PAGE); return; }
  const f = files[path];
  if (!f) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'content-type': path.endsWith('.json') ? 'application/json' : 'text/javascript' });
  res.end(readFileSync(f));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const url = `http://127.0.0.1:${server.address().port}/`;

let failed = 0;
try {
  for (const [name, type] of [['webkit', webkit], ['chromium', chromium]]) {
    const browser = await type.launch();
    try {
      const page = await browser.newPage();
      const errors = [];
      page.on('pageerror', (e) => errors.push(String(e)));
      await page.goto(url);
      await page.waitForFunction(() => window.__done, null, { timeout: 120_000 });
      const r = await page.evaluate(() => window.__done);
      if (r.error || errors.length) { console.log(`${name}: ERROR ${r.error ?? errors.join('; ')}`); failed++; continue; }
      const bad = [...r.be, ...r.dk].filter((x) => !x.ok);
      for (const b of bad) console.log(`${name}: FAIL ${b.suite ?? 'browser-entry'} ${b.id}: ${b.detail}`);
      failed += bad.length;
      console.log(`${name} (${r.ua}): browser-entry ${r.be.filter((x) => x.ok).length}/${r.be.length}, device-keys ${r.dk.filter((x) => x.ok).length}/${r.dk.length}`);
    } finally {
      await browser.close();
    }
  }
} finally {
  await new Promise((r) => server.close(r));
  rmSync(out, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
