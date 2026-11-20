/**
 * `@humanagencyp/hap-core/browser` loads in a browser: bundling src/browser.ts for the browser,
 * with every dependency inlined, meets no Node built-in, and the bundle names no `Buffer`,
 * `process` or `require`. The same bundle is what test/browser/ runs in WebKit and Chromium.
 */
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, afterAll } from 'vitest';
import { build } from 'tsup';

const out = mkdtempSync(join(tmpdir(), 'hap-core-browser-'));
afterAll(() => rmSync(out, { recursive: true, force: true }));

/**
 * Bundle `entry` for the browser with every package inlined. tsup resolves Node built-ins itself
 * (and drops their `node:` prefix) before any plugin sees them, so the check reads the bundle:
 * with everything inlined, any import left in it is a module the bundler could not inline, i.e. a
 * Node built-in.
 */
async function bundle(entry: string): Promise<{ code: string; leftImports: string[] }> {
  await build({
    entry: { bundle: entry },
    outDir: out,
    format: ['esm'],
    platform: 'browser',
    target: 'es2022',
    bundle: true,
    noExternal: [/.*/],
    dts: false,
    sourcemap: false,
    minify: false,
    clean: true,
    silent: true,
    config: false,
  });
  const file = readdirSync(out).find(f => f.startsWith('bundle'))!;
  const code = readFileSync(join(out, file), 'utf8');
  const leftImports = [
    ...code.matchAll(/(?:^|[;\n])\s*(?:import|export)\b[^;'"]*?\bfrom\s*["']([^"']+)["']/g),
    ...code.matchAll(/(?:^|[;\n])\s*import\s*["']([^"']+)["']/g),
    ...code.matchAll(/\bimport\(\s*["']([^"']+)["']\s*\)/g),
  ].map(m => m[1]);
  return { code, leftImports };
}

describe('browser entry', () => {
  it('bundles for the browser with no Node built-in', async () => {
    const { code, leftImports } = await bundle('src/browser.ts');
    expect(leftImports).toEqual([]);
    expect(code.length).toBeGreaterThan(10_000); // the entry really was bundled, not an empty file
    expect(code).not.toMatch(/\bBuffer\b/);
    expect(code).not.toMatch(/\bprocess\./);
    expect(code).not.toMatch(/\brequire\(/);
  }, 60_000);

  it('the check itself catches a Node import', async () => {
    const { leftImports } = await bundle('test/browser/fixtures/node-import.ts');
    expect(leftImports).toEqual(['crypto']);
  }, 60_000);
});
