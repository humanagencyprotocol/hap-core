/**
 * The browser entry's vectors in Node, against the source: browser-entry.json and every
 * device-keys vector file, through `src/browser.ts` exactly as a page imports it. The same runners
 * run in WebKit and Chromium through test/browser/run-browsers.mjs.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import * as hap from '../src/browser';
// @ts-expect-error plain ESM runner without types
import { runBrowserEntryVectors } from './vectors/browser-entry/runner.mjs';
// @ts-expect-error plain ESM runner without types
import { runVectors, VECTOR_FILES } from './vectors/device-keys/runner.mjs';

const dir = (s: string) => join(__dirname, 'vectors', s);

describe('browser entry vectors (Node, from source)', () => {
  it('browser-entry.json', async () => {
    const file = JSON.parse(readFileSync(join(dir('browser-entry'), 'browser-entry.json'), 'utf8'));
    const results: Array<{ id: string; ok: boolean; detail: string }> = await runBrowserEntryVectors(hap, file);
    expect(results.filter(r => !r.ok)).toEqual([]);
    expect(results.length).toBe(file.cases.length);
  });
  it('device-keys vectors through the browser entry', async () => {
    const files = (VECTOR_FILES as string[]).map(f => JSON.parse(readFileSync(join(dir('device-keys'), f), 'utf8')));
    const results: Array<{ ok: boolean }> = await runVectors(hap.deviceKeys, files);
    expect(results.filter(r => !r.ok)).toEqual([]);
    expect(results.length).toBeGreaterThan(100);
  });
});
