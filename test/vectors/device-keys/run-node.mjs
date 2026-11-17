/**
 * Node entry: run the device-keys vectors against a built bundle.
 *
 *   node test/vectors/device-keys/run-node.mjs [path/to/dist/index.mjs]
 *
 * Default bundle: ../../../dist/index.mjs (also accepts dist/device-keys/index.mjs). Exit code 1 if any case fails.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { runVectors, VECTOR_FILES } from './runner.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const bundle = process.argv[2] ? resolve(process.argv[2]) : join(here, '../../../dist/index.mjs');
const mod = await import(pathToFileURL(bundle).href);
const deviceKeys = mod.deviceKeys ?? mod; // root bundle (namespace) or the ./device-keys subpath bundle
const files = VECTOR_FILES.map((f) => JSON.parse(readFileSync(join(here, f), 'utf8')));
const results = await runVectors(deviceKeys, files);
const failed = results.filter((r) => !r.ok);
for (const r of failed) console.log(`FAIL ${r.suite} ${r.id}: ${r.detail}`);
console.log(`${results.length - failed.length}/${results.length} vector cases passed against ${bundle}`);
process.exit(failed.length ? 1 : 0);
