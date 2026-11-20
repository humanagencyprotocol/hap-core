/**
 * Runs browser-entry.json against a build of `@humanagencyp/hap-core/browser` (or the main entry:
 * the functions are the same). Plain ESM, no Node-only imports: the same file runs in vitest and
 * in a browser page.
 *
 *   import { runBrowserEntryVectors } from './runner.mjs';
 *   const results = await runBrowserEntryVectors(hap, vectorFileJson);  // [{ id, ok, detail }]
 */

function stable(v) {
  if (Array.isArray(v)) return `[${v.map(stable).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stable(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}
const unhex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
const codeOf = (e) => e?.code ?? String(e?.message ?? e).split(':')[0];

async function runOne(hap, c) {
  const i = c.input;
  switch (c.op) {
    case 'verifyMandate': {
      const p = await hap.verifyMandate(i.blob, { trustedIssuers: [i.pinned_did], now: i.now });
      return { ok: p.mandate_id };
    }
    case 'verifyMandateWithoutSubtle': {
      // Hide WebCrypto for this one call (an own property shadows the page's getter), then put it back.
      const own = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
      Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true, writable: true });
      try {
        const p = await hap.verifyMandate(i.blob, { trustedIssuers: [i.pinned_did], now: i.now });
        return { ok: p.mandate_id };
      } finally {
        if (own) Object.defineProperty(globalThis, 'crypto', own); else delete globalThis.crypto;
      }
    }
    case 'buildMandateProjection': {
      const p = hap.buildMandateProjection(i.payload, i.entry);
      return { projection: p, signing_bytes_sha256: hap.sha256Hex(hap.projectionSigningBytes(p)) };
    }
    case 'computeProfileHash': return { value: hap.computeProfileHash(i.profile) };
    case 'boundReadFields': return { value: [...hap.boundReadFields(i.profile)].sort() };
    case 'wireExecutionContext': return { value: hap.wireExecutionContext(i.execution, i.profile) };
    case 'encodeDidKey': return { value: hap.encodeDidKey(unhex(i.public_key_hex)) };
    case 'sha256Hex': return { value: hap.sha256Hex(i.text) };
    case 'base64url': {
      const s = hap.toBase64Url(unhex(i.hex));
      const back = [...hap.fromBase64Url(s)].map((b) => b.toString(16).padStart(2, '0')).join('');
      if (back !== i.hex) throw new Error(`round trip gave ${back}`);
      return { value: s };
    }
    default: throw new Error(`unknown op ${c.op}`);
  }
}

export async function runBrowserEntryVectors(hap, file) {
  const results = [];
  for (const c of file.cases) {
    let got;
    try { got = await runOne(hap, c); } catch (e) { got = { error: codeOf(e) }; }
    const ok = stable(got) === stable(c.expect);
    results.push({ id: c.id, ok, detail: ok ? '' : `expected ${stable(c.expect)}, got ${stable(got)}` });
  }
  return results;
}
