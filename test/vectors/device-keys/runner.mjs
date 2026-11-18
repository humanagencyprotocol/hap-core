/**
 * Runs the device-keys vectors (*.json in this folder) against the `deviceKeys` namespace of
 * a hap-core build. Plain ESM, no Node-only imports: the same file runs in Node (vitest,
 * suveren-e2e) and in a browser page.
 *
 *   import { runVectors } from './runner.mjs';
 *   const results = await runVectors(deviceKeys, [vectorFileJson, ...]);
 *   // results: [{ suite, id, ok, detail }]
 *
 * A case is `{ id, op, input, expect }`. `expect` is `{ error: "NAME" }` (the call must throw a
 * DeviceKeysError with that code) or an `ok` / value shape described per op below.
 */

const unhex = (dk, h) => dk.hexDecode(h);

/** JSON with sorted keys, for order-insensitive comparison. */
function stable(v) {
  if (Array.isArray(v)) return `[${v.map(stable).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stable(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}

function sortedEq(a, b) {
  return stable([...a].sort()) === stable([...b].sort());
}

function resolveChain(spec, fixtures, defaultRoot) {
  let entries;
  if (spec.ref) {
    entries = fixtures.chains[spec.ref];
    entries = entries.slice(0, spec.count ?? entries.length);
    if (spec.append) entries = [...entries, ...spec.append];
  } else {
    entries = spec.entries;
  }
  return { expectedRootDid: spec.expected_root_did ?? defaultRoot, entries };
}

async function verifiedChain(dk, spec, fixtures) {
  return dk.verifyChain(resolveChain(spec, fixtures, fixtures.root_did));
}

const OPS = {
  async 'b64u.decode'(dk, i) {
    return { hex: dk.hexEncode(dk.b64uDecode(i.text)) };
  },
  async signed_bytes(dk, i) {
    const out = {};
    out.hash = await dk.objectHash(i.object);
    out.bytes_utf8 = dk.utf8Decode(dk.signedBytes(i.object));
    return out;
  },
  async key_id(dk, i) {
    return { key_id: await dk.keyIdOf(unhex(dk, i.sign_pub_hex)) };
  },
  async 'recovery.derive'(dk, i) {
    const seed = await dk.parseRecoveryCode(i.code);
    const root = await dk.deriveRootKey(seed);
    return {
      seed_hex: dk.hexEncode(seed),
      root_private_hex: dk.hexEncode(root.privateSeed),
      root_public_hex: dk.hexEncode(root.publicKey),
      did: root.did,
    };
  },
  async 'recovery.encode'(dk, i) {
    return { code: await dk.encodeRecoveryCode(unhex(dk, i.seed_hex)) };
  },
  async 'ed25519.verify'(dk, i) {
    return { valid: await dk.verifyEd25519(unhex(dk, i.public_key_hex), unhex(dk, i.message_hex), unhex(dk, i.signature_hex)) };
  },
  async 'check.verify'(dk, i) {
    return { valid: await dk.verifyCheck(i.check_key, i.hash, i.proof) };
  },
  async 'cose.to_point'(dk, i) {
    return { point_hex: dk.hexEncode(dk.coseEc2ToRawPoint(unhex(dk, i.cose_hex))) };
  },
  async 'cose.to_point'(dk, i) {
    return { point_hex: dk.hexEncode(dk.coseEc2ToRawPoint(unhex(dk, i.cose_hex))) };
  },
  async 'ecdsa.der_to_raw'(dk, i) {
    return { raw_hex: dk.hexEncode(dk.ecdsaDerToRaw(unhex(dk, i.der_hex))) };
  },
  async 'chain.verify'(dk, i, fx) {
    const st = await dk.verifyChain({ ...resolveChain(i.chain, fx, i.expected_root_did ?? fx.root_did), storedHead: i.stored_head ?? null });
    return {
      ok: {
        head: st.head,
        active: dk.activeDevices(st).map((d) => d.key_id),
        granting: dk.grantingDevices(st).map((d) => d.key_id),
        root_pub: st.root_pub,
      },
    };
  },
  async 'signin.verify'(dk, i, fx) {
    const chain = await verifiedChain(dk, i.chain, fx);
    await dk.verifySignin(i.envelope, { aud: i.aud, now: i.now, chain });
    return { ok: true };
  },
  async 'decision.verify'(dk, i, fx) {
    const chain = await verifiedChain(dk, i.chain, fx);
    await dk.verifyDecision(i.envelope, { chain, expect: i.expect });
    return { ok: true };
  },
  async 'grant.verify'(dk, i, fx) {
    const chain = await verifiedChain(dk, i.chain, fx);
    await dk.verifyGrant(i.envelope, { chain, mandateFields: i.mandate_fields, expect: i.expect });
    return { ok: true };
  },
  async 'receipt.verify'(dk, i, fx) {
    const chain = await verifiedChain(dk, i.chain, fx);
    await dk.verifyReceipt(i.envelope, { chain, grant: i.grant });
    return { ok: true };
  },
  async 'identity-cancel.verify'(dk, i, fx) {
    const chain = await verifiedChain(dk, i.chain, fx);
    await dk.verifyIdentityCancel(i.envelope, { chain, aud: i.aud, requestId: i.request_id, now: i.now });
    return { ok: true };
  },
  async 'identity-override.verify'(dk, i, fx) {
    const adminChain = await verifiedChain(dk, i.chain, fx);
    await dk.verifyIdentityOverride(i.envelope, { adminChain, aud: i.aud, requestId: i.request_id, memberUserId: i.member_user_id, now: i.now });
    return { ok: true };
  },
  async 'pairing.derive'(dk, i) {
    const d = await dk.derivePairing(dk.b64uDecode(i.secret));
    return { pairing_id: d.pairingId, mac_key_hex: dk.hexEncode(d.macKey) };
  },
  async 'pairing.qr.decode'(dk, i) {
    const qr = dk.decodePairingQr(i.text, { now: i.now });
    return { qr, text: dk.encodePairingQr(qr) };
  },
  async 'pairing.message.verify'(dk, i) {
    await dk.verifyPairingMessage(unhex(dk, i.mac_key_hex), i.message);
    return { ok: true };
  },
  async 'pairing.commitment'(dk, i) {
    const c = await dk.pairingCommitment(i.entry, dk.b64uDecode(i.joiner_sig), dk.b64uDecode(i.r_j));
    return { c };
  },
  async 'pairing.code'(dk, i) {
    return { code: await dk.comparisonCode(unhex(dk, i.mac_key_hex), i.entry, dk.b64uDecode(i.r_j), dk.b64uDecode(i.r_a)) };
  },
  async 'identity.code'(dk, i) {
    return { code: await dk.identityCode(i.root_did) };
  },
};

function matches(actual, expect, stash) {
  for (const [k, v] of Object.entries(expect)) {
    if (k === 'differs_from') {
      const val = Object.values(actual)[0];
      if (val === v) return `expected a value different from ${v}`;
    } else if (k === 'ok' && typeof v === 'object') {
      const a = actual.ok;
      if (stable(a.head) !== stable(v.head)) return `head ${JSON.stringify(a.head)} != ${JSON.stringify(v.head)}`;
      if (!sortedEq(a.active, v.active)) return `active ${a.active} != ${v.active}`;
      if (!sortedEq(a.granting, v.granting)) return `granting ${a.granting} != ${v.granting}`;
      if (a.root_pub !== v.root_pub) return `root_pub ${a.root_pub} != ${v.root_pub}`;
    } else if (stable(actual[k]) !== stable(v)) {
      return `${k}: got ${JSON.stringify(actual[k])}, want ${JSON.stringify(v)}`;
    }
  }
  return null;
}

/**
 * @param dk the `deviceKeys` namespace of a hap-core build
 * @param files array of parsed vector files
 * @returns {Promise<{suite:string,id:string,ok:boolean,detail:string}[]>}
 */
export async function runVectors(dk, files) {
  const results = [];
  for (const file of files) {
    for (const c of file.cases) {
      const r = { suite: file.suite, id: c.id, ok: false, detail: '' };
      try {
        const op = OPS[c.op];
        if (!op) throw new Error(`unknown op ${c.op}`);
        let actual;
        let thrown = null;
        try {
          actual = await op(dk, c.input, file.fixtures ?? {});
        } catch (e) {
          thrown = e;
        }
        if (c.expect.error) {
          if (!thrown) r.detail = `expected ${c.expect.error}, got success`;
          else if (thrown.code !== c.expect.error) r.detail = `expected ${c.expect.error}, got ${thrown.code ?? thrown}`;
          else r.ok = true;
        } else if (thrown) {
          r.detail = `unexpected ${thrown.code ?? thrown}: ${thrown.message}`;
        } else {
          const why = matches(actual, c.expect);
          if (why) r.detail = why;
          else r.ok = true;
        }
      } catch (e) {
        r.detail = `runner error: ${e && e.message ? e.message : e}`;
      }
      results.push(r);
    }
  }
  return results;
}

/** Names of the vector files, in order. */
export const VECTOR_FILES = ['encoding', 'recovery', 'ed25519-strict', 'der', 'checks', 'chain', 'objects', 'pairing', 'identity'].map((n) => `${n}.json`);
