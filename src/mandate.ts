/**
 * Mandate encoding, decoding, signing, and verification (v0.7).
 *
 * Renamed from `attestation.ts` (protocol.md → *Migration from v0.6*:
 * `header.typ: "HAP-attestation"` → `"HAP-mandate"`, `attestation_id` →
 * `mandate_id`). v0.3's frame-hash path and v0.4's dual frame/bounds
 * verification are retired with the rest of pre-v0.5 — this module issues
 * and verifies `version: "0.7"` mandates only (CLAUDE.md "Decided by the
 * owner": no backward-compat verify path for 0.5/0.6).
 */

import { createHash } from 'crypto';
import * as ed from '@noble/ed25519';
import { canonicalize } from './canonicalize';
import { toBase64Url, fromBase64Url } from './base64url';
import { decodeDidKey, isKeyBearingDid } from './did-key';
import { HapError } from './errors';
import { PROTOCOL_VERSION } from './versions';
import type { Mandate, MandateHeader, MandatePayload } from './types';

/** Clock-skew tolerance (Mandate rule 9): `issued_at`/`expires_at` checks
 * tolerate up to 300s, and the tolerance never extends life past
 * `expires_at + 300s`. */
const CLOCK_SKEW_SECONDS = 300;

/**
 * Decodes a base64url-encoded mandate blob.
 * @throws HapError `MALFORMED_MANDATE` on anything that is not a strict
 * base64url-encoded JSON mandate.
 */
export function decodeMandateBlob(blob: string): Mandate {
  let json: string;
  try {
    json = new TextDecoder().decode(fromBase64Url(blob));
  } catch (err) {
    throw new HapError('MALFORMED_MANDATE', `failed to decode mandate blob: ${(err as Error).message}`);
  }
  try {
    return JSON.parse(json);
  } catch (err) {
    throw new HapError('MALFORMED_MANDATE', `mandate blob did not decode to JSON: ${err}`);
  }
}

/**
 * Encodes a mandate as a base64url blob (no padding).
 */
export function encodeMandateBlob(mandate: Mandate): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(mandate)));
}

/**
 * Computes the mandate blob id (hash of the blob) — renamed from
 * `attestationId`.
 */
export function mandateBlobId(blob: string): string {
  const hash = createHash('sha256').update(blob, 'utf8').digest('hex');
  return `sha256:${hash}`;
}

/**
 * Sign a mandate payload with the Authority Server's Ed25519 private key.
 *
 * @param opts.kid Optional key id for the envelope header. When present it
 * MUST identify the same key as `payload.issuer` (Mandate rule 8) — this
 * function does not enforce that on the signer's side; `verifyMandateSignature`
 * enforces it on the verifier's side, where a mismatch is actually dangerous.
 */
export async function signMandate(
  payload: MandatePayload,
  privateKey: Uint8Array,
  opts?: { kid?: string },
): Promise<Mandate> {
  const header: MandateHeader = { typ: 'HAP-mandate', alg: 'EdDSA', ...(opts?.kid ? { kid: opts.kid } : {}) };
  const signature = toBase64Url(await ed.signAsync(new TextEncoder().encode(canonicalize(payload)), privateKey));
  return { header, payload, signature };
}

/**
 * Verifies a mandate's Ed25519 signature. The verification key is resolved
 * from `payload.issuer` itself — never from a key offered alongside the
 * artifact (protocol.md → *Ticket Verification* step 1, which states the
 * same rule for tickets; mandates follow it identically).
 *
 * @param opts.trustedIssuers When supplied, an `issuer` not in this list is
 * rejected before any cryptography runs — "a verifier MUST reject a [...]
 * whose `issuer` it does not trust" (protocol.md → *Ticket Verification*).
 * @throws Error prefixed `INVALID_SIGNATURE:` on any verification failure.
 */
export async function verifyMandateSignature(
  mandate: Mandate,
  opts?: { trustedIssuers?: readonly string[] },
): Promise<void> {
  const { issuer } = mandate.payload;

  if (opts?.trustedIssuers && !opts.trustedIssuers.includes(issuer)) {
    throw new HapError('INVALID_SIGNATURE', `issuer ${JSON.stringify(issuer)} is not a trusted Authority Server`);
  }

  let publicKey: Uint8Array;
  try {
    publicKey = decodeDidKey(issuer);
  } catch (err) {
    // Not every valid `issuer` need be a did:key (it MAY be a did:web that
    // resolves to one) — but this package resolves did:key issuers only;
    // anything else cannot be verified offline here.
    throw new HapError('INVALID_SIGNATURE', `cannot resolve a key from issuer ${JSON.stringify(issuer)}: ${(err as Error).message}`);
  }

  // Mandate rule 8: a present kid MUST identify the same key as issuer.
  if (mandate.header.kid !== undefined) {
    const fingerprint = issuer.startsWith('did:key:') ? issuer.slice('did:key:'.length) : undefined;
    if (mandate.header.kid !== fingerprint) {
      throw new HapError('INVALID_SIGNATURE', 'header.kid disagrees with issuer\'s key (Mandate rule 8) — the field a verifier cannot forge wins');
    }
  }

  const payloadBytes = new TextEncoder().encode(canonicalize(mandate.payload));
  let sigBytes: Uint8Array;
  try {
    sigBytes = fromBase64Url(mandate.signature);
  } catch (err) {
    throw new HapError('INVALID_SIGNATURE', `${(err as Error).message}`);
  }

  const isValid = await ed.verifyAsync(sigBytes, payloadBytes, publicKey).catch(() => false);
  if (!isValid) {
    throw new HapError('INVALID_SIGNATURE', 'mandate signature verification failed');
  }
}

/**
 * Checks a mandate payload's time rules (Mandate rule 9): `expires_at` is
 * authoritative, with a {@link CLOCK_SKEW_SECONDS} tolerance that never
 * extends life past `expires_at + 300s`.
 *
 * @throws Error prefixed `TTL_EXPIRED:` when expired.
 */
export function checkMandateExpiry(
  payload: MandatePayload,
  now: number = Math.floor(Date.now() / 1000),
): void {
  if (now > payload.expires_at + CLOCK_SKEW_SECONDS) {
    throw new HapError('TTL_EXPIRED', `mandate expired at ${payload.expires_at}, current time is ${now}`);
  }
}

/** The signature fields that are present together or absent together on a
 * `mandate_owners` entry (Mandate rule 7). */
const OWNER_SIGNATURE_FIELDS = ['alg', 'signature', 'signed_at', 'nonce', 'binding', 'signing_surface'] as const;

/**
 * Validates the structural shape of `mandate_owners` (Mandate rule 7):
 * exactly one entry, `did` required, and the signature fields present
 * together or absent together. A co-signing entry's `did` MUST be key-bearing.
 *
 * @throws HapError `MALFORMED_MANDATE` on a cardinality or completeness
 * violation; `OWNER_SIGNATURE_INVALID` when a co-signing DID is not key-bearing.
 */
export function validateMandateOwners(payload: MandatePayload): void {
  const owners = payload.mandate_owners;
  if (!Array.isArray(owners) || owners.length !== 1) {
    throw new HapError(
      'MALFORMED_MANDATE',
      `mandate_owners MUST contain exactly one entry in v0.7, got ${Array.isArray(owners) ? owners.length : typeof owners}`,
    );
  }
  const entry = owners[0];
  if (!entry.did) {
    throw new HapError('MALFORMED_MANDATE', 'mandate_owners[0].did is required');
  }

  const present = OWNER_SIGNATURE_FIELDS.filter((f) => entry[f] !== undefined);
  if (present.length > 0 && present.length < OWNER_SIGNATURE_FIELDS.length) {
    const missing = OWNER_SIGNATURE_FIELDS.filter((f) => entry[f] === undefined);
    throw new HapError(
      'MALFORMED_MANDATE',
      `mandate_owners[0] carries [${present.join(', ')}] but not [${missing.join(', ')}] — ` +
        'signature fields are present together or absent together (Mandate rule 7)',
    );
  }
  if (present.length === OWNER_SIGNATURE_FIELDS.length && !isKeyBearingDid(entry.did)) {
    throw new HapError('OWNER_SIGNATURE_INVALID', `co-signing DID ${entry.did} is not key-bearing`);
  }
}

/**
 * Full mandate verification: decode, check `version`, verify the AS
 * signature, check expiry, validate `mandate_owners` shape.
 *
 * Deliberately does NOT verify any `mandate_owners` co-signature — that is
 * `verifyOwnerSignature` in `owner-signature.ts`, a separate trust axis the
 * caller opts into.
 *
 * @throws HapError `VERSION_UNSUPPORTED` for anything other than `"0.7"`.
 * @throws Error (`INVALID_SIGNATURE:` / `TTL_EXPIRED:` / `MALFORMED_MANDATE:`
 * prefixed, or `OWNER_SIGNATURE_INVALID` as a HapError) on any other failure.
 */
export async function verifyMandate(
  blob: string,
  opts?: { trustedIssuers?: readonly string[]; now?: number },
): Promise<MandatePayload> {
  const mandate = decodeMandateBlob(blob);

  if (mandate.payload.version !== PROTOCOL_VERSION) {
    throw new HapError(
      'VERSION_UNSUPPORTED',
      `mandate version ${JSON.stringify(mandate.payload.version)} is not verifiable by this implementation ` +
        `(verifies ${PROTOCOL_VERSION} only — re-issue the mandate)`,
    );
  }

  await verifyMandateSignature(mandate, opts);
  checkMandateExpiry(mandate.payload, opts?.now);
  validateMandateOwners(mandate.payload);

  return mandate.payload;
}
