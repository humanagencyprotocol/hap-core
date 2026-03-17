/**
 * Attestation Encoding, Decoding, and Verification
 */

import { createHash } from 'crypto';
import * as ed from '@noble/ed25519';
import type { Attestation, AttestationPayload } from './types';

/**
 * Decodes a base64url-encoded attestation blob.
 */
export function decodeAttestationBlob(blob: string): Attestation {
  try {
    const base64 = blob.replace(/-/g, '+').replace(/_/g, '/');
    const padding = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
    const json = Buffer.from(base64 + padding, 'base64').toString('utf8');
    return JSON.parse(json);
  } catch {
    throw new Error('MALFORMED_ATTESTATION: Failed to decode attestation blob');
  }
}

/**
 * Encodes an attestation as a base64url blob (no padding).
 */
export function encodeAttestationBlob(attestation: Attestation): string {
  const json = JSON.stringify(attestation);
  const base64 = Buffer.from(json, 'utf8').toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Computes the attestation ID (hash of the blob).
 */
export function attestationId(blob: string): string {
  const hash = createHash('sha256').update(blob, 'utf8').digest('hex');
  return `sha256:${hash}`;
}

/**
 * Verifies an attestation signature using the SP public key.
 *
 * @returns true if valid
 * @throws Error with code prefix if invalid
 */
export async function verifyAttestationSignature(
  attestation: Attestation,
  publicKeyHex: string
): Promise<void> {
  try {
    const payloadJson = JSON.stringify(attestation.payload);
    const payloadBytes = new TextEncoder().encode(payloadJson);
    const signatureBytes = Buffer.from(attestation.signature, 'base64');
    const publicKeyBytes = Buffer.from(publicKeyHex, 'hex');

    const isValid = await ed.verifyAsync(signatureBytes, payloadBytes, publicKeyBytes);

    if (!isValid) {
      throw new Error('INVALID_SIGNATURE: Attestation signature verification failed');
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('INVALID_SIGNATURE')) throw error;
    throw new Error(`INVALID_SIGNATURE: Signature verification error: ${error}`);
  }
}

/**
 * Checks if an attestation has expired.
 *
 * @throws Error if expired
 */
export function checkAttestationExpiry(
  payload: AttestationPayload,
  now: number = Math.floor(Date.now() / 1000)
): void {
  if (payload.expires_at <= now) {
    throw new Error(
      `TTL_EXPIRED: Attestation expired at ${payload.expires_at}, current time is ${now}`
    );
  }
}

/**
 * Verifies that the frame hash in the attestation matches the expected hash.
 *
 * @throws Error if frame hash doesn't match
 */
export function verifyFrameHash(attestation: Attestation, expectedFrameHash: string): void {
  if (attestation.payload.frame_hash !== expectedFrameHash) {
    throw new Error('FRAME_MISMATCH: Frame hash mismatch');
  }
}

/**
 * Full attestation verification (signature + expiry + frame hash).
 *
 * @returns The decoded attestation payload
 * @throws Error on any validation failure
 */
export async function verifyAttestation(
  blob: string,
  publicKeyHex: string,
  expectedFrameHash: string
): Promise<AttestationPayload> {
  const attestation = decodeAttestationBlob(blob);

  await verifyAttestationSignature(attestation, publicKeyHex);
  checkAttestationExpiry(attestation.payload);
  verifyFrameHash(attestation, expectedFrameHash);

  return attestation.payload;
}
