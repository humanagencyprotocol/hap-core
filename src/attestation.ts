/**
 * Attestation Encoding, Decoding, and Verification
 *
 * Supports both v0.3 (frame_hash) and v0.4 (bounds_hash + context_hash).
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
 * Verifies that the frame hash in the attestation matches the expected hash (v0.3).
 *
 * @throws Error if frame hash doesn't match
 */
export function verifyFrameHash(attestation: Attestation, expectedFrameHash: string): void {
  if (attestation.payload.frame_hash !== expectedFrameHash) {
    throw new Error('FRAME_MISMATCH: Frame hash mismatch');
  }
}

/**
 * Detects whether an attestation is v0.4 (has bounds_hash + context_hash)
 * or v0.3 (has frame_hash).
 *
 * Migration rule: if attestation has frame_hash but not bounds_hash, it is v0.3.
 */
export function isV4Attestation(attestation: Attestation): boolean {
  return attestation.payload.bounds_hash !== undefined;
}

/**
 * Verifies that the bounds hash in the attestation matches the expected hash (v0.4).
 *
 * @throws Error if bounds hash doesn't match
 */
export function verifyBoundsHash(attestation: Attestation, expectedBoundsHash: string): void {
  // Migration: if attestation has frame_hash but not bounds_hash, treat frame_hash as bounds_hash
  const attestedHash = attestation.payload.bounds_hash ?? attestation.payload.frame_hash;
  if (attestedHash !== expectedBoundsHash) {
    throw new Error('BOUNDS_MISMATCH: Bounds hash mismatch');
  }
}

/**
 * Verifies that the context hash in the attestation matches the expected hash (v0.4).
 *
 * @throws Error if context hash doesn't match
 */
export function verifyContextHash(attestation: Attestation, expectedContextHash: string): void {
  if (attestation.payload.context_hash !== expectedContextHash) {
    throw new Error('CONTEXT_MISMATCH: Context hash mismatch');
  }
}

/**
 * Full attestation verification (signature + expiry + frame hash) — v0.3.
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

/**
 * Full attestation verification for v0.4 (signature + expiry + bounds_hash + context_hash).
 *
 * @returns The decoded attestation payload
 * @throws Error on any validation failure
 */
export async function verifyAttestationV4(
  blob: string,
  publicKeyHex: string,
  expectedBoundsHash: string,
  expectedContextHash: string
): Promise<AttestationPayload> {
  const attestation = decodeAttestationBlob(blob);

  await verifyAttestationSignature(attestation, publicKeyHex);
  checkAttestationExpiry(attestation.payload);
  verifyBoundsHash(attestation, expectedBoundsHash);
  verifyContextHash(attestation, expectedContextHash);

  return attestation.payload;
}
