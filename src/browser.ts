/**
 * HAP Core — browser-safe entry (`@humanagencyp/hap-core/browser`, since 0.17.0).
 *
 * The part of hap-core a verifier in a web page or an installed web app needs: decode and verify a
 * mandate against a pinned Authority Server key, rebuild the owner's mandate projection, hash a
 * profile, filter an execution context to what a bound reads, and the device-keys module. These are
 * the SAME functions the main entry exports, from the same modules; nothing here is a copy.
 *
 * Every module reached from this file is free of Node-only imports (no `node:*`, no `Buffer`, no
 * `process`); `test/browser-entry.test.ts` bundles this file for the browser and fails on any. The
 * main entry also re-exports modules that are not here (proposal-content encryption, the
 * gatekeeper, tickets); load those from the main entry in Node.
 *
 * WebCrypto comes from `globalThis.crypto` (signatures through `@noble/ed25519`'s async API).
 */

export * from './types';
export * from './canonicalize';
export * from './base64url';
export * from './sha256';
export * from './errors';
export * from './versions';
export * from './did-key';
export * from './commitment-modes';
export * from './profile';
export * from './mandate';
export * from './owner-signature';
export * from './issuance';
/** @experimental Device keys (chain, checks, pairing, grants). The protocol does not define device enrolment yet. */
export * as deviceKeys from './device-keys/index';
