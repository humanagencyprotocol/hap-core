/**
 * WebCrypto presence, checked before a signature is verified.
 *
 * `@noble/ed25519`'s async API hashes with `globalThis.crypto.subtle`. Where it is missing (a page served
 * over plain http from a non-local address, an old runtime), noble throws, and a verifier that turns
 * every throw into "does not verify" would report a genuine signature as forged. Each verify site calls
 * `requireSubtle()` first, so a missing WebCrypto is its own error and never a signature verdict.
 */

/** Thrown when `globalThis.crypto.subtle` is missing: nothing was verified, either way. */
export class CryptoUnavailableError extends Error {
  readonly code = 'CRYPTO_UNAVAILABLE' as const;
  constructor() {
    super('CRYPTO_UNAVAILABLE: WebCrypto (globalThis.crypto.subtle) is not available, so no signature can be checked here');
    this.name = 'CryptoUnavailableError';
  }
}

/** Throws {@link CryptoUnavailableError} unless `globalThis.crypto.subtle` exists. */
export function requireSubtle(): void {
  const s = (globalThis as unknown as { crypto?: { subtle?: unknown } }).crypto?.subtle;
  if (!s) throw new CryptoUnavailableError();
}
