/**
 * Proposal content — what the Authority Server receives of a proposal
 * (protocol.md → *Proposals — what the Authority Server receives*, v0.8).
 *
 * The content is the action's argument object, serialized as RFC 8785 JCS.
 * Its fingerprint, `proposalContentHash`, is what the AS compares, what the
 * ticket carries and what every `HAP-approval` signs. The content itself is
 * encrypted to its readers — the Mandate Owner and every signed decider —
 * with exactly the construction rule 3 pins byte for byte:
 *
 * - a fresh 32-byte content key (CEK) per proposal;
 * - AES-256-GCM under the CEK, random 12-byte IV, no associated data,
 *   16-byte tag; `ciphertext` = IV ‖ GCM ciphertext ‖ tag;
 * - per reader, HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256),
 *   HKDF-SHA256, AES-256-GCM, empty `info`, the CEK sealed single-shot with
 *   empty associated data; `enc` the 32-byte encapsulated key, `ct` the
 *   48-byte sealed CEK;
 * - every binary value base64url without padding; `encrypted_keys` keyed by
 *   the reader's DID. The reader key is an X25519 key distinct from the
 *   DID's signing key.
 *
 * The conformance vector `proposal-encryption.json` fixes the CEK, the IV
 * and the ephemeral keys so the output is reproducible; real use draws all
 * three at random, and the deterministic hooks exist for that test only.
 */

import { createHash, type webcrypto } from 'crypto';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { canonicalize } from './canonicalize';
import { toBase64Url, fromBase64Url } from './base64url';
import { HapError } from './errors';

export interface ProposalContentEnvelope {
  ciphertext: string;
  encrypted_keys: Record<string, { ct: string; enc: string }>;
  readers: string[];
  unreadable: string[];
}

export interface ReaderKeyPair {
  /** Raw X25519 private key, 32 bytes. */
  privateKey: Uint8Array;
  /** Raw X25519 public key, 32 bytes. */
  publicKey: Uint8Array;
}

function suite(): CipherSuite {
  return new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
}

const webCrypto = (): webcrypto.Crypto => {
  const c = globalThis.crypto as webcrypto.Crypto | undefined;
  if (!c?.subtle) throw new Error('WebCrypto is not available in this runtime');
  return c;
};

/** The content's JCS bytes, as a string (rule 1). */
export function proposalContentJcs(args: Record<string, unknown>): string {
  if (args === null || typeof args !== 'object' || Array.isArray(args)) {
    throw new HapError('PROPOSAL_NOT_ENCRYPTED', 'proposal content is one object — the action\'s argument object');
  }
  return canonicalize(args);
}

/** `proposalContentHash` — `"sha256:" + hex(sha256(JCS(content)))` (rule 4). */
export function computeProposalContentHash(args: Record<string, unknown>): string {
  return `sha256:${createHash('sha256').update(proposalContentJcs(args), 'utf8').digest('hex')}`;
}

/** A fresh reader key pair (X25519). */
export async function generateReaderKeyPair(): Promise<ReaderKeyPair> {
  const kp = await suite().kem.generateKeyPair();
  return exportKeyPair(kp);
}

/** A reader key pair derived from input keying material (RFC 9180
 * DeriveKeyPair) — deterministic; for tests and vectors. */
export async function deriveReaderKeyPair(ikm: Uint8Array): Promise<ReaderKeyPair> {
  const kp = await suite().kem.deriveKeyPair(ikm);
  return exportKeyPair(kp);
}

async function exportKeyPair(kp: webcrypto.CryptoKeyPair): Promise<ReaderKeyPair> {
  const s = suite();
  return {
    privateKey: new Uint8Array(await s.kem.serializePrivateKey(kp.privateKey)),
    publicKey: new Uint8Array(await s.kem.serializePublicKey(kp.publicKey)),
  };
}

export interface EncryptOptions {
  /** Signed deciders for whom no reader key exists; listed, notified, unable to decide. */
  unreadable?: string[];
  /** Deterministic inputs — TESTS AND VECTORS ONLY. */
  deterministic?: {
    contentKey: Uint8Array;
    iv: Uint8Array;
    /** Per reader DID: the ephemeral key material for its HPKE wrap. */
    ephemeralIkm: Record<string, Uint8Array>;
  };
}

/**
 * Encrypt a proposal's content to its readers and compute its fingerprint.
 * @param readers Each reader's DID and raw X25519 reader public key.
 */
export async function encryptProposalContent(
  args: Record<string, unknown>,
  readers: ReadonlyArray<{ did: string; publicKey: Uint8Array }>,
  opts: EncryptOptions = {},
): Promise<{ content: ProposalContentEnvelope; proposalContentHash: string }> {
  if (readers.length === 0) {
    throw new HapError('PROPOSAL_NOT_ENCRYPTED', 'a proposal has at least one reader (the Mandate Owner)');
  }
  const jcs = proposalContentJcs(args);
  const proposalContentHash = computeProposalContentHash(args);
  const crypto = webCrypto();
  const s = suite();

  const cek = opts.deterministic?.contentKey ?? crypto.getRandomValues(new Uint8Array(32));
  const iv = opts.deterministic?.iv ?? crypto.getRandomValues(new Uint8Array(12));
  if (cek.length !== 32 || iv.length !== 12) {
    throw new HapError('PROPOSAL_NOT_ENCRYPTED', 'content key is 32 bytes and IV is 12 bytes');
  }
  const aesKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(jcs)));
  const ciphertext = new Uint8Array(iv.length + sealed.length);
  ciphertext.set(iv, 0);
  ciphertext.set(sealed, iv.length);

  const encrypted_keys: Record<string, { ct: string; enc: string }> = {};
  for (const { did, publicKey } of readers) {
    const recipientPublicKey = await s.kem.deserializePublicKey(publicKey);
    const ekmIkm = opts.deterministic?.ephemeralIkm[did];
    const sender = await s.createSenderContext({
      recipientPublicKey,
      ...(ekmIkm ? { ekm: await s.kem.deriveKeyPair(ekmIkm) } : {}),
    });
    const ct = new Uint8Array(await sender.seal(cek));
    encrypted_keys[did] = { ct: toBase64Url(ct), enc: toBase64Url(new Uint8Array(sender.enc)) };
  }

  return {
    content: {
      ciphertext: toBase64Url(ciphertext),
      encrypted_keys,
      readers: readers.map((r) => r.did),
      unreadable: [...(opts.unreadable ?? [])],
    },
    proposalContentHash,
  };
}

/**
 * Decrypt a proposal's content as one reader. A reader whose HPKE open or
 * GCM decryption fails MUST treat the proposal as unreadable — never as
 * empty or partial content (rule 3); this throws rather than returning.
 * @returns the argument object and its JCS, so the caller recomputes the
 * fingerprint and refuses on a mismatch (rule 8).
 */
export async function decryptProposalContent(
  content: ProposalContentEnvelope,
  readerDid: string,
  readerPrivateKey: Uint8Array,
): Promise<{ arguments: Record<string, unknown>; contentJcs: string; proposalContentHash: string }> {
  const wrap = content.encrypted_keys[readerDid];
  if (!wrap) throw new HapError('PROPOSAL_NOT_ENCRYPTED', `no key wrapped for reader ${readerDid}`);
  const s = suite();
  const crypto = webCrypto();
  let cek: Uint8Array;
  try {
    const recipient = await s.createRecipientContext({
      recipientKey: await s.kem.deserializePrivateKey(readerPrivateKey),
      enc: fromBase64Url(wrap.enc),
    });
    cek = new Uint8Array(await recipient.open(fromBase64Url(wrap.ct)));
  } catch (err) {
    throw new HapError('PROPOSAL_NOT_ENCRYPTED', `proposal content is unreadable for ${readerDid}: ${(err as Error).message}`);
  }
  const bytes = fromBase64Url(content.ciphertext);
  if (bytes.length < 12 + 16) throw new HapError('PROPOSAL_NOT_ENCRYPTED', 'ciphertext is shorter than IV + tag');
  let plaintext: Uint8Array;
  try {
    const aesKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12) }, aesKey, bytes.subarray(12)));
  } catch (err) {
    throw new HapError('PROPOSAL_NOT_ENCRYPTED', `proposal content is unreadable for ${readerDid}: ${(err as Error).message}`);
  }
  const contentJcs = new TextDecoder().decode(plaintext);
  let args: Record<string, unknown>;
  try {
    args = JSON.parse(contentJcs);
  } catch {
    throw new HapError('PROPOSAL_NOT_ENCRYPTED', 'decrypted content is not JSON');
  }
  return { arguments: args, contentJcs, proposalContentHash: computeProposalContentHash(args) };
}

/**
 * The reader-set rules an Authority Server applies at submission (rule 2):
 * `readers` ∪ `unreadable` equals the owner plus the signed deciders;
 * `readers` equals the key set of `encrypted_keys`.
 * @throws HapError `PROPOSAL_APPROVERS_INVALID` | `PROPOSAL_NOT_ENCRYPTED`
 */
export function checkProposalReaders(
  content: ProposalContentEnvelope,
  expected: { ownerDid: string; deciders: readonly string[] },
): void {
  const want = new Set([expected.ownerDid, ...expected.deciders]);
  const have = new Set([...content.readers, ...content.unreadable]);
  if (want.size !== have.size || [...want].some((d) => !have.has(d))) {
    throw new HapError('PROPOSAL_APPROVERS_INVALID', 'readers ∪ unreadable differs from the owner plus the signed deciders');
  }
  const keyed = new Set(Object.keys(content.encrypted_keys));
  const readers = new Set(content.readers);
  if (keyed.size !== readers.size || [...readers].some((d) => !keyed.has(d))) {
    throw new HapError('PROPOSAL_NOT_ENCRYPTED', 'readers differs from the key set of encrypted_keys');
  }
}
