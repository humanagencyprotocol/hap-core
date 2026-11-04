/**
 * Conformance vectors — proposal-encryption.json (new in v0.8).
 *
 * "This argument object, under these fixed keys, encrypts to exactly these
 * bytes." Pins the HPKE mode, the empty info and associated data, the
 * IV ‖ ciphertext ‖ tag layout and the encodings. Two implementations that
 * cannot read each other's proposals cannot interoperate at all.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  computeProposalContentHash, proposalContentJcs, encryptProposalContent, decryptProposalContent,
  deriveReaderKeyPair, checkProposalReaders,
} from '../../src/proposal-content';
import { VECTORS_DIR, haveVectors, requireVectors } from './_spec-dir';

interface Reader {
  did: string;
  ikm_hex: string;
  reader_private_key_hex: string;
  reader_public_key_hex: string;
  ephemeral_ikm_hex: string;
}

interface VectorFile {
  inputs: {
    arguments: Record<string, unknown>;
    content_jcs: string;
    content_key_hex: string;
    iv_hex: string;
    readers: Reader[];
  };
  expected: {
    content: { ciphertext: string; encrypted_keys: Record<string, { ct: string; enc: string }>; readers: string[]; unreadable: string[] };
    proposalContentHash: string;
  };
}

const hex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

requireVectors();

describe.skipIf(!haveVectors)('conformance vectors — proposal-encryption', () => {
  const file = JSON.parse(readFileSync(join(VECTORS_DIR, 'proposal-encryption.json'), 'utf8')) as VectorFile;
  const { inputs, expected } = file;

  it('the content is the JCS of the argument object, and the fingerprint is its sha256', () => {
    expect(proposalContentJcs(inputs.arguments)).toBe(inputs.content_jcs);
    expect(computeProposalContentHash(inputs.arguments)).toBe(expected.proposalContentHash);
  });

  it('reader key pairs derive from the given ikm (RFC 9180 DeriveKeyPair)', async () => {
    for (const r of inputs.readers) {
      const kp = await deriveReaderKeyPair(hex(r.ikm_hex));
      expect(Buffer.from(kp.publicKey).toString('hex')).toBe(r.reader_public_key_hex);
      expect(Buffer.from(kp.privateKey).toString('hex')).toBe(r.reader_private_key_hex);
    }
  });

  it('encrypts to exactly the published envelope under the fixed CEK, IV and ephemeral keys', async () => {
    const readers = inputs.readers.map((r) => ({ did: r.did, publicKey: hex(r.reader_public_key_hex) }));
    const ephemeralIkm: Record<string, Uint8Array> = {};
    for (const r of inputs.readers) ephemeralIkm[r.did] = hex(r.ephemeral_ikm_hex);
    const { content, proposalContentHash } = await encryptProposalContent(inputs.arguments, readers, {
      deterministic: { contentKey: hex(inputs.content_key_hex), iv: hex(inputs.iv_hex), ephemeralIkm },
    });
    expect(proposalContentHash).toBe(expected.proposalContentHash);
    expect(content).toEqual(expected.content);
  });

  it('every reader decrypts the published envelope with its own private key and recomputes the fingerprint', async () => {
    for (const r of inputs.readers) {
      const out = await decryptProposalContent(expected.content, r.did, hex(r.reader_private_key_hex));
      expect(out.contentJcs).toBe(inputs.content_jcs);
      expect(out.arguments).toEqual(inputs.arguments);
      expect(out.proposalContentHash).toBe(expected.proposalContentHash);
    }
  });

  it('a reader with the wrong key gets "unreadable", never empty or partial content', async () => {
    const [a, b] = inputs.readers;
    await expect(decryptProposalContent(expected.content, a.did, hex(b.reader_private_key_hex))).rejects.toThrow(/PROPOSAL_NOT_ENCRYPTED/);
    const tampered = { ...expected.content, ciphertext: expected.content.ciphertext.slice(0, -2) + 'AA' };
    await expect(decryptProposalContent(tampered, a.did, hex(a.reader_private_key_hex))).rejects.toThrow(/PROPOSAL_NOT_ENCRYPTED/);
  });

  it('the reader sets are checked as sets against the owner plus the signed deciders', () => {
    const [owner, approver] = inputs.readers.map((r) => r.did);
    expect(() => checkProposalReaders(expected.content, { ownerDid: owner, deciders: [approver] })).not.toThrow();
    expect(() => checkProposalReaders(expected.content, { ownerDid: owner, deciders: [approver, 'did:key:z6MkextraApprover'] })).toThrow(/PROPOSAL_APPROVERS_INVALID/);
    expect(() => checkProposalReaders(expected.content, { ownerDid: owner, deciders: [] })).toThrow(/PROPOSAL_APPROVERS_INVALID/);
    const keysDiffer = { ...expected.content, readers: [owner] };
    expect(() => checkProposalReaders(keysDiffer, { ownerDid: owner, deciders: [approver] })).toThrow(/PROPOSAL_APPROVERS_INVALID|PROPOSAL_NOT_ENCRYPTED/);
  });

  it('a fresh (random) envelope round-trips and differs from the vector', async () => {
    const readers = inputs.readers.map((r) => ({ did: r.did, publicKey: hex(r.reader_public_key_hex) }));
    const { content, proposalContentHash } = await encryptProposalContent(inputs.arguments, readers);
    expect(proposalContentHash).toBe(expected.proposalContentHash);
    expect(content.ciphertext).not.toBe(expected.content.ciphertext);
    const out = await decryptProposalContent(content, inputs.readers[1].did, hex(inputs.readers[1].reader_private_key_hex));
    expect(out.arguments).toEqual(inputs.arguments);
  });
});
