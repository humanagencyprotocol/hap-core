import { describe, it, expect } from 'vitest';
import { invalidFieldKindsReason, filesFields, computeContentHash, selectBoundFields } from '../src';
import type { ContentBinding } from '../src';

const EMAIL: ContentBinding = {
  version: '2', kind: 'jcs',
  fields: ['to', 'cc', 'subject', 'body', 'attachments'],
  required_fields: ['to', 'body'],
  field_kinds: { to: 'list', cc: 'list', subject: 'text', body: 'text', attachments: 'files' },
};

describe('content_binding.field_kinds', () => {
  it('a well-formed declaration is accepted; absent is fine too', () => {
    expect(invalidFieldKindsReason(EMAIL)).toBeNull();
    expect(invalidFieldKindsReason({ ...EMAIL, field_kinds: undefined })).toBeNull();
  });

  it('refuses a kind for a field that is not bound', () => {
    expect(invalidFieldKindsReason({ ...EMAIL, field_kinds: { bcc: 'list' } })).toMatch(/bcc/);
  });

  it('refuses an unknown kind', () => {
    expect(invalidFieldKindsReason({ ...EMAIL, field_kinds: { body: 'html' as never } })).toMatch(/text, list, files/);
  });

  it('filesFields names the files fields — by declaration, not by name', () => {
    expect(filesFields(EMAIL)).toEqual(['attachments']);
    expect(filesFields({ ...EMAIL, field_kinds: { body: 'text' } })).toEqual([]);
  });

  it('is a hint only — the hash is the same with or without it', () => {
    const args = { to: ['a@x.com'], body: 'Hi', attachments: [{ filename: 'a.pdf', sha256: 'ab' }] };
    const without = { ...EMAIL, field_kinds: undefined };
    expect(computeContentHash(EMAIL, selectBoundFields(EMAIL, args)))
      .toBe(computeContentHash(without, selectBoundFields(without, args)));
  });
});
