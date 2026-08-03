/**
 * Content binding (HAP v0.5 Content Provenance) — conformance.
 *
 * Pins the (content → canonical bytes → sha256) contract so an independent
 * verifier in any language reproduces the exact hash the gateway signs into a
 * receipt. The hash is worthless if both sides don't agree on the bytes.
 */
import { describe, it, expect } from 'vitest';
import {
  canonicalizeText,
  contentCanonicalBytes,
  computeContentHash,
  computeFieldsContentHash,
  selectBoundFields,
  isFieldBinding,
  bindingAppliesTo,
  ContentBindingError,
} from '../src/content-binding';
import type { ContentBinding } from '../src/types';

describe('canonicalizeText — text normalization rule', () => {
  it('normalizes CRLF and CR to LF', () => {
    expect(canonicalizeText('a\r\nb\rc')).toBe('a\nb\nc');
  });

  it('strips trailing per-line whitespace and trailing blank lines', () => {
    expect(canonicalizeText('a  \nb\t\n\n\n')).toBe('a\nb');
  });

  it('applies Unicode NFC (composed form wins)', () => {
    // "é" as e + combining acute (NFD) must normalize to the single code point.
    const nfd = 'é';
    const nfc = 'é';
    expect(canonicalizeText(nfd)).toBe(nfc);
    expect(canonicalizeText(nfd)).toBe(canonicalizeText(nfc));
  });

  it('is idempotent', () => {
    const once = canonicalizeText('  héllo \r\nwörld\n\n');
    expect(canonicalizeText(once)).toBe(once);
  });
});

describe('computeContentHash — pinned vectors', () => {
  it('jcs: sorts keys then hashes (order-independent)', () => {
    const a = computeContentHash({ version: '1', kind: 'jcs' }, { title: 'Q3 plan', type: 'note' });
    const b = computeContentHash({ version: '1', kind: 'jcs' }, { type: 'note', title: 'Q3 plan' });
    expect(a).toBe('sha256:82c28e63f951c1ac68080788fda46be42b2128f80c43dbc01d5c3b160a09717f');
    expect(a).toBe(b); // key order in the input must not change the hash
  });

  it('text: hashes the canonicalized string', () => {
    expect(computeContentHash({ version: '1', kind: 'text' }, 'Hello\r\nWorld  '))
      .toBe('sha256:35c6b9f66dceb6cf8f733d08689564e420e18eb40250d9435352617c027f36d6');
  });

  it('text: empty string hashes the sha256 of ""', () => {
    expect(computeContentHash({ version: '1', kind: 'text' }, ''))
      .toBe('sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});

describe('computeContentHash — kind/content mismatch fails closed', () => {
  it('jcs rejects a string', () => {
    expect(() => computeContentHash({ version: '1', kind: 'jcs' }, 'oops' as unknown as Record<string, unknown>))
      .toThrow(/jcs.*record payload/);
  });

  it('text rejects an object', () => {
    expect(() => computeContentHash({ version: '1', kind: 'text' }, { x: 1 } as unknown as string))
      .toThrow(/text.*string/);
  });

  it('contentCanonicalBytes exposes the exact bytes both sides hash', () => {
    expect(contentCanonicalBytes('jcs', { b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });
});

// ─── v2: binding over a declared field subset ────────────────────────────────

/** The shape email@0.5 ships with — used as the realistic case throughout. */
const EMAIL: ContentBinding = {
  version: '2',
  kind: 'jcs',
  fields: ['to', 'cc', 'subject', 'body'],
  required_fields: ['to', 'body'],
  appliesTo: ['send'],
};

describe('isFieldBinding — only v2 with a non-empty list selects a subset', () => {
  it('accepts v2 with fields', () => {
    expect(isFieldBinding(EMAIL)).toBe(true);
  });

  it('rejects v1, and v2 with no usable list', () => {
    expect(isFieldBinding({ version: '1', kind: 'text' })).toBe(false);
    expect(isFieldBinding({ version: '1', kind: 'jcs', fields: ['a'] })).toBe(false);
    expect(isFieldBinding({ version: '2', kind: 'jcs' })).toBe(false);
    expect(isFieldBinding({ version: '2', kind: 'jcs', fields: [] })).toBe(false);
  });
});

describe('bindingAppliesTo — strict, so a contentless action is not refused', () => {
  it('covers a declared action type', () => {
    expect(bindingAppliesTo(EMAIL, 'send')).toBe(true);
  });

  it('does NOT cover another action type — a delete carries no content', () => {
    expect(bindingAppliesTo(EMAIL, 'delete')).toBe(false);
  });

  it('does NOT cover an undeclared action type (opposite of how bounds read it)', () => {
    expect(bindingAppliesTo(EMAIL, undefined)).toBe(false);
  });

  it('with no appliesTo, covers everything including an unknown action', () => {
    const any: ContentBinding = { version: '2', kind: 'jcs', fields: ['body'] };
    expect(bindingAppliesTo(any, undefined)).toBe(true);
    expect(bindingAppliesTo(any, 'delete')).toBe(true);
  });
});

describe('selectBoundFields — what the receipt commits to', () => {
  it('selects exactly the declared fields, ignoring everything else', () => {
    expect(
      selectBoundFields(EMAIL, {
        to: ['a@x.com'],
        bcc: ['secret@x.com'], // NOT bound — a recipient cannot see it
        subject: 'Hi',
        body: 'Hello',
        threadId: 'abc123',
      }),
    ).toEqual({ to: ['a@x.com'], subject: 'Hi', body: 'Hello' });
  });

  it('omits an absent optional field — an email legitimately has no cc', () => {
    const bound = selectBoundFields(EMAIL, { to: ['a@x.com'], body: 'Hello' });
    expect(bound).toEqual({ to: ['a@x.com'], body: 'Hello' });
    expect('cc' in bound).toBe(false);
  });

  it('treats null and empty values as absent, not as a bound empty', () => {
    expect(
      selectBoundFields(EMAIL, { to: ['a@x.com'], cc: [], subject: '', body: 'Hello' }),
    ).toEqual({ to: ['a@x.com'], body: 'Hello' });
  });

  it('canonicalizes strings by the SAME rule kind:"text" uses', () => {
    // The verifier holds the DELIVERED body: CRLF endings, trailing whitespace.
    const sent = selectBoundFields(EMAIL, { to: ['a@x.com'], body: 'Hello\nWorld' });
    const delivered = selectBoundFields(EMAIL, { to: ['a@x.com'], body: 'Hello\r\nWorld  \r\n' });
    expect(delivered).toEqual(sent);
  });

  it('canonicalizes strings inside arrays too', () => {
    expect(selectBoundFields(EMAIL, { to: [' a@x.com', 'b@x.com'], body: 'x' }).to)
      .toEqual([' a@x.com', 'b@x.com']); // leading space kept; only TRAILING is stripped
    expect(selectBoundFields(EMAIL, { to: ['a@x.com  ', ''], body: 'x' }).to)
      .toEqual(['a@x.com']);
  });

  it('preserves recipient order — reordering is a change worth catching', () => {
    const ab = computeFieldsContentHash(EMAIL, { to: ['a@x.com', 'b@x.com'], body: 'x' });
    const ba = computeFieldsContentHash(EMAIL, { to: ['b@x.com', 'a@x.com'], body: 'x' });
    expect(ab).not.toBe(ba);
  });
});

describe('selectBoundFields — refuses rather than binding less than it appears to', () => {
  it('refuses when a required field is absent', () => {
    expect(() => selectBoundFields(EMAIL, { to: ['a@x.com'], subject: 'Hi' }))
      .toThrow(ContentBindingError);
    try {
      selectBoundFields(EMAIL, { to: ['a@x.com'], subject: 'Hi' });
    } catch (err) {
      expect((err as ContentBindingError).code).toBe('MISSING_REQUIRED_FIELD');
      expect((err as ContentBindingError).field).toBe('body');
    }
  });

  it('refuses when a required field is present but empty', () => {
    expect(() => selectBoundFields(EMAIL, { to: ['a@x.com'], body: '   \n\n' }))
      .toThrow(/requires "body"/);
  });

  it('refuses the gmail `raw` bypass — to/body absent because the message is elsewhere', () => {
    expect(() => selectBoundFields(EMAIL, { raw: 'base64url-rfc2822' }))
      .toThrow(ContentBindingError);
  });

  it('refuses a v2 binding that declares no fields', () => {
    expect(() => selectBoundFields({ version: '2', kind: 'jcs' }, { body: 'x' }))
      .toThrow(/non-empty `fields`/);
  });

  it('refuses required_fields that is not a subset of fields', () => {
    expect(() =>
      selectBoundFields(
        { version: '2', kind: 'jcs', fields: ['body'], required_fields: ['to'] },
        { body: 'x', to: ['a@x.com'] },
      ),
    ).toThrow(/must be a subset/);
  });

  it('refuses when no declared field carries a value, even with none required', () => {
    expect(() =>
      selectBoundFields({ version: '2', kind: 'jcs', fields: ['a', 'b'] }, { c: 'x' }),
    ).toThrow(/commit to nothing/);
  });
});

describe('computeFieldsContentHash — pinned vectors an independent verifier must match', () => {
  it('hashes the JCS of the selected object, keys sorted', () => {
    expect(contentCanonicalBytes('jcs', selectBoundFields(EMAIL, {
      subject: 'Hi',
      body: 'Hello',
      to: ['a@x.com'],
    }))).toBe('{"body":"Hello","subject":"Hi","to":["a@x.com"]}');
  });

  it('field ORDER in the profile does not move the hash (JCS sorts keys)', () => {
    const reversed: ContentBinding = { ...EMAIL, fields: ['body', 'subject', 'cc', 'to'] };
    expect(computeFieldsContentHash(reversed, { to: ['a@x.com'], subject: 'Hi', body: 'Hello' }))
      .toBe(computeFieldsContentHash(EMAIL, { to: ['a@x.com'], subject: 'Hi', body: 'Hello' }));
  });

  it('adding a bound recipient moves the hash — the gap this closes', () => {
    const approved = computeFieldsContentHash(EMAIL, { to: ['a@x.com'], body: 'Hello' });
    const redirected = computeFieldsContentHash(EMAIL, { to: ['attacker@evil.com'], body: 'Hello' });
    const ccAdded = computeFieldsContentHash(EMAIL, { to: ['a@x.com'], cc: ['attacker@evil.com'], body: 'Hello' });
    expect(redirected).not.toBe(approved);
    expect(ccAdded).not.toBe(approved);
  });

  it('changing an UNBOUND field does not move the hash — bcc stays verifiable', () => {
    const withoutBcc = computeFieldsContentHash(EMAIL, { to: ['a@x.com'], body: 'Hello' });
    const withBcc = computeFieldsContentHash(EMAIL, { to: ['a@x.com'], body: 'Hello', bcc: ['x@y.com'] });
    expect(withBcc).toBe(withoutBcc);
  });
});
