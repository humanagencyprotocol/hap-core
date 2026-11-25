import json, hmac, hashlib, base64, copy, os
D = os.path.dirname(os.path.abspath(__file__))  # this folder, wherever the repo is checked out
os.chdir(D)

p = 'runner.mjs'
s = open(p).read()
s = s.replace("await dk.verifyGrant(i.envelope, { chain, mandateFields: i.mandate_fields });", "await dk.verifyGrant(i.envelope, { chain, mandateFields: i.mandate_fields, expect: i.expect });")
s = s.replace("const qr = dk.decodePairingQr(i.text, i.now === undefined ? {} : { now: i.now });", "const qr = dk.decodePairingQr(i.text, { now: i.now });")
s = s.replace("  async 'ecdsa.der_to_raw'", "  async 'cose.to_point'(dk, i) {\n    return { point_hex: dk.hexEncode(dk.coseEc2ToRawPoint(unhex(dk, i.cose_hex))) };\n  },\n  async 'ecdsa.der_to_raw'", 1)
open(p, 'w').write(s)


def load(n): return json.load(open(n))
def save(n, o): open(n, 'w').write(json.dumps(o, indent=2, ensure_ascii=False) + '\n')
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def jcs(o): return json.dumps(o, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

# ---- objects
o = load('objects.json')
byid = {c['id']: c for c in o['cases']}
DEF = {'proposal_id': 'prop-1', 'mandate_id': 'mand-1', 'action': 'send_email', 'action_type': 'send', 'proposal_content_hash': 'sha256:' + '22' * 32}
for c in o['cases']:
    if c['op'] == 'decision.verify':
        c['input']['expect'] = {**DEF, **c['input'].get('expect', {})}
    if c['op'] == 'grant.verify':
        g = c['input']['envelope']['grant']
        c['input']['expect'] = {'ops': ['revoke'] if g['op'] == 'revoke' else ['grant', 'change'], 'mandate_id': g['mandate_id'], 'mandate_version': g['mandate_version']}

def clone(id, new, description, expect_input, error):
    c = copy.deepcopy(byid[id]); c['id'] = new; c['description'] = description
    if expect_input is None: c['input'].pop('expect', None)
    else: c['input']['expect'] = expect_input
    c['expect'] = {'error': error}
    o['cases'].append(c)

rv = byid['grant-revoke-without-check']['input']['expect']
gk = byid['grant-by-computer-with-platform-check']['input']['expect']
clone('grant-revoke-without-check', 'grant-revoke-read-as-grant', 'a revoke (no check needed) read by a caller that expects grant or change', {'ops': ['grant', 'change'], 'mandate_id': rv['mandate_id'], 'mandate_version': rv['mandate_version']}, 'GRANT_MISMATCH')
clone('grant-by-computer-with-platform-check', 'grant-for-other-mandate-id', 'a genuine grant of mand-1 presented for mand-2', {**gk, 'mandate_id': 'mand-2'}, 'GRANT_MISMATCH')
clone('grant-by-computer-with-platform-check', 'grant-for-other-version', 'a genuine grant of version 2 presented for version 1', {**gk, 'mandate_version': 1}, 'GRANT_MISMATCH')
clone('grant-by-computer-with-platform-check', 'grant-expect-missing', 'the caller gives no expectation', None, 'MALFORMED')
clone('decision-commit-by-phone', 'decision-expect-missing', 'the caller gives no expectation', None, 'MALFORMED')
clone('decision-commit-by-phone', 'decision-expect-incomplete', 'only some proposal members are given', {'proposal_id': 'prop-1'}, 'MALFORMED')
save('objects.json', o)

# ---- pairing
pr = load('pairing.json'); pb = {c['id']: c for c in pr['cases']}
for c in pr['cases']:
    if c['op'] == 'pairing.qr.decode' and 'now' not in c['input']:
        c['input']['now'] = 1794000010
qrj = pb['qr-joiner']['expect']['qr']
def qrtext(q): return 'SUVEREN-PAIR-1:' + b64u(jcs(q).encode())
def addqr(id, desc, q, expect):
    pr['cases'].append({'id': id, 'description': desc, 'op': 'pairing.qr.decode', 'input': {'text': qrtext(q), 'now': 1794000010}, 'expect': expect})
addqr('qr-as-url-http-remote', 'as_url over plain http to a remote host', {**qrj, 'as_url': 'http://evil.example'}, {'error': 'MALFORMED'})
addqr('qr-as-url-not-a-url', 'as_url is not an address', {**qrj, 'as_url': 'javascript:alert(1)'}, {'error': 'MALFORMED'})
q2 = {**qrj, 'as_url': 'http://127.0.0.1:4100'}
addqr('qr-as-url-local-http-allowed', 'plain http is allowed for 127.0.0.1 (dev lane)', q2, {'qr': q2, 'text': qrtext(q2)})
pr['cases'].append({'id': 'qr-now-missing', 'description': 'expiry cannot be skipped by leaving out now', 'op': 'pairing.qr.decode', 'input': {'text': pb['qr-joiner']['input']['text']}, 'expect': {'error': 'MALFORMED'}})
mkhex = pb['derive']['expect']['mac_key_hex']
mk = bytes.fromhex(mkhex)
hello = pb['mac-hello']['input']['message']
def mac(kind, body): return b64u(hmac.new(mk, kind.encode() + b'\0' + jcs(body).encode(), hashlib.sha256).digest())
for id, seq in [('hello-head-seq-fractional', 1.5), ('hello-head-seq-negative', -1), ('hello-head-seq-string', '3')]:
    body = copy.deepcopy(hello['body']); body['head']['seq'] = seq
    pr['cases'].append({'id': id, 'op': 'pairing.message.verify', 'input': {'mac_key_hex': mkhex, 'message': {'kind': 'hello', 'body': body, 'mac': mac('hello', body)}}, 'expect': {'error': 'MALFORMED'}})
save('pairing.json', pr)

# ---- chain
ch = load('chain.json'); main = ch['fixtures']['chains']['main']
HEX64 = 'sha256:' + '0' * 64
def addc(id, desc, chain, error, stored=None):
    inp = {'chain': chain}
    if stored is not None: inp['stored_head'] = stored
    ch['cases'].append({'id': id, 'description': desc, 'op': 'chain.verify', 'input': inp, 'expect': {'error': error}})
for id, sh in [('stored-head-empty-object', {}), ('stored-head-without-hash', {'seq': 1}), ('stored-head-without-seq', {'hash': HEX64}), ('stored-head-negative-seq', {'seq': -1, 'hash': HEX64}), ('stored-head-fractional-seq', {'seq': 1.5, 'hash': HEX64}), ('stored-head-uppercase-hash', {'seq': 1, 'hash': 'sha256:' + 'A' * 64})]:
    addc(id, 'a malformed stored head must not switch the rollback and fork checks off', {'ref': 'main', 'count': 3}, 'MALFORMED', sh)
def mut(i, f):
    e = copy.deepcopy(main[i]); f(e); return {'ref': 'main', 'count': i, 'append': [e]}
G = ch['fixtures']['devices']['G']
addc('extra-signature', 'a signature by a device this entry does not need (self-removal of H by H, plus G)', mut(4, lambda e: e['sigs'].append({'by': G, 'sig': e['sigs'][0]['sig']})), 'MALFORMED')
addc('extra-check', 'a check this entry does not need (self-removal needs none)', mut(4, lambda e: e['checks'].append({'by': G, 'check': main[1]['checks'][0]['check']})), 'MALFORMED')
addc('oversized-check-proof', 'a check proof string of 5000 characters', mut(1, lambda e: e['checks'][0]['check'].__setitem__('signature', 'A' * 5000)), 'MALFORMED')
addc('check-proof-extra-member-type', 'a check proof member that is not a string', mut(1, lambda e: e['checks'][0]['check'].__setitem__('extra', {'a': 1})), 'MALFORMED')
addc('label-zero-width-space', 'device label with U+200B', mut(1, lambda e: e['device'].__setitem__('label', 'Office​PC')), 'MALFORMED')
addc('label-bidi-override', 'device label with U+202E', mut(1, lambda e: e['device'].__setitem__('label', 'Office‮PC')), 'MALFORMED')
addc('label-tag-character', 'device label with U+E0041', mut(1, lambda e: e['device'].__setitem__('label', 'Office\U000E0041PC')), 'MALFORMED')
addc('read-pub-equals-sign-pub', 'one device record with the same key as signing and reading key', mut(1, lambda e: e['device'].__setitem__('read_pub', e['device']['sign_pub'])), 'MALFORMED')
save('chain.json', ch)

# ---- COSE
ck = load('checks.json')
cose = base64.urlsafe_b64decode(main[1]['device']['check']['pub'] + '==')
x = cose[10:42]; y = cose[45:77]
assert cose[:10] == bytes([0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20]) and cose[42:45] == bytes([0x22, 0x58, 0x20])
def addk(id, desc, b, exp): ck['cases'].append({'id': id, 'description': desc, 'op': 'cose.to_point', 'input': {'cose_hex': b.hex()}, 'expect': exp})
addk('cose-canonical', 'CTAP2 canonical COSE_Key', cose, {'point_hex': '04' + x.hex() + y.hex()})
addk('cose-non-minimal-integer', 'kty written as 0x18 0x02', bytes([0xa5, 1, 0x18, 2]) + cose[3:], {'error': 'MALFORMED'})
addk('cose-map-order', 'y before x', bytes([0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x22, 0x58, 0x20]) + y + bytes([0x21, 0x58, 0x20]) + x, {'error': 'MALFORMED'})
addk('cose-extra-member', 'six members', bytes([0xa6]) + cose[1:] + bytes([0x04, 0x01]), {'error': 'MALFORMED'})
save('checks.json', ck)
print('patched')
