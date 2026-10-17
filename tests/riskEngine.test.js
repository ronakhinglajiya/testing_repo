const test = require('node:test');
const assert = require('node:assert/strict');
const E = require('../riskEngine.js');

const sample = (id) => E.SAMPLES.find((s) => s.id === id).input;
const ids = (r) => r.flags.map((f) => f.id);

test('normal example: friend splitting dinner is low risk with no flags', () => {
  const r = E.analyze(sample('normal-dinner'));
  assert.equal(r.level, 'low');
  assert.equal(r.score, 0);
  assert.deepEqual(r.flags, []);
});

test('suspicious: fake cashback collect request asks for PIN to receive', () => {
  const r = E.analyze(sample('fake-cashback-collect'));
  assert.equal(r.level, 'high');
  assert.equal(r.headline, 'Do not share your PIN');
  for (const id of ['pin_to_receive', 'urgency', 'bait', 'collect_from_stranger', 'unknown_recipient']) {
    assert.ok(ids(r).includes(id), `expected ${id}`);
  }
});

test('suspicious: KYC SMS flags both bad links, urgency and impersonation', () => {
  const r = E.analyze(sample('kyc-sms-link'));
  assert.equal(r.level, 'high');
  assert.equal(r.headline, 'Pause and verify');
  const link = r.flags.find((f) => f.id === 'suspicious_link');
  assert.deepEqual(link.matches, ['http://sbi-kyc-update.xyz/login', 'bit.ly/sbi-kyc']);
  assert.ok(ids(r).includes('urgency'));
  assert.ok(ids(r).includes('impersonation'));
});

test('suspicious: OLX QR scam is caught as "PIN to receive"', () => {
  const r = E.analyze(sample('olx-qr-scam'));
  assert.equal(r.level, 'high');
  assert.ok(ids(r).includes('pin_to_receive'));
  assert.ok(ids(r).includes('high_amount'));
});

test('suspicious: refund call asking for AnyDesk and OTP', () => {
  const r = E.analyze(sample('refund-anydesk'));
  assert.equal(r.level, 'high');
  assert.ok(ids(r).includes('share_secret'));
  assert.ok(ids(r).includes('remote_app'));
  assert.ok(ids(r).includes('name_mismatch'));
});

test('scanning a QR to "receive" money is flagged even without the word PIN', () => {
  const r = E.analyze({ kind: 'qr', text: 'Scan this to get the refund', knownContact: false });
  assert.ok(ids(r).includes('pin_to_receive'));
  assert.equal(r.level, 'high');
});

test('official https bank link is not flagged', () => {
  const r = E.analyze({ kind: 'message', text: 'Log in at https://www.onlinesbi.sbi to see your statement', knownContact: true });
  assert.ok(!ids(r).includes('suspicious_link'));
});

test('amounts like 4,999.00 are not mistaken for links', () => {
  const r = E.analyze({ kind: 'pay', text: 'Rent ₹4,999.00 for May', knownContact: true });
  assert.ok(!ids(r).includes('suspicious_link'));
});

test('malformed UPI ID is flagged', () => {
  const r = E.analyze({ kind: 'pay', name: 'Ravi', upiId: 'ravi@@ok bank', knownContact: true });
  assert.ok(ids(r).includes('invalid_upi'));
});

test('a PIN or OTP typed into the message is masked and never returned', () => {
  const r = E.analyze({ text: 'my upi pin is 4821 and OTP: 553201' });
  assert.equal(r.secretRedacted, true);
  assert.ok(!r.cleanText.includes('4821'));
  assert.ok(!r.cleanText.includes('553201'));
  assert.ok(!JSON.stringify(r).includes('4821'));
});

test('every sample matches its expected level', () => {
  for (const s of E.SAMPLES) assert.equal(E.analyze(s.input).level, s.expected, s.id);
  assert.ok(E.SAMPLES.filter((s) => s.expected === 'low').length >= 1);
  assert.ok(E.SAMPLES.filter((s) => s.expected === 'high').length >= 2);
});
