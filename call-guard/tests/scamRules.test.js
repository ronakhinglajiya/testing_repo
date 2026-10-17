const test = require('node:test');
const assert = require('node:assert/strict');
const R = require('../public/scamRules.js');
const DEMO = require('../public/demoCalls.js');

const ids = (text, opts) => R.analyze(text, opts).flags.map((f) => f.id);
const level = (text) => R.analyze(text).level;

test('every demo call reaches its expected level', () => {
  for (const call of DEMO) {
    const text = call.lines.map((l) => l[1]).join(' ');
    assert.equal(R.analyze(text).level, call.expected, call.id);
  }
});

test('digital arrest script: alarm fires by the second line', () => {
  const call = DEMO.find((c) => c.id === 'digital-arrest');
  assert.equal(level(call.lines[0][1]), 'safe');
  assert.equal(level(call.lines.slice(0, 2).map((l) => l[1]).join(' ')), 'scam');
});

test('asking for OTP is a scam in English, Hinglish and Hindi', () => {
  assert.ok(ids('Please tell me the OTP you just received').includes('ask_otp'));
  assert.ok(ids('Sir woh OTP bata dijiye').includes('ask_otp'));
  assert.ok(ids('aapke phone pe ek code aaya hoga').includes('ask_otp'));
  assert.ok(ids('आपके फोन पर जो ओटीपी आया है वो बताइए').includes('ask_otp'));
  assert.equal(level('Sir woh OTP bata dijiye'), 'scam');
});

test('card, CVV and PIN requests are critical', () => {
  assert.ok(ids('Just read me the 16 digit card number and CVV').includes('ask_card'));
  assert.ok(ids('card ke peeche wala number bata do').includes('ask_card'));
  assert.ok(ids('What is your UPI PIN?').includes('ask_banking'));
  assert.ok(ids('apna net banking password bataiye').includes('ask_banking'));
});

test('digital arrest and secrecy phrases are caught', () => {
  assert.ok(ids('You are under digital arrest').includes('digital_arrest'));
  assert.ok(ids('aapko giraftar kiya jayega').includes('digital_arrest'));
  assert.ok(ids('Do not tell anyone about this call').includes('secrecy'));
  assert.ok(ids('kisi ko mat batana aur phone mat kaatna').includes('secrecy'));
  assert.ok(ids('किसी को मत बताना').includes('secrecy'));
});

test('police threat plus secrecy gets the combo bonus', () => {
  const r = R.analyze('This is cyber crime police. Do not tell anyone, not even your family.');
  assert.ok(r.score >= 60);
  assert.equal(r.level, 'scam');
});

test('safety advice does not trigger an alarm', () => {
  assert.equal(level('Please do not share your OTP with anyone. We never ask for your CVV or UPI PIN.'), 'safe');
  assert.equal(level('OTP kisi ko mat batana, theek hai?'), 'safe');
  assert.equal(level('Never install AnyDesk if someone asks.'), 'safe');
});

test('ordinary calls stay safe', () => {
  assert.equal(level('Hi beta, dinner pe kab aa rahe ho? Mummy ne rajma banaya hai.'), 'safe');
  assert.equal(level('My office is near the police station, I will reach by 7.'), 'safe');
  assert.equal(level('Your Swiggy order is outside, please come down.'), 'safe');
});

test('digits are masked and spoken codes are flagged', () => {
  const m = R.maskNumbers('haan 4 8 2 1 9 3 aur card 4111 1111 1111 1111');
  assert.ok(!/\d{4}/.test(m.text.replace(/\s/g, '')));
  assert.equal(m.spokenDigits, true);
  assert.ok(ids('haan 4 8 2 1').includes('spoken_digits'));
  assert.ok(ids('nothing here', { spokenDigits: true }).includes('spoken_digits'));
  assert.equal(R.maskNumbers('bill of ₹12,400 is due on the 5th').text, 'bill of ₹12,400 is due on the 5th');
});
