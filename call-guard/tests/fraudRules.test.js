const test = require('node:test');
const assert = require('node:assert/strict');
const R = require('../public/fraudRules.js');
const DEMO = require('../public/demoCalls.js');

const run = (t, o) => R.analyze(t, o);
const ids = (t, o) => run(t, o).flags.map((f) => f.id);

// Each case: [text, expected level, expected fraud type or null, is UPI fraud]
const CASES = [
  // UPI fraud
  ['Aapko 5000 cashback mila hai, bas QR scan karo aur PIN daalo, paise aa jayenge', 'scam', 'upi_fraud', true],
  ['Main aapko collect request bhej raha hoon, accept karo to refund aa jayega', 'scam', 'upi_fraud', true],
  ['Scan this QR code to receive the payment for your sofa', 'scam', 'upi_fraud', true],
  ['Galti se aapke account mein 10000 bhej diye, please wapas kar do', 'caution', 'upi_fraud', true],
  ['मैंने आपको गलती से पैसे भेज दिए, वापस कर दो', 'caution', 'upi_fraud', true],
  ['Verification ke liye ek rupaya bhejo', 'caution', 'upi_fraud', true],
  ['Ghabraiye mat, UPI PIN daal do', 'scam', 'upi_fraud', true],
  // OTP / card / banking
  ['Sir woh OTP bata dijiye na', 'scam', 'otp_fraud', false],
  ['Tension mat lijiye, bas OTP bata dijiye', 'scam', 'otp_fraud', false],
  ['आपके फोन पर जो ओटीपी आया है वो बताइए', 'scam', 'otp_fraud', false],
  ['Dont worry sir, just tell me the CVV', 'scam', 'otp_fraud', false],
  ['Card ke peeche wala number bata do', 'scam', 'otp_fraud', false],
  ['Apna net banking password bataiye', 'scam', 'otp_fraud', false],
  // Digital arrest and threats
  ['You are under digital arrest. Do not tell anyone.', 'scam', 'digital_arrest', false],
  ['यह बहुत गोपनीय मामला है, किसी को मत बताना। आपको गिरफ्तार कर लिया जाएगा।', 'scam', 'digital_arrest', false],
  ['This is cyber crime police. Do not tell anyone, not even your family.', 'scam', 'digital_arrest', false],
  // Others
  ['Download AnyDesk and I will help you get the refund', 'scam', 'remote_access', false],
  ['Aapka bijli connection aaj raat cut ho jayega, turant payment karo', 'scam', 'utility', false],
  ['Part time job hai, telegram pe task, pehle 500 deposit karo', 'scam', 'job_investment', false],
  ['Aapka video viral kar denge agar paise nahi bheje', 'scam', 'extortion', false],
  ['Aapka SBI account aaj block ho jayega, KYC update karna padega', 'caution', 'kyc_block', false],
  // Must stay safe
  ['Please do not share your OTP with anyone. We never ask for your CVV or UPI PIN.', 'safe', null, false],
  ['OTP kisi ko mat batana', 'safe', null, false],
  ['OTP share mat karna kisi ke saath', 'safe', null, false],
  ['Bhaiya pin code bata do delivery ke liye', 'safe', null, false],
  ['Your bill of ₹10,000 is due on the 5th', 'safe', null, false],
  ['Police ne chor ko arrest kiya', 'safe', null, false],
  ['Hi beta, dinner pe kab aa rahe ho? Mummy ne rajma banaya hai.', 'safe', null, false],
  ['Are you free tonight? My manager gave me a gift', 'safe', null, false],
  ['Kal milte hain, bank jaana hai passbook update karne', 'safe', null, false],
  ['Your Swiggy order is outside, please come down', 'safe', null, false]
];

for (const [text, level, type, upi] of CASES) {
  test(`${level.padEnd(7)} ${text}`, () => {
    const r = run(text);
    assert.equal(r.level, level, JSON.stringify(r.flags.map((f) => f.id)));
    assert.equal(r.fraudType ? r.fraudType.id : null, type);
    assert.equal(r.isUpiFraud, upi);
  });
}

test('every demo call reaches its expected level', () => {
  for (const call of DEMO) assert.equal(run(call.lines.map((l) => l[1])).level, call.expected, call.id);
});

test('the UPI demo call is classified as UPI fraud', () => {
  const r = run(DEMO.find((c) => c.id === 'upi-collect').lines.map((l) => l[1]));
  assert.equal(r.fraudType.id, 'upi_fraud');
  assert.equal(r.isUpiFraud, true);
});

test('normalization: spelled letters, Devanagari and wildcards map to one form', () => {
  assert.deepEqual(R.tokenize('O T P bataiye'), ['otp', 'bataiye']);
  assert.deepEqual(R.tokenize('ओटीपी बताइए'), ['otp', 'bata']);
  assert.deepEqual(R.tokenize('any desk download karo'), ['anydesk', 'download', 'karo']);
  assert.ok(ids('Sir phone mat kaatna').includes('secrecy'), 'kaat* should match kaatna');
});

test('digits and digit words are masked and flagged', () => {
  for (const t of ['haan 4 8 2 1 9 3', 'four eight two one', 'चार आठ दो एक', 'char aath do ek']) {
    const m = R.maskNumbers(t);
    assert.equal(m.spokenDigits, true, t);
    assert.ok(m.text.includes('••••'), t);
  }
  assert.ok(!/\d{4}/.test(R.maskNumbers('card 4111 1111 1111 1111').text.replace(/\s/g, '')));
  assert.ok(ids('nothing here', { spokenDigits: true }).includes('spoken_digits'));
  assert.equal(R.maskNumbers('bill of ₹12,400 is due').text, 'bill of ₹12,400 is due');
});

test('words on either side of a sentence break are never paired', () => {
  assert.equal(run(['Main bank mein OTP ke baare mein padh raha tha', 'Kal bata dunga movie kaisi thi']).level, 'safe');
});

test('fast enough for a phone: a long call transcript analyses in well under 50 ms', () => {
  const long = Array(60).fill('Hello sir main SBI head office se bol raha hoon aapka card block ho jayega OTP bata dijiye').join('. ');
  const t = process.hrtime.bigint();
  for (let i = 0; i < 20; i++) run(long);
  const ms = Number(process.hrtime.bigint() - t) / 1e6 / 20;
  assert.ok(ms < 50, `took ${ms.toFixed(1)} ms`);
});
