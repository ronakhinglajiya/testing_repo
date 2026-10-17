/*
 * Scripted sample calls for demo mode. All names and stories are fictional.
 * Each line is fed into the same pipeline as live speech-to-text output.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.DemoCalls = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  return [
    {
      id: 'digital-arrest',
      label: '"Digital arrest" (fake CBI / FedEx)',
      expected: 'scam',
      lang: 'en-IN',
      lines: [
        ['Caller', 'Hello, am I speaking with Mr. Sharma? I am calling from FedEx courier service, Mumbai.'],
        ['Caller', 'A parcel booked on your Aadhaar number has been seized by customs. It has five passports and 200 grams of MDMA drugs.'],
        ['You', 'What? I have not sent any parcel.'],
        ['Caller', 'I am connecting you to Mumbai Cyber Crime police. Please hold the line.'],
        ['Caller', 'This is Inspector Vikram Rathore. A money laundering case is registered against you and the CBI has issued an arrest warrant.'],
        ['Caller', 'You are under digital arrest from now. Stay on the video call and do not disconnect.'],
        ['Caller', 'Do not tell anyone, not even your family. This is a confidential national security matter.'],
        ['Caller', 'To prove you are innocent, transfer your funds to the RBI safe account for verification. It is refundable.'],
        ['Caller', 'Do it immediately, or police will reach your house within two hours.']
      ]
    },
    {
      id: 'bank-otp',
      label: '"Card will be blocked" OTP scam (Hinglish)',
      expected: 'scam',
      lang: 'hi-IN',
      lines: [
        ['Caller', 'Hello sir, main SBI head office se bol raha hoon, bank manager Rajesh Kumar.'],
        ['Caller', 'Aapka debit card aaj raat 12 baje block ho jayega, aapka KYC update pending hai.'],
        ['You', 'Arey, kyun? Ab main kya karoon?'],
        ['Caller', 'Tension mat lijiye sir, main abhi update kar deta hoon. Bas card ke peeche wala CVV aur expiry date bata dijiye.'],
        ['Caller', 'Aapke mobile pe ek OTP aaya hoga, 6 digit ka. Woh OTP jaldi bata dijiye.'],
        ['You', 'Haan, 4 8 2 1 9 3'],
        ['Caller', 'Sir phone mat kaatna, ek aur OTP aayega.']
      ]
    },
    {
      id: 'hindi-police',
      label: 'पुलिस धमकी (Hindi, Devanagari)',
      expected: 'scam',
      lang: 'hi-IN',
      lines: [
        ['Caller', 'नमस्ते, मैं दिल्ली पुलिस साइबर क्राइम से इंस्पेक्टर बोल रहा हूँ।'],
        ['Caller', 'आपके आधार कार्ड से एक पार्सल गया है जिसमें ड्रग्स मिले हैं, आपके खिलाफ केस दर्ज है।'],
        ['You', 'लेकिन मैंने कुछ नहीं भेजा।'],
        ['Caller', 'यह बहुत गोपनीय मामला है, किसी को मत बताना और फोन मत काटना।'],
        ['Caller', 'अगर आपने तुरंत पैसे ट्रांसफर नहीं किए तो आपको गिरफ्तार कर लिया जाएगा।']
      ]
    },
    {
      id: 'upi-collect',
      label: 'UPI "accept request to get paid" (OLX buyer)',
      expected: 'scam',
      lang: 'hi-IN',
      lines: [
        ['Caller', 'Hello, main OLX se bol raha hoon, aapka sofa kharidna hai.'],
        ['You', 'Haan ji, 12,000 ka hai.'],
        ['Caller', 'Theek hai, main army mein hoon, abhi payment kar deta hoon.'],
        ['Caller', 'Maine aapko collect request bheji hai, accept kar do, paise aa jayenge.'],
        ['You', 'Accept karne pe PIN maang raha hai.'],
        ['Caller', 'Haan, UPI PIN daal do, tabhi paise aapke account mein aa jayenge. Jaldi karo.']
      ]
    },
    {
      id: 'normal-bank',
      label: 'Normal bill reminder from a bank',
      expected: 'safe',
      lang: 'en-IN',
      lines: [
        ['Caller', "Hi, this is Priya from HDFC Bank. I'm calling to remind you that your credit card bill of ₹12,400 is due on the 5th."],
        ['You', 'Oh okay, thanks for reminding me.'],
        ['Caller', 'You can pay it from the HDFC app or net banking whenever it suits you. Please note we will never ask for your OTP, PIN or CVV.'],
        ['You', "Sure, I'll pay it this weekend."],
        ['Caller', 'Great, have a nice day!']
      ]
    }
  ];
});
