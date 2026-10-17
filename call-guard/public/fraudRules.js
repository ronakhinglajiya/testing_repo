/*
 * Ruko fraud rules: on-device, rule-based fraud detection for call transcripts
 * and messages. No network, no AI model, no API key. Runs in well under a
 * millisecond per update, so it is cheap enough for low-end phones.
 *
 * Pipeline
 *   1. normalize  lower-case, map Hindi (Devanagari) words and spelling variants
 *                 to one canonical Roman form, hide OTP/card/PIN digits
 *   2. concepts   find word lists ("concepts") in the token stream: OTP, ASK, NEG ...
 *   3. rules      a rule fires when its concepts occur close together
 *                 (e.g. ASK within 6 words of OTP, with no "never"/"mat" nearby)
 *   4. verdict    points -> safe / caution / scam, and the fraud type with the
 *                 most points (UPI fraud, OTP fraud, digital arrest ...)
 *
 * Works in the browser (window.FraudRules) and in Node (require).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.FraudRules = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var POINTS = { critical: 40, high: 20, medium: 10 };
  var CAUTION_AT = 25;
  var SCAM_AT = 60;
  var BOUNDARY = '|';

  // ---------------------------------------------------------------------------
  // 1. Normalization
  // ---------------------------------------------------------------------------

  // Multi-word variants -> one canonical form, applied to the whole lower-cased text.
  var PHRASE_CANON = [
    [/\bnahi?n?\s+to\b|\bnahin\s+to\b|नहीं\s+तो|नही\s+तो/g, 'warna'],
    [/(\d),(?=\d{2,3}\b)/g, '$1'],
    [/\bo\s*\.?\s*t\s*\.?\s*p\b/g, 'otp'],
    [/\bc\s*\.?\s*v\s*\.?\s*v\b/g, 'cvv'],
    [/\bu\s*\.?\s*p\s*\.?\s*i\b/g, 'upi'],
    [/\bk\s*\.?\s*y\s*\.?\s*c\b/g, 'kyc'],
    [/\bq\s*\.?\s*r\b(\s+code)?/g, 'qr'],
    [/\bm\s*-?\s*pin\b/g, 'mpin'],
    [/\bany\s+desk\b/g, 'anydesk'],
    [/\bteam\s+viewer\b/g, 'teamviewer'],
    [/\bquick\s+support\b/g, 'quicksupport'],
    [/\bdon'?t\b|\bdo\s+not\b/g, 'dont'],
    // Reassurance is not a negation: "don't worry, just tell me the CVV".
    [/\bdont\s+(worry|panic|be\s+scared|be\s+afraid|be\s+worried)\b/g, 'reassure'],
    [/\b(tension|fikar|fikr|chinta|pareshan)\s+(mat|na|nahi)\b|\b(mat|na)\s+(ghabra\w*|dar\w*)\b|\bghabra\w*\s+(mat|nahi)\b|\bdar\w*\s+(mat|nahi)\b/g, 'reassure'],
    [/(चिंता|टेंशन|फिकर|फ़िक्र)\s+(मत|न|ना)|घबरा\S*\s+(मत|नहीं)|डर\S*\s+(मत|नहीं)/g, 'reassure'],
    [/\bwon'?t\b|\bwill\s+not\b/g, 'wont'],
    [/\bcan'?t\b|\bcannot\b/g, 'cant'],
    [/₹\s*(\d+)/g, 'rs $1'],
    [/\brs\.?\s*(\d+)/g, 'rs $1'],
    [/\bwhats\s*app\b/g, 'whatsapp'],
    [/\bphone\s*pe\b/g, 'phonepe'],
    [/\bg\s*pay\b|\bgoogle\s+pay\b/g, 'gpay'],
    [/\bpay\s*tm\b/g, 'paytm'],
    [/\bnet\s*banking\b|\binternet\s+banking\b/g, 'netbanking'],
    [/\bscreen\s*shar\w*/g, 'screenshare']
  ];

  // Everyday phrases that contain risky words but are harmless.
  var NEUTRAL = [
    /\bpin\s*code\b|\bpincode\b|\bpostal\s+code\b|\bzip\s+code\b/g,
    /\b(promo|coupon|discount|referral|dress|area|std)\s+code\b/g,
    /पिन\s*कोड/g
  ];

  // Devanagari token -> canonical Roman token. Checked in order; a regex
  // starting with ^ and no $ is a stem (बताइए, बताओ, बताना -> bata).
  var DEVANAGARI = [
    [/^ओटीपी$|^ओटिपी$/, 'otp'], [/^कोड$/, 'code'], [/^पिन$/, 'pin'], [/^एमपिन$/, 'mpin'],
    [/^सीवीवी$/, 'cvv'], [/^कार्ड$/, 'card'], [/^नंबर$|^नम्बर$/, 'number'], [/^एक्सपायरी$/, 'expiry'],
    [/^पीछे$/, 'peeche'], [/^पासवर्ड$/, 'password'], [/^यूपीआई$/, 'upi'], [/^केवाईसी$/, 'kyc'],
    [/^बता/, 'bata'], [/^बोलिए$|^बोलिये$|^बोलो$/, 'bolo'], [/^भेज/, 'bhej'], [/^डाल/, 'daal'], [/^दीजिए$|^दीजिये$/, 'dijiye'],
    [/^दे$/, 'de'], [/^दो$/, 'do'], [/^शेयर$/, 'share'], [/^सुनाइए$|^सुनाओ$/, 'sunao'], [/^पढ़िए$|^पढ़ो$/, 'padho'], [/^लिखिए$|^लिखो$/, 'likho'],
    [/^मत$/, 'mat'], [/^नहीं$|^नही$/, 'nahi'], [/^ना$/, 'na'], [/^कभी$/, 'kabhi'],
    [/^आया$/, 'aaya'], [/^आएगा$|^आयेगा$/, 'aayega'], [/^मिला$/, 'mila'], [/^मिलेगा$|^मिलेंगे$/, 'milenge'],
    [/^आ$/, 'aa'], [/^जाएंगे$|^जायेंगे$|^जाएगा$|^जायेगा$/, 'jayega'],
    [/^पैसे$|^पैसा$/, 'paise'], [/^रुपया$/, 'rupaya'], [/^रुपये$|^रुपए$/, 'rupaye'], [/^रिफंड$/, 'refund'], [/^कैशबैक$/, 'cashback'],
    [/^स्कैन$/, 'scan'], [/^क्यूआर$/, 'qr'], [/^रिक्वेस्ट$/, 'request'], [/^अप्रूव$/, 'approve'], [/^एक्सेप्ट$/, 'accept'],
    [/^गलती$|^ग़लती$/, 'galti'], [/^वापस$/, 'wapas'], [/^लौटा/, 'lauta'],
    [/^गिरफ्तार|^गिरफ़्तार/, 'giraftar'], [/^अरेस्ट$/, 'arrest'], [/^डिजिटल$/, 'digital'], [/^वारंट$/, 'warrant'],
    [/^सीबीआई$/, 'cbi'], [/^ड्रग्स$/, 'drugs'], [/^पुलिस$/, 'police'], [/^कस्टम/, 'customs'], [/^कूरियर$/, 'courier'],
    [/^पार्सल$/, 'parcel'], [/^कोर्ट$/, 'court'], [/^जेल$/, 'jail'], [/^केस$/, 'case'], [/^दर्ज$/, 'darj'],
    [/^किसी$/, 'kisi'], [/^को$/, 'ko'], [/^भी$/, 'bhi'], [/^फोन$|^फ़ोन$/, 'phone'], [/^कॉल$/, 'call'], [/^काट/, 'kaat'],
    [/^घर$/, 'ghar'], [/^वालों$|^वालो$/, 'walo'], [/^गोपनीय$/, 'confidential'],
    [/^तुरंत$/, 'turant'], [/^जल्दी$/, 'jaldi'], [/^अभी$/, 'abhi'], [/^ब्लॉक$/, 'block'], [/^बंद$/, 'band'],
    [/^खाता$|^खाते$|^अकाउंट$/, 'account'], [/^बैंक$/, 'bank'], [/^मैनेजर$/, 'manager'], [/^अधिकारी$/, 'officer'],
    [/^इंस्पेक्टर$/, 'inspector'], [/^ट्रांसफर$/, 'transfer'], [/^सेफ$/, 'safe'], [/^एनीडेस्क$/, 'anydesk'],
    [/^स्क्रीन$/, 'screen'], [/^ऐप$|^एप$/, 'app'], [/^लिंक$/, 'link'], [/^डाउनलोड$/, 'download'], [/^क्लिक$/, 'click'],
    [/^लॉटरी$/, 'lottery'], [/^इनाम$/, 'inaam'], [/^जीत/, 'jeet'], [/^लोन$/, 'loan'], [/^बिजली$/, 'bijli'],
    [/^कनेक्शन$/, 'connection'], [/^कट$/, 'cut'], [/^वीडियो$/, 'video'], [/^वायरल$/, 'viral'],
    [/^एक$/, 'ek']
  ];

  // Digits spoken as words. Speech-to-text often writes "four eight two one"
  // or "चार आठ दो एक" instead of 4821.
  var DIGIT_WORDS = {
    zero: 1, one: 1, two: 1, three: 1, four: 1, five: 1, six: 1, seven: 1, eight: 1, nine: 1,
    shunya: 1, ek: 1, do: 1, teen: 1, char: 1, chaar: 1, paanch: 1, panch: 1, chhe: 1, che: 1, saat: 1, aath: 1, nau: 1,
    'शून्य': 1, 'एक': 1, 'दो': 1, 'तीन': 1, 'चार': 1, 'पांच': 1, 'पाँच': 1, 'छह': 1, 'छः': 1, 'सात': 1, 'आठ': 1, 'नौ': 1
  };

  function canonToken(tok) {
    if (/[ऀ-ॿ]/.test(tok)) {
      for (var i = 0; i < DEVANAGARI.length; i++) {
        if (DEVANAGARI[i][0].test(tok)) return DEVANAGARI[i][1];
      }
    }
    return tok;
  }

  /**
   * Hide codes a person may read out: runs of 4+ digits ("4821", "4 8 2 1")
   * and runs of 4+ digit words ("four eight two one", "चार आठ दो एक").
   * Returns the masked text and whether separately spoken digits were found.
   */
  function maskNumbers(text) {
    var spoken = false;
    var out = String(text || '').replace(/\d(?:[\s-]?\d){3,}/g, function (run) {
      if (/\d[\s-]\d[\s-]\d[\s-]\d/.test(run)) spoken = true;
      return '••••';
    });
    // digit words: scan word by word, mask runs of 4 or more
    var words = out.split(/(\s+)/);
    var runStart = -1, runLen = 0, i;
    function closeRun(end) {
      if (runLen >= 4) {
        spoken = true;
        for (var k = runStart; k < end; k++) words[k] = k === runStart ? '••••' : '';
      }
      runStart = -1; runLen = 0;
    }
    for (i = 0; i < words.length; i++) {
      if (/^\s+$/.test(words[i])) continue;
      var w = words[i].toLowerCase().replace(/[.,!?।]+$/, '');
      if (DIGIT_WORDS[w] || /^\d$/.test(w)) {
        if (runStart === -1) runStart = i;
        runLen++;
      } else {
        closeRun(i);
      }
    }
    closeRun(words.length);
    out = words.join('').replace(/\s{2,}/g, ' ');
    return { text: out, spokenDigits: spoken };
  }

  /**
   * Text -> canonical tokens. Sentence ends (and each utterance from speech
   * recognition) become BOUNDARY tokens so rules never pair words across them.
   */
  function tokenize(text) {
    var t = String(text || '').normalize('NFC').toLowerCase();
    NEUTRAL.forEach(function (re) { t = t.replace(re, ' _ '); });
    PHRASE_CANON.forEach(function (p) { t = t.replace(p[0], p[1]); });
    t = t.replace(/[.?!।|\n]+/g, ' | ');
    t = t.replace(/[^a-z0-9ऀ-ॿ•|_' ]+/g, ' ');
    return t.split(/\s+/).filter(Boolean).map(function (tok) {
      return tok === '|' ? BOUNDARY : canonToken(tok.replace(/'/g, ''));
    });
  }

  // ---------------------------------------------------------------------------
  // 2. Concepts (word lists). A trailing * matches any ending: bata* = bata,
  //    batao, bataiye, batana. Multi-word phrases must appear in order.
  // ---------------------------------------------------------------------------
  var CONCEPTS = {
    ASK: ['tell', 'share', 'send', 'give', 'read', 'provide', 'confirm', 'forward', 'enter', 'type', 'say', 'speak', 'dictate', 'note down',
      // Only command forms: "bol raha hoon" (I'm speaking) and "padh raha tha" (I was reading) are not requests.
      'what is', 'whats', 'bata*', 'bolo', 'boliye', 'bol do', 'bol dijiye', 'bol dena', 'de do', 'dedo', 'dijiye', 'dijie', 'dena', 'do',
      'bhej*', 'daal*', 'dal do', 'dalo', 'likho', 'likhiye', 'sunao', 'sunaiye', 'suna do', 'padho', 'padhiye', 'padh ke', 'kya hai'],
    // "na" and "no" are left out on purpose: "bata do na" is a request, and "no problem, ..." is not a negation.
    NEG: ['not', 'never', 'dont', 'wont', 'cant', 'mat', 'nahi', 'nahin', 'kabhi'],

    OTP: ['otp', 'one time password', 'verification code', 'security code', 'code'],
    ARRIVED: ['aaya', 'aya', 'aayega', 'ayega', 'aa gaya', 'aagaya', 'received', 'receive', 'came', 'come', 'mila', 'milega', 'got'],
    UPI_PIN: ['upi pin', 'pin', 'mpin', 'atm pin', 'pin number', 'secret pin'],
    CARD: ['cvv', 'cvc', 'card number', 'card no', 'card ka number', 'card ke number', 'card details', 'card ki details', 'expiry', 'expiry date',
      'valid thru', 'valid till', 'card ke peeche', 'back of your card', 'back of the card', '16 digit', 'sixteen digit'],
    PASSWORD: ['password', 'passcode', 'netbanking', 'login id', 'user id', 'customer id', 'login details'],

    PAY_ACTION: ['scan', 'scan kar*', 'scanner', 'qr', 'qr code', 'approve', 'accept', 'collect request', 'payment request', 'request',
      'pin daal*', 'pin dal*', 'pin enter', 'enter pin', 'enter your pin', 'enter upi pin', 'pay button', 'pay par click', 'pay pe click', 'click on pay'],
    RECEIVE: ['receive', 'receiving', 'get money', 'get the money', 'get the amount', 'credited', 'credit ho*', 'credit kar*', 'paise aa jayega', 'paisa aa jayega',
      'paise aa jayenge', 'aa jayega', 'aa jayenge', 'milenge', 'milega', 'jama', 'refund', 'cashback', 'prize', 'reward', 'winning amount',
      'account mein aa', 'khate mein'],
    MISTAKE: ['galti se', 'galti', 'by mistake', 'mistakenly', 'mistake', 'wrongly', 'wrong number', 'wrong account', 'accidentally'],
    RETURN: ['wapas', 'waapas', 'return', 'send back', 'back kar*', 'refund kar*', 'lauta*'],
    SMALL_AMOUNT: ['rs 1', 'rs 2', 'rs 5', 'rs 10', 'ek rupaya', 'ek rupay', 'ek rupee', 'one rupee', '1 rupee', 'token amount',
      'verification amount', 'registration fee', 'processing fee', 'security deposit', 'activation fee'],
    PAY_WORD: ['pay', 'send', 'transfer', 'bhej*', 'daal*', 'payment'],
    SAFE_ACCOUNT: ['safe account', 'secure account', 'rbi account', 'government account', 'verification account', 'saare paise', 'all your money',
      'all the money', 'fd tod*', 'fixed deposit tod*', 'break your fd'],
    TRANSFER: ['transfer', 'bhej*', 'send money', 'paise bhej*', 'pay kar*', 'deposit'],

    REMOTE_APP: ['anydesk', 'teamviewer', 'quicksupport', 'rustdesk', 'airdroid', 'screenshare', 'screen share', 'share screen', 'share your screen',
      'download app', 'download the app', 'download this app', 'app download', 'install app', 'install the app', 'install this app',
      'app install', 'apk'],
    LINK: ['link', 'click', 'link pe click', 'link par click', 'click on the link'],

    ARREST: ['digital arrest', 'arrest warrant', 'warrant', 'under arrest', 'you will be arrested', 'arrest kar*', 'arrest ho*',
      'giraftar kar*', 'giraftar ho*', 'giraftari', 'cbi', 'ncb', 'enforcement directorate', 'ed officer', 'narcotics',
      'money laundering', 'hawala', 'drugs', 'mdma', 'illegal passport*', 'video call pe rah*', 'video call par rah*', 'stay on video call',
      'stay on the video call', 'skype'],
    LAW: ['arrest', 'giraftar*', 'police', 'cyber crime', 'cyber cell', 'crime branch', 'customs', 'fedex', 'dhl', 'courier', 'parcel', 'fir', 'case darj', 'case registered',
      'case file*', 'court', 'jail', 'illegal', 'trai', 'telecom department'],
    SECRECY: ['kisi ko mat bata*', 'kisi ko bhi mat bata*', 'kisi ko nahi bata*', 'kisi ko na bata*', 'dont tell anyone', 'dont tell anybody',
      'tell no one', 'dont tell your family', 'phone mat kaat*', 'call mat kaat*', 'phone mat rakh*', 'call cut mat', 'dont disconnect', 'dont cut the call',
      'dont hang up', 'stay on the line', 'line pe rah*', 'line par rah*', 'ghar walo ko mat', 'ghar walon ko mat', 'family ko mat', 'confidential',
      'secret', 'national security', 'camera on rakh*', 'keep your camera on'],
    URGENCY: ['immediately', 'right now', 'urgent*', 'turant', 'abhi ke abhi', 'jaldi', 'last chance', 'last warning', 'aaj raat', 'aaj hi',
      'today itself', 'within', 'ghante mein', 'minute mein', 'minutes mein', 'hurry', 'asap'],
    BLOCK: ['block', 'blocked', 'block ho jayega', 'band ho jayega', 'band', 'freeze', 'frozen', 'suspend*', 'deactivat*', 'cut ho jayega',
      'kat jayega', 'disconnect*', 'seize*', 'expire*'],
    ACCOUNT: ['account', 'card', 'sim', 'kyc', 'upi', 'wallet', 'bank', 'debit card', 'credit card', 'paytm', 'phonepe', 'gpay', 'yono', 'aadhaar', 'pan'],
    KYC: ['kyc', 'kyc update', 're kyc', 'pan update', 'aadhaar update', 'pan card update'],
    IMPERSONATE: ['bank se', 'bank manager', 'manager', 'head office', 'customer care', 'customer support', 'rbi', 'reserve bank', 'sbi', 'hdfc', 'icici',
      'axis', 'kotak', 'pnb', 'paytm', 'phonepe', 'gpay', 'bhim', 'npci', 'electricity board', 'bijli vibhag', 'income tax', 'officer', 'inspector'],
    BAIT: ['lottery', 'lucky draw', 'kbc', 'kaun banega crorepati', 'prize', 'inaam', 'jeet*', 'you won', 'you have won', 'winner', 'cashback',
      'reward', 'free gift', 'loan approved', 'pre approved', 'preapproved'],
    JOB_INVEST: ['part time job', 'work from home', 'ghar baithe', 'task based', 'like karo', 'youtube like', 'rating task', 'review task', 'telegram',
      'double your money', 'paise double', 'double ho jayenge', 'guaranteed return*', 'daily profit', 'trading', 'crypto', 'bitcoin', 'investment plan', 'high return*'],
    UTILITY: ['bijli', 'electricity', 'light bill', 'electricity bill', 'bijli bill', 'gas connection', 'connection', 'meter'],
    EXTORTION: ['video viral', 'viral kar*', 'photo viral', 'nude', 'morph*', 'blackmail', 'video leak', 'family ko bhej denge']
  };

  // Compile phrases into token arrays once. The * wildcard is swapped for a
  // placeholder first, because tokenize() strips punctuation.
  var WILD = 'qqwild';
  var COMPILED = {};
  Object.keys(CONCEPTS).forEach(function (name) {
    COMPILED[name] = CONCEPTS[name].map(function (p) {
      return tokenize(p.replace(/\*/g, WILD)).map(function (t) { return t.replace(WILD, '*'); });
    });
  });

  function tokenMatches(tok, pat) {
    if (pat.charAt(pat.length - 1) === '*') return tok.indexOf(pat.slice(0, -1)) === 0;
    return tok === pat;
  }

  // Every place a concept occurs: [{start, end}] (end inclusive), longest phrase wins.
  function findConcept(tokens, name) {
    var phrases = COMPILED[name];
    var hits = [];
    for (var i = 0; i < tokens.length; i++) {
      if (tokens[i] === BOUNDARY) continue;
      var best = -1;
      for (var p = 0; p < phrases.length; p++) {
        var ph = phrases[p];
        if (i + ph.length > tokens.length) continue;
        var ok = true;
        for (var k = 0; k < ph.length; k++) {
          if (tokens[i + k] === BOUNDARY || !tokenMatches(tokens[i + k], ph[k])) { ok = false; break; }
        }
        if (ok && ph.length > best) best = ph.length;
      }
      if (best > 0) hits.push({ start: i, end: i + best - 1 });
    }
    return hits;
  }

  // ---------------------------------------------------------------------------
  // 3. Rules
  //    any:  [concept]                fires if the concept appears
  //    near: [conceptA, conceptB...]  fires if all appear within `window` tokens
  //    noNeg: true                    ignore matches with a negation just before,
  //                                   inside, or just after ("never share the OTP",
  //                                   "OTP kisi ko mat batana")
  // ---------------------------------------------------------------------------
  var RULES = [
    { id: 'ask_otp', type: 'otp_fraud', severity: 'critical', near: ['ASK', 'OTP'], window: 6, noNeg: true,
      label: 'Asking for your OTP', labelHi: 'OTP माँग रहा है',
      why: 'No bank, police or company ever asks for an OTP on a call. The OTP is the key to your money.' },
    { id: 'otp_arrived', type: 'otp_fraud', severity: 'critical', near: ['OTP', 'ARRIVED'], window: 5, noNeg: true,
      label: '"You must have got an OTP"', labelHi: '"आपको OTP आया होगा"',
      why: 'Callers say this right before asking you to read the OTP out. Never read it to anyone.' },
    { id: 'ask_card', type: 'otp_fraud', severity: 'critical', near: ['ASK', 'CARD'], window: 7, noNeg: true,
      label: 'Asking for card number, CVV or expiry', labelHi: 'कार्ड नंबर, CVV या एक्सपायरी माँग रहा है',
      why: 'Card number, CVV and expiry are enough to spend your money online.' },
    { id: 'mention_cvv', type: 'otp_fraud', severity: 'high', any: ['CARD'], noNeg: true,
      label: 'Talking about your card details', labelHi: 'कार्ड की जानकारी की बात',
      why: 'A genuine caller never needs your card number, CVV or expiry date.' },
    { id: 'ask_password', type: 'otp_fraud', severity: 'critical', near: ['ASK', 'PASSWORD'], window: 6, noNeg: true,
      label: 'Asking for banking password or login', labelHi: 'बैंकिंग पासवर्ड या लॉगिन माँग रहा है',
      why: 'Your net banking password gives full control of your account.' },
    { id: 'ask_upi_pin', type: 'upi_fraud', severity: 'critical', near: ['ASK', 'UPI_PIN'], window: 6, noNeg: true,
      label: 'Asking for or about your UPI PIN', labelHi: 'UPI PIN माँग रहा है',
      why: 'Your UPI PIN is only for sending money. Anyone who has it can empty your account.' },
    { id: 'pay_to_receive', type: 'upi_fraud', severity: 'critical', near: ['PAY_ACTION', 'RECEIVE'], window: 12, noNeg: true,
      label: 'Scan / approve / enter PIN "to receive money"', labelHi: 'पैसे "पाने" के लिए स्कैन, अप्रूव या PIN',
      why: 'Scanning a QR, approving a request or entering a PIN always SENDS money. You never do it to receive.' },
    { id: 'accidental_transfer', type: 'upi_fraud', severity: 'high', points: 30, near: ['MISTAKE', 'RETURN'], window: 15,
      label: '"Sent money by mistake, please return it"', labelHi: '"गलती से पैसे भेज दिए, वापस करो"',
      why: 'Often the "payment" was a fake SMS or a collect request. Check your bank app balance, not the caller\'s message.' },
    { id: 'small_payment', type: 'upi_fraud', severity: 'high', points: 30, near: ['SMALL_AMOUNT', 'PAY_WORD'], window: 8,
      label: 'Asking for a small "verification" payment', labelHi: '"वेरिफिकेशन" के लिए छोटा भुगतान',
      why: 'A ₹1 or ₹10 "verification" payment is used to get your PIN or start a bigger fraud.' },
    { id: 'safe_account', type: 'digital_arrest', severity: 'high', any: ['SAFE_ACCOUNT'],
      label: 'Move money to a "safe account"', labelHi: '"सेफ अकाउंट" में पैसे डालो',
      why: 'No police, RBI or court holds your money for "verification". This is always fraud.' },
    { id: 'remote_app', type: 'remote_access', severity: 'critical', any: ['REMOTE_APP'], noNeg: true,
      label: 'Asking you to install an app or share your screen', labelHi: 'ऐप डाउनलोड या स्क्रीन शेयर करवा रहा है',
      why: 'Apps like AnyDesk let the caller see and control your phone, including your OTPs.' },
    { id: 'digital_arrest', type: 'digital_arrest', severity: 'critical', any: ['ARREST'],
      label: '"Digital arrest" or arrest threat', labelHi: '"डिजिटल अरेस्ट" या गिरफ्तारी की धमकी',
      why: 'There is no "digital arrest" in Indian law. Police never arrest or question anyone on a video call.' },
    { id: 'law_threat', type: 'digital_arrest', severity: 'high', any: ['LAW'],
      label: 'Police, courier or court story', labelHi: 'पुलिस, कूरियर या कोर्ट की कहानी',
      why: 'Fake police, customs and "FedEx parcel" stories are used to frighten you. Real notices come in writing.' },
    { id: 'secrecy', type: 'digital_arrest', severity: 'high', any: ['SECRECY'],
      label: 'Telling you to keep it secret or stay on the call', labelHi: 'किसी को न बताने या कॉल न काटने को कहना',
      why: 'Scammers cut you off from family so nobody can warn you.' },
    { id: 'block_threat', type: 'kyc_block', severity: 'high', near: ['BLOCK', 'ACCOUNT'], window: 8,
      label: 'Threat to block your account, card or SIM', labelHi: 'खाता, कार्ड या SIM बंद करने की धमकी',
      why: 'Banks send written notice. They do not block accounts over a phone call.' },
    { id: 'utility_cut', type: 'utility', severity: 'high', near: ['UTILITY', 'BLOCK'], window: 10,
      label: 'Threat to cut electricity or gas', labelHi: 'बिजली या गैस कनेक्शन काटने की धमकी',
      why: 'Electricity boards do not disconnect over a call. Pay bills only in the official app.' },
    { id: 'pressure', type: null, severity: 'high', near: ['URGENCY', 'BLOCK'], window: 12, also: [['URGENCY', 'TRANSFER'], ['URGENCY', 'ASK'], ['URGENCY', 'ARREST'], ['URGENCY', 'LAW']],
      label: 'Creating panic or a deadline', labelHi: 'डर या जल्दबाज़ी पैदा करना',
      why: 'Panic stops you thinking. Genuine organisations give you time.' },
    { id: 'kyc', type: 'kyc_block', severity: 'medium', any: ['KYC'],
      label: 'Talking about KYC update', labelHi: 'KYC अपडेट की बात',
      why: 'KYC is done in the branch or official app, never over a call.' },
    { id: 'link', type: null, severity: 'medium', any: ['LINK'], noNeg: true,
      label: 'Sending a link to click', labelHi: 'लिंक पर क्लिक करवाना',
      why: 'Links from callers lead to fake bank pages or apps that steal your data.' },
    { id: 'impersonation', type: null, severity: 'medium', any: ['IMPERSONATE'],
      label: 'Claims to be a bank, app or official', labelHi: 'बैंक, ऐप या अधिकारी होने का दावा',
      why: 'Anyone can claim to be from a bank. Hang up and call the number printed on your card.' },
    { id: 'bait', type: 'prize_bait', severity: 'medium', any: ['BAIT'],
      label: 'Prize, cashback, refund or loan offer', labelHi: 'इनाम, कैशबैक, रिफंड या लोन का लालच',
      why: 'Surprise prizes and refunds are hooks to get your details.' },
    { id: 'job_invest', type: 'job_investment', severity: 'medium', any: ['JOB_INVEST'],
      label: 'Easy job or high-return investment', labelHi: 'आसान नौकरी या ज़्यादा मुनाफ़े का लालच',
      why: 'Task jobs and "guaranteed returns" pay a little first, then take a lot.' },
    { id: 'job_deposit', type: 'job_investment', severity: 'critical', near: ['JOB_INVEST', 'TRANSFER'], window: 12,
      label: 'Asking you to pay for a job or investment', labelHi: 'नौकरी या निवेश के लिए पैसे माँगना',
      why: 'Real jobs never ask you to pay. "Invest more to withdraw" is always a scam.' },
    { id: 'extortion_demand', type: 'extortion', severity: 'critical', near: ['EXTORTION', 'TRANSFER'], window: 12,
      label: 'Blackmail: pay or we leak it', labelHi: 'ब्लैकमेल: पैसे दो वरना वायरल',
      why: 'Paying never stops blackmail. Block the caller, keep evidence and report at cybercrime.gov.in or 1930.' },
    { id: 'extortion', type: 'extortion', severity: 'high', any: ['EXTORTION'],
      label: 'Threat to leak a video or photo', labelHi: 'वीडियो या फोटो वायरल करने की धमकी',
      why: 'Do not pay. Block the caller, keep evidence and report at cybercrime.gov.in or 1930.' }
  ];

  // Extra points when signs that together form a known script all appear.
  var COMBOS = [
    { all: ['law_threat', 'secrecy'], bonus: 20, type: 'digital_arrest', label: 'Classic digital-arrest script (threat + secrecy)' },
    { all: ['digital_arrest', 'safe_account'], bonus: 20, type: 'digital_arrest', label: 'Arrest threat + "safe account"' },
    { all: ['impersonation', 'block_threat'], bonus: 10, type: 'kyc_block', label: 'Fake bank + block threat' },
    { all: ['bait', 'pay_to_receive'], bonus: 10, type: 'upi_fraud', label: 'Prize + "scan to receive"' },
    { all: ['utility_cut', 'pressure'], bonus: 20, type: 'utility', label: 'Disconnection threat + deadline' },
    { all: ['accidental_transfer', 'pressure'], bonus: 20, type: 'upi_fraud', label: '"Return my money" + pressure' }
  ];

  // ---------------------------------------------------------------------------
  // 4. Fraud types and advice
  // ---------------------------------------------------------------------------
  var TYPES = {
    upi_fraud: { label: 'UPI fraud', labelHi: 'UPI धोखाधड़ी',
      adviceEn: 'Never enter your UPI PIN, scan a QR or approve a request to receive money. Decline it and hang up.',
      adviceHi: 'पैसे पाने के लिए कभी PIN न डालें, QR स्कैन न करें, रिक्वेस्ट अप्रूव न करें। कॉल काट दें।' },
    otp_fraud: { label: 'Bank / OTP fraud', labelHi: 'बैंक / OTP धोखाधड़ी',
      adviceEn: 'Do not share any OTP, card number, CVV or password. Hang up and call the number on your card.',
      adviceHi: 'OTP, कार्ड नंबर, CVV या पासवर्ड न बताएं। फोन काटें और कार्ड पर लिखे नंबर पर कॉल करें।' },
    digital_arrest: { label: 'Digital arrest scam', labelHi: 'डिजिटल अरेस्ट स्कैम',
      adviceEn: 'Hang up. Police never arrest anyone on a call. Tell your family and call 1930.',
      adviceHi: 'फोन काटें। पुलिस कॉल पर गिरफ्तार नहीं करती। परिवार को बताएं और 1930 पर कॉल करें।' },
    remote_access: { label: 'Screen-sharing scam', labelHi: 'स्क्रीन शेयरिंग स्कैम',
      adviceEn: 'Do not install any app. If you already did, uninstall it and turn off mobile data.',
      adviceHi: 'कोई ऐप इंस्टॉल न करें। कर लिया है तो हटाएं और इंटरनेट बंद करें।' },
    kyc_block: { label: 'Fake KYC / account block', labelHi: 'फर्जी KYC / खाता बंद',
      adviceEn: 'Your account will not be blocked over a call. Visit your branch or use the official app.',
      adviceHi: 'कॉल पर खाता बंद नहीं होता। शाखा जाएं या आधिकारिक ऐप इस्तेमाल करें।' },
    utility: { label: 'Fake bill / disconnection', labelHi: 'फर्जी बिल / कनेक्शन कटना',
      adviceEn: 'Check your bill in the official app. Never pay through a link or number from a caller.',
      adviceHi: 'बिल आधिकारिक ऐप में देखें। कॉलर के लिंक या नंबर पर भुगतान न करें।' },
    prize_bait: { label: 'Prize / refund bait', labelHi: 'इनाम / रिफंड का लालच',
      adviceEn: 'Real prizes never need your PIN, OTP or a fee. Hang up.',
      adviceHi: 'असली इनाम के लिए PIN, OTP या फीस नहीं लगती। फोन काटें।' },
    job_investment: { label: 'Job / investment scam', labelHi: 'नौकरी / निवेश स्कैम',
      adviceEn: 'Never pay to get a job or to withdraw "profits". Stop and report it.',
      adviceHi: 'नौकरी या "मुनाफ़ा" निकालने के लिए कभी पैसे न दें। रिपोर्ट करें।' },
    extortion: { label: 'Blackmail / extortion', labelHi: 'ब्लैकमेल',
      adviceEn: 'Do not pay. Block, keep screenshots and report at cybercrime.gov.in or 1930.',
      adviceHi: 'पैसे न दें। ब्लॉक करें, सबूत रखें और 1930 पर रिपोर्ट करें।' }
  };

  var SPOKEN_DIGITS_RULE = {
    id: 'spoken_digits', type: 'otp_fraud', severity: 'high',
    label: 'A code or number was read out on the call', labelHi: 'कॉल पर कोई कोड या नंबर बोला गया',
    why: 'If that was an OTP, PIN or card number, call your bank now and block your card.'
  };

  // ---------------------------------------------------------------------------
  // Matching
  // ---------------------------------------------------------------------------
  function sentenceOf(tokens, i) {
    var s = i, e = i;
    while (s > 0 && tokens[s - 1] !== BOUNDARY) s--;
    while (e < tokens.length - 1 && tokens[e + 1] !== BOUNDARY) e++;
    return [s, e];
  }

  function negatedAround(negHits, tokens, start, end) {
    var sent = sentenceOf(tokens, start);
    var from = Math.max(sent[0], start - 8);
    var to = Math.min(sent[1], end + 2);
    return negHits.some(function (n) { return n.start >= from && n.start <= to; });
  }

  function spanText(tokens, start, end) {
    return tokens.slice(start, end + 1).join(' ');
  }

  // Find concepts A and B within `window` tokens in the same sentence.
  function nearMatch(hitsByName, tokens, names, window, noNeg) {
    var a = hitsByName[names[0]], b = hitsByName[names[1]];
    for (var i = 0; i < a.length; i++) {
      for (var j = 0; j < b.length; j++) {
        var start = Math.min(a[i].start, b[j].start);
        var end = Math.max(a[i].end, b[j].end);
        if (end - start + 1 > window) continue;
        if (a[i].start === b[j].start && a[i].end === b[j].end) continue; // same words cannot be both concepts
        var sent = sentenceOf(tokens, start);
        if (end > sent[1]) continue;
        if (noNeg && negatedAround(hitsByName.NEG, tokens, start, end)) continue;
        return spanText(tokens, start, end);
      }
    }
    return null;
  }

  function anyMatch(hitsByName, tokens, name, noNeg) {
    var hits = hitsByName[name];
    for (var i = 0; i < hits.length; i++) {
      if (noNeg && negatedAround(hitsByName.NEG, tokens, hits[i].start, hits[i].end)) continue;
      return spanText(tokens, hits[i].start, hits[i].end);
    }
    return null;
  }

  function levelFor(score, hasCritical) {
    if (hasCritical || score >= SCAM_AT) return 'scam';
    if (score >= CAUTION_AT) return 'caution';
    return 'safe';
  }

  /**
   * Analyse a call transcript or message.
   * @param {string|string[]} input  text, or a list of utterances (each one is
   *        treated as its own sentence, which is how speech recognition delivers them)
   * @param {{spokenDigits?: boolean}} [opts]  pass true if digits were read out
   *        earlier in the call (the caller keeps only masked text)
   */
  function analyze(input, opts) {
    var raw = Array.isArray(input) ? input.join(' . ') : String(input || '');
    var masked = maskNumbers(raw);
    var tokens = tokenize(masked.text);

    var hitsByName = {};
    Object.keys(COMPILED).forEach(function (name) { hitsByName[name] = findConcept(tokens, name); });

    var flags = [];
    RULES.forEach(function (rule) {
      var quote = null;
      if (rule.any) quote = anyMatch(hitsByName, tokens, rule.any[0], rule.noNeg);
      else {
        var pairs = [rule.near].concat(rule.also || []);
        for (var p = 0; p < pairs.length && !quote; p++) quote = nearMatch(hitsByName, tokens, pairs[p], rule.window, rule.noNeg);
      }
      if (quote) {
        flags.push({ id: rule.id, type: rule.type, severity: rule.severity, points: rule.points || POINTS[rule.severity],
          label: rule.label, labelHi: rule.labelHi, why: rule.why, quote: quote });
      }
    });

    // A stronger rule makes its weaker twin redundant.
    var fired = {};
    flags.forEach(function (f) { fired[f.id] = true; });
    if (fired.ask_card) flags = flags.filter(function (f) { return f.id !== 'mention_cvv'; });
    if (fired.extortion_demand) flags = flags.filter(function (f) { return f.id !== 'extortion'; });

    if (masked.spokenDigits || (opts && opts.spokenDigits)) {
      flags.push(Object.assign({ points: POINTS.high, quote: '••••' }, SPOKEN_DIGITS_RULE));
    }

    fired = {};
    flags.forEach(function (f) { fired[f.id] = true; });
    var combos = COMBOS.filter(function (c) { return c.all.every(function (id) { return fired[id]; }); });

    var score = flags.reduce(function (s, f) { return s + f.points; }, 0);
    score = Math.min(100, score + combos.reduce(function (s, c) { return s + c.bonus; }, 0));
    var hasCritical = flags.some(function (f) { return f.severity === 'critical'; });
    var level = levelFor(score, hasCritical);

    // Fraud type = the type with the most points (critical signs break ties).
    var byType = {};
    flags.concat(combos.map(function (c) { return { type: c.type, points: c.bonus, severity: 'high' }; })).forEach(function (f) {
      if (!f.type) return;
      var t = byType[f.type] || (byType[f.type] = { points: 0, critical: 0 });
      t.points += f.points;
      if (f.severity === 'critical') t.critical++;
    });
    var typeId = Object.keys(byType).sort(function (a, b) {
      return byType[b].critical - byType[a].critical || byType[b].points - byType[a].points;
    })[0] || null;
    var fraudType = level === 'safe' || !typeId ? null : Object.assign({ id: typeId }, TYPES[typeId]);

    var order = { critical: 0, high: 1, medium: 2 };
    flags.sort(function (a, b) { return order[a.severity] - order[b.severity]; });

    return {
      score: score,
      level: level,
      fraudType: fraudType,
      isUpiFraud: level !== 'safe' && !!byType.upi_fraud && (byType.upi_fraud.critical > 0 || byType.upi_fraud.points >= 20),
      flags: flags,
      combos: combos.map(function (c) { return c.label; }),
      maskedText: masked.text
    };
  }

  return {
    analyze: analyze,
    maskNumbers: maskNumbers,
    tokenize: tokenize,
    levelFor: levelFor,
    CONCEPTS: CONCEPTS,
    RULES: RULES,
    COMBOS: COMBOS,
    TYPES: TYPES,
    CAUTION_AT: CAUTION_AT,
    SCAM_AT: SCAM_AT
  };
});
