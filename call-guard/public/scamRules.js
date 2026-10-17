/*
 * Ruko Call Guard: instant scam-phrase detector for live call transcripts.
 *
 * Works on English, Hinglish (Roman Hindi) and Hindi (Devanagari) text.
 * Pure functions, no network. Runs in the browser (window.ScamRules) and Node.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ScamRules = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var POINTS = { critical: 40, high: 20, medium: 10 };
  var CAUTION_AT = 25;
  var SCAM_AT = 60;

  // Words that turn a request into advice: "never share your OTP", "OTP kisi ko mat batana".
  var NEGATION = /\b(never|not|don'?t|dont|won'?t|mat|nahi|nahin|na)\b|मत|नहीं|कभी न|ना /i;

  // Each category fires at most once per call. `negatable` rules ignore matches
  // that sit in a negated clause, so a real bank saying "we never ask for your
  // OTP" does not trigger an alert.
  var CATEGORIES = [
    {
      id: 'ask_otp',
      severity: 'critical',
      negatable: true,
      label: 'Asking for your OTP',
      labelHi: 'OTP माँग रहा है',
      why: 'No bank, police or company ever asks for an OTP on a call. The OTP is the key to your money.',
      patterns: [
        /\b(otp|o\.?t\.?p|one[- ]time password|verification code|security code|\d[- ]digit (code|number))\b[^.?!।]{0,30}?\b(bata\w*|bol\w*|share|send|tell|read|give|de do|dijiye|dena|forward|confirm|provide|enter|type)\b/gi,
        /\b(tell|share|send|read( out)?|give|provide|confirm|forward|bata\w*|bol\w*)\b[^.?!।]{0,20}?\b(otp|one[- ]time password|verification code|security code)\b/gi,
        /\b(otp|code|sms|message)\b[^.?!।]{0,25}?\b(aaya|aya|aayega|ayega|received|come|came|mila|milega)\b/gi,
        /(ओटीपी|ओ टी पी|कोड|वेरिफिकेशन कोड)[^.?!।]{0,30}?(बता|बोल|शेयर|भेज|दीजिए|दे दो|दे दीजिए|आया|आएगा|मिला)/g
      ]
    },
    {
      id: 'ask_card',
      severity: 'critical',
      negatable: true,
      label: 'Asking for card details',
      labelHi: 'कार्ड की जानकारी माँग रहा है',
      why: 'Your card number, CVV and expiry date let anyone spend your money online.',
      patterns: [
        /\b(card number|card no|card ka number|card ke number|card details|card ki details|16[- ]digit|sixteen digit|cvv|cvc|expiry( date)?|valid (thru|till|upto)|card ke peeche|back of (your|the) card|3[- ]digit (number|code)|three[- ]digit (number|code))\b/gi,
        /(कार्ड नंबर|कार्ड का नंबर|सीवीवी|एक्सपायरी|कार्ड के पीछे|16 अंकों)/g
      ]
    },
    {
      id: 'ask_banking',
      severity: 'critical',
      negatable: true,
      label: 'Asking for PIN or banking password',
      labelHi: 'PIN या बैंकिंग पासवर्ड माँग रहा है',
      why: 'Your UPI PIN, ATM PIN and net banking password are only for you. Sharing them gives full access.',
      patterns: [
        /\b(upi pin|m-?pin|atm pin|pin number|pin code bata\w*|net ?banking (password|id|login|details)|internet banking (password|id|login)|login (id|password|details)|password|user ?id)\b/gi,
        /(यूपीआई पिन|पिन नंबर|एटीएम पिन|पासवर्ड|नेट बैंकिंग)/g
      ]
    },
    {
      id: 'remote_access',
      severity: 'critical',
      negatable: true,
      label: 'Asking you to install an app or share your screen',
      labelHi: 'ऐप डाउनलोड या स्क्रीन शेयर करवा रहा है',
      why: 'Apps like AnyDesk or TeamViewer let the caller see and control your phone, including your OTPs.',
      patterns: [
        /\b(any ?desk|team ?viewer|quick ?support|rust ?desk|airdroid|screen ?shar\w*|share (your |the )?screen|download (this |the |an |our )?app|install (this |the |an |our )?app|app (download|install) kar\w*|\.?apk|link (pe|par|per) click|click (on )?(the |this )?link)\b/gi,
        /(एनीडेस्क|एनी डेस्क|टीमव्यूअर|स्क्रीन शेयर|ऐप डाउनलोड|एप डाउनलोड|लिंक पर क्लिक)/g
      ]
    },
    {
      id: 'digital_arrest',
      severity: 'critical',
      negatable: false,
      label: '"Digital arrest" or fake arrest threat',
      labelHi: '"डिजिटल अरेस्ट" या गिरफ्तारी की धमकी',
      why: 'There is no such thing as a "digital arrest" in Indian law. Real police never arrest or question anyone over a video call.',
      patterns: [
        /\b(digital(ly)? arrest\w*|arrest warrant|warrant (issued|against)|you (are|will be) (under )?arrest\w*|under arrest|money laundering|hawala|narcotics|ncb|cbi|enforcement directorate|\bed\b (officer|case|notice)|mdma|drugs (found|in (the|your) parcel)|illegal (parcel|items|passports?)|giraftar\w*|giraftaari|arrest kar\w*|video call (pe|par|per|on) (rah\w*|stay)|stay on (the )?video call|skype (call|pe|par))\b/gi,
        /(डिजिटल अरेस्ट|गिरफ्तार|गिरफ़्तार|अरेस्ट वारंट|वारंट जारी|मनी लॉन्ड्रिंग|सीबीआई|ड्रग्स|नारकोटिक्स|वीडियो कॉल पर रह)/g
      ]
    },
    {
      id: 'secrecy',
      severity: 'high',
      negatable: false,
      label: 'Telling you to keep it secret or stay on the call',
      labelHi: 'किसी को न बताने या कॉल न काटने को कह रहा है',
      why: 'Scammers cut you off from family and friends so nobody can warn you. A real officer never says this.',
      patterns: [
        /\b(don'?t|do not|dont|never) (tell|inform|call|contact|talk to) (anyone|anybody|your family|family|your (wife|husband|son|daughter|parents)|anyone else|police|the bank|your bank)\b/gi,
        /\b(don'?t|do not|dont) (disconnect|cut|hang up|end|leave)( (the|this) (call|phone|line))?\b/gi,
        /\b(stay on (the )?(line|call)|keep (your )?(camera|video) on|keep (this|it) (secret|confidential)|confidential (matter|case|investigation)|national security|secret (matter|investigation))\b/gi,
        /\b(kisi ko (bhi )?(mat|nahi|na) (bata\w*|bol\w*)|(phone|call) (mat|na|nahi) (kaat\w*|kat\w*|cut kar\w*|band kar\w*|rakh\w*)|call cut mat|ghar (walon|wale|waalon|waale) ko (mat|nahi|na)|family ko (mat|nahi|na))\b/gi,
        /(किसी को (भी )?(मत|नहीं|ना) (बता|बोल)|फ़?फोन मत काट|कॉल मत काट|कॉल कट मत|घर वालों को (मत|नहीं)|गोपनीय)/g
      ]
    },
    {
      id: 'money_transfer',
      severity: 'high',
      negatable: false,
      label: 'Asking you to move or pay money',
      labelHi: 'पैसे ट्रांसफर या भुगतान करवा रहा है',
      why: 'No government agency asks you to move money to a "safe account" or pay a fee to clear your name.',
      patterns: [
        /\b(transfer (all )?(the |your )?(money|amount|funds|balance|savings)|safe account|secure account|rbi account|government account|verification (amount|fee|charge|process)|security deposit|processing fee|clearance fee|refundable|pay (a |the )?(fine|penalty|fee)|gift ?cards?|bitcoin|crypto|usdt|paise (transfer|bhej\w*|daal\w*|jama)|amount (transfer|bhej\w*)|scan (this|the) qr|collect request)\b/gi,
        /(पैसे ट्रांसफर|पैसा ट्रांसफर|पैसे भेज|सेफ अकाउंट|सुरक्षित खाते|जुर्माना|फीस भर)/g
      ]
    },
    {
      id: 'urgency',
      severity: 'high',
      negatable: false,
      label: 'Creating panic or urgency',
      labelHi: 'डर या जल्दबाज़ी पैदा कर रहा है',
      why: 'Panic stops you from thinking. Real banks and officials give you time and written notice.',
      patterns: [
        /\b(immediately|right now|urgent\w*|within (\d+|one|two|few) (minutes?|mins?|hours?)|in (\d+|two|few) (minutes?|hours?)|today itself|last (warning|chance)|(will be|has been|is) (blocked|frozen|suspended|deactivated|seized)|block ho (jayega|jaega|jaayega|jaaega)|band ho (jayega|jaega|jaayega|jaaega)|turant|abhi ke abhi|jaldi (kar\w*|bata\w*)|(cut|disconnected) tonight|bijli (kat|cut))\b/gi,
        /(तुरंत|अभी के अभी|जल्दी (करें|कीजिए|बताइए)|ब्लॉक हो जाएगा|बंद हो जाएगा|बंद कर दिया जाएगा|आखिरी मौका|कट जाएगी)/g
      ]
    },
    {
      id: 'law_threat',
      severity: 'high',
      negatable: false,
      label: 'Police, courier or legal threat',
      labelHi: 'पुलिस, कूरियर या कानूनी धमकी',
      why: 'Fake "police", "customs" and "FedEx parcel" stories are used to scare you. Real notices come in writing.',
      patterns: [
        /\b(police|cyber ?(crime|cell)|crime branch|customs|fedex|dhl|courier (company|service)|parcel (seized|has been|booked|containing)|fir|case (registered|darj|filed|file)|court (order|notice)|supreme court|jail|illegal|aadhaar (misuse|used|linked to)|sim (card )?(will be )?block\w*|trai)\b/gi,
        /(पुलिस|साइबर क्राइम|कस्टम|कूरियर|पार्सल|एफआईआर|केस दर्ज|कोर्ट|जेल|अवैध)/g
      ]
    },
    {
      id: 'impersonation',
      severity: 'medium',
      negatable: false,
      label: 'Claims to be a bank or official',
      labelHi: 'बैंक या अधिकारी होने का दावा',
      why: 'Anyone can say they are from a bank. If in doubt, hang up and call the number printed on your card.',
      patterns: [
        /\b(bank manager|(calling )?from (sbi|hdfc|icici|axis|kotak|pnb|rbi|your bank|the bank|head office)|(sbi|hdfc|icici|axis|kotak|pnb|bank|head office) se bol \w+|customer care|reserve bank|rbi officer|telecom department|income tax|electricity (board|department)|kyc|inspector|officer)\b/gi,
        /(बैंक से बोल|बैंक मैनेजर|हेड ऑफिस|कस्टमर केयर|आरबीआई|इंस्पेक्टर|अधिकारी|केवाईसी)/g
      ]
    },
    {
      id: 'bait',
      severity: 'medium',
      negatable: false,
      label: 'Prize, refund, loan or job offer',
      labelHi: 'इनाम, रिफंड, लोन या नौकरी का लालच',
      why: 'Surprise prizes, refunds and loans are hooks to get your details.',
      patterns: [
        /\b(lottery|lucky draw|kbc|you (have )?won|winner|prize|cashback|refund|reward points|loan (is )?(approved|sanctioned)|pre-?approved|job offer|work from home|guaranteed returns?|double (your )?money)\b/gi,
        /(लॉटरी|इनाम|जीत गए|रिफंड|कैशबैक|लोन मंजूर)/g
      ]
    }
  ];

  var COMBO_BONUS = 20; // threat + secrecy together is the classic digital-arrest script

  // Mask any run of 4+ digits (OTPs, card numbers, PINs), including spaced
  // digits like "4 8 2 1". Returns the masked text and whether a code-like
  // run of separately spoken digits was found.
  function maskNumbers(text) {
    var spoken = false;
    var out = String(text || '').replace(/\d(?:[\s-]?\d){3,}/g, function (run) {
      if (/\d[\s-]\d[\s-]\d[\s-]\d/.test(run)) spoken = true;
      return '••••';
    });
    return { text: out, spokenDigits: spoken };
  }

  function clauseBefore(text, index) {
    var start = Math.max(0, index - 60);
    var before = text.slice(start, index);
    var cut = Math.max(before.lastIndexOf('.'), before.lastIndexOf('?'), before.lastIndexOf('!'), before.lastIndexOf('।'));
    return cut === -1 ? before : before.slice(cut + 1);
  }

  function findMatch(category, text) {
    for (var i = 0; i < category.patterns.length; i++) {
      var re = category.patterns[i];
      re.lastIndex = 0;
      var m;
      while ((m = re.exec(text))) {
        if (m[0] === '') { re.lastIndex++; continue; }
        if (category.negatable && (NEGATION.test(m[0]) || NEGATION.test(clauseBefore(text, m.index)))) continue;
        return m[0].trim();
      }
    }
    return null;
  }

  function levelFor(score, hasCritical) {
    if (hasCritical || score >= SCAM_AT) return 'scam';
    if (score >= CAUTION_AT) return 'caution';
    return 'safe';
  }

  /**
   * Analyse the call transcript so far.
   * @param {string} transcript  everything heard on the call (already masked or not)
   * @param {{spokenDigits?: boolean}} [opts]  spokenDigits: digits were read out earlier
   *        (the caller keeps only masked text, so it passes this flag along)
   * @returns {{score:number, level:'safe'|'caution'|'scam', flags:Array, maskedText:string}}
   */
  function analyze(transcript, opts) {
    var masked = maskNumbers(transcript);
    var text = masked.text;
    var flags = [];

    CATEGORIES.forEach(function (c) {
      var quote = findMatch(c, text);
      if (quote) {
        flags.push({ id: c.id, severity: c.severity, points: POINTS[c.severity], label: c.label, labelHi: c.labelHi, why: c.why, quote: quote });
      }
    });

    if (masked.spokenDigits || (opts && opts.spokenDigits)) {
      flags.push({
        id: 'spoken_digits', severity: 'high', points: POINTS.high,
        label: 'A code or number was read out on the call',
        labelHi: 'कॉल पर कोई कोड या नंबर बोला गया',
        why: 'If that was an OTP, PIN or card number, call your bank now and block your card.',
        quote: '••••'
      });
    }

    var ids = flags.map(function (f) { return f.id; });
    var threat = ids.indexOf('digital_arrest') !== -1 || ids.indexOf('law_threat') !== -1;
    var bonus = threat && ids.indexOf('secrecy') !== -1 ? COMBO_BONUS : 0;
    var score = Math.min(100, flags.reduce(function (s, f) { return s + f.points; }, 0) + bonus);
    var hasCritical = flags.some(function (f) { return f.severity === 'critical'; });

    var order = { critical: 0, high: 1, medium: 2 };
    flags.sort(function (a, b) { return order[a.severity] - order[b.severity]; });

    return { score: score, level: levelFor(score, hasCritical), flags: flags, maskedText: text };
  }

  return {
    analyze: analyze,
    maskNumbers: maskNumbers,
    levelFor: levelFor,
    CATEGORIES: CATEGORIES,
    CAUTION_AT: CAUTION_AT,
    SCAM_AT: SCAM_AT
  };
});
