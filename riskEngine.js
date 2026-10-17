/*
 * Ruko UPI Check: rule-based risk engine.
 *
 * Pure functions only. No network calls, no storage, no payments.
 * Works in the browser (window.RiskEngine) and in Node (require).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.RiskEngine = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------- word lists ----------
  var RECEIVE_WORDS = /\b(receive|receiving|get (the )?(money|amount|payment)|credited|refund|cashback|prize|won|reward|winning|claim|advance|payment for your)\b/i;
  var PIN_WORDS = /\b(upi\s*pin|m-?pin|pin)\b/i;
  var PIN_TO_RECEIVE = /\b(enter|type|put|use)\b[^.!?]{0,30}\b(upi\s*pin|m-?pin|pin)\b[^.!?]{0,30}\b(receive|get|claim|credit|accept|collect)\b/i;
  var SHARE_SECRET = [
    /\b(share|send|tell|give|forward|provide|read out|whatsapp)\b[^.!?]{0,40}\b(otp|upi\s*pin|m-?pin|pin|cvv|password|card number|one[- ]time password)\b/i,
    /\b(otp|upi\s*pin|m-?pin|cvv|password)\b[^.!?]{0,30}\b(share|send|tell|give|forward)\b/i
  ];
  var REMOTE_APPS = /\b(any\s?desk|team\s?viewer|quick\s?support|rust\s?desk|airdroid|screen\s?share|screen sharing|ammyy)\b/i;
  var URGENCY = /\b(urgent|urgently|immediately|right now|within \d+\s*(min|mins|minutes|hours?|hrs?)|\d+\s*(min|mins|minutes) only|today only|last chance|act now|expire[sd]?|expiring|blocked|block(ed)? today|suspended|deactivat\w*|hurry|final notice|before midnight|asap)\b/i;
  var BAIT = /\b(won|winner|lottery|lucky draw|cashback|prize|reward|gift|refund|kyc|free|job offer|work from home|double your|guaranteed returns?|bonus|selected)\b/i;
  var AUTHORITY = /\b(bank|sbi|hdfc|icici|axis|kotak|pnb|yono|paytm|phonepe|gpay|google pay|bhim|npci|rbi|customer care|support|helpdesk|help desk|kyc|police|cyber cell|income tax|electricity|courier|army|military|government|official|amazon|flipkart|officer)\b/i;
  var SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'cutt.ly', 'is.gd', 'rb.gy', 'shorturl.at', 'tiny.cc', 'ow.ly'];
  var BAD_TLDS = ['xyz', 'top', 'click', 'buzz', 'icu', 'tk', 'ml', 'ga', 'cf', 'gq', 'live', 'online', 'site'];
  var BRANDS = ['sbi', 'hdfc', 'icici', 'axis', 'kotak', 'paytm', 'phonepe', 'gpay', 'npci', 'upi', 'rbi', 'yono', 'bhim', 'amazon', 'flipkart'];
  var OFFICIAL_DOMAINS = ['onlinesbi.sbi', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'kotak.com', 'paytm.com', 'phonepe.com', 'npci.org.in', 'rbi.org.in', 'bhimupi.org.in', 'amazon.in', 'flipkart.com', 'pay.google.com'];
  var URL_RE = /\b((?:https?:\/\/)?(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(?:\/[^\s]*)?)/gi;
  var UPI_ID_RE = /^[a-z0-9._-]{2,256}@[a-z][a-z0-9]{1,63}$/i;
  var SECRET_TYPED = /\b(upi\s*pin|m-?pin|pin|otp|password)\b\D{0,12}(\d{4,6})\b/gi;

  function firstMatch(re, text) {
    var m = text.match(re);
    return m ? m[0] : null;
  }

  function findUrls(text) {
    var out = [];
    var m;
    URL_RE.lastIndex = 0;
    while ((m = URL_RE.exec(text))) {
      var raw = m[1].replace(/[.,;:!?)]+$/, '');
      // "₹4,999.00" and similar are not links: a host needs letters in its last part
      if (!/[a-z]/i.test(raw)) continue;
      out.push(raw);
    }
    return out;
  }

  function hostOf(url) {
    return url.replace(/^https?:\/\//i, '').split(/[/:?#]/)[0].toLowerCase();
  }

  function isOfficial(host) {
    return OFFICIAL_DOMAINS.some(function (d) { return host === d || host.endsWith('.' + d); });
  }

  function linkProblems(url) {
    var host = hostOf(url);
    var problems = [];
    if (SHORTENERS.indexOf(host) !== -1) problems.push('short link hides the real website');
    if (/^http:\/\//i.test(url)) problems.push('not secure (http, not https)');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) problems.push('uses a raw number address instead of a name');
    if (/\.apk(\b|$)/i.test(url)) problems.push('downloads an app file (.apk)');
    var tld = host.split('.').pop();
    if (BAD_TLDS.indexOf(tld) !== -1) problems.push('unusual ending ".' + tld + '"');
    if (!isOfficial(host) && BRANDS.some(function (b) { return host.indexOf(b) !== -1; })) {
      problems.push('uses a bank or app name but is not its official website');
    }
    return problems;
  }

  // ---------- rules ----------
  // actionKey: PIN = "Do not share your PIN", VERIFY = "Pause and verify", RECIPIENT = "Check recipient details"
  var RULES = [
    {
      id: 'pin_to_receive',
      title: 'Asks for your UPI PIN to receive money',
      severity: 'critical',
      points: 45,
      actionKey: 'PIN',
      why: 'Your UPI PIN is only for sending money. You never need it to receive money.',
      action: 'Do not enter your PIN. Decline this request.',
      test: function (input, text) {
        var direct = firstMatch(PIN_TO_RECEIVE, text);
        if (direct) return { detail: 'The message tells you to enter a PIN to get money.', matches: [direct] };
        if ((input.kind === 'collect' || input.kind === 'qr') && RECEIVE_WORDS.test(text)) {
          var what = input.kind === 'qr' ? 'Scanning a QR code' : 'Approving a collect request';
          return {
            detail: what + ' always sends money out of your account, but this one says you will receive money.',
            matches: [firstMatch(RECEIVE_WORDS, text)]
          };
        }
        return null;
      }
    },
    {
      id: 'share_secret',
      title: 'Asks you to share a PIN, OTP or password',
      severity: 'critical',
      points: 50,
      actionKey: 'PIN',
      why: 'Banks, apps and police never ask for your PIN or OTP. Anyone who has it can empty your account.',
      action: 'Never share your PIN or OTP with anyone, not even "bank staff".',
      test: function (input, text) {
        for (var i = 0; i < SHARE_SECRET.length; i++) {
          var m = firstMatch(SHARE_SECRET[i], text);
          if (m) return { detail: 'The message asks you to give out a secret code.', matches: [m] };
        }
        return null;
      }
    },
    {
      id: 'remote_app',
      title: 'Asks you to install a screen-sharing app',
      severity: 'critical',
      points: 40,
      actionKey: 'PIN',
      why: 'Screen-sharing apps let a stranger see and control your phone, including your PIN and OTPs.',
      action: 'Do not install any app because a caller or message told you to.',
      test: function (input, text) {
        var m = firstMatch(REMOTE_APPS, text);
        return m ? { detail: 'Mentions "' + m + '".', matches: [m] } : null;
      }
    },
    {
      id: 'suspicious_link',
      title: 'Contains a suspicious link',
      severity: 'high',
      points: 25,
      actionKey: 'VERIFY',
      why: 'Fake links copy real bank pages to steal your login, PIN or card details.',
      action: 'Do not open the link. Open your bank or UPI app yourself instead.',
      test: function (input, text) {
        var bad = [];
        var matches = [];
        findUrls(text).forEach(function (url) {
          var p = linkProblems(url);
          if (p.length) { bad.push(url + ': ' + p.join('; ')); matches.push(url); }
        });
        return bad.length ? { detail: bad.join(' | '), matches: matches } : null;
      }
    },
    {
      id: 'urgency',
      title: 'Uses pressure or urgent language',
      severity: 'high',
      points: 20,
      actionKey: 'VERIFY',
      why: 'Scammers rush you so you do not stop to think. Real banks give you time.',
      action: 'Pause. Nothing real breaks if you take 10 minutes to check.',
      test: function (input, text) {
        var m = firstMatch(URGENCY, text);
        return m ? { detail: 'Says "' + m + '".', matches: [m] } : null;
      }
    },
    {
      id: 'impersonation',
      title: 'Claims to be a bank, company or official',
      severity: 'high',
      points: 25,
      actionKey: 'RECIPIENT',
      why: 'Scammers pretend to be banks, customer care, police or army to make you trust them.',
      action: 'Call the official number printed on your card or the company website, not the number in the message.',
      test: function (input, text) {
        if (input.knownContact) return null;
        var fromName = firstMatch(AUTHORITY, input.name || '');
        var fromText = firstMatch(AUTHORITY, text);
        var m = fromName || fromText;
        if (!m) return null;
        return {
          detail: (fromName ? 'Sender name "' + input.name + '"' : 'Message') + ' claims to be "' + m + '", and this is not a saved contact.',
          matches: fromText ? [fromText] : []
        };
      }
    },
    {
      id: 'bait',
      title: 'Offers a prize, cashback, refund or KYC update',
      severity: 'medium',
      points: 15,
      actionKey: 'VERIFY',
      why: 'Prizes, refunds and "KYC expiry" are the most common hooks used to start a scam.',
      action: 'Check the offer inside the official app. If it is not there, it is not real.',
      test: function (input, text) {
        var m = firstMatch(BAIT, text);
        return m ? { detail: 'Mentions "' + m + '".', matches: [m] } : null;
      }
    },
    {
      id: 'collect_from_stranger',
      title: 'Collect request from someone you do not know',
      severity: 'medium',
      points: 15,
      actionKey: 'RECIPIENT',
      why: 'A collect request takes money from you if you approve it. It never adds money.',
      action: 'Decline collect requests from people you were not expecting to pay.',
      test: function (input) {
        return input.kind === 'collect' && !input.knownContact
          ? { detail: 'Someone you have not paid before is asking to pull money from your account.', matches: [] }
          : null;
      }
    },
    {
      id: 'name_mismatch',
      title: 'Sender name does not match the UPI ID',
      severity: 'medium',
      points: 15,
      actionKey: 'RECIPIENT',
      why: 'Fraudsters set a trusted-looking display name on a personal UPI ID.',
      action: 'Check recipient details: the UPI ID and the name shown by your app should match who you expect.',
      test: function (input) {
        var id = (input.upiId || '').trim().toLowerCase();
        var name = (input.name || '').trim().toLowerCase();
        if (!id || !name || id.indexOf('@') === -1) return null;
        var local = id.split('@')[0];
        if (/^\d+$/.test(local)) return null; // phone-number IDs carry no name
        var words = name.split(/[^a-z]+/).filter(function (w) { return w.length >= 3; });
        if (!words.length) return null;
        var hit = words.some(function (w) { return local.indexOf(w) !== -1; });
        return hit ? null : { detail: '"' + input.name + '" vs ' + input.upiId + '.', matches: [] };
      }
    },
    {
      id: 'invalid_upi',
      title: 'UPI ID looks wrong',
      severity: 'medium',
      points: 15,
      actionKey: 'RECIPIENT',
      why: 'A real UPI ID looks like name@bank. Odd characters or missing parts are a red flag.',
      action: 'Ask the person to share their UPI ID again through a channel you trust.',
      test: function (input) {
        var id = (input.upiId || '').trim();
        return id && !UPI_ID_RE.test(id) ? { detail: '"' + id + '" is not a normal UPI ID.', matches: [] } : null;
      }
    },
    {
      id: 'high_amount',
      title: 'Large amount to a new person',
      severity: 'low',
      points: 10,
      actionKey: 'RECIPIENT',
      why: 'Big payments to someone new are hard to get back if something is wrong.',
      action: 'Send ₹1 first to confirm the name, or pay in person.',
      test: function (input) {
        var amt = Number(input.amount) || 0;
        return amt >= 10000 && !input.knownContact
          ? { detail: '₹' + amt.toLocaleString('en-IN') + ' to someone not in your contacts.', matches: [] }
          : null;
      }
    },
    {
      id: 'unknown_recipient',
      title: 'Recipient is not a saved contact',
      severity: 'low',
      points: 10,
      actionKey: 'RECIPIENT',
      why: 'Most fraud comes from people you have never dealt with before.',
      action: 'Check recipient details before you pay.',
      test: function (input) {
        return input.knownContact ? null : { detail: 'You have not paid this person before.', matches: [] };
      }
    }
  ];

  var SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

  var ACTION_HEADLINES = {
    PIN: 'Do not share your PIN',
    VERIFY: 'Pause and verify',
    RECIPIENT: 'Check recipient details'
  };

  function levelFor(score, hasCritical) {
    if (hasCritical || score >= 50) return 'high';
    if (score >= 20) return 'medium';
    return 'low';
  }

  // Find PINs/OTPs a user may have typed by mistake, and mask them.
  function redactSecrets(text) {
    var found = false;
    var clean = String(text || '').replace(SECRET_TYPED, function (all, word, digits) {
      found = true;
      return all.replace(digits, '••••');
    });
    return { text: clean, found: found };
  }

  function analyze(rawInput) {
    var input = Object.assign({ kind: 'message', name: '', upiId: '', amount: '', text: '', knownContact: false }, rawInput || {});
    var redacted = redactSecrets(input.text);
    input.text = redacted.text;
    var text = input.text;

    var flags = [];
    RULES.forEach(function (rule) {
      var r = rule.test(input, text);
      if (r) {
        flags.push({
          id: rule.id,
          title: rule.title,
          severity: rule.severity,
          points: rule.points,
          actionKey: rule.actionKey,
          why: rule.why,
          action: rule.action,
          detail: r.detail,
          matches: (r.matches || []).filter(Boolean)
        });
      }
    });
    flags.sort(function (a, b) { return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.points - a.points; });

    var score = Math.min(100, flags.reduce(function (s, f) { return s + f.points; }, 0));
    var hasCritical = flags.some(function (f) { return f.severity === 'critical'; });
    var level = levelFor(score, hasCritical);

    var headline;
    if (flags.some(function (f) { return f.actionKey === 'PIN'; })) headline = ACTION_HEADLINES.PIN;
    else if (level !== 'low') headline = ACTION_HEADLINES.VERIFY;
    else if (flags.length) headline = ACTION_HEADLINES.RECIPIENT;
    else headline = 'Looks okay';

    var actions = [];
    flags.forEach(function (f) { if (actions.indexOf(f.action) === -1) actions.push(f.action); });
    if (!actions.length) actions.push('Confirm the name your UPI app shows before you enter your PIN.');

    return {
      score: score,
      level: level,
      headline: headline,
      flags: flags,
      actions: actions,
      secretRedacted: redacted.found,
      cleanText: input.text
    };
  }

  // ---------- sample data (fictional, for the demo only) ----------
  var SAMPLES = [
    {
      id: 'normal-dinner',
      label: 'Dinner split from a friend',
      expected: 'low',
      input: {
        kind: 'pay',
        name: 'Priya Sharma',
        upiId: 'priya.sharma@okhdfcbank',
        amount: 450,
        text: 'Hey! My share of dinner at Udupi Cafe was ₹450. Pay when you can, thanks 🙂',
        knownContact: true
      }
    },
    {
      id: 'fake-cashback-collect',
      label: 'Fake cashback collect request',
      expected: 'high',
      input: {
        kind: 'collect',
        name: 'PhonePe Rewards',
        upiId: 'rewards.cashback7781@axl',
        amount: 4999,
        text: 'Congratulations! You have won ₹4,999 cashback. Approve this request and enter your UPI PIN to receive the amount. Offer valid for 10 minutes only.',
        knownContact: false
      }
    },
    {
      id: 'kyc-sms-link',
      label: 'Bank KYC SMS with a link',
      expected: 'high',
      input: {
        kind: 'message',
        name: 'SBI Alert',
        upiId: '',
        amount: '',
        text: 'Dear customer, your SBI YONO account will be BLOCKED today. Update your PAN/KYC immediately: http://sbi-kyc-update.xyz/login or bit.ly/sbi-kyc',
        knownContact: false
      }
    },
    {
      id: 'olx-qr-scam',
      label: '"Army buyer" QR code on OLX',
      expected: 'high',
      input: {
        kind: 'qr',
        name: 'Vikram Singh (Army)',
        upiId: '9876543210@paytm',
        amount: 15000,
        text: 'I am buying your sofa from OLX. I am in the army so I cannot come. Scan this QR and enter PIN to receive ₹15,000 advance. Hurry, I am posted out tomorrow.',
        knownContact: false
      }
    },
    {
      id: 'refund-anydesk',
      label: '"Customer care" refund call',
      expected: 'high',
      input: {
        kind: 'message',
        name: 'Amazon Customer Care',
        upiId: 'amzn.refund.desk@ybl',
        amount: 2340,
        text: 'Sir, your refund of ₹2,340 is pending. Please download AnyDesk and share the 6-digit OTP you receive so we can send the refund to your UPI.',
        knownContact: false
      }
    }
  ];

  var CHECKLIST = [
    'You never need a UPI PIN to receive money. PIN means money is leaving.',
    'Never share your PIN, OTP or password, with anyone, ever.',
    'Scanning a QR code is for paying, not for getting paid.',
    'Decline collect requests you were not expecting.',
    'Check the name your app shows before you enter your PIN.',
    'Do not click links in SMS or WhatsApp. Open your bank app yourself.',
    'Do not install AnyDesk, TeamViewer or any app a stranger asks for.',
    'If someone rushes you, stop. Urgency is a scam tactic.',
    'Lost money? Call 1930 or report at cybercrime.gov.in right away.'
  ];

  return {
    analyze: analyze,
    redactSecrets: redactSecrets,
    levelFor: levelFor,
    RULES: RULES,
    SAMPLES: SAMPLES,
    CHECKLIST: CHECKLIST
  };
});
