# Ruko Call Guard: live fraud-call warning, fully on-device

You're on a call. The caller says *"Collect request bheji hai, accept karo aur UPI PIN daalo, paise aa jayenge"* ("I've sent a collect request; accept it and enter your UPI PIN, and the money will come").
Within about a second, Ruko Call Guard fills the screen with **"Hang up now · UPI fraud"**. It beeps, vibrates, speaks a warning in English and Hindi, and shows a notification if the tab is in the background.

**No API keys. No cloud. Nothing leaves the device.**
- Speech recognition runs in the browser with [Vosk](https://alphacephei.com/vosk/) (WebAssembly, offline).
- Fraud detection is a rule-based engine of about 540 lines of plain JavaScript.

```
call audio ──► browser (mic / browser-call tab / recorded file)
                  │  16 kHz audio stays on the device
                  ▼
           Vosk speech recognition (offline, Hindi + Indian English models)
                  │  half-heard words every ~0.3 s, full sentences when the speaker pauses
                  ▼
           Fraud rules engine (public/fraudRules.js)
                  │  ~4 ms for a 10-minute call
                  ▼
   Safe ──► Be careful ──► FRAUD: full-screen alarm · fraud type · "UPI fraud: Yes/No"
```

## Why rule-based?

| | Rule-based (this project) | Cloud API (speech-to-text + LLM) |
|---|---|---|
| Privacy | Audio and text never leave the phone | Call audio sent to third parties |
| Cost | Free | Pay per minute / per token |
| Works offline | Yes, after a one-time model download | No |
| Phone load | Tiny CPU for the rules. Vosk small model: ~40 MB download, a few hundred MB RAM while listening | Network + battery for constant uploads |
| Explainable | Every alert names the exact rule and the words heard | Black box |
| Weakness | Only catches patterns it has rules for | Understands new wording |

## How the rules engine works

`public/fraudRules.js` runs in four steps, all in the browser:

**1. Normalize.** The text is lower-cased, spelling variants are joined, and Hindi script is mapped to one Roman form:
`"ओटीपी बताइए"`, `"O T P bataiye"` and `"OTP batao"` all become `otp bata…`.
Digits read out ("4 8 2 1", "four eight two one", "चार आठ दो एक") are hidden as `••••`.
Harmless phrases such as "pin code" (postal code) and "promo code" are neutralized.
"Don't worry" and "tension mat lijiye" ("don't worry" in Hindi) are recognized as reassurance, not negation.

**2. Find concepts.** About 30 word lists in English, Hinglish and Hindi:
`OTP`, `UPI_PIN`, `CARD`, `ASK` (bata*, share, send, daal*…), `PAY_ACTION` (scan, approve, accept, enter PIN…),
`RECEIVE` (paise aa jayenge, refund, cashback…), `ARREST`, `SECRECY`, `URGENCY`, `NEG` (never, mat, nahi…) and more.
A `*` matches any ending: `bata*` covers batao, bataiye and batana.

**3. Apply rules.** A rule fires when its concepts appear **close together in the same sentence**:

```js
{ id: 'pay_to_receive', type: 'upi_fraud', severity: 'critical',
  near: ['PAY_ACTION', 'RECEIVE'], window: 12, noNeg: true }
// "QR scan karo, paise aa jayenge" → fires
// "QR scan karke paise mat lena"   → negated, does not fire
```

`noNeg` ignores a match when a negation sits up to 8 words before it or 2 words after it, in the same sentence. So a bank saying *"we will never ask for your OTP, PIN or CVV"* stays safe, while *"OTP bata dijiye na"* or *"OTP bata do, nahi to block ho jayega"* ("tell me the OTP, or else it gets blocked") still fire.

**4. Decide.** Critical = 40 points, high = 20, medium = 10. Combos add bonus points; for example, police threat plus secrecy is the digital-arrest script, worth +20.
- **Be careful** at 25 points.
- **Fraud** at 60 points, or as soon as any critical rule fires.
- **Fraud type** is the type with the most points.
- **UPI fraud: Yes** appears when a critical UPI rule, or at least 20 points of UPI signs, fired.

During a call, risk only goes up: small talk after an OTP request doesn't make the call safe again.

### Fraud types and the rules behind them

| Fraud type | Rules (severity) | Example that triggers it |
|---|---|---|
| **UPI fraud** | `pay_to_receive` (critical), `ask_upi_pin` (critical), `accidental_transfer` (high, 30), `small_payment` (high, 30) | "QR scan karo, paise aa jayenge" · "UPI PIN daal do" · "Galti se paise bhej diye, wapas karo" · "Verification ke liye ek rupaya bhejo" |
| **Bank / OTP fraud** | `ask_otp`, `otp_arrived`, `ask_card`, `ask_password` (critical), `mention_cvv`, spoken digits (high) | "OTP bata dijiye" · "Aapko OTP aaya hoga" · "Card ke peeche wala number" |
| **Digital arrest** | `digital_arrest` (critical), `law_threat`, `secrecy`, `safe_account` (high) | "You are under digital arrest" · "Kisi ko mat batana" · "RBI safe account mein transfer karo" |
| **Screen-sharing** | `remote_app` (critical) | "AnyDesk download karo" |
| **Fake KYC / block** | `block_threat` (high), `kyc` (medium) | "Aapka account aaj block ho jayega, KYC update karo" |
| **Fake bill** | `utility_cut` (high) | "Bijli connection aaj raat cut ho jayega" |
| **Job / investment** | `job_deposit` (critical), `job_invest` (medium) | "Part time job hai, pehle 500 deposit karo" |
| **Blackmail** | `extortion_demand` (critical), `extortion` (high) | "Video viral kar denge agar paise nahi bheje" |
| *(any type)* | `pressure`, `impersonation`, `link`, `bait` | "Turant karo" · "SBI head office se bol raha hoon" ("calling from SBI head office") |

**Adding a rule** takes one line in `RULES` and, if needed, a new word list in `CONCEPTS`. Add a test case to `tests/fraudRules.test.js` at the same time.

## Run it

Needs Node.js 20.12 or newer.

```bash
cd call-guard
npm install          # installs the Vosk speech engine (vosk-browser, ~6 MB)
npm run models       # one-time: downloads Hindi + Indian English models (~40 MB each)
npm start            # open http://localhost:3000
npm test             # 45 tests
```

* `npm run models -- hi` downloads only the Hindi model.
* If the download is blocked, get the zip in a browser from <https://alphacephei.com/vosk/models> (`vosk-model-small-hi-0.22`, `vosk-model-small-en-in-0.4`) and run `npm run models -- --from vosk-model-small-hi-0.22.zip --as hi`.
* **Without models:** demo calls and typed tests work. Live listening asks you to run `npm run models`.
* After the first load the browser keeps the model in its own storage, so later starts take about 2 seconds and need no network.

## How to test it

1. **Demo calls (no setup):** choose **Demo call**, pick a sample, and press Start.

   | Sample | Expected |
   |---|---|
   | UPI "accept request to get paid" (OLX buyer) | Red alarm, **UPI fraud: Yes** |
   | "Digital arrest" (fake CBI / FedEx) | Red alarm, Digital arrest scam |
   | "Card will be blocked" OTP scam (Hinglish) | Red alarm, Bank / OTP fraud |
   | पुलिस धमकी (Hindi police threat) | Red alarm, Digital arrest scam |
   | Normal bill reminder from a bank | Stays green |

2. **Type a sentence:** use the box under the transcript, for example *"QR scan karo, paise aa jayenge"* or *"OTP kisi ko mat batana"* ("never tell anyone the OTP", which should stay safe). Typed lines go through exactly the same rules and alarm.
3. **Live:** choose **Phone on speaker** and the call language, press Start, and say a scam line out loud.
4. **Automated:** `npm test`. It covers 31 sentence cases (UPI, OTP, digital arrest, other scam types, and safe sentences that must not alarm), all demo calls, normalization, digit masking, a speed check, the server and the model converter.

## Using it on a real call

| Source | When |
|---|---|
| **Phone on speaker** | Put the call on speaker; keep the app open on a laptop or second phone next to it |
| **Browser call** | WhatsApp Web, Meet or Teams in desktop Chrome or Edge. Pick the tab and tick **Share tab audio** |
| **Recorded call** | Play a recording through the same pipeline |

Android and iOS don't let a web page hear a phone call on the same phone. The next step is an Android companion app that detects the call, then shows this alarm with an **End call** button. The rules engine can be reused as-is: it is plain JavaScript and also runs in Node.

## Privacy

* No API keys, no analytics, no uploads. The server only serves files, and the security policy (`connect-src 'self'`) stops the page from talking to any other server.
* Audio is turned into text in memory on the device and then discarded.
* Long numbers (OTP, card, PIN) are hidden as `••••` before they are shown or checked.
* Nothing is stored except the speech model, which the browser caches.

## Files

```
public/fraudRules.js     the rules engine (concepts, rules, combos, fraud types)
public/app.js            audio capture, Vosk speech recognition, alerts, UI
public/tapWorklet.js     audio worklet that hands audio to the recognizer
public/demoCalls.js      scripted sample calls
public/index.html        the page
server.js                static file server (no API, no keys)
scripts/get-models.js    downloads Vosk models and converts them for the browser (no dependencies)
tests/                   fraudRules, server and model-converter tests
```
