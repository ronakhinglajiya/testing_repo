# Ruko Call Guard: live scam-call warning

You're on a call. The caller says *"You are under digital arrest, don't tell anyone, read me the OTP."*
Ruko Call Guard listens to the call and, within seconds, fills the screen with a red **"Hang up now"** alarm.
It also beeps, vibrates, speaks a warning in English and Hindi, and shows a notification if the tab is in the background.

```
call audio ──► browser (mic / tab audio / file)
                  │  5-second 16 kHz WAV chunks, silence skipped
                  ▼
             server.js ──► Sarvam speech-to-text (saaras:v3, auto language)
                  │
                  ▼  transcript (all 4+ digit numbers masked as ••••)
     ┌────────────┴─────────────┐
     ▼                          ▼
 Keyword detector          OpenAI check (every ~4 s)
 instant, offline,         understands context, any language,
 English / Hinglish / हिंदी  gives scam type + "say this" line
     └────────────┬─────────────┘
                  ▼  the highest risk wins and never goes down during a call
   Safe  ──►  Be careful  ──►  SCAM: full-screen alarm + sound + voice + notification
```

## Run it

Needs Node.js 20.12 or newer. No `npm install`: there are no dependencies.

```bash
cd call-guard
cp .env.example .env        # then paste your SARVAM_API_KEY and OPENAI_API_KEY
npm start                   # open http://localhost:3000
npm test                    # 15 tests (detector + server, using fake Sarvam/OpenAI)
```

* **No keys at all?** Demo mode still works. It plays scripted calls through the keyword detector.
* **Only the Sarvam key?** Live listening works with the keyword detector. OpenAI adds the second opinion.

## Using it on a real call

| Source | When to use it |
|---|---|
| **Phone on speaker** | Put the phone call on speaker. Keep the app open on a laptop or a second phone next to it. |
| **Browser call** | WhatsApp Web, Google Meet, Teams in Chrome or Edge on desktop. Pick the call's tab and tick **Share tab audio**. Your voice comes from the mic. |
| **Recorded call** | Play a recording (mp3, wav, m4a) through the full live pipeline. Good for demos with real APIs. |
| **Demo call** | Four scripted calls: digital arrest, Hinglish bank-OTP scam, Hindi police threat, and a normal bank reminder. |

**Background:** once started, the tab keeps listening when you switch tabs or minimise the browser on desktop.
When a scam is detected you get a system notification, a sound, a spoken warning, and a flashing tab title.
It also asks the screen to stay on during the call.

**Using a phone as the listener:** browsers only allow the microphone on `https://` or `localhost`.
Run the server on your laptop and open it on the second phone through an HTTPS tunnel, for example `cloudflared tunnel --url http://localhost:3000`.

### What a web app cannot do (and the next step)

Android and iOS do not let a website hear an active phone call or run when the browser is closed.
That's why it uses speakerphone or a second device. For true always-on protection on the same phone, the next step is a small Android app.
It would use Android's call-screening or accessibility features and send audio to this same server (`/api/stt`, `/api/analyze`).
The detection logic here would not change.

## What it detects

The keyword detector (`public/scamRules.js`) works instantly and offline in English, Hinglish and Devanagari Hindi:

| Warning sign | Severity | Examples it catches |
|---|---|---|
| Asking for OTP | critical | "tell me the OTP", "OTP bata dijiye", "code aaya hoga", "ओटीपी बताइए" |
| Asking for card details | critical | card number, CVV, expiry, "card ke peeche wala number" |
| Asking for PIN / password | critical | UPI PIN, ATM PIN, net banking password |
| Screen-sharing / app install | critical | AnyDesk, TeamViewer, "app download karo", click the link |
| "Digital arrest" | critical | digital arrest, arrest warrant, CBI, money laundering, drugs in parcel, "giraftar", "stay on video call" |
| Secrecy / isolation | high | "don't tell anyone", "don't disconnect", "kisi ko mat batana", "phone mat kaatna", "किसी को मत बताना" |
| Moving money | high | "safe account", "RBI account", verification fee, refundable deposit, gift cards, crypto |
| Panic / urgency | high | immediately, "block ho jayega", "within two hours", तुरंत |
| Police / courier / legal threat | high | police, customs, FedEx parcel, FIR, court, jail |
| Spoken digits | high | "4 8 2 1 9 3" read out on the call (masked, then flagged) |
| Bank / official impersonation | medium | "SBI head office se bol raha", customer care, inspector |
| Prize / refund / loan bait | medium | lottery, KBC, refund, cashback, loan approved |

**Scoring:** critical = 40, high = 20, medium = 10. Police threat plus secrecy adds 20, because that is the digital-arrest script.
**Be careful** starts at 25. **Scam** is any critical sign or 60 and above.

**No false alarm on advice:** a real bank saying *"we will never ask for your OTP, PIN or CVV"* or *"OTP kisi ko mat batana"* stays safe. Request words inside a negated sentence are ignored.

**The OpenAI check** (`lib/openai.js`) gets the masked transcript and the detector's hits. It returns:
- a risk score and verdict
- the scam type, such as "Digital arrest" or "Bank OTP fraud"
- red flags, each with a quote from the transcript
- advice in English and Hindi
- a short line the user can say to end the call

The app takes whichever of the two is more alarmed, so the AI can add warnings but never cancels a keyword alarm.

## Privacy and safety

* API keys live only in `.env` on the server. The browser never sees them.
* Audio goes only to Sarvam, and only to be transcribed. Nothing is written to disk or logged.
* Any run of 4+ digits (OTP, card number, PIN) is masked as `••••`. This happens in the browser and again on the server, before text reaches OpenAI. A test checks that a card number never reaches OpenAI.
* The page never asks for a PIN, OTP, card or bank detail.
* A strict Content-Security-Policy is set: scripts and connections go only to the app's own server.
* It is a prototype. It can miss a scam or raise a false alarm, so the "Remember on every call" rules stay on screen.

## Configuration (`.env`)

| Variable | Default | Notes |
|---|---|---|
| `SARVAM_API_KEY` | none | From dashboard.sarvam.ai |
| `SARVAM_MODEL` | `saaras:v3` | Use `saarika:v2.5` if your account is on the older model |
| `SARVAM_MODE` | `transcribe` | `translate` gives English text, `codemix` gives Hinglish (Saaras only) |
| `SARVAM_LANGUAGE` | `unknown` | Auto-detect, or force `hi-IN`, `en-IN`, `ta-IN`, `te-IN`, `bn-IN`, `mr-IN` ... |
| `OPENAI_API_KEY` | none | |
| `OPENAI_MODEL` | `gpt-4.1-mini` | Any chat model that supports JSON output. Pick a small, fast one for live calls |
| `PORT` / `HOST` | `3000` / `127.0.0.1` | `HOST=0.0.0.0` to reach it from another device |

## Files

```
server.js              zero-dependency Node server: static files + /api/status, /api/stt, /api/analyze
lib/sarvam.js          Sarvam speech-to-text call
lib/openai.js          OpenAI prompt, call and answer clean-up
public/index.html      the app (status card, controls, transcript, reasons, full-screen alarm)
public/app.js          audio capture, chunking, WAV encoding, risk merging, alerts
public/tapWorklet.js   audio worklet that collects microphone/tab samples
public/scamRules.js    instant keyword detector (also used by the server and tests)
public/demoCalls.js    scripted sample calls
tests/                 node:test suites
```
