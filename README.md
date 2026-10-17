# Ruko UPI Check: stop fraud before payment

*"Ruko" means "stop" in Hindi.*

Ruko UPI Check is a small prototype that checks a UPI payment request, QR code, SMS or link **before** you pay. It points out the warning signs, explains each one in simple language, and tells you what to do next:

- **Do not share your PIN**
- **Pause and verify**
- **Check recipient details**

It runs entirely in the browser. It uses fictional sample data. It never asks for, stores or sends a UPI PIN, OTP, password or bank detail, and it cannot make a payment.

## Run it

No install and no build step.

```bash
# Open the tool
open index.html          # or double-click it, or: python3 -m http.server and visit localhost:8000

# Run the tests (Node 18+)
npm test

# Print the check for every sample in the terminal
npm run demo
```

## What's on the screen

| Area | What it does |
|---|---|
| **The request** | Pick an example or type your own: request type (collect / QR / SMS-link / paying), sender name, UPI ID, amount, message, and "I know this person". |
| **Verdict** | Low / Medium / High risk, a 0–100 score, and one clear action as the headline. |
| **Warning signs in the message** | The message with the exact suspicious words highlighted. |
| **Why we flagged it** | One card per warning sign: what was found, why it matters, and what to do. |
| **What do you want to do?** | Decline, Verify first, or Continue anyway. "Continue" on a high-risk request is stopped with an explanation. Nothing is paid. |
| **Before you pay: 9 rules** | A short fraud-awareness checklist, plus the 1930 helpline and cybercrime.gov.in. |
| **Test run** | Every sample run through the engine on page load, showing expected and actual result and which rules fired. |

## Warning signs it checks

| Rule | Severity | Points | Example trigger |
|---|---|---|---|
| PIN asked to **receive** money | critical | 45 | "enter your UPI PIN to receive", or a collect request or QR that promises money |
| Asks to share PIN / OTP / password | critical | 50 | "share the 6-digit OTP" |
| Screen-sharing app | critical | 40 | AnyDesk, TeamViewer, QuickSupport |
| Suspicious link | high | 25 | short links (bit.ly), `http://`, odd endings (.xyz), bank names on non-official sites, `.apk` |
| Urgent / pressure language | high | 20 | "immediately", "blocked today", "10 minutes only", "hurry" |
| Pretends to be a bank or official | high | 25 | "SBI Alert", "Customer Care", "Army", "Police" from an unknown sender |
| Prize / cashback / refund / KYC bait | medium | 15 | "won", "cashback", "KYC" |
| Collect request from a stranger | medium | 15 | collect request and not a known contact |
| Name doesn't match UPI ID | medium | 15 | "Amazon Customer Care" on `amzn.refund.desk@ybl` |
| Malformed UPI ID | medium | 15 | `ravi@@ok bank` |
| Large amount to a new person | low | 10 | ₹10,000 or more, unknown recipient |
| Not a saved contact | low | 10 | first-time recipient |

**Score** is the sum of points, capped at 100. **High** is 50 or more, or any critical sign. **Medium** is 20–49. **Low** is below 20.

## Demo: one normal and four suspicious examples

Output of `npm run demo` (shortened):

| Example | Result | Warning signs triggered |
|---|---|---|
| Dinner split from a friend (₹450, known contact) | **LOW**, 0 | none: "Looks okay" |
| Fake cashback collect request ("enter UPI PIN to receive") | **HIGH**, 100 | PIN to receive, impersonation (PhonePe), urgency, bait, collect from stranger, unknown recipient |
| Bank KYC SMS with links | **HIGH**, 95 | suspicious link ×2, impersonation (SBI), urgency ("BLOCKED"), bait (KYC), unknown recipient |
| "Army buyer" QR code on OLX | **HIGH**, 100 | PIN to receive, impersonation (Army), urgency, large amount, unknown recipient |
| "Customer care" refund call | **HIGH**, 100 | share OTP, AnyDesk, impersonation, bait, name mismatch, unknown recipient |

## How it helps users avoid the risky action

1. **It interrupts at the right moment**, before the PIN is entered, which is the step that actually moves money.
2. **It corrects the main myth.** Most UPI scams depend on people thinking a PIN or QR scan is needed to *receive* money. The top rule says plainly: a PIN always means money is leaving.
3. **It shows its reasons.** Highlighted words and a "why" for every flag teach people to spot the pattern next time.
4. **It gives one clear next step** instead of a vague warning, and makes "Decline" the most prominent button.
5. **It slows down "Continue".** On high risk, continuing shows a stop message instead of moving ahead.

## Privacy and safety

- No PIN, OTP, password or bank field exists anywhere in the UI.
- If someone types something like `PIN 4821` or `OTP: 553201` into the message, the digits are masked as `••••` in the box at once, a warning appears, and the original value is not kept in the result (covered by a test).
- No network calls, no storage (no cookies or localStorage), no payment APIs.
- All names, UPI IDs and messages are fictional.

## Files

```
index.html               UI (HTML + CSS + small script)
riskEngine.js            rules, scoring, sample data, checklist (works in the browser and Node)
tests/riskEngine.test.js 11 tests with node:test
demo.js                  terminal demo of every sample
```
