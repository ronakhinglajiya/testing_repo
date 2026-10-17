'use strict';

const SYSTEM_PROMPT = `You are a real-time scam-call detector protecting people in India.
You receive the running transcript of a phone call, produced by automatic speech recognition.
It may contain recognition errors, Hindi, English, Hinglish or other Indian languages, and usually has no reliable speaker labels.
Long digit sequences have been masked as ••••.

Decide how likely it is that the CALLER is a fraudster. Common Indian scam patterns:
- "Digital arrest": fake CBI / ED / NCB / customs / cyber-crime police, a FedEx or courier parcel with drugs or passports, money laundering,
  Aadhaar misuse, arrest warrants, "stay on video call", "don't tell anyone", "transfer money to an RBI / safe account to verify".
- Asking for OTP, UPI PIN, ATM PIN, CVV, card number, expiry date, net banking password or login.
- "Your card / account / SIM / electricity will be blocked today", fake KYC update, fake bank manager or customer care.
- Asking to install AnyDesk, TeamViewer, QuickSupport or an APK, or to click a link or scan a QR code to receive money.
- Fake prizes, lottery, KBC, refunds, cashback, loans, jobs or investments with "guaranteed returns".
- Pressure tactics: urgency, fear, secrecy, isolation from family, threats of jail.

Scoring guide for risk_score (0-100):
- 0-24: normal call. A genuine bank reminder that does NOT ask for secrets or money is normal.
- 25-59: suspicious; some pressure or impersonation signs but no clear demand yet.
- 60-100: scam. Any request for OTP / PIN / CVV / card number / passwords / remote-access apps, any "digital arrest",
  or any demand to transfer money to clear one's name must score 80 or more.
Advice such as "never share your OTP" is NOT a red flag.

Reply with JSON only, exactly this shape:
{
  "risk_score": number,
  "verdict": "safe" | "suspicious" | "scam",
  "scam_type": short string or null (e.g. "Digital arrest", "Bank OTP fraud"),
  "red_flags": [ { "label": short English label, "quote": exact short phrase copied from the transcript } ],
  "advice_en": one short sentence telling the user what to do now,
  "advice_hi": the same advice in simple Hindi (Devanagari),
  "say_this": one short sentence the user can say to end the call safely
}
Use at most 5 red_flags. Quotes must be copied from the transcript, never invented.`;

function clampText(s, max) {
  return typeof s === 'string' ? s.trim().slice(0, max) : '';
}

function normalize(raw) {
  const score = Math.max(0, Math.min(100, Math.round(Number(raw?.risk_score) || 0)));
  const verdicts = ['safe', 'suspicious', 'scam'];
  const verdict = verdicts.includes(raw?.verdict) ? raw.verdict : score >= 60 ? 'scam' : score >= 25 ? 'suspicious' : 'safe';
  const flags = Array.isArray(raw?.red_flags) ? raw.red_flags : [];
  return {
    score,
    verdict,
    scamType: clampText(raw?.scam_type, 60) || null,
    redFlags: flags.slice(0, 5).map((f) => ({ label: clampText(f?.label, 80), quote: clampText(f?.quote, 140) })).filter((f) => f.label),
    adviceEn: clampText(raw?.advice_en, 240),
    adviceHi: clampText(raw?.advice_hi, 240),
    sayThis: clampText(raw?.say_this, 200)
  };
}

/**
 * Ask OpenAI to judge the transcript. `ruleFlags` are the instant detector's
 * hits, passed as hints. Returns the normalized verdict.
 */
async function analyzeWithOpenAI(transcript, ruleFlags, cfg) {
  const hints = ruleFlags && ruleFlags.length ? `\n\nKeyword detector hits (hints, may be wrong): ${ruleFlags.join(', ')}` : '';
  const res = await fetch(`${cfg.baseUrl}/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${cfg.apiKey}` },
    body: JSON.stringify({
      model: cfg.model,
      response_format: { type: 'json_object' },
      max_completion_tokens: 600,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: `Call transcript so far:\n"""\n${transcript}\n"""${hints}` }
      ]
    }),
    signal: AbortSignal.timeout(cfg.timeoutMs || 20000)
  });

  const raw = await res.text();
  let json = null;
  try { json = JSON.parse(raw); } catch { /* non-JSON error body */ }

  if (!res.ok) {
    const detail = json?.error?.message || raw.slice(0, 200);
    const err = new Error(`OpenAI request failed (${res.status}): ${detail}`);
    err.status = res.status === 401 || res.status === 403 ? 401 : 502;
    throw err;
  }

  const content = json?.choices?.[0]?.message?.content || '{}';
  let parsed;
  try { parsed = JSON.parse(content); } catch {
    const err = new Error('OpenAI returned a reply that is not JSON.');
    err.status = 502;
    throw err;
  }
  return normalize(parsed);
}

module.exports = { analyzeWithOpenAI, normalize, SYSTEM_PROMPT };
